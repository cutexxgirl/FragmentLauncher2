use super::{
    artifact_plan::{ArtifactInventoryV2, ArtifactPlanV2},
    cas::VerifiedCasObject,
    instance_state::InstanceOperationLock,
    journal::{
        operation_garbage_limits, JournalMutation, JournalPointerV2, PendingJournalV2,
        ReconcilePlanV2,
    },
    managed_fs::{
        ensure_directory_chain, inspect_managed_node_nofollow, lease_bounded_managed_tree,
        move_managed_node_no_replace_if_identity, prepare_bounded_managed_tree_move,
        BoundedManagedTreeLease, BoundedManagedTreeMoveAuthority, BoundedManagedTreeMoveRequest,
        FileIdentity, GuardedDirectoryChain, ImmutableManagedFile, ManagedDirectoryRemovalLimits,
        ManagedDirectoryRemovalSummary, ManagedFsError, ManagedNodeKind, RelativeManagedPath,
        ResumableCommitOutcome, ResumableManagedFile,
    },
    mutable::{materialize_minecraft_options_state, MutableSettingsState},
    planner::{
        validate_pending_reconcile_plan_for_recovery, MutableMaterializationProofV2,
        StagingFileProofV2,
    },
    reconciler::ReconcilePlanAuditV2,
    release::FilePolicy,
    storage::OwnedCasRoot,
    tuf::TrustedRelease,
};
use fs2::available_space;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    fs,
    io::{ErrorKind, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};
use thiserror::Error;

const STAGING_COPY_BUFFER_BYTES: usize = 1024 * 1024;

#[cfg(test)]
std::thread_local! {
    static WHOLE_TREE_PLAN_HASH_CALCULATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static RECREATED_PATH_PLAN_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static RECREATED_PATH_LOOKUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static OPERATION_ROOT_GROWTH_RESERVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PENDING_QUARANTINE_INDEX_INSERTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PENDING_QUARANTINE_INDEX_QUERIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PENDING_QUARANTINE_INDEX_PROBES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn whole_tree_plan_sha256(plan: &ReconcilePlanV2) -> Result<String, ReconcileExecutorErrorV2> {
    #[cfg(test)]
    WHOLE_TREE_PLAN_HASH_CALCULATIONS.with(|count| count.set(count.get() + 1));
    Ok(format!(
        "{:x}",
        Sha256::digest(
            plan.canonical_bytes()
                .map_err(ReconcileExecutorErrorV2::InvalidPlan)?
        )
    ))
}

#[cfg(test)]
fn reset_scale_counters() {
    WHOLE_TREE_PLAN_HASH_CALCULATIONS.with(|count| count.set(0));
    RECREATED_PATH_PLAN_VISITS.with(|count| count.set(0));
    RECREATED_PATH_LOOKUPS.with(|count| count.set(0));
    OPERATION_ROOT_GROWTH_RESERVATIONS.with(|count| count.set(0));
}

#[cfg(test)]
fn scale_counters() -> (usize, usize, usize, usize) {
    (
        WHOLE_TREE_PLAN_HASH_CALCULATIONS.with(std::cell::Cell::get),
        RECREATED_PATH_PLAN_VISITS.with(std::cell::Cell::get),
        RECREATED_PATH_LOOKUPS.with(std::cell::Cell::get),
        OPERATION_ROOT_GROWTH_RESERVATIONS.with(std::cell::Cell::get),
    )
}

#[cfg(test)]
fn reset_pending_quarantine_index_counters() {
    PENDING_QUARANTINE_INDEX_INSERTS.with(|count| count.set(0));
    PENDING_QUARANTINE_INDEX_QUERIES.with(|count| count.set(0));
    PENDING_QUARANTINE_INDEX_PROBES.with(|count| count.set(0));
}

#[cfg(test)]
fn pending_quarantine_index_counters() -> (usize, usize, usize) {
    (
        PENDING_QUARANTINE_INDEX_INSERTS.with(std::cell::Cell::get),
        PENDING_QUARANTINE_INDEX_QUERIES.with(std::cell::Cell::get),
        PENDING_QUARANTINE_INDEX_PROBES.with(std::cell::Cell::get),
    )
}

/// A regular-file binding checked through one no-follow filesystem lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecutorFileBindingV2 {
    pub size: u64,
    pub sha256: String,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ExecutorNodeKindV2 {
    /// A regular file. `link_count` is explicit because a hard-linked file must never be moved.
    RegularFile {
        binding: ExecutorFileBindingV2,
        link_count: u32,
        allocated_size: u64,
    },
    /// A real directory, not a symlink, mount alias or reparse point.
    RealDirectory,
    /// A symlink/reparse point represented as the link object itself. Its target was not opened.
    ReparsePoint,
    /// A platform object which cannot be safely classified by the managed filesystem layer.
    Unsupported,
}

/// The identity and no-follow classification of exactly one managed path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecutorNodeSnapshotV2<I> {
    pub identity: I,
    pub kind: ExecutorNodeKindV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ExecutorMutationErrorV2 {
    NotApplied(String),
    AppliedButStateUncertain(String),
}

/// Filesystem boundary required by the reconcile state machine.
///
/// Implementations are security-sensitive. Every method must stay beneath `install_root`, hold
/// real parent-directory handles for the whole operation, reject case aliases and volume
/// crossings, and never follow a symlink or reparse point. `inspect_node` must hash a regular file
/// through the same leased handle used to obtain its identity. `rename_node_no_replace` must rename
/// the exact leased object represented by `expected`; it may move a reparse object but must never
/// traverse it and must reject a regular file whose link count is not one. The copy method must
/// stream from the exact leased source into an exclusive temporary file, sync it, atomically
/// publish it without replacement, verify the destination, and leave the source untouched.
pub(super) trait ReconcileFileSystemV2 {
    type Identity: Clone + Debug + Eq;
    type BoundedTreeLease;
    type BoundedTreeMoveAuthority;

    fn install_root(&self) -> &Path;

    fn inspect_node(
        &mut self,
        path: &RelativeManagedPath,
    ) -> Result<Option<ExecutorNodeSnapshotV2<Self::Identity>>, String>;

    /// Ensures the complete path is made only of real directories and reports whether the leaf
    /// directory was created by this call.
    fn ensure_real_directory(
        &mut self,
        path: &RelativeManagedPath,
    ) -> Result<bool, ExecutorMutationErrorV2>;

    /// Returns the exact immediate child-name set of a real directory. Implementations must
    /// reject non-Unicode names, invalid components and case-colliding aliases.
    fn list_directory_children(
        &mut self,
        path: &RelativeManagedPath,
    ) -> Result<Vec<String>, String>;

    fn lease_bounded_tree(
        &mut self,
        source: &RelativeManagedPath,
        expected: &ExecutorNodeSnapshotV2<Self::Identity>,
        limits: ManagedDirectoryRemovalLimits,
    ) -> Result<Self::BoundedTreeLease, String>;

    fn bounded_tree_lease_summary(lease: &Self::BoundedTreeLease)
        -> ManagedDirectoryRemovalSummary;

    fn revalidate_bounded_tree_lease(
        &mut self,
        lease: &Self::BoundedTreeLease,
    ) -> Result<(), String>;

    fn prepare_bounded_tree_move(
        &mut self,
        source: &RelativeManagedPath,
        expected: &ExecutorNodeSnapshotV2<Self::Identity>,
        destination: &RelativeManagedPath,
        destination_depth_within_cleanup_root: usize,
        limits: ManagedDirectoryRemovalLimits,
    ) -> Result<Self::BoundedTreeMoveAuthority, String>;

    fn bounded_tree_move_summary(
        authority: &Self::BoundedTreeMoveAuthority,
    ) -> ManagedDirectoryRemovalSummary;

    fn revalidate_bounded_tree_move(
        &mut self,
        authority: &Self::BoundedTreeMoveAuthority,
    ) -> Result<(), String>;

    fn move_bounded_tree_no_replace(
        &mut self,
        authority: Self::BoundedTreeMoveAuthority,
    ) -> Result<(), ExecutorMutationErrorV2>;

    fn rename_node_no_replace(
        &mut self,
        source: &RelativeManagedPath,
        expected: &ExecutorNodeSnapshotV2<Self::Identity>,
        destination: &RelativeManagedPath,
    ) -> Result<(), ExecutorMutationErrorV2>;

    fn copy_regular_file_no_replace(
        &mut self,
        source: &RelativeManagedPath,
        expected_source: &ExecutorNodeSnapshotV2<Self::Identity>,
        temporary: &RelativeManagedPath,
        destination: &RelativeManagedPath,
        expected_destination: &ExecutorFileBindingV2,
    ) -> Result<(), ExecutorMutationErrorV2>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ManagedExecutorIdentityV2 {
    Stable(FileIdentity),
    Reparse {
        identity: FileIdentity,
        native_kind: ManagedNodeKind,
        reparse_tag: u32,
    },
}

/// Production adapter over `managed_fs`. Its root is the same install root protected by the
/// channel operation lock.
pub(super) struct ManagedReconcileFileSystemV2 {
    install_root: PathBuf,
}

pub(super) struct ManagedBoundedTreeMoveAuthorityV2 {
    inner: BoundedManagedTreeMoveAuthority,
    source: RelativeManagedPath,
    destination: RelativeManagedPath,
    expected_identity: FileIdentity,
    expected_kind: Option<ManagedNodeKind>,
}

impl ManagedReconcileFileSystemV2 {
    pub fn new(install_root: &Path) -> Self {
        Self {
            install_root: install_root.to_path_buf(),
        }
    }
}

fn managed_native_binding(
    expected: &ExecutorNodeSnapshotV2<ManagedExecutorIdentityV2>,
) -> Result<(&FileIdentity, ManagedNodeKind, u32), String> {
    match (&expected.identity, &expected.kind) {
        (ManagedExecutorIdentityV2::Stable(identity), ExecutorNodeKindV2::RegularFile { .. }) => {
            Ok((identity, ManagedNodeKind::File, 0))
        }
        (ManagedExecutorIdentityV2::Stable(identity), ExecutorNodeKindV2::RealDirectory) => {
            Ok((identity, ManagedNodeKind::Directory, 0))
        }
        (
            ManagedExecutorIdentityV2::Reparse {
                identity,
                native_kind,
                reparse_tag,
            },
            ExecutorNodeKindV2::ReparsePoint,
        ) => Ok((identity, *native_kind, *reparse_tag)),
        _ => Err("managed executor snapshot has an inconsistent native node class".into()),
    }
}

fn classify_managed_mutation_error(error: ManagedFsError) -> ExecutorMutationErrorV2 {
    let message = error.to_string();
    match error {
        ManagedFsError::AppliedButDurabilityUnconfirmed { .. } => {
            ExecutorMutationErrorV2::AppliedButStateUncertain(message)
        }
        _ => ExecutorMutationErrorV2::NotApplied(message),
    }
}

fn executor_mutation_error(error: ExecutorMutationErrorV2) -> ReconcileExecutorErrorV2 {
    match error {
        ExecutorMutationErrorV2::NotApplied(message) => {
            ReconcileExecutorErrorV2::Filesystem(message)
        }
        ExecutorMutationErrorV2::AppliedButStateUncertain(message) => {
            ReconcileExecutorErrorV2::Interrupted(message)
        }
    }
}

fn temporary_state_uncertain(error: impl std::fmt::Display) -> ExecutorMutationErrorV2 {
    ExecutorMutationErrorV2::AppliedButStateUncertain(format!(
        "reconcile temporary may have changed before the operation failed: {error}"
    ))
}

impl ReconcileFileSystemV2 for ManagedReconcileFileSystemV2 {
    type Identity = ManagedExecutorIdentityV2;
    type BoundedTreeLease = BoundedManagedTreeLease;
    type BoundedTreeMoveAuthority = ManagedBoundedTreeMoveAuthorityV2;

    fn install_root(&self) -> &Path {
        &self.install_root
    }

    fn inspect_node(
        &mut self,
        path: &RelativeManagedPath,
    ) -> Result<Option<ExecutorNodeSnapshotV2<Self::Identity>>, String> {
        let absolute = path.join_to(&self.install_root);
        let metadata = match std::fs::symlink_metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("cannot inspect {}: {error}", absolute.display())),
        };
        if metadata.file_type().is_symlink() || metadata_is_reparse(&metadata) {
            let (identity, native_kind, reparse_tag) =
                inspect_managed_node_nofollow(&self.install_root, path)
                    .map_err(|error| error.to_string())?;
            return Ok(Some(ExecutorNodeSnapshotV2 {
                identity: ManagedExecutorIdentityV2::Reparse {
                    identity,
                    native_kind,
                    reparse_tag,
                },
                kind: ExecutorNodeKindV2::ReparsePoint,
            }));
        }
        if metadata.is_file() {
            let mut file = ImmutableManagedFile::open(&self.install_root, path)
                .map_err(|error| error.to_string())?;
            let digest = file.sha256(u64::MAX).map_err(|error| error.to_string())?;
            return Ok(Some(ExecutorNodeSnapshotV2 {
                identity: ManagedExecutorIdentityV2::Stable(file.info().identity.clone()),
                kind: ExecutorNodeKindV2::RegularFile {
                    binding: ExecutorFileBindingV2 {
                        size: digest.size,
                        sha256: digest.sha256,
                        executable: metadata_is_executable(&metadata),
                    },
                    link_count: file.info().number_of_links,
                    allocated_size: file.info().allocation_size,
                },
            }));
        }
        if metadata.is_dir() {
            let chain = GuardedDirectoryChain::open(&self.install_root, path)
                .map_err(|error| error.to_string())?;
            return Ok(Some(ExecutorNodeSnapshotV2 {
                identity: ManagedExecutorIdentityV2::Stable(chain.leaf().info().identity.clone()),
                kind: ExecutorNodeKindV2::RealDirectory,
            }));
        }
        Err(format!("unsupported managed node: {}", absolute.display()))
    }

    fn ensure_real_directory(
        &mut self,
        path: &RelativeManagedPath,
    ) -> Result<bool, ExecutorMutationErrorV2> {
        let existed = self
            .inspect_node(path)
            .map_err(ExecutorMutationErrorV2::NotApplied)?
            .is_some();
        ensure_directory_chain(&self.install_root, path).map_err(|error| {
            if !existed {
                // `GuardedDirectoryChain::ensure` can create and durably flush an earlier missing
                // component before a later component fails. Once the requested leaf was absent,
                // no untyped failure may claim that the namespace definitely stayed unchanged.
                ExecutorMutationErrorV2::AppliedButStateUncertain(error.to_string())
            } else {
                classify_managed_mutation_error(error)
            }
        })?;
        Ok(!existed)
    }

    fn list_directory_children(
        &mut self,
        path: &RelativeManagedPath,
    ) -> Result<Vec<String>, String> {
        list_managed_directory_children(&self.install_root, path).map_err(|error| error.to_string())
    }

    fn lease_bounded_tree(
        &mut self,
        source: &RelativeManagedPath,
        expected: &ExecutorNodeSnapshotV2<Self::Identity>,
        limits: ManagedDirectoryRemovalLimits,
    ) -> Result<Self::BoundedTreeLease, String> {
        let (expected_identity, expected_kind, expected_reparse_tag) =
            managed_native_binding(expected)?;
        lease_bounded_managed_tree(
            &self.install_root,
            source.clone(),
            expected_identity,
            expected_kind,
            expected_reparse_tag,
            limits,
        )
        .map_err(|error| error.to_string())
    }

    fn bounded_tree_lease_summary(
        lease: &Self::BoundedTreeLease,
    ) -> ManagedDirectoryRemovalSummary {
        lease.summary()
    }

    fn revalidate_bounded_tree_lease(
        &mut self,
        lease: &Self::BoundedTreeLease,
    ) -> Result<(), String> {
        lease.revalidate().map_err(|error| error.to_string())
    }

    fn prepare_bounded_tree_move(
        &mut self,
        source: &RelativeManagedPath,
        expected: &ExecutorNodeSnapshotV2<Self::Identity>,
        destination: &RelativeManagedPath,
        destination_depth_within_cleanup_root: usize,
        limits: ManagedDirectoryRemovalLimits,
    ) -> Result<Self::BoundedTreeMoveAuthority, String> {
        let (expected_identity, expected_kind, expected_reparse_tag) =
            managed_native_binding(expected)?;
        let inner = prepare_bounded_managed_tree_move(
            &self.install_root,
            BoundedManagedTreeMoveRequest {
                source: source.clone(),
                expected_identity,
                expected_kind,
                expected_reparse_tag,
                destination_depth_within_cleanup_root,
                destination: destination.clone(),
                limits,
            },
        )
        .map_err(|error| error.to_string())?;
        inner.revalidate().map_err(|error| error.to_string())?;
        Ok(ManagedBoundedTreeMoveAuthorityV2 {
            inner,
            source: source.clone(),
            destination: destination.clone(),
            expected_identity: expected_identity.clone(),
            expected_kind: Some(expected_kind),
        })
    }

    fn bounded_tree_move_summary(
        authority: &Self::BoundedTreeMoveAuthority,
    ) -> ManagedDirectoryRemovalSummary {
        authority.inner.summary()
    }

    fn revalidate_bounded_tree_move(
        &mut self,
        authority: &Self::BoundedTreeMoveAuthority,
    ) -> Result<(), String> {
        authority
            .inner
            .revalidate()
            .map_err(|error| error.to_string())
    }

    fn move_bounded_tree_no_replace(
        &mut self,
        authority: Self::BoundedTreeMoveAuthority,
    ) -> Result<(), ExecutorMutationErrorV2> {
        let moved = authority
            .inner
            .move_no_replace()
            .map_err(classify_managed_mutation_error)?;
        if moved.source != authority.source
            || moved.destination != authority.destination
            || moved.identity != authority.expected_identity
            || authority
                .expected_kind
                .is_some_and(|expected| moved.kind != expected)
        {
            return Err(ExecutorMutationErrorV2::AppliedButStateUncertain(
                "bounded managed move returned a different node binding".into(),
            ));
        }
        Ok(())
    }

    fn rename_node_no_replace(
        &mut self,
        source: &RelativeManagedPath,
        expected: &ExecutorNodeSnapshotV2<Self::Identity>,
        destination: &RelativeManagedPath,
    ) -> Result<(), ExecutorMutationErrorV2> {
        let identity = match &expected.identity {
            ManagedExecutorIdentityV2::Stable(identity)
            | ManagedExecutorIdentityV2::Reparse { identity, .. } => identity,
        };
        let moved = move_managed_node_no_replace_if_identity(
            &self.install_root,
            source.clone(),
            destination.clone(),
            identity,
        )
        .map_err(classify_managed_mutation_error)?;
        if moved.identity != *identity {
            return Err(ExecutorMutationErrorV2::AppliedButStateUncertain(
                "managed move returned a different filesystem identity".into(),
            ));
        }
        let expected_kind = match &expected.kind {
            ExecutorNodeKindV2::RegularFile { .. } => Some(ManagedNodeKind::File),
            ExecutorNodeKindV2::RealDirectory => Some(ManagedNodeKind::Directory),
            ExecutorNodeKindV2::ReparsePoint => match &expected.identity {
                ManagedExecutorIdentityV2::Reparse { native_kind, .. } => Some(*native_kind),
                ManagedExecutorIdentityV2::Stable(_) => None,
            },
            ExecutorNodeKindV2::Unsupported => None,
        };
        if expected_kind.is_some_and(|kind| kind != moved.kind) {
            return Err(ExecutorMutationErrorV2::AppliedButStateUncertain(
                "managed move returned a different node kind".into(),
            ));
        }
        Ok(())
    }

    fn copy_regular_file_no_replace(
        &mut self,
        source: &RelativeManagedPath,
        expected_source: &ExecutorNodeSnapshotV2<Self::Identity>,
        temporary: &RelativeManagedPath,
        destination: &RelativeManagedPath,
        expected_destination: &ExecutorFileBindingV2,
    ) -> Result<(), ExecutorMutationErrorV2> {
        if expected_destination.executable && cfg!(windows) {
            return Err(ExecutorMutationErrorV2::NotApplied(
                "Windows reconcile files cannot carry a POSIX executable bit".into(),
            ));
        }
        let mut source_file = ImmutableManagedFile::open(&self.install_root, source)
            .map_err(classify_managed_mutation_error)?;
        let ManagedExecutorIdentityV2::Stable(expected_identity) = &expected_source.identity else {
            return Err(ExecutorMutationErrorV2::NotApplied(
                "copy source is not a regular managed file".into(),
            ));
        };
        if source_file.info().identity != *expected_identity {
            return Err(ExecutorMutationErrorV2::NotApplied(
                "copy source identity changed after its staging audit".into(),
            ));
        }
        let mut temporary_file = ResumableManagedFile::open_or_create(
            &self.install_root,
            temporary.clone(),
            expected_destination.size,
        )
        // Opening a resumable slot may create it before an ordinary I/O failure is surfaced. From
        // this boundary onward every error is conservatively post-mutation: the exact temporary
        // state is intentionally rediscovered on restart instead of being reported as NotApplied.
        .map_err(temporary_state_uncertain)?;
        let mut offset = temporary_file.len().map_err(temporary_state_uncertain)?;
        if offset != 0
            && !temporary_file
                .matches_reader_prefix(&mut source_file, expected_destination.size)
                .map_err(temporary_state_uncertain)?
        {
            temporary_file
                .truncate_zero()
                .map_err(temporary_state_uncertain)?;
            offset = 0;
        }
        source_file
            .seek(SeekFrom::Start(offset))
            .map_err(temporary_state_uncertain)?;
        let mut buffer = vec![0_u8; STAGING_COPY_BUFFER_BYTES];
        loop {
            let read = source_file
                .read(&mut buffer)
                .map_err(temporary_state_uncertain)?;
            if read == 0 {
                break;
            }
            offset = temporary_file
                .write_all_at(offset, &buffer[..read])
                .map_err(temporary_state_uncertain)?;
        }
        source_file
            .revalidate()
            .map_err(temporary_state_uncertain)?;
        let digest = temporary_file
            .sha256(expected_destination.size)
            .map_err(temporary_state_uncertain)?;
        if digest.size != expected_destination.size || digest.sha256 != expected_destination.sha256
        {
            return Err(ExecutorMutationErrorV2::AppliedButStateUncertain(
                "streamed staging bytes do not match the signed destination".into(),
            ));
        }
        temporary_file
            .set_executable(expected_destination.executable)
            .and_then(|_| temporary_file.sync_all())
            .map_err(temporary_state_uncertain)?;
        match temporary_file
            .commit_no_replace_if(destination.clone(), || true)
            .map_err(temporary_state_uncertain)?
            .expect("reconcile copy always crosses its commit boundary")
        {
            ResumableCommitOutcome::Committed(committed) => {
                if committed.destination != *destination
                    || committed.size != expected_destination.size
                {
                    return Err(ExecutorMutationErrorV2::AppliedButStateUncertain(
                        "committed reconcile copy returned a different destination binding".into(),
                    ));
                }
            }
            ResumableCommitOutcome::DestinationExists(temporary_file) => {
                let mut winner = ImmutableManagedFile::open(&self.install_root, destination)
                    .map_err(temporary_state_uncertain)?;
                let digest = winner
                    .sha256(expected_destination.size)
                    .map_err(temporary_state_uncertain)?;
                let executable = metadata_is_executable(
                    &fs::metadata(destination.join_to(&self.install_root))
                        .map_err(temporary_state_uncertain)?,
                );
                winner.revalidate().map_err(temporary_state_uncertain)?;
                if digest.size != expected_destination.size
                    || digest.sha256 != expected_destination.sha256
                    || executable != expected_destination.executable
                {
                    return Err(ExecutorMutationErrorV2::AppliedButStateUncertain(
                        "racing reconcile destination differs from the plan".into(),
                    ));
                }
                temporary_file
                    .discard()
                    .map_err(temporary_state_uncertain)?;
            }
        }
        Ok(())
    }
}

fn list_managed_directory_children(
    root: &Path,
    relative: &RelativeManagedPath,
) -> Result<Vec<String>, String> {
    let chain =
        GuardedDirectoryChain::open_snapshot(root, relative).map_err(|error| error.to_string())?;
    let enumerate = || -> Result<Vec<String>, String> {
        let mut names = Vec::new();
        let mut collision_keys = BTreeSet::new();
        let entries = fs::read_dir(chain.leaf().path()).map_err(|error| {
            format!(
                "cannot enumerate {}: {error}",
                chain.leaf().path().display()
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "cannot read directory entry under {}: {error}",
                    chain.leaf().path().display()
                )
            })?;
            let name = entry.file_name().into_string().map_err(|_| {
                format!(
                    "managed directory contains a non-Unicode name: {}",
                    chain.leaf().path().display()
                )
            })?;
            let parsed = RelativeManagedPath::new(&name)
                .map_err(|error| format!("managed directory contains an invalid name: {error}"))?;
            if parsed.as_str().contains('/') {
                return Err("managed directory child name is not one component".into());
            }
            if !collision_keys.insert(name.to_lowercase()) {
                return Err(format!(
                    "managed directory contains case-colliding names: {}",
                    chain.leaf().path().display()
                ));
            }
            names.push(name);
        }
        names.sort_unstable();
        Ok(names)
    };
    let names = enumerate()?;
    chain.revalidate().map_err(|error| error.to_string())?;
    if enumerate()? != names {
        return Err("managed directory membership changed during enumeration".into());
    }
    chain.revalidate().map_err(|error| error.to_string())?;
    drop(chain);
    Ok(names)
}

fn metadata_is_reparse(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x0000_0400 != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn metadata_is_executable(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum ReconcileExecutorErrorV2 {
    #[error("invalid reconcile plan: {0}")]
    InvalidPlan(String),
    #[error("invalid reconcile executor scope: {0}")]
    InvalidScope(String),
    #[error("invalid staging proof: {0}")]
    InvalidStagingProof(String),
    #[error("unsafe managed node: {0}")]
    UnsafeNode(String),
    #[error("reconcile conflict: {0}")]
    Conflict(String),
    #[error("managed filesystem operation failed: {0}")]
    Filesystem(String),
    #[error(
        "insufficient space for pending reconcile destinations: {required_bytes} bytes required, {available_bytes} bytes available"
    )]
    InsufficientSpace {
        required_bytes: u64,
        available_bytes: u64,
    },
    #[error("reconcile execution was cancelled before any committed mutation")]
    Cancelled,
    #[error("reconcile execution was interrupted after a durable mutation: {0}")]
    Interrupted(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MutationDispositionV2 {
    Applied,
    AlreadySatisfied,
    NotApplied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MutationExecutionV2 {
    pub mutation_index: usize,
    pub disposition: MutationDispositionV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReconcileExecutionReportV2 {
    pub mutations: Vec<MutationExecutionV2>,
}

/// A non-cloneable proof emitted only after the complete reverse mutation loop succeeded. The
/// journal consumes it before recording a rolled-back continuation.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct RollbackCompletionAuthorizationV2 {
    install_id: uuid::Uuid,
    channel: super::types::BuildChannel,
    operation_id: uuid::Uuid,
    plan_sha256: String,
}

#[derive(Debug)]
pub(super) struct RollbackExecutionResultV2 {
    pub(super) report: ReconcileExecutionReportV2,
    completion: RollbackCompletionAuthorizationV2,
}

impl RollbackExecutionResultV2 {
    pub(super) fn into_completion(self) -> RollbackCompletionAuthorizationV2 {
        self.completion
    }
}

impl RollbackCompletionAuthorizationV2 {
    fn from_completed_plan(plan: &ReconcilePlanV2) -> Result<Self, String> {
        let canonical = plan.canonical_bytes()?;
        Ok(Self {
            install_id: plan.install_id,
            channel: plan.channel,
            operation_id: plan.operation_id,
            plan_sha256: format!("{:x}", Sha256::digest(canonical)),
        })
    }

    pub(super) fn validate_for(
        &self,
        pointer: &JournalPointerV2,
        plan: &ReconcilePlanV2,
    ) -> Result<(), String> {
        if self.install_id != plan.install_id
            || self.channel != plan.channel
            || self.operation_id != plan.operation_id
            || pointer.install_id != self.install_id
            || pointer.channel != self.channel
            || pointer.operation_id != self.operation_id
            || pointer.plan_sha256 != self.plan_sha256
        {
            return Err("Rollback completion belongs to another reconcile operation".into());
        }
        let canonical = plan.canonical_bytes()?;
        if format!("{:x}", Sha256::digest(canonical)) != self.plan_sha256 {
            return Err("Rollback completion plan digest changed".into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn for_completed_plan_test(plan: &ReconcilePlanV2) -> Self {
        Self::from_completed_plan(plan).expect("test rollback plan must be canonical")
    }
}

impl ReconcileExecutionReportV2 {
    pub fn applied_count(&self) -> usize {
        self.mutations
            .iter()
            .filter(|entry| entry.disposition == MutationDispositionV2::Applied)
            .count()
    }
}

/// Every path controlled by one operation. No path comes from a server-provided string other than
/// the already validated channel and UUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ReconcileOperationPathsV2 {
    pub operation_root: RelativeManagedPath,
    pub staging_root: RelativeManagedPath,
    pub backup_root: RelativeManagedPath,
    pub rollback_root: RelativeManagedPath,
    pub replacement_root: RelativeManagedPath,
    pub temporary_root: RelativeManagedPath,
    pub instance_root: RelativeManagedPath,
}

impl ReconcileOperationPathsV2 {
    pub fn from_plan(plan: &ReconcilePlanV2) -> Result<Self, ReconcileExecutorErrorV2> {
        let operation_root = managed_path(&format!(
            "state/reconcile/{}/operations/{}",
            plan.channel.as_str(),
            plan.operation_id
        ))?;
        Ok(Self {
            staging_root: join(&operation_root, "staging")?,
            backup_root: join(&operation_root, "backup")?,
            rollback_root: join(&operation_root, "rollback")?,
            replacement_root: join(&operation_root, "replacements")?,
            temporary_root: join(&operation_root, "temporary")?,
            instance_root: managed_path(&format!("instances/{}", plan.channel.as_str()))?,
            operation_root,
        })
    }

    pub fn staging_file(&self, slot: u32) -> Result<RelativeManagedPath, ReconcileExecutorErrorV2> {
        join(&self.staging_root, &format!("{slot:08}.bin"))
    }

    fn staging_partial(&self, slot: u32) -> Result<RelativeManagedPath, ReconcileExecutorErrorV2> {
        join(&self.staging_root, &format!("{slot:08}.part"))
    }

    pub fn backup_node(&self, slot: u32) -> Result<RelativeManagedPath, ReconcileExecutorErrorV2> {
        join(&self.backup_root, &format!("{slot:08}.node"))
    }

    pub fn rollback_node(
        &self,
        slot: u32,
    ) -> Result<RelativeManagedPath, ReconcileExecutorErrorV2> {
        join(&self.rollback_root, &format!("{slot:08}.node"))
    }

    pub fn replacement_node(
        &self,
        slot: u32,
    ) -> Result<RelativeManagedPath, ReconcileExecutorErrorV2> {
        join(&self.replacement_root, &format!("{slot:08}.node"))
    }

    pub fn install_temporary(
        &self,
        slot: u32,
    ) -> Result<RelativeManagedPath, ReconcileExecutorErrorV2> {
        join(&self.temporary_root, &format!("{slot:08}.tmp"))
    }

    pub fn instance_path(
        &self,
        manifest_path: &str,
    ) -> Result<RelativeManagedPath, ReconcileExecutorErrorV2> {
        managed_path(&format!(
            "{}/{}",
            self.instance_root.as_str(),
            manifest_path
        ))
    }

    /// These operation-owned artifacts are deliberately retained by roll-forward and rollback.
    /// Cleanup may start only after an explicit journal completion API has durably published its
    /// outcome-bound tombstone and immutable completion history.
    pub fn retained_artifacts(
        &self,
        plan: &ReconcilePlanV2,
    ) -> Result<Vec<RelativeManagedPath>, ReconcileExecutorErrorV2> {
        let mut paths = Vec::new();
        for mutation in &plan.mutations {
            match mutation {
                JournalMutation::Quarantine { backup_slot, .. } => {
                    paths.push(self.backup_node(*backup_slot)?);
                    paths.push(self.replacement_node(*backup_slot)?);
                }
                JournalMutation::InstallFile { staging_slot, .. } => {
                    paths.push(self.staging_file(*staging_slot)?);
                    paths.push(self.rollback_node(*staging_slot)?);
                    paths.push(self.install_temporary(*staging_slot)?);
                }
                JournalMutation::EnsureDirectory { .. } => {}
            }
        }
        Ok(paths)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReconcileStagingBindingV2 {
    install_id: uuid::Uuid,
    channel: super::types::BuildChannel,
    operation_id: uuid::Uuid,
    plan_sha256: String,
    root_binding_nonce: uuid::Uuid,
    install_root_identity: FileIdentity,
    objects_root_identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedStagingSlotV2 {
    slot: u32,
    destination_path: String,
    size: u64,
    sha256: String,
    executable: bool,
    policy: FilePolicy,
    signed_size: u64,
    signed_sha256: String,
}

/// Canonical install-slot catalog sealed into one staging authority. `expected_index_by_slot`
/// makes every source bind and writer-set check independent of the total manifest size. Sparse
/// slot numbers remain bounded by `ReconcilePlanV2::validate` before this catalog is built.
#[derive(Debug, PartialEq, Eq)]
struct CanonicalStagingSlotsV2 {
    expected: Vec<ExpectedStagingSlotV2>,
    expected_index_by_slot: Vec<Option<usize>>,
    mutable_policy_index_by_expected: Vec<Option<usize>>,
}

impl CanonicalStagingSlotsV2 {
    fn new(
        expected: Vec<ExpectedStagingSlotV2>,
        mutable_policy_index_by_expected: Vec<Option<usize>>,
    ) -> Result<Self, ReconcileExecutorErrorV2> {
        if expected.len() != mutable_policy_index_by_expected.len() {
            return Err(ReconcileExecutorErrorV2::InvalidPlan(
                "trusted staging slot policy index is incomplete".into(),
            ));
        }
        let lookup_len = expected
            .iter()
            .map(|slot| slot.slot as usize)
            .max()
            .map(|slot| slot.saturating_add(1))
            .unwrap_or(0);
        let mut expected_index_by_slot = Vec::new();
        expected_index_by_slot
            .try_reserve_exact(lookup_len)
            .map_err(|_| {
                ReconcileExecutorErrorV2::InvalidPlan(
                    "trusted staging slot index exceeds launcher memory bounds".into(),
                )
            })?;
        expected_index_by_slot.resize(lookup_len, None);
        for (index, slot) in expected.iter().enumerate() {
            let lookup = &mut expected_index_by_slot[slot.slot as usize];
            if lookup.replace(index).is_some() {
                return Err(ReconcileExecutorErrorV2::InvalidPlan(format!(
                    "trusted staging slot {} is duplicated",
                    slot.slot
                )));
            }
            let has_mutable_policy = mutable_policy_index_by_expected[index].is_some();
            if has_mutable_policy != (slot.policy == FilePolicy::ValidatedMutable) {
                return Err(ReconcileExecutorErrorV2::InvalidPlan(format!(
                    "trusted staging slot {} has no canonical mutable policy binding",
                    slot.slot
                )));
            }
        }
        Ok(Self {
            expected,
            expected_index_by_slot,
            mutable_policy_index_by_expected,
        })
    }

    fn len(&self) -> usize {
        self.expected.len()
    }

    fn iter(&self) -> impl Iterator<Item = &ExpectedStagingSlotV2> {
        self.expected.iter()
    }

    fn expected_at(&self, index: usize) -> &ExpectedStagingSlotV2 {
        &self.expected[index]
    }

    fn index_for_slot(&self, staging_slot: u32) -> Option<usize> {
        self.expected_index_by_slot
            .get(staging_slot as usize)
            .copied()
            .flatten()
    }

    fn mutable_policy_index(&self, expected_index: usize) -> Option<usize> {
        self.mutable_policy_index_by_expected[expected_index]
    }
}

/// Non-serializable authority for one trusted reconcile staging operation. The recovery plan is
/// deliberately insufficient on its own: this capability is created only while the fresh TUF
/// release, sealed artifact inventory/plan, operation lock and owned root all agree.
pub(super) struct TrustedReconcileStagingAuthorityV2<'plan, 'trusted> {
    plan: &'plan ReconcilePlanV2,
    trusted_release: &'trusted TrustedRelease,
    binding: ReconcileStagingBindingV2,
    slots: CanonicalStagingSlotsV2,
}

impl Debug for TrustedReconcileStagingAuthorityV2<'_, '_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustedReconcileStagingAuthorityV2")
            .field("binding", &self.binding)
            .field("slot_count", &self.slots.len())
            .finish()
    }
}

impl TrustedReconcileStagingAuthorityV2<'_, '_> {
    pub(super) fn plan(&self) -> &ReconcilePlanV2 {
        self.plan
    }

    fn assess_remaining_space(
        &self,
        staged: &ReconcileStagingFilesV2,
        operation_lock: &InstanceOperationLock,
        cas_root: &OwnedCasRoot,
    ) -> Result<PendingRemainingSpaceAssessmentV2, ReconcileExecutorErrorV2> {
        self.assess_remaining_space_with(staged, operation_lock, cas_root, |root| {
            available_space(root)
                .map_err(|error| format!("cannot measure pending reconcile free space: {error}"))
        })
    }

    fn assess_remaining_space_with<M>(
        &self,
        staged: &ReconcileStagingFilesV2,
        operation_lock: &InstanceOperationLock,
        cas_root: &OwnedCasRoot,
        measure_available: M,
    ) -> Result<PendingRemainingSpaceAssessmentV2, ReconcileExecutorErrorV2>
    where
        M: FnOnce(&Path) -> Result<u64, String>,
    {
        validate_authority_scope(self, operation_lock, cas_root)?;
        staged.proofs_for(self, operation_lock, cas_root)?;
        cas_root
            .revalidate()
            .map_err(ReconcileExecutorErrorV2::InvalidScope)?;
        let allocation_unit = filesystem_allocation_unit(cas_root.install_root())?;
        cas_root
            .revalidate()
            .map_err(ReconcileExecutorErrorV2::InvalidScope)?;
        let mut filesystem = ManagedReconcileFileSystemV2::new(cas_root.install_root());
        let remaining_destination_bytes =
            audit_remaining_destination_bytes(self.plan, &mut filesystem, allocation_unit)?;
        // Exact staging is already allocated, but the executor must still retain enough space
        // for every remaining destination/namespace allocation and for the journal/active-marker
        // commit boundary. Reusing the canonical safety margin prevents disk drift after staging
        // from admitting mutations which cannot be durably settled.
        let required_bytes = self
            .plan
            .disk_budget
            .required_after_exact_staging(remaining_destination_bytes)
            .map_err(ReconcileExecutorErrorV2::InvalidPlan)?;
        cas_root
            .revalidate()
            .map_err(ReconcileExecutorErrorV2::InvalidScope)?;
        let available_bytes = measure_available(cas_root.install_root())
            .map_err(ReconcileExecutorErrorV2::Filesystem)?;
        cas_root
            .revalidate()
            .map_err(ReconcileExecutorErrorV2::InvalidScope)?;
        Ok(PendingRemainingSpaceAssessmentV2 {
            binding: self.binding.clone(),
            required_bytes,
            available_bytes,
        })
    }
}

/// Private point-in-time disk witness. It is never serialized and cannot be supplied by the UI or
/// coordinator; only the root-bound authority creates and validates it immediately before
/// roll-forward.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingRemainingSpaceAssessmentV2 {
    binding: ReconcileStagingBindingV2,
    required_bytes: u64,
    available_bytes: u64,
}

impl PendingRemainingSpaceAssessmentV2 {
    fn require_fits(
        &self,
        authority: &TrustedReconcileStagingAuthorityV2<'_, '_>,
    ) -> Result<(), ReconcileExecutorErrorV2> {
        if self.binding != authority.binding {
            return Err(ReconcileExecutorErrorV2::InvalidScope(
                "pending disk assessment belongs to another reconcile authority".into(),
            ));
        }
        if self.available_bytes < self.required_bytes {
            return Err(ReconcileExecutorErrorV2::InsufficientSpace {
                required_bytes: self.required_bytes,
                available_bytes: self.available_bytes,
            });
        }
        Ok(())
    }
}

pub(super) fn authorize_reconcile_staging_v2<'plan, 'trusted>(
    plan: &'plan ReconcilePlanV2,
    trusted_release: &'trusted TrustedRelease,
    inventory: &ArtifactInventoryV2,
    artifact_plan: &ArtifactPlanV2,
    operation_lock: &InstanceOperationLock,
    cas_root: &OwnedCasRoot,
) -> Result<TrustedReconcileStagingAuthorityV2<'plan, 'trusted>, ReconcileExecutorErrorV2> {
    validate_staging_scope(plan, operation_lock, cas_root)?;
    validate_trusted_release_for_staging(plan, trusted_release)?;
    inventory
        .validate_request(
            trusted_release,
            plan.install_id,
            plan.operation_id,
            plan.channel,
            plan.target.preset,
        )
        .map_err(ReconcileExecutorErrorV2::InvalidPlan)?;
    let slots = canonical_staging_slots(plan, trusted_release)?;
    artifact_plan
        .validate_reconcile_install_paths(
            cas_root,
            inventory,
            slots.iter().map(|slot| slot.destination_path.as_str()),
        )
        .map_err(ReconcileExecutorErrorV2::InvalidPlan)?;
    cas_root
        .revalidate()
        .map_err(ReconcileExecutorErrorV2::InvalidScope)?;
    Ok(TrustedReconcileStagingAuthorityV2 {
        plan,
        trusted_release,
        binding: reconcile_staging_binding(plan, cas_root)?,
        slots,
    })
}

/// Restart classification for one immutable pending journal. Only `RollForward` carries the
/// trusted staging capability accepted by the production executor. A TUF-advanced historical
/// target is exposed solely as a read-only plan identity for a separately authorized fresh-plan
/// supersede. `CurrentIncomplete` is rollback-capable only because a fresh full-plan audit already
/// bound its complete mutation scope.
pub(super) enum PendingReconcileStagingV2<'pending, 'trusted> {
    RollForward {
        authority: Box<TrustedReconcileStagingAuthorityV2<'pending, 'trusted>>,
        staged: Box<ReconcileStagingFilesV2>,
    },
    CurrentIncomplete(PendingRollbackAuthorizationV2<'pending>),
    FreshSupersedeRequired(UntrustedPendingIdentityV2),
    Historical(UntrustedPendingIdentityV2),
}

pub(super) struct PendingReconcileRecoveryRequestV2<'pending, 'trusted, 'request> {
    pub pending: &'pending PendingJournalV2,
    pub fresh_release: &'trusted TrustedRelease,
    pub fresh_inventory: &'request ArtifactInventoryV2,
    pub fresh_artifact_plan: &'request ArtifactPlanV2,
    pub fresh_plan_audit: Option<&'request ReconcilePlanAuditV2>,
    pub mutable_proofs: &'request [MutableMaterializationProofV2],
    pub operation_lock: &'request InstanceOperationLock,
    pub cas_root: &'request OwnedCasRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UntrustedPendingReasonV2 {
    CurrentPlanAuditUnavailable,
    HistoricalTarget,
}

/// Non-mutating identity for a local pending record that fresh trust could not authorize. It may
/// be displayed or superseded by a separately planned current operation, but it can never enter
/// either reconcile mutation direction.
#[derive(Debug, Clone)]
pub(super) struct UntrustedPendingIdentityV2 {
    install_id: uuid::Uuid,
    channel: super::types::BuildChannel,
    operation_id: uuid::Uuid,
    plan_sha256: String,
    pending_trusted_release: super::tuf::TrustedReleaseEvidence,
    fresh_trusted_release: super::tuf::TrustedReleaseEvidence,
    reason: UntrustedPendingReasonV2,
}

impl UntrustedPendingIdentityV2 {
    pub(super) fn validate_for(
        &self,
        plan: &ReconcilePlanV2,
        fresh_release: &TrustedRelease,
    ) -> Result<(), String> {
        let digest = format!("{:x}", Sha256::digest(plan.canonical_bytes()?));
        let fresh = fresh_release.evidence();
        let recovery_semantics_match = match self.reason {
            UntrustedPendingReasonV2::CurrentPlanAuditUnavailable => self
                .pending_trusted_release
                .targets_match_and_roles_are_monotonic_to(fresh),
            UntrustedPendingReasonV2::HistoricalTarget => {
                historical_release_advanced(&self.pending_trusted_release, fresh)
            }
        };
        if plan.install_id != self.install_id
            || plan.channel != self.channel
            || plan.operation_id != self.operation_id
            || digest != self.plan_sha256
            || plan.target.trusted_release != self.pending_trusted_release
            || fresh_release.channel() != self.channel
            || fresh != &self.fresh_trusted_release
            || !recovery_semantics_match
        {
            return Err(
                "untrusted pending identity belongs to another plan or fresh release".into(),
            );
        }
        Ok(())
    }

    pub(super) fn fresh_release_sha256(&self) -> &str {
        &self.fresh_trusted_release.release_manifest.sha256
    }

    pub(super) fn is_historical(&self) -> bool {
        self.reason == UntrustedPendingReasonV2::HistoricalTarget
    }
}

/// Classifies an already parsed local pending record without granting any filesystem mutation
/// authority. This is the only recovery capability that may survive into a separately planned
/// fresh supersede/ready-abandon flow when a full current-plan audit is unavailable.
pub(super) fn classify_untrusted_pending_identity_v2(
    pending: &PendingJournalV2,
    fresh_release: &TrustedRelease,
) -> Result<UntrustedPendingIdentityV2, ReconcileExecutorErrorV2> {
    validate_pending_journal_binding(pending)?;
    let old = &pending.plan.target.trusted_release;
    let fresh = fresh_release.evidence();
    let reason = if old.targets_match_and_roles_are_monotonic_to(fresh) {
        UntrustedPendingReasonV2::CurrentPlanAuditUnavailable
    } else if historical_release_advanced(old, fresh) {
        UntrustedPendingReasonV2::HistoricalTarget
    } else {
        return Err(ReconcileExecutorErrorV2::InvalidPlan(
            "fresh trust neither matches nor safely advances the pending target".into(),
        ));
    };
    Ok(UntrustedPendingIdentityV2 {
        install_id: pending.plan.install_id,
        channel: pending.plan.channel,
        operation_id: pending.plan.operation_id,
        plan_sha256: pending.pointer.plan_sha256.clone(),
        pending_trusted_release: old.clone(),
        fresh_trusted_release: fresh.clone(),
        reason,
    })
}

/// A non-serializable rollback capability minted only after a fresh full-plan audit bound every
/// path and integrity boundary in the pending journal to current TUF metadata and the native
/// planner reconstructed the exact same mutation set. A later staging failure may prevent roll-
/// forward without making rollback paths local-data-controlled.
pub(super) struct PendingRollbackAuthorizationV2<'pending> {
    plan: &'pending ReconcilePlanV2,
    plan_sha256: String,
    fresh_release_sha256: String,
}

impl PendingRollbackAuthorizationV2<'_> {
    pub(super) fn plan(&self) -> &ReconcilePlanV2 {
        self.plan
    }

    pub(super) fn validate_plan(&self, plan: &ReconcilePlanV2) -> Result<(), String> {
        let digest = format!("{:x}", Sha256::digest(plan.canonical_bytes()?));
        if !std::ptr::eq(self.plan, plan) || digest != self.plan_sha256 {
            return Err("pending rollback capability belongs to another plan".into());
        }
        Ok(())
    }

    pub(super) fn fresh_release_sha256(&self) -> &str {
        &self.fresh_release_sha256
    }
}

/// The only production rollback boundary for a pending operation after restart. It accepts only a
/// current pending plan which already passed both the fresh full-scope audit and canonical native
/// mutation reconstruction, then failed staging validation.
pub(super) fn rollback_pending_reconcile_v2(
    authority: &PendingRollbackAuthorizationV2<'_>,
    operation_lock: &InstanceOperationLock,
    cas_root: &OwnedCasRoot,
) -> Result<RollbackExecutionResultV2, ReconcileExecutorErrorV2> {
    authority
        .validate_plan(authority.plan)
        .map_err(ReconcileExecutorErrorV2::InvalidPlan)?;
    validate_staging_scope(authority.plan, operation_lock, cas_root)?;
    let mut filesystem = ManagedReconcileFileSystemV2::new(cas_root.install_root());
    rollback_with_checkpoint_v2(authority.plan, operation_lock, &mut filesystem, |_| Ok(()))
}

pub(super) fn recover_pending_reconcile_staging_v2<'pending, 'trusted>(
    request: PendingReconcileRecoveryRequestV2<'pending, 'trusted, '_>,
) -> Result<PendingReconcileStagingV2<'pending, 'trusted>, ReconcileExecutorErrorV2> {
    let PendingReconcileRecoveryRequestV2 {
        pending,
        fresh_release,
        fresh_inventory,
        fresh_artifact_plan,
        fresh_plan_audit,
        mutable_proofs,
        operation_lock,
        cas_root,
    } = request;
    validate_pending_journal_binding(pending)?;
    validate_staging_scope(&pending.plan, operation_lock, cas_root)?;
    let old = &pending.plan.target.trusted_release;
    let fresh = fresh_release.evidence();
    if old.targets_match_and_roles_are_monotonic_to(fresh) {
        // A pending journal is recovery data, never authority. Rebind its entire desired tree and
        // integrity scope to the freshly trusted release through the native instance-audit
        // capability, then bind every locally materialized mutable result before granting a
        // roll-forward capability. An unavailable full-plan audit is non-mutating and requires a
        // fresh supersede; only a later staging mismatch remains rollback-capable.
        let Some(fresh_plan_audit) = fresh_plan_audit else {
            return fresh_supersede_required(pending, fresh_release);
        };
        if validate_pending_reconcile_plan_for_recovery(
            &pending.plan,
            fresh_plan_audit,
            mutable_proofs,
        )
        .is_err()
        {
            return fresh_supersede_required(pending, fresh_release);
        }
        let authority = authorize_reconcile_staging_v2(
            &pending.plan,
            fresh_release,
            fresh_inventory,
            fresh_artifact_plan,
            operation_lock,
            cas_root,
        )?;
        let audit = (|| {
            let paths = ReconcileOperationPathsV2::from_plan(&pending.plan)?;
            require_staging_topology(&pending.plan, cas_root.install_root(), false)?;
            let mut filesystem = ManagedReconcileFileSystemV2::new(cas_root.install_root());
            require_real_directory(&mut filesystem, &paths.staging_root)?;
            let proofs = audit_staging_files_v2(&pending.plan, &mut filesystem)?;
            let staged = ReconcileStagingFilesV2 {
                binding: authority.binding.clone(),
                proofs,
            };
            staged.proofs_for(&authority, operation_lock, cas_root)?;
            Ok::<_, ReconcileExecutorErrorV2>(staged)
        })();
        return match audit {
            Ok(staged) => Ok(PendingReconcileStagingV2::RollForward {
                authority: Box::new(authority),
                staged: Box::new(staged),
            }),
            Err(
                ReconcileExecutorErrorV2::InvalidStagingProof(_)
                | ReconcileExecutorErrorV2::UnsafeNode(_)
                | ReconcileExecutorErrorV2::Conflict(_),
            ) => current_incomplete_recovery(pending, fresh),
            Err(error) => Err(error),
        };
    }

    if !historical_release_advanced(old, fresh) {
        return Err(ReconcileExecutorErrorV2::InvalidPlan(
            "fresh trust neither matches nor safely advances the pending target".into(),
        ));
    }
    Ok(PendingReconcileStagingV2::Historical(
        classify_untrusted_pending_identity_v2(pending, fresh_release)?,
    ))
}

fn current_incomplete_recovery<'pending, 'trusted>(
    pending: &'pending PendingJournalV2,
    fresh: &'trusted super::tuf::TrustedReleaseEvidence,
) -> Result<PendingReconcileStagingV2<'pending, 'trusted>, ReconcileExecutorErrorV2> {
    Ok(PendingReconcileStagingV2::CurrentIncomplete(
        PendingRollbackAuthorizationV2 {
            plan: &pending.plan,
            plan_sha256: pending.pointer.plan_sha256.clone(),
            fresh_release_sha256: fresh.release_manifest.sha256.clone(),
        },
    ))
}

fn fresh_supersede_required<'pending, 'trusted>(
    pending: &'pending PendingJournalV2,
    fresh_release: &'trusted TrustedRelease,
) -> Result<PendingReconcileStagingV2<'pending, 'trusted>, ReconcileExecutorErrorV2> {
    Ok(PendingReconcileStagingV2::FreshSupersedeRequired(
        classify_untrusted_pending_identity_v2(pending, fresh_release)?,
    ))
}

fn validate_pending_journal_binding(
    pending: &PendingJournalV2,
) -> Result<(), ReconcileExecutorErrorV2> {
    pending
        .pointer
        .validate(pending.plan.install_id, pending.plan.channel)
        .map_err(ReconcileExecutorErrorV2::InvalidPlan)?;
    pending
        .plan
        .validate(pending.pointer.install_id, pending.pointer.channel)
        .map_err(ReconcileExecutorErrorV2::InvalidPlan)?;
    let digest = format!(
        "{:x}",
        Sha256::digest(
            pending
                .plan
                .canonical_bytes()
                .map_err(ReconcileExecutorErrorV2::InvalidPlan,)?
        )
    );
    if pending.pointer.operation_id != pending.plan.operation_id
        || pending.pointer.plan_sha256 != digest
    {
        return Err(ReconcileExecutorErrorV2::InvalidPlan(
            "pending journal pointer does not bind its immutable plan".into(),
        ));
    }
    Ok(())
}

fn historical_release_advanced(
    old: &super::tuf::TrustedReleaseEvidence,
    fresh: &super::tuf::TrustedReleaseEvidence,
) -> bool {
    old.channel == fresh.channel
        && fresh.roles.root >= old.roles.root
        && fresh.roles.timestamp >= old.roles.timestamp
        && fresh.roles.snapshot >= old.roles.snapshot
        && fresh.roles.targets > old.roles.targets
}

enum ReconcileStagingPayloadV2<'source> {
    ExactCas(&'source VerifiedCasObject),
    CanonicalMutable(Vec<u8>),
}

/// A non-constructible, root- and operation-bound source for exactly one staging slot. Exact
/// artifacts retain the already verified CAS handle; mutable artifacts own bytes emitted by the
/// signed native validator rather than accepting caller-provided bytes.
pub(super) struct ReconcileStagingSourceV2<'source> {
    binding: ReconcileStagingBindingV2,
    staging_slot: u32,
    expected_index: usize,
    payload: ReconcileStagingPayloadV2<'source>,
}

impl Debug for ReconcileStagingSourceV2<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReconcileStagingSourceV2")
            .field("binding", &self.binding)
            .field("staging_slot", &self.staging_slot)
            .field(
                "payload",
                &match self.payload {
                    ReconcileStagingPayloadV2::ExactCas(_) => "exact-cas",
                    ReconcileStagingPayloadV2::CanonicalMutable(_) => "canonical-mutable",
                },
            )
            .finish()
    }
}

/// Exact, deterministic staging proof emitted only after every install slot and the staging
/// directory topology have been re-audited. The coordinator can obtain ordinary planner proofs
/// only while presenting the same plan, operation lock and owned CAS root.
#[derive(Debug)]
pub(super) struct ReconcileStagingFilesV2 {
    binding: ReconcileStagingBindingV2,
    proofs: Vec<StagingFileProofV2>,
}

impl ReconcileStagingFilesV2 {
    pub(super) fn proofs_for<'a>(
        &'a self,
        authority: &TrustedReconcileStagingAuthorityV2<'_, '_>,
        operation_lock: &InstanceOperationLock,
        cas_root: &OwnedCasRoot,
    ) -> Result<&'a [StagingFileProofV2], ReconcileExecutorErrorV2> {
        validate_authority_batch_scope(authority, operation_lock, cas_root)?;
        if self.binding != authority.binding {
            return Err(ReconcileExecutorErrorV2::InvalidStagingProof(
                "sealed staging files belong to another operation or root".into(),
            ));
        }
        let mut filesystem = ManagedReconcileFileSystemV2::new(cas_root.install_root());
        let audited = audit_staging_files_v2(authority.plan, &mut filesystem)?;
        if audited != self.proofs {
            return Err(ReconcileExecutorErrorV2::InvalidStagingProof(
                "sealed staging files changed after publication".into(),
            ));
        }
        cas_root
            .revalidate()
            .map_err(ReconcileExecutorErrorV2::InvalidScope)?;
        Ok(&self.proofs)
    }
}

/// Binds one exact install mutation to its live, root-bound CAS object. The caller supplies only
/// the numeric slot; destination paths and all content policy are derived from the validated plan.
pub(super) fn bind_exact_staging_source_v2<'source>(
    authority: &TrustedReconcileStagingAuthorityV2<'_, '_>,
    operation_lock: &InstanceOperationLock,
    cas_root: &OwnedCasRoot,
    staging_slot: u32,
    object: &'source VerifiedCasObject,
) -> Result<ReconcileStagingSourceV2<'source>, ReconcileExecutorErrorV2> {
    validate_authority_scope(authority, operation_lock, cas_root)?;
    let (expected_index, expected) = authority_expected_slot(authority, staging_slot)?;
    if expected.policy != FilePolicy::Exact
        || expected.signed_size != expected.size
        || expected.signed_sha256 != expected.sha256
        || object.size() != expected.size
        || object.sha256() != expected.sha256
    {
        return Err(ReconcileExecutorErrorV2::InvalidStagingProof(format!(
            "CAS object does not authorize exact staging slot {staging_slot}"
        )));
    }
    reject_unsupported_executable(expected)?;
    object.open(cas_root).map(drop).map_err(|error| {
        ReconcileExecutorErrorV2::InvalidStagingProof(format!(
            "cannot lease exact CAS source for slot {staging_slot}: {error}"
        ))
    })?;
    cas_root
        .revalidate()
        .map_err(ReconcileExecutorErrorV2::InvalidScope)?;
    Ok(ReconcileStagingSourceV2 {
        binding: authority.binding.clone(),
        staging_slot,
        expected_index,
        payload: ReconcileStagingPayloadV2::ExactCas(object),
    })
}

/// Materializes one validated-mutable slot from its TUF-authenticated policy, signed default and
/// persisted settings state. No arbitrary bytes or destination path cross this boundary.
pub(super) fn bind_canonical_mutable_staging_source_v2(
    authority: &TrustedReconcileStagingAuthorityV2<'_, '_>,
    operation_lock: &InstanceOperationLock,
    cas_root: &OwnedCasRoot,
    staging_slot: u32,
    signed_default: &VerifiedCasObject,
    state: &mut MutableSettingsState,
) -> Result<ReconcileStagingSourceV2<'static>, ReconcileExecutorErrorV2> {
    validate_authority_scope(authority, operation_lock, cas_root)?;
    let (expected_index, expected) = authority_expected_slot(authority, staging_slot)?;
    if expected.policy != FilePolicy::ValidatedMutable
        || signed_default.size() != expected.signed_size
        || signed_default.sha256() != expected.signed_sha256
    {
        return Err(ReconcileExecutorErrorV2::InvalidStagingProof(format!(
            "signed mutable default does not authorize staging slot {staging_slot}"
        )));
    }
    reject_unsupported_executable(expected)?;
    let policy_index = authority
        .slots
        .mutable_policy_index(expected_index)
        .ok_or_else(|| {
            ReconcileExecutorErrorV2::InvalidPlan(format!(
                "trusted release has no mutable policy for {}",
                expected.destination_path
            ))
        })?;
    let policy = authority
        .trusted_release
        .manifest()
        .integrity
        .mutable_settings
        .get(policy_index)
        .ok_or_else(|| {
            ReconcileExecutorErrorV2::InvalidPlan(format!(
                "trusted release has no mutable policy for {}",
                expected.destination_path
            ))
        })?;

    let default = signed_default.open(cas_root).map_err(|error| {
        ReconcileExecutorErrorV2::InvalidStagingProof(format!(
            "cannot lease signed mutable default for slot {staging_slot}: {error}"
        ))
    })?;
    let signed_bytes = default
        .read_bounded_shared(expected.signed_size)
        .map_err(|error| ReconcileExecutorErrorV2::Filesystem(error.to_string()))?;
    let bytes = materialize_minecraft_options_state(
        &signed_bytes,
        policy,
        authority.plan.target.preset.as_str(),
        state,
    )
    .map_err(ReconcileExecutorErrorV2::InvalidStagingProof)?;
    let actual_sha256 = format!("{:x}", Sha256::digest(&bytes));
    if bytes.len() as u64 != expected.size || actual_sha256 != expected.sha256 {
        return Err(ReconcileExecutorErrorV2::InvalidStagingProof(format!(
            "canonical mutable bytes do not match planned slot {staging_slot}"
        )));
    }
    default
        .revalidate()
        .map_err(|error| ReconcileExecutorErrorV2::Filesystem(error.to_string()))?;
    cas_root
        .revalidate()
        .map_err(ReconcileExecutorErrorV2::InvalidScope)?;
    Ok(ReconcileStagingSourceV2 {
        binding: authority.binding.clone(),
        staging_slot,
        expected_index,
        payload: ReconcileStagingPayloadV2::CanonicalMutable(bytes),
    })
}

/// Writes the exact install-slot set into deterministic operation staging. A partial slot is
/// restarted through its exclusive `.part` handle; final activation is synced and no-replace.
/// Exact existing finals are accepted, while missing/extra/foreign sources and wrong finals fail
/// closed.
pub(super) fn write_reconcile_staging_v2(
    authority: &TrustedReconcileStagingAuthorityV2<'_, '_>,
    operation_lock: &InstanceOperationLock,
    cas_root: &OwnedCasRoot,
    sources: Vec<ReconcileStagingSourceV2<'_>>,
) -> Result<ReconcileStagingFilesV2, ReconcileExecutorErrorV2> {
    write_reconcile_staging_with_checkpoint_v2(authority, operation_lock, cas_root, sources, |_| {
        Ok(())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StagingWriterCheckpointV2 {
    Chunk {
        staging_slot: u32,
        written_bytes: u64,
        total_bytes: u64,
    },
    BeforeCommit(u32),
    AfterCommit(u32),
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub(super) enum StagingWriterCheckpointErrorV2 {
    #[error("staging writer was cancelled")]
    Cancelled,
    #[error("{0}")]
    Failed(String),
}

pub(super) fn write_reconcile_staging_with_checkpoint_v2<C>(
    authority: &TrustedReconcileStagingAuthorityV2<'_, '_>,
    operation_lock: &InstanceOperationLock,
    cas_root: &OwnedCasRoot,
    sources: Vec<ReconcileStagingSourceV2<'_>>,
    mut checkpoint: C,
) -> Result<ReconcileStagingFilesV2, ReconcileExecutorErrorV2>
where
    C: FnMut(StagingWriterCheckpointV2) -> Result<(), StagingWriterCheckpointErrorV2>,
{
    validate_authority_batch_scope(authority, operation_lock, cas_root)?;
    let plan = authority.plan;
    let binding = authority.binding.clone();
    if sources.len() > authority.slots.len() {
        return Err(ReconcileExecutorErrorV2::InvalidStagingProof(
            "staging contains more sealed sources than install slots".into(),
        ));
    }
    let mut by_expected = std::iter::repeat_with(|| None)
        .take(authority.slots.len())
        .collect::<Vec<Option<ReconcileStagingSourceV2<'_>>>>();
    for source in sources {
        if source.binding != binding {
            return Err(ReconcileExecutorErrorV2::InvalidStagingProof(
                "sealed staging source belongs to another operation or root".into(),
            ));
        }
        let Some(canonical_index) = authority.slots.index_for_slot(source.staging_slot) else {
            return Err(ReconcileExecutorErrorV2::InvalidStagingProof(format!(
                "trusted reconcile authority has no staging slot {}",
                source.staging_slot
            )));
        };
        let canonical = authority.slots.expected_at(canonical_index);
        if source.expected_index != canonical_index
            || !payload_matches_policy(&source.payload, canonical.policy)
            || by_expected[canonical_index].is_some()
        {
            return Err(ReconcileExecutorErrorV2::InvalidStagingProof(
                "sealed staging source set is forged, duplicated or non-canonical".into(),
            ));
        }
        by_expected[canonical_index] = Some(source);
    }
    let paths = ReconcileOperationPathsV2::from_plan(plan)?;
    ensure_directory_chain(cas_root.install_root(), &paths.staging_root)
        .map_err(|error| ReconcileExecutorErrorV2::Filesystem(error.to_string()))?;
    require_staging_topology(plan, cas_root.install_root(), true)?;
    let mut committed_staging_observed = false;

    for (expected_index, expected) in authority.slots.iter().enumerate() {
        let final_path = paths.staging_file(expected.slot)?;
        let partial_path = paths.staging_partial(expected.slot)?;
        let existing_final = require_exact_existing_staging_file(
            cas_root.install_root(),
            &final_path,
            expected,
            false,
        )
        .map_err(|error| classify_staging_error(error, committed_staging_observed))?;
        if existing_final {
            by_expected[expected_index] = None;
            committed_staging_observed = true;
            if let Some(partial) = ResumableManagedFile::open_existing(
                cas_root.install_root(),
                partial_path,
                expected.size,
            )
            .map_err(|error| {
                classify_staging_error(
                    ReconcileExecutorErrorV2::Filesystem(error.to_string()),
                    committed_staging_observed,
                )
            })? {
                partial.discard().map_err(|error| {
                    classify_staging_error(
                        ReconcileExecutorErrorV2::Filesystem(error.to_string()),
                        committed_staging_observed,
                    )
                })?;
            }
            checkpoint(StagingWriterCheckpointV2::AfterCommit(expected.slot))
                .map_err(checkpoint_error_after_commit)?;
            continue;
        }

        let mut source = by_expected[expected_index]
            .take()
            .ok_or_else(|| {
                ReconcileExecutorErrorV2::InvalidStagingProof(format!(
                    "missing sealed source for absent staging slot {}",
                    expected.slot
                ))
            })
            .map_err(|error| classify_staging_error(error, committed_staging_observed))?;

        let mut partial = ResumableManagedFile::open_or_create(
            cas_root.install_root(),
            partial_path,
            expected.size,
        )
        .map_err(|error| {
            classify_staging_error(
                ReconcileExecutorErrorV2::Filesystem(error.to_string()),
                committed_staging_observed,
            )
        })?;
        let mut resume_offset = partial.len().map_err(|error| {
            classify_staging_error(
                ReconcileExecutorErrorV2::Filesystem(error.to_string()),
                committed_staging_observed,
            )
        })?;
        let partial_matches = if resume_offset == 0 {
            true
        } else {
            staging_partial_matches(&mut partial, &source.payload, cas_root, expected.size)
                .map_err(|error| classify_staging_error(error, committed_staging_observed))?
        };
        if resume_offset != 0 && !partial_matches {
            partial.truncate_zero().map_err(|error| {
                classify_staging_error(
                    ReconcileExecutorErrorV2::Filesystem(error.to_string()),
                    committed_staging_observed,
                )
            })?;
            resume_offset = 0;
        }
        stream_staging_payload(
            &mut source.payload,
            cas_root,
            &mut partial,
            resume_offset,
            expected,
            &mut checkpoint,
            committed_staging_observed,
        )
        .map_err(|error| classify_staging_error(error, committed_staging_observed))?;
        let digest = partial.sha256(expected.size).map_err(|error| {
            classify_staging_error(
                ReconcileExecutorErrorV2::Filesystem(error.to_string()),
                committed_staging_observed,
            )
        })?;
        if digest.size != expected.size || digest.sha256 != expected.sha256 {
            return Err(classify_staging_error(
                ReconcileExecutorErrorV2::InvalidStagingProof(format!(
                    "staging source bytes do not match slot {}",
                    expected.slot
                )),
                committed_staging_observed,
            ));
        }
        partial
            .set_executable(expected.executable)
            .and_then(|_| partial.sync_all())
            .map_err(|error| {
                classify_staging_error(
                    ReconcileExecutorErrorV2::Filesystem(error.to_string()),
                    committed_staging_observed,
                )
            })?;
        validate_authority_scope(authority, operation_lock, cas_root)
            .map_err(|error| classify_staging_error(error, committed_staging_observed))?;
        validate_live_payload(&source.payload, cas_root)
            .map_err(|error| classify_staging_error(error, committed_staging_observed))?;
        let mut commit_rejection = None;
        let outcome = partial
            .commit_no_replace_if(final_path.clone(), || {
                match checkpoint(StagingWriterCheckpointV2::BeforeCommit(expected.slot)) {
                    Ok(()) => true,
                    Err(error) => {
                        commit_rejection = Some(error);
                        false
                    }
                }
            })
            .map_err(|error| map_staging_commit_error(error, committed_staging_observed))?;
        let Some(outcome) = outcome else {
            return Err(checkpoint_error_before_commit(
                commit_rejection.unwrap_or_else(|| {
                    StagingWriterCheckpointErrorV2::Failed(
                        "staging commit was rejected without a checkpoint error".into(),
                    )
                }),
                committed_staging_observed,
            ));
        };
        match outcome {
            ResumableCommitOutcome::Committed(_) => {
                committed_staging_observed = true;
            }
            ResumableCommitOutcome::DestinationExists(partial) => {
                let exact_winner = require_exact_existing_staging_file(
                    cas_root.install_root(),
                    &final_path,
                    expected,
                    true,
                )
                .map_err(|error| classify_staging_error(error, committed_staging_observed))?;
                if !exact_winner {
                    return Err(classify_staging_error(
                        ReconcileExecutorErrorV2::Conflict(format!(
                            "racing staging destination disappeared for slot {}",
                            expected.slot
                        )),
                        committed_staging_observed,
                    ));
                }
                committed_staging_observed = true;
                partial.discard().map_err(|error| {
                    classify_staging_error(
                        ReconcileExecutorErrorV2::Filesystem(error.to_string()),
                        committed_staging_observed,
                    )
                })?;
            }
        }
        let published = require_exact_existing_staging_file(
            cas_root.install_root(),
            &final_path,
            expected,
            true,
        )
        .map_err(|error| classify_staging_error(error, committed_staging_observed))?;
        if !published {
            return Err(classify_staging_error(
                ReconcileExecutorErrorV2::Conflict(format!(
                    "published staging destination disappeared for slot {}",
                    expected.slot
                )),
                committed_staging_observed,
            ));
        }
        committed_staging_observed = true;
        checkpoint(StagingWriterCheckpointV2::AfterCommit(expected.slot))
            .map_err(checkpoint_error_after_commit)?;
    }
    if by_expected.iter().any(Option::is_some) {
        return Err(classify_staging_error(
            ReconcileExecutorErrorV2::InvalidStagingProof(
                "staging source set contains unused slots".into(),
            ),
            committed_staging_observed,
        ));
    }
    require_staging_topology(plan, cas_root.install_root(), false)
        .map_err(|error| classify_staging_error(error, committed_staging_observed))?;
    let mut filesystem = ManagedReconcileFileSystemV2::new(cas_root.install_root());
    let proofs = audit_staging_files_v2(plan, &mut filesystem)
        .map_err(|error| classify_staging_error(error, committed_staging_observed))?;
    cas_root
        .revalidate()
        .map_err(ReconcileExecutorErrorV2::InvalidScope)
        .map_err(|error| classify_staging_error(error, committed_staging_observed))?;
    Ok(ReconcileStagingFilesV2 { binding, proofs })
}

fn staging_partial_matches(
    partial: &mut ResumableManagedFile,
    payload: &ReconcileStagingPayloadV2<'_>,
    cas_root: &OwnedCasRoot,
    expected_size: u64,
) -> Result<bool, ReconcileExecutorErrorV2> {
    match payload {
        ReconcileStagingPayloadV2::ExactCas(object) => {
            let mut source = object.open(cas_root).map_err(|error| {
                ReconcileExecutorErrorV2::Filesystem(format!(
                    "cannot open sealed CAS source for prefix audit: {error}"
                ))
            })?;
            partial
                .matches_reader_prefix(&mut source, expected_size)
                .map_err(|error| ReconcileExecutorErrorV2::Filesystem(error.to_string()))
        }
        ReconcileStagingPayloadV2::CanonicalMutable(bytes) => partial
            .matches_bytes_prefix(bytes, expected_size)
            .map_err(|error| ReconcileExecutorErrorV2::Filesystem(error.to_string())),
    }
}

fn stream_staging_payload<C>(
    payload: &mut ReconcileStagingPayloadV2<'_>,
    cas_root: &OwnedCasRoot,
    destination: &mut ResumableManagedFile,
    mut offset: u64,
    expected: &ExpectedStagingSlotV2,
    checkpoint: &mut C,
    committed_staging_observed: bool,
) -> Result<(), ReconcileExecutorErrorV2>
where
    C: FnMut(StagingWriterCheckpointV2) -> Result<(), StagingWriterCheckpointErrorV2>,
{
    match payload {
        ReconcileStagingPayloadV2::ExactCas(object) => {
            let mut source = object.open(cas_root).map_err(|error| {
                ReconcileExecutorErrorV2::Filesystem(format!(
                    "cannot reopen sealed CAS staging source: {error}"
                ))
            })?;
            source.seek(SeekFrom::Start(offset)).map_err(|error| {
                ReconcileExecutorErrorV2::Filesystem(format!(
                    "cannot seek sealed CAS staging source: {error}"
                ))
            })?;
            let mut buffer = vec![0_u8; STAGING_COPY_BUFFER_BYTES];
            loop {
                let read = source.read(&mut buffer).map_err(|error| {
                    ReconcileExecutorErrorV2::Filesystem(format!(
                        "cannot read sealed CAS staging source: {error}"
                    ))
                })?;
                if read == 0 {
                    break;
                }
                offset = destination
                    .write_all_at(offset, &buffer[..read])
                    .map_err(|error| ReconcileExecutorErrorV2::Filesystem(error.to_string()))?;
                if let Err(error) = checkpoint(StagingWriterCheckpointV2::Chunk {
                    staging_slot: expected.slot,
                    written_bytes: offset,
                    total_bytes: expected.size,
                }) {
                    destination.sync_all().map_err(|sync_error| {
                        classify_staging_error(
                            ReconcileExecutorErrorV2::Filesystem(format!(
                                "staging cancellation failed to flush its resumable prefix: {sync_error}; cancellation: {error}"
                            )),
                            committed_staging_observed,
                        )
                    })?;
                    return Err(checkpoint_error_before_commit(
                        error,
                        committed_staging_observed,
                    ));
                }
            }
            source
                .revalidate()
                .map_err(|error| ReconcileExecutorErrorV2::Filesystem(error.to_string()))?;
        }
        ReconcileStagingPayloadV2::CanonicalMutable(bytes) => {
            let start = usize::try_from(offset).map_err(|_| {
                ReconcileExecutorErrorV2::InvalidStagingProof(
                    "mutable staging resume offset exceeds memory bounds".into(),
                )
            })?;
            for chunk in bytes[start..].chunks(STAGING_COPY_BUFFER_BYTES) {
                offset = destination
                    .write_all_at(offset, chunk)
                    .map_err(|error| ReconcileExecutorErrorV2::Filesystem(error.to_string()))?;
                if let Err(error) = checkpoint(StagingWriterCheckpointV2::Chunk {
                    staging_slot: expected.slot,
                    written_bytes: offset,
                    total_bytes: expected.size,
                }) {
                    destination.sync_all().map_err(|sync_error| {
                        classify_staging_error(
                            ReconcileExecutorErrorV2::Filesystem(format!(
                                "staging cancellation failed to flush its resumable prefix: {sync_error}; cancellation: {error}"
                            )),
                            committed_staging_observed,
                        )
                    })?;
                    return Err(checkpoint_error_before_commit(
                        error,
                        committed_staging_observed,
                    ));
                }
            }
        }
    }
    if offset != expected.size {
        return Err(ReconcileExecutorErrorV2::InvalidStagingProof(
            "sealed staging source length changed".into(),
        ));
    }
    Ok(())
}

fn checkpoint_error_before_commit(
    error: StagingWriterCheckpointErrorV2,
    committed_staging_observed: bool,
) -> ReconcileExecutorErrorV2 {
    match error {
        StagingWriterCheckpointErrorV2::Cancelled if !committed_staging_observed => {
            ReconcileExecutorErrorV2::Cancelled
        }
        StagingWriterCheckpointErrorV2::Cancelled => ReconcileExecutorErrorV2::Interrupted(
            "staging writer was cancelled after a prior committed staging mutation".into(),
        ),
        StagingWriterCheckpointErrorV2::Failed(message) => {
            ReconcileExecutorErrorV2::Interrupted(message)
        }
    }
}

fn checkpoint_error_after_commit(
    error: StagingWriterCheckpointErrorV2,
) -> ReconcileExecutorErrorV2 {
    match error {
        StagingWriterCheckpointErrorV2::Cancelled => ReconcileExecutorErrorV2::Interrupted(
            "staging writer was cancelled after a committed staging mutation".into(),
        ),
        StagingWriterCheckpointErrorV2::Failed(message) => {
            ReconcileExecutorErrorV2::Interrupted(message)
        }
    }
}

fn map_staging_commit_error(
    error: ManagedFsError,
    committed_staging_observed: bool,
) -> ReconcileExecutorErrorV2 {
    let applied = matches!(
        error,
        ManagedFsError::AppliedButDurabilityUnconfirmed { .. }
    );
    let error = ReconcileExecutorErrorV2::Filesystem(error.to_string());
    classify_staging_error(error, applied || committed_staging_observed)
}

fn classify_staging_error(
    error: ReconcileExecutorErrorV2,
    committed_staging_observed: bool,
) -> ReconcileExecutorErrorV2 {
    if !committed_staging_observed || matches!(error, ReconcileExecutorErrorV2::Interrupted(_)) {
        return error;
    }
    ReconcileExecutorErrorV2::Interrupted(format!(
        "staging writer stopped after a committed staging mutation: {error}"
    ))
}

fn validate_live_payload(
    payload: &ReconcileStagingPayloadV2<'_>,
    cas_root: &OwnedCasRoot,
) -> Result<(), ReconcileExecutorErrorV2> {
    match payload {
        ReconcileStagingPayloadV2::ExactCas(object) => object
            .open(cas_root)
            .map(drop)
            .map_err(|error| ReconcileExecutorErrorV2::Filesystem(error.to_string())),
        ReconcileStagingPayloadV2::CanonicalMutable(_) => Ok(()),
    }
}

fn require_exact_existing_staging_file(
    install_root: &Path,
    path: &RelativeManagedPath,
    expected: &ExpectedStagingSlotV2,
    required: bool,
) -> Result<bool, ReconcileExecutorErrorV2> {
    match fs::symlink_metadata(path.join_to(install_root)) {
        Err(error) if error.kind() == ErrorKind::NotFound && !required => return Ok(false),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(ReconcileExecutorErrorV2::Conflict(format!(
                "required staging slot {} is missing",
                expected.slot
            )))
        }
        Err(error) => {
            return Err(ReconcileExecutorErrorV2::Filesystem(format!(
                "cannot inspect staging slot {}: {error}",
                expected.slot
            )))
        }
        Ok(_) => {}
    }
    let mut file = ImmutableManagedFile::open(install_root, path)
        .map_err(|error| ReconcileExecutorErrorV2::UnsafeNode(error.to_string()))?;
    let digest = file
        .sha256(expected.size)
        .map_err(|error| ReconcileExecutorErrorV2::UnsafeNode(error.to_string()))?;
    let executable = metadata_is_executable(
        &fs::metadata(path.join_to(install_root))
            .map_err(|error| ReconcileExecutorErrorV2::Filesystem(error.to_string()))?,
    );
    file.revalidate()
        .map_err(|error| ReconcileExecutorErrorV2::UnsafeNode(error.to_string()))?;
    if digest.size != expected.size
        || digest.sha256 != expected.sha256
        || executable != expected.executable
    {
        return Err(ReconcileExecutorErrorV2::Conflict(format!(
            "existing staging slot {} differs from the reconcile plan",
            expected.slot
        )));
    }
    Ok(true)
}

fn require_staging_topology(
    plan: &ReconcilePlanV2,
    install_root: &Path,
    allow_partials: bool,
) -> Result<(), ReconcileExecutorErrorV2> {
    let paths = ReconcileOperationPathsV2::from_plan(plan)?;
    let actual = list_managed_directory_children(install_root, &paths.staging_root)
        .map_err(ReconcileExecutorErrorV2::UnsafeNode)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut final_names = BTreeSet::new();
    let mut allowed = BTreeSet::new();
    for expected in expected_staging_slots(plan)? {
        let final_name = format!("{:08}.bin", expected.slot);
        final_names.insert(final_name.clone());
        allowed.insert(final_name);
        if allow_partials {
            allowed.insert(format!("{:08}.part", expected.slot));
        }
    }
    let valid = if allow_partials {
        actual.is_subset(&allowed)
    } else {
        actual == final_names
    };
    if !valid {
        return Err(ReconcileExecutorErrorV2::UnsafeNode(
            "staging directory contains missing, extra or non-canonical entries".into(),
        ));
    }
    Ok(())
}

fn payload_matches_policy(payload: &ReconcileStagingPayloadV2<'_>, policy: FilePolicy) -> bool {
    matches!(
        (payload, policy),
        (ReconcileStagingPayloadV2::ExactCas(_), FilePolicy::Exact)
            | (
                ReconcileStagingPayloadV2::CanonicalMutable(_),
                FilePolicy::ValidatedMutable
            )
    )
}

fn reject_unsupported_executable(
    expected: &ExpectedStagingSlotV2,
) -> Result<(), ReconcileExecutorErrorV2> {
    if cfg!(windows) && expected.executable {
        return Err(ReconcileExecutorErrorV2::InvalidPlan(format!(
            "Windows staging slot {} cannot carry a POSIX executable bit",
            expected.slot
        )));
    }
    Ok(())
}

fn validate_staging_scope(
    plan: &ReconcilePlanV2,
    operation_lock: &InstanceOperationLock,
    cas_root: &OwnedCasRoot,
) -> Result<(), ReconcileExecutorErrorV2> {
    validate_plan(plan)?;
    cas_root
        .revalidate()
        .map_err(ReconcileExecutorErrorV2::InvalidScope)?;
    operation_lock
        .validate_scope(cas_root.install_root(), plan.install_id, plan.channel)
        .map_err(|error| ReconcileExecutorErrorV2::InvalidScope(error.to_string()))?;
    let (_, root_install_id, _, _) = cas_root.binding();
    if root_install_id != plan.install_id {
        return Err(ReconcileExecutorErrorV2::InvalidScope(
            "owned CAS root belongs to another reconcile install".into(),
        ));
    }
    Ok(())
}

fn validate_authority_scope(
    authority: &TrustedReconcileStagingAuthorityV2<'_, '_>,
    operation_lock: &InstanceOperationLock,
    cas_root: &OwnedCasRoot,
) -> Result<(), ReconcileExecutorErrorV2> {
    cas_root
        .revalidate()
        .map_err(ReconcileExecutorErrorV2::InvalidScope)?;
    operation_lock
        .validate_scope(
            cas_root.install_root(),
            authority.binding.install_id,
            authority.binding.channel,
        )
        .map_err(|error| ReconcileExecutorErrorV2::InvalidScope(error.to_string()))?;
    let (root_binding_nonce, install_id, install_root_identity, objects_root_identity) =
        cas_root.binding();
    if authority.binding.root_binding_nonce != root_binding_nonce
        || authority.binding.install_id != install_id
        || authority.binding.install_root_identity != *install_root_identity
        || authority.binding.objects_root_identity != *objects_root_identity
    {
        return Err(ReconcileExecutorErrorV2::InvalidScope(
            "trusted reconcile staging authority belongs to another owned root".into(),
        ));
    }
    Ok(())
}

/// Recomputes the immutable plan/release catalog once at a staging batch boundary. Per-source
/// binds and just-in-time commit checks use only the constant-size live scope validation above;
/// the authority itself cannot be constructed outside this module or mutated after minting.
fn validate_authority_batch_scope(
    authority: &TrustedReconcileStagingAuthorityV2<'_, '_>,
    operation_lock: &InstanceOperationLock,
    cas_root: &OwnedCasRoot,
) -> Result<(), ReconcileExecutorErrorV2> {
    validate_authority_scope(authority, operation_lock, cas_root)?;
    validate_plan(authority.plan)?;
    validate_trusted_release_for_staging(authority.plan, authority.trusted_release)?;
    if authority.binding != reconcile_staging_binding(authority.plan, cas_root)?
        || authority.slots != canonical_staging_slots(authority.plan, authority.trusted_release)?
    {
        return Err(ReconcileExecutorErrorV2::InvalidScope(
            "trusted reconcile staging authority changed".into(),
        ));
    }
    Ok(())
}

fn authority_expected_slot<'authority>(
    authority: &'authority TrustedReconcileStagingAuthorityV2<'_, '_>,
    staging_slot: u32,
) -> Result<(usize, &'authority ExpectedStagingSlotV2), ReconcileExecutorErrorV2> {
    authority
        .slots
        .index_for_slot(staging_slot)
        .map(|index| (index, authority.slots.expected_at(index)))
        .ok_or_else(|| {
            ReconcileExecutorErrorV2::InvalidStagingProof(format!(
                "trusted reconcile authority has no staging slot {staging_slot}"
            ))
        })
}

fn reconcile_staging_binding(
    plan: &ReconcilePlanV2,
    cas_root: &OwnedCasRoot,
) -> Result<ReconcileStagingBindingV2, ReconcileExecutorErrorV2> {
    let canonical = plan
        .canonical_bytes()
        .map_err(ReconcileExecutorErrorV2::InvalidPlan)?;
    let (root_binding_nonce, _, install_root_identity, objects_root_identity) = cas_root.binding();
    Ok(ReconcileStagingBindingV2 {
        install_id: plan.install_id,
        channel: plan.channel,
        operation_id: plan.operation_id,
        plan_sha256: format!("{:x}", Sha256::digest(canonical)),
        root_binding_nonce,
        install_root_identity: install_root_identity.clone(),
        objects_root_identity: objects_root_identity.clone(),
    })
}

fn expected_staging_slots(
    plan: &ReconcilePlanV2,
) -> Result<Vec<ExpectedStagingSlotV2>, ReconcileExecutorErrorV2> {
    let desired = plan
        .desired_files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    plan.mutations
        .iter()
        .filter_map(|mutation| match mutation {
            JournalMutation::InstallFile {
                destination_path,
                staging_slot,
                size,
                sha256,
                executable,
            } => Some((destination_path, staging_slot, size, sha256, executable)),
            _ => None,
        })
        .map(
            |(destination_path, staging_slot, size, sha256, executable)| {
                let file = desired.get(destination_path.as_str()).ok_or_else(|| {
                    ReconcileExecutorErrorV2::InvalidPlan(format!(
                        "install slot {staging_slot} has no desired file"
                    ))
                })?;
                Ok(ExpectedStagingSlotV2 {
                    slot: *staging_slot,
                    destination_path: destination_path.clone(),
                    size: *size,
                    sha256: sha256.clone(),
                    executable: *executable,
                    policy: file.policy,
                    signed_size: file.signed_size,
                    signed_sha256: file.signed_sha256.clone(),
                })
            },
        )
        .collect()
}

fn canonical_staging_slots(
    plan: &ReconcilePlanV2,
    trusted_release: &TrustedRelease,
) -> Result<CanonicalStagingSlotsV2, ReconcileExecutorErrorV2> {
    let expected = expected_staging_slots(plan)?;
    let selected = trusted_release
        .manifest()
        .selected_preset(plan.target.preset)
        .map_err(ReconcileExecutorErrorV2::InvalidPlan)?;
    let manifest_by_path = selected
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    if manifest_by_path.len() != selected.files.len() {
        return Err(ReconcileExecutorErrorV2::InvalidPlan(
            "trusted preset contains duplicate staging paths".into(),
        ));
    }
    let mutable_policy_by_path = trusted_release
        .manifest()
        .integrity
        .mutable_settings
        .iter()
        .enumerate()
        .map(|(index, policy)| (policy.path.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    if mutable_policy_by_path.len() != trusted_release.manifest().integrity.mutable_settings.len() {
        return Err(ReconcileExecutorErrorV2::InvalidPlan(
            "trusted release contains duplicate mutable policy paths".into(),
        ));
    }

    let mut mutable_policy_index_by_expected = Vec::new();
    mutable_policy_index_by_expected
        .try_reserve_exact(expected.len())
        .map_err(|_| {
            ReconcileExecutorErrorV2::InvalidPlan(
                "trusted mutable staging index exceeds launcher memory bounds".into(),
            )
        })?;
    for slot in &expected {
        let manifest_file = manifest_by_path
            .get(slot.destination_path.as_str())
            .ok_or_else(|| {
                ReconcileExecutorErrorV2::InvalidPlan(format!(
                    "trusted preset is missing staging path {}",
                    slot.destination_path
                ))
            })?;
        if manifest_file.policy != slot.policy
            || manifest_file.size != slot.signed_size
            || manifest_file.sha256 != slot.signed_sha256
            || manifest_file.executable != slot.executable
        {
            return Err(ReconcileExecutorErrorV2::InvalidPlan(format!(
                "trusted manifest differs from reconcile slot {}",
                slot.slot
            )));
        }
        reject_unsupported_executable(slot)?;
        let mutable_policy_index = match slot.policy {
            FilePolicy::Exact => {
                if mutable_policy_by_path.contains_key(slot.destination_path.as_str()) {
                    return Err(ReconcileExecutorErrorV2::InvalidPlan(format!(
                        "exact staging slot {} unexpectedly has a mutable policy",
                        slot.slot
                    )));
                }
                None
            }
            FilePolicy::ValidatedMutable => Some(
                *mutable_policy_by_path
                    .get(slot.destination_path.as_str())
                    .ok_or_else(|| {
                        ReconcileExecutorErrorV2::InvalidPlan(format!(
                            "trusted release has no mutable policy for {}",
                            slot.destination_path
                        ))
                    })?,
            ),
        };
        mutable_policy_index_by_expected.push(mutable_policy_index);
    }
    CanonicalStagingSlotsV2::new(expected, mutable_policy_index_by_expected)
}

fn expected_staging_slot(
    plan: &ReconcilePlanV2,
    staging_slot: u32,
) -> Result<ExpectedStagingSlotV2, ReconcileExecutorErrorV2> {
    expected_staging_slots(plan)?
        .into_iter()
        .find(|expected| expected.slot == staging_slot)
        .ok_or_else(|| {
            ReconcileExecutorErrorV2::InvalidStagingProof(format!(
                "reconcile plan has no install staging slot {staging_slot}"
            ))
        })
}

fn validate_trusted_release_for_staging(
    plan: &ReconcilePlanV2,
    trusted_release: &TrustedRelease,
) -> Result<(), ReconcileExecutorErrorV2> {
    let manifest = trusted_release.manifest();
    if trusted_release.channel() != plan.channel
        || manifest.release.id != plan.target.release_id
        || !plan
            .target
            .trusted_release
            .targets_match_and_roles_are_monotonic_to(trusted_release.evidence())
        || trusted_release.evidence().release_manifest.sha256 != plan.target.release_manifest_sha256
        || trusted_release.evidence().java_runtime_lock.sha256 != plan.target.runtime_lock_sha256
        || trusted_release.evidence().game_runtime_lock.sha256
            != plan.target.game_runtime_lock_sha256
        || manifest.selected_preset(plan.target.preset).is_err()
    {
        return Err(ReconcileExecutorErrorV2::InvalidPlan(
            "trusted release does not bind the reconcile target".into(),
        ));
    }
    Ok(())
}

struct StagingAuditV2<I> {
    by_slot: BTreeMap<u32, ExecutorNodeSnapshotV2<I>>,
    proofs: Vec<StagingFileProofV2>,
}

/// Rebuilds staging proofs from deterministic paths and leased, no-follow file hashes.
fn audit_staging_files_v2<F: ReconcileFileSystemV2>(
    plan: &ReconcilePlanV2,
    filesystem: &mut F,
) -> Result<Vec<StagingFileProofV2>, ReconcileExecutorErrorV2> {
    validate_plan(plan)?;
    let paths = ReconcileOperationPathsV2::from_plan(plan)?;
    Ok(audit_staging_internal(plan, filesystem, &paths)?.proofs)
}

/// Collision-normalized roots which are still physically present but logically absent after the
/// pending quarantine prefix is simulated. A destination query walks only its bounded ancestors;
/// it never scans the quarantine set. Plan validation has already bounded path depth and rejected
/// overlapping quarantine roots, so admission is O(depth * log Q) with constant-bounded depth.
#[derive(Default)]
struct PendingQuarantinePathIndexV2 {
    roots: BTreeSet<String>,
}

impl PendingQuarantinePathIndexV2 {
    fn insert(&mut self, manifest_path: &str) -> Result<(), ReconcileExecutorErrorV2> {
        let path = managed_path(manifest_path)?;
        if !self.roots.insert(path.collision_key().to_owned()) {
            return Err(ReconcileExecutorErrorV2::InvalidPlan(format!(
                "pending quarantine path is duplicated: {manifest_path}"
            )));
        }
        #[cfg(test)]
        PENDING_QUARANTINE_INDEX_INSERTS.with(|count| count.set(count.get() + 1));
        Ok(())
    }

    fn contains_ancestor(&self, manifest_path: &str) -> Result<bool, ReconcileExecutorErrorV2> {
        #[cfg(test)]
        PENDING_QUARANTINE_INDEX_QUERIES.with(|count| count.set(count.get() + 1));
        let path = managed_path(manifest_path)?;
        let mut candidate = path.collision_key();
        loop {
            #[cfg(test)]
            PENDING_QUARANTINE_INDEX_PROBES.with(|count| count.set(count.get() + 1));
            if self.roots.contains(candidate) {
                return Ok(true);
            }
            let Some((parent, _)) = candidate.rsplit_once('/') else {
                return Ok(false);
            };
            candidate = parent;
        }
    }
}

/// Audits the exact crash prefix without mutating it and returns only bytes which still need a
/// second physical instance allocation. Retained staging is already allocated; exact destination,
/// install-temporary and rollback files can be completed by rename and therefore cost zero.
fn audit_remaining_destination_bytes<F: ReconcileFileSystemV2>(
    plan: &ReconcilePlanV2,
    filesystem: &mut F,
    allocation_unit: u64,
) -> Result<u64, ReconcileExecutorErrorV2> {
    validate_plan(plan)?;
    if allocation_unit == 0 {
        return Err(ReconcileExecutorErrorV2::Filesystem(
            "filesystem reported a zero allocation unit".into(),
        ));
    }
    let paths = ReconcileOperationPathsV2::from_plan(plan)?;
    let recreated_paths = RecreatedPathIndexV2::from_plan(plan)?;
    let mut remaining = 0_u64;
    for directory in [
        &paths.backup_root,
        &paths.rollback_root,
        &paths.replacement_root,
        &paths.temporary_root,
        &paths.instance_root,
    ] {
        match inspect(filesystem, directory)? {
            Some(node) if node.kind == ExecutorNodeKindV2::RealDirectory => {}
            Some(_) => {
                return Err(conflict(format!(
                    "pending disk audit workspace path is not a real directory: {}",
                    directory.as_str()
                )))
            }
            None => {
                remaining = checked_remaining_destination_sum(remaining, allocation_unit)?;
            }
        }
    }

    // Classify quarantine mutations first. The live tree is one crash prefix, while the audit is
    // a read-only simulation of canonical mutation order. If a quarantine is still pending, its
    // old source subtree must be treated as logically absent by every later Ensure/Install even
    // though it is still physically visible. If its backup already exists, a same-path source may
    // legitimately be the directory/file recreated by a later mutation in the same plan.
    let mut pending_quarantine_roots = PendingQuarantinePathIndexV2::default();
    for mutation in &plan.mutations {
        let JournalMutation::Quarantine {
            source_path,
            backup_slot,
        } = mutation
        else {
            continue;
        };
        let source = paths.instance_path(source_path)?;
        let backup = paths.backup_node(*backup_slot)?;
        let source_node = inspect(filesystem, &source)?;
        let backup_node = inspect(filesystem, &backup)?;
        match (source_node, backup_node) {
            (Some(source_node), None) => {
                require_movable(&source_node, &source)?;
                remaining = checked_remaining_destination_sum(remaining, allocation_unit)?;
                pending_quarantine_roots.insert(source_path)?;
            }
            (None, Some(backup_node)) => require_movable(&backup_node, &backup)?,
            (Some(source_node), Some(backup_node)) if recreated_paths.recreates(source_path) => {
                require_movable(&source_node, &source)?;
                require_movable(&backup_node, &backup)?;
                validate_recreated_quarantine_source(
                    &recreated_paths,
                    source_path,
                    filesystem,
                    &paths,
                )?;
            }
            (Some(_), Some(_)) => {
                return Err(conflict(format!(
                    "pending disk audit found both quarantine source {} and backup {}",
                    source.as_str(),
                    backup.as_str()
                )))
            }
            (None, None) => {
                return Err(conflict(format!(
                    "pending disk audit found neither quarantine source {} nor backup {}",
                    source.as_str(),
                    backup.as_str()
                )))
            }
        }
    }

    for mutation in &plan.mutations {
        match mutation {
            JournalMutation::Quarantine { .. } => {}
            JournalMutation::EnsureDirectory { destination_path } => {
                let destination = paths.instance_path(destination_path)?;
                if pending_quarantine_roots.contains_ancestor(destination_path)? {
                    remaining = checked_remaining_destination_sum(remaining, allocation_unit)?;
                } else if let Some(node) = inspect(filesystem, &destination)? {
                    if node.kind != ExecutorNodeKindV2::RealDirectory {
                        return Err(conflict(format!(
                            "pending disk audit directory is occupied by a non-directory: {}",
                            destination.as_str()
                        )));
                    }
                } else {
                    remaining = checked_remaining_destination_sum(remaining, allocation_unit)?;
                }
            }
            JournalMutation::InstallFile {
                destination_path,
                staging_slot,
                size,
                sha256,
                executable,
            } => {
                let destination = paths.instance_path(destination_path)?;
                let rollback = paths.rollback_node(*staging_slot)?;
                let temporary = paths.install_temporary(*staging_slot)?;
                let rollback_node = inspect(filesystem, &rollback)?;
                let temporary_node = inspect(filesystem, &temporary)?;
                if pending_quarantine_roots.contains_ancestor(destination_path)? {
                    if rollback_node.is_some() || temporary_node.is_some() {
                        return Err(conflict(format!(
                            "pending disk audit found a later install crash artifact before quarantine: {}",
                            destination.as_str()
                        )));
                    }
                    remaining = checked_remaining_destination_sum(
                        remaining,
                        round_up_allocation(*size, allocation_unit)?,
                    )?;
                    remaining = checked_remaining_destination_sum(
                        remaining,
                        allocation_unit.checked_mul(2).ok_or_else(|| {
                            ReconcileExecutorErrorV2::InvalidPlan(
                                "pending reconcile namespace reserve overflowed".into(),
                            )
                        })?,
                    )?;
                    continue;
                }
                let destination_node = inspect(filesystem, &destination)?;
                let expected = ExecutorFileBindingV2 {
                    size: *size,
                    sha256: sha256.clone(),
                    executable: *executable,
                };
                if let Some(temporary_node) = temporary_node {
                    if destination_node.is_some() || rollback_node.is_some() {
                        return Err(conflict(format!(
                            "pending disk audit temporary {} coexists with destination or rollback",
                            temporary.as_str()
                        )));
                    }
                    let actual = regular_binding(&temporary_node, &temporary)?;
                    if actual == &expected {
                        remaining = checked_remaining_destination_sum(remaining, allocation_unit)?;
                        continue;
                    }
                    if actual.size > expected.size {
                        return Err(conflict(format!(
                            "pending install temporary exceeds its planned size: {}",
                            temporary.as_str()
                        )));
                    }
                    let expected_allocation = round_up_allocation(expected.size, allocation_unit)?;
                    let allocated = regular_allocated_size(&temporary_node, &temporary)?
                        .min(expected_allocation);
                    remaining = checked_remaining_destination_sum(
                        remaining,
                        expected_allocation.saturating_sub(allocated),
                    )?;
                    remaining = checked_remaining_destination_sum(remaining, allocation_unit)?;
                    continue;
                }
                match (destination_node, rollback_node) {
                    (Some(destination_node), None) => {
                        require_regular_binding(&destination_node, &expected, &destination, true)?;
                    }
                    (None, Some(rollback_node)) => {
                        require_regular_binding(&rollback_node, &expected, &rollback, true)?;
                        remaining = checked_remaining_destination_sum(remaining, allocation_unit)?;
                    }
                    (None, None) => {
                        remaining = checked_remaining_destination_sum(
                            remaining,
                            round_up_allocation(*size, allocation_unit)?,
                        )?;
                        remaining = checked_remaining_destination_sum(
                            remaining,
                            allocation_unit.checked_mul(2).ok_or_else(|| {
                                ReconcileExecutorErrorV2::InvalidPlan(
                                    "pending reconcile namespace reserve overflowed".into(),
                                )
                            })?,
                        )?;
                    }
                    (Some(_), Some(_)) => {
                        return Err(conflict(format!(
                            "pending disk audit found both destination {} and rollback {}",
                            destination.as_str(),
                            rollback.as_str()
                        )));
                    }
                }
            }
        }
    }
    Ok(remaining)
}

fn round_up_allocation(size: u64, allocation_unit: u64) -> Result<u64, ReconcileExecutorErrorV2> {
    if allocation_unit == 0 || size == 0 {
        return Ok(0);
    }
    let remainder = size % allocation_unit;
    if remainder == 0 {
        return Ok(size);
    }
    size.checked_add(allocation_unit - remainder)
        .ok_or_else(|| {
            ReconcileExecutorErrorV2::InvalidPlan(
                "pending reconcile allocation rounding overflowed".into(),
            )
        })
}

fn regular_allocated_size<I>(
    node: &ExecutorNodeSnapshotV2<I>,
    path: &RelativeManagedPath,
) -> Result<u64, ReconcileExecutorErrorV2> {
    match &node.kind {
        ExecutorNodeKindV2::RegularFile {
            link_count: 1,
            allocated_size,
            ..
        } => Ok(*allocated_size),
        ExecutorNodeKindV2::RegularFile { link_count, .. } => {
            Err(ReconcileExecutorErrorV2::UnsafeNode(format!(
                "regular file has {link_count} hard links: {}",
                path.as_str()
            )))
        }
        _ => Err(ReconcileExecutorErrorV2::UnsafeNode(format!(
            "expected a regular no-follow file: {}",
            path.as_str()
        ))),
    }
}

fn checked_remaining_destination_sum(
    current: u64,
    additional: u64,
) -> Result<u64, ReconcileExecutorErrorV2> {
    current.checked_add(additional).ok_or_else(|| {
        ReconcileExecutorErrorV2::InvalidPlan(
            "pending reconcile remaining destination bytes overflowed".into(),
        )
    })
}

#[cfg(windows)]
fn filesystem_allocation_unit(root: &Path) -> Result<u64, ReconcileExecutorErrorV2> {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        core::PCWSTR,
        Win32::Storage::FileSystem::{GetDiskFreeSpaceW, GetVolumePathNameW},
    };

    let path = root
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut volume = vec![0_u16; 32_768];
    unsafe { GetVolumePathNameW(PCWSTR(path.as_ptr()), &mut volume) }.map_err(|error| {
        ReconcileExecutorErrorV2::Filesystem(format!(
            "cannot resolve pending reconcile volume: {error}"
        ))
    })?;
    let mut sectors_per_cluster = 0_u32;
    let mut bytes_per_sector = 0_u32;
    unsafe {
        GetDiskFreeSpaceW(
            PCWSTR(volume.as_ptr()),
            Some(&mut sectors_per_cluster),
            Some(&mut bytes_per_sector),
            None,
            None,
        )
    }
    .map_err(|error| {
        ReconcileExecutorErrorV2::Filesystem(format!(
            "cannot query pending reconcile allocation unit: {error}"
        ))
    })?;
    u64::from(sectors_per_cluster)
        .checked_mul(u64::from(bytes_per_sector))
        .filter(|unit| *unit != 0)
        .ok_or_else(|| {
            ReconcileExecutorErrorV2::Filesystem(
                "filesystem reported an invalid allocation unit".into(),
            )
        })
}

#[cfg(unix)]
fn filesystem_allocation_unit(root: &Path) -> Result<u64, ReconcileExecutorErrorV2> {
    use std::os::unix::fs::MetadataExt;
    let unit = fs::metadata(root)
        .map_err(|error| {
            ReconcileExecutorErrorV2::Filesystem(format!(
                "cannot inspect pending reconcile filesystem: {error}"
            ))
        })?
        .blksize();
    if unit == 0 {
        return Err(ReconcileExecutorErrorV2::Filesystem(
            "filesystem reported an invalid allocation unit".into(),
        ));
    }
    Ok(unit)
}

#[cfg(not(any(windows, unix)))]
fn filesystem_allocation_unit(_root: &Path) -> Result<u64, ReconcileExecutorErrorV2> {
    Ok(4096)
}

/// Production roll-forward boundary. Raw staging proofs are deliberately not accepted outside
/// this module: the caller must consume the capability produced by the trusted staging writer.
pub(super) fn roll_forward_staged_v2(
    authority: &TrustedReconcileStagingAuthorityV2<'_, '_>,
    operation_lock: &InstanceOperationLock,
    cas_root: &OwnedCasRoot,
    staged: ReconcileStagingFilesV2,
) -> Result<ReconcileExecutionReportV2, ReconcileExecutorErrorV2> {
    let disk = authority.assess_remaining_space(&staged, operation_lock, cas_root)?;
    disk.require_fits(authority)?;
    let proofs = staged
        .proofs_for(authority, operation_lock, cas_root)?
        .to_vec();
    let mut filesystem = ManagedReconcileFileSystemV2::new(cas_root.install_root());
    roll_forward_with_checkpoint_v2(
        authority.plan,
        operation_lock,
        &proofs,
        &mut filesystem,
        |_| Ok(()),
    )
}

/// Applies a plan in journal order. The caller must have loaded this exact plan through
/// `journal::detect_pending`; this function independently revalidates its scope, proofs and every
/// filesystem postcondition. Staging files are copied, never consumed.
#[cfg(test)]
pub(super) fn roll_forward_v2<F: ReconcileFileSystemV2>(
    plan: &ReconcilePlanV2,
    operation_lock: &InstanceOperationLock,
    staging_proofs: &[StagingFileProofV2],
    filesystem: &mut F,
) -> Result<ReconcileExecutionReportV2, ReconcileExecutorErrorV2> {
    roll_forward_with_checkpoint_v2(plan, operation_lock, staging_proofs, filesystem, |_| Ok(()))
}

/// Same state machine as `roll_forward_v2`, with a callback after each durable/idempotent
/// mutation. A callback error never rolls the mutation back; recovery must rerun the plan.
fn roll_forward_with_checkpoint_v2<F, C>(
    plan: &ReconcilePlanV2,
    operation_lock: &InstanceOperationLock,
    staging_proofs: &[StagingFileProofV2],
    filesystem: &mut F,
    mut checkpoint: C,
) -> Result<ReconcileExecutionReportV2, ReconcileExecutorErrorV2>
where
    F: ReconcileFileSystemV2,
    C: FnMut(&MutationExecutionV2) -> Result<(), String>,
{
    validate_scope(plan, operation_lock, filesystem.install_root())?;
    let paths = ReconcileOperationPathsV2::from_plan(plan)?;
    let recreated_paths = RecreatedPathIndexV2::from_plan(plan)?;
    prepare_workspace(filesystem, &paths)?;
    let staging = audit_staging_internal(plan, filesystem, &paths)?;
    require_exact_proofs(staging_proofs, &staging.proofs)?;
    let limits = operation_garbage_limits().map_err(ReconcileExecutorErrorV2::InvalidPlan)?;
    let mut whole_tree_moves = preflight_whole_tree_moves_v2(
        plan,
        filesystem,
        &paths,
        WholeTreeMoveDirectionV2::RollForward,
        limits,
    )?;
    whole_tree_moves.validate_for(
        plan,
        filesystem.install_root(),
        WholeTreeMoveDirectionV2::RollForward,
    )?;

    let mut report = ReconcileExecutionReportV2 {
        mutations: Vec::with_capacity(plan.mutations.len()),
    };
    for (mutation_index, mutation) in plan.mutations.iter().enumerate() {
        let disposition = match mutation {
            JournalMutation::Quarantine {
                source_path,
                backup_slot,
            } => {
                let move_reservation = whole_tree_moves.into_operation[mutation_index].take();
                roll_forward_quarantine(
                    filesystem,
                    &mut whole_tree_moves.capacity_ledger,
                    QuarantineMutationPathsV2 {
                        source_manifest_path: source_path,
                        operation_paths: &paths,
                        recreated_paths: &recreated_paths,
                        source: &paths.instance_path(source_path)?,
                        backup: &paths.backup_node(*backup_slot)?,
                    },
                    move_reservation,
                )
            }
            JournalMutation::EnsureDirectory { destination_path } => {
                roll_forward_directory(filesystem, &paths.instance_path(destination_path)?)
            }
            JournalMutation::InstallFile {
                destination_path,
                staging_slot,
                size,
                sha256,
                executable,
            } => {
                let expected_source = staging.by_slot.get(staging_slot).ok_or_else(|| {
                    ReconcileExecutorErrorV2::InvalidStagingProof(format!(
                        "staging slot {staging_slot} disappeared from its audit"
                    ))
                })?;
                roll_forward_install(
                    filesystem,
                    InstallMutationPathsV2 {
                        staging: &paths.staging_file(*staging_slot)?,
                        destination: &paths.instance_path(destination_path)?,
                        rollback: &paths.rollback_node(*staging_slot)?,
                        temporary: &paths.install_temporary(*staging_slot)?,
                    },
                    expected_source,
                    &ExecutorFileBindingV2 {
                        size: *size,
                        sha256: sha256.clone(),
                        executable: *executable,
                    },
                    &mut whole_tree_moves.capacity_ledger,
                )
            }
        };
        let disposition = mutation_result_after_prior_applied(disposition, &report)?;
        let execution = MutationExecutionV2 {
            mutation_index,
            disposition,
        };
        report.mutations.push(execution.clone());
        checkpoint(&execution).map_err(ReconcileExecutorErrorV2::Interrupted)?;
    }
    drop(staging);
    require_exact_operation_workspace_topology(
        plan,
        filesystem,
        &paths,
        WholeTreeMoveDirectionV2::RollForward,
    )
    .map_err(|error| {
        if report.applied_count() == 0 {
            error
        } else {
            applied_mutation_error("roll-forward final workspace audit", error)
        }
    })?;
    audit_final_operation_root_capacity(filesystem, &whole_tree_moves.capacity_ledger).map_err(
        |error| {
            if report.applied_count() == 0 {
                error
            } else {
                applied_mutation_error("roll-forward final operation-root audit", error)
            }
        },
    )?;
    drop(whole_tree_moves);
    Ok(report)
}

/// Reverses every possibly applied mutation in reverse journal order. It intentionally does not
/// require staging proofs: rollback is the safe decision when staging is incomplete. Installed
/// files are moved to deterministic rollback slots rather than deleted; created directories are
/// left in place, so this function never performs recursive deletion.
#[cfg(test)]
pub(super) fn rollback_v2<F: ReconcileFileSystemV2>(
    plan: &ReconcilePlanV2,
    operation_lock: &InstanceOperationLock,
    filesystem: &mut F,
) -> Result<RollbackExecutionResultV2, ReconcileExecutorErrorV2> {
    rollback_with_checkpoint_v2(plan, operation_lock, filesystem, |_| Ok(()))
}

fn rollback_with_checkpoint_v2<F, C>(
    plan: &ReconcilePlanV2,
    operation_lock: &InstanceOperationLock,
    filesystem: &mut F,
    mut checkpoint: C,
) -> Result<RollbackExecutionResultV2, ReconcileExecutorErrorV2>
where
    F: ReconcileFileSystemV2,
    C: FnMut(&MutationExecutionV2) -> Result<(), String>,
{
    validate_scope(plan, operation_lock, filesystem.install_root())?;
    let paths = ReconcileOperationPathsV2::from_plan(plan)?;
    let recreated_paths = RecreatedPathIndexV2::from_plan(plan)?;
    prepare_workspace(filesystem, &paths)?;
    let limits = operation_garbage_limits().map_err(ReconcileExecutorErrorV2::InvalidPlan)?;
    let mut whole_tree_moves = preflight_whole_tree_moves_v2(
        plan,
        filesystem,
        &paths,
        WholeTreeMoveDirectionV2::Rollback,
        limits,
    )?;
    whole_tree_moves.validate_for(
        plan,
        filesystem.install_root(),
        WholeTreeMoveDirectionV2::Rollback,
    )?;
    let mut report = ReconcileExecutionReportV2 {
        mutations: Vec::with_capacity(plan.mutations.len()),
    };

    for (mutation_index, mutation) in plan.mutations.iter().enumerate().rev() {
        let disposition = match mutation {
            JournalMutation::InstallFile {
                destination_path,
                staging_slot,
                size,
                sha256,
                executable,
            } => rollback_install(
                filesystem,
                &paths.instance_path(destination_path)?,
                &paths.rollback_node(*staging_slot)?,
                &ExecutorFileBindingV2 {
                    size: *size,
                    sha256: sha256.clone(),
                    executable: *executable,
                },
                &mut whole_tree_moves.capacity_ledger,
            ),
            JournalMutation::EnsureDirectory { destination_path } => {
                rollback_directory(filesystem, &paths.instance_path(destination_path)?)
            }
            JournalMutation::Quarantine {
                source_path,
                backup_slot,
            } => {
                let replacement_reservation =
                    whole_tree_moves.into_operation[mutation_index].take();
                let restore_reservation = whole_tree_moves.out_of_operation[mutation_index].take();
                rollback_quarantine(
                    filesystem,
                    &mut whole_tree_moves.capacity_ledger,
                    &paths.instance_path(source_path)?,
                    &paths.backup_node(*backup_slot)?,
                    recreated_paths
                        .recreates(source_path)
                        .then(|| paths.replacement_node(*backup_slot))
                        .transpose()?
                        .as_ref(),
                    replacement_reservation,
                    restore_reservation,
                )
            }
        };
        let disposition = mutation_result_after_prior_applied(disposition, &report)?;
        let execution = MutationExecutionV2 {
            mutation_index,
            disposition,
        };
        report.mutations.push(execution.clone());
        checkpoint(&execution).map_err(ReconcileExecutorErrorV2::Interrupted)?;
    }
    require_exact_operation_workspace_topology(
        plan,
        filesystem,
        &paths,
        WholeTreeMoveDirectionV2::Rollback,
    )
    .map_err(|error| {
        if report.applied_count() == 0 {
            error
        } else {
            applied_mutation_error("rollback final workspace audit", error)
        }
    })?;
    audit_final_operation_root_capacity(filesystem, &whole_tree_moves.capacity_ledger).map_err(
        |error| {
            if report.applied_count() == 0 {
                error
            } else {
                applied_mutation_error("rollback final operation-root audit", error)
            }
        },
    )?;
    drop(whole_tree_moves);
    let completion = RollbackCompletionAuthorizationV2::from_completed_plan(plan)
        .map_err(ReconcileExecutorErrorV2::InvalidPlan)?;
    Ok(RollbackExecutionResultV2 { report, completion })
}

fn mutation_result_after_prior_applied(
    result: Result<MutationDispositionV2, ReconcileExecutorErrorV2>,
    report: &ReconcileExecutionReportV2,
) -> Result<MutationDispositionV2, ReconcileExecutorErrorV2> {
    match result {
        Ok(disposition) => Ok(disposition),
        Err(error) if report.applied_count() != 0 => Err(ReconcileExecutorErrorV2::Interrupted(
            format!("whole reconcile attempt stopped after a prior durable mutation: {error}"),
        )),
        Err(error) => Err(error),
    }
}

fn validate_plan(plan: &ReconcilePlanV2) -> Result<(), ReconcileExecutorErrorV2> {
    plan.validate(plan.install_id, plan.channel)
        .map_err(ReconcileExecutorErrorV2::InvalidPlan)
}

fn validate_scope(
    plan: &ReconcilePlanV2,
    operation_lock: &InstanceOperationLock,
    install_root: &Path,
) -> Result<(), ReconcileExecutorErrorV2> {
    validate_plan(plan)?;
    operation_lock
        .validate_scope(install_root, plan.install_id, plan.channel)
        .map_err(|error| ReconcileExecutorErrorV2::InvalidScope(error.to_string()))
}

fn prepare_workspace<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    paths: &ReconcileOperationPathsV2,
) -> Result<(), ReconcileExecutorErrorV2> {
    let mut workspace_mutated = false;
    for directory in [
        &paths.operation_root,
        &paths.staging_root,
        &paths.backup_root,
        &paths.rollback_root,
        &paths.replacement_root,
        &paths.temporary_root,
        &paths.instance_root,
    ] {
        let created = match filesystem.ensure_real_directory(directory) {
            Ok(created) => created,
            Err(error) => {
                let error = executor_mutation_error(error);
                return Err(if workspace_mutated {
                    applied_mutation_error("reconcile workspace preparation", error)
                } else {
                    error
                });
            }
        };
        require_real_directory(filesystem, directory).map_err(|error| {
            let error = ReconcileExecutorErrorV2::Filesystem(format!(
                "cannot revalidate reconcile workspace directory {}: {error}",
                directory.as_str()
            ));
            if workspace_mutated || created {
                applied_mutation_error("reconcile workspace directory creation", error)
            } else {
                error
            }
        })?;
        workspace_mutated |= created;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WholeTreeMoveDirectionV2 {
    RollForward,
    Rollback,
}

struct ReservedWholeTreeMoveV2<I> {
    install_root: PathBuf,
    operation_root: RelativeManagedPath,
    source: RelativeManagedPath,
    destination: RelativeManagedPath,
    expected_root: ExecutorNodeSnapshotV2<I>,
    maximum_summary: ManagedDirectoryRemovalSummary,
    destination_depth_within_cleanup_root: usize,
    namespace_allocation_reserve: u64,
    increases_operation_root: bool,
    limits: ManagedDirectoryRemovalLimits,
}

#[derive(Clone, Copy)]
struct OperationRootCapacityV2<'a> {
    operation_root: &'a RelativeManagedPath,
    allocation_unit: u64,
    limits: ManagedDirectoryRemovalLimits,
}

struct OperationRootCapacityLedgerV2<I> {
    install_root: PathBuf,
    operation_root: RelativeManagedPath,
    expected_root: ExecutorNodeSnapshotV2<I>,
    current: ManagedDirectoryRemovalSummary,
    allocation_unit: u64,
    limits: ManagedDirectoryRemovalLimits,
}

#[derive(Debug, Clone, Copy)]
struct OperationRootGrowthReservationV2 {
    before: ManagedDirectoryRemovalSummary,
    after: ManagedDirectoryRemovalSummary,
}

#[derive(Debug, Clone, Copy)]
struct OperationRootRemovalReservationV2 {
    before: ManagedDirectoryRemovalSummary,
    after: ManagedDirectoryRemovalSummary,
}

impl<I: Clone + Eq> OperationRootCapacityLedgerV2<I> {
    fn reserve_growth(
        &self,
        candidate: ManagedDirectoryRemovalSummary,
        destination_depth_within_cleanup_root: usize,
        namespace_allocation_reserve: u64,
    ) -> Result<OperationRootGrowthReservationV2, ReconcileExecutorErrorV2> {
        Ok(OperationRootGrowthReservationV2 {
            before: self.current,
            after: add_operation_root_growth(
                self.current,
                candidate,
                destination_depth_within_cleanup_root,
                namespace_allocation_reserve,
                self.limits,
            )?,
        })
    }

    fn commit_growth(
        &mut self,
        reservation: OperationRootGrowthReservationV2,
    ) -> Result<(), ReconcileExecutorErrorV2> {
        if self.current != reservation.before {
            return Err(ReconcileExecutorErrorV2::Interrupted(
                "operation-root capacity reservation became stale before commit".into(),
            ));
        }
        self.current = reservation.after;
        Ok(())
    }

    fn reserve_removal(
        &self,
        removed: ManagedDirectoryRemovalSummary,
    ) -> Result<OperationRootRemovalReservationV2, ReconcileExecutorErrorV2> {
        let entries = self
            .current
            .entries
            .checked_sub(removed.entries)
            .ok_or_else(|| {
                ReconcileExecutorErrorV2::UnsafeNode(
                    "operation-root entry ledger would underflow before removal".into(),
                )
            })?;
        let allocated_bytes = self
            .current
            .allocated_bytes
            .checked_sub(removed.allocated_bytes)
            .ok_or_else(|| {
                ReconcileExecutorErrorV2::UnsafeNode(
                    "operation-root allocation ledger would underflow before removal".into(),
                )
            })?;
        Ok(OperationRootRemovalReservationV2 {
            before: self.current,
            after: ManagedDirectoryRemovalSummary {
                entries,
                allocated_bytes,
                // `max_depth` and every namespace allocation reserve are sticky conservative
                // charges. Directory indexes need not shrink when entries are removed; a restart
                // rebuilds exact accounting from a fresh bounded audit.
                max_depth: self.current.max_depth,
            },
        })
    }

    fn validate_removal_reservation(
        &self,
        reservation: &OperationRootRemovalReservationV2,
    ) -> Result<(), ReconcileExecutorErrorV2> {
        if self.current != reservation.before {
            return Err(ReconcileExecutorErrorV2::UnsafeNode(
                "operation-root removal reservation became stale before mutation".into(),
            ));
        }
        Ok(())
    }

    fn commit_removal(
        &mut self,
        reservation: OperationRootRemovalReservationV2,
    ) -> Result<(), ReconcileExecutorErrorV2> {
        if self.current != reservation.before {
            return Err(ReconcileExecutorErrorV2::Interrupted(
                "operation-root removal reservation became stale before commit".into(),
            ));
        }
        self.current = reservation.after;
        // `max_depth` and every namespace allocation reserve are sticky conservative charges.
        // Directory indexes need not shrink when entries are removed; a restart rebuilds exact
        // accounting from a fresh bounded audit.
        Ok(())
    }
}

struct WholeTreeMovePreflightV2<I> {
    install_root: PathBuf,
    install_id: uuid::Uuid,
    channel: super::types::BuildChannel,
    operation_id: uuid::Uuid,
    plan_sha256: String,
    direction: WholeTreeMoveDirectionV2,
    capacity_ledger: OperationRootCapacityLedgerV2<I>,
    into_operation: Vec<Option<ReservedWholeTreeMoveV2<I>>>,
    out_of_operation: Vec<Option<ReservedWholeTreeMoveV2<I>>>,
}

impl<I> WholeTreeMovePreflightV2<I> {
    fn validate_for(
        &self,
        plan: &ReconcilePlanV2,
        install_root: &Path,
        direction: WholeTreeMoveDirectionV2,
    ) -> Result<(), ReconcileExecutorErrorV2> {
        let digest = whole_tree_plan_sha256(plan)?;
        if self.install_root != install_root
            || self.install_id != plan.install_id
            || self.channel != plan.channel
            || self.operation_id != plan.operation_id
            || self.plan_sha256 != digest
            || self.direction != direction
        {
            return Err(ReconcileExecutorErrorV2::InvalidScope(
                "whole-tree preflight belongs to another plan, root or direction".into(),
            ));
        }
        Ok(())
    }
}

fn preflight_whole_tree_moves_v2<F: ReconcileFileSystemV2>(
    plan: &ReconcilePlanV2,
    filesystem: &mut F,
    paths: &ReconcileOperationPathsV2,
    direction: WholeTreeMoveDirectionV2,
    limits: ManagedDirectoryRemovalLimits,
) -> Result<WholeTreeMovePreflightV2<F::Identity>, ReconcileExecutorErrorV2> {
    let recreated_paths = RecreatedPathIndexV2::from_plan(plan)?;
    require_exact_operation_workspace_topology(plan, filesystem, paths, direction)?;
    let baseline_root = inspect(filesystem, &paths.operation_root)
        .map_err(|error| {
            ReconcileExecutorErrorV2::Filesystem(format!(
                "cannot inspect operation root after exact topology audit: {error}"
            ))
        })?
        .ok_or_else(|| {
            ReconcileExecutorErrorV2::UnsafeNode(
                "reconcile operation root disappeared before bounded preflight".into(),
            )
        })?;
    if baseline_root.kind != ExecutorNodeKindV2::RealDirectory {
        return Err(ReconcileExecutorErrorV2::UnsafeNode(
            "reconcile operation root is not a real directory".into(),
        ));
    }
    let baseline = filesystem
        .lease_bounded_tree(&paths.operation_root, &baseline_root, limits)
        .map_err(ReconcileExecutorErrorV2::UnsafeNode)?;
    let baseline_summary = F::bounded_tree_lease_summary(&baseline);
    require_bounded_operation_summary(baseline_summary, limits)?;
    let mut aggregate = baseline_summary;
    let mut into_operation = std::iter::repeat_with(|| None)
        .take(plan.mutations.len())
        .collect::<Vec<_>>();
    let mut out_of_operation = std::iter::repeat_with(|| None)
        .take(plan.mutations.len())
        .collect::<Vec<_>>();
    for (mutation_index, mutation) in plan.mutations.iter().enumerate() {
        let JournalMutation::Quarantine {
            source_path,
            backup_slot,
        } = mutation
        else {
            continue;
        };
        let source = paths.instance_path(source_path)?;
        let backup = paths.backup_node(*backup_slot)?;
        let replacement = recreated_paths
            .recreates(source_path)
            .then(|| paths.replacement_node(*backup_slot))
            .transpose()?;
        let source_node = inspect(filesystem, &source)?;
        let backup_node = inspect(filesystem, &backup)?;
        match direction {
            WholeTreeMoveDirectionV2::RollForward => match (source_node, backup_node) {
                (Some(source_node), Some(backup_node))
                    if recreated_paths.recreates(source_path) =>
                {
                    require_movable(&source_node, &source)?;
                    require_movable(&backup_node, &backup)?;
                    validate_recreated_quarantine_source(
                        &recreated_paths,
                        source_path,
                        filesystem,
                        paths,
                    )?;
                }
                (Some(_), Some(_)) => {
                    return Err(conflict(format!(
                        "both quarantine source {} and backup {} exist during preflight",
                        source.as_str(),
                        backup.as_str()
                    )))
                }
                (None, None) => {
                    return Err(conflict(format!(
                        "neither quarantine source {} nor backup {} exists during preflight",
                        source.as_str(),
                        backup.as_str()
                    )))
                }
                (None, Some(backup_node)) => require_movable(&backup_node, &backup)?,
                (Some(source_node), None) => {
                    require_movable(&source_node, &source)?;
                    let (reservation, lease) = reserve_whole_tree_move_v2(
                        filesystem,
                        OperationRootCapacityV2 {
                            operation_root: &paths.operation_root,
                            allocation_unit: plan.disk_budget.allocation_unit_bytes,
                            limits,
                        },
                        &source,
                        &source_node,
                        &backup,
                        2,
                        true,
                    )?;
                    aggregate = add_operation_root_growth(
                        aggregate,
                        reservation.maximum_summary,
                        reservation.destination_depth_within_cleanup_root,
                        reservation.namespace_allocation_reserve,
                        limits,
                    )?;
                    filesystem
                        .revalidate_bounded_tree_lease(&lease)
                        .map_err(ReconcileExecutorErrorV2::UnsafeNode)?;
                    drop(lease);
                    into_operation[mutation_index] = Some(reservation);
                }
            },
            WholeTreeMoveDirectionV2::Rollback => match (source_node, backup_node) {
                (Some(source_node), Some(backup_node)) => {
                    let Some(replacement) = replacement.as_ref() else {
                        return Err(conflict(format!(
                            "both quarantine source {} and backup {} exist during rollback preflight",
                            source.as_str(),
                            backup.as_str()
                        )));
                    };
                    if inspect(filesystem, replacement)?.is_some() {
                        return Err(conflict(format!(
                            "replacement slot already exists during rollback preflight: {}",
                            replacement.as_str()
                        )));
                    }
                    require_movable(&source_node, &source)?;
                    require_movable(&backup_node, &backup)?;
                    let (replacement_reservation, replacement_lease) =
                        reserve_whole_tree_move_v2(
                            filesystem,
                            OperationRootCapacityV2 {
                                operation_root: &paths.operation_root,
                                allocation_unit: plan.disk_budget.allocation_unit_bytes,
                                limits,
                            },
                            &source,
                            &source_node,
                            replacement,
                            2,
                            true,
                        )?;
                    aggregate = add_operation_root_growth(
                        aggregate,
                        replacement_reservation.maximum_summary,
                        replacement_reservation.destination_depth_within_cleanup_root,
                        replacement_reservation.namespace_allocation_reserve,
                        limits,
                    )?;
                    let (restore_reservation, restore_lease) = reserve_whole_tree_move_v2(
                        filesystem,
                        OperationRootCapacityV2 {
                            operation_root: &paths.operation_root,
                            allocation_unit: plan.disk_budget.allocation_unit_bytes,
                            limits,
                        },
                        &backup,
                        &backup_node,
                        &source,
                        0,
                        false,
                    )?;
                    filesystem
                        .revalidate_bounded_tree_lease(&replacement_lease)
                        .map_err(ReconcileExecutorErrorV2::UnsafeNode)?;
                    drop(replacement_lease);
                    filesystem
                        .revalidate_bounded_tree_lease(&restore_lease)
                        .map_err(ReconcileExecutorErrorV2::UnsafeNode)?;
                    drop(restore_lease);
                    into_operation[mutation_index] = Some(replacement_reservation);
                    out_of_operation[mutation_index] = Some(restore_reservation);
                }
                (None, None) => {
                    return Err(conflict(format!(
                        "quarantined source {} and backup {} are both missing during rollback preflight",
                        source.as_str(),
                        backup.as_str()
                    )))
                }
                (Some(source_node), None) => require_movable(&source_node, &source)?,
                (None, Some(backup_node)) => {
                    require_movable(&backup_node, &backup)?;
                    let (reservation, lease) = reserve_whole_tree_move_v2(
                        filesystem,
                        OperationRootCapacityV2 {
                            operation_root: &paths.operation_root,
                            allocation_unit: plan.disk_budget.allocation_unit_bytes,
                            limits,
                        },
                        &backup,
                        &backup_node,
                        &source,
                        0,
                        false,
                    )?;
                    filesystem
                        .revalidate_bounded_tree_lease(&lease)
                        .map_err(ReconcileExecutorErrorV2::UnsafeNode)?;
                    drop(lease);
                    out_of_operation[mutation_index] = Some(reservation);
                }
            },
        }
    }

    // Candidate leases are revalidated and released one at a time above, so a large manifest does
    // not retain one OS handle per quarantine entry. The baseline digest still rechecks every
    // nested candidate, while the later destination-bound JIT authority rejects any growth outside
    // its reservation.
    filesystem
        .revalidate_bounded_tree_lease(&baseline)
        .map_err(ReconcileExecutorErrorV2::UnsafeNode)?;
    drop(baseline);
    Ok(WholeTreeMovePreflightV2 {
        install_root: filesystem.install_root().to_path_buf(),
        install_id: plan.install_id,
        channel: plan.channel,
        operation_id: plan.operation_id,
        plan_sha256: whole_tree_plan_sha256(plan)?,
        direction,
        capacity_ledger: OperationRootCapacityLedgerV2 {
            install_root: filesystem.install_root().to_path_buf(),
            operation_root: paths.operation_root.clone(),
            expected_root: baseline_root,
            current: baseline_summary,
            allocation_unit: plan.disk_budget.allocation_unit_bytes,
            limits,
        },
        into_operation,
        out_of_operation,
    })
}

fn reserve_whole_tree_move_v2<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    capacity: OperationRootCapacityV2<'_>,
    source: &RelativeManagedPath,
    expected_root: &ExecutorNodeSnapshotV2<F::Identity>,
    destination: &RelativeManagedPath,
    destination_depth_within_cleanup_root: usize,
    increases_operation_root: bool,
) -> Result<(ReservedWholeTreeMoveV2<F::Identity>, F::BoundedTreeLease), ReconcileExecutorErrorV2> {
    let lease = filesystem
        .lease_bounded_tree(source, expected_root, capacity.limits)
        .map_err(ReconcileExecutorErrorV2::UnsafeNode)?;
    let maximum_summary = F::bounded_tree_lease_summary(&lease);
    let relocated_depth = maximum_summary
        .max_depth
        .checked_add(destination_depth_within_cleanup_root)
        .ok_or_else(|| {
            ReconcileExecutorErrorV2::UnsafeNode(
                "whole-tree reservation relocated depth overflowed".into(),
            )
        })?;
    if relocated_depth > capacity.limits.max_depth {
        return Err(ReconcileExecutorErrorV2::UnsafeNode(format!(
            "whole-tree reservation exceeds relocated cleanup depth: {}",
            source.as_str()
        )));
    }
    Ok((
        ReservedWholeTreeMoveV2 {
            install_root: filesystem.install_root().to_path_buf(),
            operation_root: capacity.operation_root.clone(),
            source: source.clone(),
            destination: destination.clone(),
            expected_root: expected_root.clone(),
            maximum_summary,
            destination_depth_within_cleanup_root,
            namespace_allocation_reserve: if increases_operation_root {
                capacity.allocation_unit
            } else {
                0
            },
            increases_operation_root,
            limits: capacity.limits,
        },
        lease,
    ))
}

fn require_bounded_operation_summary(
    summary: ManagedDirectoryRemovalSummary,
    limits: ManagedDirectoryRemovalLimits,
) -> Result<(), ReconcileExecutorErrorV2> {
    if summary.entries > limits.max_entries
        || summary.allocated_bytes > limits.max_allocated_bytes
        || summary.max_depth > limits.max_depth
    {
        return Err(ReconcileExecutorErrorV2::UnsafeNode(
            "reconcile operation workspace exceeds its bounded cleanup policy".into(),
        ));
    }
    Ok(())
}

fn add_operation_root_growth(
    current: ManagedDirectoryRemovalSummary,
    candidate: ManagedDirectoryRemovalSummary,
    destination_depth_within_cleanup_root: usize,
    namespace_allocation_reserve: u64,
    limits: ManagedDirectoryRemovalLimits,
) -> Result<ManagedDirectoryRemovalSummary, ReconcileExecutorErrorV2> {
    let entries = current
        .entries
        .checked_add(candidate.entries)
        .ok_or_else(|| {
            ReconcileExecutorErrorV2::UnsafeNode(
                "reconcile quarantine entry aggregate overflowed".into(),
            )
        })?;
    let allocated_bytes = current
        .allocated_bytes
        .checked_add(candidate.allocated_bytes)
        .and_then(|bytes| bytes.checked_add(namespace_allocation_reserve))
        .ok_or_else(|| {
            ReconcileExecutorErrorV2::UnsafeNode(
                "reconcile quarantine allocation aggregate overflowed".into(),
            )
        })?;
    let relocated_depth = if candidate.entries == 0 {
        current.max_depth
    } else {
        candidate
            .max_depth
            .checked_add(destination_depth_within_cleanup_root)
            .ok_or_else(|| {
                ReconcileExecutorErrorV2::UnsafeNode(
                    "reconcile operation-root growth depth overflowed".into(),
                )
            })?
    };
    let aggregate = ManagedDirectoryRemovalSummary {
        entries,
        allocated_bytes,
        max_depth: current.max_depth.max(relocated_depth),
    };
    require_bounded_operation_summary(aggregate, limits)?;
    Ok(aggregate)
}

fn reserve_operation_root_growth<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    ledger: &OperationRootCapacityLedgerV2<F::Identity>,
    candidate: ManagedDirectoryRemovalSummary,
    destination_depth_within_cleanup_root: usize,
    namespace_allocation_reserve: u64,
) -> Result<OperationRootGrowthReservationV2, ReconcileExecutorErrorV2> {
    #[cfg(test)]
    OPERATION_ROOT_GROWTH_RESERVATIONS.with(|count| count.set(count.get() + 1));
    validate_operation_root_ledger(filesystem, ledger)?;
    ledger.reserve_growth(
        candidate,
        destination_depth_within_cleanup_root,
        namespace_allocation_reserve,
    )
}

fn validate_operation_root_ledger<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    ledger: &OperationRootCapacityLedgerV2<F::Identity>,
) -> Result<(), ReconcileExecutorErrorV2> {
    if ledger.install_root != filesystem.install_root() {
        return Err(ReconcileExecutorErrorV2::InvalidScope(
            "operation-root capacity ledger belongs to another install root".into(),
        ));
    }
    let root = inspect(filesystem, &ledger.operation_root)?.ok_or_else(|| {
        ReconcileExecutorErrorV2::UnsafeNode(
            "reconcile operation root disappeared after its baseline audit".into(),
        )
    })?;
    if root != ledger.expected_root {
        return Err(ReconcileExecutorErrorV2::UnsafeNode(
            "reconcile operation root binding changed after its baseline audit".into(),
        ));
    }
    Ok(())
}

fn audit_final_operation_root_capacity<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    ledger: &OperationRootCapacityLedgerV2<F::Identity>,
) -> Result<(), ReconcileExecutorErrorV2> {
    validate_operation_root_ledger(filesystem, ledger)?;
    let lease = filesystem
        .lease_bounded_tree(&ledger.operation_root, &ledger.expected_root, ledger.limits)
        .map_err(ReconcileExecutorErrorV2::UnsafeNode)?;
    let actual = F::bounded_tree_lease_summary(&lease);
    require_bounded_operation_summary(actual, ledger.limits)?;
    filesystem
        .revalidate_bounded_tree_lease(&lease)
        .map_err(ReconcileExecutorErrorV2::UnsafeNode)?;
    drop(lease);
    if actual.entries != ledger.current.entries
        || actual.allocated_bytes > ledger.current.allocated_bytes
        || actual.max_depth > ledger.current.max_depth
    {
        return Err(ReconcileExecutorErrorV2::Interrupted(
            "final operation-root audit differs from the checked exact-write-set ledger".into(),
        ));
    }
    Ok(())
}

fn require_exact_operation_workspace_topology<F: ReconcileFileSystemV2>(
    plan: &ReconcilePlanV2,
    filesystem: &mut F,
    paths: &ReconcileOperationPathsV2,
    direction: WholeTreeMoveDirectionV2,
) -> Result<(), ReconcileExecutorErrorV2> {
    let recreated_paths = RecreatedPathIndexV2::from_plan(plan)?;
    require_exact_child_names(
        filesystem,
        &paths.operation_root,
        ["backup", "replacements", "rollback", "staging", "temporary"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        false,
    )?;
    let quarantine_names = plan
        .mutations
        .iter()
        .filter_map(|mutation| match mutation {
            JournalMutation::Quarantine { backup_slot, .. } => {
                Some(format!("{backup_slot:08}.node"))
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let replacement_names = plan
        .mutations
        .iter()
        .filter_map(|mutation| match mutation {
            JournalMutation::Quarantine {
                source_path,
                backup_slot,
            } if recreated_paths.recreates(source_path) => Some(format!("{backup_slot:08}.node")),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let install_names = plan
        .mutations
        .iter()
        .filter_map(|mutation| match mutation {
            JournalMutation::InstallFile { staging_slot, .. } => Some(*staging_slot),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    require_exact_child_names(filesystem, &paths.backup_root, quarantine_names, true)?;
    require_exact_child_names(filesystem, &paths.replacement_root, replacement_names, true)?;
    require_exact_child_names(
        filesystem,
        &paths.rollback_root,
        install_names
            .iter()
            .map(|slot| format!("{slot:08}.node"))
            .collect(),
        true,
    )?;
    require_exact_child_names(
        filesystem,
        &paths.temporary_root,
        install_names
            .iter()
            .map(|slot| format!("{slot:08}.tmp"))
            .collect(),
        true,
    )?;
    let staging_names = install_names
        .iter()
        .flat_map(|slot| match direction {
            WholeTreeMoveDirectionV2::RollForward => vec![format!("{slot:08}.bin")],
            WholeTreeMoveDirectionV2::Rollback => {
                vec![format!("{slot:08}.bin"), format!("{slot:08}.part")]
            }
        })
        .collect();
    require_exact_child_names(
        filesystem,
        &paths.staging_root,
        staging_names,
        direction == WholeTreeMoveDirectionV2::Rollback,
    )
}

fn require_exact_child_names<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    directory: &RelativeManagedPath,
    allowed: BTreeSet<String>,
    allow_missing: bool,
) -> Result<(), ReconcileExecutorErrorV2> {
    let actual = filesystem
        .list_directory_children(directory)
        .map_err(ReconcileExecutorErrorV2::UnsafeNode)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let valid = if allow_missing {
        actual.is_subset(&allowed)
    } else {
        actual == allowed
    };
    if !valid {
        return Err(ReconcileExecutorErrorV2::UnsafeNode(format!(
            "reconcile workspace contains missing, extra or non-canonical entries: {}",
            directory.as_str()
        )));
    }
    Ok(())
}

fn audit_staging_internal<F: ReconcileFileSystemV2>(
    plan: &ReconcilePlanV2,
    filesystem: &mut F,
    paths: &ReconcileOperationPathsV2,
) -> Result<StagingAuditV2<F::Identity>, ReconcileExecutorErrorV2> {
    let expected_names = expected_staging_slots(plan)?
        .into_iter()
        .map(|expected| format!("{:08}.bin", expected.slot))
        .collect::<BTreeSet<_>>();
    let actual_names = filesystem
        .list_directory_children(&paths.staging_root)
        .map_err(ReconcileExecutorErrorV2::Filesystem)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if actual_names != expected_names {
        return Err(ReconcileExecutorErrorV2::InvalidStagingProof(
            "staging directory does not contain the exact deterministic slot set".into(),
        ));
    }
    let mut by_slot = BTreeMap::new();
    let mut proofs = Vec::new();
    for mutation in &plan.mutations {
        let JournalMutation::InstallFile {
            destination_path,
            staging_slot,
            size,
            sha256,
            executable,
        } = mutation
        else {
            continue;
        };
        let path = paths.staging_file(*staging_slot)?;
        let snapshot = filesystem
            .inspect_node(&path)
            .map_err(ReconcileExecutorErrorV2::Filesystem)?
            .ok_or_else(|| {
                ReconcileExecutorErrorV2::InvalidStagingProof(format!(
                    "missing deterministic staging slot {staging_slot}"
                ))
            })?;
        let expected = ExecutorFileBindingV2 {
            size: *size,
            sha256: sha256.clone(),
            executable: *executable,
        };
        require_regular_binding(&snapshot, &expected, &path, false)?;
        if by_slot.insert(*staging_slot, snapshot).is_some() {
            return Err(ReconcileExecutorErrorV2::InvalidStagingProof(format!(
                "duplicate staging slot {staging_slot}"
            )));
        }
        proofs.push(StagingFileProofV2 {
            staging_slot: *staging_slot,
            destination_path: destination_path.clone(),
            size: *size,
            sha256: sha256.clone(),
        });
    }
    Ok(StagingAuditV2 { by_slot, proofs })
}

fn require_exact_proofs(
    supplied: &[StagingFileProofV2],
    audited: &[StagingFileProofV2],
) -> Result<(), ReconcileExecutorErrorV2> {
    if supplied != audited {
        return Err(ReconcileExecutorErrorV2::InvalidStagingProof(
            "supplied staging proof list is not the exact ordered filesystem audit".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct QuarantineMutationPathsV2<'a> {
    source_manifest_path: &'a str,
    operation_paths: &'a ReconcileOperationPathsV2,
    recreated_paths: &'a RecreatedPathIndexV2,
    source: &'a RelativeManagedPath,
    backup: &'a RelativeManagedPath,
}

fn roll_forward_quarantine<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    capacity_ledger: &mut OperationRootCapacityLedgerV2<F::Identity>,
    paths: QuarantineMutationPathsV2<'_>,
    move_reservation: Option<ReservedWholeTreeMoveV2<F::Identity>>,
) -> Result<MutationDispositionV2, ReconcileExecutorErrorV2> {
    let QuarantineMutationPathsV2 {
        source_manifest_path,
        operation_paths,
        recreated_paths,
        source,
        backup,
    } = paths;
    let source_node = inspect(filesystem, source)?;
    let backup_node = inspect(filesystem, backup)?;
    match (source_node, backup_node) {
        (Some(source_node), Some(backup_node))
            if recreated_paths.recreates(source_manifest_path) =>
        {
            require_movable(&source_node, source)?;
            require_movable(&backup_node, backup)?;
            validate_recreated_quarantine_source(
                recreated_paths,
                source_manifest_path,
                filesystem,
                operation_paths,
            )?;
            Ok(MutationDispositionV2::AlreadySatisfied)
        }
        (Some(_), Some(_)) => Err(conflict(format!(
            "both quarantine source {} and backup {} exist",
            source.as_str(),
            backup.as_str()
        ))),
        (None, None) => Err(conflict(format!(
            "neither quarantine source {} nor backup {} exists",
            source.as_str(),
            backup.as_str()
        ))),
        (None, Some(backup_node)) => {
            require_movable(&backup_node, backup)?;
            Ok(MutationDispositionV2::AlreadySatisfied)
        }
        (Some(source_node), None) => {
            require_movable(&source_node, source)?;
            let reservation = move_reservation.ok_or_else(|| {
                ReconcileExecutorErrorV2::InvalidScope(
                    "quarantine move lacks its sealed whole-tree preflight".into(),
                )
            })?;
            move_reserved_bounded_and_verify(
                filesystem,
                capacity_ledger,
                reservation,
                source,
                &source_node,
                backup,
            )?;
            Ok(MutationDispositionV2::Applied)
        }
    }
}

fn roll_forward_directory<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    destination: &RelativeManagedPath,
) -> Result<MutationDispositionV2, ReconcileExecutorErrorV2> {
    match inspect(filesystem, destination)? {
        Some(node) if node.kind == ExecutorNodeKindV2::RealDirectory => {
            Ok(MutationDispositionV2::AlreadySatisfied)
        }
        Some(_) => Err(conflict(format!(
            "directory destination is occupied by a non-directory: {}",
            destination.as_str()
        ))),
        None => {
            let created = filesystem
                .ensure_real_directory(destination)
                .map_err(executor_mutation_error)?;
            require_real_directory(filesystem, destination).map_err(|error| {
                if created {
                    applied_mutation_error("planned directory creation", error)
                } else {
                    error
                }
            })?;
            Ok(if created {
                MutationDispositionV2::Applied
            } else {
                MutationDispositionV2::AlreadySatisfied
            })
        }
    }
}

fn operation_file_growth<I>(
    existing: Option<&ExecutorNodeSnapshotV2<I>>,
    expected_size: u64,
    allocation_unit: u64,
) -> Result<(ManagedDirectoryRemovalSummary, u64), ReconcileExecutorErrorV2> {
    let maximum_allocation = round_up_allocation(expected_size, allocation_unit)?;
    let (entries, allocated_bytes, namespace_reserve) = match existing {
        Some(ExecutorNodeSnapshotV2 {
            kind: ExecutorNodeKindV2::RegularFile { allocated_size, .. },
            ..
        }) => (0, maximum_allocation.saturating_sub(*allocated_size), 0),
        Some(_) => {
            return Err(ReconcileExecutorErrorV2::UnsafeNode(
                "operation-root file growth source is not a regular file".into(),
            ))
        }
        None => (1, maximum_allocation, allocation_unit),
    };
    Ok((
        ManagedDirectoryRemovalSummary {
            entries,
            allocated_bytes,
            max_depth: 0,
        },
        namespace_reserve,
    ))
}

fn existing_regular_file_growth<I>(
    existing: &ExecutorNodeSnapshotV2<I>,
) -> Result<ManagedDirectoryRemovalSummary, ReconcileExecutorErrorV2> {
    let ExecutorNodeKindV2::RegularFile { allocated_size, .. } = &existing.kind else {
        return Err(ReconcileExecutorErrorV2::UnsafeNode(
            "operation-root move source is not a regular file".into(),
        ));
    };
    Ok(ManagedDirectoryRemovalSummary {
        entries: 1,
        allocated_bytes: *allocated_size,
        max_depth: 0,
    })
}

#[derive(Clone, Copy)]
struct InstallMutationPathsV2<'a> {
    staging: &'a RelativeManagedPath,
    destination: &'a RelativeManagedPath,
    rollback: &'a RelativeManagedPath,
    temporary: &'a RelativeManagedPath,
}

fn roll_forward_install<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    paths: InstallMutationPathsV2<'_>,
    expected_staging: &ExecutorNodeSnapshotV2<F::Identity>,
    expected: &ExecutorFileBindingV2,
    capacity_ledger: &mut OperationRootCapacityLedgerV2<F::Identity>,
) -> Result<MutationDispositionV2, ReconcileExecutorErrorV2> {
    let InstallMutationPathsV2 {
        staging,
        destination,
        rollback,
        temporary,
    } = paths;
    require_regular_binding(expected_staging, expected, staging, true)?;
    let destination_node = inspect(filesystem, destination)?;
    let rollback_node = inspect(filesystem, rollback)?;
    let temporary_node = inspect(filesystem, temporary)?;
    if let Some(temporary_node) = temporary_node {
        if destination_node.is_some() || rollback_node.is_some() {
            return Err(conflict(format!(
                "install temporary {} coexists with its destination or rollback slot",
                temporary.as_str()
            )));
        }
        let temporary_binding = regular_binding(&temporary_node, temporary)?;
        if temporary_binding.size > expected.size {
            return Err(conflict(format!(
                "install temporary exceeds its planned size: {}",
                temporary.as_str()
            )));
        }
        let existing_temporary = existing_regular_file_growth(&temporary_node)?;
        let removal_reservation = capacity_ledger.reserve_removal(existing_temporary)?;
        let (growth, namespace_reserve) = operation_file_growth(
            Some(&temporary_node),
            expected.size,
            capacity_ledger.allocation_unit,
        )?;
        let _peak_reservation = reserve_operation_root_growth(
            filesystem,
            capacity_ledger,
            growth,
            2,
            namespace_reserve,
        )?;
        capacity_ledger.validate_removal_reservation(&removal_reservation)?;
        // Even an already complete/hash-exact crash temporary must cross the resumable writer's
        // sync boundary before publication. A generic namespace rename would flush only parent
        // directories and could publish readable but never-fsynced data after restart.
        filesystem
            .copy_regular_file_no_replace(
                staging,
                expected_staging,
                temporary,
                destination,
                expected,
            )
            .map_err(executor_mutation_error)?;
        let post_copy = (|| {
            if inspect(filesystem, temporary)?.is_some() {
                return Err(conflict(format!(
                    "resumed install copy left its temporary in place: {}",
                    temporary.as_str()
                )));
            }
            require_same_file_snapshot(filesystem, staging, expected_staging, expected, false)?;
            require_exact_file(filesystem, destination, expected)
        })();
        post_copy.map_err(|error| applied_mutation_error("resumed install copy", error))?;
        capacity_ledger.commit_removal(removal_reservation)?;
        return Ok(MutationDispositionV2::Applied);
    }
    let disposition = match (destination_node, rollback_node) {
        (Some(_), Some(_)) => {
            return Err(conflict(format!(
                "both install destination {} and rollback slot {} exist",
                destination.as_str(),
                rollback.as_str()
            )))
        }
        (Some(destination_node), None) => {
            require_regular_binding(&destination_node, expected, destination, true)?;
            MutationDispositionV2::AlreadySatisfied
        }
        (None, Some(rollback_node)) => {
            require_regular_binding(&rollback_node, expected, rollback, true)?;
            let removed = existing_regular_file_growth(&rollback_node)?;
            let removal_reservation = capacity_ledger.reserve_removal(removed)?;
            validate_operation_root_ledger(filesystem, capacity_ledger)?;
            capacity_ledger.validate_removal_reservation(&removal_reservation)?;
            rename_and_verify(filesystem, rollback, &rollback_node, destination)?;
            capacity_ledger.commit_removal(removal_reservation)?;
            MutationDispositionV2::Applied
        }
        (None, None) => {
            let (growth, namespace_reserve) = operation_file_growth::<F::Identity>(
                None,
                expected.size,
                capacity_ledger.allocation_unit,
            )?;
            let _peak_reservation = reserve_operation_root_growth(
                filesystem,
                capacity_ledger,
                growth,
                2,
                namespace_reserve,
            )?;
            filesystem
                .copy_regular_file_no_replace(
                    staging,
                    expected_staging,
                    temporary,
                    destination,
                    expected,
                )
                .map_err(executor_mutation_error)?;
            let post_copy = (|| {
                if inspect(filesystem, temporary)?.is_some() {
                    return Err(conflict(format!(
                        "install copy returned but left its temporary in place: {}",
                        temporary.as_str()
                    )));
                }
                require_exact_file(filesystem, destination, expected)
            })();
            post_copy.map_err(|error| applied_mutation_error("install copy", error))?;
            MutationDispositionV2::Applied
        }
    };
    let post_install = (|| {
        require_same_file_snapshot(filesystem, staging, expected_staging, expected, false)?;
        require_exact_file(filesystem, destination, expected)
    })();
    if disposition == MutationDispositionV2::Applied {
        post_install.map_err(|error| applied_mutation_error("install publication", error))?;
    } else {
        post_install?;
    }
    Ok(disposition)
}

fn rollback_install<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    destination: &RelativeManagedPath,
    rollback: &RelativeManagedPath,
    expected: &ExecutorFileBindingV2,
    capacity_ledger: &mut OperationRootCapacityLedgerV2<F::Identity>,
) -> Result<MutationDispositionV2, ReconcileExecutorErrorV2> {
    let destination_node = inspect(filesystem, destination)?;
    let rollback_node = inspect(filesystem, rollback)?;
    match (destination_node, rollback_node) {
        (Some(_), Some(_)) => Err(conflict(format!(
            "both install destination {} and rollback slot {} exist during rollback",
            destination.as_str(),
            rollback.as_str()
        ))),
        (Some(destination_node), None) => {
            require_regular_binding(&destination_node, expected, destination, true)?;
            let growth = existing_regular_file_growth(&destination_node)?;
            let reservation = reserve_operation_root_growth(
                filesystem,
                capacity_ledger,
                growth,
                2,
                capacity_ledger.allocation_unit,
            )?;
            rename_and_verify(filesystem, destination, &destination_node, rollback)?;
            capacity_ledger.commit_growth(reservation)?;
            Ok(MutationDispositionV2::Applied)
        }
        (None, Some(rollback_node)) => {
            require_regular_binding(&rollback_node, expected, rollback, true)?;
            Ok(MutationDispositionV2::AlreadySatisfied)
        }
        (None, None) => Ok(MutationDispositionV2::NotApplied),
    }
}

fn rollback_directory<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    destination: &RelativeManagedPath,
) -> Result<MutationDispositionV2, ReconcileExecutorErrorV2> {
    match inspect(filesystem, destination)? {
        None => Ok(MutationDispositionV2::NotApplied),
        Some(node) if node.kind == ExecutorNodeKindV2::RealDirectory => {
            // Empty directories are harmless and intentionally retained; recursive delete is not
            // part of the executor contract.
            Ok(MutationDispositionV2::AlreadySatisfied)
        }
        Some(_) => Err(conflict(format!(
            "ensured directory became an unsafe node during rollback: {}",
            destination.as_str()
        ))),
    }
}

fn rollback_quarantine<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    capacity_ledger: &mut OperationRootCapacityLedgerV2<F::Identity>,
    source: &RelativeManagedPath,
    backup: &RelativeManagedPath,
    replacement: Option<&RelativeManagedPath>,
    replacement_reservation: Option<ReservedWholeTreeMoveV2<F::Identity>>,
    restore_reservation: Option<ReservedWholeTreeMoveV2<F::Identity>>,
) -> Result<MutationDispositionV2, ReconcileExecutorErrorV2> {
    let source_node = inspect(filesystem, source)?;
    let backup_node = inspect(filesystem, backup)?;
    match (source_node, backup_node) {
        (Some(source_node), Some(backup_node)) => {
            let Some(replacement) = replacement else {
                return Err(conflict(format!(
                    "both quarantine source {} and backup {} exist during rollback",
                    source.as_str(),
                    backup.as_str()
                )));
            };
            if inspect(filesystem, replacement)?.is_some() {
                return Err(conflict(format!(
                    "replacement slot already exists while source and backup coexist: {}",
                    replacement.as_str()
                )));
            }
            require_movable(&source_node, source)?;
            let replacement_reservation = replacement_reservation.ok_or_else(|| {
                ReconcileExecutorErrorV2::InvalidScope(
                    "rollback replacement move lacks its sealed whole-tree preflight".into(),
                )
            })?;
            move_reserved_bounded_and_verify(
                filesystem,
                capacity_ledger,
                replacement_reservation,
                source,
                &source_node,
                replacement,
            )?;
            let restore = (|| {
                require_movable(&backup_node, backup)?;
                let restore_reservation = restore_reservation.ok_or_else(|| {
                    ReconcileExecutorErrorV2::InvalidScope(
                        "rollback restore lacks its sealed whole-tree preflight".into(),
                    )
                })?;
                move_reserved_bounded_and_verify(
                    filesystem,
                    capacity_ledger,
                    restore_reservation,
                    backup,
                    &backup_node,
                    source,
                )
            })();
            restore.map_err(|error| {
                applied_mutation_error("rollback replacement quarantine", error)
            })?;
            Ok(MutationDispositionV2::Applied)
        }
        (None, None) => Err(conflict(format!(
            "quarantined source {} and backup {} are both missing during rollback",
            source.as_str(),
            backup.as_str()
        ))),
        (Some(source_node), None) => {
            require_movable(&source_node, source)?;
            Ok(MutationDispositionV2::AlreadySatisfied)
        }
        (None, Some(backup_node)) => {
            require_movable(&backup_node, backup)?;
            let restore_reservation = restore_reservation.ok_or_else(|| {
                ReconcileExecutorErrorV2::InvalidScope(
                    "rollback restore lacks its sealed whole-tree preflight".into(),
                )
            })?;
            move_reserved_bounded_and_verify(
                filesystem,
                capacity_ledger,
                restore_reservation,
                backup,
                &backup_node,
                source,
            )?;
            Ok(MutationDispositionV2::Applied)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RecreatedInstanceNodeV2 {
    Directory,
    File(ExecutorFileBindingV2),
}

struct RecreatedPathIndexV2 {
    expected: BTreeMap<String, (String, RecreatedInstanceNodeV2)>,
}

impl RecreatedPathIndexV2 {
    fn from_plan(plan: &ReconcilePlanV2) -> Result<Self, ReconcileExecutorErrorV2> {
        let mut expected = BTreeMap::<String, (String, RecreatedInstanceNodeV2)>::new();
        for mutation in &plan.mutations {
            #[cfg(test)]
            RECREATED_PATH_PLAN_VISITS.with(|count| count.set(count.get() + 1));
            let (destination, node) = match mutation {
                JournalMutation::EnsureDirectory { destination_path } => {
                    (destination_path, RecreatedInstanceNodeV2::Directory)
                }
                JournalMutation::InstallFile {
                    destination_path,
                    size,
                    sha256,
                    executable,
                    ..
                } => (
                    destination_path,
                    RecreatedInstanceNodeV2::File(ExecutorFileBindingV2 {
                        size: *size,
                        sha256: sha256.clone(),
                        executable: *executable,
                    }),
                ),
                JournalMutation::Quarantine { .. } => continue,
            };

            let mut ancestor = destination.as_str();
            while let Some((parent, _)) = ancestor.rsplit_once('/') {
                let parent_key = parent.to_lowercase();
                match expected.get(&parent_key) {
                    Some((_, RecreatedInstanceNodeV2::File(_))) => {
                        return Err(ReconcileExecutorErrorV2::InvalidPlan(format!(
                            "recreated path has a file ancestor: {parent}"
                        )))
                    }
                    Some(_) => {}
                    None => {
                        expected.insert(
                            parent_key,
                            (parent.to_owned(), RecreatedInstanceNodeV2::Directory),
                        );
                    }
                }
                ancestor = parent;
            }

            let destination_key = destination.to_lowercase();
            match expected.get(&destination_key) {
                Some((_, existing)) if existing != &node => {
                    return Err(ReconcileExecutorErrorV2::InvalidPlan(format!(
                        "recreated path changes node kind: {destination}"
                    )))
                }
                Some(_) => {}
                None => {
                    expected.insert(destination_key, (destination.clone(), node));
                }
            }
        }
        Ok(Self { expected })
    }

    fn recreates(&self, source: &str) -> bool {
        #[cfg(test)]
        RECREATED_PATH_LOOKUPS.with(|count| count.set(count.get() + 1));
        self.expected.contains_key(&source.to_lowercase())
    }
}

/// Proves that a source which coexists with its quarantine backup contains only the prefix of the
/// later canonical reconstruction allowed by this plan. Missing expected descendants are valid
/// (the crash may precede their mutation); every present directory/file and every child name must
/// already be exact. This prevents `(source, backup)` from becoming a blind idempotence bypass.
fn validate_recreated_quarantine_source<F: ReconcileFileSystemV2>(
    recreated_paths: &RecreatedPathIndexV2,
    source: &str,
    filesystem: &mut F,
    paths: &ReconcileOperationPathsV2,
) -> Result<(), ReconcileExecutorErrorV2> {
    let source_key = source.to_lowercase();
    if !recreated_paths.expected.contains_key(&source_key) {
        return Err(ReconcileExecutorErrorV2::InvalidPlan(format!(
            "quarantine source has no canonical reconstruction: {source}"
        )));
    }

    let mut expected_children = BTreeMap::<String, BTreeSet<String>>::new();
    let descendant_prefix = format!("{source_key}/");
    for (path_key, (path, _)) in recreated_paths.expected.range(source_key.clone()..) {
        if path_key != &source_key && !path_key.starts_with(&descendant_prefix) {
            break;
        }
        if path_key == &source_key {
            continue;
        }
        let (parent, child) = path.rsplit_once('/').ok_or_else(|| {
            ReconcileExecutorErrorV2::InvalidPlan(format!(
                "recreated quarantine descendant has no parent: {path}"
            ))
        })?;
        expected_children
            .entry(parent.to_lowercase())
            .or_default()
            .insert(child.to_owned());
    }

    let mut pending = vec![source_key.clone()];
    while let Some(path_key) = pending.pop() {
        let (manifest_path, expected_node) =
            recreated_paths.expected.get(&path_key).ok_or_else(|| {
                ReconcileExecutorErrorV2::InvalidPlan(
                    "recreated quarantine traversal escaped its expected tree".into(),
                )
            })?;
        let relative = paths.instance_path(manifest_path)?;
        let actual = inspect(filesystem, &relative)?.ok_or_else(|| {
            conflict(format!(
                "recreated quarantine node disappeared during audit: {}",
                relative.as_str()
            ))
        })?;
        match expected_node {
            RecreatedInstanceNodeV2::Directory => {
                if actual.kind != ExecutorNodeKindV2::RealDirectory {
                    return Err(conflict(format!(
                        "recreated quarantine directory has the wrong node kind: {}",
                        relative.as_str()
                    )));
                }
                let allowed = expected_children
                    .get(&path_key)
                    .cloned()
                    .unwrap_or_default();
                let actual_children = filesystem
                    .list_directory_children(&relative)
                    .map_err(ReconcileExecutorErrorV2::UnsafeNode)?;
                for child in actual_children {
                    if !allowed.contains(&child) {
                        return Err(conflict(format!(
                            "recreated quarantine directory contains an unexpected child: {}/{}",
                            relative.as_str(),
                            child
                        )));
                    }
                    let child_path = format!("{manifest_path}/{child}");
                    let child_key = child_path.to_lowercase();
                    if !recreated_paths.expected.contains_key(&child_key) {
                        return Err(conflict(format!(
                            "recreated quarantine child is not canonical: {child_path}"
                        )));
                    }
                    pending.push(child_key);
                }
            }
            RecreatedInstanceNodeV2::File(binding) => {
                require_regular_binding(&actual, binding, &relative, true)?;
            }
        }
    }
    Ok(())
}

fn inspect<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    path: &RelativeManagedPath,
) -> Result<Option<ExecutorNodeSnapshotV2<F::Identity>>, ReconcileExecutorErrorV2> {
    filesystem
        .inspect_node(path)
        .map_err(ReconcileExecutorErrorV2::Filesystem)
}

fn require_real_directory<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    path: &RelativeManagedPath,
) -> Result<(), ReconcileExecutorErrorV2> {
    match inspect(filesystem, path)? {
        Some(node) if node.kind == ExecutorNodeKindV2::RealDirectory => Ok(()),
        _ => Err(ReconcileExecutorErrorV2::UnsafeNode(format!(
            "managed directory is missing, linked or reparse-backed: {}",
            path.as_str()
        ))),
    }
}

fn require_movable<I: Debug + Eq>(
    node: &ExecutorNodeSnapshotV2<I>,
    path: &RelativeManagedPath,
) -> Result<(), ReconcileExecutorErrorV2> {
    match &node.kind {
        ExecutorNodeKindV2::RegularFile { link_count: 1, .. }
        | ExecutorNodeKindV2::RealDirectory
        | ExecutorNodeKindV2::ReparsePoint => Ok(()),
        ExecutorNodeKindV2::RegularFile { link_count, .. } => {
            Err(ReconcileExecutorErrorV2::UnsafeNode(format!(
                "hard-linked managed file has {link_count} links: {}",
                path.as_str()
            )))
        }
        ExecutorNodeKindV2::Unsupported => Err(ReconcileExecutorErrorV2::UnsafeNode(format!(
            "unsupported managed node cannot be moved: {}",
            path.as_str()
        ))),
    }
}

fn regular_binding<'a, I>(
    node: &'a ExecutorNodeSnapshotV2<I>,
    path: &RelativeManagedPath,
) -> Result<&'a ExecutorFileBindingV2, ReconcileExecutorErrorV2> {
    match &node.kind {
        ExecutorNodeKindV2::RegularFile {
            binding,
            link_count: 1,
            ..
        } => Ok(binding),
        ExecutorNodeKindV2::RegularFile { link_count, .. } => {
            Err(ReconcileExecutorErrorV2::UnsafeNode(format!(
                "regular file has {link_count} hard links: {}",
                path.as_str()
            )))
        }
        _ => Err(ReconcileExecutorErrorV2::UnsafeNode(format!(
            "expected a regular no-follow file: {}",
            path.as_str()
        ))),
    }
}

fn require_regular_binding<I>(
    node: &ExecutorNodeSnapshotV2<I>,
    expected: &ExecutorFileBindingV2,
    path: &RelativeManagedPath,
    compare_executable: bool,
) -> Result<(), ReconcileExecutorErrorV2> {
    let actual = regular_binding(node, path)?;
    if actual.size != expected.size
        || actual.sha256 != expected.sha256
        || (compare_executable && actual.executable != expected.executable)
    {
        return Err(conflict(format!(
            "regular file binding differs at {}",
            path.as_str()
        )));
    }
    Ok(())
}

fn require_exact_file<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    path: &RelativeManagedPath,
    expected: &ExecutorFileBindingV2,
) -> Result<(), ReconcileExecutorErrorV2> {
    let node = inspect(filesystem, path)?.ok_or_else(|| {
        ReconcileExecutorErrorV2::Conflict(format!(
            "expected installed file is missing after mutation: {}",
            path.as_str()
        ))
    })?;
    require_regular_binding(&node, expected, path, true)
}

fn require_same_file_snapshot<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    path: &RelativeManagedPath,
    expected_snapshot: &ExecutorNodeSnapshotV2<F::Identity>,
    expected_binding: &ExecutorFileBindingV2,
    compare_executable: bool,
) -> Result<(), ReconcileExecutorErrorV2> {
    let actual = inspect(filesystem, path)?.ok_or_else(|| {
        ReconcileExecutorErrorV2::Conflict(format!(
            "leased source disappeared during mutation: {}",
            path.as_str()
        ))
    })?;
    if actual.identity != expected_snapshot.identity {
        return Err(conflict(format!(
            "leased source identity changed during mutation: {}",
            path.as_str()
        )));
    }
    require_regular_binding(&actual, expected_binding, path, compare_executable)
}

fn rename_and_verify<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    source: &RelativeManagedPath,
    expected: &ExecutorNodeSnapshotV2<F::Identity>,
    destination: &RelativeManagedPath,
) -> Result<(), ReconcileExecutorErrorV2> {
    filesystem
        .rename_node_no_replace(source, expected, destination)
        .map_err(executor_mutation_error)?;
    let post_move = (|| {
        if inspect(filesystem, source)?.is_some() {
            return Err(conflict(format!(
                "managed rename left its source in place: {}",
                source.as_str()
            )));
        }
        let actual = inspect(filesystem, destination)?.ok_or_else(|| {
            conflict(format!(
                "managed rename did not publish its destination: {}",
                destination.as_str()
            ))
        })?;
        if actual != *expected {
            return Err(conflict(format!(
                "managed rename changed node identity or classification at {}",
                destination.as_str()
            )));
        }
        Ok(())
    })();
    post_move.map_err(|error| applied_mutation_error("managed rename", error))
}

fn move_reserved_bounded_and_verify<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    capacity_ledger: &mut OperationRootCapacityLedgerV2<F::Identity>,
    reservation: ReservedWholeTreeMoveV2<F::Identity>,
    source: &RelativeManagedPath,
    current_root: &ExecutorNodeSnapshotV2<F::Identity>,
    destination: &RelativeManagedPath,
) -> Result<(), ReconcileExecutorErrorV2> {
    if reservation.install_root != filesystem.install_root()
        || reservation.operation_root != capacity_ledger.operation_root
        || reservation.limits != capacity_ledger.limits
        || reservation.source != *source
        || reservation.destination != *destination
        || reservation.expected_root != *current_root
    {
        return Err(ReconcileExecutorErrorV2::InvalidScope(
            "whole-tree move differs from its pre-mutation reservation".into(),
        ));
    }
    let authority = filesystem
        .prepare_bounded_tree_move(
            source,
            current_root,
            destination,
            reservation.destination_depth_within_cleanup_root,
            reservation.limits,
        )
        .map_err(ReconcileExecutorErrorV2::UnsafeNode)?;
    let current_summary = F::bounded_tree_move_summary(&authority);
    if current_summary.entries > reservation.maximum_summary.entries
        || current_summary.allocated_bytes > reservation.maximum_summary.allocated_bytes
        || current_summary.max_depth > reservation.maximum_summary.max_depth
    {
        return Err(ReconcileExecutorErrorV2::UnsafeNode(format!(
            "whole-tree move grew beyond its pre-mutation reservation: {}",
            source.as_str()
        )));
    }
    let (growth_reservation, removal_reservation) = if reservation.increases_operation_root {
        (
            Some(reserve_operation_root_growth(
                filesystem,
                capacity_ledger,
                current_summary,
                reservation.destination_depth_within_cleanup_root,
                reservation.namespace_allocation_reserve,
            )?),
            None,
        )
    } else {
        validate_operation_root_ledger(filesystem, capacity_ledger)?;
        (
            None,
            Some(capacity_ledger.reserve_removal(current_summary)?),
        )
    };
    filesystem
        .revalidate_bounded_tree_move(&authority)
        .map_err(ReconcileExecutorErrorV2::UnsafeNode)?;
    if let Some(reservation) = removal_reservation.as_ref() {
        capacity_ledger.validate_removal_reservation(reservation)?;
    }
    filesystem
        .move_bounded_tree_no_replace(authority)
        .map_err(executor_mutation_error)?;
    let post_move = (|| {
        if inspect(filesystem, source)?.is_some() {
            return Err(conflict(format!(
                "bounded whole-tree move left source in place: {}",
                source.as_str()
            )));
        }
        let moved = inspect(filesystem, destination)?.ok_or_else(|| {
            conflict(format!(
                "bounded whole-tree move did not create destination: {}",
                destination.as_str()
            ))
        })?;
        if moved != *current_root {
            return Err(conflict(format!(
                "bounded whole-tree move changed root binding: {}",
                destination.as_str()
            )));
        }
        Ok(())
    })();
    post_move.map_err(|error| applied_mutation_error("bounded whole-tree move", error))?;
    if let Some(reservation) = growth_reservation {
        capacity_ledger.commit_growth(reservation)
    } else {
        capacity_ledger.commit_removal(
            removal_reservation.expect("out-of-operation move has a removal reservation"),
        )
    }
}

fn applied_mutation_error(
    operation: &str,
    error: ReconcileExecutorErrorV2,
) -> ReconcileExecutorErrorV2 {
    match error {
        ReconcileExecutorErrorV2::Interrupted(_) => error,
        other => ReconcileExecutorErrorV2::Interrupted(format!(
            "{operation} applied before verification failed: {other}"
        )),
    }
}

fn managed_path(value: &str) -> Result<RelativeManagedPath, ReconcileExecutorErrorV2> {
    RelativeManagedPath::new(value)
        .map_err(|error| ReconcileExecutorErrorV2::InvalidScope(error.to_string()))
}

fn join(
    base: &RelativeManagedPath,
    component: &str,
) -> Result<RelativeManagedPath, ReconcileExecutorErrorV2> {
    base.join_component(component)
        .map_err(|error| ReconcileExecutorErrorV2::InvalidScope(error.to_string()))
}

fn conflict(message: String) -> ReconcileExecutorErrorV2 {
    ReconcileExecutorErrorV2::Conflict(message)
}

#[cfg(test)]
mod tests {
    use super::super::{
        artifact_plan::{ArtifactInventoryV2, ArtifactPlanV2},
        availability::{ArtifactAvailabilityStateV2, VerifiedAvailabilityV2},
        cas::{cas_object_relative_path, verify_existing_object, ExpectedObject},
        contracts::{self, GameRuntimeLock, RuntimeLock},
        instance_state::{ActiveInstanceV2, InstanceStateStore},
        journal::{DiskBudgetV2, OperationKind, PlannedFileV2},
        reconciler::{audit_current_reconcile_plan_instance, InstanceAudit},
        release::{self, CurrentPointer, FilePolicy, ReleaseManifest},
        storage::select_install_directory,
        tuf::{TrustedRelease, TrustedReleaseEvidence, TrustedRoleVersions, TrustedTargetEvidence},
        types::{BuildChannel, PresetId},
    };
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{collections::BTreeMap, fs, path::PathBuf};
    use uuid::Uuid;

    #[derive(Debug)]
    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "fragment-reconcile-executor-{label}-{}",
                Uuid::new_v4()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FakeNode {
        Directory {
            identity: u64,
        },
        File {
            identity: u64,
            bytes: Vec<u8>,
            executable: bool,
            link_count: u32,
        },
        Reparse {
            identity: u64,
            target: String,
        },
        Unsupported {
            identity: u64,
        },
    }

    struct FakeBoundedTreeLease {
        root: PathBuf,
        source: String,
        snapshot: BTreeMap<String, FakeNode>,
        summary: ManagedDirectoryRemovalSummary,
        limits: ManagedDirectoryRemovalLimits,
    }

    struct FakeBoundedTreeMoveAuthority {
        lease: FakeBoundedTreeLease,
        destination: String,
    }

    struct FakeFilesystem {
        root: PathBuf,
        next_identity: u64,
        nodes: BTreeMap<String, FakeNode>,
        inspect_calls: usize,
        copy_calls: usize,
        rename_calls: usize,
        bounded_tree_move_calls: usize,
        bounded_tree_lease_calls: usize,
        bounded_tree_node_visits: usize,
        grow_before_bounded_move: Option<(String, String, Vec<u8>)>,
        grow_operation_root_before_bounded_move: Option<(String, Vec<u8>)>,
        grow_operation_root_after_copy: Option<(String, Vec<u8>)>,
        applied_uncertain_after_bounded_move: Option<String>,
        not_applied_ensure_failure: Option<String>,
        applied_uncertain_after_ensure: Option<String>,
        applied_uncertain_after_rename: Option<String>,
        applied_uncertain_after_copy: Option<String>,
        post_rename_binding_mismatch: Option<String>,
        synthetic_pending_quarantine_sources: bool,
    }

    impl FakeFilesystem {
        fn new(root: &Path) -> Self {
            Self {
                root: root.to_path_buf(),
                next_identity: 1,
                nodes: BTreeMap::new(),
                inspect_calls: 0,
                copy_calls: 0,
                rename_calls: 0,
                bounded_tree_move_calls: 0,
                bounded_tree_lease_calls: 0,
                bounded_tree_node_visits: 0,
                grow_before_bounded_move: None,
                grow_operation_root_before_bounded_move: None,
                grow_operation_root_after_copy: None,
                applied_uncertain_after_bounded_move: None,
                not_applied_ensure_failure: None,
                applied_uncertain_after_ensure: None,
                applied_uncertain_after_rename: None,
                applied_uncertain_after_copy: None,
                post_rename_binding_mismatch: None,
                synthetic_pending_quarantine_sources: false,
            }
        }

        fn allocate_identity(&mut self) -> u64 {
            let identity = self.next_identity;
            self.next_identity += 1;
            identity
        }

        fn ensure_parents(&mut self, path: &str) {
            let parts = path.split('/').collect::<Vec<_>>();
            for end in 1..parts.len() {
                let parent = parts[..end].join("/");
                if !self.nodes.contains_key(&parent) {
                    let identity = self.allocate_identity();
                    self.nodes.insert(parent, FakeNode::Directory { identity });
                }
            }
        }

        fn insert_file(&mut self, path: &str, bytes: &[u8], executable: bool) {
            self.insert_file_with_links(path, bytes, executable, 1);
        }

        fn insert_file_with_links(
            &mut self,
            path: &str,
            bytes: &[u8],
            executable: bool,
            link_count: u32,
        ) {
            self.ensure_parents(path);
            let identity = self.allocate_identity();
            self.nodes.insert(
                path.into(),
                FakeNode::File {
                    identity,
                    bytes: bytes.to_vec(),
                    executable,
                    link_count,
                },
            );
        }

        fn insert_reparse(&mut self, path: &str, target: &str) {
            self.ensure_parents(path);
            let identity = self.allocate_identity();
            self.nodes.insert(
                path.into(),
                FakeNode::Reparse {
                    identity,
                    target: target.into(),
                },
            );
        }

        fn contains(&self, path: &str) -> bool {
            self.nodes.contains_key(path)
        }

        fn file_bytes(&self, path: &str) -> Option<&[u8]> {
            match self.nodes.get(path) {
                Some(FakeNode::File { bytes, .. }) => Some(bytes),
                _ => None,
            }
        }

        fn reparse_target(&self, path: &str) -> Option<&str> {
            match self.nodes.get(path) {
                Some(FakeNode::Reparse { target, .. }) => Some(target),
                _ => None,
            }
        }

        fn snapshot(node: &FakeNode) -> ExecutorNodeSnapshotV2<u64> {
            match node {
                FakeNode::Directory { identity } => ExecutorNodeSnapshotV2 {
                    identity: *identity,
                    kind: ExecutorNodeKindV2::RealDirectory,
                },
                FakeNode::File {
                    identity,
                    bytes,
                    executable,
                    link_count,
                } => ExecutorNodeSnapshotV2 {
                    identity: *identity,
                    kind: ExecutorNodeKindV2::RegularFile {
                        binding: ExecutorFileBindingV2 {
                            size: bytes.len() as u64,
                            sha256: sha256(bytes),
                            executable: *executable,
                        },
                        link_count: *link_count,
                        allocated_size: bytes.len() as u64,
                    },
                },
                FakeNode::Reparse { identity, .. } => ExecutorNodeSnapshotV2 {
                    identity: *identity,
                    kind: ExecutorNodeKindV2::ReparsePoint,
                },
                FakeNode::Unsupported { identity } => ExecutorNodeSnapshotV2 {
                    identity: *identity,
                    kind: ExecutorNodeKindV2::Unsupported,
                },
            }
        }

        fn bounded_tree_lease(
            &mut self,
            source: &RelativeManagedPath,
            limits: ManagedDirectoryRemovalLimits,
        ) -> Result<FakeBoundedTreeLease, String> {
            let source_text = source.as_str();
            if !self.nodes.contains_key(source_text) {
                return Err("bounded fake tree source is missing".into());
            }
            let prefix = format!("{source_text}/");
            let snapshot = self
                .nodes
                .iter()
                .filter(|(path, _)| *path == source_text || path.starts_with(&prefix))
                .map(|(path, node)| (path.clone(), node.clone()))
                .collect::<BTreeMap<_, _>>();
            self.bounded_tree_node_visits = self
                .bounded_tree_node_visits
                .checked_add(snapshot.len())
                .expect("fake bounded-tree node-visit counter overflowed");
            let mut summary = ManagedDirectoryRemovalSummary {
                entries: 0,
                allocated_bytes: 0,
                max_depth: 0,
            };
            for (path, node) in &snapshot {
                let relative = path.strip_prefix(source_text).unwrap_or_default();
                let depth = relative
                    .strip_prefix('/')
                    .filter(|suffix| !suffix.is_empty())
                    .map_or(0, |suffix| suffix.split('/').count());
                let allocated = match node {
                    FakeNode::File {
                        bytes,
                        link_count: 1,
                        ..
                    } => bytes.len() as u64,
                    FakeNode::File { .. } => {
                        return Err("bounded fake tree contains a hard-linked file".into())
                    }
                    FakeNode::Directory { .. } | FakeNode::Reparse { .. } => 0,
                    FakeNode::Unsupported { .. } => {
                        return Err("bounded fake tree contains an unsupported node".into())
                    }
                };
                summary.entries = summary
                    .entries
                    .checked_add(1)
                    .ok_or_else(|| "bounded fake tree entry overflow".to_string())?;
                summary.allocated_bytes = summary
                    .allocated_bytes
                    .checked_add(allocated)
                    .ok_or_else(|| "bounded fake tree allocation overflow".to_string())?;
                summary.max_depth = summary.max_depth.max(depth);
            }
            for (path, node) in &snapshot {
                if matches!(node, FakeNode::Reparse { .. })
                    && snapshot
                        .keys()
                        .any(|candidate| candidate.starts_with(&format!("{path}/")))
                {
                    return Err("bounded fake reparse point has traversed descendants".into());
                }
            }
            require_bounded_operation_summary(summary, limits)
                .map_err(|error| error.to_string())?;
            Ok(FakeBoundedTreeLease {
                root: self.root.clone(),
                source: source_text.into(),
                snapshot,
                summary,
                limits,
            })
        }

        fn revalidate_fake_tree_lease(
            &mut self,
            lease: &FakeBoundedTreeLease,
        ) -> Result<(), String> {
            if lease.root != self.root {
                return Err("bounded fake tree lease belongs to another root".into());
            }
            let source =
                RelativeManagedPath::new(&lease.source).map_err(|error| error.to_string())?;
            let current = self.bounded_tree_lease(&source, lease.limits)?;
            if current.snapshot != lease.snapshot || current.summary != lease.summary {
                return Err("bounded fake tree changed after preflight".into());
            }
            Ok(())
        }
    }

    impl ReconcileFileSystemV2 for FakeFilesystem {
        type Identity = u64;
        type BoundedTreeLease = FakeBoundedTreeLease;
        type BoundedTreeMoveAuthority = FakeBoundedTreeMoveAuthority;

        fn install_root(&self) -> &Path {
            &self.root
        }

        fn inspect_node(
            &mut self,
            path: &RelativeManagedPath,
        ) -> Result<Option<ExecutorNodeSnapshotV2<Self::Identity>>, String> {
            self.inspect_calls += 1;
            if let Some(node) = self.nodes.get(path.as_str()) {
                return Ok(Some(Self::snapshot(node)));
            }
            if self.synthetic_pending_quarantine_sources {
                let prefix = "instances/stable/mods/q";
                if path.as_str().strip_prefix(prefix).is_some_and(|suffix| {
                    suffix.len() == 6 && suffix.bytes().all(|byte| byte.is_ascii_digit())
                }) {
                    return Ok(Some(ExecutorNodeSnapshotV2 {
                        identity: u64::MAX,
                        kind: ExecutorNodeKindV2::RealDirectory,
                    }));
                }
            }
            Ok(None)
        }

        fn ensure_real_directory(
            &mut self,
            path: &RelativeManagedPath,
        ) -> Result<bool, ExecutorMutationErrorV2> {
            if self
                .not_applied_ensure_failure
                .as_ref()
                .is_some_and(|expected| expected == path.as_str())
            {
                self.not_applied_ensure_failure.take();
                return Err(ExecutorMutationErrorV2::NotApplied(
                    "injected fake pre-mutation directory failure".into(),
                ));
            }
            let mut created_leaf = false;
            let parts = path.as_str().split('/').collect::<Vec<_>>();
            for end in 1..=parts.len() {
                let current = parts[..end].join("/");
                match self.nodes.get(&current) {
                    Some(FakeNode::Directory { .. }) => {}
                    Some(_) => {
                        return Err(ExecutorMutationErrorV2::NotApplied(format!(
                            "unsafe directory component: {current}"
                        )))
                    }
                    None => {
                        let identity = self.allocate_identity();
                        self.nodes.insert(current, FakeNode::Directory { identity });
                        if end == parts.len() {
                            created_leaf = true;
                        }
                    }
                }
            }
            if created_leaf
                && self
                    .applied_uncertain_after_ensure
                    .as_ref()
                    .is_some_and(|expected| expected == path.as_str())
            {
                self.applied_uncertain_after_ensure.take();
                return Err(ExecutorMutationErrorV2::AppliedButStateUncertain(
                    "injected fake directory durability uncertainty".into(),
                ));
            }
            Ok(created_leaf)
        }

        fn list_directory_children(
            &mut self,
            path: &RelativeManagedPath,
        ) -> Result<Vec<String>, String> {
            if !matches!(
                self.nodes.get(path.as_str()),
                Some(FakeNode::Directory { .. })
            ) {
                return Err("directory is missing or unsafe".into());
            }
            let prefix = format!("{}/", path.as_str());
            let mut children = BTreeSet::new();
            let mut collision_keys = BTreeSet::new();
            for candidate in self.nodes.keys() {
                let Some(suffix) = candidate.strip_prefix(&prefix) else {
                    continue;
                };
                let name = suffix
                    .split('/')
                    .next()
                    .expect("a child suffix is non-empty");
                if name.is_empty() {
                    return Err("empty fake child name".into());
                }
                if children.insert(name.to_owned()) && !collision_keys.insert(name.to_lowercase()) {
                    return Err("case-colliding fake child names".into());
                }
            }
            Ok(children.into_iter().collect())
        }

        fn lease_bounded_tree(
            &mut self,
            source: &RelativeManagedPath,
            expected: &ExecutorNodeSnapshotV2<Self::Identity>,
            limits: ManagedDirectoryRemovalLimits,
        ) -> Result<Self::BoundedTreeLease, String> {
            self.bounded_tree_lease_calls += 1;
            let lease = self.bounded_tree_lease(source, limits)?;
            let root = lease
                .snapshot
                .get(source.as_str())
                .map(Self::snapshot)
                .ok_or_else(|| "bounded fake lease root is missing".to_string())?;
            if &root != expected {
                return Err("bounded fake lease root differs from executor audit".into());
            }
            Ok(lease)
        }

        fn bounded_tree_lease_summary(
            lease: &Self::BoundedTreeLease,
        ) -> ManagedDirectoryRemovalSummary {
            lease.summary
        }

        fn revalidate_bounded_tree_lease(
            &mut self,
            lease: &Self::BoundedTreeLease,
        ) -> Result<(), String> {
            self.revalidate_fake_tree_lease(lease)
        }

        fn prepare_bounded_tree_move(
            &mut self,
            source: &RelativeManagedPath,
            expected: &ExecutorNodeSnapshotV2<Self::Identity>,
            destination: &RelativeManagedPath,
            destination_depth_within_cleanup_root: usize,
            limits: ManagedDirectoryRemovalLimits,
        ) -> Result<Self::BoundedTreeMoveAuthority, String> {
            if let Some((path, bytes)) = self.grow_operation_root_before_bounded_move.take() {
                self.insert_file(&path, &bytes, false);
            }
            if self
                .grow_before_bounded_move
                .as_ref()
                .is_some_and(|(expected_source, _, _)| expected_source == source.as_str())
            {
                let (_, child, bytes) = self
                    .grow_before_bounded_move
                    .take()
                    .expect("bounded fake growth hook was present");
                self.insert_file(&child, &bytes, false);
            }
            if source.collision_key() == destination.collision_key()
                || destination
                    .collision_key()
                    .starts_with(&format!("{}/", source.collision_key()))
            {
                return Err("invalid bounded fake move topology".into());
            }
            let lease = self.bounded_tree_lease(source, limits)?;
            let root = lease
                .snapshot
                .get(source.as_str())
                .map(Self::snapshot)
                .ok_or_else(|| "bounded fake move root is missing".to_string())?;
            if &root != expected {
                return Err("bounded fake move root differs from executor audit".into());
            }
            let relocated_depth = lease
                .summary
                .max_depth
                .checked_add(destination_depth_within_cleanup_root)
                .ok_or_else(|| "bounded fake move depth overflow".to_string())?;
            if relocated_depth > limits.max_depth {
                return Err("bounded fake move exceeds relocated cleanup depth".into());
            }
            let destination_parent = destination
                .parent()
                .ok_or_else(|| "bounded fake move destination has no parent".to_string())?;
            if !matches!(
                self.nodes.get(destination_parent.as_str()),
                Some(FakeNode::Directory { .. })
            ) {
                return Err("bounded fake move destination parent is missing or unsafe".into());
            }
            Ok(FakeBoundedTreeMoveAuthority {
                lease,
                destination: destination.as_str().into(),
            })
        }

        fn bounded_tree_move_summary(
            authority: &Self::BoundedTreeMoveAuthority,
        ) -> ManagedDirectoryRemovalSummary {
            authority.lease.summary
        }

        fn revalidate_bounded_tree_move(
            &mut self,
            authority: &Self::BoundedTreeMoveAuthority,
        ) -> Result<(), String> {
            self.revalidate_fake_tree_lease(&authority.lease)
        }

        fn move_bounded_tree_no_replace(
            &mut self,
            authority: Self::BoundedTreeMoveAuthority,
        ) -> Result<(), ExecutorMutationErrorV2> {
            self.bounded_tree_move_calls += 1;
            self.revalidate_fake_tree_lease(&authority.lease)
                .map_err(ExecutorMutationErrorV2::NotApplied)?;
            let destination_prefix = format!("{}/", authority.destination);
            if self
                .nodes
                .keys()
                .any(|path| path == &authority.destination || path.starts_with(&destination_prefix))
            {
                return Err(ExecutorMutationErrorV2::NotApplied(
                    "bounded fake move destination exists".into(),
                ));
            }
            let source_prefix = format!("{}/", authority.lease.source);
            let moves = authority
                .lease
                .snapshot
                .keys()
                .map(|source| {
                    let suffix = source
                        .strip_prefix(&authority.lease.source)
                        .expect("bounded fake source snapshot is canonical");
                    (source.clone(), format!("{}{suffix}", authority.destination))
                })
                .collect::<Vec<_>>();
            for (_, destination) in &moves {
                if self.nodes.contains_key(destination) {
                    return Err(ExecutorMutationErrorV2::NotApplied(
                        "bounded fake move descendant destination exists".into(),
                    ));
                }
            }
            let mut moved = Vec::with_capacity(moves.len());
            for (source, destination) in moves {
                let node = self.nodes.remove(&source).ok_or_else(|| {
                    ExecutorMutationErrorV2::NotApplied("bounded fake move source changed".into())
                })?;
                moved.push((destination, node));
            }
            for (destination, node) in moved {
                self.nodes.insert(destination, node);
            }
            if self
                .nodes
                .keys()
                .any(|path| path == &authority.lease.source || path.starts_with(&source_prefix))
            {
                return Err(ExecutorMutationErrorV2::AppliedButStateUncertain(
                    "bounded fake move left source descendants".into(),
                ));
            }
            if self
                .applied_uncertain_after_bounded_move
                .as_ref()
                .is_some_and(|source| source == &authority.lease.source)
            {
                self.applied_uncertain_after_bounded_move.take();
                return Err(ExecutorMutationErrorV2::AppliedButStateUncertain(
                    "injected bounded fake post-move durability uncertainty".into(),
                ));
            }
            Ok(())
        }

        fn rename_node_no_replace(
            &mut self,
            source: &RelativeManagedPath,
            expected: &ExecutorNodeSnapshotV2<Self::Identity>,
            destination: &RelativeManagedPath,
        ) -> Result<(), ExecutorMutationErrorV2> {
            self.rename_calls += 1;
            if self.nodes.contains_key(destination.as_str()) {
                return Err(ExecutorMutationErrorV2::NotApplied(
                    "destination exists".into(),
                ));
            }
            self.ensure_parents(destination.as_str());
            let actual = self
                .nodes
                .get(source.as_str())
                .map(Self::snapshot)
                .ok_or_else(|| ExecutorMutationErrorV2::NotApplied("source missing".into()))?;
            if &actual != expected {
                return Err(ExecutorMutationErrorV2::NotApplied(
                    "source lease changed".into(),
                ));
            }
            if matches!(
                actual.kind,
                ExecutorNodeKindV2::RegularFile { link_count, .. } if link_count != 1
            ) {
                return Err(ExecutorMutationErrorV2::NotApplied(
                    "hard link rejected".into(),
                ));
            }
            let node = self.nodes.remove(source.as_str()).unwrap();
            self.nodes.insert(destination.as_str().into(), node);
            if self
                .post_rename_binding_mismatch
                .as_ref()
                .is_some_and(|expected_source| expected_source == source.as_str())
            {
                self.post_rename_binding_mismatch.take();
                let replacement_identity = self.allocate_identity();
                match self.nodes.get_mut(destination.as_str()) {
                    Some(FakeNode::Directory { identity })
                    | Some(FakeNode::File { identity, .. })
                    | Some(FakeNode::Reparse { identity, .. })
                    | Some(FakeNode::Unsupported { identity }) => {
                        *identity = replacement_identity;
                    }
                    None => unreachable!("fake rename destination was just inserted"),
                }
            }
            let after = self
                .nodes
                .get(destination.as_str())
                .map(Self::snapshot)
                .expect("fake rename destination was just inserted");
            if after != *expected {
                return Err(ExecutorMutationErrorV2::AppliedButStateUncertain(
                    "fake rename returned a different destination binding".into(),
                ));
            }
            if self
                .applied_uncertain_after_rename
                .as_ref()
                .is_some_and(|expected_source| expected_source == source.as_str())
            {
                self.applied_uncertain_after_rename.take();
                return Err(ExecutorMutationErrorV2::AppliedButStateUncertain(
                    "injected fake rename durability uncertainty".into(),
                ));
            }
            Ok(())
        }

        fn copy_regular_file_no_replace(
            &mut self,
            source: &RelativeManagedPath,
            expected_source: &ExecutorNodeSnapshotV2<Self::Identity>,
            temporary: &RelativeManagedPath,
            destination: &RelativeManagedPath,
            expected_destination: &ExecutorFileBindingV2,
        ) -> Result<(), ExecutorMutationErrorV2> {
            self.copy_calls += 1;
            if self.nodes.contains_key(destination.as_str()) {
                return Err(ExecutorMutationErrorV2::NotApplied(
                    "destination exists".into(),
                ));
            }
            let actual = self
                .nodes
                .get(source.as_str())
                .map(Self::snapshot)
                .ok_or_else(|| ExecutorMutationErrorV2::NotApplied("source missing".into()))?;
            if &actual != expected_source {
                return Err(ExecutorMutationErrorV2::NotApplied(
                    "source lease changed".into(),
                ));
            }
            let bytes = match self.nodes.get(source.as_str()) {
                Some(FakeNode::File {
                    bytes,
                    link_count: 1,
                    ..
                }) => bytes.clone(),
                _ => {
                    return Err(ExecutorMutationErrorV2::NotApplied(
                        "source is not a single-link regular file".into(),
                    ))
                }
            };
            if bytes.len() as u64 != expected_destination.size
                || sha256(&bytes) != expected_destination.sha256
            {
                return Err(ExecutorMutationErrorV2::NotApplied(
                    "source binding mismatch".into(),
                ));
            }
            match self.nodes.get_mut(temporary.as_str()) {
                Some(FakeNode::File {
                    bytes: partial,
                    executable,
                    link_count: 1,
                    ..
                }) => {
                    if partial.len() > bytes.len() || bytes[..partial.len()] != partial[..] {
                        partial.clear();
                    }
                    partial.extend_from_slice(&bytes[partial.len()..]);
                    *executable = expected_destination.executable;
                }
                Some(_) => {
                    return Err(ExecutorMutationErrorV2::NotApplied(
                        "temporary is not a resumable single-link file".into(),
                    ))
                }
                None => {
                    self.insert_file(temporary.as_str(), &bytes, expected_destination.executable)
                }
            }
            let snapshot = self
                .nodes
                .get(temporary.as_str())
                .map(Self::snapshot)
                .unwrap();
            self.rename_node_no_replace(temporary, &snapshot, destination)?;
            if self
                .applied_uncertain_after_copy
                .as_ref()
                .is_some_and(|expected_destination| expected_destination == destination.as_str())
            {
                self.applied_uncertain_after_copy.take();
                return Err(ExecutorMutationErrorV2::AppliedButStateUncertain(
                    "injected fake copy durability uncertainty".into(),
                ));
            }
            if let Some((path, bytes)) = self.grow_operation_root_after_copy.take() {
                self.insert_file(&path, &bytes, false);
            }
            Ok(())
        }
    }

    /// Constant-memory filesystem used only to prove the ledger's asymptotic boundary at the
    /// signed 200k-file ceiling. It models recursive audit cost as the exact number of nodes in
    /// the current summary, without allocating 200k fake files or touching NTFS.
    struct ScaleLedgerFilesystem {
        root: PathBuf,
        operation_root: RelativeManagedPath,
        root_snapshot: ExecutorNodeSnapshotV2<u64>,
        current: ManagedDirectoryRemovalSummary,
        inspect_calls: usize,
        full_audit_calls: usize,
        node_visits: usize,
    }

    impl ReconcileFileSystemV2 for ScaleLedgerFilesystem {
        type Identity = u64;
        type BoundedTreeLease = ManagedDirectoryRemovalSummary;
        type BoundedTreeMoveAuthority = ();

        fn install_root(&self) -> &Path {
            &self.root
        }

        fn inspect_node(
            &mut self,
            path: &RelativeManagedPath,
        ) -> Result<Option<ExecutorNodeSnapshotV2<Self::Identity>>, String> {
            self.inspect_calls += 1;
            Ok((path == &self.operation_root).then(|| self.root_snapshot.clone()))
        }

        fn ensure_real_directory(
            &mut self,
            _path: &RelativeManagedPath,
        ) -> Result<bool, ExecutorMutationErrorV2> {
            Err(ExecutorMutationErrorV2::NotApplied(
                "scale filesystem does not mutate directories".into(),
            ))
        }

        fn list_directory_children(
            &mut self,
            _path: &RelativeManagedPath,
        ) -> Result<Vec<String>, String> {
            Err("scale filesystem does not enumerate directories".into())
        }

        fn lease_bounded_tree(
            &mut self,
            source: &RelativeManagedPath,
            expected: &ExecutorNodeSnapshotV2<Self::Identity>,
            limits: ManagedDirectoryRemovalLimits,
        ) -> Result<Self::BoundedTreeLease, String> {
            if source != &self.operation_root || expected != &self.root_snapshot {
                return Err("scale audit belongs to another root binding".into());
            }
            require_bounded_operation_summary(self.current, limits)
                .map_err(|error| error.to_string())?;
            self.full_audit_calls += 1;
            self.node_visits = self
                .node_visits
                .checked_add(self.current.entries)
                .ok_or_else(|| "scale node-visit counter overflowed".to_string())?;
            Ok(self.current)
        }

        fn bounded_tree_lease_summary(
            lease: &Self::BoundedTreeLease,
        ) -> ManagedDirectoryRemovalSummary {
            *lease
        }

        fn revalidate_bounded_tree_lease(
            &mut self,
            lease: &Self::BoundedTreeLease,
        ) -> Result<(), String> {
            self.node_visits = self
                .node_visits
                .checked_add(self.current.entries)
                .ok_or_else(|| "scale node-visit counter overflowed".to_string())?;
            if lease != &self.current {
                return Err("scale bounded-tree summary changed".into());
            }
            Ok(())
        }

        fn prepare_bounded_tree_move(
            &mut self,
            _source: &RelativeManagedPath,
            _expected: &ExecutorNodeSnapshotV2<Self::Identity>,
            _destination: &RelativeManagedPath,
            _destination_depth_within_cleanup_root: usize,
            _limits: ManagedDirectoryRemovalLimits,
        ) -> Result<Self::BoundedTreeMoveAuthority, String> {
            Err("scale filesystem does not prepare moves".into())
        }

        fn bounded_tree_move_summary(
            _authority: &Self::BoundedTreeMoveAuthority,
        ) -> ManagedDirectoryRemovalSummary {
            ManagedDirectoryRemovalSummary {
                entries: 0,
                allocated_bytes: 0,
                max_depth: 0,
            }
        }

        fn revalidate_bounded_tree_move(
            &mut self,
            _authority: &Self::BoundedTreeMoveAuthority,
        ) -> Result<(), String> {
            Err("scale filesystem does not revalidate moves".into())
        }

        fn move_bounded_tree_no_replace(
            &mut self,
            _authority: Self::BoundedTreeMoveAuthority,
        ) -> Result<(), ExecutorMutationErrorV2> {
            Err(ExecutorMutationErrorV2::NotApplied(
                "scale filesystem does not move trees".into(),
            ))
        }

        fn rename_node_no_replace(
            &mut self,
            _source: &RelativeManagedPath,
            _expected: &ExecutorNodeSnapshotV2<Self::Identity>,
            _destination: &RelativeManagedPath,
        ) -> Result<(), ExecutorMutationErrorV2> {
            Err(ExecutorMutationErrorV2::NotApplied(
                "scale filesystem does not rename nodes".into(),
            ))
        }

        fn copy_regular_file_no_replace(
            &mut self,
            _source: &RelativeManagedPath,
            _expected_source: &ExecutorNodeSnapshotV2<Self::Identity>,
            _temporary: &RelativeManagedPath,
            _destination: &RelativeManagedPath,
            _expected_destination: &ExecutorFileBindingV2,
        ) -> Result<(), ExecutorMutationErrorV2> {
            Err(ExecutorMutationErrorV2::NotApplied(
                "scale filesystem does not copy files".into(),
            ))
        }
    }

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    fn target_marker(install_id: Uuid, channel: BuildChannel) -> ActiveInstanceV2 {
        let release_id = format!("rel_{}", "a".repeat(24));
        let release_hash = "b".repeat(64);
        let runtime_hash = "c".repeat(64);
        let game_hash = "d".repeat(64);
        ActiveInstanceV2::new(
            install_id,
            channel,
            1,
            release_id.clone(),
            PresetId::Medium,
            release_hash.clone(),
            runtime_hash.clone(),
            game_hash.clone(),
            TrustedReleaseEvidence {
                schema_version: 1,
                channel,
                roles: TrustedRoleVersions {
                    root: 1,
                    timestamp: 1,
                    snapshot: 1,
                    targets: 1,
                },
                current: TrustedTargetEvidence {
                    name: "current.json".into(),
                    length: 1,
                    sha256: "e".repeat(64),
                },
                release_manifest: TrustedTargetEvidence {
                    name: format!("release-{release_id}.json"),
                    length: 1,
                    sha256: release_hash,
                },
                java_runtime_lock: TrustedTargetEvidence {
                    name: format!("runtime-windows-x64-{runtime_hash}.json"),
                    length: 1,
                    sha256: runtime_hash,
                },
                game_runtime_lock: TrustedTargetEvidence {
                    name: format!("game-runtime-windows-x64-{game_hash}.json"),
                    length: 1,
                    sha256: game_hash,
                },
            },
        )
        .unwrap()
    }

    fn plan(install_id: Uuid, operation_id: Uuid) -> ReconcilePlanV2 {
        let bytes = b"new-content";
        let hash = sha256(bytes);
        ReconcilePlanV2 {
            schema_version: 2,
            install_id,
            operation_id,
            channel: BuildChannel::Stable,
            kind: OperationKind::Install,
            base: None,
            target: target_marker(install_id, BuildChannel::Stable),
            strict_roots: vec!["mods".into()],
            preserved_paths: vec![],
            desired_files: vec![PlannedFileV2 {
                path: "data/new.bin".into(),
                signed_size: bytes.len() as u64,
                signed_sha256: hash.clone(),
                installed_size: bytes.len() as u64,
                installed_sha256: hash.clone(),
                executable: false,
                policy: FilePolicy::Exact,
            }],
            disk_budget: DiskBudgetV2::new(0, 0, 0, bytes.len() as u64).unwrap(),
            mutations: vec![
                JournalMutation::Quarantine {
                    source_path: "legacy.bin".into(),
                    backup_slot: 0,
                },
                JournalMutation::EnsureDirectory {
                    destination_path: "data".into(),
                },
                JournalMutation::InstallFile {
                    destination_path: "data/new.bin".into(),
                    staging_slot: 0,
                    size: bytes.len() as u64,
                    sha256: hash,
                    executable: false,
                },
            ],
        }
    }

    fn trusted_files(
        exact_bytes: &[u8],
        mutable_bytes: &[u8],
        release_suffix: char,
        metadata_version: u64,
    ) -> TrustedRelease {
        const RUNTIME_HASH: &str =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        const GAME_HASH: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let game_template = contracts::tests::game_runtime_lock();
        let mut runtime_json = contracts::tests::runtime_lock();
        runtime_json["minecraft"]["versionJsonUrl"] =
            game_template["provenance"]["minecraftVersionJson"]["url"].clone();
        runtime_json["minecraft"]["versionJsonSha1"] =
            game_template["provenance"]["minecraftVersionJson"]["sha1"].clone();
        let runtime_bytes = serde_json::to_vec(&runtime_json).unwrap();
        let runtime_lock = RuntimeLock::parse_and_validate(&runtime_bytes).unwrap();
        let game_json = contracts::tests::verified_game_runtime_lock_for(
            RUNTIME_HASH,
            &runtime_lock.java.archive.sha256,
            &runtime_lock.extracted_tree_sha256().unwrap(),
        );
        let game_bytes = serde_json::to_vec(&game_json).unwrap();
        let game_runtime_lock = GameRuntimeLock::parse_and_validate(&game_bytes).unwrap();

        let release_id = format!("rel_{}", release_suffix.to_string().repeat(24));
        let mut manifest_json = release::tests::manifest();
        manifest_json["release"]["id"] = serde_json::Value::String(release_id.clone());
        manifest_json["runtime"]["java"]["archive"]["sha256"] =
            serde_json::Value::String(runtime_lock.java.archive.sha256.clone());
        manifest_json["runtime"]["java"]["runtimeLockSha256"] =
            serde_json::Value::String(RUNTIME_HASH.into());
        manifest_json["runtime"]["java"]["runtimeTarget"] =
            serde_json::Value::String(format!("runtime-windows-x64-{RUNTIME_HASH}.json"));
        manifest_json["runtime"]["game"]["runtimeLockSha256"] =
            serde_json::Value::String(GAME_HASH.into());
        manifest_json["runtime"]["game"]["runtimeTarget"] =
            serde_json::Value::String(format!("game-runtime-windows-x64-{GAME_HASH}.json"));
        for preset in manifest_json["presets"].as_array_mut().unwrap() {
            for file in preset["files"].as_array_mut().unwrap() {
                let bytes = match file["path"].as_str().unwrap() {
                    "mods/fragment-launch-guard.jar" => exact_bytes,
                    "options.txt" => mutable_bytes,
                    path => panic!("unexpected manifest fixture path: {path}"),
                };
                file["size"] = serde_json::Value::from(bytes.len() as u64);
                file["sha256"] = serde_json::Value::String(sha256(bytes));
            }
        }
        let manifest_bytes = serde_json::to_vec(&manifest_json).unwrap();
        let manifest = ReleaseManifest::parse_and_validate(&manifest_bytes).unwrap();
        manifest.bind_runtime_lock(&runtime_lock).unwrap();
        manifest
            .bind_game_runtime_lock(&runtime_lock, &game_runtime_lock)
            .unwrap();
        let current = CurrentPointer {
            schema_version: 1,
            channel: BuildChannel::Stable,
            release_id: release_id.clone(),
            manifest_target: format!("release-{release_id}.json"),
        };
        let evidence = TrustedReleaseEvidence {
            schema_version: 1,
            channel: BuildChannel::Stable,
            roles: TrustedRoleVersions {
                root: 1,
                timestamp: metadata_version,
                snapshot: metadata_version,
                targets: metadata_version,
            },
            current: TrustedTargetEvidence {
                name: "current.json".into(),
                length: 128,
                sha256: sha256(format!("current-{release_id}").as_bytes()),
            },
            release_manifest: TrustedTargetEvidence {
                name: current.manifest_target.clone(),
                length: manifest_bytes.len() as u64,
                sha256: sha256(&manifest_bytes),
            },
            java_runtime_lock: TrustedTargetEvidence {
                name: manifest.runtime.java.runtime_target.clone(),
                length: runtime_bytes.len() as u64,
                sha256: RUNTIME_HASH.into(),
            },
            game_runtime_lock: TrustedTargetEvidence {
                name: manifest.runtime.game.runtime_target.clone(),
                length: game_bytes.len() as u64,
                sha256: GAME_HASH.into(),
            },
        };
        TrustedRelease::new_for_test(
            BuildChannel::Stable,
            current,
            manifest,
            runtime_lock,
            game_runtime_lock,
            1,
            evidence,
        )
    }

    fn target_from_trusted(install_id: Uuid, trusted: &TrustedRelease) -> ActiveInstanceV2 {
        ActiveInstanceV2::new(
            install_id,
            BuildChannel::Stable,
            1,
            trusted.manifest().release.id.clone(),
            PresetId::Medium,
            trusted.evidence().release_manifest.sha256.clone(),
            trusted.evidence().java_runtime_lock.sha256.clone(),
            trusted.evidence().game_runtime_lock.sha256.clone(),
            trusted.evidence().clone(),
        )
        .unwrap()
    }

    fn one_file_plan(
        install_id: Uuid,
        operation_id: Uuid,
        trusted: &TrustedRelease,
        path: &str,
        signed_bytes: &[u8],
        installed_bytes: &[u8],
        policy: FilePolicy,
    ) -> ReconcilePlanV2 {
        let signed_sha256 = sha256(signed_bytes);
        let installed_sha256 = sha256(installed_bytes);
        let parent = path.rsplit_once('/').map(|(parent, _)| parent);
        let mut mutations = Vec::new();
        if let Some(parent) = parent {
            mutations.push(JournalMutation::EnsureDirectory {
                destination_path: parent.into(),
            });
        }
        mutations.push(JournalMutation::InstallFile {
            destination_path: path.into(),
            staging_slot: 0,
            size: installed_bytes.len() as u64,
            sha256: installed_sha256.clone(),
            executable: false,
        });
        let plan = ReconcilePlanV2 {
            schema_version: 2,
            install_id,
            operation_id,
            channel: BuildChannel::Stable,
            kind: OperationKind::Install,
            base: None,
            target: target_from_trusted(install_id, trusted),
            strict_roots: vec![path.split('/').next().unwrap().into()],
            preserved_paths: vec![],
            desired_files: vec![PlannedFileV2 {
                path: path.into(),
                signed_size: signed_bytes.len() as u64,
                signed_sha256,
                installed_size: installed_bytes.len() as u64,
                installed_sha256,
                executable: false,
                policy,
            }],
            disk_budget: DiskBudgetV2::new(0, 0, 0, installed_bytes.len() as u64).unwrap(),
            mutations,
        };
        plan.validate(install_id, BuildChannel::Stable).unwrap();
        plan
    }

    fn current_manifest_plan_with_mutable_override(
        install_id: Uuid,
        operation_id: Uuid,
        trusted: &TrustedRelease,
        mutable_bytes: &[u8],
    ) -> ReconcilePlanV2 {
        let preset = trusted
            .manifest()
            .selected_preset(PresetId::Medium)
            .unwrap();
        let mut desired_files = preset
            .files
            .iter()
            .map(|file| {
                let (installed_size, installed_sha256) = if file.path == "options.txt" {
                    (mutable_bytes.len() as u64, sha256(mutable_bytes))
                } else {
                    (file.size, file.sha256.clone())
                };
                PlannedFileV2 {
                    path: file.path.clone(),
                    signed_size: file.size,
                    signed_sha256: file.sha256.clone(),
                    installed_size,
                    installed_sha256,
                    executable: file.executable,
                    policy: file.policy,
                }
            })
            .collect::<Vec<_>>();
        desired_files.sort_by(|left, right| {
            left.path
                .to_lowercase()
                .cmp(&right.path.to_lowercase())
                .then(left.path.cmp(&right.path))
        });
        let mut strict_roots = trusted.manifest().integrity.strict_roots.clone();
        strict_roots.sort_by(|left, right| {
            left.to_lowercase()
                .cmp(&right.to_lowercase())
                .then(left.cmp(right))
        });
        let mut preserved_paths = trusted.manifest().integrity.preserved_paths.clone();
        preserved_paths.sort_by(|left, right| {
            left.to_lowercase()
                .cmp(&right.to_lowercase())
                .then(left.cmp(right))
        });
        let plan = ReconcilePlanV2 {
            schema_version: 2,
            install_id,
            operation_id,
            channel: BuildChannel::Stable,
            kind: OperationKind::Install,
            base: None,
            target: target_from_trusted(install_id, trusted),
            strict_roots,
            preserved_paths,
            desired_files,
            disk_budget: DiskBudgetV2::new(0, 0, 0, 0).unwrap(),
            mutations: Vec::new(),
        };
        plan.validate(install_id, BuildChannel::Stable).unwrap();
        plan
    }

    fn pre_mutation_missing_audit(plan: &ReconcilePlanV2) -> InstanceAudit {
        InstanceAudit {
            missing_files: plan
                .desired_files
                .iter()
                .map(|file| file.path.clone())
                .collect(),
            missing_directories: plan
                .mutations
                .iter()
                .filter_map(|mutation| match mutation {
                    JournalMutation::EnsureDirectory { destination_path } => {
                        Some(destination_path.clone())
                    }
                    _ => None,
                })
                .collect(),
            ..InstanceAudit::default()
        }
    }

    fn write_verified_object(root: &OwnedCasRoot, bytes: &[u8]) -> VerifiedCasObject {
        let expected = ExpectedObject {
            sha256: sha256(bytes),
            size: bytes.len() as u64,
        };
        let relative = cas_object_relative_path(&expected.sha256).unwrap();
        fs::create_dir_all(relative.join_to(root.managed_root()).parent().unwrap()).unwrap();
        fs::write(relative.join_to(root.managed_root()), bytes).unwrap();
        verify_existing_object(root, &expected, 0).unwrap()
    }

    fn artifact_authority(
        root: &OwnedCasRoot,
        trusted: &TrustedRelease,
        install_id: Uuid,
        operation_id: Uuid,
        install_path: &str,
        complete_sha256: &str,
    ) -> (ArtifactInventoryV2, ArtifactPlanV2) {
        let inventory = ArtifactInventoryV2::build(
            root,
            trusted,
            install_id,
            operation_id,
            BuildChannel::Stable,
            PresetId::Medium,
        )
        .unwrap();
        let availability = VerifiedAvailabilityV2::for_test(
            &inventory,
            [(
                complete_sha256.to_owned(),
                ArtifactAvailabilityStateV2::Complete,
            )],
            true,
            true,
        );
        let artifact_plan =
            ArtifactPlanV2::for_reconcile(&inventory, &availability, [install_path.into()])
                .unwrap();
        (inventory, artifact_plan)
    }

    struct ExactProductionFixture {
        _directory: TestRoot,
        root: OwnedCasRoot,
        trusted: TrustedRelease,
        inventory: ArtifactInventoryV2,
        artifact_plan: ArtifactPlanV2,
        plan: ReconcilePlanV2,
        object: VerifiedCasObject,
        bytes: Vec<u8>,
    }

    impl ExactProductionFixture {
        fn new(label: &str, bytes: Vec<u8>) -> Self {
            Self::new_with_metadata_version(label, bytes, 1)
        }

        fn new_with_metadata_version(label: &str, bytes: Vec<u8>, metadata_version: u64) -> Self {
            let directory = TestRoot::new(label);
            let selected = select_install_directory(&directory.0).unwrap();
            let install_id = selected.install_id();
            let root = selected.into_owned_cas_root();
            let operation_id = Uuid::new_v4();
            let trusted = trusted_files(&bytes, b"renderDistance:12\n", 'a', metadata_version);
            let object = write_verified_object(&root, &bytes);
            let path = "mods/fragment-launch-guard.jar";
            let plan = one_file_plan(
                install_id,
                operation_id,
                &trusted,
                path,
                &bytes,
                &bytes,
                FilePolicy::Exact,
            );
            let (inventory, artifact_plan) = artifact_authority(
                &root,
                &trusted,
                install_id,
                operation_id,
                path,
                &sha256(&bytes),
            );
            Self {
                _directory: directory,
                root,
                trusted,
                inventory,
                artifact_plan,
                plan,
                object,
                bytes,
            }
        }

        fn lock(&self) -> InstanceOperationLock {
            InstanceStateStore::new(self.root.install_root(), self.plan.install_id)
                .acquire_operation_lock(self.plan.channel)
                .unwrap()
        }

        fn authority<'a>(
            &'a self,
            lock: &InstanceOperationLock,
        ) -> TrustedReconcileStagingAuthorityV2<'a, 'a> {
            authorize_reconcile_staging_v2(
                &self.plan,
                &self.trusted,
                &self.inventory,
                &self.artifact_plan,
                lock,
                &self.root,
            )
            .unwrap()
        }
    }

    fn trusted_with_role_versions(
        trusted: &TrustedRelease,
        roles: TrustedRoleVersions,
    ) -> TrustedRelease {
        let mut evidence = trusted.evidence().clone();
        evidence.roles = roles;
        TrustedRelease::new_for_test(
            trusted.channel(),
            trusted.current().clone(),
            trusted.manifest().clone(),
            trusted.runtime_lock().clone(),
            trusted.game_runtime_lock().clone(),
            roles.root,
            evidence,
        )
    }

    struct Fixture {
        root: TestRoot,
        plan: ReconcilePlanV2,
        filesystem: FakeFilesystem,
        proofs: Vec<StagingFileProofV2>,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let root = TestRoot::new(label);
            let install_id = Uuid::new_v4();
            let plan = plan(install_id, Uuid::new_v4());
            plan.validate(install_id, BuildChannel::Stable).unwrap();
            let paths = ReconcileOperationPathsV2::from_plan(&plan).unwrap();
            let mut filesystem = FakeFilesystem::new(&root.0);
            filesystem.insert_file("instances/stable/legacy.bin", b"old-content", false);
            filesystem.insert_file(
                paths.staging_file(0).unwrap().as_str(),
                b"new-content",
                false,
            );
            let proofs = audit_staging_files_v2(&plan, &mut filesystem).unwrap();
            Self {
                root,
                plan,
                filesystem,
                proofs,
            }
        }

        fn lock(&self) -> InstanceOperationLock {
            InstanceStateStore::new(&self.root.0, self.plan.install_id)
                .acquire_operation_lock(self.plan.channel)
                .unwrap()
        }

        fn assert_forward(&self) {
            let paths = ReconcileOperationPathsV2::from_plan(&self.plan).unwrap();
            assert_eq!(
                self.filesystem.file_bytes("instances/stable/data/new.bin"),
                Some(b"new-content".as_slice())
            );
            assert!(!self.filesystem.contains("instances/stable/legacy.bin"));
            assert!(self
                .filesystem
                .contains(paths.backup_node(0).unwrap().as_str()));
            assert_eq!(
                self.filesystem
                    .file_bytes(paths.staging_file(0).unwrap().as_str()),
                Some(b"new-content".as_slice())
            );
        }

        fn assert_rolled_back(&self) {
            let paths = ReconcileOperationPathsV2::from_plan(&self.plan).unwrap();
            assert_eq!(
                self.filesystem.file_bytes("instances/stable/legacy.bin"),
                Some(b"old-content".as_slice())
            );
            assert!(!self.filesystem.contains("instances/stable/data/new.bin"));
            assert_eq!(
                self.filesystem
                    .file_bytes(paths.staging_file(0).unwrap().as_str()),
                Some(b"new-content".as_slice())
            );
        }
    }

    #[test]
    fn deterministic_paths_are_channel_operation_and_slot_scoped() {
        let stable = plan(Uuid::new_v4(), Uuid::new_v4());
        let stable_paths = ReconcileOperationPathsV2::from_plan(&stable).unwrap();
        assert_eq!(
            stable_paths.staging_file(7).unwrap().as_str(),
            format!(
                "state/reconcile/stable/operations/{}/staging/00000007.bin",
                stable.operation_id
            )
        );
        assert_eq!(
            stable_paths.backup_node(7).unwrap().as_str(),
            format!(
                "state/reconcile/stable/operations/{}/backup/00000007.node",
                stable.operation_id
            )
        );
        assert_eq!(
            stable_paths.rollback_node(7).unwrap().as_str(),
            format!(
                "state/reconcile/stable/operations/{}/rollback/00000007.node",
                stable.operation_id
            )
        );
        assert_eq!(
            stable_paths.replacement_node(7).unwrap().as_str(),
            format!(
                "state/reconcile/stable/operations/{}/replacements/00000007.node",
                stable.operation_id
            )
        );
        assert_eq!(
            stable_paths.install_temporary(7).unwrap().as_str(),
            format!(
                "state/reconcile/stable/operations/{}/temporary/00000007.tmp",
                stable.operation_id
            )
        );
    }

    #[test]
    fn whole_tree_preflight_is_cumulative_exact_and_root_bound() {
        let root = TestRoot::new("whole-tree-cumulative");
        let install_id = Uuid::new_v4();
        let mut plan = plan(install_id, Uuid::new_v4());
        let ensure = plan.mutations[1].clone();
        let install = plan.mutations[2].clone();
        plan.mutations = vec![
            JournalMutation::Quarantine {
                source_path: "legacy-a.bin".into(),
                backup_slot: 0,
            },
            JournalMutation::Quarantine {
                source_path: "legacy-b.bin".into(),
                backup_slot: 1,
            },
            ensure,
            install,
        ];
        plan.validate(install_id, BuildChannel::Stable).unwrap();
        let paths = ReconcileOperationPathsV2::from_plan(&plan).unwrap();
        let mut filesystem = FakeFilesystem::new(&root.0);
        filesystem.insert_file("instances/stable/legacy-a.bin", b"a", false);
        filesystem.insert_file("instances/stable/legacy-b.bin", b"b", false);
        filesystem.insert_file(
            paths.staging_file(0).unwrap().as_str(),
            b"new-content",
            false,
        );
        prepare_workspace(&mut filesystem, &paths).unwrap();

        assert!(matches!(
            preflight_whole_tree_moves_v2(
                &plan,
                &mut filesystem,
                &paths,
                WholeTreeMoveDirectionV2::RollForward,
                ManagedDirectoryRemovalLimits {
                    max_entries: 8,
                    max_allocated_bytes: u64::MAX,
                    max_depth: 8,
                },
            ),
            Err(ReconcileExecutorErrorV2::UnsafeNode(_))
        ));
        assert!(filesystem.contains("instances/stable/legacy-a.bin"));
        assert!(filesystem.contains("instances/stable/legacy-b.bin"));
        assert!(!filesystem.contains(paths.backup_node(0).unwrap().as_str()));
        assert!(!filesystem.contains(paths.backup_node(1).unwrap().as_str()));

        let exact_limit = ManagedDirectoryRemovalLimits {
            max_entries: 9,
            max_allocated_bytes: 15,
            max_depth: 8,
        };
        let mut admission = preflight_whole_tree_moves_v2(
            &plan,
            &mut filesystem,
            &paths,
            WholeTreeMoveDirectionV2::RollForward,
            exact_limit,
        )
        .unwrap();
        let reservation = admission.into_operation[0].take().unwrap();
        let foreign_root = TestRoot::new("whole-tree-foreign");
        let mut foreign = FakeFilesystem::new(&foreign_root.0);
        foreign.nodes = filesystem.nodes.clone();
        let source = paths.instance_path("legacy-a.bin").unwrap();
        let destination = paths.backup_node(0).unwrap();
        let current = filesystem.inspect_node(&source).unwrap().unwrap();
        assert!(matches!(
            move_reserved_bounded_and_verify(
                &mut foreign,
                &mut admission.capacity_ledger,
                reservation,
                &source,
                &current,
                &destination,
            ),
            Err(ReconcileExecutorErrorV2::InvalidScope(_))
        ));

        filesystem.insert_file(
            &format!("{}/extra.node", paths.backup_root.as_str()),
            b"extra",
            false,
        );
        assert!(preflight_whole_tree_moves_v2(
            &plan,
            &mut filesystem,
            &paths,
            WholeTreeMoveDirectionV2::RollForward,
            ManagedDirectoryRemovalLimits {
                max_entries: 100,
                max_allocated_bytes: u64::MAX,
                max_depth: 8,
            },
        )
        .is_err());
        assert!(filesystem.contains("instances/stable/legacy-a.bin"));
    }

    #[test]
    fn unrelated_operation_root_growth_is_rejected_by_the_final_ledger_audit() {
        let root = TestRoot::new("whole-tree-live-growth");
        let install_id = Uuid::new_v4();
        let mut plan = plan(install_id, Uuid::new_v4());
        let ensure = plan.mutations[1].clone();
        let install = plan.mutations[2].clone();
        plan.mutations = vec![
            JournalMutation::Quarantine {
                source_path: "legacy-a.bin".into(),
                backup_slot: 0,
            },
            JournalMutation::Quarantine {
                source_path: "legacy-b.bin".into(),
                backup_slot: 1,
            },
            ensure,
            install,
        ];
        plan.validate(install_id, BuildChannel::Stable).unwrap();
        let paths = ReconcileOperationPathsV2::from_plan(&plan).unwrap();
        let mut filesystem = FakeFilesystem::new(&root.0);
        filesystem.insert_file("instances/stable/legacy-a.bin", b"a", false);
        filesystem.insert_file("instances/stable/legacy-b.bin", b"b", false);
        filesystem.insert_file(
            paths.staging_file(0).unwrap().as_str(),
            b"new-content",
            false,
        );
        prepare_workspace(&mut filesystem, &paths).unwrap();
        let first_backup = paths.backup_node(0).unwrap();
        let first = filesystem
            .nodes
            .remove("instances/stable/legacy-a.bin")
            .unwrap();
        filesystem.nodes.insert(first_backup.as_str().into(), first);

        let generous = ManagedDirectoryRemovalLimits {
            max_entries: 100,
            max_allocated_bytes: 1024,
            max_depth: 16,
        };
        let baseline = filesystem
            .bounded_tree_lease(&paths.operation_root, generous)
            .unwrap()
            .summary;
        let second_source = paths.instance_path("legacy-b.bin").unwrap();
        let candidate = filesystem
            .bounded_tree_lease(&second_source, generous)
            .unwrap()
            .summary;
        let exact = add_operation_root_growth(
            baseline,
            candidate,
            2,
            plan.disk_budget.allocation_unit_bytes,
            generous,
        )
        .unwrap();
        let exact_limits = ManagedDirectoryRemovalLimits {
            max_entries: exact.entries,
            max_allocated_bytes: exact.allocated_bytes,
            max_depth: exact.max_depth,
        };
        let mut preflight = preflight_whole_tree_moves_v2(
            &plan,
            &mut filesystem,
            &paths,
            WholeTreeMoveDirectionV2::RollForward,
            exact_limits,
        )
        .unwrap();
        let reservation = preflight.into_operation[1].take().unwrap();
        let second_destination = paths.backup_node(1).unwrap();
        let current = filesystem.inspect_node(&second_source).unwrap().unwrap();
        filesystem.grow_operation_root_before_bounded_move =
            Some((first_backup.as_str().into(), vec![b'x'; 128]));

        move_reserved_bounded_and_verify(
            &mut filesystem,
            &mut preflight.capacity_ledger,
            reservation,
            &second_source,
            &current,
            &second_destination,
        )
        .unwrap();
        let error =
            audit_final_operation_root_capacity(&mut filesystem, &preflight.capacity_ledger)
                .unwrap_err();
        assert!(matches!(
            error,
            ReconcileExecutorErrorV2::Interrupted(_) | ReconcileExecutorErrorV2::UnsafeNode(_)
        ));
        assert!(!filesystem.contains(second_source.as_str()));
        assert!(filesystem.contains(second_destination.as_str()));
    }

    #[test]
    fn late_unrelated_growth_after_copy_is_fail_closed_by_the_final_audit() {
        let mut fixture = Fixture::new("late-operation-root-growth");
        fixture.plan.mutations[0] = JournalMutation::Quarantine {
            source_path: "legacy".into(),
            backup_slot: 0,
        };
        fixture
            .plan
            .validate(fixture.plan.install_id, BuildChannel::Stable)
            .unwrap();
        fixture
            .filesystem
            .nodes
            .remove("instances/stable/legacy.bin");
        fixture
            .filesystem
            .insert_file("instances/stable/legacy/old.bin", b"old", false);
        let paths = ReconcileOperationPathsV2::from_plan(&fixture.plan).unwrap();
        fixture.filesystem.grow_operation_root_after_copy = Some((
            format!("{}/late.bin", paths.backup_node(0).unwrap().as_str()),
            b"external".to_vec(),
        ));
        let lock = fixture.lock();

        let error = roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap_err();
        assert!(matches!(error, ReconcileExecutorErrorV2::Interrupted(_)));
        assert!(fixture.filesystem.contains("instances/stable/data/new.bin"));
        assert!(fixture.filesystem.contains(&format!(
            "{}/late.bin",
            paths.backup_node(0).unwrap().as_str()
        )));
    }

    #[test]
    fn operation_root_full_audits_are_constant_across_many_install_slots() {
        const FILE_COUNT: u32 = 128;
        let root = TestRoot::new("linear-operation-root-audits");
        let install_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let bytes = b"x";
        let hash = sha256(bytes);
        let mut desired_files = Vec::with_capacity(FILE_COUNT as usize);
        let mut mutations = Vec::with_capacity(FILE_COUNT as usize + 1);
        mutations.push(JournalMutation::EnsureDirectory {
            destination_path: "data".into(),
        });
        for slot in 0..FILE_COUNT {
            let path = format!("data/{slot:06}.bin");
            desired_files.push(PlannedFileV2 {
                path: path.clone(),
                signed_size: bytes.len() as u64,
                signed_sha256: hash.clone(),
                installed_size: bytes.len() as u64,
                installed_sha256: hash.clone(),
                executable: false,
                policy: FilePolicy::Exact,
            });
            mutations.push(JournalMutation::InstallFile {
                destination_path: path,
                staging_slot: slot,
                size: bytes.len() as u64,
                sha256: hash.clone(),
                executable: false,
            });
        }
        let plan = ReconcilePlanV2 {
            schema_version: 2,
            install_id,
            operation_id,
            channel: BuildChannel::Stable,
            kind: OperationKind::Install,
            base: None,
            target: target_marker(install_id, BuildChannel::Stable),
            strict_roots: vec!["data".into()],
            preserved_paths: vec![],
            desired_files,
            disk_budget: DiskBudgetV2::new(0, 0, 0, FILE_COUNT as u64).unwrap(),
            mutations,
        };
        plan.validate(install_id, BuildChannel::Stable).unwrap();
        let paths = ReconcileOperationPathsV2::from_plan(&plan).unwrap();
        let mut filesystem = FakeFilesystem::new(&root.0);
        prepare_workspace(&mut filesystem, &paths).unwrap();
        for slot in 0..FILE_COUNT {
            filesystem.insert_file(paths.staging_file(slot).unwrap().as_str(), bytes, false);
        }
        let proofs = audit_staging_files_v2(&plan, &mut filesystem).unwrap();
        let lock = InstanceStateStore::new(&root.0, install_id)
            .acquire_operation_lock(BuildChannel::Stable)
            .unwrap();

        reset_scale_counters();
        let report = roll_forward_v2(&plan, &lock, &proofs, &mut filesystem).unwrap();
        assert_eq!(report.mutations.len(), FILE_COUNT as usize + 1);
        assert_eq!(filesystem.copy_calls, FILE_COUNT as usize);
        assert_eq!(
            filesystem.bounded_tree_lease_calls, 2,
            "one baseline and one final full operation-root audit must cover every install slot"
        );
        assert_eq!(
            filesystem.bounded_tree_node_visits,
            4 * (FILE_COUNT as usize + 6),
            "baseline/final lease plus their revalidation must each visit the tree once"
        );
        let (plan_hashes, recreated_visits, recreated_lookups, growth_reservations) =
            scale_counters();
        assert_eq!(plan_hashes, 2, "plan hashing must be per operation");
        assert_eq!(
            recreated_visits,
            4 * (FILE_COUNT as usize + 1),
            "four operation-level recreated-path indexes must each scan the mutation set once"
        );
        assert_eq!(recreated_lookups, 0);
        assert_eq!(
            growth_reservations, FILE_COUNT as usize,
            "every fresh install gets exactly one JIT ledger reservation"
        );
    }

    #[test]
    fn operation_root_ledger_is_linear_at_two_hundred_thousand_files() {
        const FILE_COUNT: usize = release::MAX_FILES_PER_PRESET;
        const BASELINE_ENTRIES: usize = 6;
        let operation_root = managed_path("state/reconcile/stable/operations/scale").unwrap();
        let root_snapshot = ExecutorNodeSnapshotV2 {
            identity: 1,
            kind: ExecutorNodeKindV2::RealDirectory,
        };
        let baseline_summary = ManagedDirectoryRemovalSummary {
            entries: BASELINE_ENTRIES,
            allocated_bytes: 0,
            max_depth: 2,
        };
        let limits = ManagedDirectoryRemovalLimits {
            max_entries: BASELINE_ENTRIES + FILE_COUNT,
            max_allocated_bytes: (FILE_COUNT as u64) * 2,
            max_depth: 2,
        };
        let mut filesystem = ScaleLedgerFilesystem {
            root: PathBuf::from("scale-ledger-root"),
            operation_root: operation_root.clone(),
            root_snapshot: root_snapshot.clone(),
            current: baseline_summary,
            inspect_calls: 0,
            full_audit_calls: 0,
            node_visits: 0,
        };

        let baseline = filesystem
            .lease_bounded_tree(&operation_root, &root_snapshot, limits)
            .unwrap();
        filesystem.revalidate_bounded_tree_lease(&baseline).unwrap();
        let mut ledger = OperationRootCapacityLedgerV2 {
            install_root: filesystem.root.clone(),
            operation_root,
            expected_root: root_snapshot,
            current: baseline_summary,
            allocation_unit: 1,
            limits,
        };

        reset_scale_counters();
        for _ in 0..FILE_COUNT {
            let reservation = reserve_operation_root_growth(
                &mut filesystem,
                &ledger,
                ManagedDirectoryRemovalSummary {
                    entries: 1,
                    allocated_bytes: 1,
                    max_depth: 0,
                },
                2,
                1,
            )
            .unwrap();
            let after = reservation.after;
            ledger.commit_growth(reservation).unwrap();
            filesystem.current = after;
        }
        audit_final_operation_root_capacity(&mut filesystem, &ledger).unwrap();

        let (plan_hashes, recreated_visits, recreated_lookups, growth_reservations) =
            scale_counters();
        assert_eq!(plan_hashes, 0);
        assert_eq!(recreated_visits, 0);
        assert_eq!(recreated_lookups, 0);
        assert_eq!(growth_reservations, FILE_COUNT);
        assert_eq!(filesystem.inspect_calls, FILE_COUNT + 1);
        assert_eq!(filesystem.full_audit_calls, 2);
        assert_eq!(
            filesystem.node_visits,
            2 * FILE_COUNT + 4 * BASELINE_ENTRIES,
            "baseline/final leases and revalidations must stay within a checked linear bound"
        );
        assert_eq!(ledger.current.entries, FILE_COUNT + BASELINE_ENTRIES);
        assert_eq!(ledger.current.allocated_bytes, (FILE_COUNT as u64) * 2);
    }

    #[test]
    fn operation_root_ledger_overflow_precedes_install_mutation() {
        let root = TestRoot::new("ledger-overflow-before-copy");
        let operation_root = managed_path("state/reconcile/stable/operations/overflow").unwrap();
        let staging =
            managed_path(&format!("{}/staging/00000000.bin", operation_root.as_str())).unwrap();
        let rollback = managed_path(&format!(
            "{}/rollback/00000000.node",
            operation_root.as_str()
        ))
        .unwrap();
        let temporary = managed_path(&format!(
            "{}/temporary/00000000.tmp",
            operation_root.as_str()
        ))
        .unwrap();
        let destination = managed_path("instances/stable/data/new.bin").unwrap();
        let mut filesystem = FakeFilesystem::new(&root.0);
        filesystem.ensure_real_directory(&operation_root).unwrap();
        filesystem.insert_file(staging.as_str(), b"x", false);
        let staging_node = filesystem.inspect_node(&staging).unwrap().unwrap();
        let root_node = filesystem.inspect_node(&operation_root).unwrap().unwrap();
        let current = ManagedDirectoryRemovalSummary {
            entries: 2,
            allocated_bytes: 1,
            max_depth: 2,
        };
        let mut ledger = OperationRootCapacityLedgerV2 {
            install_root: root.0.clone(),
            operation_root,
            expected_root: root_node,
            current,
            allocation_unit: 1,
            limits: ManagedDirectoryRemovalLimits {
                max_entries: current.entries,
                max_allocated_bytes: current.allocated_bytes,
                max_depth: current.max_depth,
            },
        };
        let before = filesystem.nodes.clone();

        let error = roll_forward_install(
            &mut filesystem,
            InstallMutationPathsV2 {
                staging: &staging,
                destination: &destination,
                rollback: &rollback,
                temporary: &temporary,
            },
            &staging_node,
            &ExecutorFileBindingV2 {
                size: 1,
                sha256: sha256(b"x"),
                executable: false,
            },
            &mut ledger,
        )
        .unwrap_err();

        assert!(matches!(error, ReconcileExecutorErrorV2::UnsafeNode(_)));
        assert_eq!(filesystem.copy_calls, 0);
        assert_eq!(filesystem.nodes, before);
        assert_eq!(ledger.current, current);
    }

    #[test]
    fn operation_root_removal_underflow_precedes_rollback_slot_rename() {
        let root = TestRoot::new("ledger-underflow-before-rename");
        let operation_root = managed_path("state/reconcile/stable/operations/underflow").unwrap();
        let staging =
            managed_path(&format!("{}/staging/00000000.bin", operation_root.as_str())).unwrap();
        let rollback = managed_path(&format!(
            "{}/rollback/00000000.node",
            operation_root.as_str()
        ))
        .unwrap();
        let temporary = managed_path(&format!(
            "{}/temporary/00000000.tmp",
            operation_root.as_str()
        ))
        .unwrap();
        let destination = managed_path("instances/stable/data/new.bin").unwrap();
        let mut filesystem = FakeFilesystem::new(&root.0);
        filesystem.ensure_real_directory(&operation_root).unwrap();
        filesystem.insert_file(staging.as_str(), b"x", false);
        filesystem.insert_file(rollback.as_str(), b"x", false);
        let staging_node = filesystem.inspect_node(&staging).unwrap().unwrap();
        let root_node = filesystem.inspect_node(&operation_root).unwrap().unwrap();
        let current = ManagedDirectoryRemovalSummary {
            entries: 0,
            allocated_bytes: 0,
            max_depth: 2,
        };
        let mut ledger = OperationRootCapacityLedgerV2 {
            install_root: root.0.clone(),
            operation_root,
            expected_root: root_node,
            current,
            allocation_unit: 1,
            limits: ManagedDirectoryRemovalLimits {
                max_entries: 10,
                max_allocated_bytes: 10,
                max_depth: 4,
            },
        };
        let before = filesystem.nodes.clone();

        let error = roll_forward_install(
            &mut filesystem,
            InstallMutationPathsV2 {
                staging: &staging,
                destination: &destination,
                rollback: &rollback,
                temporary: &temporary,
            },
            &staging_node,
            &ExecutorFileBindingV2 {
                size: 1,
                sha256: sha256(b"x"),
                executable: false,
            },
            &mut ledger,
        )
        .unwrap_err();

        assert!(matches!(error, ReconcileExecutorErrorV2::UnsafeNode(_)));
        assert_eq!(filesystem.rename_calls, 0);
        assert_eq!(filesystem.nodes, before);
        assert_eq!(ledger.current, current);
    }

    #[test]
    fn operation_root_removal_underflow_precedes_bounded_tree_move() {
        let root = TestRoot::new("ledger-underflow-before-tree-move");
        let operation_root =
            managed_path("state/reconcile/stable/operations/tree-underflow").unwrap();
        let source =
            managed_path(&format!("{}/backup/00000000.node", operation_root.as_str())).unwrap();
        let destination = managed_path("instances/stable/restored.bin").unwrap();
        let mut filesystem = FakeFilesystem::new(&root.0);
        filesystem.ensure_real_directory(&operation_root).unwrap();
        filesystem
            .ensure_real_directory(&managed_path("instances/stable").unwrap())
            .unwrap();
        filesystem.insert_file(source.as_str(), b"x", false);
        let operation_root_node = filesystem.inspect_node(&operation_root).unwrap().unwrap();
        let source_node = filesystem.inspect_node(&source).unwrap().unwrap();
        let limits = ManagedDirectoryRemovalLimits {
            max_entries: 10,
            max_allocated_bytes: 10,
            max_depth: 4,
        };
        let source_summary = filesystem
            .bounded_tree_lease(&source, limits)
            .unwrap()
            .summary;
        let current = ManagedDirectoryRemovalSummary {
            entries: 0,
            allocated_bytes: 0,
            max_depth: 2,
        };
        let mut ledger = OperationRootCapacityLedgerV2 {
            install_root: root.0.clone(),
            operation_root: operation_root.clone(),
            expected_root: operation_root_node,
            current,
            allocation_unit: 1,
            limits,
        };
        let reservation = ReservedWholeTreeMoveV2 {
            install_root: root.0.clone(),
            operation_root,
            source: source.clone(),
            destination: destination.clone(),
            expected_root: source_node.clone(),
            maximum_summary: source_summary,
            destination_depth_within_cleanup_root: 0,
            namespace_allocation_reserve: 0,
            increases_operation_root: false,
            limits,
        };
        let before = filesystem.nodes.clone();

        let error = move_reserved_bounded_and_verify(
            &mut filesystem,
            &mut ledger,
            reservation,
            &source,
            &source_node,
            &destination,
        )
        .unwrap_err();

        assert!(matches!(error, ReconcileExecutorErrorV2::UnsafeNode(_)));
        assert_eq!(filesystem.bounded_tree_move_calls, 0);
        assert_eq!(filesystem.nodes, before);
        assert_eq!(ledger.current, current);
    }

    #[test]
    fn recreated_path_index_visits_two_hundred_thousand_mutations_once() {
        const FILE_COUNT: usize = release::MAX_FILES_PER_PRESET;
        let install_id = Uuid::new_v4();
        let mut scale_plan = plan(install_id, Uuid::new_v4());
        let hash = "a".repeat(64);
        scale_plan.mutations = (0..FILE_COUNT)
            .map(|slot| JournalMutation::InstallFile {
                destination_path: format!("mods/{slot:06}.jar"),
                staging_slot: slot as u32,
                size: 1,
                sha256: hash.clone(),
                executable: false,
            })
            .collect();

        reset_scale_counters();
        let index = RecreatedPathIndexV2::from_plan(&scale_plan).unwrap();
        assert_eq!(index.expected.len(), FILE_COUNT + 1);
        for slot in 0..FILE_COUNT {
            assert!(index.recreates(&format!("mods/{slot:06}.jar")));
        }
        let (plan_hashes, recreated_visits, recreated_lookups, growth_reservations) =
            scale_counters();
        assert_eq!(plan_hashes, 0);
        assert_eq!(recreated_visits, FILE_COUNT);
        assert_eq!(recreated_lookups, FILE_COUNT);
        assert_eq!(growth_reservations, 0);
    }

    #[test]
    fn pending_destination_audit_indexes_maximum_mixed_mutation_shape() {
        const GROUP_COUNT: usize = 66_666;
        let root = TestRoot::new("pending-prefix-index-scale");
        let install_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let hash = sha256(b"x");
        let desired_files = (0..GROUP_COUNT)
            .map(|slot| PlannedFileV2 {
                path: format!("mods/q{slot:06}/new.jar"),
                signed_size: 1,
                signed_sha256: hash.clone(),
                installed_size: 1,
                installed_sha256: hash.clone(),
                executable: false,
                policy: FilePolicy::Exact,
            })
            .collect::<Vec<_>>();
        let mut mutations = Vec::with_capacity(GROUP_COUNT * 3);
        mutations.extend((0..GROUP_COUNT).map(|slot| JournalMutation::Quarantine {
            source_path: format!("mods/q{slot:06}"),
            backup_slot: slot as u32,
        }));
        mutations.extend(
            (0..GROUP_COUNT).map(|slot| JournalMutation::EnsureDirectory {
                destination_path: format!("mods/q{slot:06}"),
            }),
        );
        mutations.extend((0..GROUP_COUNT).map(|slot| JournalMutation::InstallFile {
            destination_path: format!("mods/q{slot:06}/new.jar"),
            staging_slot: slot as u32,
            size: 1,
            sha256: hash.clone(),
            executable: false,
        }));
        let plan = ReconcilePlanV2 {
            schema_version: 2,
            install_id,
            operation_id,
            channel: BuildChannel::Stable,
            kind: OperationKind::Install,
            base: None,
            target: target_marker(install_id, BuildChannel::Stable),
            strict_roots: vec!["mods".into()],
            preserved_paths: vec![],
            desired_files,
            disk_budget: DiskBudgetV2::new(0, 0, 0, GROUP_COUNT as u64).unwrap(),
            mutations,
        };
        let paths = ReconcileOperationPathsV2::from_plan(&plan).unwrap();
        let mut filesystem = FakeFilesystem::new(&root.0);
        prepare_workspace(&mut filesystem, &paths).unwrap();
        filesystem.synthetic_pending_quarantine_sources = true;
        filesystem.inspect_calls = 0;

        reset_pending_quarantine_index_counters();
        let remaining = audit_remaining_destination_bytes(&plan, &mut filesystem, 1).unwrap();
        let (inserts, queries, probes) = pending_quarantine_index_counters();

        assert_eq!(plan.mutations.len(), GROUP_COUNT * 3);
        assert_eq!(remaining, (GROUP_COUNT as u64) * 5);
        assert_eq!(inserts, GROUP_COUNT);
        assert_eq!(queries, GROUP_COUNT * 2);
        assert_eq!(
            probes,
            GROUP_COUNT * 3,
            "exact recreated directories take one ancestor probe and child installs take two"
        );
        assert_eq!(filesystem.inspect_calls, GROUP_COUNT * 4 + 5);
    }

    #[test]
    fn whole_tree_preflight_enforces_entry_allocation_and_relocated_depth_limits() {
        let root = TestRoot::new("whole-tree-limits");
        let install_id = Uuid::new_v4();
        let mut plan = plan(install_id, Uuid::new_v4());
        let hash = sha256(b"new-content");
        plan.desired_files[0].path = "mods/new.jar".into();
        plan.desired_files[0].signed_sha256 = hash.clone();
        plan.desired_files[0].installed_sha256 = hash.clone();
        plan.mutations = vec![
            JournalMutation::Quarantine {
                source_path: "mods".into(),
                backup_slot: 0,
            },
            JournalMutation::EnsureDirectory {
                destination_path: "mods".into(),
            },
            JournalMutation::InstallFile {
                destination_path: "mods/new.jar".into(),
                staging_slot: 0,
                size: b"new-content".len() as u64,
                sha256: hash,
                executable: false,
            },
        ];
        plan.validate(install_id, BuildChannel::Stable).unwrap();
        let paths = ReconcileOperationPathsV2::from_plan(&plan).unwrap();
        let mut filesystem = FakeFilesystem::new(&root.0);
        filesystem
            .ensure_real_directory(&managed_path("instances/stable/mods/old").unwrap())
            .unwrap();
        filesystem.insert_file("instances/stable/mods/old/file.bin", b"old", false);
        filesystem.insert_file(
            paths.staging_file(0).unwrap().as_str(),
            b"new-content",
            false,
        );
        prepare_workspace(&mut filesystem, &paths).unwrap();

        for limits in [
            ManagedDirectoryRemovalLimits {
                max_entries: 9,
                max_allocated_bytes: 15,
                max_depth: 4,
            },
            ManagedDirectoryRemovalLimits {
                max_entries: 10,
                max_allocated_bytes: 14,
                max_depth: 4,
            },
            ManagedDirectoryRemovalLimits {
                max_entries: 10,
                max_allocated_bytes: 15,
                max_depth: 3,
            },
        ] {
            assert!(preflight_whole_tree_moves_v2(
                &plan,
                &mut filesystem,
                &paths,
                WholeTreeMoveDirectionV2::RollForward,
                limits,
            )
            .is_err());
            assert!(filesystem.contains("instances/stable/mods/old/file.bin"));
            assert!(!filesystem.contains(paths.backup_node(0).unwrap().as_str()));
        }

        preflight_whole_tree_moves_v2(
            &plan,
            &mut filesystem,
            &paths,
            WholeTreeMoveDirectionV2::RollForward,
            ManagedDirectoryRemovalLimits {
                max_entries: 10,
                max_allocated_bytes: 15,
                max_depth: 4,
            },
        )
        .unwrap();
    }

    #[test]
    fn resumes_after_a_crash_after_every_mutation() {
        for crash_after in 1..=3 {
            let mut fixture = Fixture::new(&format!("crash-{crash_after}"));
            let lock = fixture.lock();
            let mut completed = 0;
            let error = roll_forward_with_checkpoint_v2(
                &fixture.plan,
                &lock,
                &fixture.proofs,
                &mut fixture.filesystem,
                |_| {
                    completed += 1;
                    if completed == crash_after {
                        Err(format!("injected crash {crash_after}"))
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap_err();
            assert!(matches!(error, ReconcileExecutorErrorV2::Interrupted(_)));

            let report = roll_forward_v2(
                &fixture.plan,
                &lock,
                &fixture.proofs,
                &mut fixture.filesystem,
            )
            .unwrap();
            assert_eq!(report.mutations.len(), 3);
            fixture.assert_forward();
        }
    }

    #[test]
    fn repeated_roll_forward_is_fully_idempotent_and_keeps_staging() {
        let mut fixture = Fixture::new("repeat-forward");
        let lock = fixture.lock();
        let first = roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap();
        assert_eq!(first.applied_count(), 3);
        let second = roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap();
        assert_eq!(second.applied_count(), 0);
        assert!(second
            .mutations
            .iter()
            .all(|entry| entry.disposition == MutationDispositionV2::AlreadySatisfied));
        fixture.assert_forward();
    }

    #[test]
    fn resumes_from_an_exact_deterministic_install_temporary() {
        let mut fixture = Fixture::new("install-temporary");
        let paths = ReconcileOperationPathsV2::from_plan(&fixture.plan).unwrap();
        fixture.filesystem.insert_file(
            paths.install_temporary(0).unwrap().as_str(),
            b"new-content",
            false,
        );
        let lock = fixture.lock();
        roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap();
        assert!(!fixture
            .filesystem
            .contains(paths.install_temporary(0).unwrap().as_str()));
        fixture.assert_forward();
    }

    #[test]
    fn managed_adapter_streams_rolls_forward_and_rolls_back_on_disk() {
        let root = TestRoot::new("managed-adapter");
        let install_id = Uuid::new_v4();
        let plan = plan(install_id, Uuid::new_v4());
        let paths = ReconcileOperationPathsV2::from_plan(&plan).unwrap();
        let legacy = root.0.join("instances/stable/legacy.bin");
        let staging = paths.staging_file(0).unwrap().join_to(&root.0);
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::create_dir_all(staging.parent().unwrap()).unwrap();
        fs::write(&legacy, b"old-content").unwrap();
        fs::write(&staging, b"new-content").unwrap();

        let store = InstanceStateStore::new(&root.0, install_id);
        let lock = store.acquire_operation_lock(BuildChannel::Stable).unwrap();
        let mut filesystem = ManagedReconcileFileSystemV2::new(&root.0);
        let proofs = audit_staging_files_v2(&plan, &mut filesystem).unwrap();
        roll_forward_v2(&plan, &lock, &proofs, &mut filesystem).unwrap();
        drop(proofs);
        rollback_v2(&plan, &lock, &mut filesystem).unwrap();
        assert_eq!(fs::read(&legacy).unwrap(), b"old-content");
        assert_eq!(fs::read(&staging).unwrap(), b"new-content");
        assert!(!root.0.join("instances/stable/data/new.bin").exists());
        assert_eq!(
            fs::read(paths.rollback_node(0).unwrap().join_to(&root.0)).unwrap(),
            b"new-content"
        );
    }

    #[test]
    fn rejects_incomplete_reordered_or_forged_staging_proofs() {
        let mut fixture = Fixture::new("proofs");
        let lock = fixture.lock();
        assert!(matches!(
            roll_forward_v2(&fixture.plan, &lock, &[], &mut fixture.filesystem),
            Err(ReconcileExecutorErrorV2::InvalidStagingProof(_))
        ));

        let mut forged = fixture.proofs.clone();
        forged[0].sha256 = "0".repeat(64);
        assert!(matches!(
            roll_forward_v2(&fixture.plan, &lock, &forged, &mut fixture.filesystem),
            Err(ReconcileExecutorErrorV2::InvalidStagingProof(_))
        ));

        let paths = ReconcileOperationPathsV2::from_plan(&fixture.plan).unwrap();
        fixture.filesystem.insert_file(
            paths.staging_file(0).unwrap().as_str(),
            b"forged-content",
            false,
        );
        assert!(matches!(
            roll_forward_v2(
                &fixture.plan,
                &lock,
                &fixture.proofs,
                &mut fixture.filesystem
            ),
            Err(ReconcileExecutorErrorV2::Conflict(_))
                | Err(ReconcileExecutorErrorV2::InvalidStagingProof(_))
        ));
    }

    #[test]
    fn rejects_destination_and_backup_conflicts_without_replacement() {
        let mut fixture = Fixture::new("conflicts");
        let lock = fixture.lock();
        let paths = ReconcileOperationPathsV2::from_plan(&fixture.plan).unwrap();
        fixture
            .filesystem
            .insert_file(paths.backup_node(0).unwrap().as_str(), b"other", false);
        assert!(matches!(
            roll_forward_v2(
                &fixture.plan,
                &lock,
                &fixture.proofs,
                &mut fixture.filesystem
            ),
            Err(ReconcileExecutorErrorV2::Conflict(_))
        ));

        fixture
            .filesystem
            .nodes
            .remove(paths.backup_node(0).unwrap().as_str());
        fixture
            .filesystem
            .insert_file("instances/stable/data/new.bin", b"wrong", false);
        assert!(matches!(
            roll_forward_v2(
                &fixture.plan,
                &lock,
                &fixture.proofs,
                &mut fixture.filesystem
            ),
            Err(ReconcileExecutorErrorV2::Interrupted(_))
        ));
        assert!(fixture
            .filesystem
            .contains(paths.backup_node(0).unwrap().as_str()));
    }

    #[test]
    fn never_follows_reparse_points_and_rejects_hard_links() {
        let mut reparse_fixture = Fixture::new("reparse-stage");
        let paths = ReconcileOperationPathsV2::from_plan(&reparse_fixture.plan).unwrap();
        let stage = paths.staging_file(0).unwrap();
        reparse_fixture.filesystem.nodes.remove(stage.as_str());
        reparse_fixture
            .filesystem
            .insert_file("outside/target.bin", b"new-content", false);
        reparse_fixture
            .filesystem
            .insert_reparse(stage.as_str(), "outside/target.bin");
        assert!(matches!(
            audit_staging_files_v2(&reparse_fixture.plan, &mut reparse_fixture.filesystem),
            Err(ReconcileExecutorErrorV2::UnsafeNode(_))
        ));
        assert_eq!(
            reparse_fixture.filesystem.file_bytes("outside/target.bin"),
            Some(b"new-content".as_slice())
        );

        let mut quarantine_fixture = Fixture::new("reparse-quarantine");
        quarantine_fixture
            .filesystem
            .nodes
            .remove("instances/stable/legacy.bin");
        quarantine_fixture
            .filesystem
            .insert_file("outside/target.bin", b"target", false);
        quarantine_fixture
            .filesystem
            .insert_reparse("instances/stable/legacy.bin", "outside/target.bin");
        let lock = quarantine_fixture.lock();
        roll_forward_v2(
            &quarantine_fixture.plan,
            &lock,
            &quarantine_fixture.proofs,
            &mut quarantine_fixture.filesystem,
        )
        .unwrap();
        let backup = ReconcileOperationPathsV2::from_plan(&quarantine_fixture.plan)
            .unwrap()
            .backup_node(0)
            .unwrap();
        assert_eq!(
            quarantine_fixture
                .filesystem
                .reparse_target(backup.as_str()),
            Some("outside/target.bin")
        );
        assert_eq!(
            quarantine_fixture
                .filesystem
                .file_bytes("outside/target.bin"),
            Some(b"target".as_slice())
        );

        let mut hardlink_fixture = Fixture::new("hardlink");
        hardlink_fixture.filesystem.insert_file_with_links(
            "instances/stable/legacy.bin",
            b"old",
            false,
            2,
        );
        let lock = hardlink_fixture.lock();
        assert!(matches!(
            roll_forward_v2(
                &hardlink_fixture.plan,
                &lock,
                &hardlink_fixture.proofs,
                &mut hardlink_fixture.filesystem
            ),
            Err(ReconcileExecutorErrorV2::UnsafeNode(_))
        ));
    }

    #[test]
    fn rollback_recovers_every_partial_prefix_and_is_idempotent() {
        for prefix in 0..=3 {
            let mut fixture = Fixture::new(&format!("rollback-prefix-{prefix}"));
            let lock = fixture.lock();
            if prefix > 0 {
                let mut completed = 0;
                let _ = roll_forward_with_checkpoint_v2(
                    &fixture.plan,
                    &lock,
                    &fixture.proofs,
                    &mut fixture.filesystem,
                    |_| {
                        completed += 1;
                        if completed == prefix {
                            Err("stop".into())
                        } else {
                            Ok(())
                        }
                    },
                );
            }
            rollback_v2(&fixture.plan, &lock, &mut fixture.filesystem).unwrap();
            rollback_v2(&fixture.plan, &lock, &mut fixture.filesystem).unwrap();
            fixture.assert_rolled_back();
        }
    }

    #[test]
    fn resumes_after_a_crash_after_every_rollback_mutation() {
        for crash_after in 1..=3 {
            let mut fixture = Fixture::new(&format!("rollback-crash-{crash_after}"));
            let lock = fixture.lock();
            roll_forward_v2(
                &fixture.plan,
                &lock,
                &fixture.proofs,
                &mut fixture.filesystem,
            )
            .unwrap();
            let mut completed = 0;
            let error =
                rollback_with_checkpoint_v2(&fixture.plan, &lock, &mut fixture.filesystem, |_| {
                    completed += 1;
                    if completed == crash_after {
                        Err(format!("injected rollback crash {crash_after}"))
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert!(matches!(error, ReconcileExecutorErrorV2::Interrupted(_)));
            rollback_v2(&fixture.plan, &lock, &mut fixture.filesystem).unwrap();
            fixture.assert_rolled_back();
        }
    }

    #[test]
    fn rollback_stashes_a_recreated_directory_before_restoring_its_backup() {
        let root = TestRoot::new("directory-replacement");
        let install_id = Uuid::new_v4();
        let mut plan = plan(install_id, Uuid::new_v4());
        let hash = sha256(b"new-content");
        plan.desired_files[0].path = "mods/new.jar".into();
        plan.desired_files[0].signed_sha256 = hash.clone();
        plan.desired_files[0].installed_sha256 = hash.clone();
        plan.mutations = vec![
            JournalMutation::Quarantine {
                source_path: "mods".into(),
                backup_slot: 0,
            },
            JournalMutation::EnsureDirectory {
                destination_path: "mods".into(),
            },
            JournalMutation::InstallFile {
                destination_path: "mods/new.jar".into(),
                staging_slot: 0,
                size: b"new-content".len() as u64,
                sha256: hash,
                executable: false,
            },
        ];
        plan.validate(install_id, BuildChannel::Stable).unwrap();
        let paths = ReconcileOperationPathsV2::from_plan(&plan).unwrap();
        let mut filesystem = FakeFilesystem::new(&root.0);
        filesystem
            .ensure_real_directory(&managed_path("instances/stable/mods").unwrap())
            .unwrap();
        let original_identity = match filesystem.nodes.get("instances/stable/mods").unwrap() {
            FakeNode::Directory { identity } => *identity,
            _ => unreachable!(),
        };
        filesystem.insert_file(
            paths.staging_file(0).unwrap().as_str(),
            b"new-content",
            false,
        );
        let proofs = audit_staging_files_v2(&plan, &mut filesystem).unwrap();
        let lock = InstanceStateStore::new(&root.0, install_id)
            .acquire_operation_lock(BuildChannel::Stable)
            .unwrap();
        roll_forward_v2(&plan, &lock, &proofs, &mut filesystem).unwrap();
        rollback_v2(&plan, &lock, &mut filesystem).unwrap();
        rollback_v2(&plan, &lock, &mut filesystem).unwrap();

        assert_eq!(
            match filesystem.nodes.get("instances/stable/mods").unwrap() {
                FakeNode::Directory { identity } => *identity,
                _ => unreachable!(),
            },
            original_identity
        );
        assert!(!filesystem.contains("instances/stable/mods/new.jar"));
        assert!(filesystem.contains(paths.replacement_node(0).unwrap().as_str()));
        assert!(!filesystem.contains(paths.backup_node(0).unwrap().as_str()));
        assert_eq!(
            filesystem.file_bytes(paths.staging_file(0).unwrap().as_str()),
            Some(b"new-content".as_slice())
        );
    }

    #[test]
    fn rollback_rejects_post_reservation_growth_then_restarts_with_a_fresh_bound() {
        let root = TestRoot::new("rollback-reservation-growth");
        let install_id = Uuid::new_v4();
        let mut plan = plan(install_id, Uuid::new_v4());
        let hash = sha256(b"new-content");
        plan.desired_files[0].path = "mods/new.jar".into();
        plan.desired_files[0].signed_sha256 = hash.clone();
        plan.desired_files[0].installed_sha256 = hash.clone();
        plan.mutations = vec![
            JournalMutation::Quarantine {
                source_path: "mods".into(),
                backup_slot: 0,
            },
            JournalMutation::EnsureDirectory {
                destination_path: "mods".into(),
            },
            JournalMutation::InstallFile {
                destination_path: "mods/new.jar".into(),
                staging_slot: 0,
                size: b"new-content".len() as u64,
                sha256: hash,
                executable: false,
            },
        ];
        plan.validate(install_id, BuildChannel::Stable).unwrap();
        let paths = ReconcileOperationPathsV2::from_plan(&plan).unwrap();
        let mut filesystem = FakeFilesystem::new(&root.0);
        filesystem
            .ensure_real_directory(&managed_path("instances/stable/mods").unwrap())
            .unwrap();
        filesystem.insert_file("instances/stable/mods/original.bin", b"old", false);
        filesystem.insert_file(
            paths.staging_file(0).unwrap().as_str(),
            b"new-content",
            false,
        );
        let proofs = audit_staging_files_v2(&plan, &mut filesystem).unwrap();
        let lock = InstanceStateStore::new(&root.0, install_id)
            .acquire_operation_lock(BuildChannel::Stable)
            .unwrap();
        roll_forward_v2(&plan, &lock, &proofs, &mut filesystem).unwrap();

        filesystem.grow_before_bounded_move = Some((
            "instances/stable/mods".into(),
            "instances/stable/mods/injected.bin".into(),
            vec![b'x'; b"new-content".len() + 1],
        ));
        assert!(matches!(
            rollback_v2(&plan, &lock, &mut filesystem),
            Err(ReconcileExecutorErrorV2::UnsafeNode(_))
                | Err(ReconcileExecutorErrorV2::Interrupted(_))
        ));
        assert!(filesystem.contains("instances/stable/mods/injected.bin"));
        assert!(filesystem.contains(paths.backup_node(0).unwrap().as_str()));

        rollback_v2(&plan, &lock, &mut filesystem).unwrap();
        assert!(filesystem.contains("instances/stable/mods/original.bin"));
        assert!(!filesystem.contains("instances/stable/mods/injected.bin"));
        assert!(filesystem.contains(&format!(
            "{}/injected.bin",
            paths.replacement_node(0).unwrap().as_str()
        )));
    }

    #[test]
    fn first_bounded_move_preserves_applied_uncertain_classification() {
        let mut fixture = Fixture::new("bounded-applied-uncertain");
        let lock = fixture.lock();
        fixture.filesystem.applied_uncertain_after_bounded_move =
            Some("instances/stable/legacy.bin".into());

        let error = roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap_err();
        assert!(matches!(error, ReconcileExecutorErrorV2::Interrupted(_)));
        let paths = ReconcileOperationPathsV2::from_plan(&fixture.plan).unwrap();
        assert!(!fixture.filesystem.contains("instances/stable/legacy.bin"));
        assert!(fixture
            .filesystem
            .contains(paths.backup_node(0).unwrap().as_str()));
    }

    #[test]
    fn rollback_second_whole_tree_failure_is_applied_uncertain() {
        let root = TestRoot::new("rollback-second-whole-tree-failure");
        let install_id = Uuid::new_v4();
        let mut plan = plan(install_id, Uuid::new_v4());
        let hash = sha256(b"new-content");
        plan.desired_files[0].path = "mods/new.jar".into();
        plan.desired_files[0].signed_sha256 = hash.clone();
        plan.desired_files[0].installed_sha256 = hash.clone();
        plan.mutations = vec![
            JournalMutation::Quarantine {
                source_path: "mods".into(),
                backup_slot: 0,
            },
            JournalMutation::EnsureDirectory {
                destination_path: "mods".into(),
            },
            JournalMutation::InstallFile {
                destination_path: "mods/new.jar".into(),
                staging_slot: 0,
                size: b"new-content".len() as u64,
                sha256: hash,
                executable: false,
            },
        ];
        plan.validate(install_id, BuildChannel::Stable).unwrap();
        let paths = ReconcileOperationPathsV2::from_plan(&plan).unwrap();
        let mut filesystem = FakeFilesystem::new(&root.0);
        filesystem
            .ensure_real_directory(&managed_path("instances/stable/mods").unwrap())
            .unwrap();
        filesystem.insert_file("instances/stable/mods/original.bin", b"old", false);
        filesystem.insert_file(
            paths.staging_file(0).unwrap().as_str(),
            b"new-content",
            false,
        );
        let proofs = audit_staging_files_v2(&plan, &mut filesystem).unwrap();
        let lock = InstanceStateStore::new(&root.0, install_id)
            .acquire_operation_lock(BuildChannel::Stable)
            .unwrap();
        roll_forward_v2(&plan, &lock, &proofs, &mut filesystem).unwrap();

        let backup = paths.backup_node(0).unwrap();
        filesystem.grow_before_bounded_move = Some((
            backup.as_str().into(),
            format!("{}/late.bin", backup.as_str()),
            b"late".to_vec(),
        ));
        let error = rollback_v2(&plan, &lock, &mut filesystem).unwrap_err();
        assert!(matches!(error, ReconcileExecutorErrorV2::Interrupted(_)));
        assert!(!filesystem.contains("instances/stable/mods"));
        assert!(filesystem.contains(paths.replacement_node(0).unwrap().as_str()));
        assert!(filesystem.contains(backup.as_str()));
    }

    #[test]
    fn roll_forward_can_resume_after_a_completed_rollback() {
        let mut fixture = Fixture::new("forward-after-rollback");
        let lock = fixture.lock();
        roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap();
        rollback_v2(&fixture.plan, &lock, &mut fixture.filesystem).unwrap();
        fixture.assert_rolled_back();
        roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap();
        fixture.assert_forward();
    }

    #[test]
    fn rollback_rejects_ambiguous_source_backup_and_installed_conflicts() {
        let mut fixture = Fixture::new("rollback-conflict");
        let lock = fixture.lock();
        let paths = ReconcileOperationPathsV2::from_plan(&fixture.plan).unwrap();
        fixture
            .filesystem
            .insert_file(paths.backup_node(0).unwrap().as_str(), b"backup", false);
        assert!(matches!(
            rollback_v2(&fixture.plan, &lock, &mut fixture.filesystem),
            Err(ReconcileExecutorErrorV2::Conflict(_))
        ));

        fixture
            .filesystem
            .nodes
            .remove(paths.backup_node(0).unwrap().as_str());
        fixture
            .filesystem
            .insert_file("instances/stable/data/new.bin", b"wrong", false);
        assert!(matches!(
            rollback_v2(&fixture.plan, &lock, &mut fixture.filesystem),
            Err(ReconcileExecutorErrorV2::Conflict(_))
        ));
    }

    #[test]
    fn operation_lock_prevents_cross_root_and_cross_channel_execution() {
        let mut fixture = Fixture::new("scope");
        let other_root = TestRoot::new("scope-other");
        let lock = InstanceStateStore::new(&other_root.0, fixture.plan.install_id)
            .acquire_operation_lock(fixture.plan.channel)
            .unwrap();
        assert!(matches!(
            roll_forward_v2(
                &fixture.plan,
                &lock,
                &fixture.proofs,
                &mut fixture.filesystem
            ),
            Err(ReconcileExecutorErrorV2::InvalidScope(_))
        ));
    }

    #[test]
    fn retained_artifact_list_contains_staging_backup_and_rollback_slots() {
        let fixture = Fixture::new("retained");
        let paths = ReconcileOperationPathsV2::from_plan(&fixture.plan).unwrap();
        let retained = paths.retained_artifacts(&fixture.plan).unwrap();
        assert_eq!(retained.len(), 5);
        assert!(retained.contains(&paths.staging_file(0).unwrap()));
        assert!(retained.contains(&paths.backup_node(0).unwrap()));
        assert!(retained.contains(&paths.replacement_node(0).unwrap()));
        assert!(retained.contains(&paths.rollback_node(0).unwrap()));
        assert!(retained.contains(&paths.install_temporary(0).unwrap()));
    }

    #[test]
    fn canonical_staging_slot_index_handles_thousands_of_sparse_slots() {
        const SLOT_COUNT: usize = release::MAX_FILES_PER_PRESET;
        let expected = (0..SLOT_COUNT)
            .map(|index| ExpectedStagingSlotV2 {
                slot: ((SLOT_COUNT - index - 1) * 2) as u32,
                destination_path: format!("mods/indexed-{index:05}.jar"),
                size: index as u64,
                sha256: "a".repeat(64),
                executable: false,
                policy: FilePolicy::Exact,
                signed_size: index as u64,
                signed_sha256: "a".repeat(64),
            })
            .collect::<Vec<_>>();
        let slots = CanonicalStagingSlotsV2::new(expected, vec![None; SLOT_COUNT]).unwrap();
        assert_eq!(slots.len(), SLOT_COUNT);
        for expected_index in 0..SLOT_COUNT {
            let expected = slots.expected_at(expected_index);
            assert_eq!(
                slots.index_for_slot(expected.slot),
                Some(expected_index),
                "dense lookup must preserve the canonical source index"
            );
            assert_eq!(slots.index_for_slot(expected.slot + 1), None);
        }
        assert_eq!(slots.index_for_slot((SLOT_COUNT * 2) as u32), None);

        let duplicate = vec![
            ExpectedStagingSlotV2 {
                slot: 7,
                destination_path: "mods/left.jar".into(),
                size: 1,
                sha256: "b".repeat(64),
                executable: false,
                policy: FilePolicy::Exact,
                signed_size: 1,
                signed_sha256: "b".repeat(64),
            },
            ExpectedStagingSlotV2 {
                slot: 7,
                destination_path: "mods/right.jar".into(),
                size: 1,
                sha256: "c".repeat(64),
                executable: false,
                policy: FilePolicy::Exact,
                signed_size: 1,
                signed_sha256: "c".repeat(64),
            },
        ];
        assert!(matches!(
            CanonicalStagingSlotsV2::new(duplicate, vec![None, None]),
            Err(ReconcileExecutorErrorV2::InvalidPlan(_))
        ));
    }

    #[test]
    fn trusted_writer_is_idempotent_and_rejects_extra_staging_entries() {
        let fixture = ExactProductionFixture::new("trusted-writer", b"trusted-exact".to_vec());
        let lock = fixture.lock();
        let authority = fixture.authority(&lock);
        let source =
            bind_exact_staging_source_v2(&authority, &lock, &fixture.root, 0, &fixture.object)
                .unwrap();
        let staged =
            write_reconcile_staging_v2(&authority, &lock, &fixture.root, vec![source]).unwrap();
        assert_eq!(
            staged
                .proofs_for(&authority, &lock, &fixture.root)
                .unwrap()
                .len(),
            1
        );

        let resumed = write_reconcile_staging_v2(&authority, &lock, &fixture.root, vec![]).unwrap();
        resumed
            .proofs_for(&authority, &lock, &fixture.root)
            .unwrap();
        let paths = ReconcileOperationPathsV2::from_plan(&fixture.plan).unwrap();
        fs::write(
            paths
                .staging_root
                .join_to(fixture.root.install_root())
                .join("extra.bin"),
            b"x",
        )
        .unwrap();
        assert!(matches!(
            resumed.proofs_for(&authority, &lock, &fixture.root),
            Err(ReconcileExecutorErrorV2::InvalidStagingProof(_))
                | Err(ReconcileExecutorErrorV2::Filesystem(_))
        ));
    }

    #[test]
    fn writer_resumes_exact_prefix_and_restarts_a_corrupt_partial() {
        let bytes = (0..(STAGING_COPY_BUFFER_BYTES * 2 + 37))
            .map(|index| (index.wrapping_mul(31) & 0xff) as u8)
            .collect::<Vec<_>>();
        let fixture = ExactProductionFixture::new("partial-resume", bytes);
        let lock = fixture.lock();
        let authority = fixture.authority(&lock);
        let source =
            bind_exact_staging_source_v2(&authority, &lock, &fixture.root, 0, &fixture.object)
                .unwrap();
        let error = write_reconcile_staging_with_checkpoint_v2(
            &authority,
            &lock,
            &fixture.root,
            vec![source],
            |event| match event {
                StagingWriterCheckpointV2::Chunk { .. } => Err(
                    StagingWriterCheckpointErrorV2::Failed("cancel after first chunk".into()),
                ),
                _ => Ok(()),
            },
        )
        .unwrap_err();
        assert!(matches!(error, ReconcileExecutorErrorV2::Interrupted(_)));
        let paths = ReconcileOperationPathsV2::from_plan(&fixture.plan).unwrap();
        let partial = paths
            .staging_partial(0)
            .unwrap()
            .join_to(fixture.root.install_root());
        assert_eq!(
            fs::metadata(&partial).unwrap().len(),
            STAGING_COPY_BUFFER_BYTES as u64
        );

        let source =
            bind_exact_staging_source_v2(&authority, &lock, &fixture.root, 0, &fixture.object)
                .unwrap();
        let mut resumed_at = None;
        let error = write_reconcile_staging_with_checkpoint_v2(
            &authority,
            &lock,
            &fixture.root,
            vec![source],
            |event| match event {
                StagingWriterCheckpointV2::Chunk { written_bytes, .. } => {
                    resumed_at = Some(written_bytes);
                    Err(StagingWriterCheckpointErrorV2::Failed(
                        "cancel resumed write".into(),
                    ))
                }
                _ => Ok(()),
            },
        )
        .unwrap_err();
        assert!(matches!(error, ReconcileExecutorErrorV2::Interrupted(_)));
        assert_eq!(resumed_at, Some((STAGING_COPY_BUFFER_BYTES * 2) as u64));
        assert_eq!(
            fs::metadata(&partial).unwrap().len(),
            (STAGING_COPY_BUFFER_BYTES * 2) as u64
        );

        fs::write(&partial, b"corrupt-prefix").unwrap();
        let source =
            bind_exact_staging_source_v2(&authority, &lock, &fixture.root, 0, &fixture.object)
                .unwrap();
        write_reconcile_staging_v2(&authority, &lock, &fixture.root, vec![source]).unwrap();
        assert_eq!(
            fs::read(
                paths
                    .staging_file(0)
                    .unwrap()
                    .join_to(fixture.root.install_root())
            )
            .unwrap(),
            fixture.bytes
        );
        assert!(!partial.exists());
    }

    #[test]
    fn writer_distinguishes_clean_cancellation_from_post_commit_interruption() {
        let chunk_fixture = ExactProductionFixture::new(
            "typed-chunk-cancellation",
            vec![b'x'; STAGING_COPY_BUFFER_BYTES + 1],
        );
        let chunk_lock = chunk_fixture.lock();
        let chunk_authority = chunk_fixture.authority(&chunk_lock);
        let chunk_source = bind_exact_staging_source_v2(
            &chunk_authority,
            &chunk_lock,
            &chunk_fixture.root,
            0,
            &chunk_fixture.object,
        )
        .unwrap();
        let chunk_error = write_reconcile_staging_with_checkpoint_v2(
            &chunk_authority,
            &chunk_lock,
            &chunk_fixture.root,
            vec![chunk_source],
            |checkpoint| match checkpoint {
                StagingWriterCheckpointV2::Chunk { .. } => {
                    Err(StagingWriterCheckpointErrorV2::Cancelled)
                }
                _ => Ok(()),
            },
        )
        .unwrap_err();
        assert_eq!(chunk_error, ReconcileExecutorErrorV2::Cancelled);

        let before_fixture =
            ExactProductionFixture::new("typed-before-commit-cancellation", b"before".to_vec());
        let before_lock = before_fixture.lock();
        let before_authority = before_fixture.authority(&before_lock);
        let before_source = bind_exact_staging_source_v2(
            &before_authority,
            &before_lock,
            &before_fixture.root,
            0,
            &before_fixture.object,
        )
        .unwrap();
        let before_error = write_reconcile_staging_with_checkpoint_v2(
            &before_authority,
            &before_lock,
            &before_fixture.root,
            vec![before_source],
            |checkpoint| match checkpoint {
                StagingWriterCheckpointV2::BeforeCommit(_) => {
                    Err(StagingWriterCheckpointErrorV2::Cancelled)
                }
                _ => Ok(()),
            },
        )
        .unwrap_err();
        assert_eq!(before_error, ReconcileExecutorErrorV2::Cancelled);
        let before_final = ReconcileOperationPathsV2::from_plan(&before_fixture.plan)
            .unwrap()
            .staging_file(0)
            .unwrap()
            .join_to(before_fixture.root.install_root());
        assert!(!before_final.exists());

        let after_fixture =
            ExactProductionFixture::new("typed-after-commit-cancellation", b"after".to_vec());
        let after_lock = after_fixture.lock();
        let after_authority = after_fixture.authority(&after_lock);
        let after_source = bind_exact_staging_source_v2(
            &after_authority,
            &after_lock,
            &after_fixture.root,
            0,
            &after_fixture.object,
        )
        .unwrap();
        let after_error = write_reconcile_staging_with_checkpoint_v2(
            &after_authority,
            &after_lock,
            &after_fixture.root,
            vec![after_source],
            |checkpoint| match checkpoint {
                StagingWriterCheckpointV2::AfterCommit(_) => {
                    Err(StagingWriterCheckpointErrorV2::Cancelled)
                }
                _ => Ok(()),
            },
        )
        .unwrap_err();
        assert!(matches!(
            after_error,
            ReconcileExecutorErrorV2::Interrupted(_)
        ));
        let after_final = ReconcileOperationPathsV2::from_plan(&after_fixture.plan)
            .unwrap()
            .staging_file(0)
            .unwrap()
            .join_to(after_fixture.root.install_root());
        assert_eq!(fs::read(after_final).unwrap(), b"after");

        assert!(matches!(
            checkpoint_error_before_commit(StagingWriterCheckpointErrorV2::Cancelled, true),
            ReconcileExecutorErrorV2::Interrupted(_)
        ));
        assert!(matches!(
            map_staging_commit_error(
                ManagedFsError::AppliedButDurabilityUnconfirmed {
                    destination: PathBuf::from("committed-staging.bin"),
                    detail: "injected post-commit failure".into(),
                },
                false,
            ),
            ReconcileExecutorErrorV2::Interrupted(_)
        ));
        assert!(matches!(
            classify_staging_error(
                ReconcileExecutorErrorV2::Conflict("injected post-verify failure".into()),
                true,
            ),
            ReconcileExecutorErrorV2::Interrupted(_)
        ));
        assert!(matches!(
            classify_staging_error(
                ReconcileExecutorErrorV2::Filesystem(
                    "injected exact-winner partial cleanup failure".into(),
                ),
                true,
            ),
            ReconcileExecutorErrorV2::Interrupted(_)
        ));
    }

    #[test]
    fn no_replace_race_accepts_only_an_exact_concurrent_winner() {
        let fixture = ExactProductionFixture::new("race-exact", b"race-exact".to_vec());
        let lock = fixture.lock();
        let authority = fixture.authority(&lock);
        let final_path = ReconcileOperationPathsV2::from_plan(&fixture.plan)
            .unwrap()
            .staging_file(0)
            .unwrap()
            .join_to(fixture.root.install_root());
        let source =
            bind_exact_staging_source_v2(&authority, &lock, &fixture.root, 0, &fixture.object)
                .unwrap();
        write_reconcile_staging_with_checkpoint_v2(
            &authority,
            &lock,
            &fixture.root,
            vec![source],
            |event| {
                if event == StagingWriterCheckpointV2::BeforeCommit(0) {
                    fs::write(&final_path, &fixture.bytes).unwrap();
                }
                Ok(())
            },
        )
        .unwrap();

        let wrong = ExactProductionFixture::new("race-wrong", b"race-wrong".to_vec());
        let wrong_lock = wrong.lock();
        let wrong_authority = wrong.authority(&wrong_lock);
        let wrong_final = ReconcileOperationPathsV2::from_plan(&wrong.plan)
            .unwrap()
            .staging_file(0)
            .unwrap()
            .join_to(wrong.root.install_root());
        let source = bind_exact_staging_source_v2(
            &wrong_authority,
            &wrong_lock,
            &wrong.root,
            0,
            &wrong.object,
        )
        .unwrap();
        let result = write_reconcile_staging_with_checkpoint_v2(
            &wrong_authority,
            &wrong_lock,
            &wrong.root,
            vec![source],
            |event| {
                if event == StagingWriterCheckpointV2::BeforeCommit(0) {
                    fs::write(&wrong_final, b"wrong-winner").unwrap();
                }
                Ok(())
            },
        );
        assert!(
            result.is_err(),
            "a wrong concurrent winner must fail closed"
        );
        assert_eq!(fs::read(wrong_final).unwrap(), b"wrong-winner");
    }

    #[test]
    fn writer_rejects_foreign_roots_hardlinks_and_reparse_slots() {
        let left = ExactProductionFixture::new("foreign-left", b"shared-bytes".to_vec());
        let right = ExactProductionFixture::new("foreign-right", b"shared-bytes".to_vec());
        let right_lock = right.lock();
        let right_authority = right.authority(&right_lock);
        assert!(bind_exact_staging_source_v2(
            &right_authority,
            &right_lock,
            &right.root,
            0,
            &left.object,
        )
        .is_err());

        let paths = ReconcileOperationPathsV2::from_plan(&right.plan).unwrap();
        fs::create_dir_all(paths.staging_root.join_to(right.root.install_root())).unwrap();
        let outside = right.root.install_root().join("outside.bin");
        fs::write(&outside, &right.bytes).unwrap();
        fs::hard_link(
            &outside,
            paths
                .staging_file(0)
                .unwrap()
                .join_to(right.root.install_root()),
        )
        .unwrap();
        assert!(matches!(
            write_reconcile_staging_v2(&right_authority, &right_lock, &right.root, vec![]),
            Err(ReconcileExecutorErrorV2::UnsafeNode(_))
        ));

        fs::remove_file(
            paths
                .staging_file(0)
                .unwrap()
                .join_to(right.root.install_root()),
        )
        .unwrap();
        #[cfg(windows)]
        {
            use std::os::windows::fs::symlink_file;
            if symlink_file(
                &outside,
                paths
                    .staging_file(0)
                    .unwrap()
                    .join_to(right.root.install_root()),
            )
            .is_ok()
            {
                assert!(matches!(
                    write_reconcile_staging_v2(&right_authority, &right_lock, &right.root, vec![]),
                    Err(ReconcileExecutorErrorV2::UnsafeNode(_))
                ));
            }
        }
    }

    #[test]
    fn managed_rename_rejects_a_source_swap_before_namespace_commit() {
        let directory = TestRoot::new("rename-source-swap");
        let selected = select_install_directory(&directory.0).unwrap();
        let root = selected.into_owned_cas_root();
        let source = managed_path("instances/stable/source.bin").unwrap();
        let destination = managed_path("state/reconcile/stable/swapped.node").unwrap();
        fs::create_dir_all(source.join_to(root.install_root()).parent().unwrap()).unwrap();
        fs::create_dir_all(destination.join_to(root.install_root()).parent().unwrap()).unwrap();
        fs::write(source.join_to(root.install_root()), b"audited").unwrap();
        let mut filesystem = ManagedReconcileFileSystemV2::new(root.install_root());
        let snapshot = filesystem.inspect_node(&source).unwrap().unwrap();

        let displaced = root.install_root().join("displaced.bin");
        fs::rename(source.join_to(root.install_root()), &displaced).unwrap();
        fs::write(source.join_to(root.install_root()), b"replacement").unwrap();
        assert!(filesystem
            .rename_node_no_replace(&source, &snapshot, &destination)
            .is_err());
        assert_eq!(
            fs::read(source.join_to(root.install_root())).unwrap(),
            b"replacement"
        );
        assert!(!destination.join_to(root.install_root()).exists());
        assert_eq!(fs::read(displaced).unwrap(), b"audited");
    }

    #[test]
    fn managed_copy_reports_post_temporary_source_drift_as_applied_uncertain() {
        let directory = TestRoot::new("copy-source-drift-after-temp");
        let selected = select_install_directory(&directory.0).unwrap();
        let root = selected.into_owned_cas_root();
        let source = managed_path("state/reconcile/stable/source.bin").unwrap();
        let temporary = managed_path("state/reconcile/stable/temporary/00000000.tmp").unwrap();
        let destination = managed_path("instances/stable/copied.bin").unwrap();
        for path in [&source, &temporary, &destination] {
            fs::create_dir_all(path.join_to(root.install_root()).parent().unwrap()).unwrap();
        }
        let expected_bytes = b"original";
        fs::write(source.join_to(root.install_root()), expected_bytes).unwrap();
        let mut filesystem = ManagedReconcileFileSystemV2::new(root.install_root());
        let expected_source = filesystem.inspect_node(&source).unwrap().unwrap();

        fs::write(source.join_to(root.install_root()), b"tampered").unwrap();
        let error = filesystem
            .copy_regular_file_no_replace(
                &source,
                &expected_source,
                &temporary,
                &destination,
                &ExecutorFileBindingV2 {
                    size: expected_bytes.len() as u64,
                    sha256: sha256(expected_bytes),
                    executable: false,
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ExecutorMutationErrorV2::AppliedButStateUncertain(_)
        ));
        assert!(temporary.join_to(root.install_root()).is_file());
        assert!(!destination.join_to(root.install_root()).exists());
    }

    #[test]
    fn canonical_mutable_source_is_materialized_from_trusted_policy() {
        let directory = TestRoot::new("mutable-stage");
        let selected = select_install_directory(&directory.0).unwrap();
        let install_id = selected.install_id();
        let root = selected.into_owned_cas_root();
        let operation_id = Uuid::new_v4();
        let default = b"renderDistance:12\n";
        let trusted = trusted_files(b"guard", default, 'a', 1);
        let object = write_verified_object(&root, default);
        let plan = one_file_plan(
            install_id,
            operation_id,
            &trusted,
            "options.txt",
            default,
            default,
            FilePolicy::ValidatedMutable,
        );
        let (inventory, artifact_plan) = artifact_authority(
            &root,
            &trusted,
            install_id,
            operation_id,
            "options.txt",
            &sha256(default),
        );
        let lock = InstanceStateStore::new(root.install_root(), install_id)
            .acquire_operation_lock(BuildChannel::Stable)
            .unwrap();
        let authority = authorize_reconcile_staging_v2(
            &plan,
            &trusted,
            &inventory,
            &artifact_plan,
            &lock,
            &root,
        )
        .unwrap();
        let mut state = MutableSettingsState::new();
        let source = bind_canonical_mutable_staging_source_v2(
            &authority, &lock, &root, 0, &object, &mut state,
        )
        .unwrap();
        write_reconcile_staging_v2(&authority, &lock, &root, vec![source]).unwrap();
        let staged = ReconcileOperationPathsV2::from_plan(&plan)
            .unwrap()
            .staging_file(0)
            .unwrap()
            .join_to(root.install_root());
        assert_eq!(fs::read(staged).unwrap(), default);
    }

    #[test]
    fn restart_recovery_seals_current_complete_and_incomplete_staging() {
        let fixture = ExactProductionFixture::new("restart-current", b"restart".to_vec());
        let lock = fixture.lock();
        let authority = fixture.authority(&lock);
        let source =
            bind_exact_staging_source_v2(&authority, &lock, &fixture.root, 0, &fixture.object)
                .unwrap();
        write_reconcile_staging_v2(&authority, &lock, &fixture.root, vec![source]).unwrap();
        let pointer = JournalPointerV2 {
            schema_version: 2,
            install_id: fixture.plan.install_id,
            channel: fixture.plan.channel,
            operation_id: fixture.plan.operation_id,
            plan_sha256: format!(
                "{:x}",
                Sha256::digest(fixture.plan.canonical_bytes().unwrap())
            ),
        };
        let pending = PendingJournalV2 {
            pointer,
            plan: fixture.plan.clone(),
        };
        let plan_audit = ReconcilePlanAuditV2::for_test(
            &pending.plan,
            pre_mutation_missing_audit(&pending.plan),
        );
        let recovered = recover_pending_reconcile_staging_v2(PendingReconcileRecoveryRequestV2 {
            pending: &pending,
            fresh_release: &fixture.trusted,
            fresh_inventory: &fixture.inventory,
            fresh_artifact_plan: &fixture.artifact_plan,
            fresh_plan_audit: Some(&plan_audit),
            mutable_proofs: &[],
            operation_lock: &lock,
            cas_root: &fixture.root,
        })
        .unwrap();
        let PendingReconcileStagingV2::RollForward { authority, staged } = recovered else {
            panic!("complete current staging must recover for roll-forward")
        };
        roll_forward_staged_v2(&authority, &lock, &fixture.root, *staged).unwrap();
        assert_eq!(
            fs::read(
                fixture
                    .root
                    .install_root()
                    .join("instances/stable/mods/fragment-launch-guard.jar")
            )
            .unwrap(),
            fixture.bytes
        );

        let incomplete = ExactProductionFixture::new("restart-incomplete", b"missing".to_vec());
        let incomplete_lock = incomplete.lock();
        let pointer = JournalPointerV2 {
            schema_version: 2,
            install_id: incomplete.plan.install_id,
            channel: incomplete.plan.channel,
            operation_id: incomplete.plan.operation_id,
            plan_sha256: format!(
                "{:x}",
                Sha256::digest(incomplete.plan.canonical_bytes().unwrap())
            ),
        };
        let pending = PendingJournalV2 {
            pointer,
            plan: incomplete.plan.clone(),
        };
        let plan_audit = ReconcilePlanAuditV2::for_test(
            &pending.plan,
            pre_mutation_missing_audit(&pending.plan),
        );
        let recovered = recover_pending_reconcile_staging_v2(PendingReconcileRecoveryRequestV2 {
            pending: &pending,
            fresh_release: &incomplete.trusted,
            fresh_inventory: &incomplete.inventory,
            fresh_artifact_plan: &incomplete.artifact_plan,
            fresh_plan_audit: Some(&plan_audit),
            mutable_proofs: &[],
            operation_lock: &incomplete_lock,
            cas_root: &incomplete.root,
        })
        .unwrap();
        let PendingReconcileStagingV2::CurrentIncomplete(rollback) = recovered else {
            panic!("missing current staging must be rollback-only")
        };
        rollback_pending_reconcile_v2(&rollback, &incomplete_lock, &incomplete.root).unwrap();
    }

    #[test]
    fn restart_recovery_accepts_only_monotonic_metadata_for_the_same_exact_target() {
        let fixture = ExactProductionFixture::new_with_metadata_version(
            "restart-monotonic-metadata",
            b"restart-monotonic".to_vec(),
            2,
        );
        let lock = fixture.lock();
        let authority = fixture.authority(&lock);
        let source =
            bind_exact_staging_source_v2(&authority, &lock, &fixture.root, 0, &fixture.object)
                .unwrap();
        write_reconcile_staging_v2(&authority, &lock, &fixture.root, vec![source]).unwrap();
        let pending = PendingJournalV2 {
            pointer: JournalPointerV2 {
                schema_version: 2,
                install_id: fixture.plan.install_id,
                channel: fixture.plan.channel,
                operation_id: fixture.plan.operation_id,
                plan_sha256: format!(
                    "{:x}",
                    Sha256::digest(fixture.plan.canonical_bytes().unwrap())
                ),
            },
            plan: fixture.plan.clone(),
        };

        let advanced = trusted_with_role_versions(
            &fixture.trusted,
            TrustedRoleVersions {
                root: 1,
                timestamp: 3,
                snapshot: 3,
                targets: 3,
            },
        );
        let (advanced_inventory, advanced_artifact_plan) = artifact_authority(
            &fixture.root,
            &advanced,
            fixture.plan.install_id,
            fixture.plan.operation_id,
            "mods/fragment-launch-guard.jar",
            &sha256(&fixture.bytes),
        );
        let current_identity = classify_untrusted_pending_identity_v2(&pending, &advanced).unwrap();
        current_identity
            .validate_for(&pending.plan, &advanced)
            .unwrap();
        assert!(
            current_identity
                .validate_for(&pending.plan, &fixture.trusted)
                .is_err(),
            "same-target role rollback must not reuse a fresher pending identity"
        );
        assert!(validate_trusted_release_for_staging(&pending.plan, &advanced).is_ok());
        let full_current_plan = current_manifest_plan_with_mutable_override(
            fixture.plan.install_id,
            fixture.plan.operation_id,
            &fixture.trusted,
            b"renderDistance:12\n",
        );
        assert!(audit_current_reconcile_plan_instance(
            fixture.root.install_root(),
            &full_current_plan,
            &advanced
        )
        .is_ok());
        // The exact-writer fixture intentionally narrows the full signed preset to one exact file,
        // so use its already canonical native plan audit after separately proving the production
        // full-plan monotonic bridge above.
        let advanced_audit = ReconcilePlanAuditV2::for_test(
            &pending.plan,
            pre_mutation_missing_audit(&pending.plan),
        );
        let recovered = recover_pending_reconcile_staging_v2(PendingReconcileRecoveryRequestV2 {
            pending: &pending,
            fresh_release: &advanced,
            fresh_inventory: &advanced_inventory,
            fresh_artifact_plan: &advanced_artifact_plan,
            fresh_plan_audit: Some(&advanced_audit),
            mutable_proofs: &[],
            operation_lock: &lock,
            cas_root: &fixture.root,
        })
        .unwrap();
        assert!(matches!(
            recovered,
            PendingReconcileStagingV2::RollForward { .. }
        ));

        let lower = trusted_with_role_versions(
            &fixture.trusted,
            TrustedRoleVersions {
                root: 1,
                timestamp: 1,
                snapshot: 1,
                targets: 1,
            },
        );
        let (lower_inventory, lower_artifact_plan) = artifact_authority(
            &fixture.root,
            &lower,
            fixture.plan.install_id,
            fixture.plan.operation_id,
            "mods/fragment-launch-guard.jar",
            &sha256(&fixture.bytes),
        );
        assert!(validate_trusted_release_for_staging(&pending.plan, &lower).is_err());
        assert!(audit_current_reconcile_plan_instance(
            fixture.root.install_root(),
            &full_current_plan,
            &lower
        )
        .is_err());
        let lower_recovery =
            recover_pending_reconcile_staging_v2(PendingReconcileRecoveryRequestV2 {
                pending: &pending,
                fresh_release: &lower,
                fresh_inventory: &lower_inventory,
                fresh_artifact_plan: &lower_artifact_plan,
                fresh_plan_audit: None,
                mutable_proofs: &[],
                operation_lock: &lock,
                cas_root: &fixture.root,
            });
        assert!(matches!(
            lower_recovery,
            Err(ReconcileExecutorErrorV2::InvalidPlan(_))
        ));

        let drifted = trusted_files(&fixture.bytes, b"renderDistance:12\n", 'b', 3);
        let (drifted_inventory, drifted_artifact_plan) = artifact_authority(
            &fixture.root,
            &drifted,
            fixture.plan.install_id,
            fixture.plan.operation_id,
            "mods/fragment-launch-guard.jar",
            &sha256(&fixture.bytes),
        );
        assert!(validate_trusted_release_for_staging(&pending.plan, &drifted).is_err());
        assert!(audit_current_reconcile_plan_instance(
            fixture.root.install_root(),
            &full_current_plan,
            &drifted
        )
        .is_err());
        let drifted_recovery =
            recover_pending_reconcile_staging_v2(PendingReconcileRecoveryRequestV2 {
                pending: &pending,
                fresh_release: &drifted,
                fresh_inventory: &drifted_inventory,
                fresh_artifact_plan: &drifted_artifact_plan,
                fresh_plan_audit: None,
                mutable_proofs: &[],
                operation_lock: &lock,
                cas_root: &fixture.root,
            })
            .unwrap();
        let PendingReconcileStagingV2::Historical(historical_identity) = drifted_recovery else {
            panic!("advanced target must remain a non-mutating historical identity")
        };
        historical_identity
            .validate_for(&pending.plan, &drifted)
            .unwrap();
        let drifted_role_rollback = trusted_with_role_versions(
            &drifted,
            TrustedRoleVersions {
                root: 3,
                timestamp: 3,
                snapshot: 3,
                targets: 2,
            },
        );
        assert!(
            historical_identity
                .validate_for(&pending.plan, &drifted_role_rollback)
                .is_err(),
            "historical identity must bind the exact fresh role evidence"
        );

        let paths = ReconcileOperationPathsV2::from_plan(&pending.plan).unwrap();
        assert!(paths
            .staging_file(0)
            .unwrap()
            .join_to(fixture.root.install_root())
            .is_file());
        assert!(!fixture
            .root
            .install_root()
            .join("instances/stable/mods/fragment-launch-guard.jar")
            .exists());
    }

    #[test]
    fn forged_pending_scope_with_an_active_base_never_mints_rollback_authority() {
        let directory = TestRoot::new("forged-pending-scope");
        let selected = select_install_directory(&directory.0).unwrap();
        let install_id = selected.install_id();
        let root = selected.into_owned_cas_root();
        let operation_id = Uuid::new_v4();
        let trusted = trusted_files(b"guard", b"renderDistance:12\n", 'a', 1);
        let mut trusted_plan = current_manifest_plan_with_mutable_override(
            install_id,
            operation_id,
            &trusted,
            b"renderDistance:20\n",
        );
        trusted_plan.kind = OperationKind::Repair;
        trusted_plan.base = Some(trusted_plan.target.clone());
        trusted_plan.target.generation += 1;
        trusted_plan
            .validate(install_id, BuildChannel::Stable)
            .unwrap();
        let plan_audit =
            audit_current_reconcile_plan_instance(root.install_root(), &trusted_plan, &trusted)
                .unwrap();

        let mut forged = trusted_plan.clone();
        forged.strict_roots = vec!["mods".into()];
        forged.validate(install_id, BuildChannel::Stable).unwrap();
        let pending = PendingJournalV2 {
            pointer: JournalPointerV2 {
                schema_version: 2,
                install_id,
                channel: BuildChannel::Stable,
                operation_id,
                plan_sha256: format!("{:x}", Sha256::digest(forged.canonical_bytes().unwrap())),
            },
            plan: forged,
        };
        let inventory = ArtifactInventoryV2::build(
            &root,
            &trusted,
            install_id,
            operation_id,
            BuildChannel::Stable,
            PresetId::Medium,
        )
        .unwrap();
        let availability = VerifiedAvailabilityV2::for_test(&inventory, [], true, true);
        let artifact_plan =
            ArtifactPlanV2::for_reconcile(&inventory, &availability, Vec::<String>::new()).unwrap();
        let lock = InstanceStateStore::new(root.install_root(), install_id)
            .acquire_operation_lock(BuildChannel::Stable)
            .unwrap();
        assert!(plan_audit.audit_for(&pending.plan).is_err());
        assert!(audit_current_reconcile_plan_instance(
            root.install_root(),
            &pending.plan,
            &trusted
        )
        .is_err());
        let recovered = recover_pending_reconcile_staging_v2(PendingReconcileRecoveryRequestV2 {
            pending: &pending,
            fresh_release: &trusted,
            fresh_inventory: &inventory,
            fresh_artifact_plan: &artifact_plan,
            fresh_plan_audit: None,
            mutable_proofs: &[],
            operation_lock: &lock,
            cas_root: &root,
        })
        .unwrap();
        let PendingReconcileStagingV2::FreshSupersedeRequired(identity) = recovered else {
            panic!("forged pending scope must remain non-mutating")
        };
        identity.validate_for(&pending.plan, &trusted).unwrap();
        assert!(!identity.is_historical());
        assert_eq!(
            identity.fresh_release_sha256(),
            trusted.evidence().release_manifest.sha256
        );
    }

    #[test]
    fn forged_mutable_binding_never_mints_rollback_authority() {
        let directory = TestRoot::new("forged-mutable-binding");
        let selected = select_install_directory(&directory.0).unwrap();
        let install_id = selected.install_id();
        let root = selected.into_owned_cas_root();
        let operation_id = Uuid::new_v4();
        let default = b"renderDistance:12\n";
        let forged_materialization = b"renderDistance:99\n";
        let trusted = trusted_files(b"guard", default, 'a', 1);
        let plan = current_manifest_plan_with_mutable_override(
            install_id,
            operation_id,
            &trusted,
            forged_materialization,
        );
        let plan_audit =
            audit_current_reconcile_plan_instance(root.install_root(), &plan, &trusted).unwrap();
        let pending = PendingJournalV2 {
            pointer: JournalPointerV2 {
                schema_version: 2,
                install_id,
                channel: BuildChannel::Stable,
                operation_id,
                plan_sha256: format!("{:x}", Sha256::digest(plan.canonical_bytes().unwrap())),
            },
            plan,
        };
        let inventory = ArtifactInventoryV2::build(
            &root,
            &trusted,
            install_id,
            operation_id,
            BuildChannel::Stable,
            PresetId::Medium,
        )
        .unwrap();
        let availability = VerifiedAvailabilityV2::for_test(&inventory, [], true, true);
        let artifact_plan =
            ArtifactPlanV2::for_reconcile(&inventory, &availability, Vec::<String>::new()).unwrap();
        let lock = InstanceStateStore::new(root.install_root(), install_id)
            .acquire_operation_lock(BuildChannel::Stable)
            .unwrap();
        let native_proof = MutableMaterializationProofV2 {
            path: "options.txt".into(),
            size: default.len() as u64,
            sha256: sha256(default),
            current_matches: false,
        };
        let native_proofs = [native_proof];
        let recovered = recover_pending_reconcile_staging_v2(PendingReconcileRecoveryRequestV2 {
            pending: &pending,
            fresh_release: &trusted,
            fresh_inventory: &inventory,
            fresh_artifact_plan: &artifact_plan,
            fresh_plan_audit: Some(&plan_audit),
            mutable_proofs: &native_proofs,
            operation_lock: &lock,
            cas_root: &root,
        })
        .unwrap();
        assert!(matches!(
            recovered,
            PendingReconcileStagingV2::FreshSupersedeRequired(_)
        ));
    }

    #[test]
    fn forged_mutation_set_never_mints_forward_or_rollback_authority() {
        let directory = TestRoot::new("forged-mutation-set");
        let selected = select_install_directory(&directory.0).unwrap();
        let install_id = selected.install_id();
        let root = selected.into_owned_cas_root();
        let operation_id = Uuid::new_v4();
        let default = b"renderDistance:12\n";
        let trusted = trusted_files(b"guard", default, 'a', 1);
        // The desired tree is fully current and the mutable binding is native, but the empty
        // mutation set is not what the fresh missing-instance audit canonically produces.
        let plan = current_manifest_plan_with_mutable_override(
            install_id,
            operation_id,
            &trusted,
            default,
        );
        let plan_audit =
            audit_current_reconcile_plan_instance(root.install_root(), &plan, &trusted).unwrap();
        let pending = PendingJournalV2 {
            pointer: JournalPointerV2 {
                schema_version: 2,
                install_id,
                channel: BuildChannel::Stable,
                operation_id,
                plan_sha256: format!("{:x}", Sha256::digest(plan.canonical_bytes().unwrap())),
            },
            plan,
        };
        let inventory = ArtifactInventoryV2::build(
            &root,
            &trusted,
            install_id,
            operation_id,
            BuildChannel::Stable,
            PresetId::Medium,
        )
        .unwrap();
        let availability = VerifiedAvailabilityV2::for_test(&inventory, [], true, true);
        let artifact_plan =
            ArtifactPlanV2::for_reconcile(&inventory, &availability, Vec::<String>::new()).unwrap();
        let lock = InstanceStateStore::new(root.install_root(), install_id)
            .acquire_operation_lock(BuildChannel::Stable)
            .unwrap();
        let native_proof = MutableMaterializationProofV2 {
            path: "options.txt".into(),
            size: default.len() as u64,
            sha256: sha256(default),
            current_matches: false,
        };
        let native_proofs = [native_proof];
        let recovered = recover_pending_reconcile_staging_v2(PendingReconcileRecoveryRequestV2 {
            pending: &pending,
            fresh_release: &trusted,
            fresh_inventory: &inventory,
            fresh_artifact_plan: &artifact_plan,
            fresh_plan_audit: Some(&plan_audit),
            mutable_proofs: &native_proofs,
            operation_lock: &lock,
            cas_root: &root,
        })
        .unwrap();
        assert!(matches!(
            recovered,
            PendingReconcileStagingV2::FreshSupersedeRequired(_)
        ));
    }

    #[test]
    fn pending_disk_audit_tracks_every_durable_mutation_prefix() {
        for prefix in 0..=3 {
            let mut fixture = Fixture::new(&format!("disk-prefix-{prefix}"));
            let lock = fixture.lock();
            if prefix != 0 {
                let mut completed = 0_usize;
                let error = roll_forward_with_checkpoint_v2(
                    &fixture.plan,
                    &lock,
                    &fixture.proofs,
                    &mut fixture.filesystem,
                    |_| {
                        completed += 1;
                        if completed == prefix {
                            Err("prefix boundary".into())
                        } else {
                            Ok(())
                        }
                    },
                )
                .unwrap_err();
                assert!(matches!(error, ReconcileExecutorErrorV2::Interrupted(_)));
            }

            let remaining =
                audit_remaining_destination_bytes(&fixture.plan, &mut fixture.filesystem, 1)
                    .unwrap();
            assert_eq!(
                remaining,
                [19, 14, 13, 0][prefix],
                "wrong remaining destination reserve after mutation prefix {prefix}"
            );
        }

        let mut temporary = Fixture::new("disk-temporary-prefix");
        let paths = ReconcileOperationPathsV2::from_plan(&temporary.plan).unwrap();
        temporary.filesystem.insert_file(
            paths.install_temporary(0).unwrap().as_str(),
            b"new-content",
            false,
        );
        assert_eq!(
            audit_remaining_destination_bytes(&temporary.plan, &mut temporary.filesystem, 1)
                .unwrap(),
            6
        );

        let mut partial = Fixture::new("disk-partial-temporary-prefix");
        let paths = ReconcileOperationPathsV2::from_plan(&partial.plan).unwrap();
        partial.filesystem.insert_file(
            paths.install_temporary(0).unwrap().as_str(),
            b"new-",
            false,
        );
        assert_eq!(
            audit_remaining_destination_bytes(&partial.plan, &mut partial.filesystem, 1).unwrap(),
            13
        );
    }

    #[test]
    fn first_directory_creation_uncertainty_is_interrupted() {
        let mut fixture = Fixture::new("first-directory-uncertain");
        let paths = ReconcileOperationPathsV2::from_plan(&fixture.plan).unwrap();
        let legacy = fixture
            .filesystem
            .nodes
            .remove("instances/stable/legacy.bin")
            .unwrap();
        fixture
            .filesystem
            .nodes
            .insert(paths.backup_node(0).unwrap().as_str().into(), legacy);
        fixture.filesystem.applied_uncertain_after_ensure = Some("instances/stable/data".into());
        let lock = fixture.lock();

        let error = roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap_err();
        assert!(matches!(error, ReconcileExecutorErrorV2::Interrupted(_)));
        assert!(fixture.filesystem.contains("instances/stable/data"));
        assert!(!fixture.filesystem.contains("instances/stable/data/new.bin"));
    }

    #[test]
    fn later_workspace_failure_remembers_earlier_directory_creation() {
        let root = TestRoot::new("workspace-prefix-uncertain");
        let plan = plan(Uuid::new_v4(), Uuid::new_v4());
        let paths = ReconcileOperationPathsV2::from_plan(&plan).unwrap();
        let mut filesystem = FakeFilesystem::new(&root.0);
        filesystem.not_applied_ensure_failure = Some(paths.rollback_root.as_str().into());

        let error = prepare_workspace(&mut filesystem, &paths).unwrap_err();
        assert!(matches!(error, ReconcileExecutorErrorV2::Interrupted(_)));
        assert!(filesystem.contains(paths.operation_root.as_str()));
        assert!(filesystem.contains(paths.staging_root.as_str()));
        assert!(filesystem.contains(paths.backup_root.as_str()));
        assert!(!filesystem.contains(paths.rollback_root.as_str()));
    }

    #[test]
    fn first_install_copy_uncertainty_is_interrupted() {
        let mut fixture = Fixture::new("first-copy-uncertain");
        let paths = ReconcileOperationPathsV2::from_plan(&fixture.plan).unwrap();
        let legacy = fixture
            .filesystem
            .nodes
            .remove("instances/stable/legacy.bin")
            .unwrap();
        fixture
            .filesystem
            .nodes
            .insert(paths.backup_node(0).unwrap().as_str().into(), legacy);
        fixture
            .filesystem
            .ensure_real_directory(&managed_path("instances/stable/data").unwrap())
            .unwrap();
        fixture.filesystem.applied_uncertain_after_copy =
            Some("instances/stable/data/new.bin".into());
        let lock = fixture.lock();

        let error = roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap_err();
        assert!(matches!(error, ReconcileExecutorErrorV2::Interrupted(_)));
        assert_eq!(
            fixture
                .filesystem
                .file_bytes("instances/stable/data/new.bin"),
            Some(b"new-content".as_slice())
        );
    }

    #[test]
    fn first_rollback_rename_uncertainty_is_interrupted() {
        let mut fixture = Fixture::new("first-rollback-rename-uncertain");
        let lock = fixture.lock();
        roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap();
        fixture.filesystem.applied_uncertain_after_rename =
            Some("instances/stable/data/new.bin".into());

        let error = rollback_v2(&fixture.plan, &lock, &mut fixture.filesystem).unwrap_err();
        assert!(matches!(error, ReconcileExecutorErrorV2::Interrupted(_)));
        let paths = ReconcileOperationPathsV2::from_plan(&fixture.plan).unwrap();
        assert!(!fixture.filesystem.contains("instances/stable/data/new.bin"));
        assert!(fixture
            .filesystem
            .contains(paths.rollback_node(0).unwrap().as_str()));
    }

    #[test]
    fn post_rename_binding_mismatch_is_interrupted() {
        let mut fixture = Fixture::new("post-rename-binding-mismatch");
        let lock = fixture.lock();
        roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap();
        fixture.filesystem.post_rename_binding_mismatch =
            Some("instances/stable/data/new.bin".into());

        let error = rollback_v2(&fixture.plan, &lock, &mut fixture.filesystem).unwrap_err();
        assert!(matches!(error, ReconcileExecutorErrorV2::Interrupted(_)));
    }

    #[test]
    fn same_path_quarantine_install_is_ordered_idempotent_and_rejects_wrong_recreation() {
        let mut fixture = Fixture::new("same-path-quarantine-install");
        fixture.plan.desired_files[0].path = "legacy.bin".into();
        fixture.plan.mutations = vec![
            JournalMutation::Quarantine {
                source_path: "legacy.bin".into(),
                backup_slot: 0,
            },
            JournalMutation::InstallFile {
                destination_path: "legacy.bin".into(),
                staging_slot: 0,
                size: b"new-content".len() as u64,
                sha256: sha256(b"new-content"),
                executable: false,
            },
        ];
        fixture
            .plan
            .validate(fixture.plan.install_id, fixture.plan.channel)
            .unwrap();
        fixture.proofs = audit_staging_files_v2(&fixture.plan, &mut fixture.filesystem).unwrap();
        assert!(
            audit_remaining_destination_bytes(&fixture.plan, &mut fixture.filesystem, 4096)
                .unwrap()
                >= 3 * 4096
        );

        let lock = fixture.lock();
        roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap();
        assert_eq!(
            fixture.filesystem.file_bytes("instances/stable/legacy.bin"),
            Some(b"new-content".as_slice())
        );
        // A restart sees both the recreated source and its quarantine backup. The exact planned
        // recreation is a satisfied prefix, not a conflict.
        roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap();

        fixture
            .filesystem
            .nodes
            .remove("instances/stable/legacy.bin");
        fixture.filesystem.insert_file(
            "instances/stable/legacy.bin",
            b"unexpected-occupant",
            false,
        );
        assert!(matches!(
            audit_remaining_destination_bytes(&fixture.plan, &mut fixture.filesystem, 4096),
            Err(ReconcileExecutorErrorV2::Conflict(_))
                | Err(ReconcileExecutorErrorV2::UnsafeNode(_))
        ));
    }

    #[test]
    fn quarantined_directory_shadows_old_children_and_accepts_only_recreated_plan_prefix() {
        let mut fixture = Fixture::new("directory-quarantine-recreate");
        fixture
            .filesystem
            .nodes
            .remove("instances/stable/legacy.bin");
        fixture
            .filesystem
            .insert_file("instances/stable/config/old.bin", b"old", false);
        fixture.plan.strict_roots = vec!["config".into()];
        fixture.plan.desired_files[0].path = "config/sub/new.bin".into();
        fixture.plan.mutations = vec![
            JournalMutation::Quarantine {
                source_path: "config".into(),
                backup_slot: 0,
            },
            JournalMutation::EnsureDirectory {
                destination_path: "config".into(),
            },
            JournalMutation::EnsureDirectory {
                destination_path: "config/sub".into(),
            },
            JournalMutation::InstallFile {
                destination_path: "config/sub/new.bin".into(),
                staging_slot: 0,
                size: b"new-content".len() as u64,
                sha256: sha256(b"new-content"),
                executable: false,
            },
        ];
        fixture
            .plan
            .validate(fixture.plan.install_id, fixture.plan.channel)
            .unwrap();
        fixture.proofs = audit_staging_files_v2(&fixture.plan, &mut fixture.filesystem).unwrap();
        // The matching old subtree is still physically present, but it receives no destination
        // credit because canonical mutation order quarantines it first.
        assert!(
            audit_remaining_destination_bytes(&fixture.plan, &mut fixture.filesystem, 4096)
                .unwrap()
                >= 5 * 4096
        );
        let lock = fixture.lock();
        roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap();
        roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap();
        fixture.filesystem.insert_file(
            "instances/stable/config/unexpected.bin",
            b"unexpected",
            false,
        );
        assert!(matches!(
            audit_remaining_destination_bytes(&fixture.plan, &mut fixture.filesystem, 4096),
            Err(ReconcileExecutorErrorV2::Conflict(_))
                | Err(ReconcileExecutorErrorV2::UnsafeNode(_))
        ));
    }

    #[test]
    fn managed_roll_forward_resumes_a_partial_install_temporary() {
        let root = TestRoot::new("managed-partial-install-temporary");
        let install_id = Uuid::new_v4();
        let plan = plan(install_id, Uuid::new_v4());
        let paths = ReconcileOperationPathsV2::from_plan(&plan).unwrap();
        let staging = paths.staging_file(0).unwrap().join_to(&root.0);
        let temporary = paths.install_temporary(0).unwrap().join_to(&root.0);
        fs::create_dir_all(staging.parent().unwrap()).unwrap();
        fs::create_dir_all(temporary.parent().unwrap()).unwrap();
        fs::create_dir_all(root.0.join("instances/stable")).unwrap();
        fs::write(&staging, b"new-content").unwrap();
        fs::write(&temporary, b"new-").unwrap();
        fs::write(root.0.join("instances/stable/legacy.bin"), b"old-content").unwrap();
        let lock = InstanceStateStore::new(&root.0, install_id)
            .acquire_operation_lock(BuildChannel::Stable)
            .unwrap();
        let mut filesystem = ManagedReconcileFileSystemV2::new(&root.0);
        let proofs = audit_staging_files_v2(&plan, &mut filesystem).unwrap();
        roll_forward_v2(&plan, &lock, &proofs, &mut filesystem).unwrap();
        assert_eq!(
            fs::read(root.0.join("instances/stable/data/new.bin")).unwrap(),
            b"new-content"
        );
        assert!(!temporary.exists());
    }

    #[test]
    fn complete_install_temporary_crosses_the_resumable_sync_boundary() {
        let mut fixture = Fixture::new("complete-temporary-sync");
        let paths = ReconcileOperationPathsV2::from_plan(&fixture.plan).unwrap();
        fixture.filesystem.insert_file(
            paths.install_temporary(0).unwrap().as_str(),
            b"new-content",
            false,
        );
        let lock = fixture.lock();
        roll_forward_v2(
            &fixture.plan,
            &lock,
            &fixture.proofs,
            &mut fixture.filesystem,
        )
        .unwrap();
        assert_eq!(fixture.filesystem.copy_calls, 1);
        assert_eq!(
            fixture
                .filesystem
                .file_bytes("instances/stable/data/new.bin"),
            Some(b"new-content".as_slice())
        );
        assert!(!fixture
            .filesystem
            .contains(paths.install_temporary(0).unwrap().as_str()));
    }

    #[test]
    fn pending_disk_assessment_enforces_exact_threshold_binding_and_overflow() {
        let fixture = ExactProductionFixture::new("disk-threshold", b"threshold".to_vec());
        let lock = fixture.lock();
        let authority = fixture.authority(&lock);
        let source =
            bind_exact_staging_source_v2(&authority, &lock, &fixture.root, 0, &fixture.object)
                .unwrap();
        let staged =
            write_reconcile_staging_v2(&authority, &lock, &fixture.root, vec![source]).unwrap();
        let baseline = authority
            .assess_remaining_space_with(&staged, &lock, &fixture.root, |_| Ok(u64::MAX))
            .unwrap();
        assert!(baseline.required_bytes >= fixture.plan.disk_budget.journal_reserve_bytes);
        assert!(baseline.required_bytes >= fixture.plan.disk_budget.safety_margin_bytes);
        let below = baseline.required_bytes - 1;
        let assessed = authority
            .assess_remaining_space_with(&staged, &lock, &fixture.root, |_| Ok(below))
            .unwrap();
        assert!(matches!(
            assessed.require_fits(&authority),
            Err(ReconcileExecutorErrorV2::InsufficientSpace {
                required_bytes,
                available_bytes
            }) if required_bytes == baseline.required_bytes && available_bytes == below
        ));
        let binding = authority.binding.clone();
        PendingRemainingSpaceAssessmentV2 {
            binding: binding.clone(),
            required_bytes: 10,
            available_bytes: 10,
        }
        .require_fits(&authority)
        .unwrap();
        assert!(matches!(
            PendingRemainingSpaceAssessmentV2 {
                binding: binding.clone(),
                required_bytes: 10,
                available_bytes: 9,
            }
            .require_fits(&authority),
            Err(ReconcileExecutorErrorV2::InsufficientSpace {
                required_bytes: 10,
                available_bytes: 9
            })
        ));
        let mut foreign_binding = binding;
        foreign_binding.operation_id = Uuid::new_v4();
        assert!(matches!(
            PendingRemainingSpaceAssessmentV2 {
                binding: foreign_binding,
                required_bytes: 0,
                available_bytes: u64::MAX,
            }
            .require_fits(&authority),
            Err(ReconcileExecutorErrorV2::InvalidScope(_))
        ));
        assert!(checked_remaining_destination_sum(u64::MAX, 1).is_err());
        let first = round_up_allocation(1, 4096).unwrap();
        let two_tiny_files = checked_remaining_destination_sum(first, first).unwrap();
        assert_eq!(two_tiny_files, 8192);
        assert!(round_up_allocation(u64::MAX, 4096).is_err());
    }

    #[test]
    fn pending_disk_assessment_rejects_a_foreign_or_rebound_root() {
        let left = ExactProductionFixture::new("disk-root-left", b"same-root-bytes".to_vec());
        let right = ExactProductionFixture::new("disk-root-right", b"same-root-bytes".to_vec());
        let left_lock = left.lock();
        let authority = left.authority(&left_lock);
        let source =
            bind_exact_staging_source_v2(&authority, &left_lock, &left.root, 0, &left.object)
                .unwrap();
        let staged =
            write_reconcile_staging_v2(&authority, &left_lock, &left.root, vec![source]).unwrap();
        assert!(matches!(
            authority.assess_remaining_space(&staged, &left_lock, &right.root),
            Err(ReconcileExecutorErrorV2::InvalidScope(_))
                | Err(ReconcileExecutorErrorV2::InvalidStagingProof(_))
        ));
    }
}
