use super::{
    instance_state::InstanceOperationLock,
    journal::{JournalMutation, ReconcilePlanV2},
    managed_fs::{
        ensure_directory_chain, move_managed_node_no_replace, ExclusiveManagedFile, FileIdentity,
        GuardedDirectoryChain, ImmutableManagedFile, ManagedNodeKind, RelativeManagedPath,
    },
    planner::StagingFileProofV2,
};
use std::{
    collections::BTreeMap,
    fmt::Debug,
    io::ErrorKind,
    path::{Path, PathBuf},
};
use thiserror::Error;

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

    fn install_root(&self) -> &Path;

    fn inspect_node(
        &mut self,
        path: &RelativeManagedPath,
    ) -> Result<Option<ExecutorNodeSnapshotV2<Self::Identity>>, String>;

    /// Ensures the complete path is made only of real directories and reports whether the leaf
    /// directory was created by this call.
    fn ensure_real_directory(&mut self, path: &RelativeManagedPath) -> Result<bool, String>;

    fn rename_node_no_replace(
        &mut self,
        source: &RelativeManagedPath,
        expected: &ExecutorNodeSnapshotV2<Self::Identity>,
        destination: &RelativeManagedPath,
    ) -> Result<(), String>;

    fn copy_regular_file_no_replace(
        &mut self,
        source: &RelativeManagedPath,
        expected_source: &ExecutorNodeSnapshotV2<Self::Identity>,
        temporary: &RelativeManagedPath,
        destination: &RelativeManagedPath,
        expected_destination: &ExecutorFileBindingV2,
    ) -> Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ManagedExecutorIdentityV2 {
    Stable(FileIdentity),
    /// The safe move primitive obtains and verifies the real identity through its own handle. The
    /// executor intentionally has no path-derived identity for a reparse object.
    OpaqueReparse,
}

/// Production adapter over `managed_fs`. Its root is the same install root protected by the
/// channel operation lock.
pub(super) struct ManagedReconcileFileSystemV2 {
    install_root: PathBuf,
}

impl ManagedReconcileFileSystemV2 {
    pub fn new(install_root: &Path) -> Self {
        Self {
            install_root: install_root.to_path_buf(),
        }
    }
}

impl ReconcileFileSystemV2 for ManagedReconcileFileSystemV2 {
    type Identity = ManagedExecutorIdentityV2;

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
            return Ok(Some(ExecutorNodeSnapshotV2 {
                identity: ManagedExecutorIdentityV2::OpaqueReparse,
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

    fn ensure_real_directory(&mut self, path: &RelativeManagedPath) -> Result<bool, String> {
        let existed = self.inspect_node(path)?.is_some();
        ensure_directory_chain(&self.install_root, path).map_err(|error| error.to_string())?;
        Ok(!existed)
    }

    fn rename_node_no_replace(
        &mut self,
        source: &RelativeManagedPath,
        expected: &ExecutorNodeSnapshotV2<Self::Identity>,
        destination: &RelativeManagedPath,
    ) -> Result<(), String> {
        let moved =
            move_managed_node_no_replace(&self.install_root, source.clone(), destination.clone())
                .map_err(|error| error.to_string())?;
        if let ManagedExecutorIdentityV2::Stable(identity) = &expected.identity {
            if moved.identity != *identity {
                return Err("managed move returned a different filesystem identity".into());
            }
        }
        let expected_kind = match &expected.kind {
            ExecutorNodeKindV2::RegularFile { .. } => Some(ManagedNodeKind::File),
            ExecutorNodeKindV2::RealDirectory => Some(ManagedNodeKind::Directory),
            ExecutorNodeKindV2::ReparsePoint | ExecutorNodeKindV2::Unsupported => None,
        };
        if expected_kind.is_some_and(|kind| kind != moved.kind) {
            return Err("managed move returned a different node kind".into());
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
    ) -> Result<(), String> {
        if expected_destination.executable && cfg!(windows) {
            return Err("Windows reconcile files cannot carry a POSIX executable bit".into());
        }
        let mut source_file = ImmutableManagedFile::open(&self.install_root, source)
            .map_err(|error| error.to_string())?;
        let ManagedExecutorIdentityV2::Stable(expected_identity) = &expected_source.identity else {
            return Err("copy source has no stable filesystem identity".into());
        };
        if source_file.info().identity != *expected_identity {
            return Err("copy source identity changed after its staging audit".into());
        }
        let mut temporary_file =
            ExclusiveManagedFile::create(&self.install_root, temporary.clone())
                .map_err(|error| error.to_string())?;
        let digest = source_file
            .copy_to_exclusive(&mut temporary_file, expected_destination.size)
            .map_err(|error| error.to_string())?;
        if digest.size != expected_destination.size || digest.sha256 != expected_destination.sha256
        {
            return Err("streamed staging bytes do not match the signed destination".into());
        }
        set_executable_bit(&mut temporary_file, expected_destination.executable)?;
        temporary_file
            .sync()
            .map_err(|error| error.to_string())?
            .rename_no_replace(destination.clone())
            .map_err(|error| error.to_string())?;
        Ok(())
    }
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

fn set_executable_bit(file: &mut ExclusiveManagedFile, executable: bool) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = file
            .file_mut()
            .metadata()
            .map_err(|error| format!("cannot inspect staged permissions: {error}"))?
            .permissions();
        let mode = permissions.mode();
        permissions.set_mode(if executable {
            mode | 0o111
        } else {
            mode & !0o111
        });
        file.file_mut()
            .set_permissions(permissions)
            .map_err(|error| format!("cannot set staged executable bit: {error}"))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (file, executable);
    }
    Ok(())
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
    /// Cleanup may start only after `journal::clear_pending` has durably published its tombstone.
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

struct StagingAuditV2<I> {
    by_slot: BTreeMap<u32, ExecutorNodeSnapshotV2<I>>,
    proofs: Vec<StagingFileProofV2>,
}

/// Rebuilds staging proofs from deterministic paths and leased, no-follow file hashes.
pub(super) fn audit_staging_files_v2<F: ReconcileFileSystemV2>(
    plan: &ReconcilePlanV2,
    filesystem: &mut F,
) -> Result<Vec<StagingFileProofV2>, ReconcileExecutorErrorV2> {
    validate_plan(plan)?;
    let paths = ReconcileOperationPathsV2::from_plan(plan)?;
    Ok(audit_staging_internal(plan, filesystem, &paths)?.proofs)
}

/// Applies a plan in journal order. The caller must have loaded this exact plan through
/// `journal::detect_pending`; this function independently revalidates its scope, proofs and every
/// filesystem postcondition. Staging files are copied, never consumed.
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
pub(super) fn roll_forward_with_checkpoint_v2<F, C>(
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
    prepare_workspace(filesystem, &paths)?;
    let staging = audit_staging_internal(plan, filesystem, &paths)?;
    require_exact_proofs(staging_proofs, &staging.proofs)?;

    let mut report = ReconcileExecutionReportV2 {
        mutations: Vec::with_capacity(plan.mutations.len()),
    };
    for (mutation_index, mutation) in plan.mutations.iter().enumerate() {
        let disposition = match mutation {
            JournalMutation::Quarantine {
                source_path,
                backup_slot,
            } => roll_forward_quarantine(
                filesystem,
                &paths.instance_path(source_path)?,
                &paths.backup_node(*backup_slot)?,
            )?,
            JournalMutation::EnsureDirectory { destination_path } => {
                roll_forward_directory(filesystem, &paths.instance_path(destination_path)?)?
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
                    &paths.staging_file(*staging_slot)?,
                    expected_source,
                    &paths.instance_path(destination_path)?,
                    &paths.rollback_node(*staging_slot)?,
                    &paths.install_temporary(*staging_slot)?,
                    &ExecutorFileBindingV2 {
                        size: *size,
                        sha256: sha256.clone(),
                        executable: *executable,
                    },
                )?
            }
        };
        let execution = MutationExecutionV2 {
            mutation_index,
            disposition,
        };
        report.mutations.push(execution.clone());
        checkpoint(&execution).map_err(ReconcileExecutorErrorV2::Interrupted)?;
    }
    Ok(report)
}

/// Reverses every possibly applied mutation in reverse journal order. It intentionally does not
/// require staging proofs: rollback is the safe decision when staging is incomplete. Installed
/// files are moved to deterministic rollback slots rather than deleted; created directories are
/// left in place, so this function never performs recursive deletion.
pub(super) fn rollback_v2<F: ReconcileFileSystemV2>(
    plan: &ReconcilePlanV2,
    operation_lock: &InstanceOperationLock,
    filesystem: &mut F,
) -> Result<ReconcileExecutionReportV2, ReconcileExecutorErrorV2> {
    rollback_with_checkpoint_v2(plan, operation_lock, filesystem, |_| Ok(()))
}

pub(super) fn rollback_with_checkpoint_v2<F, C>(
    plan: &ReconcilePlanV2,
    operation_lock: &InstanceOperationLock,
    filesystem: &mut F,
    mut checkpoint: C,
) -> Result<ReconcileExecutionReportV2, ReconcileExecutorErrorV2>
where
    F: ReconcileFileSystemV2,
    C: FnMut(&MutationExecutionV2) -> Result<(), String>,
{
    validate_scope(plan, operation_lock, filesystem.install_root())?;
    let paths = ReconcileOperationPathsV2::from_plan(plan)?;
    prepare_workspace(filesystem, &paths)?;
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
            )?,
            JournalMutation::EnsureDirectory { destination_path } => {
                rollback_directory(filesystem, &paths.instance_path(destination_path)?)?
            }
            JournalMutation::Quarantine {
                source_path,
                backup_slot,
            } => rollback_quarantine(
                filesystem,
                &paths.instance_path(source_path)?,
                &paths.backup_node(*backup_slot)?,
                plan_recreates_path(plan, source_path)
                    .then(|| paths.replacement_node(*backup_slot))
                    .transpose()?
                    .as_ref(),
            )?,
        };
        let execution = MutationExecutionV2 {
            mutation_index,
            disposition,
        };
        report.mutations.push(execution.clone());
        checkpoint(&execution).map_err(ReconcileExecutorErrorV2::Interrupted)?;
    }
    Ok(report)
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
    for directory in [
        &paths.operation_root,
        &paths.staging_root,
        &paths.backup_root,
        &paths.rollback_root,
        &paths.replacement_root,
        &paths.temporary_root,
        &paths.instance_root,
    ] {
        filesystem
            .ensure_real_directory(directory)
            .map_err(ReconcileExecutorErrorV2::Filesystem)?;
        require_real_directory(filesystem, directory)?;
    }
    Ok(())
}

fn audit_staging_internal<F: ReconcileFileSystemV2>(
    plan: &ReconcilePlanV2,
    filesystem: &mut F,
    paths: &ReconcileOperationPathsV2,
) -> Result<StagingAuditV2<F::Identity>, ReconcileExecutorErrorV2> {
    let mut by_slot = BTreeMap::new();
    let mut proofs = Vec::new();
    for mutation in &plan.mutations {
        let JournalMutation::InstallFile {
            destination_path,
            staging_slot,
            size,
            sha256,
            ..
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
            executable: regular_binding(&snapshot, &path)?.executable,
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

fn roll_forward_quarantine<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    source: &RelativeManagedPath,
    backup: &RelativeManagedPath,
) -> Result<MutationDispositionV2, ReconcileExecutorErrorV2> {
    let source_node = inspect(filesystem, source)?;
    let backup_node = inspect(filesystem, backup)?;
    match (source_node, backup_node) {
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
            rename_and_verify(filesystem, source, &source_node, backup)?;
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
                .map_err(ReconcileExecutorErrorV2::Filesystem)?;
            require_real_directory(filesystem, destination)?;
            Ok(if created {
                MutationDispositionV2::Applied
            } else {
                MutationDispositionV2::AlreadySatisfied
            })
        }
    }
}

fn roll_forward_install<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    staging: &RelativeManagedPath,
    expected_staging: &ExecutorNodeSnapshotV2<F::Identity>,
    destination: &RelativeManagedPath,
    rollback: &RelativeManagedPath,
    temporary: &RelativeManagedPath,
    expected: &ExecutorFileBindingV2,
) -> Result<MutationDispositionV2, ReconcileExecutorErrorV2> {
    require_regular_binding(expected_staging, expected, staging, true)?;
    let destination_node = inspect(filesystem, destination)?;
    let rollback_node = inspect(filesystem, rollback)?;
    let temporary_node = inspect(filesystem, temporary)?;
    if let Some(temporary_node) = temporary_node {
        require_regular_binding(&temporary_node, expected, temporary, true)?;
        if destination_node.is_some() || rollback_node.is_some() {
            return Err(conflict(format!(
                "install temporary {} coexists with its destination or rollback slot",
                temporary.as_str()
            )));
        }
        rename_and_verify(filesystem, temporary, &temporary_node, destination)?;
        require_same_file_snapshot(filesystem, staging, expected_staging, expected, false)?;
        require_exact_file(filesystem, destination, expected)?;
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
            rename_and_verify(filesystem, rollback, &rollback_node, destination)?;
            MutationDispositionV2::Applied
        }
        (None, None) => {
            filesystem
                .copy_regular_file_no_replace(
                    staging,
                    expected_staging,
                    temporary,
                    destination,
                    expected,
                )
                .map_err(ReconcileExecutorErrorV2::Filesystem)?;
            if inspect(filesystem, temporary)?.is_some() {
                return Err(conflict(format!(
                    "install copy returned but left its temporary in place: {}",
                    temporary.as_str()
                )));
            }
            require_exact_file(filesystem, destination, expected)?;
            MutationDispositionV2::Applied
        }
    };
    require_same_file_snapshot(filesystem, staging, expected_staging, expected, false)?;
    require_exact_file(filesystem, destination, expected)?;
    Ok(disposition)
}

fn rollback_install<F: ReconcileFileSystemV2>(
    filesystem: &mut F,
    destination: &RelativeManagedPath,
    rollback: &RelativeManagedPath,
    expected: &ExecutorFileBindingV2,
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
            rename_and_verify(filesystem, destination, &destination_node, rollback)?;
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
    source: &RelativeManagedPath,
    backup: &RelativeManagedPath,
    replacement: Option<&RelativeManagedPath>,
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
            rename_and_verify(filesystem, source, &source_node, replacement)?;
            require_movable(&backup_node, backup)?;
            rename_and_verify(filesystem, backup, &backup_node, source)?;
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
            rename_and_verify(filesystem, backup, &backup_node, source)?;
            Ok(MutationDispositionV2::Applied)
        }
    }
}

fn plan_recreates_path(plan: &ReconcilePlanV2, source: &str) -> bool {
    let source = source.to_lowercase();
    plan.mutations.iter().any(|mutation| {
        let destination = match mutation {
            JournalMutation::EnsureDirectory { destination_path }
            | JournalMutation::InstallFile {
                destination_path, ..
            } => destination_path,
            JournalMutation::Quarantine { .. } => return false,
        }
        .to_lowercase();
        destination == source || destination.starts_with(&format!("{source}/"))
    })
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
        .map_err(ReconcileExecutorErrorV2::Filesystem)?;
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
        instance_state::{ActiveInstanceV2, InstanceStateStore},
        journal::{DiskBudgetV2, OperationKind, PlannedFileV2},
        release::FilePolicy,
        tuf::{TrustedReleaseEvidence, TrustedRoleVersions, TrustedTargetEvidence},
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

    #[derive(Debug, Clone)]
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

    struct FakeFilesystem {
        root: PathBuf,
        next_identity: u64,
        nodes: BTreeMap<String, FakeNode>,
    }

    impl FakeFilesystem {
        fn new(root: &Path) -> Self {
            Self {
                root: root.to_path_buf(),
                next_identity: 1,
                nodes: BTreeMap::new(),
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
    }

    impl ReconcileFileSystemV2 for FakeFilesystem {
        type Identity = u64;

        fn install_root(&self) -> &Path {
            &self.root
        }

        fn inspect_node(
            &mut self,
            path: &RelativeManagedPath,
        ) -> Result<Option<ExecutorNodeSnapshotV2<Self::Identity>>, String> {
            Ok(self.nodes.get(path.as_str()).map(Self::snapshot))
        }

        fn ensure_real_directory(&mut self, path: &RelativeManagedPath) -> Result<bool, String> {
            let mut created_leaf = false;
            let parts = path.as_str().split('/').collect::<Vec<_>>();
            for end in 1..=parts.len() {
                let current = parts[..end].join("/");
                match self.nodes.get(&current) {
                    Some(FakeNode::Directory { .. }) => {}
                    Some(_) => return Err(format!("unsafe directory component: {current}")),
                    None => {
                        let identity = self.allocate_identity();
                        self.nodes.insert(current, FakeNode::Directory { identity });
                        if end == parts.len() {
                            created_leaf = true;
                        }
                    }
                }
            }
            Ok(created_leaf)
        }

        fn rename_node_no_replace(
            &mut self,
            source: &RelativeManagedPath,
            expected: &ExecutorNodeSnapshotV2<Self::Identity>,
            destination: &RelativeManagedPath,
        ) -> Result<(), String> {
            if self.nodes.contains_key(destination.as_str()) {
                return Err("destination exists".into());
            }
            self.ensure_parents(destination.as_str());
            let actual = self
                .nodes
                .get(source.as_str())
                .map(Self::snapshot)
                .ok_or_else(|| "source missing".to_string())?;
            if &actual != expected {
                return Err("source lease changed".into());
            }
            if matches!(
                actual.kind,
                ExecutorNodeKindV2::RegularFile { link_count, .. } if link_count != 1
            ) {
                return Err("hard link rejected".into());
            }
            let node = self.nodes.remove(source.as_str()).unwrap();
            self.nodes.insert(destination.as_str().into(), node);
            Ok(())
        }

        fn copy_regular_file_no_replace(
            &mut self,
            source: &RelativeManagedPath,
            expected_source: &ExecutorNodeSnapshotV2<Self::Identity>,
            temporary: &RelativeManagedPath,
            destination: &RelativeManagedPath,
            expected_destination: &ExecutorFileBindingV2,
        ) -> Result<(), String> {
            if self.nodes.contains_key(destination.as_str())
                || self.nodes.contains_key(temporary.as_str())
            {
                return Err("destination or temporary exists".into());
            }
            let actual = self
                .nodes
                .get(source.as_str())
                .map(Self::snapshot)
                .ok_or_else(|| "source missing".to_string())?;
            if &actual != expected_source {
                return Err("source lease changed".into());
            }
            let bytes = match self.nodes.get(source.as_str()) {
                Some(FakeNode::File {
                    bytes,
                    link_count: 1,
                    ..
                }) => bytes.clone(),
                _ => return Err("source is not a single-link regular file".into()),
            };
            if bytes.len() as u64 != expected_destination.size
                || sha256(&bytes) != expected_destination.sha256
            {
                return Err("source binding mismatch".into());
            }
            self.insert_file(temporary.as_str(), &bytes, expected_destination.executable);
            let snapshot = self
                .nodes
                .get(temporary.as_str())
                .map(Self::snapshot)
                .unwrap();
            self.rename_node_no_replace(temporary, &snapshot, destination)?;
            Ok(())
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
        assert_eq!(
            fs::read(root.0.join("instances/stable/data/new.bin")).unwrap(),
            b"new-content"
        );
        assert_eq!(fs::read(&staging).unwrap(), b"new-content");
        assert!(!legacy.exists());

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
            Err(ReconcileExecutorErrorV2::Conflict(_))
        ));
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
}
