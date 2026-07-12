use super::{
    contracts::{is_sha256, validate_manifest_path},
    instance_state::{ActiveInstanceV2, InstanceOperationLock, InstanceStateStore},
    managed_fs::{
        atomic_write_small, ensure_directory_chain, ExclusiveManagedFile, ImmutableManagedFile,
        ManagedFsError, RelativeManagedPath,
    },
    planner::{FinalizeCommitAuthorizationV2, RepairSupersedeAuthorizationV2},
    reconcile_executor::RollbackCompletionAuthorizationV2,
    release::FilePolicy,
    types::BuildChannel,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    io::Write,
    path::Path,
};
use uuid::{Uuid, Version};

const JOURNAL_SCHEMA_VERSION: u8 = 2;
const MAX_POINTER_BYTES: u64 = 4 * 1024;
const MAX_PLAN_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PRESERVED_PATHS: usize = 4_096;
const MAX_MUTATIONS: usize = 400_000;
const MAX_RELATIVE_PATH_BYTES: usize = 1_024;
const MAX_RELATIVE_PATH_SEGMENTS: usize = 128;
const MAX_MANAGED_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_PLAN_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024 * 1024;
pub(super) const JOURNAL_RESERVE_BYTES: u64 = 64 * 1024 * 1024 + 64 * 1024;
pub(super) const MINIMUM_SAFETY_MARGIN_BYTES: u64 = 256 * 1024 * 1024;

/// The only mutable commit point in the reconcile journal.
///
/// The plan path is deliberately not stored here: it is derived from the trusted channel,
/// operation ID and plan digest. This keeps all filesystem paths launcher-owned.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JournalPointerV2 {
    pub schema_version: u8,
    pub install_id: Uuid,
    pub channel: BuildChannel,
    pub operation_id: Uuid,
    pub plan_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JournalTombstoneV2 {
    schema_version: u8,
    install_id: Uuid,
    channel: BuildChannel,
    completed_pointer: JournalPointerV2,
    completed_pointer_sha256: String,
    outcome: JournalCompletionOutcomeV2,
    continuation: Option<ActiveInstanceV2>,
}

/// The durable outcome of one reconcile operation.
///
/// `continuation` is independently bound to the immutable plan before a tombstone is accepted:
/// committed and superseded operations continue from the exact target, while a rollback
/// continues from the exact optional base. Keeping these cases distinct prevents a rolled-back
/// first install (`base = None`) from being mistaken for a committed generation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum JournalCompletionOutcomeV2 {
    CommittedTarget,
    RolledBackToBase,
    SupersededForRepair,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
enum JournalSlotV2 {
    Pending(JournalPointerV2),
    Cleared(Box<JournalTombstoneV2>),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OperationKind {
    Install,
    Update,
    Repair,
    PresetChange,
}

/// A complete, content-addressed description of one instance transition.
///
/// It is a recovery record, not authorization: the caller must build it from a freshly trusted
/// release and re-audit the instance before returning `ready` or launching.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconcilePlanV2 {
    pub schema_version: u8,
    pub install_id: Uuid,
    pub operation_id: Uuid,
    pub channel: BuildChannel,
    pub kind: OperationKind,
    pub base: Option<ActiveInstanceV2>,
    pub target: ActiveInstanceV2,
    pub strict_roots: Vec<String>,
    pub preserved_paths: Vec<String>,
    pub desired_files: Vec<PlannedFileV2>,
    pub disk_budget: DiskBudgetV2,
    pub mutations: Vec<JournalMutation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlannedFileV2 {
    pub path: String,
    pub signed_size: u64,
    pub signed_sha256: String,
    pub installed_size: u64,
    pub installed_sha256: String,
    pub executable: bool,
    pub policy: FilePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskBudgetV2 {
    pub missing_download_bytes: u64,
    pub java_extracted_bytes: u64,
    pub game_extracted_bytes: u64,
    pub staging_bytes: u64,
    pub journal_reserve_bytes: u64,
    pub safety_margin_bytes: u64,
    pub required_bytes: u64,
}

impl DiskBudgetV2 {
    pub fn new(
        missing_download_bytes: u64,
        java_extracted_bytes: u64,
        game_extracted_bytes: u64,
        staging_bytes: u64,
    ) -> Result<Self, String> {
        let subtotal = [
            missing_download_bytes,
            java_extracted_bytes,
            game_extracted_bytes,
            staging_bytes,
            JOURNAL_RESERVE_BYTES,
        ]
        .into_iter()
        .try_fold(0_u64, |total, value| total.checked_add(value))
        .ok_or_else(|| "Disk budget subtotal overflowed".to_string())?;
        let five_percent = subtotal / 20 + u64::from(subtotal % 20 != 0);
        let safety_margin_bytes = five_percent.max(MINIMUM_SAFETY_MARGIN_BYTES);
        let required_bytes = subtotal
            .checked_add(safety_margin_bytes)
            .ok_or_else(|| "Disk budget total overflowed".to_string())?;
        Ok(Self {
            missing_download_bytes,
            java_extracted_bytes,
            game_extracted_bytes,
            staging_bytes,
            journal_reserve_bytes: JOURNAL_RESERVE_BYTES,
            safety_margin_bytes,
            required_bytes,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        let expected = Self::new(
            self.missing_download_bytes,
            self.java_extracted_bytes,
            self.game_extracted_bytes,
            self.staging_bytes,
        )?;
        if *self != expected {
            return Err("Reconcile disk budget is not canonical".into());
        }
        Ok(())
    }

    pub fn fits(&self, available_bytes: u64) -> bool {
        available_bytes >= self.required_bytes
    }
}

/// Filesystem actions are intentionally relative and individually enumerable. In particular,
/// there is no recursive-delete mutation. Quarantine is a recoverable rename into a numbered
/// backup slot; installation consumes an already verified numbered staging slot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum JournalMutation {
    Quarantine {
        source_path: String,
        backup_slot: u32,
    },
    EnsureDirectory {
        destination_path: String,
    },
    InstallFile {
        destination_path: String,
        staging_slot: u32,
        size: u64,
        sha256: String,
        executable: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingJournalV2 {
    pub pointer: JournalPointerV2,
    pub plan: ReconcilePlanV2,
}

impl JournalPointerV2 {
    pub fn validate(
        &self,
        expected_install_id: Uuid,
        expected_channel: BuildChannel,
    ) -> Result<(), String> {
        if self.schema_version != JOURNAL_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported reconcile journal pointer schema {}",
                self.schema_version
            ));
        }
        validate_identity(
            self.install_id,
            self.operation_id,
            self.channel,
            expected_install_id,
            expected_channel,
        )?;
        if !is_sha256(&self.plan_sha256) {
            return Err("Reconcile journal pointer has an invalid plan SHA-256".into());
        }
        Ok(())
    }
}

impl ReconcilePlanV2 {
    pub fn validate(
        &self,
        expected_install_id: Uuid,
        expected_channel: BuildChannel,
    ) -> Result<(), String> {
        if self.schema_version != JOURNAL_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported reconcile plan schema {}",
                self.schema_version
            ));
        }
        validate_identity(
            self.install_id,
            self.operation_id,
            self.channel,
            expected_install_id,
            expected_channel,
        )?;
        self.target
            .validate(expected_install_id, expected_channel)
            .map_err(|error| format!("Invalid reconcile target state: {error}"))?;

        match (&self.kind, &self.base) {
            (OperationKind::Install, None) if self.target.generation == 1 => {}
            (OperationKind::Install, None) => {
                return Err("An install target must be generation 1".into())
            }
            (OperationKind::Install, Some(_)) => {
                return Err("An install plan must not have a base state".into())
            }
            (_, None) => return Err("A non-install plan requires a base state".into()),
            (_, Some(base)) => {
                base.validate(expected_install_id, expected_channel)
                    .map_err(|error| format!("Invalid reconcile base state: {error}"))?;
                let next_generation = base
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| "Reconcile generation overflowed".to_string())?;
                if self.target.generation != next_generation {
                    return Err(
                        "Reconcile target generation must immediately follow its base".into(),
                    );
                }

                let same_release = same_release_content(base, &self.target);
                let same_preset = base.preset == self.target.preset;
                match self.kind {
                    OperationKind::Repair if !(same_release && same_preset) => {
                        return Err("A repair plan must preserve release, preset and runtime".into())
                    }
                    OperationKind::PresetChange if !same_release || same_preset => {
                        return Err(
                            "A preset-change plan may only change the selected preset".into()
                        )
                    }
                    OperationKind::Update if same_release => {
                        return Err(
                            "An update plan must change the immutable release binding".into()
                        )
                    }
                    _ => {}
                }
            }
        }

        let strict = validate_canonical_paths(&self.strict_roots, MAX_PRESERVED_PATHS, "strict")?;
        if self.strict_roots.is_empty() {
            return Err("Reconcile plan must bind at least one strict root".into());
        }
        let preserved = self.validate_preserved_paths()?;
        for path in &strict.ordered {
            if preserved.overlaps(path) {
                return Err("Strict roots overlap preserved paths".into());
            }
        }
        let desired = self.validate_desired_files(&preserved)?;
        let staging_bytes = self.validate_mutations(&preserved, &desired)?;
        self.disk_budget.validate()?;
        if self.disk_budget.staging_bytes != staging_bytes {
            return Err("Disk budget staging bytes do not match install mutations".into());
        }
        Ok(())
    }

    fn validate_preserved_paths(&self) -> Result<PathBoundaryIndex, String> {
        validate_canonical_paths(&self.preserved_paths, MAX_PRESERVED_PATHS, "preserved")
    }

    fn validate_desired_files(
        &self,
        preserved: &PathBoundaryIndex,
    ) -> Result<BTreeMap<String, &PlannedFileV2>, String> {
        if self.desired_files.is_empty() || self.desired_files.len() > MAX_MUTATIONS {
            return Err("Reconcile plan desired-file set is empty or oversized".into());
        }
        let mut previous: Option<String> = None;
        let mut desired = BTreeMap::new();
        for file in &self.desired_files {
            validate_mutation_path(&file.path, preserved)?;
            let key = path_key(&file.path);
            require_sorted_unique(&previous, &key, "desired file")?;
            if file.signed_size > MAX_MANAGED_FILE_BYTES
                || file.installed_size > MAX_MANAGED_FILE_BYTES
                || !is_sha256(&file.signed_sha256)
                || !is_sha256(&file.installed_sha256)
                || (file.policy == FilePolicy::Exact
                    && (file.signed_size != file.installed_size
                        || file.signed_sha256 != file.installed_sha256))
            {
                return Err(format!("Desired file binding is invalid: {}", file.path));
            }
            desired.insert(key.clone(), file);
            previous = Some(key);
        }
        Ok(desired)
    }

    fn validate_mutations(
        &self,
        preserved: &PathBoundaryIndex,
        desired: &BTreeMap<String, &PlannedFileV2>,
    ) -> Result<u64, String> {
        if self.mutations.len() > MAX_MUTATIONS {
            return Err("Reconcile plan has too many mutations".into());
        }

        let mut phase = 0_u8;
        let mut previous_quarantine: Option<String> = None;
        let mut previous_directory: Option<String> = None;
        let mut previous_install: Option<String> = None;
        let mut quarantine_paths = PathBoundaryIndex::default();
        let mut directory_paths = BTreeSet::new();
        let mut install_paths = PathBoundaryIndex::default();
        let mut backup_slots = HashSet::new();
        let mut staging_slots = HashSet::new();
        let mut total_file_bytes = 0_u64;

        for mutation in &self.mutations {
            match mutation {
                JournalMutation::Quarantine {
                    source_path,
                    backup_slot,
                } => {
                    if phase > 0 {
                        return Err("Quarantine mutations must precede all other mutations".into());
                    }
                    validate_mutation_path(source_path, preserved)?;
                    let key = path_key(source_path);
                    require_sorted_unique(&previous_quarantine, &key, "quarantine")?;
                    if quarantine_paths.overlaps(&key) {
                        return Err(format!("Quarantine paths overlap: {source_path}"));
                    }
                    if (*backup_slot as usize) >= MAX_MUTATIONS
                        || !backup_slots.insert(*backup_slot)
                    {
                        return Err("Backup slots must be unique and within launcher bounds".into());
                    }
                    quarantine_paths.insert(key.clone());
                    previous_quarantine = Some(key);
                }
                JournalMutation::EnsureDirectory { destination_path } => {
                    if phase > 1 {
                        return Err(
                            "Ensure-directory mutations must precede install-file mutations".into(),
                        );
                    }
                    phase = 1;
                    validate_mutation_path(destination_path, preserved)?;
                    let key = path_key(destination_path);
                    require_sorted_unique(&previous_directory, &key, "directory")?;
                    directory_paths.insert(key.clone());
                    previous_directory = Some(key);
                }
                JournalMutation::InstallFile {
                    destination_path,
                    staging_slot,
                    size,
                    sha256,
                    executable,
                } => {
                    phase = 2;
                    validate_mutation_path(destination_path, preserved)?;
                    let key = path_key(destination_path);
                    require_sorted_unique(&previous_install, &key, "install")?;
                    if install_paths.overlaps(&key) {
                        return Err(format!("Installed file paths overlap: {destination_path}"));
                    }
                    if quarantine_paths.has_descendant(&key) {
                        return Err(format!(
                            "Installed file path is an ancestor of a separately quarantined path: {destination_path}"
                        ));
                    }
                    let directory_prefix = format!("{key}/");
                    if directory_paths.contains(&key)
                        || directory_paths
                            .range(directory_prefix.clone()..)
                            .next()
                            .is_some_and(|directory| directory.starts_with(&directory_prefix))
                    {
                        return Err(format!(
                            "An installed file path collides with an ensured directory: {destination_path}"
                        ));
                    }
                    if (*staging_slot as usize) >= MAX_MUTATIONS
                        || !staging_slots.insert(*staging_slot)
                    {
                        return Err(
                            "Staging slots must be unique and within launcher bounds".into()
                        );
                    }
                    if *size > MAX_MANAGED_FILE_BYTES || !is_sha256(sha256) {
                        return Err(format!(
                            "Installed file has an invalid size or SHA-256: {destination_path}"
                        ));
                    }
                    let expected = desired.get(&key).ok_or_else(|| {
                        format!("Install mutation is not a desired file: {destination_path}")
                    })?;
                    if expected.installed_size != *size
                        || expected.installed_sha256 != *sha256
                        || expected.executable != *executable
                    {
                        return Err(format!(
                            "Install mutation does not match desired file: {destination_path}"
                        ));
                    }
                    total_file_bytes = total_file_bytes
                        .checked_add(*size)
                        .filter(|total| *total <= MAX_PLAN_FILE_BYTES)
                        .ok_or_else(|| {
                            "Reconcile plan's installed byte total exceeds its limit".to_string()
                        })?;
                    install_paths.insert(key.clone());
                    previous_install = Some(key);
                }
            }
        }
        Ok(total_file_bytes)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate(self.install_id, self.channel)?;
        serialize_bounded(self, MAX_PLAN_BYTES as usize, "reconcile plan")
    }
}

fn same_release_content(base: &ActiveInstanceV2, target: &ActiveInstanceV2) -> bool {
    base.release_id == target.release_id
        && base.release_manifest_sha256 == target.release_manifest_sha256
        && base.runtime_lock_sha256 == target.runtime_lock_sha256
        && base.game_runtime_lock_sha256 == target.game_runtime_lock_sha256
        && base
            .trusted_release
            .is_monotonic_to(&target.trusted_release)
}

/// Serialize and publish the immutable, content-addressed plan file. This does not publish the
/// mutable `pending.json` pointer and does not touch the instance tree.
pub fn write_immutable_plan(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
    plan: &ReconcilePlanV2,
) -> Result<JournalPointerV2, String> {
    operation_lock
        .validate_scope(install_root, expected_install_id, expected_channel)
        .map_err(|error| format!("Invalid reconcile operation lock: {error}"))?;
    plan.validate(expected_install_id, expected_channel)?;
    let bytes = serialize_bounded(plan, MAX_PLAN_BYTES as usize, "reconcile plan")?;
    let plan_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let pointer = JournalPointerV2 {
        schema_version: JOURNAL_SCHEMA_VERSION,
        install_id: plan.install_id,
        channel: plan.channel,
        operation_id: plan.operation_id,
        plan_sha256,
    };
    let paths = JournalPaths::new(expected_channel, &pointer)?;
    paths.prepare(install_root)?;
    publish_immutable_file(install_root, &paths.temporary, &paths.plan, &bytes, true)?;

    let persisted = read_bounded(install_root, &paths.plan, MAX_PLAN_BYTES, "reconcile plan")?;
    if persisted != bytes || format!("{:x}", Sha256::digest(&persisted)) != pointer.plan_sha256 {
        return Err("Persisted reconcile plan failed immutable verification".into());
    }
    Ok(pointer)
}

/// Atomically exposes a verified plan as this channel's pending operation.
pub fn publish_pending(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
    pointer: &JournalPointerV2,
) -> Result<(), String> {
    operation_lock
        .validate_scope(install_root, expected_install_id, expected_channel)
        .map_err(|error| format!("Invalid reconcile operation lock: {error}"))?;
    pointer.validate(expected_install_id, expected_channel)?;
    let paths = JournalPaths::new(expected_channel, pointer)?;
    paths.prepare(install_root)?;
    let plan = load_plan(
        install_root,
        &paths.plan,
        pointer,
        expected_install_id,
        expected_channel,
    )?;
    if plan.operation_id != pointer.operation_id {
        return Err("Reconcile plan does not match its journal pointer".into());
    }

    let bytes = serialize_bounded(pointer, MAX_POINTER_BYTES as usize, "journal pointer")?;
    match read_optional_bounded(
        install_root,
        &paths.pending,
        MAX_POINTER_BYTES,
        "journal slot",
    )? {
        None => publish_immutable_file(
            install_root,
            &paths.temporary,
            &paths.pending,
            &bytes,
            false,
        )?,
        Some(existing) => {
            match parse_journal_slot(&existing, expected_install_id, expected_channel)? {
                JournalSlotV2::Pending(existing_pointer)
                    if existing_pointer == *pointer && existing == bytes =>
                {
                    // Exact retry after a crash or an unobserved successful publication.
                }
                JournalSlotV2::Pending(_) => {
                    return Err(
                        "A pending reconcile journal already exists for this channel".into(),
                    )
                }
                JournalSlotV2::Cleared(tombstone) => {
                    validate_persisted_completion(
                        install_root,
                        expected_install_id,
                        expected_channel,
                        operation_lock,
                        &tombstone,
                        &existing,
                    )?;
                    if tombstone.completed_pointer.operation_id == pointer.operation_id {
                        return Err("A completed reconcile operation ID cannot be reused".into());
                    }
                    if plan.base != tombstone.continuation {
                        return Err(
                            "A new reconcile operation must continue from the exact completed state"
                                .into(),
                        );
                    }
                    atomic_write_small(
                        install_root,
                        paths.pending.clone(),
                        &bytes,
                        MAX_POINTER_BYTES as usize,
                    )
                    .map_err(|error| format!("Cannot publish pending journal pointer: {error}"))?;
                }
            }
        }
    }
    let persisted = read_bounded(
        install_root,
        &paths.pending,
        MAX_POINTER_BYTES,
        "journal pointer",
    )?;
    if persisted != bytes {
        return Err("Published reconcile journal pointer changed during verification".into());
    }
    Ok(())
}

/// Detect and fully validate a pending operation for exactly one installation and channel.
pub fn detect_pending(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
) -> Result<Option<PendingJournalV2>, String> {
    operation_lock
        .validate_scope(install_root, expected_install_id, expected_channel)
        .map_err(|error| format!("Invalid reconcile operation lock: {error}"))?;
    let pending = journal_pending_path(expected_channel)?;
    let bytes =
        match read_optional_bounded(install_root, &pending, MAX_POINTER_BYTES, "journal slot")? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
    match parse_journal_slot(&bytes, expected_install_id, expected_channel)? {
        JournalSlotV2::Cleared(tombstone) => {
            validate_persisted_completion(
                install_root,
                expected_install_id,
                expected_channel,
                operation_lock,
                &tombstone,
                &bytes,
            )?;
            Ok(None)
        }
        JournalSlotV2::Pending(pointer) => {
            let paths = JournalPaths::new(expected_channel, &pointer)?;
            let plan = load_plan(
                install_root,
                &paths.plan,
                &pointer,
                expected_install_id,
                expected_channel,
            )?;
            Ok(Some(PendingJournalV2 { pointer, plan }))
        }
    }
}

/// Completes an operation only after the caller has observed its exact committed target.
pub fn complete_pending_committed(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
    expected: &JournalPointerV2,
    authorization: FinalizeCommitAuthorizationV2,
) -> Result<bool, String> {
    let plan = load_authorized_plan(
        install_root,
        expected_install_id,
        expected_channel,
        operation_lock,
        expected,
    )?;
    authorization.validate_for(expected, &plan)?;
    complete_pending(
        install_root,
        expected_install_id,
        expected_channel,
        operation_lock,
        expected,
        JournalCompletionOutcomeV2::CommittedTarget,
    )
}

/// Completes a rollback only from the exact optional plan base. `None` is meaningful: it is the
/// continuation state after rolling back a first install which never had an active generation.
pub fn complete_pending_rolled_back(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
    expected: &JournalPointerV2,
    authorization: RollbackCompletionAuthorizationV2,
) -> Result<bool, String> {
    let plan = load_authorized_plan(
        install_root,
        expected_install_id,
        expected_channel,
        operation_lock,
        expected,
    )?;
    authorization.validate_for(expected, &plan)?;
    complete_pending(
        install_root,
        expected_install_id,
        expected_channel,
        operation_lock,
        expected,
        JournalCompletionOutcomeV2::RolledBackToBase,
    )
}

fn load_authorized_plan(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
    expected: &JournalPointerV2,
) -> Result<ReconcilePlanV2, String> {
    operation_lock
        .validate_scope(install_root, expected_install_id, expected_channel)
        .map_err(|error| format!("Invalid reconcile operation lock: {error}"))?;
    expected.validate(expected_install_id, expected_channel)?;
    let paths = JournalPaths::new(expected_channel, expected)?;
    load_plan(
        install_root,
        &paths.plan,
        expected,
        expected_install_id,
        expected_channel,
    )
}

/// Atomically replaces a failed committed operation with one exact repair operation. The
/// authorization is emitted only by the recovery planner after it observed the exact active
/// target and a failed final audit. Supersede history is durable before `pending.json` changes,
/// and `pending.json` is replaced directly with the repair pointer, so no idle/ready state is
/// observable between the two operations.
#[allow(clippy::too_many_arguments)]
pub fn supersede_pending_with_repair(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
    failed_pointer: &JournalPointerV2,
    authorization: RepairSupersedeAuthorizationV2,
    repair_plan: &ReconcilePlanV2,
) -> Result<JournalPointerV2, String> {
    operation_lock
        .validate_scope(install_root, expected_install_id, expected_channel)
        .map_err(|error| format!("Invalid reconcile operation lock: {error}"))?;
    failed_pointer.validate(expected_install_id, expected_channel)?;
    let failed_paths = JournalPaths::new(expected_channel, failed_pointer)?;
    let failed_plan = load_plan(
        install_root,
        &failed_paths.plan,
        failed_pointer,
        expected_install_id,
        expected_channel,
    )?;
    authorization.validate_for(failed_pointer, &failed_plan)?;
    let active = InstanceStateStore::new(install_root, expected_install_id)
        .load_locked(operation_lock)
        .map_err(|error| format!("Cannot verify active state for repair supersede: {error}"))?;
    if active.as_ref() != Some(&failed_plan.target) {
        return Err("Repair supersede target is not the exact active marker".into());
    }
    validate_superseding_repair(&failed_plan, repair_plan)?;

    let repair_pointer = write_immutable_plan(
        install_root,
        expected_install_id,
        expected_channel,
        operation_lock,
        repair_plan,
    )?;
    let failed_pointer_bytes = serialize_bounded(
        failed_pointer,
        MAX_POINTER_BYTES as usize,
        "failed journal pointer",
    )?;
    let completion = JournalTombstoneV2 {
        schema_version: JOURNAL_SCHEMA_VERSION,
        install_id: expected_install_id,
        channel: expected_channel,
        completed_pointer: failed_pointer.clone(),
        completed_pointer_sha256: format!("{:x}", Sha256::digest(&failed_pointer_bytes)),
        outcome: JournalCompletionOutcomeV2::SupersededForRepair,
        continuation: Some(failed_plan.target.clone()),
    };
    completion.validate(expected_install_id, expected_channel)?;
    validate_completion_binding(
        &failed_plan,
        completion.outcome,
        completion.continuation.as_ref(),
    )?;
    let completion_bytes = serialize_bounded(
        &completion,
        MAX_POINTER_BYTES as usize,
        "journal completion",
    )?;
    let repair_pointer_bytes = serialize_bounded(
        &repair_pointer,
        MAX_POINTER_BYTES as usize,
        "repair journal pointer",
    )?;
    let current = read_bounded(
        install_root,
        &failed_paths.pending,
        MAX_POINTER_BYTES,
        "journal slot",
    )?;
    match parse_journal_slot(&current, expected_install_id, expected_channel)? {
        JournalSlotV2::Pending(pointer)
            if pointer == *failed_pointer && current == failed_pointer_bytes => {}
        JournalSlotV2::Pending(pointer)
            if pointer == repair_pointer && current == repair_pointer_bytes =>
        {
            validate_completion_history(
                install_root,
                expected_install_id,
                expected_channel,
                &completion,
                &completion_bytes,
            )?;
            return Ok(repair_pointer);
        }
        _ => {
            return Err(
                "Pending journal is neither the failed operation nor its exact repair replacement"
                    .into(),
            )
        }
    }

    failed_paths.prepare(install_root)?;
    publish_immutable_file(
        install_root,
        &failed_paths.temporary,
        &failed_paths.completion,
        &completion_bytes,
        true,
    )?;
    validate_completion_history(
        install_root,
        expected_install_id,
        expected_channel,
        &completion,
        &completion_bytes,
    )?;
    atomic_write_small(
        install_root,
        failed_paths.pending.clone(),
        &repair_pointer_bytes,
        MAX_POINTER_BYTES as usize,
    )
    .map_err(|error| format!("Cannot atomically supersede journal with repair: {error}"))?;
    let persisted = read_bounded(
        install_root,
        &failed_paths.pending,
        MAX_POINTER_BYTES,
        "repair journal pointer",
    )?;
    if persisted != repair_pointer_bytes {
        return Err("Superseding repair pointer changed during verification".into());
    }
    Ok(repair_pointer)
}

fn validate_superseding_repair(
    failed: &ReconcilePlanV2,
    repair: &ReconcilePlanV2,
) -> Result<(), String> {
    repair.validate(failed.install_id, failed.channel)?;
    if repair.operation_id == failed.operation_id
        || repair.kind != OperationKind::Repair
        || repair.base.as_ref() != Some(&failed.target)
        || repair.strict_roots != failed.strict_roots
        || repair.preserved_paths != failed.preserved_paths
        || repair.desired_files != failed.desired_files
        || repair.mutations.is_empty()
    {
        return Err(
            "Superseding operation is not the exact bounded repair of the failed target".into(),
        );
    }
    Ok(())
}

/// Replaces only the exact pending pointer with an outcome-bound tombstone. The immutable
/// completion record is published first, so a crash can leave either the old pending pointer or a
/// tombstone backed by durable history, never a history-free continuation.
#[allow(clippy::too_many_arguments)]
fn complete_pending(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
    expected: &JournalPointerV2,
    outcome: JournalCompletionOutcomeV2,
) -> Result<bool, String> {
    operation_lock
        .validate_scope(install_root, expected_install_id, expected_channel)
        .map_err(|error| format!("Invalid reconcile operation lock: {error}"))?;
    expected.validate(expected_install_id, expected_channel)?;
    let paths = JournalPaths::new(expected_channel, expected)?;
    let cleared_plan = load_plan(
        install_root,
        &paths.plan,
        expected,
        expected_install_id,
        expected_channel,
    )?;
    if outcome == JournalCompletionOutcomeV2::SupersededForRepair {
        return Err("A repair supersede cannot be published as an idle tombstone".into());
    }
    let active = InstanceStateStore::new(install_root, expected_install_id)
        .load_locked(operation_lock)
        .map_err(|error| format!("Cannot verify active state for journal completion: {error}"))?;
    let continuation = match outcome {
        JournalCompletionOutcomeV2::CommittedTarget => {
            if active.as_ref() != Some(&cleared_plan.target) {
                return Err("Committed journal target is not the exact active marker".into());
            }
            active
        }
        JournalCompletionOutcomeV2::RolledBackToBase => {
            if active != cleared_plan.base {
                return Err("Rolled-back journal base is not the exact active marker".into());
            }
            active
        }
        JournalCompletionOutcomeV2::SupersededForRepair => unreachable!("rejected above"),
    };
    validate_completion_binding(&cleared_plan, outcome, continuation.as_ref())?;
    let pending = journal_pending_path(expected_channel)?;
    let expected_bytes =
        serialize_bounded(expected, MAX_POINTER_BYTES as usize, "journal pointer")?;
    let tombstone = JournalTombstoneV2 {
        schema_version: JOURNAL_SCHEMA_VERSION,
        install_id: expected_install_id,
        channel: expected_channel,
        completed_pointer: expected.clone(),
        completed_pointer_sha256: format!("{:x}", Sha256::digest(&expected_bytes)),
        outcome,
        continuation,
    };
    tombstone.validate(expected_install_id, expected_channel)?;
    let tombstone_bytes =
        serialize_bounded(&tombstone, MAX_POINTER_BYTES as usize, "journal tombstone")?;
    let current =
        match read_optional_bounded(install_root, &pending, MAX_POINTER_BYTES, "journal slot")? {
            Some(bytes) => bytes,
            None => return Ok(false),
        };
    match parse_journal_slot(&current, expected_install_id, expected_channel)? {
        JournalSlotV2::Cleared(existing) => {
            validate_persisted_completion(
                install_root,
                expected_install_id,
                expected_channel,
                operation_lock,
                &existing,
                &current,
            )?;
            if *existing != tombstone {
                return Err("Journal operation was completed with another outcome".into());
            }
            return Ok(false);
        }
        JournalSlotV2::Pending(pointer) if pointer == *expected && current == expected_bytes => {}
        JournalSlotV2::Pending(_) => {
            return Err("Pending journal pointer is not the exact pointer being cleared".into())
        }
    }

    paths.prepare(install_root)?;
    publish_immutable_file(
        install_root,
        &paths.temporary,
        &paths.completion,
        &tombstone_bytes,
        true,
    )?;
    let history = read_bounded(
        install_root,
        &paths.completion,
        MAX_POINTER_BYTES,
        "journal completion history",
    )?;
    if history != tombstone_bytes {
        return Err("Persisted journal completion history changed during verification".into());
    }
    atomic_write_small(
        install_root,
        pending.clone(),
        &tombstone_bytes,
        MAX_POINTER_BYTES as usize,
    )
    .map_err(|error| format!("Cannot atomically clear journal pointer: {error}"))?;
    let persisted = read_bounded(
        install_root,
        &pending,
        MAX_POINTER_BYTES,
        "journal tombstone",
    )?;
    if persisted != tombstone_bytes {
        return Err("Journal tombstone changed during verification".into());
    }
    validate_persisted_completion(
        install_root,
        expected_install_id,
        expected_channel,
        operation_lock,
        &tombstone,
        &persisted,
    )?;
    Ok(true)
}

fn validate_identity(
    install_id: Uuid,
    operation_id: Uuid,
    channel: BuildChannel,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
) -> Result<(), String> {
    if expected_install_id.is_nil()
        || install_id != expected_install_id
        || channel != expected_channel
    {
        return Err("Reconcile journal belongs to another installation or channel".into());
    }
    if operation_id.is_nil() || operation_id.get_version() != Some(Version::Random) {
        return Err("Reconcile operation ID must be a non-nil UUIDv4".into());
    }
    Ok(())
}

impl JournalTombstoneV2 {
    fn validate(
        &self,
        expected_install_id: Uuid,
        expected_channel: BuildChannel,
    ) -> Result<(), String> {
        if self.schema_version != JOURNAL_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported reconcile journal tombstone schema {}",
                self.schema_version
            ));
        }
        validate_identity(
            self.install_id,
            self.completed_pointer.operation_id,
            self.channel,
            expected_install_id,
            expected_channel,
        )?;
        self.completed_pointer
            .validate(expected_install_id, expected_channel)?;
        if self.completed_pointer.install_id != self.install_id
            || self.completed_pointer.channel != self.channel
        {
            return Err("Reconcile journal tombstone pointer scope is inconsistent".into());
        }
        let pointer_bytes = serialize_bounded(
            &self.completed_pointer,
            MAX_POINTER_BYTES as usize,
            "completed journal pointer",
        )?;
        if !is_sha256(&self.completed_pointer_sha256)
            || self.completed_pointer_sha256 != format!("{:x}", Sha256::digest(pointer_bytes))
        {
            return Err("Reconcile journal tombstone has an invalid pointer SHA-256".into());
        }
        if let Some(continuation) = &self.continuation {
            continuation
                .validate(expected_install_id, expected_channel)
                .map_err(|error| format!("Invalid completed reconcile continuation: {error}"))?;
        }
        if self.outcome != JournalCompletionOutcomeV2::RolledBackToBase
            && self.continuation.is_none()
        {
            return Err("Committed and superseded operations require a continuation target".into());
        }
        Ok(())
    }
}

fn validate_completion_binding(
    plan: &ReconcilePlanV2,
    outcome: JournalCompletionOutcomeV2,
    continuation: Option<&ActiveInstanceV2>,
) -> Result<(), String> {
    let expected = match outcome {
        JournalCompletionOutcomeV2::CommittedTarget
        | JournalCompletionOutcomeV2::SupersededForRepair => Some(&plan.target),
        JournalCompletionOutcomeV2::RolledBackToBase => plan.base.as_ref(),
    };
    if continuation != expected {
        return Err(match outcome {
            JournalCompletionOutcomeV2::CommittedTarget => {
                "Committed journal outcome does not match the exact plan target"
            }
            JournalCompletionOutcomeV2::RolledBackToBase => {
                "Rolled-back journal outcome does not match the exact optional plan base"
            }
            JournalCompletionOutcomeV2::SupersededForRepair => {
                "Superseded journal outcome does not match the exact active plan target"
            }
        }
        .into());
    }
    Ok(())
}

fn validate_persisted_completion(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
    tombstone: &JournalTombstoneV2,
    pending_bytes: &[u8],
) -> Result<ReconcilePlanV2, String> {
    if tombstone.outcome == JournalCompletionOutcomeV2::SupersededForRepair {
        return Err("A repair supersede completion cannot occupy the pending journal slot".into());
    }
    let plan = validate_completion_history(
        install_root,
        expected_install_id,
        expected_channel,
        tombstone,
        pending_bytes,
    )?;
    let active = InstanceStateStore::new(install_root, expected_install_id)
        .load_locked(operation_lock)
        .map_err(|error| format!("Cannot verify completed journal continuation: {error}"))?;
    if active != tombstone.continuation {
        return Err("Journal completion continuation is not the exact active marker".into());
    }
    Ok(plan)
}

fn validate_completion_history(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    tombstone: &JournalTombstoneV2,
    expected_bytes: &[u8],
) -> Result<ReconcilePlanV2, String> {
    tombstone.validate(expected_install_id, expected_channel)?;
    let canonical = serialize_bounded(tombstone, MAX_POINTER_BYTES as usize, "journal tombstone")?;
    if expected_bytes != canonical {
        return Err("Reconcile journal tombstone is not the exact canonical completion".into());
    }
    let paths = JournalPaths::new(expected_channel, &tombstone.completed_pointer)?;
    let plan = load_plan(
        install_root,
        &paths.plan,
        &tombstone.completed_pointer,
        expected_install_id,
        expected_channel,
    )?;
    validate_completion_binding(&plan, tombstone.outcome, tombstone.continuation.as_ref())?;
    let history = read_bounded(
        install_root,
        &paths.completion,
        MAX_POINTER_BYTES,
        "journal completion history",
    )?;
    if history != canonical {
        return Err("Journal tombstone has no exact immutable completion history".into());
    }
    Ok(plan)
}

fn parse_journal_slot(
    bytes: &[u8],
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
) -> Result<JournalSlotV2, String> {
    let slot: JournalSlotV2 = parse_without_duplicate_keys(bytes, "journal slot")?;
    let canonical = match &slot {
        JournalSlotV2::Pending(pointer) => {
            pointer.validate(expected_install_id, expected_channel)?;
            serialize_bounded(pointer, MAX_POINTER_BYTES as usize, "journal pointer")?
        }
        JournalSlotV2::Cleared(tombstone) => {
            tombstone.validate(expected_install_id, expected_channel)?;
            serialize_bounded(tombstone, MAX_POINTER_BYTES as usize, "journal tombstone")?
        }
    };
    if bytes != canonical {
        return Err("Reconcile journal slot is not in canonical form".into());
    }
    Ok(slot)
}

fn validate_relative_path(path: &str) -> Result<(), String> {
    validate_manifest_path(path)?;
    RelativeManagedPath::new(path)
        .map_err(|error| format!("Reconcile path cannot be materialized safely: {error}"))?;
    if path.len() > MAX_RELATIVE_PATH_BYTES || path.split('/').count() > MAX_RELATIVE_PATH_SEGMENTS
    {
        return Err(format!("Reconcile path exceeds launcher bounds: {path}"));
    }
    Ok(())
}

fn validate_mutation_path(path: &str, preserved_paths: &PathBoundaryIndex) -> Result<(), String> {
    validate_relative_path(path)?;
    if preserved_paths.overlaps(&path_key(path)) {
        return Err(format!("Mutation overlaps preserved data: {path}"));
    }
    Ok(())
}

fn require_sorted_unique(
    previous: &Option<String>,
    current: &str,
    mutation_kind: &str,
) -> Result<(), String> {
    if previous
        .as_ref()
        .is_some_and(|value| value.as_str() >= current)
    {
        return Err(format!(
            "{mutation_kind} paths must be unique and sorted by their case-folded path"
        ));
    }
    Ok(())
}

fn validate_canonical_paths(
    values: &[String],
    maximum: usize,
    label: &str,
) -> Result<PathBoundaryIndex, String> {
    if values.len() > maximum {
        return Err(format!("Reconcile plan has too many {label} paths"));
    }
    let mut previous: Option<String> = None;
    let mut paths = PathBoundaryIndex::default();
    for path in values {
        validate_relative_path(path)?;
        let key = path_key(path);
        if previous.as_ref().is_some_and(|value| value >= &key) {
            return Err(format!(
                "{label} paths must be unique and sorted by their case-folded path"
            ));
        }
        if paths.overlaps(&key) {
            return Err(format!("{label} paths overlap: {path}"));
        }
        paths.insert(key.clone());
        previous = Some(key);
    }
    Ok(paths)
}

fn path_key(path: &str) -> String {
    path.to_lowercase()
}

#[derive(Default)]
struct PathBoundaryIndex {
    exact: HashSet<String>,
    ordered: BTreeSet<String>,
}

impl PathBoundaryIndex {
    fn insert(&mut self, path: String) {
        self.exact.insert(path.clone());
        self.ordered.insert(path);
    }

    fn overlaps(&self, path: &str) -> bool {
        if self.exact.contains(path)
            || path
                .match_indices('/')
                .any(|(separator, _)| self.exact.contains(&path[..separator]))
        {
            return true;
        }
        self.has_descendant(path)
    }

    fn has_descendant(&self, path: &str) -> bool {
        let descendant_prefix = format!("{path}/");
        self.ordered
            .range(descendant_prefix.clone()..)
            .next()
            .is_some_and(|candidate| candidate.starts_with(&descendant_prefix))
    }
}

fn load_plan(
    install_root: &Path,
    path: &RelativeManagedPath,
    pointer: &JournalPointerV2,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
) -> Result<ReconcilePlanV2, String> {
    let bytes = read_bounded(install_root, path, MAX_PLAN_BYTES, "reconcile plan")?;
    if format!("{:x}", Sha256::digest(&bytes)) != pointer.plan_sha256 {
        return Err("Reconcile plan SHA-256 does not match its journal pointer".into());
    }
    let plan: ReconcilePlanV2 = parse_without_duplicate_keys(&bytes, "reconcile plan")?;
    plan.validate(expected_install_id, expected_channel)?;
    if plan.operation_id != pointer.operation_id
        || plan.install_id != pointer.install_id
        || plan.channel != pointer.channel
    {
        return Err("Reconcile plan identity does not match its journal pointer".into());
    }
    if bytes != serialize_bounded(&plan, MAX_PLAN_BYTES as usize, "reconcile plan")? {
        return Err("Reconcile plan is not in canonical form".into());
    }
    Ok(plan)
}

fn serialize_bounded<T: Serialize>(
    value: &T,
    maximum: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| format!("Cannot serialize {label}: {error}"))?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(format!("Serialized {label} exceeds its launcher limit"));
    }
    Ok(bytes)
}

fn parse_without_duplicate_keys<T: DeserializeOwned>(
    bytes: &[u8],
    label: &str,
) -> Result<T, String> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(format!("{label} JSON must not contain a UTF-8 BOM"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer)
        .map_err(|error| format!("Invalid {label} JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("Trailing {label} JSON data: {error}"))?;
    Ok(value)
}

fn read_optional_bounded(
    install_root: &Path,
    path: &RelativeManagedPath,
    maximum: u64,
    label: &str,
) -> Result<Option<Vec<u8>>, String> {
    match ImmutableManagedFile::open(install_root, path) {
        Ok(mut file) => {
            let bytes = file
                .read_bounded(maximum)
                .map_err(|error| format!("Cannot read {label}: {error}"))?;
            if bytes.is_empty() {
                return Err(format!("{label} is empty"));
            }
            Ok(Some(bytes))
        }
        Err(ManagedFsError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        }
        Err(error) => Err(format!("Cannot open {label}: {error}")),
    }
}

fn read_bounded(
    install_root: &Path,
    path: &RelativeManagedPath,
    maximum: u64,
    label: &str,
) -> Result<Vec<u8>, String> {
    read_optional_bounded(install_root, path, maximum, label)?
        .ok_or_else(|| format!("{label} is missing"))
}

fn publish_immutable_file(
    install_root: &Path,
    temporary_directory: &RelativeManagedPath,
    destination: &RelativeManagedPath,
    bytes: &[u8],
    allow_identical: bool,
) -> Result<(), String> {
    if let Some(existing) = read_optional_bounded(
        install_root,
        destination,
        bytes.len() as u64,
        "existing journal file",
    )? {
        return if allow_identical && existing == bytes {
            Ok(())
        } else {
            Err("Journal destination already exists with non-reusable contents".into())
        };
    }

    let temporary = temporary_directory
        .join_component(&format!("journal-{}.tmp", Uuid::new_v4()))
        .map_err(|error| format!("Cannot allocate journal temporary path: {error}"))?;
    let mut exclusive = ExclusiveManagedFile::create(install_root, temporary.clone())
        .map_err(|error| format!("Cannot create journal temporary file: {error}"))?;
    exclusive
        .file_mut()
        .write_all(bytes)
        .map_err(|error| format!("Cannot write journal temporary file: {error}"))?;
    let synced = exclusive
        .sync()
        .map_err(|error| format!("Cannot flush journal temporary file: {error}"))?;
    match synced.rename_no_replace(destination.clone()) {
        Ok(_) => {}
        Err(ManagedFsError::Conflict(_)) if allow_identical => {
            let existing = read_bounded(
                install_root,
                destination,
                bytes.len() as u64,
                "concurrently published journal file",
            )?;
            if existing != bytes {
                return Err("Concurrent immutable journal publication differs".into());
            }
        }
        Err(ManagedFsError::Conflict(_)) => {
            return Err("A pending reconcile journal already exists for this channel".into())
        }
        Err(error) => return Err(format!("Cannot commit journal file: {error}")),
    }

    let persisted = read_bounded(
        install_root,
        destination,
        bytes.len() as u64,
        "published journal file",
    )?;
    if persisted != bytes {
        return Err("Published journal file changed during verification".into());
    }
    Ok(())
}

fn journal_pending_path(channel: BuildChannel) -> Result<RelativeManagedPath, String> {
    RelativeManagedPath::new(&format!("state/journals/{}/pending.json", channel.as_str()))
        .map_err(|error| format!("Cannot derive journal pointer path: {error}"))
}

struct JournalPaths {
    channel_root: RelativeManagedPath,
    plans: RelativeManagedPath,
    completions: RelativeManagedPath,
    temporary: RelativeManagedPath,
    plan: RelativeManagedPath,
    completion: RelativeManagedPath,
    pending: RelativeManagedPath,
}

impl JournalPaths {
    fn new(channel: BuildChannel, pointer: &JournalPointerV2) -> Result<Self, String> {
        let channel_root =
            RelativeManagedPath::new(&format!("state/journals/{}", channel.as_str()))
                .map_err(|error| format!("Cannot derive journal directory: {error}"))?;
        let plans = channel_root
            .join_component("plans")
            .map_err(|error| format!("Cannot derive journal plans directory: {error}"))?;
        let completions = channel_root
            .join_component("completions")
            .map_err(|error| format!("Cannot derive journal completions directory: {error}"))?;
        let temporary = channel_root
            .join_component("temporary")
            .map_err(|error| format!("Cannot derive journal temporary directory: {error}"))?;
        let plan = plans
            .join_component(&format!(
                "{}-{}.json",
                pointer.operation_id, pointer.plan_sha256
            ))
            .map_err(|error| format!("Cannot derive immutable journal plan path: {error}"))?;
        let completion = completions
            .join_component(&format!(
                "{}-{}.json",
                pointer.operation_id, pointer.plan_sha256
            ))
            .map_err(|error| format!("Cannot derive immutable journal completion path: {error}"))?;
        let pending = channel_root
            .join_component("pending.json")
            .map_err(|error| format!("Cannot derive pending journal path: {error}"))?;
        Ok(Self {
            channel_root,
            plans,
            completions,
            temporary,
            plan,
            completion,
            pending,
        })
    }

    fn prepare(&self, install_root: &Path) -> Result<(), String> {
        for directory in [
            &self.channel_root,
            &self.plans,
            &self.completions,
            &self.temporary,
        ] {
            ensure_directory_chain(install_root, directory)
                .map_err(|error| format!("Cannot prepare reconcile journal directory: {error}"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_manager::{instance_state::InstanceStateStore, types::PresetId};
    use serde_json::Value;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const HASH_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fragment-journal-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn active(
        install_id: Uuid,
        channel: BuildChannel,
        generation: u64,
        release_suffix: char,
        preset: PresetId,
    ) -> ActiveInstanceV2 {
        let release_id = format!("rel_{}", release_suffix.to_string().repeat(24));
        ActiveInstanceV2::new(
            install_id,
            channel,
            generation,
            release_id.clone(),
            preset,
            HASH_A.into(),
            HASH_C.into(),
            HASH_D.into(),
            crate::build_manager::tuf::TrustedReleaseEvidence {
                schema_version: 1,
                channel,
                roles: crate::build_manager::tuf::TrustedRoleVersions {
                    root: 1,
                    timestamp: 1,
                    snapshot: 1,
                    targets: 1,
                },
                current: crate::build_manager::tuf::TrustedTargetEvidence {
                    name: "current.json".into(),
                    length: 1,
                    sha256: HASH_B.into(),
                },
                release_manifest: crate::build_manager::tuf::TrustedTargetEvidence {
                    name: format!("release-{release_id}.json"),
                    length: 1,
                    sha256: HASH_A.into(),
                },
                java_runtime_lock: crate::build_manager::tuf::TrustedTargetEvidence {
                    name: format!("runtime-windows-x64-{HASH_C}.json"),
                    length: 1,
                    sha256: HASH_C.into(),
                },
                game_runtime_lock: crate::build_manager::tuf::TrustedTargetEvidence {
                    name: format!("game-runtime-windows-x64-{HASH_D}.json"),
                    length: 1,
                    sha256: HASH_D.into(),
                },
            },
        )
        .expect("fixture state")
    }

    fn install_plan(install_id: Uuid, channel: BuildChannel) -> ReconcilePlanV2 {
        ReconcilePlanV2 {
            schema_version: 2,
            install_id,
            operation_id: Uuid::new_v4(),
            channel,
            kind: OperationKind::Install,
            base: None,
            target: active(install_id, channel, 1, 'a', PresetId::Medium),
            strict_roots: vec!["mods".into()],
            preserved_paths: vec!["logs".into(), "saves".into()],
            desired_files: vec![PlannedFileV2 {
                path: "mods/fragment.jar".into(),
                signed_size: 7,
                signed_sha256: HASH_B.into(),
                installed_size: 7,
                installed_sha256: HASH_B.into(),
                executable: false,
                policy: FilePolicy::Exact,
            }],
            disk_budget: DiskBudgetV2::new(0, 0, 0, 7).unwrap(),
            mutations: vec![
                JournalMutation::Quarantine {
                    source_path: "mods/old.jar".into(),
                    backup_slot: 0,
                },
                JournalMutation::EnsureDirectory {
                    destination_path: "mods".into(),
                },
                JournalMutation::InstallFile {
                    destination_path: "mods/fragment.jar".into(),
                    staging_slot: 0,
                    size: 7,
                    sha256: HASH_B.into(),
                    executable: false,
                },
            ],
        }
    }

    fn repair_after(plan: &ReconcilePlanV2) -> ReconcilePlanV2 {
        let mut target = plan.target.clone();
        target.generation = target
            .generation
            .checked_add(1)
            .expect("fixture generation");
        ReconcilePlanV2 {
            schema_version: 2,
            install_id: plan.install_id,
            operation_id: Uuid::new_v4(),
            channel: plan.channel,
            kind: OperationKind::Repair,
            base: Some(plan.target.clone()),
            target,
            strict_roots: plan.strict_roots.clone(),
            preserved_paths: plan.preserved_paths.clone(),
            desired_files: plan.desired_files.clone(),
            disk_budget: plan.disk_budget.clone(),
            mutations: plan.mutations.clone(),
        }
    }

    #[test]
    fn rejects_path_escapes_and_preserved_overlap() {
        let install_id = Uuid::new_v4();
        for path in ["../escape", "mods\\evil.jar", "C:/evil.jar", "/absolute"] {
            let mut plan = install_plan(install_id, BuildChannel::Stable);
            plan.mutations[0] = JournalMutation::Quarantine {
                source_path: path.into(),
                backup_slot: 0,
            };
            assert!(plan.validate(install_id, BuildChannel::Stable).is_err());
        }
        let mut oversized_component = install_plan(install_id, BuildChannel::Stable);
        oversized_component.mutations[0] = JournalMutation::Quarantine {
            source_path: format!("mods/{}", "a".repeat(256)),
            backup_slot: 0,
        };
        assert!(oversized_component
            .validate(install_id, BuildChannel::Stable)
            .is_err());

        let mut overlap = install_plan(install_id, BuildChannel::Stable);
        overlap.preserved_paths = vec!["mods/custom".into()];
        overlap.mutations[2] = JournalMutation::InstallFile {
            destination_path: "mods/custom/cheat.jar".into(),
            staging_slot: 0,
            size: 1,
            sha256: HASH_B.into(),
            executable: false,
        };
        assert!(overlap.validate(install_id, BuildChannel::Stable).is_err());

        let mut overlapping_preserved = install_plan(install_id, BuildChannel::Stable);
        overlapping_preserved.preserved_paths = vec!["a".into(), "a-b".into(), "a/c".into()];
        assert!(overlapping_preserved
            .validate(install_id, BuildChannel::Stable)
            .is_err());
    }

    #[test]
    fn rejects_wrong_install_channel_generation_kind_and_slots() {
        let install_id = Uuid::new_v4();
        let other_install = Uuid::new_v4();
        let plan = install_plan(install_id, BuildChannel::Stable);
        assert!(plan.validate(other_install, BuildChannel::Stable).is_err());
        assert!(plan.validate(install_id, BuildChannel::Dev).is_err());

        let mut mismatched_target = plan.clone();
        mismatched_target.target.install_id = other_install;
        assert!(mismatched_target
            .validate(install_id, BuildChannel::Stable)
            .is_err());

        let mut bad_generation = plan.clone();
        bad_generation.target.generation = 2;
        assert!(bad_generation
            .validate(install_id, BuildChannel::Stable)
            .is_err());

        let mut bad_slot = plan.clone();
        bad_slot.mutations.push(JournalMutation::InstallFile {
            destination_path: "mods/z.jar".into(),
            staging_slot: 0,
            size: 1,
            sha256: HASH_B.into(),
            executable: false,
        });
        assert!(bad_slot.validate(install_id, BuildChannel::Stable).is_err());

        let base = active(install_id, BuildChannel::Stable, 1, 'a', PresetId::Low);
        let mut preset_change = ReconcilePlanV2 {
            kind: OperationKind::PresetChange,
            base: Some(base),
            target: active(install_id, BuildChannel::Stable, 2, 'a', PresetId::High),
            disk_budget: DiskBudgetV2::new(0, 0, 0, 0).unwrap(),
            mutations: Vec::new(),
            ..plan
        };
        assert!(preset_change
            .validate(install_id, BuildChannel::Stable)
            .is_ok());
        preset_change.target.release_id = format!("rel_{}", "c".repeat(24));
        assert!(preset_change
            .validate(install_id, BuildChannel::Stable)
            .is_err());

        let base = active(install_id, BuildChannel::Stable, 1, 'a', PresetId::Low);
        let mut update_with_preset_change = ReconcilePlanV2 {
            kind: OperationKind::Update,
            base: Some(base),
            target: active(install_id, BuildChannel::Stable, 2, 'b', PresetId::High),
            disk_budget: DiskBudgetV2::new(0, 0, 0, 0).unwrap(),
            mutations: Vec::new(),
            ..install_plan(install_id, BuildChannel::Stable)
        };
        assert!(update_with_preset_change
            .validate(install_id, BuildChannel::Stable)
            .is_ok());
        update_with_preset_change.target.release_id = update_with_preset_change
            .base
            .as_ref()
            .unwrap()
            .release_id
            .clone();
        assert!(update_with_preset_change
            .validate(install_id, BuildChannel::Stable)
            .is_err());
    }

    #[test]
    fn rejects_corrupt_future_duplicate_and_noncanonical_json() {
        let install_id = Uuid::new_v4();
        let root = temp_root("bad-json");
        fs::create_dir_all(&root).unwrap();
        let state = InstanceStateStore::new(&root, install_id);
        let lock = state
            .acquire_operation_lock(BuildChannel::Stable)
            .expect("stable operation lock");
        let plan = install_plan(install_id, BuildChannel::Stable);
        let pointer = write_immutable_plan(&root, install_id, BuildChannel::Stable, &lock, &plan)
            .expect("write plan");
        let pending = journal_pending_path(BuildChannel::Stable)
            .unwrap()
            .join_to(&root);

        for raw in [
            b"{".as_slice(),
            br#"{"schemaVersion":2}"#,
            br#"{"schemaVersion":2,"schemaVersion":2}"#,
            br#"{"future":true}"#,
        ] {
            fs::write(&pending, raw).unwrap();
            assert!(detect_pending(&root, install_id, BuildChannel::Stable, &lock).is_err());
        }

        let mut value = serde_json::to_value(&pointer).unwrap();
        value["futureField"] = Value::Bool(true);
        fs::write(&pending, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(detect_pending(&root, install_id, BuildChannel::Stable, &lock).is_err());

        fs::write(&pending, serde_json::to_vec_pretty(&pointer).unwrap()).unwrap();
        assert!(detect_pending(&root, install_id, BuildChannel::Stable, &lock).is_err());

        let raw_plan = serde_json::to_string(&plan).unwrap();
        let duplicate_nested = raw_plan.replacen(
            "\"schemaVersion\":2",
            "\"schemaVersion\":2,\"schemaVersion\":2",
            1,
        );
        assert!(parse_without_duplicate_keys::<ReconcilePlanV2>(
            duplicate_nested.as_bytes(),
            "reconcile plan"
        )
        .is_err());

        let mut future_plan = serde_json::to_value(&plan).unwrap();
        future_plan["futureField"] = Value::Bool(true);
        assert!(parse_without_duplicate_keys::<ReconcilePlanV2>(
            &serde_json::to_vec(&future_plan).unwrap(),
            "reconcile plan"
        )
        .is_err());

        let mut future_mutation = serde_json::to_value(&plan).unwrap();
        future_mutation["mutations"][0]["futureField"] = Value::Bool(true);
        assert!(parse_without_duplicate_keys::<ReconcilePlanV2>(
            &serde_json::to_vec(&future_mutation).unwrap(),
            "reconcile plan"
        )
        .is_err());
        drop(lock);
        drop(state);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn immutable_plan_pointer_recovery_and_exact_clear_are_channel_isolated() {
        let root = temp_root("lifecycle");
        let install_id = Uuid::new_v4();
        fs::create_dir_all(&root).unwrap();
        let state = InstanceStateStore::new(&root, install_id);
        let stable_lock = state
            .acquire_operation_lock(BuildChannel::Stable)
            .expect("stable operation lock");
        let dev_lock = state
            .acquire_operation_lock(BuildChannel::Dev)
            .expect("dev operation lock");
        let stable_plan = install_plan(install_id, BuildChannel::Stable);
        assert!(write_immutable_plan(
            &root,
            install_id,
            BuildChannel::Stable,
            &dev_lock,
            &stable_plan,
        )
        .is_err());
        let stable_pointer = write_immutable_plan(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &stable_plan,
        )
        .expect("write stable plan");
        let duplicate = write_immutable_plan(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &stable_plan,
        )
        .expect("same immutable plan is idempotent");
        assert_eq!(stable_pointer, duplicate);
        publish_pending(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &stable_pointer,
        )
        .expect("publish stable pointer");
        publish_pending(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &stable_pointer,
        )
        .expect("exact pending publication retry is idempotent");

        assert!(
            detect_pending(&root, install_id, BuildChannel::Dev, &dev_lock)
                .expect("dev detection")
                .is_none()
        );
        assert!(detect_pending(&root, install_id, BuildChannel::Stable, &dev_lock).is_err());

        let other_root = temp_root("foreign-lock");
        fs::create_dir_all(&other_root).unwrap();
        let other_state = InstanceStateStore::new(&other_root, install_id);
        let other_lock = other_state
            .acquire_operation_lock(BuildChannel::Stable)
            .expect("foreign-root operation lock");
        assert!(detect_pending(&root, install_id, BuildChannel::Stable, &other_lock).is_err());
        drop(other_lock);
        drop(other_state);
        let _ = fs::remove_dir_all(other_root);

        let recovered = detect_pending(&root, install_id, BuildChannel::Stable, &stable_lock)
            .expect("stable detection")
            .expect("stable pending");
        assert_eq!(recovered.pointer, stable_pointer);
        assert_eq!(recovered.plan, stable_plan);

        let mut wrong = stable_pointer.clone();
        wrong.operation_id = Uuid::new_v4();
        assert!(complete_pending_committed(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &wrong,
            FinalizeCommitAuthorizationV2::for_exact_final_audit_test(&stable_plan),
        )
        .is_err());
        assert!(
            detect_pending(&root, install_id, BuildChannel::Stable, &stable_lock)
                .expect("pointer restored")
                .is_some()
        );
        assert!(complete_pending_committed(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &stable_pointer,
            FinalizeCommitAuthorizationV2::for_exact_final_audit_test(&stable_plan),
        )
        .is_err());

        state
            .save_locked(&stable_lock, &stable_plan.target)
            .expect("commit exact stable target marker");
        assert!(complete_pending_committed(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &stable_pointer,
            FinalizeCommitAuthorizationV2::for_exact_final_audit_test(&stable_plan),
        )
        .expect("clear stable pointer"));
        assert!(
            detect_pending(&root, install_id, BuildChannel::Stable, &stable_lock)
                .expect("stable detection after clear")
                .is_none()
        );
        assert!(!complete_pending_committed(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &stable_pointer,
            FinalizeCommitAuthorizationV2::for_exact_final_audit_test(&stable_plan),
        )
        .expect("idempotent clear"));
        assert!(publish_pending(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &stable_pointer,
        )
        .is_err());

        let mut reused_id_target = stable_plan.target.clone();
        reused_id_target.generation = 2;
        let reused_id_plan = ReconcilePlanV2 {
            schema_version: 2,
            install_id,
            operation_id: stable_pointer.operation_id,
            channel: BuildChannel::Stable,
            kind: OperationKind::Repair,
            base: Some(stable_plan.target.clone()),
            target: reused_id_target,
            strict_roots: stable_plan.strict_roots.clone(),
            preserved_paths: stable_plan.preserved_paths.clone(),
            desired_files: stable_plan.desired_files.clone(),
            disk_budget: DiskBudgetV2::new(0, 0, 0, 0).unwrap(),
            mutations: Vec::new(),
        };
        let reused_id_pointer = write_immutable_plan(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &reused_id_plan,
        )
        .expect("write changed plan that reuses a cleared operation ID");
        assert!(publish_pending(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &reused_id_pointer,
        )
        .is_err());

        let mut stale_plan = stable_plan.clone();
        stale_plan.operation_id = Uuid::new_v4();
        let stale_pointer = write_immutable_plan(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &stale_plan,
        )
        .expect("write a structurally valid but stale install plan");
        assert!(publish_pending(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &stale_pointer,
        )
        .is_err());

        let mut next_target = stable_plan.target.clone();
        next_target.generation = 2;
        let next_plan = ReconcilePlanV2 {
            schema_version: 2,
            install_id,
            operation_id: Uuid::new_v4(),
            channel: BuildChannel::Stable,
            kind: OperationKind::Repair,
            base: Some(stable_plan.target.clone()),
            target: next_target,
            strict_roots: stable_plan.strict_roots.clone(),
            preserved_paths: stable_plan.preserved_paths.clone(),
            desired_files: stable_plan.desired_files.clone(),
            disk_budget: DiskBudgetV2::new(0, 0, 0, 0).unwrap(),
            mutations: Vec::new(),
        };
        let next_pointer = write_immutable_plan(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &next_plan,
        )
        .expect("write next reconcile plan");
        publish_pending(
            &root,
            install_id,
            BuildChannel::Stable,
            &stable_lock,
            &next_pointer,
        )
        .expect("a genuinely new next-generation operation is allowed");
        let next_pending = detect_pending(&root, install_id, BuildChannel::Stable, &stable_lock)
            .expect("detect next operation")
            .expect("next operation must be pending");
        assert_eq!(next_pending.plan, next_plan);
        drop(dev_lock);
        drop(stable_lock);
        drop(state);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rolled_back_completion_continues_from_exact_optional_base() {
        let root = temp_root("rollback-continuations");
        let install_id = Uuid::new_v4();
        fs::create_dir_all(&root).unwrap();
        let state = InstanceStateStore::new(&root, install_id);
        let lock = state.acquire_operation_lock(BuildChannel::Stable).unwrap();

        let first_install = install_plan(install_id, BuildChannel::Stable);
        let first_pointer = write_immutable_plan(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &first_install,
        )
        .unwrap();
        publish_pending(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &first_pointer,
        )
        .unwrap();
        let mut foreign_rollback = first_install.clone();
        foreign_rollback.operation_id = Uuid::new_v4();
        assert!(complete_pending_rolled_back(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &first_pointer,
            RollbackCompletionAuthorizationV2::for_completed_plan_test(&foreign_rollback),
        )
        .is_err());
        assert!(complete_pending_rolled_back(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &first_pointer,
            RollbackCompletionAuthorizationV2::for_completed_plan_test(&first_install),
        )
        .unwrap());
        assert!(
            detect_pending(&root, install_id, BuildChannel::Stable, &lock)
                .unwrap()
                .is_none()
        );

        let wrong_after_none = repair_after(&first_install);
        let wrong_pointer = write_immutable_plan(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &wrong_after_none,
        )
        .unwrap();
        assert!(publish_pending(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &wrong_pointer,
        )
        .is_err());

        let mut retried_install = first_install.clone();
        retried_install.operation_id = Uuid::new_v4();
        let retry_pointer = write_immutable_plan(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &retried_install,
        )
        .unwrap();
        publish_pending(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &retry_pointer,
        )
        .unwrap();

        state.save_locked(&lock, &retried_install.target).unwrap();
        let repair = repair_after(&retried_install);
        let repair_pointer =
            write_immutable_plan(&root, install_id, BuildChannel::Stable, &lock, &repair).unwrap();
        // The retried install is still pending; complete it before publishing the repair.
        complete_pending_committed(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &retry_pointer,
            FinalizeCommitAuthorizationV2::for_exact_final_audit_test(&retried_install),
        )
        .unwrap();
        publish_pending(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &repair_pointer,
        )
        .unwrap();
        assert!(complete_pending_rolled_back(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &repair_pointer,
            RollbackCompletionAuthorizationV2::for_completed_plan_test(&repair),
        )
        .unwrap());

        let mut exact_base_retry = repair.clone();
        exact_base_retry.operation_id = Uuid::new_v4();
        let exact_pointer = write_immutable_plan(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &exact_base_retry,
        )
        .unwrap();
        publish_pending(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &exact_pointer,
        )
        .unwrap();

        drop(lock);
        drop(state);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn failed_commit_is_atomically_replaced_by_exact_repair_and_retry_is_idempotent() {
        let root = temp_root("supersede-repair");
        let install_id = Uuid::new_v4();
        fs::create_dir_all(&root).unwrap();
        let state = InstanceStateStore::new(&root, install_id);
        let lock = state.acquire_operation_lock(BuildChannel::Stable).unwrap();
        let failed = install_plan(install_id, BuildChannel::Stable);
        let failed_pointer =
            write_immutable_plan(&root, install_id, BuildChannel::Stable, &lock, &failed).unwrap();
        publish_pending(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &failed_pointer,
        )
        .unwrap();
        let repair = repair_after(&failed);

        assert!(supersede_pending_with_repair(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &failed_pointer,
            RepairSupersedeAuthorizationV2::for_failed_final_audit_test(&failed),
            &repair,
        )
        .is_err());
        state.save_locked(&lock, &failed.target).unwrap();

        let mut altered = repair_after(&failed);
        altered.strict_roots = vec!["config".into()];
        assert!(supersede_pending_with_repair(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &failed_pointer,
            RepairSupersedeAuthorizationV2::for_failed_final_audit_test(&failed),
            &altered,
        )
        .is_err());

        // Crash boundary: immutable supersede history may be durable while the old pointer is
        // still pending. Retrying must reuse that exact history and perform the direct swap.
        let failed_paths = JournalPaths::new(BuildChannel::Stable, &failed_pointer).unwrap();
        let failed_pointer_bytes = serialize_bounded(
            &failed_pointer,
            MAX_POINTER_BYTES as usize,
            "failed pointer",
        )
        .unwrap();
        let prewritten = JournalTombstoneV2 {
            schema_version: JOURNAL_SCHEMA_VERSION,
            install_id,
            channel: BuildChannel::Stable,
            completed_pointer: failed_pointer.clone(),
            completed_pointer_sha256: format!("{:x}", Sha256::digest(&failed_pointer_bytes)),
            outcome: JournalCompletionOutcomeV2::SupersededForRepair,
            continuation: Some(failed.target.clone()),
        };
        let prewritten_bytes = serialize_bounded(
            &prewritten,
            MAX_POINTER_BYTES as usize,
            "prewritten completion",
        )
        .unwrap();
        publish_immutable_file(
            &root,
            &failed_paths.temporary,
            &failed_paths.completion,
            &prewritten_bytes,
            true,
        )
        .unwrap();
        assert_eq!(
            fs::read(failed_paths.pending.join_to(&root)).unwrap(),
            failed_pointer_bytes
        );

        let repair_pointer = supersede_pending_with_repair(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &failed_pointer,
            RepairSupersedeAuthorizationV2::for_failed_final_audit_test(&failed),
            &repair,
        )
        .unwrap();
        let detected = detect_pending(&root, install_id, BuildChannel::Stable, &lock)
            .unwrap()
            .expect("supersede must never expose an idle journal");
        assert_eq!(detected.pointer, repair_pointer);
        assert_eq!(detected.plan, repair);

        assert_eq!(
            supersede_pending_with_repair(
                &root,
                install_id,
                BuildChannel::Stable,
                &lock,
                &failed_pointer,
                RepairSupersedeAuthorizationV2::for_failed_final_audit_test(&failed),
                &repair,
            )
            .unwrap(),
            repair_pointer
        );

        let mut third = repair_after(&failed);
        third.operation_id = Uuid::new_v4();
        assert!(supersede_pending_with_repair(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &failed_pointer,
            RepairSupersedeAuthorizationV2::for_failed_final_audit_test(&failed),
            &third,
        )
        .is_err());

        drop(lock);
        drop(state);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn forged_completion_outcome_cannot_override_the_active_marker() {
        let root = temp_root("forged-outcome");
        let install_id = Uuid::new_v4();
        fs::create_dir_all(&root).unwrap();
        let state = InstanceStateStore::new(&root, install_id);
        let lock = state.acquire_operation_lock(BuildChannel::Stable).unwrap();
        let plan = install_plan(install_id, BuildChannel::Stable);
        let pointer =
            write_immutable_plan(&root, install_id, BuildChannel::Stable, &lock, &plan).unwrap();
        publish_pending(&root, install_id, BuildChannel::Stable, &lock, &pointer).unwrap();
        state.save_locked(&lock, &plan.target).unwrap();
        complete_pending_committed(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &pointer,
            FinalizeCommitAuthorizationV2::for_exact_final_audit_test(&plan),
        )
        .unwrap();

        let paths = JournalPaths::new(BuildChannel::Stable, &pointer).unwrap();
        let mut forged: JournalTombstoneV2 =
            serde_json::from_slice(&fs::read(paths.pending.join_to(&root)).unwrap()).unwrap();
        forged.outcome = JournalCompletionOutcomeV2::RolledBackToBase;
        forged.continuation = None;
        let forged_bytes =
            serialize_bounded(&forged, MAX_POINTER_BYTES as usize, "forged completion").unwrap();
        fs::write(paths.pending.join_to(&root), &forged_bytes).unwrap();
        fs::write(paths.completion.join_to(&root), &forged_bytes).unwrap();
        assert!(detect_pending(&root, install_id, BuildChannel::Stable, &lock).is_err());

        drop(lock);
        drop(state);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replacement_path_is_allowed_but_sequences_and_duplicates_are_rejected() {
        let install_id = Uuid::new_v4();
        let mut replacement = install_plan(install_id, BuildChannel::Stable);
        replacement.mutations[0] = JournalMutation::Quarantine {
            source_path: "mods/fragment.jar".into(),
            backup_slot: 0,
        };
        assert!(replacement
            .validate(install_id, BuildChannel::Stable)
            .is_ok());

        let mut bad_order = replacement.clone();
        bad_order.mutations.swap(0, 2);
        assert!(bad_order
            .validate(install_id, BuildChannel::Stable)
            .is_err());

        let mut duplicate = replacement.clone();
        duplicate.mutations.insert(
            1,
            JournalMutation::Quarantine {
                source_path: "mods/fragment.jar".into(),
                backup_slot: 1,
            },
        );
        assert!(duplicate
            .validate(install_id, BuildChannel::Stable)
            .is_err());

        let mut impossible_parent_install = replacement.clone();
        impossible_parent_install.mutations[0] = JournalMutation::Quarantine {
            source_path: "mods/tree/old.jar".into(),
            backup_slot: 0,
        };
        impossible_parent_install.mutations[2] = JournalMutation::InstallFile {
            destination_path: "mods/tree".into(),
            staging_slot: 0,
            size: 1,
            sha256: HASH_B.into(),
            executable: false,
        };
        assert!(impossible_parent_install
            .validate(install_id, BuildChannel::Stable)
            .is_err());

        let mut separated_quarantine_overlap = replacement.clone();
        separated_quarantine_overlap.mutations.splice(
            0..1,
            [
                JournalMutation::Quarantine {
                    source_path: "mods/a".into(),
                    backup_slot: 0,
                },
                JournalMutation::Quarantine {
                    source_path: "mods/a-b".into(),
                    backup_slot: 1,
                },
                JournalMutation::Quarantine {
                    source_path: "mods/a/c".into(),
                    backup_slot: 2,
                },
            ],
        );
        assert!(separated_quarantine_overlap
            .validate(install_id, BuildChannel::Stable)
            .is_err());

        let mut separated_install_overlap = replacement;
        separated_install_overlap.mutations.truncate(2);
        separated_install_overlap.mutations.extend([
            JournalMutation::InstallFile {
                destination_path: "mods/a".into(),
                staging_slot: 0,
                size: 1,
                sha256: HASH_B.into(),
                executable: false,
            },
            JournalMutation::InstallFile {
                destination_path: "mods/a-b".into(),
                staging_slot: 1,
                size: 1,
                sha256: HASH_B.into(),
                executable: false,
            },
            JournalMutation::InstallFile {
                destination_path: "mods/a/c".into(),
                staging_slot: 2,
                size: 1,
                sha256: HASH_B.into(),
                executable: false,
            },
        ]);
        assert!(separated_install_overlap
            .validate(install_id, BuildChannel::Stable)
            .is_err());
    }
}
