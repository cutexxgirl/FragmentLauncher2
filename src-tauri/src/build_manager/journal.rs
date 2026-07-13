use super::{
    contracts::{is_sha256, validate_manifest_path},
    instance_state::{ActiveInstanceV2, InstanceOperationLock, InstanceStateStore},
    managed_fs::{
        atomic_write_small, ensure_directory_chain, inspect_managed_garbage_node_nofollow,
        remove_bounded_managed_garbage_tree, validate_materializable_manifest_path,
        ExclusiveManagedFile, ImmutableManagedFile, ManagedDirectoryRemovalLimits, ManagedFsError,
        RelativeManagedPath, MAX_MANAGED_FILE_BYTES, MAX_MANAGED_RELEASE_BYTES,
        MAX_MANIFEST_PATH_COMPONENTS, MAX_RECONCILE_MUTATIONS, MAX_RELEASE_MANAGED_PATHS,
        MAX_RELEASE_PATH_COMPONENTS,
    },
    planner::{
        CurrentPlanSupersedeAuthorizationV2, CurrentReadyAbandonAuthorizationV2,
        FinalizeCommitAuthorizationV2, RepairSupersedeAuthorizationV2,
    },
    reconcile_executor::{
        ReconcileStagingFilesV2, RollbackCompletionAuthorizationV2,
        TrustedReconcileStagingAuthorityV2,
    },
    release::{FilePolicy, MAX_FILES_PER_PRESET, MAX_RECONCILE_PLAN_BYTES as MAX_PLAN_BYTES},
    storage::OwnedCasRoot,
    types::BuildChannel,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    io::{self, Write},
    path::Path,
};
use uuid::{Uuid, Version};

const JOURNAL_SCHEMA_VERSION: u8 = 2;
const MAX_POINTER_BYTES: u64 = 4 * 1024;
const MAX_PRESERVED_PATHS: usize = MAX_RELEASE_MANAGED_PATHS;
const MAX_MUTATIONS: usize = MAX_RECONCILE_MUTATIONS;
// Executor materialization prefixes every manifest path with `instances/<channel>`.
const MAX_RELATIVE_PATH_SEGMENTS: usize = MAX_MANIFEST_PATH_COMPONENTS;
const MAX_PLAN_FILE_BYTES: u64 = MAX_MANAGED_RELEASE_BYTES;
const MAX_RECONCILE_MAINTENANCE_ENTRIES: usize = 4_096;
// Every mutation can conservatively own two flat crash slots; every installed file can own two
// additional staging/temporary slots. Quarantined signed topology is charged separately through
// the aggregate release component budget, so deep paths do not multiply the file bound.
const MAX_OPERATION_BASE_ENTRIES_PER_MUTATION: usize = 2;
const MAX_OPERATION_EXTRA_ENTRIES_PER_INSTALL: usize = 2;
// Fixed entries are the operation root and its five launcher-owned child directories.
const MAX_OPERATION_FIXED_ENTRIES: usize = 6;
// A relocated signed path is nested below the operation root and one slot-directory level; the
// slot node itself replaces the original path's first component, adding one net level.
const MAX_OPERATION_RELOCATED_PATH_DEPTH_OVERHEAD: usize = 1;
// Staging, an in-flight destination copy, and the previous rollback/quarantine copy can each
// coexist at a crash boundary. Per-entry slack covers directory indices and allocation rounding;
// it is deliberately policy overhead, not a claim about bytes which deletion will reclaim.
const MAX_OPERATION_PLAN_BYTE_COPIES: u64 = 3;
const MAX_OPERATION_ALLOCATION_OVERHEAD_PER_ENTRY: u64 = MAX_SUPPORTED_ALLOCATION_UNIT_BYTES;
pub(super) const JOURNAL_RESERVE_BYTES: u64 = 64 * 1024 * 1024 + 64 * 1024;
pub(super) const MINIMUM_SAFETY_MARGIN_BYTES: u64 = 256 * 1024 * 1024;
pub(super) const MAX_SUPPORTED_ALLOCATION_UNIT_BYTES: u64 = 16 * 1024 * 1024;
const JOURNAL_NAMESPACE_ENTRY_RESERVE: u64 = 16;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    successor: Option<JournalPointerV2>,
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
    SupersededForCurrentPlan,
    AbandonedForCurrentReady,
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

/// A serialized crash-recovery record of the budget computed by the planner.
///
/// Structural validation and reconcile-copy totals are independently checked here, but dynamic
/// availability reserves cannot be reconstructed from a journal alone. Consequently this record
/// is never disk-allocation authority; only the non-serializable capability returned by a fresh
/// `plan_build` may authorize a free-space check before mutation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiskBudgetV2 {
    pub allocation_unit_bytes: u64,
    pub missing_download_bytes: u64,
    pub java_extracted_bytes: u64,
    pub game_extracted_bytes: u64,
    pub processor_workspace_bytes: u64,
    pub staging_bytes: u64,
    pub reconcile_destination_bytes: u64,
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
        Self::new_with_allocation_unit(
            missing_download_bytes,
            java_extracted_bytes,
            game_extracted_bytes,
            0,
            1,
            staging_bytes,
        )
    }

    pub fn new_with_processor_workspace(
        missing_download_bytes: u64,
        java_extracted_bytes: u64,
        game_extracted_bytes: u64,
        processor_workspace_bytes: u64,
        staging_bytes: u64,
    ) -> Result<Self, String> {
        Self::new_with_allocation_unit(
            missing_download_bytes,
            java_extracted_bytes,
            game_extracted_bytes,
            processor_workspace_bytes,
            1,
            staging_bytes,
        )
    }

    pub(super) fn new_with_allocation_unit(
        missing_download_bytes: u64,
        java_extracted_bytes: u64,
        game_extracted_bytes: u64,
        processor_workspace_bytes: u64,
        allocation_unit_bytes: u64,
        staging_bytes: u64,
    ) -> Result<Self, String> {
        Self::new_with_physical_layout(
            missing_download_bytes,
            java_extracted_bytes,
            game_extracted_bytes,
            processor_workspace_bytes,
            allocation_unit_bytes,
            staging_bytes,
            staging_bytes,
        )
    }

    pub(super) fn new_with_physical_layout(
        missing_download_bytes: u64,
        java_extracted_bytes: u64,
        game_extracted_bytes: u64,
        processor_workspace_bytes: u64,
        allocation_unit_bytes: u64,
        staging_bytes: u64,
        reconcile_destination_bytes: u64,
    ) -> Result<Self, String> {
        validate_allocation_unit(allocation_unit_bytes)?;
        let journal_reserve_bytes = journal_reserve_for_allocation_unit(allocation_unit_bytes)?;
        let subtotal = [
            missing_download_bytes,
            java_extracted_bytes,
            game_extracted_bytes,
            processor_workspace_bytes,
            staging_bytes,
            reconcile_destination_bytes,
            journal_reserve_bytes,
        ]
        .into_iter()
        .try_fold(0_u64, |total, value| total.checked_add(value))
        .ok_or_else(|| "Disk budget subtotal overflowed".to_string())?;
        let (safety_margin_bytes, required_bytes) = required_with_safety_margin(subtotal)?;
        Ok(Self {
            allocation_unit_bytes,
            missing_download_bytes,
            java_extracted_bytes,
            game_extracted_bytes,
            processor_workspace_bytes,
            staging_bytes,
            reconcile_destination_bytes,
            journal_reserve_bytes,
            safety_margin_bytes,
            required_bytes,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        let expected = Self::new_with_physical_layout(
            self.missing_download_bytes,
            self.java_extracted_bytes,
            self.game_extracted_bytes,
            self.processor_workspace_bytes,
            self.allocation_unit_bytes,
            self.staging_bytes,
            self.reconcile_destination_bytes,
        )?;
        if *self != expected {
            return Err("Reconcile disk budget is not canonical".into());
        }
        Ok(())
    }

    /// Recomputes the current physical admission after a non-serializable, root-bound auditor has
    /// proved that every deterministic reconcile staging slot is complete and exact. The caller
    /// supplies only the independently measured remaining destination/namespace allocation; this
    /// method never treats the serialized staging total as live availability evidence.
    ///
    /// The fresh dynamic download/runtime/processor reserves remain charged, as do the bounded
    /// journal/marker commit reserve and canonical safety margin. This helper is arithmetic only:
    /// it grants no staging credit unless wrapped by the sealed resume authority and exact staging
    /// capability in the reconcile executor.
    pub(super) fn required_after_exact_staging(
        &self,
        remaining_destination_bytes: u64,
    ) -> Result<u64, String> {
        self.validate()?;
        let subtotal = [
            self.missing_download_bytes,
            self.java_extracted_bytes,
            self.game_extracted_bytes,
            self.processor_workspace_bytes,
            remaining_destination_bytes,
            self.journal_reserve_bytes,
            self.safety_margin_bytes,
        ]
        .into_iter()
        .try_fold(0_u64, |total, value| total.checked_add(value))
        .ok_or_else(|| "Resume disk budget subtotal overflowed".to_string())?;
        Ok(subtotal)
    }
}

fn journal_reserve_for_allocation_unit(allocation_unit: u64) -> Result<u64, String> {
    let namespace = if allocation_unit == 1 {
        0
    } else {
        allocation_unit
            .checked_mul(JOURNAL_NAMESPACE_ENTRY_RESERVE)
            .ok_or_else(|| "Journal namespace reserve overflowed".to_string())?
    };
    JOURNAL_RESERVE_BYTES
        .checked_add(namespace)
        .ok_or_else(|| "Journal reserve overflowed".to_string())
}

fn required_with_safety_margin(subtotal: u64) -> Result<(u64, u64), String> {
    let five_percent = subtotal / 20 + u64::from(!subtotal.is_multiple_of(20));
    let safety_margin_bytes = five_percent.max(MINIMUM_SAFETY_MARGIN_BYTES);
    let required_bytes = subtotal
        .checked_add(safety_margin_bytes)
        .ok_or_else(|| "Disk budget total overflowed".to_string())?;
    Ok((safety_margin_bytes, required_bytes))
}

/// Canonical admission for non-journaled download/bootstrap phases. The caller supplies an exact
/// physical content+namespace subtotal; this adds the same bounded headroom as a full build
/// without charging reconcile journal storage which the phase cannot create.
pub(super) fn required_phase_bytes(subtotal: u64) -> Result<u64, String> {
    required_with_safety_margin(subtotal).map(|(_, required)| required)
}

fn validate_allocation_unit(value: u64) -> Result<(), String> {
    if value == 1
        || (value.is_power_of_two() && (512..=MAX_SUPPORTED_ALLOCATION_UNIT_BYTES).contains(&value))
    {
        Ok(())
    } else {
        Err("Disk budget allocation unit is invalid".into())
    }
}

fn round_up_disk_allocation(size: u64, allocation_unit: u64) -> Result<u64, String> {
    if size == 0 || allocation_unit == 1 {
        return Ok(size);
    }
    let remainder = size % allocation_unit;
    if remainder == 0 {
        Ok(size)
    } else {
        size.checked_add(allocation_unit - remainder)
            .ok_or_else(|| "Disk allocation rounding overflowed".into())
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

pub(super) struct PendingJournalTransitionV2 {
    pub(super) pending: PendingJournalV2,
    pub(super) durable_successor: Option<PendingJournalV2>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ReconcileMaintenanceReportV2 {
    pub(super) operation_roots_removed: usize,
    pub(super) completion_histories_removed: usize,
    pub(super) orphan_plans_removed: usize,
    pub(super) temporary_files_removed: usize,
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
        self.validate_mutations(&preserved, &desired)?;
        // Establish budget self-consistency before deriving any plan-bound reserve from its
        // fields. A canonical budget may still disagree with the mutation set; the exact staging
        // and destination checks below report those independent invariants deterministically.
        self.disk_budget.validate()?;
        let (allocated_file_bytes, install_count, quarantine_count, directory_count) =
            self.mutations.iter().try_fold(
                (0_u64, 0_u64, 0_u64, 0_u64),
                |(bytes, installs, quarantines, directories), mutation| match mutation {
                    JournalMutation::InstallFile { size, .. } => {
                        Ok::<(u64, u64, u64, u64), String>((
                            bytes
                                .checked_add(round_up_disk_allocation(
                                    *size,
                                    self.disk_budget.allocation_unit_bytes,
                                )?)
                                .ok_or_else(|| {
                                    "Allocated reconcile byte total overflowed".to_string()
                                })?,
                            installs
                                .checked_add(1)
                                .ok_or_else(|| "Reconcile install count overflowed".to_string())?,
                            quarantines,
                            directories,
                        ))
                    }
                    JournalMutation::Quarantine { .. } => Ok((
                        bytes,
                        installs,
                        quarantines
                            .checked_add(1)
                            .ok_or_else(|| "Reconcile quarantine count overflowed".to_string())?,
                        directories,
                    )),
                    JournalMutation::EnsureDirectory { .. } => Ok((
                        bytes,
                        installs,
                        quarantines,
                        directories
                            .checked_add(1)
                            .ok_or_else(|| "Reconcile directory count overflowed".to_string())?,
                    )),
                },
            )?;
        let (expected_staging_bytes, expected_destination_bytes) = if self
            .disk_budget
            .allocation_unit_bytes
            == 1
        {
            (allocated_file_bytes, allocated_file_bytes)
        } else {
            let staging_entries = install_count
                .checked_mul(2)
                .and_then(|count| count.checked_add(5))
                .ok_or_else(|| "Reconcile staging namespace count overflowed".to_string())?;
            let destination_entries = install_count
                .checked_mul(2)
                .and_then(|count| count.checked_add(quarantine_count))
                .and_then(|count| count.checked_add(directory_count))
                .and_then(|count| count.checked_add(5))
                .ok_or_else(|| "Reconcile destination namespace count overflowed".to_string())?;
            let staging_namespace = staging_entries
                .checked_mul(self.disk_budget.allocation_unit_bytes)
                .ok_or_else(|| "Reconcile staging namespace reserve overflowed".to_string())?;
            let destination_namespace = destination_entries
                .checked_mul(self.disk_budget.allocation_unit_bytes)
                .ok_or_else(|| "Reconcile destination namespace reserve overflowed".to_string())?;
            (
                allocated_file_bytes
                    .checked_add(staging_namespace)
                    .ok_or_else(|| "Reconcile staging reserve overflowed".to_string())?,
                allocated_file_bytes
                    .checked_add(destination_namespace)
                    .ok_or_else(|| "Reconcile destination reserve overflowed".to_string())?,
            )
        };
        if self.disk_budget.staging_bytes != expected_staging_bytes {
            return Err("Disk budget staging bytes do not match install mutations".into());
        }
        if self.disk_budget.reconcile_destination_bytes != expected_destination_bytes {
            return Err(
                "Disk budget reconcile destination bytes do not match install mutations".into(),
            );
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
        validate_desired_file_policy_count(self.desired_files.len())?;
        let mut previous: Option<String> = None;
        let mut desired = BTreeMap::new();
        let mut path_components = 0_usize;
        let mut signed_bytes = 0_u64;
        let mut installed_bytes = 0_u64;
        for file in &self.desired_files {
            validate_mutation_path(&file.path, preserved)?;
            path_components = checked_reconcile_path_component_total(
                path_components,
                file.path.split('/').count(),
            )?;
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
            signed_bytes = checked_desired_file_bytes(signed_bytes, file.signed_size)?;
            installed_bytes = checked_desired_file_bytes(installed_bytes, file.installed_size)?;
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

fn validate_desired_file_policy_count(count: usize) -> Result<(), String> {
    if count == 0 || count > MAX_FILES_PER_PRESET {
        return Err("Reconcile plan desired-file set is empty or oversized".into());
    }
    Ok(())
}

fn checked_reconcile_path_component_total(
    current: usize,
    additional: usize,
) -> Result<usize, String> {
    current
        .checked_add(additional)
        .filter(|total| *total <= MAX_RELEASE_PATH_COMPONENTS)
        .ok_or_else(|| "Reconcile desired-file topology exceeds its component budget".to_string())
}

fn checked_desired_file_bytes(current: u64, additional: u64) -> Result<u64, String> {
    current
        .checked_add(additional)
        .filter(|total| *total <= MAX_MANAGED_RELEASE_BYTES)
        .ok_or_else(|| "Reconcile desired-file bytes exceed the managed release budget".into())
}

fn same_release_content(base: &ActiveInstanceV2, target: &ActiveInstanceV2) -> bool {
    base.release_id == target.release_id
        && base.release_manifest_sha256 == target.release_manifest_sha256
        && base.runtime_lock_sha256 == target.runtime_lock_sha256
        && base.game_runtime_lock_sha256 == target.game_runtime_lock_sha256
        && base
            .trusted_release
            .targets_match_and_roles_are_monotonic_to(&target.trusted_release)
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

/// Detects the crash boundary where a stale pending pointer still names the old operation while
/// its exact current-plan supersede history and immutable successor plan are already durable.
/// This is structural recovery evidence only; the coordinator must rebuild fresh non-serializable
/// planner/staging authority and require the resulting plan to equal `durable_successor` byte for
/// byte before retrying the atomic pointer swap.
pub(super) fn detect_pending_transition(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
) -> Result<Option<PendingJournalTransitionV2>, String> {
    let Some(pending) = detect_pending(
        install_root,
        expected_install_id,
        expected_channel,
        operation_lock,
    )?
    else {
        return Ok(None);
    };
    let durable_successor = load_durable_successor_for_pending(
        install_root,
        expected_install_id,
        expected_channel,
        &pending,
    )?;
    operation_lock
        .validate_scope(install_root, expected_install_id, expected_channel)
        .map_err(|error| format!("Pending transition lock changed: {error}"))?;
    Ok(Some(PendingJournalTransitionV2 {
        pending,
        durable_successor,
    }))
}

fn load_durable_successor_for_pending(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    pending: &PendingJournalV2,
) -> Result<Option<PendingJournalV2>, String> {
    let paths = JournalPaths::new(expected_channel, &pending.pointer)?;
    let Some(history_bytes) = read_optional_bounded(
        install_root,
        &paths.completion,
        MAX_POINTER_BYTES,
        "pending transition completion history",
    )?
    else {
        return Ok(None);
    };
    let tombstone: JournalTombstoneV2 =
        parse_without_duplicate_keys(&history_bytes, "pending transition completion history")?;
    let canonical = serialize_bounded(
        &tombstone,
        MAX_POINTER_BYTES as usize,
        "pending transition completion history",
    )?;
    if canonical != history_bytes || tombstone.completed_pointer != pending.pointer {
        return Err("Pending transition completion history is not exact for its pointer".into());
    }
    let validated_plan = validate_completion_history(
        install_root,
        expected_install_id,
        expected_channel,
        &tombstone,
        &history_bytes,
    )?;
    if validated_plan != pending.plan {
        return Err("Pending transition history loaded another immutable plan".into());
    }
    if tombstone.outcome != JournalCompletionOutcomeV2::SupersededForCurrentPlan {
        return Ok(None);
    }
    let successor = tombstone
        .successor
        .as_ref()
        .ok_or_else(|| "Current-plan transition history has no successor".to_string())?;
    let successor_paths = JournalPaths::new(expected_channel, successor)?;
    let successor_plan = load_plan(
        install_root,
        &successor_paths.plan,
        successor,
        expected_install_id,
        expected_channel,
    )?;
    if successor_plan.operation_id != successor.operation_id {
        return Err("Pending transition successor plan does not match its pointer".into());
    }
    validate_superseding_current_plan(
        &pending.plan,
        tombstone.continuation.as_ref(),
        &successor_plan,
    )?;
    Ok(Some(PendingJournalV2 {
        pointer: successor.clone(),
        plan: successor_plan,
    }))
}

/// Completes only the bookkeeping half of a previously authorized current-plan supersede.
///
/// The immutable old completion history and exact successor plan must already be durable. This
/// function never executes either plan, never touches staging/instance files and never grants
/// roll-forward or rollback authority; it only converges `pending.json` from the recorded old
/// pointer to the recorded successor pointer. The successor is then classified normally against
/// fresh TUF state by the coordinator.
#[allow(clippy::too_many_arguments)]
pub(super) fn advance_pending_to_recorded_successor(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
    expected_pending: &JournalPointerV2,
    expected_successor: &JournalPointerV2,
) -> Result<PendingJournalV2, String> {
    operation_lock
        .validate_scope(install_root, expected_install_id, expected_channel)
        .map_err(|error| format!("Invalid reconcile operation lock: {error}"))?;
    expected_pending.validate(expected_install_id, expected_channel)?;
    expected_successor.validate(expected_install_id, expected_channel)?;
    if expected_pending.operation_id == expected_successor.operation_id {
        return Err("Recorded successor reuses the pending operation ID".into());
    }

    let old_paths = JournalPaths::new(expected_channel, expected_pending)?;
    let old_plan = load_plan(
        install_root,
        &old_paths.plan,
        expected_pending,
        expected_install_id,
        expected_channel,
    )?;
    let old_pending = PendingJournalV2 {
        pointer: expected_pending.clone(),
        plan: old_plan,
    };
    let recorded = load_durable_successor_for_pending(
        install_root,
        expected_install_id,
        expected_channel,
        &old_pending,
    )?
    .ok_or_else(|| "Pending operation has no durable current-plan successor".to_string())?;
    if recorded.pointer != *expected_successor {
        return Err("Durable transition records another successor pointer".into());
    }

    let state = InstanceStateStore::new(install_root, expected_install_id);
    let active = state
        .load_locked(operation_lock)
        .map_err(|error| format!("Cannot verify active state for pointer handoff: {error}"))?;
    if active != recorded.plan.base {
        return Err("Recorded successor base is not the exact active marker".into());
    }

    let pending_path = journal_pending_path(expected_channel)?;
    let current_bytes = read_bounded(
        install_root,
        &pending_path,
        MAX_POINTER_BYTES,
        "pending pointer handoff slot",
    )?;
    let current_pointer =
        match parse_journal_slot(&current_bytes, expected_install_id, expected_channel)? {
            JournalSlotV2::Pending(pointer) => pointer,
            JournalSlotV2::Cleared(_) => {
                return Err("Pending pointer handoff found a completed journal slot".into())
            }
        };
    let old_bytes = serialize_bounded(
        expected_pending,
        MAX_POINTER_BYTES as usize,
        "expected pending pointer",
    )?;
    let successor_bytes = serialize_bounded(
        expected_successor,
        MAX_POINTER_BYTES as usize,
        "recorded successor pointer",
    )?;
    if current_pointer == *expected_pending && current_bytes == old_bytes {
        atomic_write_small(
            install_root,
            pending_path.clone(),
            &successor_bytes,
            MAX_POINTER_BYTES as usize,
        )
        .map_err(|error| format!("Cannot atomically advance pending pointer: {error}"))?;
    } else if current_pointer != *expected_successor || current_bytes != successor_bytes {
        return Err("Pending pointer changed outside the recorded transition".into());
    }

    let persisted = read_bounded(
        install_root,
        &pending_path,
        MAX_POINTER_BYTES,
        "advanced successor pointer",
    )?;
    if persisted != successor_bytes {
        return Err("Advanced successor pointer changed during verification".into());
    }
    let active_after = state
        .load_locked(operation_lock)
        .map_err(|error| format!("Cannot reverify active state after pointer handoff: {error}"))?;
    if active_after != recorded.plan.base {
        return Err("Active marker changed during recorded pointer handoff".into());
    }
    operation_lock
        .validate_scope(install_root, expected_install_id, expected_channel)
        .map_err(|error| format!("Recorded pointer handoff lock changed: {error}"))?;
    Ok(recorded)
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

/// Durably abandons a stale pointer only after the fresh signed planner independently classified
/// the exact active continuation as Ready. Callers must repeat the fresh audit after this tombstone
/// is published before exposing Ready or launching.
pub fn abandon_stale_pending_for_current_ready(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
    expected: &JournalPointerV2,
    authorization: CurrentReadyAbandonAuthorizationV2,
) -> Result<bool, String> {
    let stale_plan = load_authorized_plan(
        install_root,
        expected_install_id,
        expected_channel,
        operation_lock,
        expected,
    )?;
    authorization.validate_for(expected, &stale_plan)?;
    let active = InstanceStateStore::new(install_root, expected_install_id)
        .load_locked(operation_lock)
        .map_err(|error| format!("Cannot verify active state for fresh-ready abandon: {error}"))?;
    if active.as_ref() != Some(authorization.continuation()) {
        return Err("Fresh-ready active marker changed before stale journal abandon".into());
    }
    complete_pending(
        install_root,
        expected_install_id,
        expected_channel,
        operation_lock,
        expected,
        JournalCompletionOutcomeV2::AbandonedForCurrentReady,
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
        successor: None,
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

/// Atomically replaces a failed committed historical operation with one completely prepared
/// update derived from the freshly trusted TUF release. The new plan and every staging slot are
/// revalidated through non-serializable planner/staging authorities before durable supersede
/// history is written; `pending.json` then changes directly from old to new with no idle gap.
#[allow(clippy::too_many_arguments)]
pub fn supersede_stale_pending_with_current_plan(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
    cas_root: &OwnedCasRoot,
    failed_pointer: &JournalPointerV2,
    authorization: CurrentPlanSupersedeAuthorizationV2,
    update_authority: &TrustedReconcileStagingAuthorityV2<'_, '_>,
    staged_update: &ReconcileStagingFilesV2,
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
    let current_plan = update_authority.plan();
    authorization.validate_for(failed_pointer, &failed_plan, current_plan)?;
    let active = InstanceStateStore::new(install_root, expected_install_id)
        .load_locked(operation_lock)
        .map_err(|error| {
            format!("Cannot verify active state for current-plan supersede: {error}")
        })?;
    if active.as_ref() != authorization.continuation() {
        return Err("Current-plan supersede active marker changed after planning".into());
    }
    validate_superseding_current_plan(&failed_plan, active.as_ref(), current_plan)?;
    staged_update
        .proofs_for(update_authority, operation_lock, cas_root)
        .map_err(|error| format!("Prepared current-update staging is invalid: {error}"))?;

    let update_pointer = write_immutable_plan(
        install_root,
        expected_install_id,
        expected_channel,
        operation_lock,
        current_plan,
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
        outcome: JournalCompletionOutcomeV2::SupersededForCurrentPlan,
        continuation: active.clone(),
        successor: Some(update_pointer.clone()),
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
    let update_pointer_bytes = serialize_bounded(
        &update_pointer,
        MAX_POINTER_BYTES as usize,
        "current-update journal pointer",
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
            if pointer == update_pointer && current == update_pointer_bytes =>
        {
            validate_completion_history(
                install_root,
                expected_install_id,
                expected_channel,
                &completion,
                &completion_bytes,
            )?;
            return Ok(update_pointer);
        }
        _ => return Err(
            "Pending journal is neither the failed operation nor its exact signed-current update"
                .into(),
        ),
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
        &update_pointer_bytes,
        MAX_POINTER_BYTES as usize,
    )
    .map_err(|error| format!("Cannot atomically supersede journal with current update: {error}"))?;
    let persisted = read_bounded(
        install_root,
        &failed_paths.pending,
        MAX_POINTER_BYTES,
        "current-update journal pointer",
    )?;
    if persisted != update_pointer_bytes {
        return Err("Superseding current-update pointer changed during verification".into());
    }
    Ok(update_pointer)
}

fn validate_superseding_current_plan(
    failed: &ReconcilePlanV2,
    active: Option<&ActiveInstanceV2>,
    update: &ReconcilePlanV2,
) -> Result<(), String> {
    update.validate(failed.install_id, failed.channel)?;
    if update.operation_id == failed.operation_id || update.base.as_ref() != active {
        return Err(
            "Superseding operation is not the authorized signed-current plan for the observed state"
                .into(),
        );
    }
    Ok(())
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
    if matches!(
        outcome,
        JournalCompletionOutcomeV2::SupersededForRepair
            | JournalCompletionOutcomeV2::SupersededForCurrentPlan
    ) {
        return Err("A supersede cannot be published as an idle tombstone".into());
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
        JournalCompletionOutcomeV2::AbandonedForCurrentReady => active,
        JournalCompletionOutcomeV2::SupersededForRepair
        | JournalCompletionOutcomeV2::SupersededForCurrentPlan => unreachable!("rejected above"),
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
        successor: None,
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
        if let Some(successor) = &self.successor {
            successor.validate(expected_install_id, expected_channel)?;
            if successor.operation_id == self.completed_pointer.operation_id {
                return Err(
                    "Reconcile supersede successor reuses the completed operation ID".into(),
                );
            }
        }
        match self.outcome {
            JournalCompletionOutcomeV2::SupersededForCurrentPlan if self.successor.is_none() => {
                return Err("Current-plan supersede history requires its exact successor".into())
            }
            JournalCompletionOutcomeV2::SupersededForCurrentPlan => {}
            _ if self.successor.is_some() => {
                return Err("Only current-plan supersede history may contain a successor".into())
            }
            _ => {}
        }
        if !matches!(
            self.outcome,
            JournalCompletionOutcomeV2::RolledBackToBase
                | JournalCompletionOutcomeV2::SupersededForCurrentPlan
        ) && self.continuation.is_none()
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
    if outcome == JournalCompletionOutcomeV2::SupersededForCurrentPlan {
        // This outcome deliberately abandons every stale-plan mutation. The continuation is the
        // exact live marker bound by the non-serializable fresh-plan authorization at publication.
        return Ok(());
    }
    if outcome == JournalCompletionOutcomeV2::AbandonedForCurrentReady {
        // Bound to the exact active marker by the fresh-ready authorization before publication.
        return Ok(());
    }
    let expected = match outcome {
        JournalCompletionOutcomeV2::CommittedTarget
        | JournalCompletionOutcomeV2::SupersededForRepair => Some(&plan.target),
        JournalCompletionOutcomeV2::RolledBackToBase => plan.base.as_ref(),
        JournalCompletionOutcomeV2::SupersededForCurrentPlan => unreachable!("handled above"),
        JournalCompletionOutcomeV2::AbandonedForCurrentReady => unreachable!("handled above"),
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
            JournalCompletionOutcomeV2::SupersededForCurrentPlan => unreachable!("handled above"),
            JournalCompletionOutcomeV2::AbandonedForCurrentReady => unreachable!("handled above"),
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
    if matches!(
        tombstone.outcome,
        JournalCompletionOutcomeV2::SupersededForRepair
            | JournalCompletionOutcomeV2::SupersededForCurrentPlan
    ) {
        return Err("A supersede completion cannot occupy the pending journal slot".into());
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
    if let Some(successor) = &tombstone.successor {
        let successor_paths = JournalPaths::new(expected_channel, successor)?;
        let successor_plan = load_plan(
            install_root,
            &successor_paths.plan,
            successor,
            expected_install_id,
            expected_channel,
        )?;
        if successor_plan.operation_id == plan.operation_id
            || successor_plan.base.as_ref() != tombstone.continuation.as_ref()
        {
            return Err(
                "Journal supersede history successor is not bound to its exact continuation".into(),
            );
        }
    }
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
    validate_materializable_manifest_path(path)
        .map_err(|error| format!("Reconcile path cannot be materialized safely: {error}"))?;
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
    let mut counter = BoundedJsonCounter {
        length: 0,
        maximum,
        exceeded: false,
    };
    if let Err(error) = serde_json::to_writer(&mut counter, value) {
        if counter.exceeded {
            return Err(format!("Serialized {label} exceeds its launcher limit"));
        }
        return Err(format!("Cannot serialize {label}: {error}"));
    }
    if counter.length == 0 {
        return Err(format!("Serialized {label} exceeds its launcher limit"));
    }

    let mut buffer = BoundedJsonBuffer {
        bytes: Vec::with_capacity(counter.length),
        maximum,
        exceeded: false,
    };
    if let Err(error) = serde_json::to_writer(&mut buffer, value) {
        if buffer.exceeded {
            return Err(format!("Serialized {label} exceeds its launcher limit"));
        }
        return Err(format!("Cannot serialize {label}: {error}"));
    }
    if buffer.bytes.len() != counter.length {
        return Err(format!(
            "Cannot serialize {label}: serialized size changed across bounded passes"
        ));
    }
    Ok(buffer.bytes)
}

struct BoundedJsonCounter {
    length: usize,
    maximum: usize,
    exceeded: bool,
}

impl Write for BoundedJsonCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.length.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("bounded JSON limit exceeded"));
        };
        if next > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other("bounded JSON limit exceeded"));
        }
        self.length = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct BoundedJsonBuffer {
    bytes: Vec<u8>,
    maximum: usize,
    exceeded: bool,
}

impl Write for BoundedJsonBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.bytes.len().checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("bounded JSON limit exceeded"));
        };
        if next > self.maximum {
            self.exceeded = true;
            return Err(io::Error::other("bounded JSON limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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

struct ReconcileMaintenanceSlot {
    bytes: Option<Vec<u8>>,
    protected_operation_ids: BTreeSet<Uuid>,
    protected_plans: BTreeSet<String>,
    protected_completions: BTreeSet<String>,
    _lease: Option<ImmutableManagedFile>,
}

/// Removes every operation-owned reconcile namespace which is not the exact current pending
/// operation, then bounds immutable journal state to the plan/history required by the current
/// slot. This must run under the channel operation lock after the caller has classified the exact
/// pending transition and before another operation starts staging. It is intentionally safe while
/// an old pending operation exists: that operation and any history-only durable successor remain
/// protected, while unrelated roots from failed pre-supersede retries are reclaimed. A
/// completion-history-only crash window never grants cleanup authority because the still-pending
/// operation ID remains protected by the leased slot.
pub(super) fn maintain_completed_reconcile_state(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
) -> Result<ReconcileMaintenanceReportV2, String> {
    operation_lock
        .validate_scope(install_root, expected_install_id, expected_channel)
        .map_err(|error| format!("Invalid reconcile maintenance lock: {error}"))?;
    let slot = load_reconcile_maintenance_slot(
        install_root,
        expected_install_id,
        expected_channel,
        operation_lock,
    )?;
    let mut report = ReconcileMaintenanceReportV2::default();
    let operations = RelativeManagedPath::new(&format!(
        "state/reconcile/{}/operations",
        expected_channel.as_str()
    ))
    .map_err(|error| format!("Cannot derive reconcile operations directory: {error}"))?;
    let operation_names = bounded_managed_namespace_names(install_root, &operations)?;
    for name in &operation_names {
        let operation_id = parse_canonical_operation_id(name)?;
        if slot.protected_operation_ids.contains(&operation_id) {
            continue;
        }
        revalidate_maintenance_slot(
            install_root,
            expected_install_id,
            expected_channel,
            operation_lock,
            &slot,
        )?;
        let relative = operations
            .join_component(name)
            .map_err(|error| format!("Cannot derive stale operation root: {error}"))?;
        if remove_reconcile_garbage_path(install_root, &relative, operation_garbage_limits()?)? {
            report.operation_roots_removed += 1;
        }
        revalidate_maintenance_slot(
            install_root,
            expected_install_id,
            expected_channel,
            operation_lock,
            &slot,
        )?;
    }
    let remaining_operations = bounded_managed_namespace_names(install_root, &operations)?;
    for name in remaining_operations {
        let operation_id = parse_canonical_operation_id(&name)?;
        if !slot.protected_operation_ids.contains(&operation_id) {
            return Err("Completed reconcile operation cleanup made no bounded progress".into());
        }
    }

    let journal_root =
        RelativeManagedPath::new(&format!("state/journals/{}", expected_channel.as_str()))
            .map_err(|error| format!("Cannot derive reconcile journal directory: {error}"))?;
    let completions = journal_root
        .join_component("completions")
        .map_err(|error| format!("Cannot derive completion history directory: {error}"))?;
    for name in bounded_managed_namespace_names(install_root, &completions)? {
        parse_canonical_journal_artifact_name(&name)?;
        if slot.protected_completions.contains(&name) {
            continue;
        }
        revalidate_maintenance_slot(
            install_root,
            expected_install_id,
            expected_channel,
            operation_lock,
            &slot,
        )?;
        let relative = completions
            .join_component(&name)
            .map_err(|error| format!("Cannot derive obsolete completion path: {error}"))?;
        if remove_reconcile_garbage_path(install_root, &relative, journal_file_garbage_limits())? {
            report.completion_histories_removed += 1;
        }
    }

    let plans = journal_root
        .join_component("plans")
        .map_err(|error| format!("Cannot derive immutable plan directory: {error}"))?;
    for name in bounded_managed_namespace_names(install_root, &plans)? {
        parse_canonical_journal_artifact_name(&name)?;
        if slot.protected_plans.contains(&name) {
            continue;
        }
        revalidate_maintenance_slot(
            install_root,
            expected_install_id,
            expected_channel,
            operation_lock,
            &slot,
        )?;
        let relative = plans
            .join_component(&name)
            .map_err(|error| format!("Cannot derive orphan plan path: {error}"))?;
        if remove_reconcile_garbage_path(install_root, &relative, journal_file_garbage_limits())? {
            report.orphan_plans_removed += 1;
        }
    }

    let temporary = journal_root
        .join_component("temporary")
        .map_err(|error| format!("Cannot derive journal temporary directory: {error}"))?;
    for name in bounded_managed_namespace_names(install_root, &temporary)? {
        parse_canonical_journal_temporary_name(&name)?;
        revalidate_maintenance_slot(
            install_root,
            expected_install_id,
            expected_channel,
            operation_lock,
            &slot,
        )?;
        let relative = temporary
            .join_component(&name)
            .map_err(|error| format!("Cannot derive stale journal temporary path: {error}"))?;
        if remove_reconcile_garbage_path(install_root, &relative, journal_file_garbage_limits())? {
            report.temporary_files_removed += 1;
        }
    }
    revalidate_maintenance_slot(
        install_root,
        expected_install_id,
        expected_channel,
        operation_lock,
        &slot,
    )?;
    Ok(report)
}

fn load_reconcile_maintenance_slot(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
) -> Result<ReconcileMaintenanceSlot, String> {
    let pending = journal_pending_path(expected_channel)?;
    let mut lease = match ImmutableManagedFile::open(install_root, &pending) {
        Ok(lease) => Some(lease),
        Err(ManagedFsError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            None
        }
        Err(error) => return Err(format!("Cannot lease reconcile journal slot: {error}")),
    };
    let Some(file) = lease.as_mut() else {
        return Ok(ReconcileMaintenanceSlot {
            bytes: None,
            protected_operation_ids: BTreeSet::new(),
            protected_plans: BTreeSet::new(),
            protected_completions: BTreeSet::new(),
            _lease: None,
        });
    };
    let bytes = file
        .read_bounded(MAX_POINTER_BYTES)
        .map_err(|error| format!("Cannot read leased reconcile journal slot: {error}"))?;
    let parsed = parse_journal_slot(&bytes, expected_install_id, expected_channel)?;
    let (pointer, pending_journal) = match &parsed {
        JournalSlotV2::Pending(pointer) => {
            let paths = JournalPaths::new(expected_channel, pointer)?;
            let plan = load_plan(
                install_root,
                &paths.plan,
                pointer,
                expected_install_id,
                expected_channel,
            )?;
            (
                pointer,
                Some(PendingJournalV2 {
                    pointer: pointer.clone(),
                    plan,
                }),
            )
        }
        JournalSlotV2::Cleared(tombstone) => {
            validate_persisted_completion(
                install_root,
                expected_install_id,
                expected_channel,
                operation_lock,
                tombstone,
                &bytes,
            )?;
            (&tombstone.completed_pointer, None)
        }
    };
    let artifact_name = format!("{}-{}.json", pointer.operation_id, pointer.plan_sha256);
    let mut protected_operation_ids = BTreeSet::new();
    let mut protected_plans = BTreeSet::from([artifact_name.clone()]);
    let protected_completions = BTreeSet::from([artifact_name]);
    if let Some(pending) = &pending_journal {
        protected_operation_ids.insert(pending.pointer.operation_id);
        if let Some(successor) = load_durable_successor_for_pending(
            install_root,
            expected_install_id,
            expected_channel,
            pending,
        )? {
            protected_operation_ids.insert(successor.pointer.operation_id);
            protected_plans.insert(format!(
                "{}-{}.json",
                successor.pointer.operation_id, successor.pointer.plan_sha256
            ));
        }
    }
    Ok(ReconcileMaintenanceSlot {
        bytes: Some(bytes),
        protected_operation_ids,
        protected_plans,
        // Completion history may already be durable while the old pending pointer is still
        // visible. Retain that exact same-operation history so completion/supersede can retry.
        protected_completions,
        _lease: lease,
    })
}

fn revalidate_maintenance_slot(
    install_root: &Path,
    expected_install_id: Uuid,
    expected_channel: BuildChannel,
    operation_lock: &InstanceOperationLock,
    slot: &ReconcileMaintenanceSlot,
) -> Result<(), String> {
    operation_lock
        .validate_scope(install_root, expected_install_id, expected_channel)
        .map_err(|error| format!("Reconcile maintenance lock changed: {error}"))?;
    match (&slot._lease, &slot.bytes) {
        (Some(lease), Some(expected)) => {
            lease.revalidate().map_err(|error| {
                format!("Reconcile journal slot changed during cleanup: {error}")
            })?;
            if lease
                .read_bounded_shared(MAX_POINTER_BYTES)
                .map_err(|error| format!("Cannot re-read reconcile journal slot: {error}"))?
                != *expected
            {
                return Err("Reconcile journal slot bytes changed during cleanup".into());
            }
        }
        (None, None) => {
            if read_optional_bounded(
                install_root,
                &journal_pending_path(expected_channel)?,
                MAX_POINTER_BYTES,
                "journal slot",
            )?
            .is_some()
            {
                return Err("A reconcile journal slot appeared during cleanup".into());
            }
        }
        _ => return Err("Reconcile maintenance slot lease is internally inconsistent".into()),
    }
    Ok(())
}

fn bounded_managed_namespace_names(
    install_root: &Path,
    relative: &RelativeManagedPath,
) -> Result<Vec<String>, String> {
    let guard = ensure_directory_chain(install_root, relative)
        .map_err(|error| format!("Cannot prepare reconcile maintenance namespace: {error}"))?;
    let mut names = Vec::new();
    let mut collision_keys = BTreeSet::new();
    for entry in fs::read_dir(guard.leaf().path())
        .map_err(|error| format!("Cannot enumerate reconcile maintenance namespace: {error}"))?
    {
        let entry = entry
            .map_err(|error| format!("Cannot inspect reconcile maintenance entry: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Reconcile maintenance entry name is not Unicode".to_string())?;
        if !collision_keys.insert(name.to_lowercase()) {
            return Err("Reconcile maintenance namespace contains a Windows collision".into());
        }
        names.push(name);
        if names.len() > MAX_RECONCILE_MAINTENANCE_ENTRIES {
            return Err("Reconcile maintenance namespace exceeds its entry limit".into());
        }
    }
    names.sort_unstable();
    guard
        .revalidate()
        .map_err(|error| format!("Reconcile maintenance namespace changed: {error}"))?;
    Ok(names)
}

fn parse_canonical_operation_id(name: &str) -> Result<Uuid, String> {
    let operation_id = Uuid::parse_str(name)
        .map_err(|_| "Reconcile operation root name is not a UUID".to_string())?;
    if operation_id.is_nil()
        || operation_id.get_version() != Some(Version::Random)
        || operation_id.to_string() != name
    {
        return Err("Reconcile operation root name is not a canonical UUIDv4".into());
    }
    Ok(operation_id)
}

fn parse_canonical_journal_artifact_name(name: &str) -> Result<(Uuid, String), String> {
    if name.len() != 106 || name.as_bytes().get(36) != Some(&b'-') || !name.ends_with(".json") {
        return Err("Immutable reconcile journal filename is not canonical".into());
    }
    let operation_id = parse_canonical_operation_id(&name[..36])?;
    let sha256 = &name[37..101];
    if !is_sha256(sha256) {
        return Err("Immutable reconcile journal filename has an invalid SHA-256".into());
    }
    Ok((operation_id, sha256.to_owned()))
}

fn parse_canonical_journal_temporary_name(name: &str) -> Result<Uuid, String> {
    let operation = name
        .strip_prefix("journal-")
        .and_then(|value| value.strip_suffix(".tmp"))
        .ok_or_else(|| "Journal temporary filename is not canonical".to_string())?;
    parse_canonical_operation_id(operation)
}

fn remove_reconcile_garbage_path(
    install_root: &Path,
    relative: &RelativeManagedPath,
    limits: ManagedDirectoryRemovalLimits,
) -> Result<bool, String> {
    let identity = match inspect_managed_garbage_node_nofollow(install_root, relative) {
        Ok(identity) => identity,
        Err(ManagedFsError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(false)
        }
        Err(error) => return Err(format!("Cannot lease reconcile garbage: {error}")),
    };
    remove_bounded_managed_garbage_tree(install_root, relative, &identity, limits)
        .map_err(|error| format!("Cannot remove bounded reconcile garbage: {error}"))?;
    Ok(true)
}

/// Hard ceiling shared by pre-move quarantine admission and completed-operation cleanup.
/// Signed release topology fits this ceiling; unknown or modified subtrees must be audited and
/// cumulatively admitted before their first whole-tree rename. It is not permission to move an
/// unaudited subtree and it is never increased from observed filesystem contents.
pub(super) fn operation_garbage_limits() -> Result<ManagedDirectoryRemovalLimits, String> {
    operation_garbage_limits_for_release_policy(MAX_FILES_PER_PRESET, MAX_RELEASE_PATH_COMPONENTS)
}

fn operation_garbage_limits_for_release_policy(
    max_release_files: usize,
    max_release_path_components: usize,
) -> Result<ManagedDirectoryRemovalLimits, String> {
    if max_release_files > MAX_FILES_PER_PRESET {
        return Err("Reconcile garbage policy exceeds the signed release file bound".into());
    }
    if max_release_path_components > MAX_RELEASE_PATH_COMPONENTS {
        return Err("Reconcile garbage policy exceeds the signed path topology bound".into());
    }
    let mutation_entries = MAX_MUTATIONS
        .checked_mul(MAX_OPERATION_BASE_ENTRIES_PER_MUTATION)
        .ok_or_else(|| "Reconcile garbage mutation-entry policy overflowed".to_string())?;
    let install_entries = max_release_files
        .checked_mul(MAX_OPERATION_EXTRA_ENTRIES_PER_INSTALL)
        .ok_or_else(|| "Reconcile garbage install-entry policy overflowed".to_string())?;
    let max_entries = mutation_entries
        .checked_add(install_entries)
        .and_then(|entries| entries.checked_add(max_release_path_components))
        .and_then(|entries| entries.checked_add(MAX_OPERATION_FIXED_ENTRIES))
        .ok_or_else(|| "Reconcile garbage entry policy overflowed".to_string())?;
    let allocation_overhead = u64::try_from(max_entries)
        .ok()
        .and_then(|entries| entries.checked_mul(MAX_OPERATION_ALLOCATION_OVERHEAD_PER_ENTRY))
        .ok_or_else(|| "Reconcile garbage allocation-overhead policy overflowed".to_string())?;
    let max_allocated_bytes = MAX_PLAN_FILE_BYTES
        .checked_mul(MAX_OPERATION_PLAN_BYTE_COPIES)
        .and_then(|bytes| bytes.checked_add(allocation_overhead))
        .ok_or_else(|| "Reconcile garbage allocated-byte policy overflowed".to_string())?;
    let max_depth = MAX_RELATIVE_PATH_SEGMENTS
        .checked_add(MAX_OPERATION_RELOCATED_PATH_DEPTH_OVERHEAD)
        .ok_or_else(|| "Reconcile garbage depth policy overflowed".to_string())?;
    Ok(ManagedDirectoryRemovalLimits {
        max_entries,
        max_allocated_bytes,
        max_depth,
    })
}

fn journal_file_garbage_limits() -> ManagedDirectoryRemovalLimits {
    ManagedDirectoryRemovalLimits {
        max_entries: 1,
        max_allocated_bytes: MAX_PLAN_BYTES + JOURNAL_RESERVE_BYTES,
        max_depth: 0,
    }
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
    use crate::build_manager::{
        instance_state::InstanceStateStore,
        release::{
            projected_ensure_directory_json_bytes, projected_install_file_json_bytes,
            projected_planned_file_json_bytes, projected_quarantine_json_bytes,
            projected_reconcile_directories, projected_worst_case_reconcile_plan_bytes,
            ManifestFile,
        },
        types::PresetId,
    };
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

    #[test]
    fn bounded_serializer_accepts_the_exact_limit_and_rejects_one_byte_less() {
        let value = "x".repeat(4_096);
        let expected = serde_json::to_vec(&value).unwrap();
        assert_eq!(
            serialize_bounded(&value, expected.len(), "test value").unwrap(),
            expected
        );
        assert_eq!(
            serialize_bounded(&value, expected.len() - 1, "test value").unwrap_err(),
            "Serialized test value exceeds its launcher limit"
        );
    }

    #[test]
    fn release_projection_matches_canonical_journal_records_and_unicode_plan() {
        let path = "config/\u{1e9e}.toml".to_string();
        let planned = PlannedFileV2 {
            path: path.clone(),
            signed_size: 12_345,
            signed_sha256: HASH_A.into(),
            installed_size: 987_654_321,
            installed_sha256: HASH_B.into(),
            executable: false,
            policy: FilePolicy::ValidatedMutable,
        };
        assert_eq!(
            serde_json::to_vec(&planned).unwrap().len() as u64,
            projected_planned_file_json_bytes(
                &path,
                planned.signed_size,
                planned.installed_size,
                planned.executable,
                planned.policy,
            )
            .unwrap()
        );

        let quarantine = JournalMutation::Quarantine {
            source_path: path.clone(),
            backup_slot: 399_999,
        };
        assert_eq!(
            serde_json::to_vec(&quarantine).unwrap().len() as u64,
            projected_quarantine_json_bytes(&path, 399_999).unwrap()
        );
        let ensure = JournalMutation::EnsureDirectory {
            destination_path: "\u{1e9e}".into(),
        };
        assert_eq!(
            serde_json::to_vec(&ensure).unwrap().len() as u64,
            projected_ensure_directory_json_bytes("\u{1e9e}").unwrap()
        );
        let install = JournalMutation::InstallFile {
            destination_path: path.clone(),
            staging_slot: 399_999,
            size: u64::MAX,
            sha256: HASH_C.into(),
            executable: false,
        };
        assert_eq!(
            serde_json::to_vec(&install).unwrap().len() as u64,
            projected_install_file_json_bytes(&path, 399_999, u64::MAX, false).unwrap()
        );

        let install_id = Uuid::new_v4();
        let mut plan = install_plan(install_id, BuildChannel::Stable);
        plan.desired_files = vec![PlannedFileV2 {
            path: path.clone(),
            signed_size: u64::MAX,
            signed_sha256: HASH_A.into(),
            installed_size: u64::MAX,
            installed_sha256: HASH_B.into(),
            executable: false,
            policy: FilePolicy::ValidatedMutable,
        }];
        plan.mutations = vec![quarantine, ensure, install];
        let files = vec![ManifestFile {
            path: path.clone(),
            size: u64::MAX,
            sha256: HASH_A.into(),
            executable: false,
            policy: FilePolicy::ValidatedMutable,
        }];
        let uppercase_parent = "\u{1e9e}".to_string();
        let lowercase_parent = uppercase_parent.to_lowercase();
        assert!(uppercase_parent.len() > lowercase_parent.len());
        assert!(
            projected_ensure_directory_json_bytes(&uppercase_parent).unwrap()
                > projected_ensure_directory_json_bytes(&lowercase_parent).unwrap()
        );
        let parents =
            projected_reconcile_directories(&files, std::slice::from_ref(&uppercase_parent));
        assert_eq!(parents.get(&lowercase_parent), Some(&uppercase_parent));
        let projected = projected_worst_case_reconcile_plan_bytes(&files, &parents).unwrap();
        let canonical =
            serialize_bounded(&plan, MAX_PLAN_BYTES as usize, "reconcile plan").unwrap();
        assert!(projected >= canonical.len() as u64);
    }

    #[test]
    fn disk_budget_serializes_and_validates_processor_workspace_reserve_canonically() {
        let budget = DiskBudgetV2::new_with_processor_workspace(1, 2, 3, 4, 5).unwrap();
        assert_eq!(budget.allocation_unit_bytes, 1);
        assert_eq!(budget.processor_workspace_bytes, 4);
        assert_eq!(budget.reconcile_destination_bytes, 5);
        let expected_subtotal = 1 + 2 + 3 + 4 + 5 + 5 + JOURNAL_RESERVE_BYTES;
        assert_eq!(budget.safety_margin_bytes, MINIMUM_SAFETY_MARGIN_BYTES);
        assert_eq!(
            budget.required_bytes,
            expected_subtotal + MINIMUM_SAFETY_MARGIN_BYTES
        );
        budget.validate().unwrap();

        let mut value = serde_json::to_value(&budget).unwrap();
        assert_eq!(value["processorWorkspaceBytes"], 4);
        assert_eq!(value["allocationUnitBytes"], 1);
        assert_eq!(value["reconcileDestinationBytes"], 5);
        value
            .as_object_mut()
            .unwrap()
            .remove("processorWorkspaceBytes");
        assert!(serde_json::from_value::<DiskBudgetV2>(value).is_err());

        let mut value = serde_json::to_value(&budget).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("reconcileDestinationBytes");
        assert!(serde_json::from_value::<DiskBudgetV2>(value).is_err());

        let mut forged = budget;
        forged.processor_workspace_bytes += 1;
        assert!(forged.validate().is_err());
    }

    #[test]
    fn plan_binds_reconcile_destination_reserve_to_install_mutations() {
        let install_id = Uuid::new_v4();
        let mut plan = install_plan(install_id, BuildChannel::Stable);
        plan.disk_budget = DiskBudgetV2::new_with_physical_layout(
            plan.disk_budget.missing_download_bytes,
            plan.disk_budget.java_extracted_bytes,
            plan.disk_budget.game_extracted_bytes,
            plan.disk_budget.processor_workspace_bytes,
            plan.disk_budget.allocation_unit_bytes,
            plan.disk_budget.staging_bytes,
            plan.disk_budget.reconcile_destination_bytes + 1,
        )
        .unwrap();
        assert_eq!(
            plan.validate(install_id, BuildChannel::Stable).unwrap_err(),
            "Disk budget reconcile destination bytes do not match install mutations"
        );

        let mut noncanonical = install_plan(install_id, BuildChannel::Stable);
        noncanonical.disk_budget.reconcile_destination_bytes += 1;
        assert_eq!(
            noncanonical
                .validate(install_id, BuildChannel::Stable)
                .unwrap_err(),
            "Reconcile disk budget is not canonical"
        );
    }

    #[test]
    fn plan_binds_reconcile_files_to_its_physical_allocation_unit() {
        let install_id = Uuid::new_v4();
        let mut plan = install_plan(install_id, BuildChannel::Stable);
        plan.disk_budget =
            DiskBudgetV2::new_with_physical_layout(0, 0, 0, 0, 4096, 8 * 4096, 10 * 4096).unwrap();
        plan.validate(install_id, BuildChannel::Stable).unwrap();

        plan.disk_budget = DiskBudgetV2::new_with_physical_layout(
            0,
            0,
            0,
            0,
            64 * 1024,
            8 * 64 * 1024,
            10 * 64 * 1024,
        )
        .unwrap();
        plan.validate(install_id, BuildChannel::Stable).unwrap();

        assert!(DiskBudgetV2::new_with_allocation_unit(0, 0, 0, 0, 0, 0).is_err());
        assert!(DiskBudgetV2::new_with_allocation_unit(0, 0, 0, 0, 3, 0).is_err());
    }

    #[test]
    fn namespace_reserve_covers_two_hundred_thousand_zero_byte_replacements() {
        for allocation_unit in [4096_u64, 64 * 1024] {
            let installs = 200_000_u64;
            let quarantines = 200_000_u64;
            let staging_entries = installs * 2 + 5;
            let destination_entries = 5 + quarantines + installs * 2;
            let staging = staging_entries * allocation_unit;
            let destination = destination_entries * allocation_unit;
            let budget = DiskBudgetV2::new_with_physical_layout(
                0,
                0,
                0,
                0,
                allocation_unit,
                staging,
                destination,
            )
            .unwrap();
            assert_eq!(budget.staging_bytes, staging);
            assert_eq!(budget.reconcile_destination_bytes, destination);
            assert!(budget.staging_bytes > MINIMUM_SAFETY_MARGIN_BYTES);
            budget.validate().unwrap();
        }
    }

    #[test]
    fn exact_staging_resume_keeps_dynamic_commit_and_safety_reserves() {
        let budget = DiskBudgetV2::new_with_processor_workspace(11, 13, 17, 19, 1_000_000).unwrap();
        let remaining_destination = 23;
        let expected_subtotal = 11 + 13 + 17 + 19 + remaining_destination + JOURNAL_RESERVE_BYTES;
        assert_eq!(
            budget
                .required_after_exact_staging(remaining_destination)
                .unwrap(),
            expected_subtotal + MINIMUM_SAFETY_MARGIN_BYTES
        );
        assert!(budget.required_after_exact_staging(u64::MAX).is_err());

        let large = DiskBudgetV2::new(0, 0, 0, 16 * 1024 * 1024 * 1024).unwrap();
        assert!(large.safety_margin_bytes > MINIMUM_SAFETY_MARGIN_BYTES);
        assert_eq!(
            large.required_after_exact_staging(31).unwrap(),
            31 + large.journal_reserve_bytes + large.safety_margin_bytes
        );

        let mut forged = budget;
        forged.reconcile_destination_bytes += 1;
        assert!(forged.required_after_exact_staging(0).is_err());
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
            successor: None,
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
    fn fresh_ready_authorization_abandons_stale_pointer_with_exact_active_continuation() {
        let root = temp_root("fresh-ready-abandon");
        let install_id = Uuid::new_v4();
        fs::create_dir_all(&root).unwrap();
        let state = InstanceStateStore::new(&root, install_id);
        let lock = state.acquire_operation_lock(BuildChannel::Stable).unwrap();
        let stale = install_plan(install_id, BuildChannel::Stable);
        let pointer =
            write_immutable_plan(&root, install_id, BuildChannel::Stable, &lock, &stale).unwrap();
        publish_pending(&root, install_id, BuildChannel::Stable, &lock, &pointer).unwrap();
        state.save_locked(&lock, &stale.target).unwrap();
        let authorization = CurrentReadyAbandonAuthorizationV2::for_test(&stale, &stale.target);
        assert!(abandon_stale_pending_for_current_ready(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &pointer,
            authorization,
        )
        .unwrap());
        assert!(
            detect_pending(&root, install_id, BuildChannel::Stable, &lock)
                .unwrap()
                .is_none()
        );
        assert!(!abandon_stale_pending_for_current_ready(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &pointer,
            CurrentReadyAbandonAuthorizationV2::for_test(&stale, &stale.target),
        )
        .unwrap());

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
    fn maintenance_removes_unpublished_root_and_orphan_journal_files() {
        let root = temp_root("maintenance-orphans");
        let install_id = Uuid::new_v4();
        fs::create_dir_all(&root).unwrap();
        let state = InstanceStateStore::new(&root, install_id);
        let lock = state.acquire_operation_lock(BuildChannel::Stable).unwrap();
        let orphan = Uuid::new_v4();
        let operation_root = root.join(format!("state/reconcile/stable/operations/{orphan}"));
        fs::create_dir_all(operation_root.join("staging")).unwrap();
        fs::write(operation_root.join("staging/00000000.bin"), b"stale").unwrap();
        let journal_root = root.join("state/journals/stable");
        fs::create_dir_all(journal_root.join("plans")).unwrap();
        fs::create_dir_all(journal_root.join("completions")).unwrap();
        fs::create_dir_all(journal_root.join("temporary")).unwrap();
        let artifact = format!("{orphan}-{HASH_A}.json");
        let orphan_plan = journal_root.join("plans").join(&artifact);
        fs::write(&orphan_plan, b"orphan plan").unwrap();
        fs::write(
            journal_root.join("completions").join(&artifact),
            b"orphan completion",
        )
        .unwrap();
        fs::write(
            journal_root
                .join("temporary")
                .join(format!("journal-{orphan}.tmp")),
            b"temporary",
        )
        .unwrap();

        let report =
            maintain_completed_reconcile_state(&root, install_id, BuildChannel::Stable, &lock)
                .unwrap();
        assert_eq!(report.operation_roots_removed, 1);
        assert_eq!(report.completion_histories_removed, 1);
        assert_eq!(report.orphan_plans_removed, 1);
        assert_eq!(report.temporary_files_removed, 1);
        assert!(!operation_root.exists());
        assert!(fs::read_dir(journal_root.join("plans"))
            .unwrap()
            .next()
            .is_none());

        drop(lock);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn maintenance_protects_pending_bundle_and_removes_failed_replacement_staging() {
        let root = temp_root("maintenance-pending-window");
        let install_id = Uuid::new_v4();
        fs::create_dir_all(&root).unwrap();
        let state = InstanceStateStore::new(&root, install_id);
        let lock = state.acquire_operation_lock(BuildChannel::Stable).unwrap();
        let plan = install_plan(install_id, BuildChannel::Stable);
        let pointer =
            write_immutable_plan(&root, install_id, BuildChannel::Stable, &lock, &plan).unwrap();
        publish_pending(&root, install_id, BuildChannel::Stable, &lock, &pointer).unwrap();
        let paths = JournalPaths::new(BuildChannel::Stable, &pointer).unwrap();
        let pointer_bytes =
            serialize_bounded(&pointer, MAX_POINTER_BYTES as usize, "test pointer").unwrap();
        let completion = JournalTombstoneV2 {
            schema_version: JOURNAL_SCHEMA_VERSION,
            install_id,
            channel: BuildChannel::Stable,
            completed_pointer: pointer.clone(),
            completed_pointer_sha256: format!("{:x}", Sha256::digest(pointer_bytes)),
            outcome: JournalCompletionOutcomeV2::CommittedTarget,
            continuation: Some(plan.target.clone()),
            successor: None,
        };
        let completion_bytes =
            serialize_bounded(&completion, MAX_POINTER_BYTES as usize, "test completion").unwrap();
        publish_immutable_file(
            &root,
            &paths.temporary,
            &paths.completion,
            &completion_bytes,
            true,
        )
        .unwrap();
        let current_root = root.join(format!(
            "state/reconcile/stable/operations/{}",
            plan.operation_id
        ));
        fs::create_dir_all(current_root.join("staging")).unwrap();
        fs::write(current_root.join("staging/current.bin"), b"current").unwrap();

        let stale = Uuid::new_v4();
        let stale_root = root.join(format!("state/reconcile/stable/operations/{stale}"));
        fs::create_dir_all(stale_root.join("staging")).unwrap();
        fs::write(stale_root.join("staging/00000000.bin"), b"stale").unwrap();
        let stale_plan = root.join(format!("state/journals/stable/plans/{stale}-{HASH_A}.json"));
        fs::write(&stale_plan, b"unpublished replacement plan").unwrap();
        let report =
            maintain_completed_reconcile_state(&root, install_id, BuildChannel::Stable, &lock)
                .unwrap();
        assert_eq!(report.operation_roots_removed, 1);
        assert_eq!(report.orphan_plans_removed, 1);
        assert!(current_root.is_dir());
        assert!(!stale_root.exists());
        assert!(!stale_plan.exists());
        assert!(paths.plan.join_to(&root).is_file());
        assert!(paths.completion.join_to(&root).is_file());
        assert_eq!(
            fs::read(paths.pending.join_to(&root)).unwrap(),
            serialize_bounded(&pointer, MAX_POINTER_BYTES as usize, "test pointer").unwrap()
        );

        drop(lock);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn operation_garbage_policy_covers_max_release_shape_and_rejects_expansion() {
        let limits = operation_garbage_limits_for_release_policy(
            MAX_FILES_PER_PRESET,
            MAX_RELEASE_PATH_COMPONENTS,
        )
        .unwrap();
        let expected_mutation_entries = MAX_MUTATIONS
            .checked_mul(MAX_OPERATION_BASE_ENTRIES_PER_MUTATION)
            .unwrap();
        let expected_entries = MAX_FILES_PER_PRESET
            .checked_mul(MAX_OPERATION_EXTRA_ENTRIES_PER_INSTALL)
            .and_then(|entries| entries.checked_add(expected_mutation_entries))
            .and_then(|entries| entries.checked_add(MAX_RELEASE_PATH_COMPONENTS))
            .and_then(|entries| entries.checked_add(MAX_OPERATION_FIXED_ENTRIES))
            .unwrap();
        let expected_overhead = u64::try_from(expected_entries)
            .unwrap()
            .checked_mul(MAX_OPERATION_ALLOCATION_OVERHEAD_PER_ENTRY)
            .unwrap();
        let expected_bytes = MAX_PLAN_FILE_BYTES
            .checked_mul(MAX_OPERATION_PLAN_BYTE_COPIES)
            .and_then(|bytes| bytes.checked_add(expected_overhead))
            .unwrap();

        assert_eq!(limits.max_entries, expected_entries);
        assert_eq!(limits.max_allocated_bytes, expected_bytes);
        assert_eq!(
            limits.max_depth,
            MAX_RELATIVE_PATH_SEGMENTS + MAX_OPERATION_RELOCATED_PATH_DEPTH_OVERHEAD
        );
        assert_eq!(limits, operation_garbage_limits().unwrap());
        assert!(operation_garbage_limits_for_release_policy(
            MAX_FILES_PER_PRESET + 1,
            MAX_RELEASE_PATH_COMPONENTS,
        )
        .is_err());
        assert!(operation_garbage_limits_for_release_policy(
            MAX_FILES_PER_PRESET,
            MAX_RELEASE_PATH_COMPONENTS + 1,
        )
        .is_err());
        assert!(operation_garbage_limits_for_release_policy(usize::MAX, usize::MAX).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn operation_garbage_policy_accepts_exact_relocated_depth_and_rejects_one_more() {
        fn create_depth(root: &Path, relative: &RelativeManagedPath, deepest: usize) -> PathBuf {
            let mut current = relative.join_to(root);
            fs::create_dir_all(&current).unwrap();
            for _ in 1..deepest {
                current.push("d");
                fs::create_dir(&current).unwrap();
            }
            current.push("leaf.bin");
            fs::write(&current, b"leaf").unwrap();
            current
        }

        let root = temp_root("operation-garbage-depth");
        fs::create_dir_all(&root).unwrap();
        let limits = operation_garbage_limits().unwrap();
        let exact = RelativeManagedPath::new(&format!(
            "state/reconcile/stable/operations/{}",
            Uuid::new_v4()
        ))
        .unwrap();
        create_depth(&root, &exact, limits.max_depth);
        let exact_identity = inspect_managed_garbage_node_nofollow(&root, &exact).unwrap();
        remove_bounded_managed_garbage_tree(&root, &exact, &exact_identity, limits).unwrap();
        assert!(!exact.join_to(&root).exists());

        let over = RelativeManagedPath::new(&format!(
            "state/reconcile/stable/operations/{}",
            Uuid::new_v4()
        ))
        .unwrap();
        let over_leaf = create_depth(&root, &over, limits.max_depth + 1);
        let over_identity = inspect_managed_garbage_node_nofollow(&root, &over).unwrap();
        assert!(remove_bounded_managed_garbage_tree(&root, &over, &over_identity, limits).is_err());
        assert!(over_leaf.is_file());
        assert!(over.join_to(&root).is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn plan_path_segment_bound_matches_prefixed_executor_materialization() {
        fn path_with_segments(count: usize) -> String {
            assert!(count >= 2);
            let mut segments = Vec::with_capacity(count);
            segments.push("mods".to_string());
            for index in 1..count - 1 {
                segments.push(format!("d{index}"));
            }
            segments.push("fragment.jar".to_string());
            segments.join("/")
        }

        let install_id = Uuid::new_v4();
        let mut accepted = install_plan(install_id, BuildChannel::Stable);
        let accepted_path = path_with_segments(MAX_RELATIVE_PATH_SEGMENTS);
        accepted.desired_files[0].path = accepted_path.clone();
        let JournalMutation::InstallFile {
            destination_path, ..
        } = accepted.mutations.last_mut().unwrap()
        else {
            panic!("fixture must end with install")
        };
        *destination_path = accepted_path;
        accepted.validate(install_id, BuildChannel::Stable).unwrap();

        let mut rejected = accepted;
        let rejected_path = path_with_segments(MAX_RELATIVE_PATH_SEGMENTS + 1);
        rejected.desired_files[0].path = rejected_path.clone();
        let JournalMutation::InstallFile {
            destination_path, ..
        } = rejected.mutations.last_mut().unwrap()
        else {
            panic!("fixture must end with install")
        };
        *destination_path = rejected_path;
        assert!(rejected.validate(install_id, BuildChannel::Stable).is_err());
        assert!(validate_desired_file_policy_count(MAX_FILES_PER_PRESET).is_ok());
        assert!(validate_desired_file_policy_count(MAX_FILES_PER_PRESET + 1).is_err());
        assert_eq!(
            checked_reconcile_path_component_total(MAX_RELEASE_PATH_COMPONENTS - 1, 1).unwrap(),
            MAX_RELEASE_PATH_COMPONENTS
        );
        assert!(checked_reconcile_path_component_total(MAX_RELEASE_PATH_COMPONENTS, 1).is_err());
        assert!(checked_reconcile_path_component_total(usize::MAX, 1).is_err());
        assert_eq!(
            checked_desired_file_bytes(
                MAX_MANAGED_RELEASE_BYTES - MAX_MANAGED_FILE_BYTES,
                MAX_MANAGED_FILE_BYTES,
            )
            .unwrap(),
            MAX_MANAGED_RELEASE_BYTES
        );
        assert!(checked_desired_file_bytes(MAX_MANAGED_RELEASE_BYTES, 1).is_err());
        assert!(checked_desired_file_bytes(u64::MAX, 1).is_err());
    }

    #[test]
    fn durable_current_plan_transition_is_detected_and_protected_before_pointer_swap() {
        let root = temp_root("durable-transition");
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
        let mut successor = install_plan(install_id, BuildChannel::Stable);
        successor.operation_id = Uuid::new_v4();
        let successor_pointer =
            write_immutable_plan(&root, install_id, BuildChannel::Stable, &lock, &successor)
                .unwrap();
        let failed_paths = JournalPaths::new(BuildChannel::Stable, &failed_pointer).unwrap();
        let failed_pointer_bytes = serialize_bounded(
            &failed_pointer,
            MAX_POINTER_BYTES as usize,
            "failed pointer",
        )
        .unwrap();
        let completion = JournalTombstoneV2 {
            schema_version: JOURNAL_SCHEMA_VERSION,
            install_id,
            channel: BuildChannel::Stable,
            completed_pointer: failed_pointer.clone(),
            completed_pointer_sha256: format!("{:x}", Sha256::digest(failed_pointer_bytes)),
            outcome: JournalCompletionOutcomeV2::SupersededForCurrentPlan,
            continuation: None,
            successor: Some(successor_pointer.clone()),
        };
        let completion_bytes = serialize_bounded(
            &completion,
            MAX_POINTER_BYTES as usize,
            "transition completion",
        )
        .unwrap();
        publish_immutable_file(
            &root,
            &failed_paths.temporary,
            &failed_paths.completion,
            &completion_bytes,
            true,
        )
        .unwrap();
        for operation in [failed.operation_id, successor.operation_id] {
            let path = root.join(format!("state/reconcile/stable/operations/{operation}"));
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("state.bin"), b"protected").unwrap();
        }

        let transition = detect_pending_transition(&root, install_id, BuildChannel::Stable, &lock)
            .unwrap()
            .unwrap();
        assert_eq!(transition.pending.pointer, failed_pointer);
        assert_eq!(
            transition.durable_successor.unwrap().pointer,
            successor_pointer
        );
        let report =
            maintain_completed_reconcile_state(&root, install_id, BuildChannel::Stable, &lock)
                .unwrap();
        assert_eq!(report.operation_roots_removed, 0);
        assert!(root
            .join(format!(
                "state/reconcile/stable/operations/{}",
                failed.operation_id
            ))
            .is_dir());
        assert!(root
            .join(format!(
                "state/reconcile/stable/operations/{}",
                successor.operation_id
            ))
            .is_dir());
        assert!(failed_paths.completion.join_to(&root).is_file());
        assert!(JournalPaths::new(BuildChannel::Stable, &successor_pointer)
            .unwrap()
            .plan
            .join_to(&root)
            .is_file());
        let mut third = install_plan(install_id, BuildChannel::Stable);
        third.operation_id = Uuid::new_v4();
        let third_pointer =
            write_immutable_plan(&root, install_id, BuildChannel::Stable, &lock, &third).unwrap();
        assert!(advance_pending_to_recorded_successor(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &failed_pointer,
            &third_pointer,
        )
        .is_err());
        let advanced = advance_pending_to_recorded_successor(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &failed_pointer,
            &successor_pointer,
        )
        .unwrap();
        assert_eq!(advanced.pointer, successor_pointer);
        assert_eq!(
            detect_pending(&root, install_id, BuildChannel::Stable, &lock)
                .unwrap()
                .unwrap()
                .pointer,
            successor_pointer
        );
        assert_eq!(
            advance_pending_to_recorded_successor(
                &root,
                install_id,
                BuildChannel::Stable,
                &lock,
                &failed_pointer,
                &successor_pointer,
            )
            .unwrap()
            .pointer,
            successor_pointer
        );
        let pending_path = journal_pending_path(BuildChannel::Stable)
            .unwrap()
            .join_to(&root);
        let third_pointer_bytes =
            serialize_bounded(&third_pointer, MAX_POINTER_BYTES as usize, "third pointer").unwrap();
        fs::write(&pending_path, &third_pointer_bytes).unwrap();
        assert!(advance_pending_to_recorded_successor(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &failed_pointer,
            &successor_pointer,
        )
        .is_err());
        let successor_pointer_bytes = serialize_bounded(
            &successor_pointer,
            MAX_POINTER_BYTES as usize,
            "successor pointer",
        )
        .unwrap();
        fs::write(&pending_path, &successor_pointer_bytes).unwrap();

        let mut forged_completion = completion.clone();
        forged_completion.successor = Some(third_pointer.clone());
        let forged_completion_bytes = serialize_bounded(
            &forged_completion,
            MAX_POINTER_BYTES as usize,
            "forged transition completion",
        )
        .unwrap();
        fs::write(
            failed_paths.completion.join_to(&root),
            forged_completion_bytes,
        )
        .unwrap();
        assert!(advance_pending_to_recorded_successor(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &failed_pointer,
            &successor_pointer,
        )
        .is_err());
        fs::write(failed_paths.completion.join_to(&root), &completion_bytes).unwrap();

        state.save_locked(&lock, &failed.target).unwrap();
        assert!(advance_pending_to_recorded_successor(
            &root,
            install_id,
            BuildChannel::Stable,
            &lock,
            &failed_pointer,
            &successor_pointer,
        )
        .is_err());

        drop(lock);
        drop(state);
        fs::remove_dir_all(root).unwrap();
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
