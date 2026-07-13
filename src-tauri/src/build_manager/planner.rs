use super::{
    artifact_plan::{ArtifactInventoryV2, ArtifactPlanV2, MutableBootstrapPlanV2},
    availability::VerifiedAvailabilityV2,
    contracts::{
        GameRuntimeLock, GameRuntimeRole, GameRuntimeSource, NormalizedProcessorArgument,
        OfflineProcessorVerification, ProcessorInput, ProcessorMaterializationAccess, RuntimeLock,
    },
    instance_state::ActiveInstanceV2,
    journal::{DiskBudgetV2, JournalMutation, OperationKind, PlannedFileV2, ReconcilePlanV2},
    managed_fs::FileIdentity,
    reconcile_executor::UntrustedPendingIdentityV2,
    reconciler::{InstanceAudit, ReconcilePlanAuditV2},
    release::{FilePolicy, ManifestFile},
    storage::OwnedCasRoot,
    tuf::TrustedRelease,
    types::{BuildChannel, PresetId},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
use thiserror::Error;
use uuid::{Uuid, Version};

const RECONCILE_PLAN_SCHEMA_VERSION: u8 = 2;
// These are executor-enforced maxima, not estimates derived from host free-space behavior. The
// processor owns two independently writable trees (`temp` and `state/user-home`) and a bounded
// state marker. Everything else in the processor workspace budget comes from the signed lock.
const PROCESSOR_SCRATCH_TREE_BYTES: u64 = 256 * 1024 * 1024;
const PROCESSOR_SCRATCH_TREE_COUNT: u64 = 2;
const PROCESSOR_SCRATCH_ENTRY_COUNT: u64 = 512;
const PROCESSOR_STATE_MARKER_RESERVE_BYTES: u64 = 256 * 1024;
const PROCESSOR_EMERGENCY_RECOVERY_RESERVE_BYTES: u64 = 64 * 1024 * 1024;
const PROCESSOR_WORKSPACE_NAMESPACE_ENTRIES: u64 = 1_417;
const JAVA_GENERATION_MARKER_RESERVE_BYTES: u64 = 16 * 1024;
const JAVA_GENERATION_FIXED_NAMESPACE_ENTRIES: u64 = 8;
const GAME_GENERATION_MARKER_RESERVE_BYTES: u64 = 64 * 1024;
const GAME_GENERATION_FIXED_NAMESPACE_ENTRIES: u64 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PlannedBuildState {
    Download,
    Update,
    Repair,
    Ready,
}

#[derive(Debug, PartialEq, Eq)]
struct CanonicalDiskBudgetBindingV2 {
    install_id: Uuid,
    operation_id: Uuid,
    channel: BuildChannel,
    plan_sha256: String,
    root_binding_nonce: Uuid,
    install_root_identity: FileIdentity,
    objects_root_identity: FileIdentity,
    inventory_fingerprint: String,
}

/// Non-serializable authority to enforce exactly one freshly planned disk budget.
///
/// The serialized `DiskBudgetV2` inside a journal is only a crash record: dynamic availability
/// inputs cannot be reconstructed from that record. This capability has private construction and
/// is emitted only alongside a fresh `plan_build`; every use revalidates the exact canonical plan,
/// operation, artifact inventory and leased CAS root before exposing its required byte count.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct CanonicalDiskBudgetAuthorityV2 {
    binding: CanonicalDiskBudgetBindingV2,
    budget: DiskBudgetV2,
    artifact_plan: ArtifactPlanV2,
}

/// A same-root free-space measurement made by a validated budget authority. Its fields and
/// constructor are private so callers cannot substitute a stale snapshot or an arbitrary value.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct DiskSpaceAssessmentV2 {
    available_bytes: u64,
    required_bytes: u64,
}

impl DiskSpaceAssessmentV2 {
    pub(super) fn available_bytes(&self) -> u64 {
        self.available_bytes
    }

    pub(super) fn required_bytes(&self) -> u64 {
        self.required_bytes
    }

    pub(super) fn fits(&self) -> bool {
        self.available_bytes >= self.required_bytes
    }
}

impl CanonicalDiskBudgetAuthorityV2 {
    fn seal(
        plan: &ReconcilePlanV2,
        artifact_plan: ArtifactPlanV2,
        inventory: &ArtifactInventoryV2,
        root: &OwnedCasRoot,
    ) -> Result<Self, String> {
        plan.validate(plan.install_id, plan.channel)?;
        inventory.validate_root(root)?;
        artifact_plan.validate_for(inventory)?;
        let plan_sha256 = canonical_plan_sha256(plan)?;
        let (root_binding_nonce, root_install_id, install_identity, objects_identity) =
            root.binding();
        let allocation_unit_bytes = filesystem_allocation_unit(root.install_root())
            .map_err(|error| format!("Cannot query planned allocation unit: {error}"))?;
        if root_install_id != plan.install_id
            || root_binding_nonce != inventory.root_binding_nonce()
            || plan.disk_budget.allocation_unit_bytes != allocation_unit_bytes
            || plan.disk_budget.missing_download_bytes
                != artifact_plan.validated_disk_download_reserve_bytes(root, inventory)?
        {
            return Err("Disk budget authority root differs from its planned operation".into());
        }
        let authority = Self {
            binding: CanonicalDiskBudgetBindingV2 {
                install_id: plan.install_id,
                operation_id: plan.operation_id,
                channel: plan.channel,
                plan_sha256,
                root_binding_nonce,
                install_root_identity: install_identity.clone(),
                objects_root_identity: objects_identity.clone(),
                inventory_fingerprint: inventory.fingerprint().to_owned(),
            },
            budget: plan.disk_budget.clone(),
            artifact_plan,
        };
        authority.validate_for(plan, inventory, root)?;
        Ok(authority)
    }

    pub(super) fn validate_for(
        &self,
        plan: &ReconcilePlanV2,
        inventory: &ArtifactInventoryV2,
        root: &OwnedCasRoot,
    ) -> Result<(), String> {
        plan.validate(plan.install_id, plan.channel)?;
        inventory.validate_root(root)?;
        self.artifact_plan.validate_for(inventory)?;
        let (root_binding_nonce, root_install_id, install_identity, objects_identity) =
            root.binding();
        let allocation_unit_bytes = filesystem_allocation_unit(root.install_root())
            .map_err(|error| format!("Cannot requery planned allocation unit: {error}"))?;
        if self.binding.install_id != plan.install_id
            || self.binding.operation_id != plan.operation_id
            || self.binding.channel != plan.channel
            || root_install_id != plan.install_id
            || self.binding.root_binding_nonce != root_binding_nonce
            || self.binding.root_binding_nonce != inventory.root_binding_nonce()
            || self.binding.install_root_identity != *install_identity
            || self.binding.objects_root_identity != *objects_identity
            || self.binding.inventory_fingerprint != inventory.fingerprint()
            || self.budget.allocation_unit_bytes != allocation_unit_bytes
            || self.budget.missing_download_bytes
                != self
                    .artifact_plan
                    .validated_disk_download_reserve_bytes(root, inventory)?
        {
            return Err("Disk budget authority belongs to another operation or CAS root".into());
        }
        if self.binding.plan_sha256 != canonical_plan_sha256(plan)? {
            return Err("Disk budget authority canonical plan digest changed".into());
        }
        if self.budget != plan.disk_budget {
            return Err("Disk budget authority record changed".into());
        }
        root.revalidate()?;
        Ok(())
    }

    pub(super) fn canonical_budget_for<'a>(
        &'a self,
        plan: &ReconcilePlanV2,
        inventory: &ArtifactInventoryV2,
        root: &OwnedCasRoot,
    ) -> Result<&'a DiskBudgetV2, String> {
        self.validate_for(plan, inventory, root)?;
        Ok(&self.budget)
    }

    pub(super) fn artifact_plan_for<'a>(
        &'a self,
        plan: &ReconcilePlanV2,
        inventory: &ArtifactInventoryV2,
        root: &OwnedCasRoot,
    ) -> Result<&'a ArtifactPlanV2, String> {
        self.validate_for(plan, inventory, root)?;
        Ok(&self.artifact_plan)
    }

    /// Measures the filesystem bound into this authority; no caller-supplied free-space value is
    /// accepted. Root revalidation brackets the OS query so a replaced/rebound path fails closed.
    pub(super) fn assess_space_for(
        &self,
        plan: &ReconcilePlanV2,
        inventory: &ArtifactInventoryV2,
        root: &OwnedCasRoot,
    ) -> Result<DiskSpaceAssessmentV2, String> {
        let required_bytes = self
            .canonical_budget_for(plan, inventory, root)?
            .required_bytes;
        root.revalidate()?;
        let available_bytes = fs2::available_space(root.install_root())
            .map_err(|error| format!("Cannot query bound install free space: {error}"))?;
        // A credited sparse/partial object is dynamic capacity state just like free space. Repeat
        // the complete authority validation after the OS query so truncate/replacement/allocation
        // drift in the measurement window fails closed.
        self.validate_for(plan, inventory, root)?;
        Ok(DiskSpaceAssessmentV2 {
            available_bytes,
            required_bytes,
        })
    }
}

fn canonical_plan_sha256(plan: &ReconcilePlanV2) -> Result<String, String> {
    Ok(format!("{:x}", Sha256::digest(plan.canonical_bytes()?)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MutableMaterializationProofV2 {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    /// True only after the named native validator proved that the current file equals the
    /// canonical materialization represented by `size` and `sha256`.
    pub current_matches: bool,
}

pub(super) struct PlannerRequestV2<'a> {
    pub install_id: Uuid,
    pub channel: BuildChannel,
    pub preset: PresetId,
    pub operation_id: Uuid,
    pub trusted_release: &'a TrustedRelease,
    pub artifact_inventory: &'a ArtifactInventoryV2,
    pub cas_root: &'a OwnedCasRoot,
    pub installed: Option<&'a ActiveInstanceV2>,
    pub audit: &'a InstanceAudit,
    pub mutable_files: &'a [MutableMaterializationProofV2],
    pub availability: &'a VerifiedAvailabilityV2,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct PlannedBuildV2 {
    pub state: PlannedBuildState,
    pub plan: Option<ReconcilePlanV2>,
    /// Informational crash/display record. It cannot authorize filesystem mutation.
    pub disk_budget_record: DiskBudgetV2,
    /// Present only for a fresh non-ready plan and impossible to deserialize from a journal.
    pub disk_budget_authority: Option<CanonicalDiskBudgetAuthorityV2>,
}

/// A fresh, planner-derived update which is allowed to replace a failed committed old journal.
/// Its non-serializable disk authority proves that ordinary callers did not construct the plan
/// from journal JSON. The coordinator must finish downloads, runtime generation and exact staging
/// before asking the journal to publish this replacement.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct PreparedCurrentPlanV2 {
    plan: ReconcilePlanV2,
    disk_budget_authority: CanonicalDiskBudgetAuthorityV2,
}

impl PreparedCurrentPlanV2 {
    pub(super) fn plan(&self) -> &ReconcilePlanV2 {
        &self.plan
    }

    pub(super) fn disk_budget_authority(&self) -> &CanonicalDiskBudgetAuthorityV2 {
        &self.disk_budget_authority
    }

    pub(super) fn artifact_plan(&self) -> &ArtifactPlanV2 {
        &self.disk_budget_authority.artifact_plan
    }

    fn validate_for(
        &self,
        failed_plan: &ReconcilePlanV2,
        observed_active: Option<&ActiveInstanceV2>,
        fresh_release: &TrustedRelease,
        inventory: &ArtifactInventoryV2,
        root: &OwnedCasRoot,
    ) -> Result<(), PlannerError> {
        failed_plan
            .validate(failed_plan.install_id, failed_plan.channel)
            .map_err(PlannerError::Plan)?;
        validate_trusted_release(fresh_release, failed_plan.channel)?;
        self.plan
            .validate(failed_plan.install_id, failed_plan.channel)
            .map_err(PlannerError::Plan)?;
        self.disk_budget_authority
            .validate_for(&self.plan, inventory, root)
            .map_err(PlannerError::Plan)?;
        if self.plan.operation_id == failed_plan.operation_id
            || self.plan.base.as_ref() != observed_active
            || !marker_binds_current_content(&self.plan.target, fresh_release, failed_plan.channel)
            || fresh_release
                .manifest()
                .selected_preset(self.plan.target.preset)
                .is_err()
        {
            return Err(PlannerError::Plan(
                "Prepared recovery plan is not the fresh signed successor of the observed state"
                    .into(),
            ));
        }
        root.revalidate().map_err(PlannerError::Availability)
    }
}

pub(super) struct CurrentPlanSupersedeRequestV2<'a> {
    pub failed_plan: &'a ReconcilePlanV2,
    pub active_marker: Option<&'a ActiveInstanceV2>,
    pub fresh_release: &'a TrustedRelease,
    /// Required only while the pending target still equals signed current. Stale targets are
    /// never audited or executed and therefore leave this empty.
    pub current_final_audit: Option<&'a ReconcilePlanAuditV2>,
    pub current_final_mutable_files: &'a [MutableMaterializationProofV2],
    /// Sealed non-mutating classification minted only when fresh trust could not bind the local
    /// pending plan strongly enough to audit it. This can waive the failed-final-audit input, but
    /// it never authorizes a stale mutation or rollback path.
    pub untrusted_pending_identity: Option<&'a UntrustedPendingIdentityV2>,
    pub prepared_update: &'a PreparedCurrentPlanV2,
    pub artifact_inventory: &'a ArtifactInventoryV2,
    pub cas_root: &'a OwnedCasRoot,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum PlannerError {
    #[error("trusted release is invalid: {0}")]
    TrustedRelease(String),
    #[error("installed marker is invalid: {0}")]
    InstalledMarker(String),
    #[error("instance audit is contradictory or incomplete: {0}")]
    Audit(String),
    #[error("mutable-settings proof is invalid: {0}")]
    MutableProof(String),
    #[error("verified availability is invalid: {0}")]
    Availability(String),
    #[error("planner arithmetic overflowed while computing {0}")]
    Overflow(&'static str),
    #[error("reconcile plan is invalid: {0}")]
    Plan(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StagingFileProofV2 {
    pub staging_slot: u32,
    pub destination_path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug)]
pub(super) struct RecoveryRequestV2<'a> {
    pub plan: &'a ReconcilePlanV2,
    pub active_marker: Option<&'a ActiveInstanceV2>,
    pub fresh_release: &'a TrustedRelease,
    pub staging_files: &'a [StagingFileProofV2],
    pub final_audit: Option<&'a ReconcilePlanAuditV2>,
    pub final_mutable_files: &'a [MutableMaterializationProofV2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RollbackReasonV2 {
    StagingProofIncomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecoveryRequiredReasonV2 {
    InvalidPlan,
    InvalidFreshRelease,
    MarkerDiverged,
    FinalAuditRequired,
}

/// A non-serializable, operation-bound capability emitted only when the active marker is the
/// exact plan target but the mandatory final audit failed. The journal consumes this capability
/// to create a repair-only supersede outcome; ordinary callers cannot turn an arbitrary pending
/// operation into a repair continuation.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct RepairSupersedeAuthorizationV2 {
    install_id: Uuid,
    channel: BuildChannel,
    operation_id: Uuid,
    plan_sha256: String,
}

/// A non-serializable capability proving that recovery observed the exact committed target and
/// that its final immutable/mutable audit matched the plan.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct FinalizeCommitAuthorizationV2 {
    install_id: Uuid,
    channel: BuildChannel,
    operation_id: Uuid,
    plan_sha256: String,
}

/// Non-serializable authorization for the one atomic transition from a failed committed old
/// operation to a fully prepared update derived from the freshly trusted TUF release.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct CurrentPlanSupersedeAuthorizationV2 {
    install_id: Uuid,
    channel: BuildChannel,
    failed_operation_id: Uuid,
    failed_plan_sha256: String,
    update_operation_id: Uuid,
    update_plan_sha256: String,
    continuation: Option<ActiveInstanceV2>,
}

/// Non-serializable proof that the fresh signed planner observed the exact active marker and
/// classified the actual tree/runtimes as Ready while an unrelated stale journal remained.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct CurrentReadyAbandonAuthorizationV2 {
    install_id: Uuid,
    channel: BuildChannel,
    stale_operation_id: Uuid,
    stale_plan_sha256: String,
    continuation: ActiveInstanceV2,
}

impl RepairSupersedeAuthorizationV2 {
    fn for_failed_final_audit(plan: &ReconcilePlanV2, canonical_plan: &[u8]) -> Self {
        Self {
            install_id: plan.install_id,
            channel: plan.channel,
            operation_id: plan.operation_id,
            plan_sha256: format!("{:x}", Sha256::digest(canonical_plan)),
        }
    }

    pub(super) fn validate_for(
        &self,
        pointer: &super::journal::JournalPointerV2,
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
            return Err(
                "Repair supersede authorization belongs to another reconcile operation".into(),
            );
        }
        let canonical = plan.canonical_bytes()?;
        if format!("{:x}", Sha256::digest(canonical)) != self.plan_sha256 {
            return Err("Repair supersede authorization plan digest changed".into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn for_failed_final_audit_test(plan: &ReconcilePlanV2) -> Self {
        let canonical = plan
            .canonical_bytes()
            .expect("test supersede plan must be canonical");
        Self::for_failed_final_audit(plan, &canonical)
    }
}

impl FinalizeCommitAuthorizationV2 {
    fn for_exact_final_audit(plan: &ReconcilePlanV2, canonical_plan: &[u8]) -> Self {
        Self {
            install_id: plan.install_id,
            channel: plan.channel,
            operation_id: plan.operation_id,
            plan_sha256: format!("{:x}", Sha256::digest(canonical_plan)),
        }
    }

    pub(super) fn validate_for(
        &self,
        pointer: &super::journal::JournalPointerV2,
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
            return Err("Commit authorization belongs to another reconcile operation".into());
        }
        let canonical = plan.canonical_bytes()?;
        if format!("{:x}", Sha256::digest(canonical)) != self.plan_sha256 {
            return Err("Commit authorization plan digest changed".into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn for_exact_final_audit_test(plan: &ReconcilePlanV2) -> Self {
        let canonical = plan
            .canonical_bytes()
            .expect("test commit plan must be canonical");
        Self::for_exact_final_audit(plan, &canonical)
    }
}

impl CurrentPlanSupersedeAuthorizationV2 {
    fn seal(
        failed_plan: &ReconcilePlanV2,
        update_plan: &ReconcilePlanV2,
        continuation: Option<&ActiveInstanceV2>,
    ) -> Result<Self, String> {
        Ok(Self {
            install_id: failed_plan.install_id,
            channel: failed_plan.channel,
            failed_operation_id: failed_plan.operation_id,
            failed_plan_sha256: canonical_plan_sha256(failed_plan)?,
            update_operation_id: update_plan.operation_id,
            update_plan_sha256: canonical_plan_sha256(update_plan)?,
            continuation: continuation.cloned(),
        })
    }

    pub(super) fn validate_for(
        &self,
        failed_pointer: &super::journal::JournalPointerV2,
        failed_plan: &ReconcilePlanV2,
        update_plan: &ReconcilePlanV2,
    ) -> Result<(), String> {
        if self.install_id != failed_plan.install_id
            || self.channel != failed_plan.channel
            || self.failed_operation_id != failed_plan.operation_id
            || self.update_operation_id != update_plan.operation_id
            || failed_pointer.install_id != self.install_id
            || failed_pointer.channel != self.channel
            || failed_pointer.operation_id != self.failed_operation_id
            || failed_pointer.plan_sha256 != self.failed_plan_sha256
            || canonical_plan_sha256(failed_plan)? != self.failed_plan_sha256
            || canonical_plan_sha256(update_plan)? != self.update_plan_sha256
            || update_plan.base != self.continuation
        {
            return Err(
                "Current-update supersede authorization belongs to another reconcile transition"
                    .into(),
            );
        }
        Ok(())
    }

    pub(super) fn continuation(&self) -> Option<&ActiveInstanceV2> {
        self.continuation.as_ref()
    }
}

impl CurrentReadyAbandonAuthorizationV2 {
    fn seal(stale_plan: &ReconcilePlanV2, continuation: &ActiveInstanceV2) -> Result<Self, String> {
        Ok(Self {
            install_id: stale_plan.install_id,
            channel: stale_plan.channel,
            stale_operation_id: stale_plan.operation_id,
            stale_plan_sha256: canonical_plan_sha256(stale_plan)?,
            continuation: continuation.clone(),
        })
    }

    pub(super) fn validate_for(
        &self,
        stale_pointer: &super::journal::JournalPointerV2,
        stale_plan: &ReconcilePlanV2,
    ) -> Result<(), String> {
        if self.install_id != stale_plan.install_id
            || self.channel != stale_plan.channel
            || self.stale_operation_id != stale_plan.operation_id
            || stale_pointer.install_id != self.install_id
            || stale_pointer.channel != self.channel
            || stale_pointer.operation_id != self.stale_operation_id
            || stale_pointer.plan_sha256 != self.stale_plan_sha256
            || canonical_plan_sha256(stale_plan)? != self.stale_plan_sha256
        {
            return Err(
                "Fresh-ready abandon authorization belongs to another stale journal".into(),
            );
        }
        Ok(())
    }

    pub(super) fn continuation(&self) -> &ActiveInstanceV2 {
        &self.continuation
    }

    #[cfg(test)]
    pub(super) fn for_test(stale_plan: &ReconcilePlanV2, continuation: &ActiveInstanceV2) -> Self {
        Self::seal(stale_plan, continuation).expect("test stale plan must be canonical")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RecoveryDecisionV2 {
    RollForward,
    FinalizeCommittedTarget(FinalizeCommitAuthorizationV2),
    /// TUF advanced beyond the local pending target, so the old recovery record is no longer an
    /// authority for audit, roll-forward or rollback. The coordinator must build and fully stage a
    /// fresh `Update` before atomically superseding the old journal.
    PrepareCurrentPlan,
    RollbackRequired(RollbackReasonV2),
    SupersedeForRepair(RepairSupersedeAuthorizationV2),
    RecoveryRequired(RecoveryRequiredReasonV2),
}

pub(super) fn plan_build(request: PlannerRequestV2<'_>) -> Result<PlannedBuildV2, PlannerError> {
    validate_trusted_release(request.trusted_release, request.channel)?;
    if request.install_id.is_nil()
        || request.operation_id.is_nil()
        || request.operation_id.get_version() != Some(Version::Random)
    {
        return Err(PlannerError::Plan(
            "install ID and operation UUIDv4 are required".into(),
        ));
    }
    request
        .artifact_inventory
        .validate_root(request.cas_root)
        .map_err(PlannerError::Availability)?;
    request
        .artifact_inventory
        .validate_request(
            request.trusted_release,
            request.install_id,
            request.operation_id,
            request.channel,
            request.preset,
        )
        .map_err(PlannerError::Availability)?;
    request
        .availability
        .validate_for(request.artifact_inventory)
        .map_err(PlannerError::Availability)?;
    if let Some(installed) = request.installed {
        installed
            .validate(request.install_id, request.channel)
            .map_err(PlannerError::InstalledMarker)?;
    }

    let preset = request
        .trusted_release
        .manifest()
        .selected_preset(request.preset)
        .map_err(PlannerError::TrustedRelease)?;
    let mutable = validate_mutable_proofs(&preset.files, request.mutable_files, request.audit)?;
    let desired = build_desired_files(&preset.files, &mutable)?;
    let audit_plan = plan_instance_mutations(request.audit, &desired, &mutable)?;

    let marker_content_current = request.installed.is_some_and(|installed| {
        marker_binds_current_content(installed, request.trusted_release, request.channel)
    });
    if let Some(installed) = request.installed {
        if !installed
            .trusted_release
            .roles_are_monotonic_to(request.trusted_release.evidence())
        {
            return Err(PlannerError::InstalledMarker(
                "fresh TUF role versions are older than the installed evidence".into(),
            ));
        }
    }
    let marker_current = marker_content_current
        && request
            .installed
            .is_some_and(|installed| installed.preset == request.preset);
    let java_generation_verified = request.availability.java_generation_complete();
    let game_generation_verified = request.availability.game_generation_complete();
    let runtime_ready = java_generation_verified && game_generation_verified;
    let needs_repair = !audit_plan.mutations.is_empty() || !runtime_ready;

    let state = match request.installed {
        None => PlannedBuildState::Download,
        Some(_) if !marker_content_current => PlannedBuildState::Update,
        Some(_) if !marker_current => PlannedBuildState::Update,
        Some(_) if needs_repair => PlannedBuildState::Repair,
        Some(_) => PlannedBuildState::Ready,
    };

    if state == PlannedBuildState::Ready {
        let budget = DiskBudgetV2::new(0, 0, 0, 0).map_err(PlannerError::Plan)?;
        request
            .artifact_inventory
            .validate_root(request.cas_root)
            .map_err(PlannerError::Availability)?;
        return Ok(PlannedBuildV2 {
            state,
            plan: None,
            disk_budget_record: budget,
            disk_budget_authority: None,
        });
    }

    let generation = request.installed.map_or(Ok(1), |installed| {
        installed
            .generation
            .checked_add(1)
            .ok_or(PlannerError::Overflow("target generation"))
    })?;
    let target = active_target(
        request.install_id,
        request.channel,
        generation,
        request.preset,
        request.trusted_release,
    )?;
    let operation_kind = match (request.installed, marker_content_current, marker_current) {
        (None, _, _) => OperationKind::Install,
        (Some(_), true, false) => OperationKind::PresetChange,
        (Some(_), true, true) => OperationKind::Repair,
        (Some(_), false, _) => OperationKind::Update,
    };

    let install_paths = desired
        .iter()
        .filter(|file| audit_plan.install_keys.contains(&path_key(&file.path)))
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    let artifact_plan = ArtifactPlanV2::for_reconcile(
        request.artifact_inventory,
        request.availability,
        install_paths,
    )
    .map_err(PlannerError::Availability)?;
    artifact_plan
        .validate_for(request.artifact_inventory)
        .map_err(PlannerError::Availability)?;
    request
        .cas_root
        .revalidate()
        .map_err(PlannerError::Availability)?;
    let allocation_unit_bytes = filesystem_allocation_unit(request.cas_root.install_root())
        .map_err(PlannerError::Availability)?;
    request
        .cas_root
        .revalidate()
        .map_err(PlannerError::Availability)?;
    let requirements = artifact_plan
        .validated_disk_download_reserve_bytes(request.cas_root, request.artifact_inventory)
        .map_err(PlannerError::Plan)?;
    let (reconcile_file_bytes, install_count, quarantine_count, directory_count) = audit_plan
        .mutations
        .iter()
        .try_fold(
            (0_u64, 0_u64, 0_u64, 0_u64),
            |(bytes, installs, quarantines, directories), mutation| match mutation {
                JournalMutation::InstallFile { size, .. } => Some((
                    bytes.checked_add(round_up_allocation(*size, allocation_unit_bytes).ok()?)?,
                    installs.checked_add(1)?,
                    quarantines,
                    directories,
                )),
                JournalMutation::Quarantine { .. } => {
                    Some((bytes, installs, quarantines.checked_add(1)?, directories))
                }
                JournalMutation::EnsureDirectory { .. } => {
                    Some((bytes, installs, quarantines, directories.checked_add(1)?))
                }
            },
        )
        .ok_or(PlannerError::Overflow("instance reconcile physical layout"))?;
    let (staging_bytes, reconcile_destination_bytes) = if allocation_unit_bytes == 1 {
        (reconcile_file_bytes, reconcile_file_bytes)
    } else {
        let staging_entries = install_count
            .checked_mul(2)
            .and_then(|value| value.checked_add(5))
            .ok_or(PlannerError::Overflow("instance staging namespace"))?;
        let destination_entries = install_count
            .checked_mul(2)
            .and_then(|value| value.checked_add(quarantine_count))
            .and_then(|value| value.checked_add(directory_count))
            .and_then(|value| value.checked_add(5))
            .ok_or(PlannerError::Overflow("instance destination namespace"))?;
        (
            reconcile_file_bytes
                .checked_add(
                    staging_entries
                        .checked_mul(allocation_unit_bytes)
                        .ok_or(PlannerError::Overflow("instance staging namespace"))?,
                )
                .ok_or(PlannerError::Overflow("instance staging bytes"))?,
            reconcile_file_bytes
                .checked_add(
                    destination_entries
                        .checked_mul(allocation_unit_bytes)
                        .ok_or(PlannerError::Overflow("instance destination namespace"))?,
                )
                .ok_or(PlannerError::Overflow("instance destination bytes"))?,
        )
    };
    let java_extracted_bytes = if java_generation_verified {
        0
    } else {
        sum_java_files(
            request.trusted_release.runtime_lock(),
            allocation_unit_bytes,
        )?
    };
    let game_extracted_bytes = if game_generation_verified {
        0
    } else {
        sum_game_files(
            request.trusted_release.game_runtime_lock(),
            allocation_unit_bytes,
        )?
    };
    let processor_workspace_bytes = if game_generation_verified {
        0
    } else {
        processor_workspace_bytes(
            request.trusted_release.game_runtime_lock(),
            allocation_unit_bytes,
        )?
    };
    let disk_budget = DiskBudgetV2::new_with_physical_layout(
        requirements,
        java_extracted_bytes,
        game_extracted_bytes,
        processor_workspace_bytes,
        allocation_unit_bytes,
        staging_bytes,
        reconcile_destination_bytes,
    )
    .map_err(PlannerError::Plan)?;

    let mut strict_roots = request
        .trusted_release
        .manifest()
        .integrity
        .strict_roots
        .clone();
    canonicalize_paths(&mut strict_roots);
    let mut preserved_paths = request
        .trusted_release
        .manifest()
        .integrity
        .preserved_paths
        .clone();
    canonicalize_paths(&mut preserved_paths);
    let plan = ReconcilePlanV2 {
        schema_version: RECONCILE_PLAN_SCHEMA_VERSION,
        install_id: request.install_id,
        operation_id: request.operation_id,
        channel: request.channel,
        kind: operation_kind,
        base: request.installed.cloned(),
        target,
        strict_roots,
        preserved_paths,
        desired_files: desired,
        disk_budget: disk_budget.clone(),
        mutations: audit_plan.mutations,
    };
    plan.validate(request.install_id, request.channel)
        .map_err(PlannerError::Plan)?;
    // This also proves that every serialized vector is already canonical and bounded.
    plan.canonical_bytes().map_err(PlannerError::Plan)?;
    request
        .artifact_inventory
        .validate_root(request.cas_root)
        .map_err(PlannerError::Availability)?;
    let disk_budget_authority = CanonicalDiskBudgetAuthorityV2::seal(
        &plan,
        artifact_plan,
        request.artifact_inventory,
        request.cas_root,
    )
    .map_err(PlannerError::Plan)?;

    Ok(PlannedBuildV2 {
        state,
        plan: Some(plan),
        disk_budget_record: disk_budget,
        disk_budget_authority: Some(disk_budget_authority),
    })
}

/// Consumes the private authorities emitted by `plan_build` and seals a fresh current plan for
/// superseding one stale pending operation. A deserialized or caller-crafted plan cannot satisfy
/// this boundary because it has no `CanonicalDiskBudgetAuthorityV2`.
pub(super) fn prepare_current_plan_supersede(
    failed_plan: &ReconcilePlanV2,
    observed_active: Option<&ActiveInstanceV2>,
    fresh_release: &TrustedRelease,
    planned_update: PlannedBuildV2,
    inventory: &ArtifactInventoryV2,
    root: &OwnedCasRoot,
) -> Result<PreparedCurrentPlanV2, PlannerError> {
    let PlannedBuildV2 {
        state,
        plan,
        disk_budget_record,
        disk_budget_authority,
    } = planned_update;
    let (Some(plan), Some(disk_budget_authority)) = (plan, disk_budget_authority) else {
        return Err(PlannerError::Plan(
            "Recovery successor is missing its fresh planner execution authority".into(),
        ));
    };
    if state == PlannedBuildState::Ready || disk_budget_record != plan.disk_budget {
        return Err(PlannerError::Plan(
            "Recovery successor must be the exact non-ready plan returned by the fresh planner"
                .into(),
        ));
    }
    let prepared = PreparedCurrentPlanV2 {
        plan,
        disk_budget_authority,
    };
    prepared.validate_for(failed_plan, observed_active, fresh_release, inventory, root)?;
    Ok(prepared)
}

/// Emits the atomic journal-supersede capability without authorizing any mutation from the stale
/// plan. The replacement base is the exact observed active marker and every replacement mutation
/// comes from the separately sealed fresh-current planner result.
pub(super) fn authorize_current_plan_supersede(
    request: CurrentPlanSupersedeRequestV2<'_>,
) -> Result<CurrentPlanSupersedeAuthorizationV2, PlannerError> {
    request
        .failed_plan
        .validate(request.failed_plan.install_id, request.failed_plan.channel)
        .map_err(PlannerError::Plan)?;
    validate_trusted_release(request.fresh_release, request.failed_plan.channel)?;
    if let Some(identity) = request.untrusted_pending_identity {
        if request.current_final_audit.is_some() {
            return Err(PlannerError::Plan(
                "Untrusted pending identity cannot be mixed with a final audit".into(),
            ));
        }
        identity
            .validate_for(request.failed_plan, request.fresh_release)
            .map_err(PlannerError::Plan)?;
    }
    let target_is_current = marker_binds_current_content(
        &request.failed_plan.target,
        request.fresh_release,
        request.failed_plan.channel,
    ) && request
        .fresh_release
        .manifest()
        .selected_preset(request.failed_plan.target.preset)
        .is_ok();
    if !target_is_current && request.untrusted_pending_identity.is_none() {
        return Err(PlannerError::Plan(
            "Stale-target supersede requires sealed pending identity classification".into(),
        ));
    }
    if target_is_current {
        match request.current_final_audit {
            Some(audit)
                if final_audit_matches_plan(
                    request.failed_plan,
                    audit,
                    request.current_final_mutable_files,
                ) =>
            {
                return Err(PlannerError::Plan(
                    "An exactly audited current target must be finalized, not superseded".into(),
                ));
            }
            Some(_) => {}
            None if request.untrusted_pending_identity.is_some() => {}
            None => {
                return Err(PlannerError::Plan(
                    "Current-target supersede requires a failed final audit or sealed untrusted identity"
                        .into(),
                ));
            }
        }
    }
    request.prepared_update.validate_for(
        request.failed_plan,
        request.active_marker,
        request.fresh_release,
        request.artifact_inventory,
        request.cas_root,
    )?;
    CurrentPlanSupersedeAuthorizationV2::seal(
        request.failed_plan,
        request.prepared_update.plan(),
        request.active_marker,
    )
    .map_err(PlannerError::Plan)
}

/// Re-runs the fresh signed planner and seals the narrow case where the actual active instance is
/// already Ready. The stale journal is never used as desired-tree or mutation authority.
pub(super) fn authorize_stale_pending_ready_abandon(
    stale_plan: &ReconcilePlanV2,
    observed_active: &ActiveInstanceV2,
    untrusted_pending_identity: &UntrustedPendingIdentityV2,
    fresh_request: PlannerRequestV2<'_>,
) -> Result<CurrentReadyAbandonAuthorizationV2, PlannerError> {
    stale_plan
        .validate(stale_plan.install_id, stale_plan.channel)
        .map_err(PlannerError::Plan)?;
    untrusted_pending_identity
        .validate_for(stale_plan, fresh_request.trusted_release)
        .map_err(PlannerError::Plan)?;
    if fresh_request.install_id != stale_plan.install_id
        || fresh_request.channel != stale_plan.channel
        || fresh_request.installed != Some(observed_active)
    {
        return Err(PlannerError::Plan(
            "Fresh-ready abandon request does not describe this stale journal and active marker"
                .into(),
        ));
    }
    let planned = plan_build(fresh_request)?;
    if planned.state != PlannedBuildState::Ready
        || planned.plan.is_some()
        || planned.disk_budget_authority.is_some()
    {
        return Err(PlannerError::Plan(
            "A stale journal can be abandoned only after a fresh exact Ready classification".into(),
        ));
    }
    CurrentReadyAbandonAuthorizationV2::seal(stale_plan, observed_active)
        .map_err(PlannerError::Plan)
}

pub(super) fn plan_mutable_bootstrap(
    root: &OwnedCasRoot,
    inventory: &ArtifactInventoryV2,
    availability: &VerifiedAvailabilityV2,
) -> Result<MutableBootstrapPlanV2, PlannerError> {
    inventory
        .validate_root(root)
        .map_err(PlannerError::Availability)?;
    let plan = MutableBootstrapPlanV2::build(inventory, availability)
        .map_err(PlannerError::Availability)?;
    plan.validate_for(inventory)
        .map_err(PlannerError::Availability)?;
    inventory
        .validate_root(root)
        .map_err(PlannerError::Availability)?;
    Ok(plan)
}

pub(super) fn decide_recovery(request: RecoveryRequestV2<'_>) -> RecoveryDecisionV2 {
    let canonical_plan = match request.plan.canonical_bytes() {
        Ok(bytes) => bytes,
        Err(_) => {
            return RecoveryDecisionV2::RecoveryRequired(RecoveryRequiredReasonV2::InvalidPlan)
        }
    };
    if request
        .plan
        .validate(request.plan.install_id, request.plan.channel)
        .is_err()
    {
        return RecoveryDecisionV2::RecoveryRequired(RecoveryRequiredReasonV2::InvalidPlan);
    }
    if validate_trusted_release(request.fresh_release, request.plan.channel).is_err() {
        return RecoveryDecisionV2::RecoveryRequired(RecoveryRequiredReasonV2::InvalidFreshRelease);
    }

    let target_is_current = marker_binds_current_content(
        &request.plan.target,
        request.fresh_release,
        request.plan.channel,
    ) && request
        .fresh_release
        .manifest()
        .selected_preset(request.plan.target.preset)
        .is_ok();

    if !target_is_current {
        // No mutation or audit scope from a stale local plan is authoritative. Recovery must use
        // a new plan built exclusively from the freshly trusted release and the actual tree.
        return RecoveryDecisionV2::PrepareCurrentPlan;
    }

    if request.active_marker == Some(&request.plan.target) {
        let Some(audit) = request.final_audit else {
            return RecoveryDecisionV2::RecoveryRequired(
                RecoveryRequiredReasonV2::FinalAuditRequired,
            );
        };
        if final_audit_matches_plan(request.plan, audit, request.final_mutable_files) {
            let authorization =
                FinalizeCommitAuthorizationV2::for_exact_final_audit(request.plan, &canonical_plan);
            return RecoveryDecisionV2::FinalizeCommittedTarget(authorization);
        }
        return RecoveryDecisionV2::PrepareCurrentPlan;
    }

    let marker_is_base = match (&request.plan.base, request.active_marker) {
        (None, None) => true,
        (Some(base), Some(active)) => base == active,
        _ => false,
    };
    if !marker_is_base {
        return RecoveryDecisionV2::RecoveryRequired(RecoveryRequiredReasonV2::MarkerDiverged);
    }
    if !staging_proof_matches(request.plan, request.staging_files) {
        return RecoveryDecisionV2::RollbackRequired(RollbackReasonV2::StagingProofIncomplete);
    }
    RecoveryDecisionV2::RollForward
}

fn validate_trusted_release(
    trusted: &TrustedRelease,
    expected_channel: BuildChannel,
) -> Result<(), PlannerError> {
    if trusted.channel() != expected_channel
        || trusted.current().channel != expected_channel
        || trusted.current().release_id != trusted.manifest().release.id
        || trusted.tuf_root_version() != trusted.evidence().roles.root
    {
        return Err(PlannerError::TrustedRelease(
            "channel, current target, release or root version mismatch".into(),
        ));
    }
    trusted
        .manifest()
        .validate()
        .map_err(PlannerError::TrustedRelease)?;
    trusted
        .runtime_lock()
        .validate()
        .map_err(PlannerError::TrustedRelease)?;
    trusted
        .game_runtime_lock()
        .validate()
        .map_err(PlannerError::TrustedRelease)?;
    trusted
        .manifest()
        .bind_runtime_lock(trusted.runtime_lock())
        .map_err(PlannerError::TrustedRelease)?;
    trusted
        .manifest()
        .bind_game_runtime_lock(trusted.runtime_lock(), trusted.game_runtime_lock())
        .map_err(PlannerError::TrustedRelease)?;
    trusted
        .evidence()
        .validate_binding(
            expected_channel,
            &trusted.manifest().release.id,
            &trusted.current().manifest_target,
            &trusted.manifest().runtime.java.runtime_target,
            &trusted.manifest().runtime.game.runtime_target,
            &trusted.evidence().release_manifest.sha256,
            &trusted.manifest().runtime.java.runtime_lock_sha256,
            &trusted.manifest().runtime.game.runtime_lock_sha256,
        )
        .map_err(PlannerError::TrustedRelease)
}

fn active_target(
    install_id: Uuid,
    channel: BuildChannel,
    generation: u64,
    preset: PresetId,
    trusted: &TrustedRelease,
) -> Result<ActiveInstanceV2, PlannerError> {
    ActiveInstanceV2::new(
        install_id,
        channel,
        generation,
        trusted.manifest().release.id.clone(),
        preset,
        trusted.evidence().release_manifest.sha256.clone(),
        trusted.manifest().runtime.java.runtime_lock_sha256.clone(),
        trusted.manifest().runtime.game.runtime_lock_sha256.clone(),
        trusted.evidence().clone(),
    )
    .map_err(PlannerError::Plan)
}

fn marker_binds_current_content(
    marker: &ActiveInstanceV2,
    trusted: &TrustedRelease,
    channel: BuildChannel,
) -> bool {
    marker.channel == channel
        && marker.release_id == trusted.manifest().release.id
        && marker.release_manifest_sha256 == trusted.evidence().release_manifest.sha256
        && marker.runtime_lock_sha256 == trusted.manifest().runtime.java.runtime_lock_sha256
        && marker.game_runtime_lock_sha256 == trusted.manifest().runtime.game.runtime_lock_sha256
        && marker
            .trusted_release
            .targets_match_and_roles_are_monotonic_to(trusted.evidence())
}

fn build_desired_files(
    manifest_files: &[ManifestFile],
    mutable: &BTreeMap<String, &MutableMaterializationProofV2>,
) -> Result<Vec<PlannedFileV2>, PlannerError> {
    let mut desired = Vec::with_capacity(manifest_files.len());
    for file in manifest_files {
        let (installed_size, installed_sha256) = match file.policy {
            FilePolicy::Exact => (file.size, file.sha256.clone()),
            FilePolicy::ValidatedMutable => {
                let proof = mutable.get(&path_key(&file.path)).ok_or_else(|| {
                    PlannerError::MutableProof(format!("missing proof for {}", file.path))
                })?;
                (proof.size, proof.sha256.clone())
            }
        };
        desired.push(PlannedFileV2 {
            path: file.path.clone(),
            signed_size: file.size,
            signed_sha256: file.sha256.clone(),
            installed_size,
            installed_sha256,
            executable: file.executable,
            policy: file.policy,
        });
    }
    desired.sort_by(|left, right| path_order(&left.path, &right.path));
    Ok(desired)
}

fn validate_mutable_proofs<'a>(
    manifest_files: &[ManifestFile],
    proofs: &'a [MutableMaterializationProofV2],
    audit: &InstanceAudit,
) -> Result<BTreeMap<String, &'a MutableMaterializationProofV2>, PlannerError> {
    let expected = manifest_files
        .iter()
        .filter(|file| file.policy == FilePolicy::ValidatedMutable)
        .map(|file| (path_key(&file.path), file.path.as_str()))
        .collect::<BTreeMap<_, _>>();
    let candidates = canonical_path_map(
        audit
            .validated_mutable_candidates
            .iter()
            .map(String::as_str),
        "mutable candidates",
        false,
    )?;
    let mut result = BTreeMap::new();
    let mut previous: Option<String> = None;
    for proof in proofs {
        let key = path_key(&proof.path);
        if previous.as_ref().is_some_and(|value| value >= &key) || !is_sha256(&proof.sha256) {
            return Err(PlannerError::MutableProof(
                "proofs must be canonical, unique and contain SHA-256".into(),
            ));
        }
        let expected_path = expected.get(&key).ok_or_else(|| {
            PlannerError::MutableProof(format!("unexpected proof for {}", proof.path))
        })?;
        if *expected_path != proof.path {
            return Err(PlannerError::MutableProof(format!(
                "mutable proof path casing differs: {}",
                proof.path
            )));
        }
        if proof.current_matches
            && candidates
                .get(&key)
                .is_none_or(|candidate| candidate != expected_path)
        {
            return Err(PlannerError::MutableProof(format!(
                "current mutable file was not an audited candidate: {}",
                proof.path
            )));
        }
        result.insert(key.clone(), proof);
        previous = Some(key);
    }
    if result.len() != expected.len() {
        return Err(PlannerError::MutableProof(
            "every validated-mutable file requires exactly one proof".into(),
        ));
    }
    Ok(result)
}

struct AuditPlan {
    install_keys: BTreeSet<String>,
    mutations: Vec<JournalMutation>,
}

fn plan_instance_mutations(
    audit: &InstanceAudit,
    desired: &[PlannedFileV2],
    mutable: &BTreeMap<String, &MutableMaterializationProofV2>,
) -> Result<AuditPlan, PlannerError> {
    let desired_by_key = desired
        .iter()
        .map(|file| (path_key(&file.path), file))
        .collect::<BTreeMap<_, _>>();
    let verified = canonical_path_map(
        audit.verified_exact.iter().map(String::as_str),
        "verified exact files",
        false,
    )?;
    let candidates = canonical_path_map(
        audit
            .validated_mutable_candidates
            .iter()
            .map(String::as_str),
        "mutable candidates",
        false,
    )?;
    let missing = canonical_path_map(
        audit.missing_files.iter().map(String::as_str),
        "missing files",
        false,
    )?;
    let modified = canonical_path_map(
        audit.modified_files.iter().map(|value| value.path.as_str()),
        "modified files",
        true,
    )?;
    let unknown_files = canonical_path_map(
        audit.unknown_files.iter().map(String::as_str),
        "unknown files",
        false,
    )?;
    let unknown_directories = canonical_path_map(
        audit.unknown_directories.iter().map(String::as_str),
        "unknown directories",
        false,
    )?;
    let unsafe_entries = canonical_path_map(
        audit.unsafe_entries.iter().map(|value| value.path.as_str()),
        "unsafe entries",
        true,
    )?;
    if unsafe_entries.values().any(|path| path == ".") {
        return Err(PlannerError::Audit(
            "the instance root itself is unsafe and cannot be journal-repaired".into(),
        ));
    }

    let mut install_keys = BTreeSet::new();
    for (key, file) in &desired_by_key {
        let deviation = missing.contains_key(key)
            || modified.contains_key(key)
            || unsafe_entries.contains_key(key)
            || unknown_files.contains_key(key)
            || unknown_directories.contains_key(key);
        match file.policy {
            FilePolicy::Exact => {
                let is_verified = verified.get(key).is_some_and(|path| path == &file.path);
                if is_verified && deviation {
                    return Err(PlannerError::Audit(format!(
                        "exact file is both verified and divergent: {}",
                        file.path
                    )));
                }
                if !is_verified && !deviation {
                    return Err(PlannerError::Audit(format!(
                        "exact file has no complete audit classification: {}",
                        file.path
                    )));
                }
                if deviation {
                    install_keys.insert(key.clone());
                }
            }
            FilePolicy::ValidatedMutable => {
                let proof = mutable.get(key).expect("mutable proofs were validated");
                let is_candidate = candidates.get(key).is_some_and(|path| path == &file.path);
                if proof.current_matches && (!is_candidate || deviation) {
                    return Err(PlannerError::Audit(format!(
                        "mutable file proof contradicts the audit: {}",
                        file.path
                    )));
                }
                if !proof.current_matches {
                    install_keys.insert(key.clone());
                }
            }
        }
    }

    for collection in [&verified, &candidates, &missing, &modified, &unsafe_entries] {
        for (key, path) in collection {
            if let Some(file) = desired_by_key.get(key) {
                if file.path != *path {
                    return Err(PlannerError::Audit(format!(
                        "audit path casing differs from desired path: {path}"
                    )));
                }
            }
        }
    }

    let mut quarantine = BTreeMap::new();
    for collection in [
        &modified,
        &unknown_files,
        &unknown_directories,
        &unsafe_entries,
    ] {
        for (key, path) in collection {
            quarantine
                .entry(key.clone())
                .or_insert_with(|| path.clone());
        }
    }
    // A mutable candidate is an existing file, but a false materialization proof means the
    // canonical replacement must be installed. Treat that existing candidate like every other
    // replaceable divergent entry so the executor never has to overwrite it in place. Keeping it
    // in the common quarantine map also preserves top-level deduplication when an audited parent
    // is already being quarantined.
    for (key, path) in &candidates {
        let must_replace_mutable_candidate = install_keys.contains(key)
            && desired_by_key
                .get(key)
                .is_some_and(|file| file.policy == FilePolicy::ValidatedMutable)
            && mutable.get(key).is_some_and(|proof| !proof.current_matches);
        if must_replace_mutable_candidate {
            quarantine
                .entry(key.clone())
                .or_insert_with(|| path.clone());
        }
    }
    let quarantine = top_level_paths(quarantine);
    let mut mutations = Vec::new();
    for (slot, path) in quarantine.values().enumerate() {
        let backup_slot = u32::try_from(slot).map_err(|_| PlannerError::Overflow("backup slot"))?;
        mutations.push(JournalMutation::Quarantine {
            source_path: path.clone(),
            backup_slot,
        });
    }

    let mut directories = canonical_path_map(
        audit.missing_directories.iter().map(String::as_str),
        "missing directories",
        false,
    )?;
    for key in &install_keys {
        let file = desired_by_key
            .get(key)
            .expect("install keys are derived from desired files");
        for parent in parent_paths(&file.path) {
            directories.entry(path_key(&parent)).or_insert(parent);
        }
    }
    for path in directories.values() {
        mutations.push(JournalMutation::EnsureDirectory {
            destination_path: path.clone(),
        });
    }
    for (slot, key) in install_keys.iter().enumerate() {
        let file = desired_by_key
            .get(key)
            .expect("install keys are derived from desired files");
        let staging_slot =
            u32::try_from(slot).map_err(|_| PlannerError::Overflow("staging slot"))?;
        mutations.push(JournalMutation::InstallFile {
            destination_path: file.path.clone(),
            staging_slot,
            size: file.installed_size,
            sha256: file.installed_sha256.clone(),
            executable: file.executable,
        });
    }
    Ok(AuditPlan {
        install_keys,
        mutations,
    })
}

fn sum_java_files(lock: &RuntimeLock, allocation_unit: u64) -> Result<u64, PlannerError> {
    let content = lock
        .java
        .files
        .iter()
        .try_fold(0_u64, |total, file| {
            total.checked_add(round_up_allocation(file.size, allocation_unit).ok()?)
        })
        .ok_or(PlannerError::Overflow("Java runtime extracted bytes"))?;
    if allocation_unit == 1 {
        return Ok(content);
    }
    let file_count = u64::try_from(lock.java.files.len())
        .map_err(|_| PlannerError::Overflow("Java runtime file count"))?;
    let directory_count =
        unique_parent_directory_count(lock.java.files.iter().map(|file| file.path.as_str()))?;
    let namespace_entries = file_count
        .checked_add(directory_count)
        .and_then(|value| value.checked_add(JAVA_GENERATION_FIXED_NAMESPACE_ENTRIES))
        .ok_or(PlannerError::Overflow("Java runtime namespace entries"))?;
    [
        content,
        round_up_allocation(JAVA_GENERATION_MARKER_RESERVE_BYTES, allocation_unit)
            .map_err(|_| PlannerError::Overflow("Java generation marker bytes"))?,
        namespace_entries
            .checked_mul(allocation_unit)
            .ok_or(PlannerError::Overflow("Java runtime namespace bytes"))?,
    ]
    .into_iter()
    .try_fold(0_u64, |total, value| total.checked_add(value))
    .ok_or(PlannerError::Overflow("Java runtime physical bytes"))
}

fn sum_game_files(lock: &GameRuntimeLock, allocation_unit: u64) -> Result<u64, PlannerError> {
    let content = lock
        .files
        .iter()
        .try_fold(0_u64, |total, file| {
            total.checked_add(
                round_up_allocation(game_runtime_file_size(&file.source), allocation_unit).ok()?,
            )
        })
        .ok_or(PlannerError::Overflow("game runtime extracted bytes"))?;
    if allocation_unit == 1 {
        return Ok(content);
    }
    let file_count = u64::try_from(lock.files.len())
        .map_err(|_| PlannerError::Overflow("game runtime file count"))?;
    let directory_count =
        unique_parent_directory_count(lock.files.iter().map(|file| file.path.as_str()))?;
    let namespace_entries = file_count
        .checked_add(directory_count)
        .and_then(|value| value.checked_add(GAME_GENERATION_FIXED_NAMESPACE_ENTRIES))
        .ok_or(PlannerError::Overflow("game runtime namespace entries"))?;
    [
        content,
        round_up_allocation(GAME_GENERATION_MARKER_RESERVE_BYTES, allocation_unit)
            .map_err(|_| PlannerError::Overflow("game generation marker bytes"))?,
        namespace_entries
            .checked_mul(allocation_unit)
            .ok_or(PlannerError::Overflow("game runtime namespace bytes"))?,
    ]
    .into_iter()
    .try_fold(0_u64, |total, value| total.checked_add(value))
    .ok_or(PlannerError::Overflow("game runtime physical bytes"))
}

fn unique_parent_directory_count<'a>(
    paths: impl Iterator<Item = &'a str>,
) -> Result<u64, PlannerError> {
    let mut directories = BTreeSet::new();
    for path in paths {
        for parent in parent_paths(path) {
            directories.insert(path_key(&parent));
        }
    }
    u64::try_from(directories.len())
        .map_err(|_| PlannerError::Overflow("runtime parent directory count"))
}

/// Pessimistic peak space retained while building a missing immutable game generation.
///
/// The final 4,028-file generation and missing CAS objects are budgeted separately. This reserve
/// covers the independent processor-input copies, embedded patch, signed output/write-set,
/// executor-bounded scratch/state, a physically preallocated emergency recovery reserve, and one
/// largest-file incoming copy that can coexist with the completed staging tree immediately before
/// publication.
fn processor_workspace_bytes(
    lock: &GameRuntimeLock,
    allocation_unit: u64,
) -> Result<u64, PlannerError> {
    let minecraft_client = unique_official_runtime_path(lock, GameRuntimeRole::MinecraftClient)?;
    let minecraft_mappings =
        unique_official_runtime_path(lock, GameRuntimeRole::MinecraftClientMappings)?;
    let installer = unique_official_runtime_path(lock, GameRuntimeRole::NeoforgeInstaller)?;

    let mut upstream = BTreeMap::new();
    for step in &lock.provenance.processor_plans.upstream.steps {
        if upstream.insert(step.upstream_index, step).is_some() {
            return Err(PlannerError::Plan(
                "Processor plan contains duplicate upstream indices".into(),
            ));
        }
    }
    let mut official_paths = BTreeSet::from([installer]);
    for reference in &lock.provenance.processor_plans.executable.steps {
        let step = upstream.get(&reference.upstream_index).ok_or_else(|| {
            PlannerError::Plan(format!(
                "Executable processor step {} is absent from the upstream plan",
                reference.upstream_index
            ))
        })?;
        official_paths.insert(step.jar_path.clone());
        official_paths.extend(step.classpath.iter().cloned());
        for argument in &step.arguments {
            match argument {
                NormalizedProcessorArgument::Path { path } => {
                    official_paths.insert(path.clone());
                }
                NormalizedProcessorArgument::Input {
                    input: ProcessorInput::MinecraftClient,
                } => {
                    official_paths.insert(minecraft_client.clone());
                }
                NormalizedProcessorArgument::Input {
                    input: ProcessorInput::MinecraftClientMappings,
                }
                | NormalizedProcessorArgument::Materialization {
                    access: ProcessorMaterializationAccess::Read,
                    ..
                } => {
                    official_paths.insert(minecraft_mappings.clone());
                }
                NormalizedProcessorArgument::Materialization {
                    access: ProcessorMaterializationAccess::Write,
                    ..
                } => {
                    return Err(PlannerError::Plan(
                        "Executable processor plan contains a writable input materialization"
                            .into(),
                    ));
                }
                NormalizedProcessorArgument::Literal { .. }
                | NormalizedProcessorArgument::Input {
                    input: ProcessorInput::ClientPatch,
                }
                | NormalizedProcessorArgument::Output { .. } => {}
            }
        }
    }

    let mut official_input_bytes = 0_u64;
    for path in official_paths {
        let file = lock
            .files
            .iter()
            .find(|file| file.path == path)
            .ok_or_else(|| {
                PlannerError::Plan(format!(
                    "Processor input is absent from the signed game runtime: {path}"
                ))
            })?;
        let GameRuntimeSource::Official { size, .. } = &file.source else {
            return Err(PlannerError::Plan(format!(
                "Processor input is not an official artifact: {path}"
            )));
        };
        official_input_bytes = official_input_bytes
            .checked_add(
                round_up_allocation(*size, allocation_unit)
                    .map_err(|_| PlannerError::Overflow("processor official input bytes"))?,
            )
            .ok_or(PlannerError::Overflow("processor official input bytes"))?;
    }

    let mut derived_output_bytes = 0_u64;
    let mut largest_incoming_copy_bytes = 0_u64;
    for file in &lock.files {
        let size = game_runtime_file_size(&file.source);
        largest_incoming_copy_bytes = largest_incoming_copy_bytes.max(size);
        if matches!(&file.source, GameRuntimeSource::Derived { .. }) {
            derived_output_bytes = derived_output_bytes
                .checked_add(
                    round_up_allocation(size, allocation_unit)
                        .map_err(|_| PlannerError::Overflow("processor derived output bytes"))?,
                )
                .ok_or(PlannerError::Overflow("processor derived output bytes"))?;
        }
    }
    if largest_incoming_copy_bytes == 0 {
        return Err(PlannerError::Plan(
            "Game runtime has no non-empty file for the incoming-copy reserve".into(),
        ));
    }

    let mut transient_sizes = BTreeMap::new();
    let OfflineProcessorVerification::Verified { runs, .. } = &lock.verification.offline_processors
    else {
        return Err(PlannerError::Plan(
            "Pending processor verification cannot be disk-budgeted".into(),
        ));
    };
    for run in runs.iter() {
        for step in &run.steps {
            for artifact in &step.removed_transient_artifacts {
                if transient_sizes
                    .insert(artifact.path.clone(), artifact.size)
                    .is_some_and(|existing| existing != artifact.size)
                {
                    return Err(PlannerError::Plan(
                        "Processor receipt reuses a transient path with another size".into(),
                    ));
                }
            }
        }
    }
    let transient_output_bytes = transient_sizes
        .values()
        .try_fold(0_u64, |total, size| {
            total.checked_add(round_up_allocation(*size, allocation_unit).ok()?)
        })
        .ok_or(PlannerError::Overflow("processor transient output bytes"))?;
    let scratch_tree_bytes = PROCESSOR_SCRATCH_TREE_BYTES
        .checked_add(
            PROCESSOR_SCRATCH_ENTRY_COUNT
                .checked_mul(allocation_unit.saturating_sub(1))
                .ok_or(PlannerError::Overflow(
                    "processor scratch allocation overhead",
                ))?,
        )
        .ok_or(PlannerError::Overflow(
            "processor scratch allocation overhead",
        ))?;
    let scratch_bytes = scratch_tree_bytes
        .checked_mul(PROCESSOR_SCRATCH_TREE_COUNT)
        .ok_or(PlannerError::Overflow("processor scratch bytes"))?;

    let content = [
        official_input_bytes,
        round_up_allocation(lock.provenance.client_patch.size, allocation_unit)
            .map_err(|_| PlannerError::Overflow("processor client patch bytes"))?,
        derived_output_bytes,
        transient_output_bytes,
        scratch_bytes,
        round_up_allocation(PROCESSOR_STATE_MARKER_RESERVE_BYTES, allocation_unit)
            .map_err(|_| PlannerError::Overflow("processor state marker bytes"))?,
        round_up_allocation(PROCESSOR_EMERGENCY_RECOVERY_RESERVE_BYTES, allocation_unit)
            .map_err(|_| PlannerError::Overflow("processor emergency reserve bytes"))?,
        round_up_allocation(largest_incoming_copy_bytes, allocation_unit)
            .map_err(|_| PlannerError::Overflow("processor incoming copy bytes"))?,
    ]
    .into_iter()
    .try_fold(0_u64, |total, value| total.checked_add(value))
    .ok_or(PlannerError::Overflow("processor workspace bytes"))?;
    if allocation_unit == 1 {
        return Ok(content);
    }
    content
        .checked_add(
            PROCESSOR_WORKSPACE_NAMESPACE_ENTRIES
                .checked_mul(allocation_unit)
                .ok_or(PlannerError::Overflow(
                    "processor workspace namespace bytes",
                ))?,
        )
        .ok_or(PlannerError::Overflow("processor workspace physical bytes"))
}

fn unique_official_runtime_path(
    lock: &GameRuntimeLock,
    role: GameRuntimeRole,
) -> Result<String, PlannerError> {
    let mut matching = lock.files.iter().filter(|file| {
        file.role == role && matches!(&file.source, GameRuntimeSource::Official { .. })
    });
    let path = matching
        .next()
        .map(|file| file.path.clone())
        .ok_or_else(|| {
            PlannerError::Plan(format!("Official processor role is missing: {role:?}"))
        })?;
    if matching.next().is_some() {
        return Err(PlannerError::Plan(format!(
            "Official processor role is ambiguous: {role:?}"
        )));
    }
    Ok(path)
}

fn game_runtime_file_size(source: &GameRuntimeSource) -> u64 {
    match source {
        GameRuntimeSource::Official { size, .. } | GameRuntimeSource::Derived { size, .. } => *size,
    }
}

fn round_up_allocation(size: u64, allocation_unit: u64) -> Result<u64, String> {
    if allocation_unit == 0 {
        return Err("Filesystem allocation unit is zero".into());
    }
    if size == 0 || allocation_unit == 1 {
        return Ok(size);
    }
    let remainder = size % allocation_unit;
    if remainder == 0 {
        Ok(size)
    } else {
        size.checked_add(allocation_unit - remainder)
            .ok_or_else(|| "Filesystem allocation rounding overflowed".into())
    }
}

#[cfg(windows)]
pub(super) fn filesystem_allocation_unit(root: &Path) -> Result<u64, String> {
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
    unsafe { GetVolumePathNameW(PCWSTR(path.as_ptr()), &mut volume) }
        .map_err(|error| format!("Cannot resolve install volume: {error}"))?;
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
    .map_err(|error| format!("Cannot query install allocation unit: {error}"))?;
    u64::from(sectors_per_cluster)
        .checked_mul(u64::from(bytes_per_sector))
        .filter(|value| *value != 0)
        .ok_or_else(|| "Filesystem reported an invalid allocation unit".into())
}

#[cfg(unix)]
pub(super) fn filesystem_allocation_unit(root: &Path) -> Result<u64, String> {
    use std::os::unix::fs::MetadataExt;
    let value = std::fs::metadata(root)
        .map_err(|error| format!("Cannot inspect install filesystem: {error}"))?
        .blksize();
    if value == 0 {
        Err("Filesystem reported an invalid allocation unit".into())
    } else {
        Ok(value)
    }
}

#[cfg(not(any(windows, unix)))]
pub(super) fn filesystem_allocation_unit(_root: &Path) -> Result<u64, String> {
    Ok(4096)
}

fn staging_proof_matches(plan: &ReconcilePlanV2, proofs: &[StagingFileProofV2]) -> bool {
    let expected = plan
        .mutations
        .iter()
        .filter_map(|mutation| match mutation {
            JournalMutation::InstallFile {
                destination_path,
                staging_slot,
                size,
                sha256,
                ..
            } => Some((
                *staging_slot,
                destination_path.as_str(),
                *size,
                sha256.as_str(),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    if expected.len() != proofs.len() {
        return false;
    }
    expected.iter().zip(proofs).all(|(expected, proof)| {
        expected.0 == proof.staging_slot
            && expected.1 == proof.destination_path
            && expected.2 == proof.size
            && expected.3 == proof.sha256
    })
}

/// Reconstructs the only mutation set a fresh native instance audit can authorize for the exact
/// pending desired tree. A journal is recovery data, not mutation authority: even a plan whose
/// signed desired files are current must not smuggle different quarantine/directory/install
/// mutations into roll-forward or rollback.
pub(super) fn validate_pending_reconcile_plan_for_recovery(
    plan: &ReconcilePlanV2,
    bound_audit: &ReconcilePlanAuditV2,
    proofs: &[MutableMaterializationProofV2],
) -> Result<(), String> {
    let audit = bound_audit.audit_for(plan)?;
    let signed_files = plan
        .desired_files
        .iter()
        .map(|file| ManifestFile {
            path: file.path.clone(),
            size: file.signed_size,
            sha256: file.signed_sha256.clone(),
            executable: file.executable,
            policy: file.policy,
        })
        .collect::<Vec<_>>();
    let mutable =
        validate_mutable_proofs(&signed_files, proofs, audit).map_err(|error| error.to_string())?;
    for file in plan
        .desired_files
        .iter()
        .filter(|file| file.policy == FilePolicy::ValidatedMutable)
    {
        let proof = mutable
            .get(&path_key(&file.path))
            .expect("native mutable proofs were validated");
        if proof.size != file.installed_size || proof.sha256 != file.installed_sha256 {
            return Err(format!(
                "Pending mutable materialization differs from native policy: {}",
                file.path
            ));
        }
    }
    let canonical = plan_instance_mutations(audit, &plan.desired_files, &mutable)
        .map_err(|error| error.to_string())?;
    if canonical.mutations != plan.mutations {
        return Err(
            "Pending reconcile mutations differ from the fresh canonical audit plan".into(),
        );
    }
    Ok(())
}

fn final_audit_matches_plan(
    plan: &ReconcilePlanV2,
    bound_audit: &ReconcilePlanAuditV2,
    mutable: &[MutableMaterializationProofV2],
) -> bool {
    let Ok(audit) = bound_audit.audit_for(plan) else {
        return false;
    };
    if audit.needs_reconciliation() {
        return false;
    }
    let exact_expected = plan
        .desired_files
        .iter()
        .filter(|file| file.policy == FilePolicy::Exact)
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    let exact_actual = audit
        .verified_exact
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mutable_expected = plan
        .desired_files
        .iter()
        .filter(|file| file.policy == FilePolicy::ValidatedMutable)
        .collect::<Vec<_>>();
    let mutable_candidates = audit
        .validated_mutable_candidates
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if exact_expected != exact_actual
        || mutable_expected
            .iter()
            .map(|file| file.path.as_str())
            .collect::<BTreeSet<_>>()
            != mutable_candidates
        || mutable_expected.len() != mutable.len()
    {
        return false;
    }
    mutable_expected.iter().zip(mutable).all(|(file, proof)| {
        proof.current_matches
            && file.path == proof.path
            && file.installed_size == proof.size
            && file.installed_sha256 == proof.sha256
    })
}

fn canonical_path_map<'a>(
    values: impl Iterator<Item = &'a str>,
    label: &str,
    allow_exact_duplicates: bool,
) -> Result<BTreeMap<String, String>, PlannerError> {
    let mut map = BTreeMap::new();
    for path in values {
        let key = path_key(path);
        match map.get(&key) {
            Some(existing) if allow_exact_duplicates && existing == path => {}
            Some(_) => {
                return Err(PlannerError::Audit(format!(
                    "{label} contain duplicate or case-colliding path {path}"
                )))
            }
            None => {
                map.insert(key, path.to_owned());
            }
        }
    }
    Ok(map)
}

fn top_level_paths(paths: BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    for (key, path) in paths {
        if result
            .keys()
            .any(|ancestor: &String| key.starts_with(&format!("{ancestor}/")))
        {
            continue;
        }
        result.insert(key, path);
    }
    result
}

fn parent_paths(path: &str) -> Vec<String> {
    let components = path.split('/').collect::<Vec<_>>();
    (1..components.len())
        .map(|length| components[..length].join("/"))
        .collect()
}

fn canonicalize_paths(paths: &mut [String]) {
    paths.sort_by(|left, right| path_order(left, right));
}

fn path_order(left: &str, right: &str) -> std::cmp::Ordering {
    path_key(left)
        .cmp(&path_key(right))
        .then_with(|| left.cmp(right))
}

fn path_key(path: &str) -> String {
    path.to_lowercase()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::build_manager::{
        contracts::{self, GameRuntimeLock},
        reconciler::{ModifiedFile, ModifiedKind},
        release::{self, CurrentPointer, ReleaseManifest},
        storage::select_install_directory,
        tuf::{TrustedReleaseEvidence, TrustedRoleVersions, TrustedTargetEvidence},
    };
    use sha2::{Digest, Sha256};

    const EXACT_HASH: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const MUTABLE_HASH: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const MATERIALIZED_HASH: &str =
        "9999999999999999999999999999999999999999999999999999999999999999";
    const RUNTIME_HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const GAME_HASH: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    pub(crate) fn trusted(release_suffix: char, metadata_version: u64) -> TrustedRelease {
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
                match file["path"].as_str().unwrap() {
                    "mods/fragment-launch-guard.jar" => {
                        file["sha256"] = serde_json::Value::String(EXACT_HASH.into())
                    }
                    "options.txt" => {
                        file["sha256"] = serde_json::Value::String(MUTABLE_HASH.into())
                    }
                    path => panic!("unexpected manifest fixture path: {path}"),
                }
            }
        }
        let manifest_bytes = serde_json::to_vec(&manifest_json).unwrap();
        let manifest = ReleaseManifest::parse_and_validate(&manifest_bytes).unwrap();
        manifest.bind_runtime_lock(&runtime_lock).unwrap();
        manifest
            .bind_game_runtime_lock(&runtime_lock, &game_runtime_lock)
            .unwrap();
        let manifest_hash = format!("{:x}", Sha256::digest(&manifest_bytes));
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
                sha256: "a".repeat(64),
            },
            release_manifest: TrustedTargetEvidence {
                name: current.manifest_target.clone(),
                length: manifest_bytes.len() as u64,
                sha256: manifest_hash,
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

    fn mutable(current_matches: bool) -> Vec<MutableMaterializationProofV2> {
        vec![MutableMaterializationProofV2 {
            path: "options.txt".into(),
            size: 20,
            sha256: MATERIALIZED_HASH.into(),
            current_matches,
        }]
    }

    fn missing_audit() -> InstanceAudit {
        InstanceAudit {
            missing_files: vec![
                "mods/fragment-launch-guard.jar".into(),
                "options.txt".into(),
            ],
            missing_directories: vec![
                "config".into(),
                "mods".into(),
                "resourcepacks".into(),
                "shaderpacks".into(),
            ],
            ..InstanceAudit::default()
        }
    }

    fn ready_audit() -> InstanceAudit {
        InstanceAudit {
            verified_exact: vec!["mods/fragment-launch-guard.jar".into()],
            validated_mutable_candidates: vec!["options.txt".into()],
            ..InstanceAudit::default()
        }
    }

    fn test_inventory(
        root: &super::super::storage::OwnedCasRoot,
        trusted: &TrustedRelease,
        install_id: Uuid,
        operation_id: Uuid,
    ) -> ArtifactInventoryV2 {
        ArtifactInventoryV2::build(
            root,
            trusted,
            install_id,
            operation_id,
            BuildChannel::Stable,
            PresetId::Medium,
        )
        .unwrap()
    }

    struct TestInstall {
        directory: std::path::PathBuf,
        root: Option<super::super::storage::OwnedCasRoot>,
        install_id: Uuid,
    }

    impl TestInstall {
        fn root(&self) -> &super::super::storage::OwnedCasRoot {
            self.root.as_ref().expect("test root")
        }

        fn from_owner_marker(source: &TestInstall) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "fragment-planner-artifacts-rebound-{}",
                Uuid::new_v4()
            ));
            std::fs::create_dir(&directory).unwrap();
            std::fs::copy(
                source.directory.join(".fragment-launcher-root.json"),
                directory.join(".fragment-launcher-root.json"),
            )
            .unwrap();
            let selected = select_install_directory(&directory).unwrap();
            assert_eq!(selected.install_id(), source.install_id);
            Self {
                directory,
                root: Some(selected.into_owned_cas_root()),
                install_id: source.install_id,
            }
        }
    }

    impl Drop for TestInstall {
        fn drop(&mut self) {
            drop(self.root.take());
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn test_install() -> TestInstall {
        let directory =
            std::env::temp_dir().join(format!("fragment-planner-artifacts-{}", Uuid::new_v4()));
        let selected = select_install_directory(&directory).unwrap();
        let install_id = selected.install_id();
        TestInstall {
            directory,
            root: Some(selected.into_owned_cas_root()),
            install_id,
        }
    }

    fn ready_availability(inventory: &ArtifactInventoryV2) -> VerifiedAvailabilityV2 {
        VerifiedAvailabilityV2::for_test(inventory, [], true, true)
    }

    fn missing_availability(inventory: &ArtifactInventoryV2) -> VerifiedAvailabilityV2 {
        VerifiedAvailabilityV2::for_test(inventory, [], false, false)
    }

    #[allow(clippy::too_many_arguments)]
    fn request<'a>(
        install_id: Uuid,
        operation_id: Uuid,
        trusted_release: &'a TrustedRelease,
        artifact_inventory: &'a ArtifactInventoryV2,
        cas_root: &'a super::super::storage::OwnedCasRoot,
        installed: Option<&'a ActiveInstanceV2>,
        audit: &'a InstanceAudit,
        mutable_files: &'a [MutableMaterializationProofV2],
        availability: &'a VerifiedAvailabilityV2,
    ) -> PlannerRequestV2<'a> {
        PlannerRequestV2 {
            install_id,
            channel: BuildChannel::Stable,
            preset: PresetId::Medium,
            operation_id,
            trusted_release,
            artifact_inventory,
            cas_root,
            installed,
            audit,
            mutable_files,
            availability,
        }
    }

    #[test]
    fn plans_a_canonical_initial_download_with_pessimistic_disk_budget() {
        let install = test_install();
        let install_id = install.install_id;
        let operation_id = Uuid::new_v4();
        let current_release = trusted('a', 1);
        let audit = missing_audit();
        let mutable = mutable(false);
        let inventory = test_inventory(install.root(), &current_release, install_id, operation_id);
        let availability = missing_availability(&inventory);
        let planned = plan_build(request(
            install_id,
            operation_id,
            &current_release,
            &inventory,
            install.root(),
            None,
            &audit,
            &mutable,
            &availability,
        ))
        .unwrap();
        assert_eq!(planned.state, PlannedBuildState::Download);
        let plan = planned.plan.as_ref().unwrap();
        let authority = planned.disk_budget_authority.as_ref().unwrap();
        assert_eq!(
            authority
                .canonical_budget_for(plan, &inventory, install.root())
                .unwrap(),
            &plan.disk_budget
        );
        assert_eq!(
            authority
                .artifact_plan_for(plan, &inventory, install.root())
                .unwrap()
                .disk_download_reserve_bytes_for_allocation_unit(
                    plan.disk_budget.allocation_unit_bytes,
                )
                .unwrap(),
            plan.disk_budget.missing_download_bytes
        );
        let assessment = authority
            .assess_space_for(plan, &inventory, install.root())
            .unwrap();
        assert_eq!(assessment.required_bytes(), plan.disk_budget.required_bytes);
        assert_eq!(
            assessment.fits(),
            assessment.available_bytes() >= assessment.required_bytes()
        );
        assert_eq!(plan.kind, OperationKind::Install);
        assert_eq!(plan.target.generation, 1);
        assert_eq!(
            plan.target.release_id,
            current_release.manifest().release.id
        );
        assert_eq!(
            plan.target.release_manifest_sha256,
            current_release.evidence().release_manifest.sha256
        );
        assert_eq!(plan.target.runtime_lock_sha256, RUNTIME_HASH);
        assert_eq!(plan.target.game_runtime_lock_sha256, GAME_HASH);
        assert_eq!(plan.desired_files.len(), 2);
        assert!(plan.disk_budget.allocation_unit_bytes >= 1);
        assert!(plan.disk_budget.staging_bytes >= 24);
        let destination_only_entries = plan
            .mutations
            .iter()
            .filter(|mutation| {
                matches!(
                    mutation,
                    JournalMutation::Quarantine { .. } | JournalMutation::EnsureDirectory { .. }
                )
            })
            .count() as u64;
        let expected_destination_bytes = if plan.disk_budget.allocation_unit_bytes == 1 {
            plan.disk_budget.staging_bytes
        } else {
            plan.disk_budget
                .staging_bytes
                .checked_add(
                    destination_only_entries
                        .checked_mul(plan.disk_budget.allocation_unit_bytes)
                        .unwrap(),
                )
                .unwrap()
        };
        assert_eq!(
            plan.disk_budget.reconcile_destination_bytes,
            expected_destination_bytes
        );
        assert!(plan.disk_budget.missing_download_bytes > 0);
        assert!(plan.disk_budget.java_extracted_bytes > 0);
        assert!(plan.disk_budget.game_extracted_bytes > 0);
        // The synthetic lock deliberately concentrates its asset bytes into one very large file;
        // the incoming-copy reserve must therefore be derived rather than hard-coded.
        assert_eq!(
            plan.disk_budget.processor_workspace_bytes,
            processor_workspace_bytes(
                current_release.game_runtime_lock(),
                plan.disk_budget.allocation_unit_bytes,
            )
            .unwrap()
        );
        assert!(plan.disk_budget.safety_margin_bytes >= 256 * 1024 * 1024);
        assert!(plan.disk_budget.required_bytes > plan.disk_budget.staging_bytes);
        assert_eq!(
            plan.canonical_bytes().unwrap(),
            plan.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn disk_budget_authority_rejects_a_self_consistent_forged_plan_digest() {
        let install = test_install();
        let install_id = install.install_id;
        let operation_id = Uuid::new_v4();
        let current_release = trusted('a', 1);
        let audit = missing_audit();
        let mutable = mutable(false);
        let inventory = test_inventory(install.root(), &current_release, install_id, operation_id);
        let availability = missing_availability(&inventory);
        let planned = plan_build(request(
            install_id,
            operation_id,
            &current_release,
            &inventory,
            install.root(),
            None,
            &audit,
            &mutable,
            &availability,
        ))
        .unwrap();
        let authority = planned.disk_budget_authority.as_ref().unwrap();
        let mut forged = planned.plan.clone().unwrap();
        let original = &forged.disk_budget;
        forged.disk_budget = DiskBudgetV2::new_with_physical_layout(
            original.missing_download_bytes + 1,
            original.java_extracted_bytes,
            original.game_extracted_bytes,
            original.processor_workspace_bytes,
            original.allocation_unit_bytes,
            original.staging_bytes,
            original.reconcile_destination_bytes,
        )
        .unwrap();

        // A journal alone cannot reconstruct dynamic availability reserves, so this is a valid
        // structural crash record. It still cannot acquire the non-serializable authority issued
        // for the actual fresh plan.
        forged.validate(install_id, BuildChannel::Stable).unwrap();
        assert_eq!(
            authority
                .validate_for(&forged, &inventory, install.root())
                .unwrap_err(),
            "Disk budget authority canonical plan digest changed"
        );

        let rebound = TestInstall::from_owner_marker(&install);
        assert!(authority
            .validate_for(planned.plan.as_ref().unwrap(), &inventory, rebound.root(),)
            .is_err());
    }

    #[test]
    fn returns_ready_only_for_fresh_binding_exact_audit_mutable_proof_and_runtimes() {
        let install = test_install();
        let install_id = install.install_id;
        let operation_id = Uuid::new_v4();
        let installed_release = trusted('a', 1);
        let installed = active_target(
            install_id,
            BuildChannel::Stable,
            1,
            PresetId::Medium,
            &installed_release,
        )
        .unwrap();
        let fresh = trusted('a', 2);
        let audit = ready_audit();
        let mutable = mutable(true);
        let inventory = test_inventory(install.root(), &fresh, install_id, operation_id);
        let availability = ready_availability(&inventory);
        let planned = plan_build(request(
            install_id,
            operation_id,
            &fresh,
            &inventory,
            install.root(),
            Some(&installed),
            &audit,
            &mutable,
            &availability,
        ))
        .unwrap();
        assert_eq!(planned.state, PlannedBuildState::Ready);
        assert!(planned.plan.is_none());
        assert_eq!(planned.disk_budget_record.processor_workspace_bytes, 0);
        assert!(planned.disk_budget_authority.is_none());
        assert_eq!(
            planned.disk_budget_record.required_bytes,
            256 * 1024 * 1024 + 64 * 1024 * 1024 + 64 * 1024
        );
    }

    #[test]
    fn modified_current_release_is_repair_and_old_release_is_update() {
        let install = test_install();
        let install_id = install.install_id;
        let fresh = trusted('a', 1);
        let current = active_target(
            install_id,
            BuildChannel::Stable,
            1,
            PresetId::Medium,
            &fresh,
        )
        .unwrap();
        let mut audit = ready_audit();
        audit.verified_exact.clear();
        audit.modified_files.push(ModifiedFile {
            path: "mods/fragment-launch-guard.jar".into(),
            kind: ModifiedKind::Sha256,
        });
        let mutable = mutable(true);
        let repair_operation = Uuid::new_v4();
        let repair_inventory = test_inventory(install.root(), &fresh, install_id, repair_operation);
        let availability = ready_availability(&repair_inventory);
        let repair = plan_build(request(
            install_id,
            repair_operation,
            &fresh,
            &repair_inventory,
            install.root(),
            Some(&current),
            &audit,
            &mutable,
            &availability,
        ))
        .unwrap();
        assert_eq!(repair.state, PlannedBuildState::Repair);
        assert_eq!(repair.plan.unwrap().kind, OperationKind::Repair);

        let old = trusted('b', 1);
        let old_marker =
            active_target(install_id, BuildChannel::Stable, 1, PresetId::Medium, &old).unwrap();
        let target_audit = ready_audit();
        let update_operation = Uuid::new_v4();
        let update_inventory = test_inventory(install.root(), &fresh, install_id, update_operation);
        let update_availability = ready_availability(&update_inventory);
        let update = plan_build(request(
            install_id,
            update_operation,
            &fresh,
            &update_inventory,
            install.root(),
            Some(&old_marker),
            &target_audit,
            &mutable,
            &update_availability,
        ))
        .unwrap();
        assert_eq!(update.state, PlannedBuildState::Update);
        assert_eq!(update.plan.unwrap().kind, OperationKind::Update);
    }

    #[test]
    fn changed_target_with_lower_tuf_roles_is_rejected() {
        let install = test_install();
        let installed_release = trusted('a', 2);
        let installed = active_target(
            install.install_id,
            BuildChannel::Stable,
            1,
            PresetId::Medium,
            &installed_release,
        )
        .unwrap();
        let fresh = trusted('b', 1);
        let operation_id = Uuid::new_v4();
        let inventory = test_inventory(install.root(), &fresh, install.install_id, operation_id);
        let availability = ready_availability(&inventory);

        let error = plan_build(request(
            install.install_id,
            operation_id,
            &fresh,
            &inventory,
            install.root(),
            Some(&installed),
            &ready_audit(),
            &mutable(true),
            &availability,
        ))
        .unwrap_err();

        assert!(matches!(error, PlannerError::InstalledMarker(message)
            if message.contains("role versions are older")));
    }

    #[test]
    fn changed_target_with_higher_tuf_roles_is_an_update() {
        let install = test_install();
        let installed_release = trusted('a', 1);
        let installed = active_target(
            install.install_id,
            BuildChannel::Stable,
            1,
            PresetId::Medium,
            &installed_release,
        )
        .unwrap();
        let fresh = trusted('b', 2);
        let operation_id = Uuid::new_v4();
        let inventory = test_inventory(install.root(), &fresh, install.install_id, operation_id);
        let availability = ready_availability(&inventory);

        let update = plan_build(request(
            install.install_id,
            operation_id,
            &fresh,
            &inventory,
            install.root(),
            Some(&installed),
            &ready_audit(),
            &mutable(true),
            &availability,
        ))
        .unwrap();

        assert_eq!(update.state, PlannedBuildState::Update);
        assert_eq!(update.plan.unwrap().kind, OperationKind::Update);
    }

    #[test]
    fn never_trusts_a_mutable_candidate_without_named_materialization_proof() {
        let install = test_install();
        let install_id = install.install_id;
        let operation_id = Uuid::new_v4();
        let current_release = trusted('a', 1);
        let installed = active_target(
            install_id,
            BuildChannel::Stable,
            1,
            PresetId::Medium,
            &current_release,
        )
        .unwrap();
        let audit = ready_audit();
        let inventory = test_inventory(install.root(), &current_release, install_id, operation_id);
        let availability = ready_availability(&inventory);
        let error = plan_build(request(
            install_id,
            operation_id,
            &current_release,
            &inventory,
            install.root(),
            Some(&installed),
            &audit,
            &[],
            &availability,
        ))
        .unwrap_err();
        assert!(matches!(error, PlannerError::MutableProof(_)));
    }

    #[test]
    fn preset_change_and_invalid_mutable_repair_quarantine_existing_candidate_before_install() {
        let install = test_install();
        let install_id = install.install_id;
        let release = trusted('a', 1);
        let audit = ready_audit();
        let stale_materialization = mutable(false);

        let plan_for = |installed: &ActiveInstanceV2| {
            let operation_id = Uuid::new_v4();
            let inventory = test_inventory(install.root(), &release, install_id, operation_id);
            let availability = ready_availability(&inventory);
            plan_build(request(
                install_id,
                operation_id,
                &release,
                &inventory,
                install.root(),
                Some(installed),
                &audit,
                &stale_materialization,
                &availability,
            ))
            .unwrap()
            .plan
            .unwrap()
        };
        let assert_quarantine_then_install = |plan: &ReconcilePlanV2| {
            assert_eq!(plan.mutations.len(), 2);
            assert!(matches!(
                &plan.mutations[0],
                JournalMutation::Quarantine {
                    source_path,
                    backup_slot: 0,
                } if source_path == "options.txt"
            ));
            assert!(matches!(
                &plan.mutations[1],
                JournalMutation::InstallFile {
                    destination_path,
                    staging_slot: 0,
                    size: 20,
                    sha256,
                    executable: false,
                } if destination_path == "options.txt" && sha256 == MATERIALIZED_HASH
            ));
        };

        let previous_preset =
            active_target(install_id, BuildChannel::Stable, 1, PresetId::Low, &release).unwrap();
        let preset_change = plan_for(&previous_preset);
        assert_eq!(preset_change.kind, OperationKind::PresetChange);
        assert_quarantine_then_install(&preset_change);

        let current_preset = active_target(
            install_id,
            BuildChannel::Stable,
            1,
            PresetId::Medium,
            &release,
        )
        .unwrap();
        let repair = plan_for(&current_preset);
        assert_eq!(repair.kind, OperationKind::Repair);
        assert_quarantine_then_install(&repair);
    }

    #[test]
    fn planner_and_mutable_bootstrap_require_the_live_inventory_root() {
        let install = test_install();
        let rebound = TestInstall::from_owner_marker(&install);
        let install_id = install.install_id;
        let operation_id = Uuid::new_v4();
        let release = trusted('a', 1);
        let inventory = test_inventory(install.root(), &release, install_id, operation_id);
        let availability = missing_availability(&inventory);
        let audit = missing_audit();
        let mutable = mutable(false);
        let error = plan_build(request(
            install_id,
            operation_id,
            &release,
            &inventory,
            rebound.root(),
            None,
            &audit,
            &mutable,
            &availability,
        ))
        .unwrap_err();
        assert!(matches!(error, PlannerError::Availability(_)));
        assert!(plan_mutable_bootstrap(rebound.root(), &inventory, &availability).is_err());
        assert!(plan_mutable_bootstrap(install.root(), &inventory, &availability).is_ok());
    }

    #[test]
    fn recovery_rolls_forward_only_with_current_target_and_exact_staging_proof() {
        let install = test_install();
        let install_id = install.install_id;
        let operation_id = Uuid::new_v4();
        let current_release = trusted('a', 1);
        let audit = missing_audit();
        let mutable = mutable(false);
        let inventory = test_inventory(install.root(), &current_release, install_id, operation_id);
        let availability = missing_availability(&inventory);
        let planned = plan_build(request(
            install_id,
            operation_id,
            &current_release,
            &inventory,
            install.root(),
            None,
            &audit,
            &mutable,
            &availability,
        ))
        .unwrap();
        let plan = planned.plan.unwrap();
        let staging = plan
            .mutations
            .iter()
            .filter_map(|mutation| match mutation {
                JournalMutation::InstallFile {
                    destination_path,
                    staging_slot,
                    size,
                    sha256,
                    ..
                } => Some(StagingFileProofV2 {
                    staging_slot: *staging_slot,
                    destination_path: destination_path.clone(),
                    size: *size,
                    sha256: sha256.clone(),
                }),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            decide_recovery(RecoveryRequestV2 {
                plan: &plan,
                active_marker: None,
                fresh_release: &current_release,
                staging_files: &staging,
                final_audit: None,
                final_mutable_files: &[],
            }),
            RecoveryDecisionV2::RollForward
        );
        assert_eq!(
            decide_recovery(RecoveryRequestV2 {
                plan: &plan,
                active_marker: None,
                fresh_release: &current_release,
                staging_files: &staging[..staging.len() - 1],
                final_audit: None,
                final_mutable_files: &[],
            }),
            RecoveryDecisionV2::RollbackRequired(RollbackReasonV2::StagingProofIncomplete)
        );
        let moved_channel = trusted('b', 2);
        assert_eq!(
            decide_recovery(RecoveryRequestV2 {
                plan: &plan,
                active_marker: None,
                fresh_release: &moved_channel,
                staging_files: &staging,
                final_audit: None,
                final_mutable_files: &[],
            }),
            RecoveryDecisionV2::PrepareCurrentPlan
        );
    }

    #[test]
    fn committed_target_requires_exact_audit_and_signals_update_after_tuf_advance() {
        let install = test_install();
        let install_id = install.install_id;
        let operation_id = Uuid::new_v4();
        let current_release = trusted('a', 3);
        let audit = missing_audit();
        let mutable_before = mutable(false);
        let inventory = test_inventory(install.root(), &current_release, install_id, operation_id);
        let availability = missing_availability(&inventory);
        let plan = plan_build(request(
            install_id,
            operation_id,
            &current_release,
            &inventory,
            install.root(),
            None,
            &audit,
            &mutable_before,
            &availability,
        ))
        .unwrap()
        .plan
        .unwrap();
        let same_release_pending = super::super::journal::PendingJournalV2 {
            pointer: super::super::journal::JournalPointerV2 {
                schema_version: 2,
                install_id,
                channel: BuildChannel::Stable,
                operation_id,
                plan_sha256: canonical_plan_sha256(&plan).unwrap(),
            },
            plan: plan.clone(),
        };
        let same_release_identity =
            super::super::reconcile_executor::classify_untrusted_pending_identity_v2(
                &same_release_pending,
                &current_release,
            )
            .unwrap();
        assert!(matches!(
            decide_recovery(RecoveryRequestV2 {
                plan: &plan,
                active_marker: Some(&plan.target),
                fresh_release: &current_release,
                staging_files: &[],
                final_audit: None,
                final_mutable_files: &[],
            }),
            RecoveryDecisionV2::RecoveryRequired(RecoveryRequiredReasonV2::FinalAuditRequired)
        ));
        let final_audit = ReconcilePlanAuditV2::for_test(&plan, ready_audit());
        let failed_final_audit = ReconcilePlanAuditV2::for_test(&plan, audit.clone());
        let final_mutable = mutable(true);
        assert!(matches!(
            decide_recovery(RecoveryRequestV2 {
                plan: &plan,
                active_marker: Some(&plan.target),
                fresh_release: &current_release,
                staging_files: &[],
                final_audit: Some(&final_audit),
                final_mutable_files: &final_mutable,
            }),
            RecoveryDecisionV2::FinalizeCommittedTarget(_)
        ));
        let same_ready_operation_id = Uuid::new_v4();
        let same_ready_inventory = test_inventory(
            install.root(),
            &current_release,
            install_id,
            same_ready_operation_id,
        );
        let same_ready_availability = ready_availability(&same_ready_inventory);
        authorize_stale_pending_ready_abandon(
            &plan,
            &plan.target,
            &same_release_identity,
            request(
                install_id,
                same_ready_operation_id,
                &current_release,
                &same_ready_inventory,
                install.root(),
                Some(&plan.target),
                &ready_audit(),
                &final_mutable,
                &same_ready_availability,
            ),
        )
        .unwrap();
        assert!(matches!(
            decide_recovery(RecoveryRequestV2 {
                plan: &plan,
                active_marker: Some(&plan.target),
                fresh_release: &current_release,
                staging_files: &[],
                final_audit: Some(&failed_final_audit),
                final_mutable_files: &mutable_before,
            }),
            RecoveryDecisionV2::PrepareCurrentPlan
        ));

        let repair_operation_id = Uuid::new_v4();
        let repair_inventory = test_inventory(
            install.root(),
            &current_release,
            install_id,
            repair_operation_id,
        );
        let repair_availability = missing_availability(&repair_inventory);
        let repair_planned = plan_build(request(
            install_id,
            repair_operation_id,
            &current_release,
            &repair_inventory,
            install.root(),
            Some(&plan.target),
            &audit,
            &mutable_before,
            &repair_availability,
        ))
        .unwrap();
        assert_eq!(repair_planned.state, PlannedBuildState::Repair);
        let prepared_repair = prepare_current_plan_supersede(
            &plan,
            Some(&plan.target),
            &current_release,
            repair_planned,
            &repair_inventory,
            install.root(),
        )
        .unwrap();
        authorize_current_plan_supersede(CurrentPlanSupersedeRequestV2 {
            failed_plan: &plan,
            active_marker: Some(&plan.target),
            fresh_release: &current_release,
            current_final_audit: Some(&failed_final_audit),
            current_final_mutable_files: &mutable_before,
            untrusted_pending_identity: None,
            prepared_update: &prepared_repair,
            artifact_inventory: &repair_inventory,
            cas_root: install.root(),
        })
        .unwrap();

        let pending = super::super::journal::PendingJournalV2 {
            pointer: super::super::journal::JournalPointerV2 {
                schema_version: 2,
                install_id,
                channel: BuildChannel::Stable,
                operation_id,
                plan_sha256: canonical_plan_sha256(&plan).unwrap(),
            },
            plan: plan.clone(),
        };
        let untrusted_identity =
            super::super::reconcile_executor::classify_untrusted_pending_identity_v2(
                &pending,
                &current_release,
            )
            .unwrap();
        authorize_current_plan_supersede(CurrentPlanSupersedeRequestV2 {
            failed_plan: &plan,
            active_marker: Some(&plan.target),
            fresh_release: &current_release,
            current_final_audit: None,
            current_final_mutable_files: &[],
            untrusted_pending_identity: Some(&untrusted_identity),
            prepared_update: &prepared_repair,
            artifact_inventory: &repair_inventory,
            cas_root: install.root(),
        })
        .unwrap();
        let mut other_plan = plan.clone();
        other_plan.operation_id = Uuid::new_v4();
        assert!(untrusted_identity
            .validate_for(&other_plan, &current_release)
            .is_err());
        assert!(
            authorize_current_plan_supersede(CurrentPlanSupersedeRequestV2 {
                failed_plan: &plan,
                active_marker: Some(&plan.target),
                fresh_release: &current_release,
                current_final_audit: Some(&final_audit),
                current_final_mutable_files: &final_mutable,
                untrusted_pending_identity: Some(&untrusted_identity),
                prepared_update: &prepared_repair,
                artifact_inventory: &repair_inventory,
                cas_root: install.root(),
            })
            .is_err()
        );

        let advanced = trusted('b', 4);
        let advanced_identity =
            super::super::reconcile_executor::classify_untrusted_pending_identity_v2(
                &pending, &advanced,
            )
            .unwrap();
        assert!(untrusted_identity.validate_for(&plan, &advanced).is_err());
        assert!(matches!(
            decide_recovery(RecoveryRequestV2 {
                plan: &plan,
                active_marker: Some(&plan.target),
                fresh_release: &advanced,
                staging_files: &[],
                final_audit: None,
                final_mutable_files: &[],
            }),
            RecoveryDecisionV2::PrepareCurrentPlan
        ));
        assert!(matches!(
            decide_recovery(RecoveryRequestV2 {
                plan: &plan,
                active_marker: Some(&plan.target),
                fresh_release: &advanced,
                staging_files: &[],
                final_audit: Some(&final_audit),
                final_mutable_files: &final_mutable,
            }),
            RecoveryDecisionV2::PrepareCurrentPlan
        ));
        assert!(matches!(
            decide_recovery(RecoveryRequestV2 {
                plan: &plan,
                active_marker: Some(&plan.target),
                fresh_release: &advanced,
                staging_files: &[],
                final_audit: Some(&failed_final_audit),
                final_mutable_files: &mutable_before,
            }),
            RecoveryDecisionV2::PrepareCurrentPlan
        ));
        let divergent_active = active_target(
            install_id,
            BuildChannel::Stable,
            plan.target.generation + 1,
            plan.target.preset,
            &advanced,
        )
        .unwrap();
        assert!(matches!(
            decide_recovery(RecoveryRequestV2 {
                plan: &plan,
                active_marker: Some(&divergent_active),
                fresh_release: &advanced,
                staging_files: &[],
                final_audit: None,
                final_mutable_files: &[],
            }),
            RecoveryDecisionV2::PrepareCurrentPlan
        ));

        let update_operation_id = Uuid::new_v4();
        let update_inventory =
            test_inventory(install.root(), &advanced, install_id, update_operation_id);
        let update_availability = missing_availability(&update_inventory);
        let planned_update = plan_build(request(
            install_id,
            update_operation_id,
            &advanced,
            &update_inventory,
            install.root(),
            Some(&plan.target),
            &audit,
            &mutable_before,
            &update_availability,
        ))
        .unwrap();
        assert_eq!(planned_update.state, PlannedBuildState::Update);
        let prepared = prepare_current_plan_supersede(
            &plan,
            Some(&plan.target),
            &advanced,
            planned_update,
            &update_inventory,
            install.root(),
        )
        .unwrap();
        assert_eq!(prepared.plan().base.as_ref(), Some(&plan.target));
        assert!(prepared
            .disk_budget_authority()
            .validate_for(prepared.plan(), &update_inventory, install.root())
            .is_ok());
        assert!(prepared
            .artifact_plan()
            .validate_for(&update_inventory)
            .is_ok());
        assert!(
            authorize_current_plan_supersede(CurrentPlanSupersedeRequestV2 {
                failed_plan: &plan,
                active_marker: Some(&plan.target),
                fresh_release: &advanced,
                current_final_audit: None,
                current_final_mutable_files: &[],
                untrusted_pending_identity: None,
                prepared_update: &prepared,
                artifact_inventory: &update_inventory,
                cas_root: install.root(),
            })
            .is_err()
        );
        let authorization = authorize_current_plan_supersede(CurrentPlanSupersedeRequestV2 {
            failed_plan: &plan,
            active_marker: Some(&plan.target),
            fresh_release: &advanced,
            current_final_audit: None,
            current_final_mutable_files: &[],
            untrusted_pending_identity: Some(&advanced_identity),
            prepared_update: &prepared,
            artifact_inventory: &update_inventory,
            cas_root: install.root(),
        })
        .unwrap();
        let pointer = super::super::journal::JournalPointerV2 {
            schema_version: 2,
            install_id,
            channel: BuildChannel::Stable,
            operation_id,
            plan_sha256: canonical_plan_sha256(&plan).unwrap(),
        };
        authorization
            .validate_for(&pointer, &plan, prepared.plan())
            .unwrap();
        assert_eq!(authorization.continuation(), Some(&plan.target));
        let mut forged_update = prepared.plan().clone();
        forged_update.operation_id = Uuid::new_v4();
        assert!(authorization
            .validate_for(&pointer, &plan, &forged_update)
            .is_err());

        let ready_operation_id = Uuid::new_v4();
        let current_active = active_target(
            install_id,
            BuildChannel::Stable,
            plan.target.generation + 1,
            plan.target.preset,
            &advanced,
        )
        .unwrap();
        let ready_inventory =
            test_inventory(install.root(), &advanced, install_id, ready_operation_id);
        let ready_availability = ready_availability(&ready_inventory);
        let ready_audit = ready_audit();
        let ready_mutable = mutable(true);
        let ready_authorization = authorize_stale_pending_ready_abandon(
            &plan,
            &current_active,
            &advanced_identity,
            request(
                install_id,
                ready_operation_id,
                &advanced,
                &ready_inventory,
                install.root(),
                Some(&current_active),
                &ready_audit,
                &ready_mutable,
                &ready_availability,
            ),
        )
        .unwrap();
        ready_authorization.validate_for(&pointer, &plan).unwrap();
        assert_eq!(ready_authorization.continuation(), &current_active);
    }

    #[test]
    fn disk_budget_overflow_is_fail_closed() {
        assert!(DiskBudgetV2::new_with_processor_workspace(u64::MAX, 1, 0, 0, 0).is_err());
        assert!(DiskBudgetV2::new_with_processor_workspace(0, 0, 0, 0, u64::MAX).is_err());
    }

    #[test]
    fn physical_allocation_rounding_covers_tiny_file_fanout() {
        assert_eq!(round_up_allocation(1, 4096).unwrap(), 4096);
        assert_eq!(round_up_allocation(4096, 4096).unwrap(), 4096);
        assert_eq!(round_up_allocation(4097, 4096).unwrap(), 8192);
        assert_eq!(round_up_allocation(1, 64 * 1024).unwrap(), 64 * 1024);
        let tiny_files_4k = 200_000_u64.checked_mul(4096).unwrap();
        let tiny_files_64k = 200_000_u64.checked_mul(64 * 1024).unwrap();
        assert_eq!(tiny_files_4k, 819_200_000);
        assert_eq!(tiny_files_64k, 13_107_200_000);

        let lock = GameRuntimeLock::parse_and_validate(include_bytes!(
            "../../tests/fixtures/game-runtime-lock-v2-release-canonical-verified.json"
        ))
        .unwrap();
        let logical = processor_workspace_bytes(&lock, 1).unwrap();
        assert!(processor_workspace_bytes(&lock, 4096).unwrap() > logical);
        assert!(processor_workspace_bytes(&lock, 64 * 1024).unwrap() > logical);
        assert!(round_up_allocation(u64::MAX, 4096).is_err());
    }

    #[test]
    fn processor_workspace_budget_matches_the_canonical_release_lock() {
        let lock = GameRuntimeLock::parse_and_validate(include_bytes!(
            "../../tests/fixtures/game-runtime-lock-v2-release-canonical-verified.json"
        ))
        .unwrap();
        assert_eq!(processor_workspace_bytes(&lock, 1).unwrap(), 749_101_988);
    }
}
