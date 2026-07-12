use super::{
    artifact_plan::{ArtifactInventoryV2, ArtifactPlanV2, MutableBootstrapPlanV2},
    availability::VerifiedAvailabilityV2,
    contracts::{GameRuntimeSource, RuntimeLock},
    instance_state::ActiveInstanceV2,
    journal::{DiskBudgetV2, JournalMutation, OperationKind, PlannedFileV2, ReconcilePlanV2},
    reconciler::InstanceAudit,
    release::{FilePolicy, ManifestFile},
    storage::OwnedCasRoot,
    tuf::TrustedRelease,
    types::{BuildChannel, PresetId},
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::{Uuid, Version};

const RECONCILE_PLAN_SCHEMA_VERSION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PlannedBuildState {
    Download,
    Update,
    Repair,
    Ready,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlannedBuildV2 {
    pub state: PlannedBuildState,
    pub plan: Option<ReconcilePlanV2>,
    pub disk_budget: DiskBudgetV2,
    pub artifact_plan: Option<ArtifactPlanV2>,
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
    pub final_audit: Option<&'a InstanceAudit>,
    pub final_mutable_files: &'a [MutableMaterializationProofV2],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RollbackReasonV2 {
    TargetNoLongerCurrent,
    StagingProofIncomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecoveryRequiredReasonV2 {
    InvalidPlan,
    InvalidFreshRelease,
    MarkerDiverged,
    TargetNoLongerCurrentAfterCommit,
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

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RecoveryDecisionV2 {
    RollForward,
    FinalizeCommittedTarget(FinalizeCommitAuthorizationV2),
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
        if installed
            .trusted_release
            .targets_match(request.trusted_release.evidence())
            && !installed
                .trusted_release
                .is_monotonic_to(request.trusted_release.evidence())
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
            disk_budget: budget,
            artifact_plan: None,
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
    let requirements = artifact_plan.disk_download_reserve_bytes();
    let staging_bytes = audit_plan
        .mutations
        .iter()
        .try_fold(0_u64, |total, mutation| match mutation {
            JournalMutation::InstallFile { size, .. } => total.checked_add(*size),
            _ => Some(total),
        })
        .ok_or(PlannerError::Overflow("instance staging bytes"))?;
    let java_extracted_bytes = if java_generation_verified {
        0
    } else {
        sum_java_files(request.trusted_release.runtime_lock())?
    };
    let game_extracted_bytes = if game_generation_verified {
        0
    } else {
        request
            .trusted_release
            .game_runtime_lock()
            .files
            .iter()
            .try_fold(0_u64, |total, file| {
                let size = match &file.source {
                    GameRuntimeSource::Official { size, .. }
                    | GameRuntimeSource::Derived { size, .. } => *size,
                };
                total.checked_add(size)
            })
            .ok_or(PlannerError::Overflow("game runtime extracted bytes"))?
    };
    let disk_budget = DiskBudgetV2::new(
        requirements,
        java_extracted_bytes,
        game_extracted_bytes,
        staging_bytes,
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

    Ok(PlannedBuildV2 {
        state,
        plan: Some(plan),
        disk_budget,
        artifact_plan: Some(artifact_plan),
    })
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

    if request.active_marker == Some(&request.plan.target) {
        if !target_is_current {
            return RecoveryDecisionV2::RecoveryRequired(
                RecoveryRequiredReasonV2::TargetNoLongerCurrentAfterCommit,
            );
        }
        let Some(audit) = request.final_audit else {
            return RecoveryDecisionV2::RecoveryRequired(
                RecoveryRequiredReasonV2::FinalAuditRequired,
            );
        };
        return if final_audit_matches_plan(request.plan, audit, request.final_mutable_files) {
            RecoveryDecisionV2::FinalizeCommittedTarget(
                FinalizeCommitAuthorizationV2::for_exact_final_audit(request.plan, &canonical_plan),
            )
        } else {
            RecoveryDecisionV2::SupersedeForRepair(
                RepairSupersedeAuthorizationV2::for_failed_final_audit(
                    request.plan,
                    &canonical_plan,
                ),
            )
        };
    }

    let marker_is_base = match (&request.plan.base, request.active_marker) {
        (None, None) => true,
        (Some(base), Some(active)) => base == active,
        _ => false,
    };
    if !marker_is_base {
        return RecoveryDecisionV2::RecoveryRequired(RecoveryRequiredReasonV2::MarkerDiverged);
    }
    if !target_is_current {
        return RecoveryDecisionV2::RollbackRequired(RollbackReasonV2::TargetNoLongerCurrent);
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
        && marker.trusted_release.is_monotonic_to(trusted.evidence())
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

fn sum_java_files(lock: &RuntimeLock) -> Result<u64, PlannerError> {
    lock.java
        .files
        .iter()
        .try_fold(0_u64, |total, file| total.checked_add(file.size))
        .ok_or(PlannerError::Overflow("Java runtime extracted bytes"))
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

fn final_audit_matches_plan(
    plan: &ReconcilePlanV2,
    audit: &InstanceAudit,
    mutable: &[MutableMaterializationProofV2],
) -> bool {
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
        let plan = planned.plan.unwrap();
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
        assert_eq!(plan.disk_budget.staging_bytes, 24);
        assert!(plan.disk_budget.missing_download_bytes > 0);
        assert!(plan.disk_budget.java_extracted_bytes > 0);
        assert!(plan.disk_budget.game_extracted_bytes > 0);
        assert!(plan.disk_budget.safety_margin_bytes >= 256 * 1024 * 1024);
        assert!(plan.disk_budget.required_bytes > plan.disk_budget.staging_bytes);
        assert_eq!(
            plan.canonical_bytes().unwrap(),
            plan.canonical_bytes().unwrap()
        );
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
        assert_eq!(
            planned.disk_budget.required_bytes,
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
            RecoveryDecisionV2::RollbackRequired(RollbackReasonV2::TargetNoLongerCurrent)
        );
    }

    #[test]
    fn committed_target_requires_and_accepts_only_a_final_exact_audit() {
        let install = test_install();
        let install_id = install.install_id;
        let operation_id = Uuid::new_v4();
        let trusted = trusted('a', 1);
        let audit = missing_audit();
        let mutable_before = mutable(false);
        let inventory = test_inventory(install.root(), &trusted, install_id, operation_id);
        let availability = missing_availability(&inventory);
        let plan = plan_build(request(
            install_id,
            operation_id,
            &trusted,
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
        assert!(matches!(
            decide_recovery(RecoveryRequestV2 {
                plan: &plan,
                active_marker: Some(&plan.target),
                fresh_release: &trusted,
                staging_files: &[],
                final_audit: None,
                final_mutable_files: &[],
            }),
            RecoveryDecisionV2::RecoveryRequired(RecoveryRequiredReasonV2::FinalAuditRequired)
        ));
        let final_audit = ready_audit();
        let final_mutable = mutable(true);
        assert!(matches!(
            decide_recovery(RecoveryRequestV2 {
                plan: &plan,
                active_marker: Some(&plan.target),
                fresh_release: &trusted,
                staging_files: &[],
                final_audit: Some(&final_audit),
                final_mutable_files: &final_mutable,
            }),
            RecoveryDecisionV2::FinalizeCommittedTarget(_)
        ));
        assert!(matches!(
            decide_recovery(RecoveryRequestV2 {
                plan: &plan,
                active_marker: Some(&plan.target),
                fresh_release: &trusted,
                staging_files: &[],
                final_audit: Some(&audit),
                final_mutable_files: &mutable_before,
            }),
            RecoveryDecisionV2::SupersedeForRepair(_)
        ));
    }

    #[test]
    fn disk_budget_overflow_is_fail_closed() {
        assert!(DiskBudgetV2::new(u64::MAX, 1, 0, 0).is_err());
    }
}
