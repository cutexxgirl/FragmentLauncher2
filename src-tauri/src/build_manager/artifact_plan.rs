use super::{
    availability::{ArtifactAvailabilityStateV2, VerifiedAvailabilityV2},
    cas::{VerifiedCasObject, VerifiedCasPartialAllocationV2},
    contracts::{
        validate_manifest_path, validate_official_game_source, GameRuntimeLock, GameRuntimeRole,
        GameRuntimeSource, RuntimeLock,
    },
    release::FilePolicy,
    storage::OwnedCasRoot,
    tuf::{TrustedRelease, TrustedReleaseEvidence},
    types::{BuildChannel, PresetId},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use unicode_normalization::UnicodeNormalization;
use uuid::{Uuid, Version};

const INVENTORY_SCHEMA_VERSION: u8 = 2;
const MAX_ARTIFACTS: usize = 250_000;

/// Which authenticated service is allowed to provide an artifact. Keeping this in the sealed
/// requirement prevents an official Mojang/NeoForge URL from being silently replaced by Spark,
/// or a private Spark object from being fetched from an arbitrary public URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum ArtifactAuthorityV2 {
    SparkCas,
    OfficialHttps,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum ArtifactSourceV2 {
    SparkCas,
    OfficialHttps { url: String, sha1: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ArtifactProvenanceKindV2 {
    ManifestExact,
    MutableDefault,
    JavaArchive,
    GameRuntimeOfficial,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactProvenanceV2 {
    kind: ArtifactProvenanceKindV2,
    path: String,
    role: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ArtifactRequirementV2 {
    sha256: String,
    size: u64,
    authority: ArtifactAuthorityV2,
    source: ArtifactSourceV2,
    provenances: Vec<ArtifactProvenanceV2>,
}

impl ArtifactRequirementV2 {
    pub(super) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(super) fn size(&self) -> u64 {
        self.size
    }

    pub(super) fn authority(&self) -> ArtifactAuthorityV2 {
        self.authority
    }

    pub(super) fn official_source(&self) -> Option<(&str, &str)> {
        match &self.source {
            ArtifactSourceV2::OfficialHttps { url, sha1 } => Some((url, sha1)),
            ArtifactSourceV2::SparkCas => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactBindingV2 {
    schema_version: u8,
    install_id: Uuid,
    operation_id: Uuid,
    channel: BuildChannel,
    preset: PresetId,
    release_id: String,
    tuf_root_version: u64,
    evidence: TrustedReleaseEvidence,
    cas_root: CasRootBindingV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct CasRootBindingV2 {
    binding_nonce: Uuid,
    install_root_volume: u64,
    install_root_file_id: [u8; 16],
    objects_root_volume: u64,
    objects_root_file_id: [u8; 16],
}

/// A release-bound candidate inventory. Its fields and constructor are private to this module;
/// callers can inspect requirements but cannot append a hash or rewrite its trust binding.
#[derive(Debug)]
pub(super) struct ArtifactInventoryV2 {
    binding: ArtifactBindingV2,
    fingerprint: String,
    artifacts: Vec<ArtifactRequirementV2>,
    manifest_by_path: BTreeMap<String, String>,
    mutable_by_path: BTreeMap<String, String>,
    java_archive_sha256: String,
    official_sha256: Vec<String>,
    runtime_lock: RuntimeLock,
    game_runtime_lock: GameRuntimeLock,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlannedArtifactV2 {
    requirement: ArtifactRequirementV2,
    availability: ArtifactAvailabilityStateV2,
    resume_from: u64,
    partial_allocation: Option<VerifiedCasPartialAllocationV2>,
}

/// A short-lived view that is usable only while the exact owned CAS capability is live. It is
/// created from a sealed plan and yields non-constructible execution items for Spark or a future
/// official downloader.
pub(super) struct ArtifactExecutionViewV2<'a> {
    binding: &'a ArtifactBindingV2,
    inventory: &'a ArtifactInventoryV2,
    requirements: &'a [PlannedArtifactV2],
}

pub(super) struct PlannedArtifactExecutionV2<'a> {
    binding: &'a ArtifactBindingV2,
    inventory: &'a ArtifactInventoryV2,
    planned: &'a PlannedArtifactV2,
}

/// Exact Java-install authority extracted from one sealed reconcile plan. The constructor is
/// private and succeeds only when that plan actually reserved/verified the signed Java archive.
pub(super) struct PlannedJavaArchiveV2<'a> {
    binding: &'a ArtifactBindingV2,
    inventory: &'a ArtifactInventoryV2,
    planned: &'a PlannedArtifactV2,
}

/// Non-serializable authority for assembling the immutable 4,028-file game generation. It can
/// only be extracted from a sealed reconcile plan which contains every official game requirement,
/// and it owns the exact post-download, root-bound CAS capabilities for that set.
pub(super) struct PlannedGameGenerationV2<'a> {
    binding: &'a ArtifactBindingV2,
    inventory: &'a ArtifactInventoryV2,
    plan: &'a ArtifactPlanV2,
    official_objects: BTreeMap<String, VerifiedCasObject>,
    generation_binding: PlannedGameGenerationBindingV2,
}

/// Opaque, cloneable correlation token for processor/publication results. Private fields prevent
/// another module from manufacturing a result for a different operation, release, root or lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlannedGameGenerationBindingV2 {
    digest: String,
    install_id: Uuid,
    operation_id: Uuid,
    root_binding_nonce: Uuid,
    inventory_fingerprint: String,
    runtime_lock_sha256: String,
    game_runtime_lock_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ArtifactExecutionSourceV2<'a> {
    SparkCas,
    OfficialHttps { url: &'a str, sha1: &'a str },
}

impl<'a> ArtifactExecutionViewV2<'a> {
    pub(super) fn items(&self) -> impl ExactSizeIterator<Item = PlannedArtifactExecutionV2<'_>> {
        self.requirements
            .iter()
            .map(|planned| PlannedArtifactExecutionV2 {
                binding: self.binding,
                inventory: self.inventory,
                planned,
            })
    }
}

impl PlannedArtifactExecutionV2<'_> {
    pub(super) fn validate_root(&self, root: &OwnedCasRoot) -> Result<(), String> {
        self.inventory.validate_root(root)?;
        if self.binding != &self.inventory.binding
            || self
                .inventory
                .requirement(&self.planned.requirement.sha256)?
                != &self.planned.requirement
        {
            return Err("Planned artifact execution binding is invalid".into());
        }
        Ok(())
    }

    pub(super) fn sha256(&self) -> &str {
        &self.planned.requirement.sha256
    }

    pub(super) fn size(&self) -> u64 {
        self.planned.requirement.size
    }

    pub(super) fn resume_from(&self) -> u64 {
        self.planned.resume_from
    }

    pub(super) fn availability(&self) -> ArtifactAvailabilityStateV2 {
        self.planned.availability
    }

    pub(super) fn partial_allocation(&self) -> Option<&VerifiedCasPartialAllocationV2> {
        self.planned.partial_allocation.as_ref()
    }

    pub(super) fn channel(&self) -> BuildChannel {
        self.binding.channel
    }

    pub(super) fn preset(&self) -> PresetId {
        self.binding.preset
    }

    pub(super) fn release_id(&self) -> &str {
        &self.binding.release_id
    }

    pub(super) fn source(&self) -> ArtifactExecutionSourceV2<'_> {
        match &self.planned.requirement.source {
            ArtifactSourceV2::SparkCas => ArtifactExecutionSourceV2::SparkCas,
            ArtifactSourceV2::OfficialHttps { url, sha1 } => {
                ArtifactExecutionSourceV2::OfficialHttps { url, sha1 }
            }
        }
    }
}

/// Non-serializable download authority for exactly one reconcile operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ArtifactPlanV2 {
    binding: ArtifactBindingV2,
    inventory_fingerprint: String,
    requirements: Vec<PlannedArtifactV2>,
    network_bytes: u64,
    disk_download_reserve_bytes: u64,
}

/// The only pre-planner exception: canonical signed defaults needed to materialize and validate
/// user-mutable settings. It carries the same operation/release binding as the final plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MutableBootstrapPlanV2 {
    binding: ArtifactBindingV2,
    inventory_fingerprint: String,
    requirements: Vec<PlannedArtifactV2>,
    network_bytes: u64,
    disk_download_reserve_bytes: u64,
}

impl ArtifactInventoryV2 {
    pub(super) fn build(
        root: &OwnedCasRoot,
        trusted: &TrustedRelease,
        install_id: Uuid,
        operation_id: Uuid,
        channel: BuildChannel,
        preset: PresetId,
    ) -> Result<Self, String> {
        root.revalidate()?;
        validate_release_binding(trusted, channel)?;
        if install_id.is_nil()
            || operation_id.is_nil()
            || operation_id.get_version() != Some(Version::Random)
        {
            return Err("Artifact inventory requires an install ID and operation UUIDv4".into());
        }
        let (root_nonce, root_install_id, install_identity, objects_identity) = root.binding();
        if root_install_id != install_id {
            return Err("Owned CAS root belongs to another install ID".into());
        }
        let selected = trusted.manifest().selected_preset(preset)?;
        let binding = ArtifactBindingV2 {
            schema_version: INVENTORY_SCHEMA_VERSION,
            install_id,
            operation_id,
            channel,
            preset,
            release_id: trusted.manifest().release.id.clone(),
            tuf_root_version: trusted.tuf_root_version(),
            evidence: trusted.evidence().clone(),
            cas_root: CasRootBindingV2 {
                binding_nonce: root_nonce,
                install_root_volume: install_identity.volume_serial_number,
                install_root_file_id: install_identity.file_id,
                objects_root_volume: objects_identity.volume_serial_number,
                objects_root_file_id: objects_identity.file_id,
            },
        };

        let mut by_sha = BTreeMap::<String, ArtifactRequirementV2>::new();
        let mut manifest_by_path = BTreeMap::new();
        let mut mutable_by_path = BTreeMap::new();
        let mut manifest_paths = BTreeMap::new();
        for file in &selected.files {
            validate_manifest_path(&file.path)?;
            register_path(&mut manifest_paths, &file.path, "manifest")?;
            let key = path_key(&file.path);
            if manifest_by_path
                .insert(key.clone(), file.sha256.clone())
                .is_some()
            {
                return Err("Selected preset contains duplicate artifact paths".into());
            }
            let kind = match file.policy {
                FilePolicy::Exact => ArtifactProvenanceKindV2::ManifestExact,
                FilePolicy::ValidatedMutable => {
                    mutable_by_path.insert(key, file.sha256.clone());
                    ArtifactProvenanceKindV2::MutableDefault
                }
            };
            insert_requirement(
                &mut by_sha,
                ArtifactRequirementV2 {
                    sha256: file.sha256.clone(),
                    size: file.size,
                    authority: ArtifactAuthorityV2::SparkCas,
                    source: ArtifactSourceV2::SparkCas,
                    provenances: vec![ArtifactProvenanceV2 {
                        kind,
                        path: file.path.clone(),
                        role: None,
                    }],
                },
            )?;
        }

        let java_archive_sha256 = trusted.runtime_lock().java.archive.sha256.clone();
        insert_requirement(
            &mut by_sha,
            ArtifactRequirementV2 {
                sha256: java_archive_sha256.clone(),
                size: trusted.runtime_lock().java.archive.size,
                authority: ArtifactAuthorityV2::SparkCas,
                source: ArtifactSourceV2::SparkCas,
                provenances: vec![ArtifactProvenanceV2 {
                    kind: ArtifactProvenanceKindV2::JavaArchive,
                    path: "runtime/java/archive".into(),
                    role: None,
                }],
            },
        )?;

        let mut official_sha256 = BTreeSet::new();
        let mut game_paths = BTreeMap::new();
        for file in &trusted.game_runtime_lock().files {
            validate_manifest_path(&file.path)?;
            register_path(&mut game_paths, &file.path, "game runtime")?;
            let GameRuntimeSource::Official {
                url,
                size,
                sha1,
                sha256,
            } = &file.source
            else {
                continue;
            };
            validate_official_game_source(url, sha1)?;
            official_sha256.insert(sha256.clone());
            insert_requirement(
                &mut by_sha,
                ArtifactRequirementV2 {
                    sha256: sha256.clone(),
                    size: *size,
                    authority: ArtifactAuthorityV2::OfficialHttps,
                    source: ArtifactSourceV2::OfficialHttps {
                        url: url.clone(),
                        sha1: sha1.clone(),
                    },
                    provenances: vec![ArtifactProvenanceV2 {
                        kind: ArtifactProvenanceKindV2::GameRuntimeOfficial,
                        path: file.path.clone(),
                        role: Some(role_name(file.role)?),
                    }],
                },
            )?;
        }
        if by_sha.len() > MAX_ARTIFACTS {
            return Err("Artifact inventory exceeds the launcher limit".into());
        }
        let artifacts = by_sha.into_values().collect::<Vec<_>>();
        let fingerprint = inventory_fingerprint(&binding, &artifacts)?;
        root.revalidate()?;
        let inventory = Self {
            binding,
            fingerprint,
            artifacts,
            manifest_by_path,
            mutable_by_path,
            java_archive_sha256,
            official_sha256: official_sha256.into_iter().collect(),
            runtime_lock: trusted.runtime_lock().clone(),
            game_runtime_lock: trusted.game_runtime_lock().clone(),
        };
        inventory.validate_root(root)?;
        Ok(inventory)
    }

    pub(super) fn artifacts(&self) -> &[ArtifactRequirementV2] {
        &self.artifacts
    }

    pub(super) fn install_id(&self) -> Uuid {
        self.binding.install_id
    }

    pub(super) fn operation_id(&self) -> Uuid {
        self.binding.operation_id
    }

    pub(super) fn release_id(&self) -> &str {
        &self.binding.release_id
    }

    pub(super) fn trusted_evidence(&self) -> &TrustedReleaseEvidence {
        &self.binding.evidence
    }

    pub(super) fn runtime_lock(&self) -> &RuntimeLock {
        &self.runtime_lock
    }

    pub(super) fn game_runtime_lock(&self) -> &GameRuntimeLock {
        &self.game_runtime_lock
    }

    pub(super) fn java_runtime_lock_sha256(&self) -> &str {
        &self.binding.evidence.java_runtime_lock.sha256
    }

    pub(super) fn game_runtime_lock_sha256(&self) -> &str {
        &self.binding.evidence.game_runtime_lock.sha256
    }

    pub(super) fn java_archive_sha256(&self) -> &str {
        &self.java_archive_sha256
    }

    pub(super) fn official_game_sha256(&self) -> &[String] {
        &self.official_sha256
    }

    pub(super) fn mutable_default_sha256(&self, path: &str) -> Result<&str, String> {
        self.mutable_by_path
            .get(&path_key(path))
            .map(String::as_str)
            .ok_or_else(|| format!("Artifact inventory has no mutable default for {path}"))
    }

    pub(super) fn manifest_sha256(&self, path: &str) -> Result<&str, String> {
        self.manifest_by_path
            .get(&path_key(path))
            .map(String::as_str)
            .ok_or_else(|| format!("Artifact inventory has no manifest object for {path}"))
    }

    pub(super) fn is_java_archive_sha256(&self, sha256: &str) -> bool {
        self.java_archive_sha256 == sha256
    }

    pub(super) fn is_official_game_sha256(&self, sha256: &str) -> bool {
        self.official_sha256
            .binary_search_by(|candidate| candidate.as_str().cmp(sha256))
            .is_ok()
    }

    pub(super) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(super) fn root_binding_nonce(&self) -> Uuid {
        self.binding.cas_root.binding_nonce
    }

    pub(super) fn validate_root(&self, root: &OwnedCasRoot) -> Result<(), String> {
        root.revalidate()?;
        let (nonce, install_id, install_identity, objects_identity) = root.binding();
        if install_id != self.binding.install_id
            || nonce != self.binding.cas_root.binding_nonce
            || install_identity.volume_serial_number != self.binding.cas_root.install_root_volume
            || install_identity.file_id != self.binding.cas_root.install_root_file_id
            || objects_identity.volume_serial_number != self.binding.cas_root.objects_root_volume
            || objects_identity.file_id != self.binding.cas_root.objects_root_file_id
        {
            return Err("Owned CAS root differs from the sealed artifact inventory".into());
        }
        Ok(())
    }

    pub(super) fn validate_request(
        &self,
        trusted: &TrustedRelease,
        install_id: Uuid,
        operation_id: Uuid,
        channel: BuildChannel,
        preset: PresetId,
    ) -> Result<(), String> {
        validate_release_binding(trusted, channel)?;
        if self.binding.install_id != install_id
            || self.binding.operation_id != operation_id
            || self.binding.channel != channel
            || self.binding.preset != preset
            || self.binding.release_id != trusted.manifest().release.id
            || self.binding.tuf_root_version != trusted.tuf_root_version()
            || self.binding.evidence != *trusted.evidence()
            || inventory_fingerprint(&self.binding, &self.artifacts)? != self.fingerprint
        {
            return Err("Artifact inventory belongs to another trusted operation".into());
        }
        Ok(())
    }

    fn requirement(&self, sha256: &str) -> Result<&ArtifactRequirementV2, String> {
        self.artifacts
            .binary_search_by(|candidate| candidate.sha256.as_str().cmp(sha256))
            .ok()
            .map(|index| &self.artifacts[index])
            .ok_or_else(|| "Artifact inventory is missing its own requirement".into())
    }
}

impl ArtifactPlanV2 {
    pub(super) fn for_reconcile(
        inventory: &ArtifactInventoryV2,
        availability: &VerifiedAvailabilityV2,
        install_paths: impl IntoIterator<Item = String>,
    ) -> Result<Self, String> {
        availability.validate_for(inventory)?;
        let mut hashes = BTreeSet::new();
        for path in install_paths {
            let hash = inventory
                .manifest_by_path
                .get(&path_key(&path))
                .ok_or_else(|| format!("Reconcile requested an unsigned artifact path: {path}"))?;
            hashes.insert(hash.clone());
        }
        if !availability.java_generation_complete() {
            hashes.insert(inventory.java_archive_sha256.clone());
        }
        if !availability.game_generation_complete() {
            hashes.extend(inventory.official_sha256.iter().cloned());
        }
        let (requirements, network_bytes, disk_download_reserve_bytes) =
            missing_requirements(inventory, availability, hashes)?;
        Ok(Self {
            binding: inventory.binding.clone(),
            inventory_fingerprint: inventory.fingerprint.clone(),
            requirements,
            network_bytes,
            disk_download_reserve_bytes,
        })
    }

    pub(super) fn execution_view<'a>(
        &'a self,
        root: &OwnedCasRoot,
        inventory: &'a ArtifactInventoryV2,
    ) -> Result<ArtifactExecutionViewV2<'a>, String> {
        self.validate_for(inventory)?;
        inventory.validate_root(root)?;
        Ok(ArtifactExecutionViewV2 {
            binding: &self.binding,
            inventory,
            requirements: &self.requirements,
        })
    }

    pub(super) fn java_archive<'a>(
        &'a self,
        root: &OwnedCasRoot,
        inventory: &'a ArtifactInventoryV2,
    ) -> Result<PlannedJavaArchiveV2<'a>, String> {
        self.validate_for(inventory)?;
        inventory.validate_root(root)?;
        let planned = self
            .requirements
            .binary_search_by(|candidate| {
                candidate
                    .requirement
                    .sha256
                    .as_str()
                    .cmp(&inventory.java_archive_sha256)
            })
            .ok()
            .and_then(|index| self.requirements.get(index))
            .ok_or_else(|| {
                "Artifact plan does not authorize Java runtime installation".to_string()
            })?;
        let expected = inventory.requirement(&inventory.java_archive_sha256)?;
        if &planned.requirement != expected
            || expected.authority != ArtifactAuthorityV2::SparkCas
            || expected.source != ArtifactSourceV2::SparkCas
            || expected.provenances
                != [ArtifactProvenanceV2 {
                    kind: ArtifactProvenanceKindV2::JavaArchive,
                    path: "runtime/java/archive".into(),
                    role: None,
                }]
        {
            return Err("Artifact plan Java archive authority is invalid".into());
        }
        Ok(PlannedJavaArchiveV2 {
            binding: &self.binding,
            inventory,
            planned,
        })
    }

    pub(super) fn game_generation<'a>(
        &'a self,
        root: &OwnedCasRoot,
        inventory: &'a ArtifactInventoryV2,
        official_objects: Vec<VerifiedCasObject>,
    ) -> Result<PlannedGameGenerationV2<'a>, String> {
        self.validate_game_generation_plan(root, inventory)?;
        let official_objects = collect_exact_official_objects(
            inventory,
            official_objects,
            |object| (object.sha256(), object.size()),
            |object| {
                object
                    .open(root)
                    .map(drop)
                    .map_err(|error| format!("Official CAS capability is not live: {error}"))
            },
        )?;
        let digest = game_generation_binding_digest(&self.binding, inventory)?;
        Ok(PlannedGameGenerationV2 {
            binding: &self.binding,
            inventory,
            plan: self,
            official_objects,
            generation_binding: PlannedGameGenerationBindingV2 {
                digest,
                install_id: self.binding.install_id,
                operation_id: self.binding.operation_id,
                root_binding_nonce: self.binding.cas_root.binding_nonce,
                inventory_fingerprint: inventory.fingerprint.clone(),
                runtime_lock_sha256: inventory.java_runtime_lock_sha256().to_owned(),
                game_runtime_lock_sha256: inventory.game_runtime_lock_sha256().to_owned(),
            },
        })
    }

    fn validate_game_generation_plan(
        &self,
        root: &OwnedCasRoot,
        inventory: &ArtifactInventoryV2,
    ) -> Result<(), String> {
        self.validate_for(inventory)?;
        inventory.validate_root(root)?;
        validate_exact_official_inventory(inventory)?;
        if inventory_fingerprint(&inventory.binding, &inventory.artifacts)? != inventory.fingerprint
        {
            return Err("Game generation inventory fingerprint changed".into());
        }
        let planned_official = self
            .requirements
            .iter()
            .filter(|planned| planned.requirement.authority == ArtifactAuthorityV2::OfficialHttps)
            .collect::<Vec<_>>();
        if planned_official.len() != inventory.official_sha256.len() {
            return Err(
                "Artifact plan does not authorize the exact official game artifact set".into(),
            );
        }
        for (planned, expected_sha256) in planned_official.iter().zip(&inventory.official_sha256) {
            let expected = inventory.requirement(expected_sha256)?;
            if planned.requirement.sha256 != *expected_sha256 || &planned.requirement != expected {
                return Err("Artifact plan contains a forged official game requirement".into());
            }
        }
        Ok(())
    }

    pub(super) fn network_bytes(&self) -> u64 {
        self.network_bytes
    }

    pub(super) fn disk_download_reserve_bytes(&self) -> u64 {
        self.disk_download_reserve_bytes
    }

    pub(super) fn disk_download_reserve_bytes_for_allocation_unit(
        &self,
        allocation_unit: u64,
    ) -> Result<u64, String> {
        if allocation_unit == 0 {
            return Err("Artifact disk allocation unit is zero".into());
        }
        let content = self.requirements.iter().try_fold(0_u64, |total, planned| {
            let charge = if planned.availability == ArtifactAvailabilityStateV2::Complete {
                0
            } else {
                round_up_allocation(planned.requirement.size, allocation_unit)?
            };
            total
                .checked_add(charge)
                .ok_or_else(|| "Artifact physical disk reserve overflow".to_string())
        })?;
        content
            .checked_add(artifact_namespace_reserve(
                &self.requirements,
                allocation_unit,
            )?)
            .ok_or_else(|| "Artifact physical namespace reserve overflow".to_string())
    }

    /// Revalidates every credited partial against the exact live CAS root and charges only
    /// clusters already proven to be physically allocated. Missing/uncredited objects retain the
    /// full rounded-final reserve. Network accounting deliberately remains the full signed size.
    pub(super) fn validated_disk_download_reserve_bytes(
        &self,
        root: &OwnedCasRoot,
        inventory: &ArtifactInventoryV2,
    ) -> Result<u64, String> {
        self.validate_for(inventory)?;
        inventory.validate_root(root)?;
        let allocation_unit = super::planner::filesystem_allocation_unit(root.install_root())?;
        if allocation_unit == 0 {
            return Err("Artifact disk allocation unit is zero".into());
        }
        let content = self.requirements.iter().try_fold(0_u64, |total, planned| {
            let rounded_final = round_up_allocation(planned.requirement.size, allocation_unit)?;
            let charge = if planned.availability == ArtifactAvailabilityStateV2::Complete {
                0
            } else if let Some(evidence) = &planned.partial_allocation {
                evidence.validate_live(
                    root,
                    &planned.requirement.sha256,
                    planned.requirement.size,
                )?;
                rounded_final.saturating_sub(evidence.allocated_size().min(rounded_final))
            } else {
                rounded_final
            };
            total
                .checked_add(charge)
                .ok_or_else(|| "Artifact physical disk reserve overflow".to_string())
        })?;
        let reserve = content
            .checked_add(artifact_namespace_reserve(
                &self.requirements,
                allocation_unit,
            )?)
            .ok_or_else(|| "Artifact physical namespace reserve overflow".to_string())?;
        inventory.validate_root(root)?;
        Ok(reserve)
    }

    pub(super) fn validate_for(&self, inventory: &ArtifactInventoryV2) -> Result<(), String> {
        if self.binding != inventory.binding
            || self.inventory_fingerprint != inventory.fingerprint
            || self
                .requirements
                .windows(2)
                .any(|pair| pair[0].requirement.sha256 >= pair[1].requirement.sha256)
        {
            return Err("Artifact plan binding or canonical order is invalid".into());
        }
        let (network, reserve) = self.requirements.iter().try_fold(
            (0_u64, 0_u64),
            |(network, reserve), planned| -> Result<(u64, u64), String> {
                let expected = inventory.requirement(&planned.requirement.sha256)?;
                if expected != &planned.requirement || !valid_planned_availability(planned) {
                    return Err("Artifact plan contains a forged requirement".into());
                }
                if let Some(evidence) = &planned.partial_allocation {
                    evidence.validate_sealed_identity(
                        self.binding.cas_root.binding_nonce,
                        self.binding.install_id,
                        planned.requirement.sha256(),
                        planned.requirement.size(),
                    )?;
                }
                let charge = if planned.availability == ArtifactAvailabilityStateV2::Complete {
                    0
                } else {
                    planned.requirement.size
                };
                let network = network
                    .checked_add(charge)
                    .ok_or_else(|| "Artifact plan network byte total overflow".to_string())?;
                let reserve = reserve
                    .checked_add(charge)
                    .ok_or_else(|| "Artifact plan disk reserve overflow".to_string())?;
                Ok((network, reserve))
            },
        )?;
        if network != self.network_bytes || reserve != self.disk_download_reserve_bytes {
            return Err("Artifact plan byte total changed".into());
        }
        Ok(())
    }

    /// Proves that every reconcile install path is backed by a manifest artifact carried by this
    /// exact sealed download plan. Runtime-only requirements may also be present; callers still
    /// cannot turn them into instance files because path authorization stays in the inventory.
    pub(super) fn validate_reconcile_install_paths<'a>(
        &self,
        root: &OwnedCasRoot,
        inventory: &ArtifactInventoryV2,
        install_paths: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), String> {
        self.validate_for(inventory)?;
        inventory.validate_root(root)?;
        let mut seen = BTreeSet::new();
        for path in install_paths {
            let key = path_key(path);
            if !seen.insert(key.clone()) {
                return Err("Reconcile staging paths are duplicated or case-colliding".into());
            }
            let sha256 = inventory
                .manifest_by_path
                .get(&key)
                .ok_or_else(|| format!("Reconcile staging path is not in the manifest: {path}"))?;
            let planned = self
                .requirements
                .binary_search_by(|candidate| candidate.requirement.sha256.as_str().cmp(sha256))
                .ok()
                .and_then(|index| self.requirements.get(index))
                .ok_or_else(|| format!("Artifact plan does not authorize staging path: {path}"))?;
            let expected = inventory.requirement(sha256)?;
            if &planned.requirement != expected
                || !expected.provenances.iter().any(|provenance| {
                    provenance.path == path
                        && matches!(
                            provenance.kind,
                            ArtifactProvenanceKindV2::ManifestExact
                                | ArtifactProvenanceKindV2::MutableDefault
                        )
                })
            {
                return Err(format!(
                    "Artifact plan staging provenance is invalid for path: {path}"
                ));
            }
        }
        root.revalidate()?;
        Ok(())
    }
}

impl PlannedJavaArchiveV2<'_> {
    pub(super) fn validate_root(&self, root: &OwnedCasRoot) -> Result<(), String> {
        self.inventory.validate_root(root)?;
        if self.binding != &self.inventory.binding
            || self.planned.requirement.sha256 != self.inventory.java_archive_sha256
            || self
                .inventory
                .requirement(&self.planned.requirement.sha256)?
                != &self.planned.requirement
        {
            return Err("Planned Java archive binding is invalid".into());
        }
        Ok(())
    }

    pub(super) fn sha256(&self) -> &str {
        &self.planned.requirement.sha256
    }

    pub(super) fn size(&self) -> u64 {
        self.planned.requirement.size
    }

    pub(super) fn runtime_lock(&self) -> &RuntimeLock {
        &self.inventory.runtime_lock
    }

    pub(super) fn runtime_lock_sha256(&self) -> &str {
        self.inventory.java_runtime_lock_sha256()
    }
}

impl PlannedGameGenerationV2<'_> {
    pub(super) fn validate_root(&self, root: &OwnedCasRoot) -> Result<(), String> {
        self.plan
            .validate_game_generation_plan(root, self.inventory)?;
        if self.binding != &self.inventory.binding
            || self.generation_binding.digest
                != game_generation_binding_digest(self.binding, self.inventory)?
            || self.official_objects.len() != self.inventory.official_sha256.len()
        {
            return Err("Planned game generation binding is invalid".into());
        }
        for (sha256, object) in &self.official_objects {
            let expected = self.inventory.requirement(sha256)?;
            if expected.authority != ArtifactAuthorityV2::OfficialHttps
                || object.sha256() != sha256
                || object.size() != expected.size
            {
                return Err("Planned game generation CAS set changed".into());
            }
            object
                .open(root)
                .map(drop)
                .map_err(|error| format!("Official CAS capability is no longer live: {error}"))?;
        }
        Ok(())
    }

    pub(super) fn binding(&self) -> PlannedGameGenerationBindingV2 {
        self.generation_binding.clone()
    }

    pub(super) fn validate_binding(
        &self,
        candidate: &PlannedGameGenerationBindingV2,
    ) -> Result<(), String> {
        if candidate != &self.generation_binding {
            return Err("Game generation result belongs to another sealed plan".into());
        }
        Ok(())
    }

    pub(super) fn binding_digest(&self) -> &str {
        &self.generation_binding.digest
    }

    pub(super) fn inventory_fingerprint(&self) -> &str {
        &self.inventory.fingerprint
    }

    pub(super) fn install_id(&self) -> Uuid {
        self.binding.install_id
    }

    pub(super) fn operation_id(&self) -> Uuid {
        self.binding.operation_id
    }

    pub(super) fn root_binding_nonce(&self) -> Uuid {
        self.binding.cas_root.binding_nonce
    }

    pub(super) fn release_id(&self) -> &str {
        &self.binding.release_id
    }

    pub(super) fn trusted_evidence(&self) -> &TrustedReleaseEvidence {
        &self.binding.evidence
    }

    pub(super) fn runtime_lock(&self) -> &RuntimeLock {
        &self.inventory.runtime_lock
    }

    pub(super) fn game_runtime_lock(&self) -> &GameRuntimeLock {
        &self.inventory.game_runtime_lock
    }

    pub(super) fn runtime_lock_sha256(&self) -> &str {
        self.inventory.java_runtime_lock_sha256()
    }

    pub(super) fn game_runtime_lock_sha256(&self) -> &str {
        self.inventory.game_runtime_lock_sha256()
    }

    pub(super) fn official_object_count(&self) -> usize {
        self.official_objects.len()
    }

    pub(super) fn official_object(&self, sha256: &str) -> Result<&VerifiedCasObject, String> {
        if self
            .inventory
            .official_sha256
            .binary_search_by(|candidate| candidate.as_str().cmp(sha256))
            .is_err()
        {
            return Err("Game generation requested a non-official CAS object".into());
        }
        self.official_objects
            .get(sha256)
            .ok_or_else(|| "Game generation is missing an official CAS capability".into())
    }

    pub(super) fn official_objects(
        &self,
    ) -> impl ExactSizeIterator<Item = (&str, &VerifiedCasObject)> {
        self.official_objects
            .iter()
            .map(|(sha256, object)| (sha256.as_str(), object))
    }
}

impl PlannedGameGenerationBindingV2 {
    pub(super) fn digest(&self) -> &str {
        &self.digest
    }

    pub(super) fn install_id(&self) -> Uuid {
        self.install_id
    }

    pub(super) fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub(super) fn root_binding_nonce(&self) -> Uuid {
        self.root_binding_nonce
    }

    pub(super) fn inventory_fingerprint(&self) -> &str {
        &self.inventory_fingerprint
    }

    pub(super) fn runtime_lock_sha256(&self) -> &str {
        &self.runtime_lock_sha256
    }

    pub(super) fn game_runtime_lock_sha256(&self) -> &str {
        &self.game_runtime_lock_sha256
    }
}

impl MutableBootstrapPlanV2 {
    pub(super) fn build(
        inventory: &ArtifactInventoryV2,
        availability: &VerifiedAvailabilityV2,
    ) -> Result<Self, String> {
        availability.validate_for(inventory)?;
        let hashes = inventory
            .mutable_by_path
            .values()
            .cloned()
            .collect::<BTreeSet<_>>();
        let (requirements, network_bytes, disk_download_reserve_bytes) =
            missing_requirements(inventory, availability, hashes)?;
        Ok(Self {
            binding: inventory.binding.clone(),
            inventory_fingerprint: inventory.fingerprint.clone(),
            requirements,
            network_bytes,
            disk_download_reserve_bytes,
        })
    }

    pub(super) fn execution_view<'a>(
        &'a self,
        root: &OwnedCasRoot,
        inventory: &'a ArtifactInventoryV2,
    ) -> Result<ArtifactExecutionViewV2<'a>, String> {
        self.validate_for(inventory)?;
        inventory.validate_root(root)?;
        Ok(ArtifactExecutionViewV2 {
            binding: &self.binding,
            inventory,
            requirements: &self.requirements,
        })
    }

    pub(super) fn network_bytes(&self) -> u64 {
        self.network_bytes
    }

    pub(super) fn disk_download_reserve_bytes(&self) -> u64 {
        self.disk_download_reserve_bytes
    }

    pub(super) fn validated_disk_download_reserve_bytes(
        &self,
        root: &OwnedCasRoot,
        inventory: &ArtifactInventoryV2,
    ) -> Result<u64, String> {
        self.validate_for(inventory)?;
        inventory.validate_root(root)?;
        let allocation_unit = super::planner::filesystem_allocation_unit(root.install_root())?;
        if allocation_unit == 0 {
            return Err("Mutable bootstrap allocation unit is zero".into());
        }
        let content = self.requirements.iter().try_fold(0_u64, |total, planned| {
            let rounded_final = round_up_allocation(planned.requirement.size, allocation_unit)?;
            let charge = if planned.availability == ArtifactAvailabilityStateV2::Complete {
                0
            } else if let Some(evidence) = &planned.partial_allocation {
                evidence.validate_live(
                    root,
                    &planned.requirement.sha256,
                    planned.requirement.size,
                )?;
                rounded_final.saturating_sub(evidence.allocated_size().min(rounded_final))
            } else {
                rounded_final
            };
            total
                .checked_add(charge)
                .ok_or_else(|| "Mutable bootstrap physical reserve overflow".to_string())
        })?;
        let reserve = content
            .checked_add(artifact_namespace_reserve(
                &self.requirements,
                allocation_unit,
            )?)
            .ok_or_else(|| "Mutable bootstrap namespace reserve overflow".to_string())?;
        inventory.validate_root(root)?;
        Ok(reserve)
    }

    pub(super) fn validate_for(&self, inventory: &ArtifactInventoryV2) -> Result<(), String> {
        if self.binding != inventory.binding || self.inventory_fingerprint != inventory.fingerprint
        {
            return Err("Mutable bootstrap belongs to another trusted operation".into());
        }
        if self
            .requirements
            .windows(2)
            .any(|pair| pair[0].requirement.sha256 >= pair[1].requirement.sha256)
        {
            return Err("Mutable bootstrap requirements are not canonical".into());
        }
        let mut network = 0_u64;
        let mut reserve = 0_u64;
        for planned in &self.requirements {
            let expected = inventory.requirement(planned.requirement.sha256())?;
            if expected != &planned.requirement
                || !valid_planned_availability(planned)
                || !inventory
                    .mutable_by_path
                    .values()
                    .any(|hash| hash == planned.requirement.sha256())
            {
                return Err("Mutable bootstrap contains a forged non-default artifact".into());
            }
            if let Some(evidence) = &planned.partial_allocation {
                evidence.validate_sealed_identity(
                    self.binding.cas_root.binding_nonce,
                    self.binding.install_id,
                    planned.requirement.sha256(),
                    planned.requirement.size(),
                )?;
            }
            let charge = if planned.availability == ArtifactAvailabilityStateV2::Complete {
                0
            } else {
                planned.requirement.size
            };
            network = network
                .checked_add(charge)
                .ok_or_else(|| "Mutable bootstrap network byte total overflow".to_string())?;
            reserve = reserve
                .checked_add(charge)
                .ok_or_else(|| "Mutable bootstrap disk reserve overflow".to_string())?;
        }
        if network != self.network_bytes || reserve != self.disk_download_reserve_bytes {
            return Err("Mutable bootstrap byte total changed".into());
        }
        Ok(())
    }
}

fn missing_requirements(
    inventory: &ArtifactInventoryV2,
    availability: &VerifiedAvailabilityV2,
    hashes: BTreeSet<String>,
) -> Result<(Vec<PlannedArtifactV2>, u64, u64), String> {
    let mut requirements = Vec::new();
    let mut network = 0_u64;
    let mut reserve = 0_u64;
    for sha256 in hashes {
        let expected = inventory.requirement(&sha256)?;
        let state = *availability.state(&sha256)?;
        let partial_allocation = availability.partial_allocation(&sha256)?.cloned();
        let resume_from = match state {
            ArtifactAvailabilityStateV2::Complete
            | ArtifactAvailabilityStateV2::Missing
            | ArtifactAvailabilityStateV2::Corrupt => 0,
            ArtifactAvailabilityStateV2::Partial { bytes } => bytes,
            ArtifactAvailabilityStateV2::CoveredByJavaGeneration
            | ArtifactAvailabilityStateV2::CoveredByGameGeneration => {
                return Err("A generation-covered artifact cannot enter a download plan".into());
            }
        };
        if resume_from > expected.size {
            return Err("Partial artifact availability is not resumable".into());
        }
        // A `.part` length is useful network-resume evidence, but not disk-allocation evidence:
        // NTFS sparse/compressed files can have a large logical length with almost no allocated
        // clusters. Budget the complete signed size until a final object is fully verified.
        let charge = if state == ArtifactAvailabilityStateV2::Complete {
            0
        } else {
            expected.size
        };
        network = network
            .checked_add(charge)
            .ok_or_else(|| "Artifact network byte total overflow".to_string())?;
        reserve = reserve
            .checked_add(charge)
            .ok_or_else(|| "Artifact disk reserve overflow".to_string())?;
        requirements.push(PlannedArtifactV2 {
            requirement: expected.clone(),
            availability: state,
            resume_from,
            partial_allocation,
        });
    }
    Ok((requirements, network, reserve))
}

fn valid_planned_availability(planned: &PlannedArtifactV2) -> bool {
    match planned.availability {
        ArtifactAvailabilityStateV2::Partial { bytes } => {
            bytes == planned.resume_from
                && bytes <= planned.requirement.size
                && planned
                    .partial_allocation
                    .as_ref()
                    .is_none_or(|evidence| evidence.logical_size() == bytes)
        }
        ArtifactAvailabilityStateV2::Complete
        | ArtifactAvailabilityStateV2::Missing
        | ArtifactAvailabilityStateV2::Corrupt => {
            planned.resume_from == 0 && planned.partial_allocation.is_none()
        }
        ArtifactAvailabilityStateV2::CoveredByJavaGeneration
        | ArtifactAvailabilityStateV2::CoveredByGameGeneration => false,
    }
}

fn round_up_allocation(size: u64, allocation_unit: u64) -> Result<u64, String> {
    if size == 0 || allocation_unit == 1 {
        return Ok(size);
    }
    let remainder = size % allocation_unit;
    if remainder == 0 {
        Ok(size)
    } else {
        size.checked_add(allocation_unit - remainder)
            .ok_or_else(|| "Artifact allocation rounding overflow".into())
    }
}

fn artifact_namespace_reserve(
    requirements: &[PlannedArtifactV2],
    allocation_unit: u64,
) -> Result<u64, String> {
    if allocation_unit == 1 {
        return Ok(0);
    }
    let incomplete = requirements
        .iter()
        .filter(|planned| planned.availability != ArtifactAvailabilityStateV2::Complete)
        .collect::<Vec<_>>();
    if incomplete.is_empty() {
        return Ok(0);
    }
    let count = u64::try_from(incomplete.len())
        .map_err(|_| "Artifact namespace count overflow".to_string())?;
    let corrupt = u64::try_from(
        incomplete
            .iter()
            .filter(|planned| planned.availability == ArtifactAvailabilityStateV2::Corrupt)
            .count(),
    )
    .map_err(|_| "Artifact corrupt namespace count overflow".to_string())?;
    let shards = incomplete
        .iter()
        .map(|planned| &planned.requirement.sha256[..2])
        .collect::<BTreeSet<_>>();
    let shard_count = u64::try_from(shards.len())
        .map_err(|_| "Artifact shard namespace count overflow".to_string())?;
    // Each incomplete object can require its object/partial entry and persistent lock entry.
    // At most eight no-replace destination names coexist because downloads are bounded to eight.
    // Three fixed entries cover objects, lock and temporary namespace roots; corrupt finals need
    // one additional quarantine destination each.
    let entries = count
        .checked_mul(2)
        .and_then(|value| value.checked_add(count.min(8)))
        .and_then(|value| value.checked_add(shard_count))
        .and_then(|value| value.checked_add(3))
        .and_then(|value| value.checked_add(corrupt))
        .ok_or_else(|| "Artifact namespace entry count overflow".to_string())?;
    entries
        .checked_mul(allocation_unit)
        .ok_or_else(|| "Artifact namespace reserve overflow".to_string())
}

fn insert_requirement(
    by_sha: &mut BTreeMap<String, ArtifactRequirementV2>,
    mut candidate: ArtifactRequirementV2,
) -> Result<(), String> {
    validate_sha256(&candidate.sha256)?;
    if candidate.provenances.len() != 1 {
        return Err("Artifact requirement has invalid provenance".into());
    }
    match by_sha.get_mut(&candidate.sha256) {
        None => {
            by_sha.insert(candidate.sha256.clone(), candidate);
        }
        Some(existing) => {
            if existing.size != candidate.size
                || existing.authority != candidate.authority
                || existing.source != candidate.source
                || !compatible_provenance(existing, &candidate)
            {
                return Err(format!(
                    "SHA-256 {} is reused with conflicting size, source or provenance",
                    candidate.sha256
                ));
            }
            let provenance = candidate.provenances.pop().expect("one provenance");
            if existing.provenances.binary_search(&provenance).is_err() {
                existing.provenances.push(provenance);
                existing.provenances.sort();
            }
        }
    }
    Ok(())
}

fn compatible_provenance(
    existing: &ArtifactRequirementV2,
    candidate: &ArtifactRequirementV2,
) -> bool {
    let existing_kind = existing.provenances.first().map(|value| value.kind);
    let candidate_kind = candidate.provenances.first().map(|value| value.kind);
    existing_kind == candidate_kind
        && matches!(
            existing_kind,
            Some(ArtifactProvenanceKindV2::ManifestExact)
                | Some(ArtifactProvenanceKindV2::MutableDefault)
                | Some(ArtifactProvenanceKindV2::GameRuntimeOfficial)
        )
}

fn validate_release_binding(trusted: &TrustedRelease, channel: BuildChannel) -> Result<(), String> {
    if trusted.channel() != channel
        || trusted.current().channel != channel
        || trusted.current().release_id != trusted.manifest().release.id
        || trusted.tuf_root_version() != trusted.evidence().roles.root
    {
        return Err("Trusted release channel/current/root binding is invalid".into());
    }
    trusted.manifest().validate()?;
    trusted.runtime_lock().validate()?;
    trusted.game_runtime_lock().validate()?;
    trusted
        .manifest()
        .bind_runtime_lock(trusted.runtime_lock())?;
    trusted
        .manifest()
        .bind_game_runtime_lock(trusted.runtime_lock(), trusted.game_runtime_lock())?;
    trusted.evidence().validate_binding(
        channel,
        &trusted.manifest().release.id,
        &trusted.current().manifest_target,
        &trusted.manifest().runtime.java.runtime_target,
        &trusted.manifest().runtime.game.runtime_target,
        &trusted.evidence().release_manifest.sha256,
        &trusted.manifest().runtime.java.runtime_lock_sha256,
        &trusted.manifest().runtime.game.runtime_lock_sha256,
    )
}

fn inventory_fingerprint(
    binding: &ArtifactBindingV2,
    artifacts: &[ArtifactRequirementV2],
) -> Result<String, String> {
    #[derive(Serialize)]
    struct Envelope<'a> {
        domain: &'static str,
        binding: &'a ArtifactBindingV2,
        artifacts: &'a [ArtifactRequirementV2],
    }
    let bytes = serde_json::to_vec(&Envelope {
        domain: "ru.fragmc.launcher.artifact-inventory.v2",
        binding,
        artifacts,
    })
    .map_err(|error| format!("Cannot bind artifact inventory: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn game_generation_binding_digest(
    binding: &ArtifactBindingV2,
    inventory: &ArtifactInventoryV2,
) -> Result<String, String> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Envelope<'a> {
        domain: &'static str,
        binding: &'a ArtifactBindingV2,
        inventory_fingerprint: &'a str,
        runtime_lock_sha256: &'a str,
        game_runtime_lock_sha256: &'a str,
        official_sha256: &'a [String],
    }
    let bytes = serde_json::to_vec(&Envelope {
        domain: "ru.fragmc.launcher.planned-game-generation.v2",
        binding,
        inventory_fingerprint: &inventory.fingerprint,
        runtime_lock_sha256: inventory.java_runtime_lock_sha256(),
        game_runtime_lock_sha256: inventory.game_runtime_lock_sha256(),
        official_sha256: &inventory.official_sha256,
    })
    .map_err(|error| format!("Cannot bind planned game generation: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_exact_official_inventory(inventory: &ArtifactInventoryV2) -> Result<(), String> {
    let mut expected = BTreeMap::<String, ArtifactRequirementV2>::new();
    for file in &inventory.game_runtime_lock.files {
        let GameRuntimeSource::Official {
            url,
            size,
            sha1,
            sha256,
        } = &file.source
        else {
            continue;
        };
        insert_requirement(
            &mut expected,
            ArtifactRequirementV2 {
                sha256: sha256.clone(),
                size: *size,
                authority: ArtifactAuthorityV2::OfficialHttps,
                source: ArtifactSourceV2::OfficialHttps {
                    url: url.clone(),
                    sha1: sha1.clone(),
                },
                provenances: vec![ArtifactProvenanceV2 {
                    kind: ArtifactProvenanceKindV2::GameRuntimeOfficial,
                    path: file.path.clone(),
                    role: Some(role_name(file.role)?),
                }],
            },
        )?;
    }
    let expected_hashes = expected.keys().cloned().collect::<Vec<_>>();
    if expected_hashes != inventory.official_sha256 {
        return Err("Artifact inventory official game set is missing, extra or duplicated".into());
    }
    let inventory_official = inventory
        .artifacts
        .iter()
        .filter(|requirement| requirement.authority == ArtifactAuthorityV2::OfficialHttps)
        .collect::<Vec<_>>();
    if inventory_official.len() != expected.len() {
        return Err("Artifact inventory contains an extra official requirement".into());
    }
    for (sha256, requirement) in expected {
        if inventory.requirement(&sha256)? != &requirement {
            return Err("Artifact inventory official requirement metadata changed".into());
        }
    }
    Ok(())
}

fn collect_exact_official_objects<T, D, V>(
    inventory: &ArtifactInventoryV2,
    objects: Vec<T>,
    mut describe: D,
    mut validate: V,
) -> Result<BTreeMap<String, T>, String>
where
    D: FnMut(&T) -> (&str, u64),
    V: FnMut(&T) -> Result<(), String>,
{
    validate_exact_official_inventory(inventory)?;
    if objects.len() != inventory.official_sha256.len() {
        return Err("Official CAS capability set is missing or contains extras".into());
    }
    let mut exact = BTreeMap::new();
    for object in objects {
        let (sha256, size) = describe(&object);
        let sha256 = sha256.to_owned();
        let expected = inventory
            .official_sha256
            .binary_search(&sha256)
            .ok()
            .and_then(|_| inventory.requirement(&sha256).ok())
            .ok_or_else(|| "Official CAS capability set contains an unsigned extra".to_string())?;
        if size != expected.size {
            return Err("Official CAS capability size differs from signed metadata".into());
        }
        validate(&object)?;
        if exact.insert(sha256, object).is_some() {
            return Err("Official CAS capability set contains a duplicate".into());
        }
    }
    if exact.len() != inventory.official_sha256.len()
        || exact
            .keys()
            .zip(&inventory.official_sha256)
            .any(|(actual, expected)| actual != expected)
    {
        return Err("Official CAS capability set is not exact".into());
    }
    Ok(exact)
}

fn register_path(
    paths: &mut BTreeMap<String, String>,
    path: &str,
    label: &str,
) -> Result<(), String> {
    let key = path_key(path);
    if paths
        .insert(key, path.to_owned())
        .is_some_and(|existing| existing != path)
    {
        return Err(format!("{label} paths collide by case or normalization"));
    }
    Ok(())
}

fn path_key(path: &str) -> String {
    path.nfkc().flat_map(char::to_lowercase).collect()
}

fn role_name(role: GameRuntimeRole) -> Result<String, String> {
    serde_json::to_value(role)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| "Cannot encode game runtime artifact role".into())
}

fn validate_sha256(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Artifact requirement has an invalid SHA-256".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_manager::{
        availability::VerifiedAvailabilityV2,
        planner::tests::trusted,
        storage::{select_install_directory, OwnedCasRoot},
    };
    use std::{fs, path::PathBuf};

    struct TestRoot {
        path: PathBuf,
        root: Option<OwnedCasRoot>,
        install_id: Uuid,
    }

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("fragment-artifact-plan-{label}-{}", Uuid::new_v4()));
            let selected = select_install_directory(&path).unwrap();
            let install_id = selected.install_id();
            Self {
                path,
                root: Some(selected.into_owned_cas_root()),
                install_id,
            }
        }

        fn root(&self) -> &OwnedCasRoot {
            self.root.as_ref().unwrap()
        }

        fn from_owner_marker(label: &str, source: &TestRoot) -> Self {
            let path = std::env::temp_dir()
                .join(format!("fragment-artifact-plan-{label}-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            fs::copy(
                source.path.join(".fragment-launcher-root.json"),
                path.join(".fragment-launcher-root.json"),
            )
            .unwrap();
            let selected = select_install_directory(&path).unwrap();
            assert_eq!(selected.install_id(), source.install_id);
            Self {
                path,
                install_id: selected.install_id(),
                root: Some(selected.into_owned_cas_root()),
            }
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            drop(self.root.take());
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn inventory(
        root: &TestRoot,
        trusted: &TrustedRelease,
        operation_id: Uuid,
    ) -> ArtifactInventoryV2 {
        ArtifactInventoryV2::build(
            root.root(),
            trusted,
            root.install_id,
            operation_id,
            BuildChannel::Stable,
            PresetId::Medium,
        )
        .unwrap()
    }

    #[test]
    fn inventory_is_exactly_release_bound_and_keeps_authoritative_sources() {
        let root = TestRoot::new("enumerates");
        let release = trusted('a', 1);
        let operation_id = Uuid::new_v4();
        let inventory = inventory(&root, &release, operation_id);

        let expected = release
            .manifest()
            .selected_preset(PresetId::Medium)
            .unwrap()
            .files
            .iter()
            .map(|file| file.sha256.clone())
            .chain(std::iter::once(
                release.runtime_lock().java.archive.sha256.clone(),
            ))
            .chain(release.game_runtime_lock().files.iter().filter_map(|file| {
                if let GameRuntimeSource::Official { sha256, .. } = &file.source {
                    Some(sha256.clone())
                } else {
                    None
                }
            }))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            inventory
                .artifacts()
                .iter()
                .map(|artifact| artifact.sha256().to_owned())
                .collect::<BTreeSet<_>>(),
            expected
        );
        assert_eq!(
            inventory
                .artifacts()
                .iter()
                .filter(|artifact| artifact.authority() == ArtifactAuthorityV2::OfficialHttps)
                .count(),
            4_022
        );
        assert!(inventory
            .artifacts()
            .iter()
            .filter(|artifact| artifact.authority() == ArtifactAuthorityV2::OfficialHttps)
            .all(|artifact| artifact.official_source().is_some()));
        assert!(inventory
            .artifacts()
            .windows(2)
            .all(|pair| pair[0].sha256() < pair[1].sha256()));
    }

    #[test]
    fn wrong_operation_release_and_injected_hash_are_rejected() {
        let root = TestRoot::new("binding");
        let release = trusted('a', 1);
        let operation_id = Uuid::new_v4();
        let mut inventory = inventory(&root, &release, operation_id);
        assert!(inventory
            .validate_request(
                &release,
                root.install_id,
                Uuid::new_v4(),
                BuildChannel::Stable,
                PresetId::Medium,
            )
            .is_err());
        assert!(inventory
            .validate_request(
                &trusted('b', 2),
                root.install_id,
                operation_id,
                BuildChannel::Stable,
                PresetId::Medium,
            )
            .is_err());

        inventory.artifacts.push(ArtifactRequirementV2 {
            sha256: "0".repeat(64),
            size: 1,
            authority: ArtifactAuthorityV2::SparkCas,
            source: ArtifactSourceV2::SparkCas,
            provenances: vec![ArtifactProvenanceV2 {
                kind: ArtifactProvenanceKindV2::ManifestExact,
                path: "mods/injected.jar".into(),
                role: None,
            }],
        });
        inventory
            .artifacts
            .sort_by(|left, right| left.sha256.cmp(&right.sha256));
        assert!(inventory
            .validate_request(
                &release,
                root.install_id,
                operation_id,
                BuildChannel::Stable,
                PresetId::Medium,
            )
            .is_err());
    }

    #[test]
    fn conflicting_duplicate_and_case_ambiguous_paths_fail_closed() {
        let root = TestRoot::new("duplicates");
        let operation_id = Uuid::new_v4();
        let conflict_base = trusted('a', 1);
        let mut conflict_manifest = conflict_base.manifest().clone();
        let files = &mut conflict_manifest
            .presets
            .iter_mut()
            .find(|preset| preset.id == PresetId::Medium)
            .unwrap()
            .files;
        files[1].sha256 = files[0].sha256.clone();
        files[1].size = files[0].size.saturating_add(1);
        let conflict = TrustedRelease::new_for_test(
            conflict_base.channel(),
            conflict_base.current().clone(),
            conflict_manifest,
            conflict_base.runtime_lock().clone(),
            conflict_base.game_runtime_lock().clone(),
            conflict_base.tuf_root_version(),
            conflict_base.evidence().clone(),
        );
        assert!(ArtifactInventoryV2::build(
            root.root(),
            &conflict,
            root.install_id,
            operation_id,
            BuildChannel::Stable,
            PresetId::Medium,
        )
        .is_err());

        let alias_base = trusted('a', 1);
        let mut alias_manifest = alias_base.manifest().clone();
        let files = &mut alias_manifest
            .presets
            .iter_mut()
            .find(|preset| preset.id == PresetId::Medium)
            .unwrap()
            .files;
        let mut duplicate = files[0].clone();
        duplicate.path = duplicate.path.to_uppercase();
        files.push(duplicate);
        let alias = TrustedRelease::new_for_test(
            alias_base.channel(),
            alias_base.current().clone(),
            alias_manifest,
            alias_base.runtime_lock().clone(),
            alias_base.game_runtime_lock().clone(),
            alias_base.tuf_root_version(),
            alias_base.evidence().clone(),
        );
        assert!(ArtifactInventoryV2::build(
            root.root(),
            &alias,
            root.install_id,
            Uuid::new_v4(),
            BuildChannel::Stable,
            PresetId::Medium,
        )
        .is_err());
    }

    #[test]
    fn duplicate_metadata_rules_merge_only_compatible_provenance() {
        let hash = "1".repeat(64);
        let spark = |kind, path: &str| ArtifactRequirementV2 {
            sha256: hash.clone(),
            size: 7,
            authority: ArtifactAuthorityV2::SparkCas,
            source: ArtifactSourceV2::SparkCas,
            provenances: vec![ArtifactProvenanceV2 {
                kind,
                path: path.into(),
                role: None,
            }],
        };
        let mut immutable = BTreeMap::new();
        insert_requirement(
            &mut immutable,
            spark(ArtifactProvenanceKindV2::ManifestExact, "mods/a.jar"),
        )
        .unwrap();
        insert_requirement(
            &mut immutable,
            spark(ArtifactProvenanceKindV2::ManifestExact, "mods/b.jar"),
        )
        .unwrap();
        assert_eq!(immutable.len(), 1);
        assert_eq!(immutable[&hash].provenances.len(), 2);

        let mut mutable = BTreeMap::new();
        insert_requirement(
            &mut mutable,
            spark(ArtifactProvenanceKindV2::MutableDefault, "options.txt"),
        )
        .unwrap();
        insert_requirement(
            &mut mutable,
            spark(
                ArtifactProvenanceKindV2::MutableDefault,
                "config/client.toml",
            ),
        )
        .unwrap();
        assert_eq!(mutable.len(), 1);
        assert_eq!(mutable[&hash].provenances.len(), 2);
        assert!(insert_requirement(
            &mut mutable,
            spark(ArtifactProvenanceKindV2::ManifestExact, "mods/conflict.jar"),
        )
        .is_err());
        assert!(insert_requirement(
            &mut mutable,
            ArtifactRequirementV2 {
                sha256: hash,
                size: 7,
                authority: ArtifactAuthorityV2::OfficialHttps,
                source: ArtifactSourceV2::OfficialHttps {
                    url: "https://example.invalid/object".into(),
                    sha1: "2".repeat(40),
                },
                provenances: vec![ArtifactProvenanceV2 {
                    kind: ArtifactProvenanceKindV2::GameRuntimeOfficial,
                    path: "libraries/conflict.jar".into(),
                    role: Some("library".into()),
                }],
            },
        )
        .is_err());
    }

    #[test]
    fn cached_runtime_inputs_remain_in_the_sealed_execution_set() {
        let root = TestRoot::new("cached-runtime-inputs");
        let release = trusted('a', 1);
        let inventory = inventory(&root, &release, Uuid::new_v4());
        let complete = inventory
            .artifacts()
            .iter()
            .map(|artifact| {
                (
                    artifact.sha256().to_owned(),
                    ArtifactAvailabilityStateV2::Complete,
                )
            })
            .collect::<Vec<_>>();
        let availability = VerifiedAvailabilityV2::for_test(&inventory, complete, false, false);
        let plan = ArtifactPlanV2::for_reconcile(&inventory, &availability, []).unwrap();
        plan.validate_for(&inventory).unwrap();
        let view = plan.execution_view(root.root(), &inventory).unwrap();
        let items = view.items().collect::<Vec<_>>();
        assert_eq!(items.len(), 4_023);
        assert!(items
            .iter()
            .all(|item| item.availability() == ArtifactAvailabilityStateV2::Complete));
        assert_eq!(
            items
                .iter()
                .filter(|item| item.source() == ArtifactExecutionSourceV2::SparkCas)
                .count(),
            1
        );
        assert_eq!(plan.network_bytes(), 0);
        assert_eq!(plan.disk_download_reserve_bytes(), 0);
        let first = &items[0];
        assert_eq!(first.channel(), BuildChannel::Stable);
        assert_eq!(first.preset(), PresetId::Medium);
        assert_eq!(first.release_id(), release.manifest().release.id);

        let rebound = TestRoot::from_owner_marker("cached-runtime-rebound", &root);
        assert!(plan.execution_view(rebound.root(), &inventory).is_err());
        assert!(first.validate_root(rebound.root()).is_err());
    }

    #[test]
    fn missing_download_reserve_rounds_each_physical_object_independently() {
        let root = TestRoot::new("physical-download-reserve");
        let release = trusted('a', 1);
        let inventory = inventory(&root, &release, Uuid::new_v4());
        let availability = VerifiedAvailabilityV2::for_test(&inventory, [], false, false);
        let plan = ArtifactPlanV2::for_reconcile(&inventory, &availability, []).unwrap();
        let items = plan
            .execution_view(root.root(), &inventory)
            .unwrap()
            .items()
            .map(|item| (item.sha256().to_owned(), item.size(), item.availability()))
            .collect::<Vec<_>>();
        let expected_content_4k = items
            .iter()
            .filter(|(_, _, state)| *state != ArtifactAvailabilityStateV2::Complete)
            .try_fold(0_u64, |total, (_, size, _)| {
                total.checked_add(round_up_allocation(*size, 4096).unwrap())
            })
            .unwrap();
        let incomplete = items
            .iter()
            .filter(|(_, _, state)| *state != ArtifactAvailabilityStateV2::Complete)
            .collect::<Vec<_>>();
        let incomplete_count = incomplete.len() as u64;
        let shard_count = incomplete
            .iter()
            .map(|(sha256, _, _)| &sha256[..2])
            .collect::<BTreeSet<_>>()
            .len() as u64;
        let expected_4k = expected_content_4k
            + (2 * incomplete_count + incomplete_count.min(8) + shard_count + 3) * 4096;
        assert_eq!(
            plan.disk_download_reserve_bytes_for_allocation_unit(4096)
                .unwrap(),
            expected_4k
        );
        assert_eq!(
            plan.disk_download_reserve_bytes_for_allocation_unit(1)
                .unwrap(),
            plan.disk_download_reserve_bytes()
        );
        assert!(expected_4k >= plan.disk_download_reserve_bytes());
        assert!(plan
            .disk_download_reserve_bytes_for_allocation_unit(0)
            .is_err());
    }

    #[test]
    fn java_install_authority_is_plan_root_and_operation_bound() {
        let root = TestRoot::new("java-authority");
        let release = trusted('a', 1);
        let sealed_inventory = inventory(&root, &release, Uuid::new_v4());
        let availability = VerifiedAvailabilityV2::for_test(&sealed_inventory, [], false, false);
        let plan = ArtifactPlanV2::for_reconcile(&sealed_inventory, &availability, []).unwrap();
        let java = plan.java_archive(root.root(), &sealed_inventory).unwrap();
        assert_eq!(java.sha256(), release.runtime_lock().java.archive.sha256);
        assert_eq!(java.size(), release.runtime_lock().java.archive.size);
        assert_eq!(
            java.runtime_lock_sha256(),
            sealed_inventory.java_runtime_lock_sha256()
        );
        java.validate_root(root.root()).unwrap();

        let rebound = TestRoot::from_owner_marker("java-rebound", &root);
        assert!(java.validate_root(rebound.root()).is_err());
        assert!(plan
            .java_archive(rebound.root(), &sealed_inventory)
            .is_err());

        let other_operation = inventory(&root, &release, Uuid::new_v4());
        assert!(plan.java_archive(root.root(), &other_operation).is_err());

        let runtime_ready = VerifiedAvailabilityV2::for_test(&sealed_inventory, [], true, false);
        let without_java =
            ArtifactPlanV2::for_reconcile(&sealed_inventory, &runtime_ready, []).unwrap();
        assert!(without_java
            .java_archive(root.root(), &sealed_inventory)
            .is_err());
    }

    #[test]
    fn game_generation_plan_accepts_post_download_capabilities_and_rejects_ready_rebound_plans() {
        let root = TestRoot::new("game-authority");
        let release = trusted('a', 1);
        let sealed_inventory = inventory(&root, &release, Uuid::new_v4());

        // An initial install is planned from Missing availability. Completion is proved later by
        // the exact live VerifiedCasObject set, not by the pre-download snapshot.
        let missing = VerifiedAvailabilityV2::for_test(&sealed_inventory, [], false, false);
        let download_plan = ArtifactPlanV2::for_reconcile(&sealed_inventory, &missing, []).unwrap();
        download_plan
            .validate_game_generation_plan(root.root(), &sealed_inventory)
            .unwrap();

        #[derive(Debug)]
        struct FakeCapability {
            sha256: String,
            size: u64,
            live: bool,
        }
        let downloaded = sealed_inventory
            .official_sha256
            .iter()
            .map(|sha256| FakeCapability {
                sha256: sha256.clone(),
                size: sealed_inventory.requirement(sha256).unwrap().size,
                live: true,
            })
            .collect::<Vec<_>>();
        let exact = collect_exact_official_objects(
            &sealed_inventory,
            downloaded,
            |object| (object.sha256.as_str(), object.size),
            |object| object.live.then_some(()).ok_or_else(|| "wrong root".into()),
        )
        .unwrap();
        assert_eq!(exact.len(), 4_022);

        let already_ready = VerifiedAvailabilityV2::for_test(&sealed_inventory, [], false, true);
        let no_generation_authority =
            ArtifactPlanV2::for_reconcile(&sealed_inventory, &already_ready, []).unwrap();
        assert!(no_generation_authority
            .execution_view(root.root(), &sealed_inventory)
            .unwrap()
            .items()
            .all(|item| !sealed_inventory.is_official_game_sha256(item.sha256())));
        assert!(no_generation_authority
            .validate_game_generation_plan(root.root(), &sealed_inventory)
            .is_err());

        let rebound = TestRoot::from_owner_marker("game-authority-rebound", &root);
        assert!(download_plan
            .validate_game_generation_plan(rebound.root(), &sealed_inventory)
            .is_err());

        let other_operation = inventory(&root, &release, Uuid::new_v4());
        assert!(download_plan
            .validate_game_generation_plan(root.root(), &other_operation)
            .is_err());
        let other_release = inventory(&root, &trusted('b', 2), Uuid::new_v4());
        assert!(download_plan
            .validate_game_generation_plan(root.root(), &other_release)
            .is_err());
    }

    #[test]
    fn exact_official_capability_set_rejects_missing_extra_duplicate_size_and_root() {
        #[derive(Debug)]
        struct FakeCapability {
            sha256: String,
            size: u64,
            live: bool,
        }

        let root = TestRoot::new("game-capability-set");
        let inventory = inventory(&root, &trusted('a', 1), Uuid::new_v4());
        let make_exact = || {
            inventory
                .official_sha256
                .iter()
                .map(|sha256| FakeCapability {
                    sha256: sha256.clone(),
                    size: inventory.requirement(sha256).unwrap().size,
                    live: true,
                })
                .collect::<Vec<_>>()
        };
        let validate = |objects| {
            collect_exact_official_objects(
                &inventory,
                objects,
                |object: &FakeCapability| (object.sha256.as_str(), object.size),
                |object| object.live.then_some(()).ok_or_else(|| "wrong root".into()),
            )
        };

        let mut missing = make_exact();
        missing.pop();
        assert!(validate(missing).is_err());

        let mut extra = make_exact();
        extra[0].sha256 = "0".repeat(64);
        assert!(validate(extra).is_err());

        let mut duplicate = make_exact();
        duplicate[1].sha256 = duplicate[0].sha256.clone();
        duplicate[1].size = duplicate[0].size;
        assert!(validate(duplicate).is_err());

        let mut wrong_size = make_exact();
        wrong_size[0].size = wrong_size[0].size.saturating_add(1);
        assert!(validate(wrong_size).is_err());

        let mut wrong_root = make_exact();
        wrong_root[0].live = false;
        assert!(validate(wrong_root).is_err());
    }

    #[test]
    fn game_generation_binding_digest_covers_operation_release_root_and_lock_set() {
        let root = TestRoot::new("game-binding-digest");
        let release = trusted('a', 1);
        let first = inventory(&root, &release, Uuid::new_v4());
        let second_operation = inventory(&root, &release, Uuid::new_v4());
        let second_release = inventory(&root, &trusted('b', 2), Uuid::new_v4());
        let first_digest = game_generation_binding_digest(&first.binding, &first).unwrap();
        assert_ne!(
            first_digest,
            game_generation_binding_digest(&second_operation.binding, &second_operation).unwrap()
        );
        assert_ne!(
            first_digest,
            game_generation_binding_digest(&second_release.binding, &second_release).unwrap()
        );

        let rebound = TestRoot::from_owner_marker("game-binding-digest-rebound", &root);
        let rebound_inventory = inventory(&rebound, &release, Uuid::new_v4());
        assert_ne!(
            first_digest,
            game_generation_binding_digest(&rebound_inventory.binding, &rebound_inventory).unwrap()
        );
    }

    #[test]
    fn mutable_bootstrap_contains_only_missing_signed_defaults() {
        let root = TestRoot::new("mutable");
        let release = trusted('a', 1);
        let inventory = inventory(&root, &release, Uuid::new_v4());
        let availability = VerifiedAvailabilityV2::for_test(&inventory, [], false, false);
        let plan = MutableBootstrapPlanV2::build(&inventory, &availability).unwrap();
        plan.validate_for(&inventory).unwrap();
        let view = plan.execution_view(root.root(), &inventory).unwrap();
        let requirements = view.items().collect::<Vec<_>>();
        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0].sha256(), "e".repeat(64));
        assert_eq!(plan.network_bytes(), requirements[0].size());
        assert_eq!(plan.disk_download_reserve_bytes(), requirements[0].size());

        let complete = VerifiedAvailabilityV2::for_test(
            &inventory,
            [("e".repeat(64), ArtifactAvailabilityStateV2::Complete)],
            false,
            false,
        );
        let cached = MutableBootstrapPlanV2::build(&inventory, &complete).unwrap();
        assert_eq!(
            cached
                .execution_view(root.root(), &inventory)
                .unwrap()
                .items()
                .len(),
            1
        );
        assert_eq!(cached.network_bytes(), 0);
        assert_eq!(cached.disk_download_reserve_bytes(), 0);
    }

    #[test]
    fn generation_covered_states_can_never_become_download_authority() {
        let root = TestRoot::new("covered-plan-state");
        let inventory = inventory(&root, &trusted('a', 1), Uuid::new_v4());
        let java_hash = inventory.java_archive_sha256().to_owned();
        let official_hash = inventory.official_game_sha256()[0].clone();

        for (sha256, state) in [
            (
                java_hash.clone(),
                ArtifactAvailabilityStateV2::CoveredByJavaGeneration,
            ),
            (
                official_hash.clone(),
                ArtifactAvailabilityStateV2::CoveredByGameGeneration,
            ),
        ] {
            let availability = VerifiedAvailabilityV2::for_test(
                &inventory,
                [(sha256.clone(), state)],
                false,
                false,
            );
            assert!(missing_requirements(
                &inventory,
                &availability,
                BTreeSet::from([sha256.clone()])
            )
            .is_err());

            let planned = PlannedArtifactV2 {
                requirement: inventory.requirement(&sha256).unwrap().clone(),
                availability: state,
                resume_from: 0,
                partial_allocation: None,
            };
            assert!(!valid_planned_availability(&planned));
        }
    }
}
