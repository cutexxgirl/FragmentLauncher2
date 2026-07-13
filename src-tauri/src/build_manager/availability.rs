use super::{
    artifact_plan::ArtifactInventoryV2,
    cas::{audit_object_availability, CasObjectAvailability, ExpectedObject},
    game_generation::{audit_installed_game_generation, GameRuntimeInstallation},
    managed_fs::{GuardedDirectoryChain, ManagedFsError, RelativeManagedPath},
    runtime::{audit_installed_runtime_generation, RuntimeInstallation},
    storage::OwnedCasRoot,
};
#[cfg(test)]
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ArtifactAvailabilityStateV2 {
    Missing,
    Partial { bytes: u64 },
    Complete,
    Corrupt,
    CoveredByJavaGeneration,
    CoveredByGameGeneration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedArtifactAvailabilityV2 {
    sha256: String,
    state: ArtifactAvailabilityStateV2,
}

/// A sealed snapshot emitted only by the native CAS/runtime scanner. There is intentionally no
/// public constructor and no mutable access to states, so the planner cannot be handed a caller-
/// asserted "complete" object or runtime generation.
#[derive(Debug)]
pub(super) struct VerifiedAvailabilityV2 {
    install_id: Uuid,
    inventory_fingerprint: String,
    root_binding_nonce: Uuid,
    artifacts: Vec<VerifiedArtifactAvailabilityV2>,
    java_installation: Option<RuntimeInstallation>,
    game_installation: Option<GameRuntimeInstallation>,
    #[cfg(test)]
    synthetic_game_generation_complete: bool,
}

impl VerifiedAvailabilityV2 {
    pub(super) fn scan(
        root: &OwnedCasRoot,
        inventory: &ArtifactInventoryV2,
    ) -> Result<Self, String> {
        inventory.validate_root(root)?;
        let (binding_nonce, install_id, _, _) = root.binding();
        if install_id != inventory.install_id() {
            return Err("Owned CAS root belongs to another artifact inventory".into());
        }
        let java_installation = audit_installed_runtime_generation(
            root,
            inventory.java_runtime_lock_sha256(),
            inventory.runtime_lock(),
        )?;
        root.revalidate()?;
        let game_installation = audit_repairable_game_generation(root, inventory)?;
        root.revalidate()?;
        let artifacts = scan_artifact_states(
            root,
            inventory,
            java_installation.is_some(),
            game_installation.is_some(),
        )?;
        inventory.validate_root(root)?;
        Ok(Self {
            install_id,
            inventory_fingerprint: inventory.fingerprint().to_owned(),
            root_binding_nonce: binding_nonce,
            artifacts,
            java_installation,
            game_installation,
            #[cfg(test)]
            synthetic_game_generation_complete: false,
        })
    }

    pub(super) fn validate_for(&self, inventory: &ArtifactInventoryV2) -> Result<(), String> {
        if self.install_id != inventory.install_id()
            || self.inventory_fingerprint != inventory.fingerprint()
            || self.root_binding_nonce != inventory.root_binding_nonce()
            || self.artifacts.len() != inventory.artifacts().len()
        {
            return Err("Verified availability belongs to another inventory/root".into());
        }
        for (actual, expected) in self.artifacts.iter().zip(inventory.artifacts()) {
            if actual.sha256 != expected.sha256() {
                return Err("Verified availability artifact order or identity changed".into());
            }
            if let ArtifactAvailabilityStateV2::Partial { bytes } = actual.state {
                if bytes > expected.size() {
                    return Err("Verified partial artifact exceeds its signed size".into());
                }
            }
            match actual.state {
                ArtifactAvailabilityStateV2::CoveredByJavaGeneration
                    if !self.java_generation_complete()
                        || !inventory.is_java_archive_sha256(expected.sha256()) =>
                {
                    return Err("Java-covered availability is not backed by its generation".into());
                }
                ArtifactAvailabilityStateV2::CoveredByGameGeneration
                    if !self.game_generation_complete()
                        || !inventory.is_official_game_sha256(expected.sha256()) =>
                {
                    return Err("Game-covered availability is not backed by its generation".into());
                }
                _ => {}
            }
        }
        if self.java_installation.as_ref().is_some_and(|runtime| {
            runtime.runtime_lock_sha256() != inventory.java_runtime_lock_sha256()
        }) {
            return Err("Verified Java generation belongs to another runtime lock".into());
        }
        if self.game_installation.as_ref().is_some_and(|runtime| {
            runtime.game_runtime_lock_sha256() != inventory.game_runtime_lock_sha256()
                || runtime.install_id() != inventory.install_id()
                || runtime.root_binding_nonce() != inventory.root_binding_nonce()
                || runtime.inventory_fingerprint() != inventory.fingerprint()
        }) {
            return Err("Verified game generation belongs to another inventory/root".into());
        }
        if self.java_generation_complete()
            && self.state(inventory.java_archive_sha256())?
                != &ArtifactAvailabilityStateV2::CoveredByJavaGeneration
        {
            return Err("Verified Java generation does not cover its archive".into());
        }
        if self.game_generation_complete()
            && inventory.official_game_sha256().iter().any(|sha256| {
                self.state(sha256).ok()
                    != Some(&ArtifactAvailabilityStateV2::CoveredByGameGeneration)
            })
        {
            return Err("Verified game generation does not cover its official artifacts".into());
        }
        Ok(())
    }

    pub(super) fn state(&self, sha256: &str) -> Result<&ArtifactAvailabilityStateV2, String> {
        self.artifacts
            .binary_search_by(|candidate| candidate.sha256.as_str().cmp(sha256))
            .ok()
            .map(|index| &self.artifacts[index].state)
            .ok_or_else(|| "Availability has no state for a sealed artifact".into())
    }

    pub(super) fn java_generation_complete(&self) -> bool {
        self.java_installation.is_some()
    }

    pub(super) fn game_generation_complete(&self) -> bool {
        let complete = self.game_installation.is_some();
        #[cfg(test)]
        {
            complete || self.synthetic_game_generation_complete
        }
        #[cfg(not(test))]
        {
            complete
        }
    }

    pub(super) fn java_installation(&self) -> Option<&RuntimeInstallation> {
        self.java_installation.as_ref()
    }

    pub(super) fn game_installation(&self) -> Option<&GameRuntimeInstallation> {
        self.game_installation.as_ref()
    }

    #[cfg(test)]
    pub(super) fn for_test(
        inventory: &ArtifactInventoryV2,
        states: impl IntoIterator<Item = (String, ArtifactAvailabilityStateV2)>,
        java_generation_complete: bool,
        game_generation_complete: bool,
    ) -> Self {
        let overrides = states.into_iter().collect::<BTreeMap<_, _>>();
        let artifacts = inventory
            .artifacts()
            .iter()
            .map(|expected| VerifiedArtifactAvailabilityV2 {
                sha256: expected.sha256().to_owned(),
                state: if java_generation_complete
                    && inventory.is_java_archive_sha256(expected.sha256())
                {
                    ArtifactAvailabilityStateV2::CoveredByJavaGeneration
                } else if game_generation_complete
                    && inventory.is_official_game_sha256(expected.sha256())
                {
                    ArtifactAvailabilityStateV2::CoveredByGameGeneration
                } else {
                    overrides
                        .get(expected.sha256())
                        .copied()
                        .unwrap_or(ArtifactAvailabilityStateV2::Missing)
                },
            })
            .collect();
        Self {
            install_id: inventory.install_id(),
            inventory_fingerprint: inventory.fingerprint().to_owned(),
            root_binding_nonce: inventory.root_binding_nonce(),
            artifacts,
            java_installation: java_generation_complete.then(|| {
                RuntimeInstallation::synthetic(
                    "java-generation".into(),
                    "java-generation/image".into(),
                    "java-generation/image/bin/javaw.exe".into(),
                    "java-generation/image/bin/java.exe".into(),
                    inventory.java_runtime_lock_sha256().to_owned(),
                )
            }),
            game_installation: None,
            synthetic_game_generation_complete: game_generation_complete,
        }
    }

    #[cfg(test)]
    fn scan_with_synthetic_generation_coverage(
        root: &OwnedCasRoot,
        inventory: &ArtifactInventoryV2,
        java_generation_complete: bool,
        game_generation_complete: bool,
    ) -> Result<Self, String> {
        inventory.validate_root(root)?;
        let (binding_nonce, install_id, _, _) = root.binding();
        let artifacts = scan_artifact_states(
            root,
            inventory,
            java_generation_complete,
            game_generation_complete,
        )?;
        Ok(Self {
            install_id,
            inventory_fingerprint: inventory.fingerprint().to_owned(),
            root_binding_nonce: binding_nonce,
            artifacts,
            java_installation: java_generation_complete.then(|| {
                RuntimeInstallation::synthetic(
                    "java-generation".into(),
                    "java-generation/image".into(),
                    "java-generation/image/bin/javaw.exe".into(),
                    "java-generation/image/bin/java.exe".into(),
                    inventory.java_runtime_lock_sha256().to_owned(),
                )
            }),
            game_installation: None,
            synthetic_game_generation_complete: game_generation_complete,
        })
    }
}

fn audit_repairable_game_generation(
    root: &OwnedCasRoot,
    inventory: &ArtifactInventoryV2,
) -> Result<Option<GameRuntimeInstallation>, String> {
    match audit_installed_game_generation(root, inventory) {
        Ok(installed) => Ok(installed),
        Err(audit_error) => {
            let relative = RelativeManagedPath::new(&format!(
                "runtime/minecraft/generations/{}",
                inventory.game_runtime_lock_sha256()
            ))
            .map_err(|error| format!("Cannot construct game generation path: {error}"))?;
            match GuardedDirectoryChain::open(root.install_root(), &relative) {
                Ok(existing) => {
                    existing
                        .revalidate()
                        .map_err(|error| format!("Unsafe game generation: {error}"))?;
                    // A real root-bound directory with bad/incomplete contents is repairable. It
                    // covers nothing; the ordinary CAS scan below becomes the source of truth.
                    Ok(None)
                }
                Err(ManagedFsError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    Ok(None)
                }
                Err(error) => Err(format!(
                    "Cannot inspect game runtime generation after {audit_error}: {error}"
                )),
            }
        }
    }
}

fn scan_artifact_states(
    root: &OwnedCasRoot,
    inventory: &ArtifactInventoryV2,
    java_generation_complete: bool,
    game_generation_complete: bool,
) -> Result<Vec<VerifiedArtifactAvailabilityV2>, String> {
    scan_artifact_states_with(
        inventory,
        java_generation_complete,
        game_generation_complete,
        |expected| {
            root.revalidate()?;
            audit_object_availability(
                root,
                &ExpectedObject {
                    sha256: expected.sha256().to_owned(),
                    size: expected.size(),
                },
            )
            .map_err(|error| format!("Cannot audit artifact {}: {error}", expected.sha256()))
        },
    )
}

fn scan_artifact_states_with(
    inventory: &ArtifactInventoryV2,
    java_generation_complete: bool,
    game_generation_complete: bool,
    mut audit: impl FnMut(
        &super::artifact_plan::ArtifactRequirementV2,
    ) -> Result<CasObjectAvailability, String>,
) -> Result<Vec<VerifiedArtifactAvailabilityV2>, String> {
    inventory
        .artifacts()
        .iter()
        .map(|expected| {
            let state = if java_generation_complete
                && inventory.is_java_archive_sha256(expected.sha256())
            {
                ArtifactAvailabilityStateV2::CoveredByJavaGeneration
            } else if game_generation_complete
                && inventory.is_official_game_sha256(expected.sha256())
            {
                ArtifactAvailabilityStateV2::CoveredByGameGeneration
            } else {
                match audit(expected)? {
                    CasObjectAvailability::Missing => ArtifactAvailabilityStateV2::Missing,
                    CasObjectAvailability::Partial { bytes } => {
                        ArtifactAvailabilityStateV2::Partial { bytes }
                    }
                    CasObjectAvailability::Complete => ArtifactAvailabilityStateV2::Complete,
                    CasObjectAvailability::Corrupt => ArtifactAvailabilityStateV2::Corrupt,
                }
            };
            Ok(VerifiedArtifactAvailabilityV2 {
                sha256: expected.sha256().to_owned(),
                state,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_manager::{
        artifact_plan::ArtifactInventoryV2,
        planner::tests::trusted,
        storage::{select_install_directory, OwnedCasRoot},
        types::{BuildChannel, PresetId},
    };
    use sha2::{Digest, Sha256};
    use std::{fs, path::PathBuf};

    struct TestRoot {
        path: PathBuf,
        root: Option<OwnedCasRoot>,
        install_id: Uuid,
    }

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("fragment-availability-{label}-{}", Uuid::new_v4()));
            let selected = select_install_directory(&path).unwrap();
            let install_id = selected.install_id();
            Self {
                path,
                root: Some(selected.into_owned_cas_root()),
                install_id,
            }
        }

        fn from_owner_marker(label: &str, source: &TestRoot) -> Self {
            let path = std::env::temp_dir()
                .join(format!("fragment-availability-{label}-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            fs::copy(
                source.path.join(".fragment-launcher-root.json"),
                path.join(".fragment-launcher-root.json"),
            )
            .unwrap();
            let selected = select_install_directory(&path).unwrap();
            let install_id = selected.install_id();
            assert_eq!(install_id, source.install_id);
            Self {
                path,
                root: Some(selected.into_owned_cas_root()),
                install_id,
            }
        }

        fn root(&self) -> &OwnedCasRoot {
            self.root.as_ref().unwrap()
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            drop(self.root.take());
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn fixture_release(exact: &[u8], mutable_size: u64) -> super::super::tuf::TrustedRelease {
        let base = trusted('a', 1);
        let mut manifest = base.manifest().clone();
        let exact_sha256 = format!("{:x}", Sha256::digest(exact));
        let mutable_sha256 = format!("{:x}", Sha256::digest(vec![b'm'; mutable_size as usize]));
        for preset in &mut manifest.presets {
            let exact_file = preset
                .files
                .iter_mut()
                .find(|file| file.path == "mods/fragment-launch-guard.jar")
                .unwrap();
            exact_file.size = exact.len() as u64;
            exact_file.sha256 = exact_sha256.clone();
            let mutable = preset
                .files
                .iter_mut()
                .find(|file| file.path == "options.txt")
                .unwrap();
            mutable.size = mutable_size;
            mutable.sha256 = mutable_sha256.clone();
        }
        manifest.validate().unwrap();
        super::super::tuf::TrustedRelease::new_for_test(
            base.channel(),
            base.current().clone(),
            manifest,
            base.runtime_lock().clone(),
            base.game_runtime_lock().clone(),
            base.tuf_root_version(),
            base.evidence().clone(),
        )
    }

    fn inventory(
        root: &TestRoot,
        release: &super::super::tuf::TrustedRelease,
    ) -> ArtifactInventoryV2 {
        ArtifactInventoryV2::build(
            root.root(),
            release,
            root.install_id,
            Uuid::new_v4(),
            BuildChannel::Stable,
            PresetId::Medium,
        )
        .unwrap()
    }

    fn object_paths(root: &OwnedCasRoot, sha256: &str) -> (PathBuf, PathBuf) {
        let shard = root.managed_root().join("sha256").join(&sha256[..2]);
        (shard.join(sha256), shard.join(format!(".{sha256}.part")))
    }

    fn write(path: &PathBuf, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn scanner_classifies_missing_partial_complete_and_corrupt_without_hashing_partial() {
        let root = TestRoot::new("states");
        let exact = b"signed exact bytes";
        let release = fixture_release(exact, 10);
        let inventory = inventory(&root, &release);
        let preset = release
            .manifest()
            .selected_preset(PresetId::Medium)
            .unwrap();
        let exact_hash = preset
            .files
            .iter()
            .find(|file| file.path.starts_with("mods/"))
            .unwrap()
            .sha256
            .clone();
        let mutable_hash = preset
            .files
            .iter()
            .find(|file| file.path == "options.txt")
            .unwrap()
            .sha256
            .clone();
        let (exact_final, _) = object_paths(root.root(), &exact_hash);
        write(&exact_final, exact);
        let (_, mutable_partial) = object_paths(root.root(), &mutable_hash);
        write(&mutable_partial, b"part");

        let scanned = VerifiedAvailabilityV2::scan(root.root(), &inventory).unwrap();
        assert_eq!(
            scanned.state(&exact_hash).unwrap(),
            &ArtifactAvailabilityStateV2::Complete
        );
        assert_eq!(
            scanned.state(&mutable_hash).unwrap(),
            &ArtifactAvailabilityStateV2::Partial { bytes: 4 }
        );
        assert!(scanned
            .artifacts
            .iter()
            .any(|entry| entry.state == ArtifactAvailabilityStateV2::Missing));

        fs::remove_file(&mutable_partial).unwrap();
        let (mutable_final, _) = object_paths(root.root(), &mutable_hash);
        write(&mutable_final, b"xxxxxxxxxx");
        let corrupt = VerifiedAvailabilityV2::scan(root.root(), &inventory).unwrap();
        assert_eq!(
            corrupt.state(&mutable_hash).unwrap(),
            &ArtifactAvailabilityStateV2::Corrupt
        );
    }

    #[test]
    fn exact_size_partial_is_still_planned_and_oversized_partial_is_corrupt() {
        let root = TestRoot::new("partial-limits");
        let release = fixture_release(b"exact", 4);
        let inventory = inventory(&root, &release);
        let hash = release
            .manifest()
            .selected_preset(PresetId::Medium)
            .unwrap()
            .files
            .iter()
            .find(|file| file.path == "options.txt")
            .unwrap()
            .sha256
            .clone();
        let (_, partial) = object_paths(root.root(), &hash);
        write(&partial, b"mmmm");
        let scanned = VerifiedAvailabilityV2::scan(root.root(), &inventory).unwrap();
        assert_eq!(
            scanned.state(&hash).unwrap(),
            &ArtifactAvailabilityStateV2::Partial { bytes: 4 }
        );
        let bootstrap =
            super::super::artifact_plan::MutableBootstrapPlanV2::build(&inventory, &scanned)
                .unwrap();
        assert_eq!(bootstrap.network_bytes(), 4);
        assert_eq!(bootstrap.disk_download_reserve_bytes(), 4);
        assert_eq!(
            bootstrap
                .execution_view(root.root(), &inventory)
                .unwrap()
                .items()
                .len(),
            1
        );

        fs::write(&partial, b"oversized").unwrap();
        let oversized = VerifiedAvailabilityV2::scan(root.root(), &inventory).unwrap();
        assert_eq!(
            oversized.state(&hash).unwrap(),
            &ArtifactAvailabilityStateV2::Corrupt
        );
    }

    #[test]
    fn unsafe_links_fail_closed_and_corrupt_java_generation_remains_repairable() {
        let root = TestRoot::new("unsafe");
        let release = fixture_release(b"hard-link target", 4);
        let inventory = inventory(&root, &release);
        let hash = release
            .manifest()
            .selected_preset(PresetId::Medium)
            .unwrap()
            .files
            .iter()
            .find(|file| file.path.starts_with("mods/"))
            .unwrap()
            .sha256
            .clone();
        let outside = root.path.join("outside.bin");
        fs::write(&outside, b"hard-link target").unwrap();
        let (final_path, _) = object_paths(root.root(), &hash);
        fs::create_dir_all(final_path.parent().unwrap()).unwrap();
        fs::hard_link(&outside, &final_path).unwrap();
        assert!(VerifiedAvailabilityV2::scan(root.root(), &inventory).is_err());

        fs::remove_file(&final_path).unwrap();
        fs::remove_file(&outside).unwrap();
        let generation = root
            .path
            .join("runtime/java/generations")
            .join(inventory.java_runtime_lock_sha256());
        fs::create_dir_all(&generation).unwrap();
        let corrupt_generation = VerifiedAvailabilityV2::scan(root.root(), &inventory).unwrap();
        assert!(!corrupt_generation.java_generation_complete());
    }

    #[test]
    fn copied_owner_marker_and_forged_root_nonce_cannot_rebind_availability() {
        let first = TestRoot::new("root-a");
        let second = TestRoot::from_owner_marker("root-b", &first);
        let release = fixture_release(b"root-bound", 4);
        let inventory = inventory(&first, &release);
        assert!(VerifiedAvailabilityV2::scan(second.root(), &inventory).is_err());

        let mut forged = VerifiedAvailabilityV2::for_test(&inventory, [], false, false);
        forged.root_binding_nonce = Uuid::new_v4();
        assert!(forged.validate_for(&inventory).is_err());
    }

    #[test]
    fn incomplete_game_generation_never_covers_official_cas() {
        let root = TestRoot::new("game-generation");
        let release = fixture_release(b"game", 4);
        let inventory = inventory(&root, &release);
        let fake = root
            .path
            .join("runtime/minecraft/generations")
            .join(inventory.game_runtime_lock_sha256());
        fs::create_dir_all(fake).unwrap();
        let scanned = VerifiedAvailabilityV2::scan(root.root(), &inventory).unwrap();
        assert!(!scanned.game_generation_complete());
        assert!(inventory.official_game_sha256().iter().all(|sha256| {
            scanned.state(sha256).unwrap() != &ArtifactAvailabilityStateV2::CoveredByGameGeneration
        }));
    }

    #[test]
    fn generation_coverage_skips_every_owned_artifact_class_with_zero_cas_audits() {
        let root = TestRoot::new("coverage-counter");
        let release = fixture_release(b"coverage", 4);
        let inventory = inventory(&root, &release);
        let mut audited = Vec::new();
        let states = scan_artifact_states_with(&inventory, true, true, |expected| {
            audited.push(expected.sha256().to_owned());
            Ok(CasObjectAvailability::Missing)
        })
        .unwrap();

        assert!(audited.iter().all(|sha256| {
            !inventory.is_java_archive_sha256(sha256) && !inventory.is_official_game_sha256(sha256)
        }));
        assert_eq!(
            audited.len(),
            inventory.artifacts().len() - inventory.official_game_sha256().len() - 1
        );
        assert_eq!(
            states
                .iter()
                .filter(|entry| {
                    entry.state == ArtifactAvailabilityStateV2::CoveredByGameGeneration
                })
                .count(),
            inventory.official_game_sha256().len()
        );
        assert_eq!(
            states
                .iter()
                .filter(|entry| {
                    entry.state == ArtifactAvailabilityStateV2::CoveredByJavaGeneration
                })
                .count(),
            1
        );
    }

    #[test]
    fn verified_game_coverage_ignores_unsafe_official_cas_but_corrupt_generation_falls_back() {
        let root = TestRoot::new("coverage-adversarial");
        let release = fixture_release(b"coverage", 4);
        let inventory = inventory(&root, &release);
        let official = inventory.official_game_sha256()[0].clone();
        let corrupt_official = inventory.official_game_sha256()[1].clone();
        let (official_final, _) = object_paths(root.root(), &official);
        let (corrupt_final, _) = object_paths(root.root(), &corrupt_official);
        fs::create_dir_all(&official_final).unwrap();
        write(&corrupt_final, b"wrong");

        let covered = VerifiedAvailabilityV2::scan_with_synthetic_generation_coverage(
            root.root(),
            &inventory,
            false,
            true,
        )
        .unwrap();
        covered.validate_for(&inventory).unwrap();
        assert_eq!(
            covered.state(&official).unwrap(),
            &ArtifactAvailabilityStateV2::CoveredByGameGeneration
        );
        assert_eq!(
            covered.state(&corrupt_official).unwrap(),
            &ArtifactAvailabilityStateV2::CoveredByGameGeneration
        );

        // With no verified game generation, the same unsafe CAS node is inspected and rejected.
        assert!(VerifiedAvailabilityV2::scan(root.root(), &inventory).is_err());
        fs::remove_dir(&official_final).unwrap();
        write(&official_final, b"wrong");
        let corrupt_generation = root
            .path
            .join("runtime/minecraft/generations")
            .join(inventory.game_runtime_lock_sha256());
        fs::create_dir_all(corrupt_generation).unwrap();

        let fallback = VerifiedAvailabilityV2::scan(root.root(), &inventory).unwrap();
        assert!(!fallback.game_generation_complete());
        assert_eq!(
            fallback.state(&official).unwrap(),
            &ArtifactAvailabilityStateV2::Corrupt
        );
    }

    #[test]
    fn covered_states_without_matching_sealed_capability_are_rejected() {
        let root = TestRoot::new("forged-coverage");
        let release = fixture_release(b"coverage", 4);
        let inventory = inventory(&root, &release);
        let mut forged = VerifiedAvailabilityV2::for_test(
            &inventory,
            [(
                inventory.java_archive_sha256().to_owned(),
                ArtifactAvailabilityStateV2::CoveredByJavaGeneration,
            )],
            false,
            false,
        );
        assert!(forged.validate_for(&inventory).is_err());

        forged.artifacts = VerifiedAvailabilityV2::for_test(
            &inventory,
            [(
                inventory.official_game_sha256()[0].clone(),
                ArtifactAvailabilityStateV2::CoveredByGameGeneration,
            )],
            false,
            false,
        )
        .artifacts;
        assert!(forged.validate_for(&inventory).is_err());
    }
}
