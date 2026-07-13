use super::{
    journal::ReconcilePlanV2,
    managed_fs::{
        GuardedDirectoryChain, ImmutableManagedFile, RecursiveChangeSentinel, RelativeManagedPath,
    },
    release::{FilePolicy, ManifestFile, ReleaseManifest},
    tuf::TrustedRelease,
    types::{BuildChannel, PresetId},
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

const MAX_UNKNOWN_INSTANCE_AUDIT_ENTRIES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DesiredFilePolicy {
    Exact,
    ValidatedMutable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DesiredFile {
    pub path: String,
    relative: RelativeManagedPath,
    pub size: u64,
    pub sha256: String,
    pub policy: DesiredFilePolicy,
}

/// A case-folded view of everything which may exist below one channel instance.
///
/// Manifest files and required directories are managed. Preserved roots are
/// opaque: their root is checked for a safe directory type, then the subtree is
/// deliberately not enumerated.
#[derive(Debug, Clone)]
pub(super) struct DesiredTree {
    files: BTreeMap<String, DesiredFile>,
    directories: BTreeMap<String, String>,
    required_directories: BTreeSet<String>,
    preserved_roots: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ModifiedKind {
    Size,
    Sha256,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ModifiedFile {
    pub path: String,
    pub kind: ModifiedKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum UnsafeEntryKind {
    CaseCollision,
    CaseMismatch,
    NonCanonicalName,
    Symlink,
    ReparsePoint,
    ExpectedFileIsDirectory,
    ExpectedDirectoryIsFile,
    UnsupportedFileType,
    UnsafeRegularFile,
    UnsafeDirectory,
    ChangedDuringRead,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct UnsafeEntry {
    pub path: String,
    pub kind: UnsafeEntryKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct InstanceAudit {
    /// Exact files whose opened handle matched both signed length and SHA-256.
    pub verified_exact: Vec<String>,
    /// Safe regular files which still require their named mutable validator.
    pub validated_mutable_candidates: Vec<String>,
    pub missing_files: Vec<String>,
    pub missing_directories: Vec<String>,
    pub modified_files: Vec<ModifiedFile>,
    pub unknown_files: Vec<String>,
    pub unknown_directories: Vec<String>,
    pub unsafe_entries: Vec<UnsafeEntry>,
}

/// Handle-bound launch authority for the exact, signed part of one channel instance.
///
/// Exact files are opened with write/delete sharing disabled and remain leased for the whole game
/// process. Signed mutable settings are sealed through admission and process creation, then
/// released as the final suspended-child gate action immediately before `ResumeThread`. Sticky
/// recursive notifications reject late namespace, metadata and NTFS stream changes without a
/// second admission-window enumeration.
pub(super) struct LaunchInstanceLease {
    instance_root: std::path::PathBuf,
    anchor: GuardedDirectoryChain,
    desired: DesiredTree,
    exact_files: BTreeMap<String, ImmutableManagedFile>,
    mutable_seals: BTreeMap<String, ImmutableManagedFile>,
    change_sentinel: RecursiveChangeSentinel,
}

impl std::fmt::Debug for LaunchInstanceLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LaunchInstanceLease")
            .field("instance_root", &self.instance_root)
            .field("exact_file_count", &self.exact_files.len())
            .field("mutable_seal_count", &self.mutable_seals.len())
            .finish_non_exhaustive()
    }
}

impl LaunchInstanceLease {
    pub(super) fn instance_root(&self) -> &Path {
        &self.instance_root
    }

    /// Full content audit. This may read every exact file and therefore must run before the
    /// short-lived server launch admission is requested.
    pub(super) fn revalidate_full(&self) -> Result<InstanceAudit, String> {
        self.change_sentinel
            .revalidate_clean()
            .map_err(|error| error.to_string())?;
        self.anchor
            .revalidate()
            .map_err(|error| error.to_string())?;
        for file in self.exact_files.values() {
            file.revalidate().map_err(|error| error.to_string())?;
        }
        for file in self.mutable_seals.values() {
            file.revalidate().map_err(|error| error.to_string())?;
        }
        let audit = audit_instance_directory(&self.instance_root, &self.desired)?;
        if audit.needs_reconciliation() {
            return Err("Instance changed after launch preparation and must be repaired".into());
        }
        self.anchor
            .revalidate()
            .map_err(|error| error.to_string())?;
        for file in self.exact_files.values() {
            file.revalidate().map_err(|error| error.to_string())?;
        }
        for file in self.mutable_seals.values() {
            file.revalidate().map_err(|error| error.to_string())?;
        }
        self.change_sentinel
            .revalidate_clean()
            .map_err(|error| error.to_string())?;
        Ok(audit)
    }

    /// Content-size-independent final audit. The sticky recursive sentinel was armed before the
    /// full baseline audit, so this performs only O(1) handle/notification checks and never
    /// re-enumerates or hashes the instance inside the short admission-to-CreateProcessW window.
    pub(super) fn revalidate_fast(&self) -> Result<(), String> {
        self.change_sentinel
            .revalidate_clean()
            .map_err(|error| error.to_string())?;
        // Exact files remain protected by their immutable handles and the sticky metadata
        // sentinel. Mutable files are the only handles intentionally released at ResumeThread,
        // so explicitly re-prove their retained identities at that boundary.
        for file in self.mutable_seals.values() {
            file.revalidate().map_err(|error| error.to_string())?;
        }
        self.change_sentinel
            .revalidate_clean()
            .map_err(|error| error.to_string())
    }

    /// Releases only signed mutable-setting files at the suspended-process boundary. Exact mods,
    /// resources and configs remain sealed for the complete game lifetime.
    pub(super) fn release_mutable_seals_for_resume(&mut self) -> Result<(), String> {
        self.revalidate_fast()?;
        self.mutable_seals.clear();
        Ok(())
    }
}

/// Fresh post-game authority. It accepts a damaged namespace so the planner can classify Repair,
/// but a Ready result is possible only when every verified exact and mutable candidate remains
/// handle-sealed across capture and planning.
pub(super) struct PostGameInstanceLease {
    anchor: GuardedDirectoryChain,
    exact_files: BTreeMap<String, ImmutableManagedFile>,
    mutable_seals: BTreeMap<String, ImmutableManagedFile>,
    change_sentinel: RecursiveChangeSentinel,
}

impl PostGameInstanceLease {
    pub(super) fn revalidate(&self) -> Result<(), String> {
        self.change_sentinel
            .revalidate_clean()
            .map_err(|error| error.to_string())?;
        self.anchor
            .revalidate()
            .map_err(|error| error.to_string())?;
        for file in self.exact_files.values().chain(self.mutable_seals.values()) {
            file.revalidate().map_err(|error| error.to_string())?;
        }
        self.change_sentinel
            .revalidate_clean()
            .map_err(|error| error.to_string())
    }
}

/// Non-serializable proof that an instance audit was built from the exact immutable pending plan,
/// not from a newer release manifest which may have become current after the target marker was
/// committed.
#[derive(Debug, Clone)]
pub(super) struct ReconcilePlanAuditV2 {
    install_id: uuid::Uuid,
    channel: BuildChannel,
    operation_id: uuid::Uuid,
    plan_sha256: String,
    audit: InstanceAudit,
}

impl ReconcilePlanAuditV2 {
    pub(super) fn audit_for<'a>(
        &'a self,
        plan: &ReconcilePlanV2,
    ) -> Result<&'a InstanceAudit, String> {
        plan.validate(plan.install_id, plan.channel)?;
        let canonical = plan.canonical_bytes()?;
        if self.install_id != plan.install_id
            || self.channel != plan.channel
            || self.operation_id != plan.operation_id
            || self.plan_sha256 != format!("{:x}", Sha256::digest(canonical))
        {
            return Err("Final instance audit belongs to another reconcile plan".into());
        }
        Ok(&self.audit)
    }

    #[cfg(test)]
    pub(super) fn for_test(plan: &ReconcilePlanV2, audit: InstanceAudit) -> Self {
        Self {
            install_id: plan.install_id,
            channel: plan.channel,
            operation_id: plan.operation_id,
            plan_sha256: format!(
                "{:x}",
                Sha256::digest(plan.canonical_bytes().expect("test plan must be canonical"))
            ),
            audit,
        }
    }
}

impl DesiredTree {
    pub(super) fn from_release(
        release: &ReleaseManifest,
        preset: PresetId,
    ) -> Result<Self, String> {
        let preset = release.selected_preset(preset)?;
        Self::from_parts(
            &preset.files,
            &release.integrity.strict_roots,
            &release.integrity.preserved_paths,
        )
    }

    fn from_reconcile_plan(plan: &ReconcilePlanV2) -> Result<Self, String> {
        plan.validate(plan.install_id, plan.channel)?;
        let files = plan
            .desired_files
            .iter()
            .map(|file| ManifestFile {
                path: file.path.clone(),
                size: file.installed_size,
                sha256: file.installed_sha256.clone(),
                executable: file.executable,
                policy: file.policy,
            })
            .collect::<Vec<_>>();
        Self::from_parts(&files, &plan.strict_roots, &plan.preserved_paths)
    }

    fn from_parts(
        files: &[ManifestFile],
        strict_roots: &[String],
        preserved_roots: &[String],
    ) -> Result<Self, String> {
        let mut tree = Self {
            files: BTreeMap::new(),
            directories: BTreeMap::new(),
            required_directories: BTreeSet::new(),
            preserved_roots: BTreeMap::new(),
        };

        for strict in strict_roots {
            let strict_key = path_key(strict);
            if preserved_roots.iter().any(|preserved| {
                let preserved_key = path_key(preserved);
                is_within_key(&strict_key, &preserved_key)
                    || is_within_key(&preserved_key, &strict_key)
            }) {
                return Err(format!("Strict root overlaps preserved data: {strict}"));
            }
        }

        for file in files {
            let relative =
                RelativeManagedPath::new(&file.path).map_err(|error| error.to_string())?;
            let key = path_key(&file.path);
            if tree.files.contains_key(&key) {
                return Err(format!("Duplicate desired file: {}", file.path));
            }
            for parent in parent_paths(&file.path) {
                tree.insert_directory(&parent, true)?;
            }
            tree.files.insert(
                key,
                DesiredFile {
                    path: file.path.clone(),
                    relative,
                    size: file.size,
                    sha256: file.sha256.clone(),
                    policy: match file.policy {
                        FilePolicy::Exact => DesiredFilePolicy::Exact,
                        FilePolicy::ValidatedMutable => DesiredFilePolicy::ValidatedMutable,
                    },
                },
            );
        }

        for root in strict_roots {
            for directory in parent_paths_inclusive(root) {
                tree.insert_directory(&directory, true)?;
            }
        }
        for root in preserved_roots {
            for directory in parent_paths_inclusive(root) {
                tree.insert_directory(&directory, false)?;
            }
            let key = path_key(root);
            if tree
                .preserved_roots
                .insert(key.clone(), root.clone())
                .is_some()
            {
                return Err(format!("Duplicate preserved root: {root}"));
            }
        }

        for (key, file) in &tree.files {
            if tree.directories.contains_key(key) {
                return Err(format!(
                    "Desired path is both a file and directory: {}",
                    file.path
                ));
            }
            if tree.preserved_roots.iter().any(|(preserved, _)| {
                is_within_key(key, preserved) || is_within_key(preserved, key)
            }) {
                return Err(format!(
                    "Managed file overlaps preserved data: {}",
                    file.path
                ));
            }
        }
        Ok(tree)
    }

    fn insert_directory(&mut self, path: &str, required: bool) -> Result<(), String> {
        RelativeManagedPath::new(path).map_err(|error| error.to_string())?;
        let key = path_key(path);
        if self.files.contains_key(&key) {
            return Err(format!("Desired directory collides with a file: {path}"));
        }
        if let Some(existing) = self.directories.get(&key) {
            if existing != path {
                return Err(format!(
                    "Case-colliding desired directories: {existing} and {path}"
                ));
            }
        } else {
            self.directories.insert(key.clone(), path.to_owned());
        }
        if required {
            self.required_directories.insert(key);
        }
        Ok(())
    }

    fn canonical_path(&self, key: &str) -> Option<&str> {
        self.files
            .get(key)
            .map(|file| file.path.as_str())
            .or_else(|| self.directories.get(key).map(String::as_str))
    }
}

impl InstanceAudit {
    pub(super) fn needs_reconciliation(&self) -> bool {
        !self.missing_files.is_empty()
            || !self.missing_directories.is_empty()
            || !self.modified_files.is_empty()
            || !self.unknown_files.is_empty()
            || !self.unknown_directories.is_empty()
            || !self.unsafe_entries.is_empty()
    }

    pub(super) fn is_safe_for_mutable_validation(&self) -> bool {
        !self.needs_reconciliation()
    }

    fn finish(&mut self) {
        for paths in [
            &mut self.verified_exact,
            &mut self.validated_mutable_candidates,
            &mut self.missing_files,
            &mut self.missing_directories,
            &mut self.unknown_files,
            &mut self.unknown_directories,
        ] {
            paths.sort_by(path_order);
            paths.dedup();
        }
        self.modified_files.sort_by(|left, right| {
            path_order(&left.path, &right.path).then(left.kind.cmp(&right.kind))
        });
        self.modified_files.dedup();
        self.unsafe_entries.sort_by(|left, right| {
            path_order(&left.path, &right.path).then(left.kind.cmp(&right.kind))
        });
        self.unsafe_entries.dedup();
    }
}

/// Audits exactly `<install_root>/instances/<channel>` while retaining a guarded
/// install-root-to-instance directory chain for the whole operation.
///
/// The returned value deliberately contains classifications, not live handles.
/// A same-user adversary can modify paths after this function returns, so callers
/// must perform a final audit immediately before spawning Java. The mandatory
/// server launch guard remains the authority for multiplayer admission.
pub(super) fn audit_release_instance(
    install_root: &Path,
    channel: BuildChannel,
    release: &ReleaseManifest,
    preset: PresetId,
) -> Result<InstanceAudit, String> {
    let desired = DesiredTree::from_release(release, preset)?;
    audit_desired_instance(install_root, channel, &desired)
}

/// Builds the non-cloneable launch lease only after two complete audits around acquisition of
/// every exact-file handle. This closes the audit/open race for signed mods, resources and
/// configuration files: once acquired on Windows, another same-user process cannot overwrite,
/// truncate, rename or delete those files until the game exits and the lease is dropped.
pub(super) fn lease_release_instance(
    install_root: &Path,
    channel: BuildChannel,
    release: &ReleaseManifest,
    preset: PresetId,
) -> Result<LaunchInstanceLease, String> {
    let desired = DesiredTree::from_release(release, preset)?;
    let instance_relative = RelativeManagedPath::new(&format!("instances/{}", channel.as_str()))
        .map_err(|error| error.to_string())?;
    let anchor = GuardedDirectoryChain::open(install_root, &instance_relative)
        .map_err(|error| error.to_string())?;
    let instance_root = anchor.leaf().path().to_path_buf();
    let change_sentinel =
        RecursiveChangeSentinel::arm(&instance_root).map_err(|error| error.to_string())?;
    let first = audit_instance_directory(&instance_root, &desired)?;
    if first.needs_reconciliation() {
        return Err("Instance is not launch-ready and must be repaired".into());
    }
    let mut exact_files = BTreeMap::new();
    let mut mutable_seals = BTreeMap::new();
    for (key, file) in &desired.files {
        let opened = ImmutableManagedFile::open(&instance_root, &file.relative)
            .map_err(|error| error.to_string())?;
        match file.policy {
            DesiredFilePolicy::Exact => {
                if exact_files.insert(key.clone(), opened).is_some() {
                    return Err("Launch lease exact-file identity map is duplicated".into());
                }
            }
            DesiredFilePolicy::ValidatedMutable => {
                if mutable_seals.insert(key.clone(), opened).is_some() {
                    return Err("Launch lease mutable-file identity map is duplicated".into());
                }
            }
        }
    }
    if exact_files.len() != first.verified_exact.len() {
        return Err("Launch lease exact-file coverage disagrees with the signed audit".into());
    }
    if mutable_seals.len() != first.validated_mutable_candidates.len() {
        return Err("Launch lease mutable-file coverage disagrees with the signed audit".into());
    }

    let lease = LaunchInstanceLease {
        instance_root,
        anchor,
        desired,
        exact_files,
        mutable_seals,
        change_sentinel,
    };
    let _ = lease.revalidate_full()?;
    Ok(lease)
}

/// Audits and seals the local instance without requiring it to be Ready. This is used only after
/// the contained game Job is proven empty: allowed mutable values can be captured, while unknown
/// or disallowed content remains an explicit Repair classification.
pub(super) fn lease_post_game_instance(
    install_root: &Path,
    channel: BuildChannel,
    release: &ReleaseManifest,
    preset: PresetId,
) -> Result<(InstanceAudit, PostGameInstanceLease), String> {
    let desired = DesiredTree::from_release(release, preset)?;
    let instance_relative = RelativeManagedPath::new(&format!("instances/{}", channel.as_str()))
        .map_err(|error| error.to_string())?;
    let anchor = GuardedDirectoryChain::open(install_root, &instance_relative)
        .map_err(|error| error.to_string())?;
    let instance_root = anchor.leaf().path().to_path_buf();
    let change_sentinel =
        RecursiveChangeSentinel::arm(&instance_root).map_err(|error| error.to_string())?;
    let first = audit_instance_directory(&instance_root, &desired)?;

    let verified = first
        .verified_exact
        .iter()
        .map(|path| path_key(path))
        .collect::<BTreeSet<_>>();
    let mutable = first
        .validated_mutable_candidates
        .iter()
        .map(|path| path_key(path))
        .collect::<BTreeSet<_>>();
    let mut exact_files = BTreeMap::new();
    let mut mutable_seals = BTreeMap::new();
    for (key, file) in &desired.files {
        let destination = match file.policy {
            DesiredFilePolicy::Exact if verified.contains(key) => &mut exact_files,
            DesiredFilePolicy::ValidatedMutable if mutable.contains(key) => &mut mutable_seals,
            _ => continue,
        };
        let opened = ImmutableManagedFile::open(&instance_root, &file.relative)
            .map_err(|error| error.to_string())?;
        if destination.insert(key.clone(), opened).is_some() {
            return Err("Post-game instance seal map is duplicated".into());
        }
    }
    if exact_files.len() != first.verified_exact.len()
        || mutable_seals.len() != first.validated_mutable_candidates.len()
    {
        return Err("Post-game instance seals disagree with the baseline audit".into());
    }

    // The confirming audit runs only after every baseline-approved file is write/delete sealed.
    // A same-size overwrite in the first audit/open gap is therefore either denied or rehashed.
    let second = audit_instance_directory(&instance_root, &desired)?;
    let lease = PostGameInstanceLease {
        anchor,
        exact_files,
        mutable_seals,
        change_sentinel,
    };
    lease.revalidate()?;
    Ok((second, lease))
}

/// Audits the exact desired tree serialized in one immutable pending plan only while a freshly
/// trusted TUF release still binds that exact target. A stale plan cannot obtain this capability;
/// it must be atomically superseded by a fresh-current plan instead.
pub(super) fn audit_current_reconcile_plan_instance(
    install_root: &Path,
    plan: &ReconcilePlanV2,
    current_release: &TrustedRelease,
) -> Result<ReconcilePlanAuditV2, String> {
    plan.validate(plan.install_id, plan.channel)?;
    validate_current_plan_binding(plan, current_release)?;
    let desired = DesiredTree::from_reconcile_plan(plan)?;
    let audit = audit_desired_instance(install_root, plan.channel, &desired)?;
    let canonical = plan.canonical_bytes()?;
    Ok(ReconcilePlanAuditV2 {
        install_id: plan.install_id,
        channel: plan.channel,
        operation_id: plan.operation_id,
        plan_sha256: format!("{:x}", Sha256::digest(canonical)),
        audit,
    })
}

fn validate_current_plan_binding(
    plan: &ReconcilePlanV2,
    current: &TrustedRelease,
) -> Result<(), String> {
    let manifest = current.manifest();
    if current.channel() != plan.channel
        || current.current().channel != plan.channel
        || current.current().release_id != manifest.release.id
        || plan.target.release_id != manifest.release.id
        || !plan
            .target
            .trusted_release
            .targets_match(current.evidence())
        || !plan
            .target
            .trusted_release
            .roles_are_monotonic_to(current.evidence())
        || plan.target.release_manifest_sha256 != current.evidence().release_manifest.sha256
        || plan.target.runtime_lock_sha256 != manifest.runtime.java.runtime_lock_sha256
        || plan.target.game_runtime_lock_sha256 != manifest.runtime.game.runtime_lock_sha256
    {
        return Err("Historical TUF release does not bind the pending target".into());
    }
    current.evidence().validate_binding(
        plan.channel,
        &manifest.release.id,
        &current.current().manifest_target,
        &manifest.runtime.java.runtime_target,
        &manifest.runtime.game.runtime_target,
        &current.evidence().release_manifest.sha256,
        &manifest.runtime.java.runtime_lock_sha256,
        &manifest.runtime.game.runtime_lock_sha256,
    )?;
    manifest.bind_runtime_lock(current.runtime_lock())?;
    manifest.bind_game_runtime_lock(current.runtime_lock(), current.game_runtime_lock())?;

    let preset = manifest.selected_preset(plan.target.preset)?;
    let mut signed_strict_roots = manifest.integrity.strict_roots.clone();
    signed_strict_roots.sort_by(path_order);
    let mut signed_preserved_paths = manifest.integrity.preserved_paths.clone();
    signed_preserved_paths.sort_by(path_order);
    if plan.strict_roots != signed_strict_roots
        || plan.preserved_paths != signed_preserved_paths
        || plan.desired_files.len() != preset.files.len()
    {
        return Err("Pending reconcile scope differs from the current signed manifest".into());
    }
    let signed = preset
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect::<BTreeMap<_, _>>();
    for planned in &plan.desired_files {
        let Some(file) = signed.get(planned.path.as_str()) else {
            return Err("Pending desired file is absent from the current signed preset".into());
        };
        if planned.signed_size != file.size
            || planned.signed_sha256 != file.sha256
            || planned.executable != file.executable
            || planned.policy != file.policy
            || (planned.policy == FilePolicy::Exact
                && (planned.installed_size != file.size || planned.installed_sha256 != file.sha256))
        {
            return Err("Pending desired file differs from the current signed preset".into());
        }
    }
    Ok(())
}

fn audit_desired_instance(
    install_root: &Path,
    channel: BuildChannel,
    desired: &DesiredTree,
) -> Result<InstanceAudit, String> {
    let instance_relative = RelativeManagedPath::new(&format!("instances/{}", channel.as_str()))
        .map_err(|error| error.to_string())?;
    let instance_root = instance_relative.join_to(install_root);

    let anchor = match fs::symlink_metadata(&instance_root) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && !is_reparse_point(&metadata) =>
        {
            GuardedDirectoryChain::open(install_root, &instance_relative)
                .map_err(|error| error.to_string())?
        }
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Ok(audit_unavailable_root(
                desired,
                Some(UnsafeEntryKind::Symlink),
            ));
        }
        Ok(metadata) if is_reparse_point(&metadata) => {
            return Ok(audit_unavailable_root(
                desired,
                Some(UnsafeEntryKind::ReparsePoint),
            ));
        }
        Ok(_) => {
            return Ok(audit_unavailable_root(
                desired,
                Some(UnsafeEntryKind::ExpectedDirectoryIsFile),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(audit_unavailable_root(desired, None));
        }
        Err(error) => {
            return Err(format!(
                "Cannot inspect instance root {}: {error}",
                instance_root.display()
            ));
        }
    };
    let audit = audit_instance_directory(&instance_root, desired)?;
    recheck_guarded_directory(install_root, Some(&instance_relative), &anchor)?;
    Ok(audit)
}

fn audit_unavailable_root(
    desired: &DesiredTree,
    root_issue: Option<UnsafeEntryKind>,
) -> InstanceAudit {
    let mut audit = InstanceAudit {
        missing_files: desired
            .files
            .values()
            .map(|file| file.path.clone())
            .collect(),
        missing_directories: desired
            .required_directories
            .iter()
            .filter_map(|key| desired.directories.get(key).cloned())
            .collect(),
        ..InstanceAudit::default()
    };
    if let Some(kind) = root_issue {
        audit.unsafe_entries.push(UnsafeEntry {
            path: ".".into(),
            kind,
        });
    }
    audit.finish();
    audit
}

/// Audits a directory treated as an already-approved filesystem trust root.
/// Production callers should prefer `audit_release_instance`, which also guards
/// the `install_root/instances/<channel>` ancestor chain.
pub(super) fn audit_instance_directory(
    instance_root: &Path,
    desired: &DesiredTree,
) -> Result<InstanceAudit, String> {
    audit_instance_directory_with_mode(instance_root, desired, &ExactFileAudit::FullContent)
}

enum ExactFileAudit<'a> {
    FullContent,
    RetainedIdentity(&'a BTreeMap<String, ImmutableManagedFile>),
}

struct DirectoryScanContext<'scan, 'retained> {
    instance_root: &'scan Path,
    desired: &'scan DesiredTree,
    exact_audit: &'scan ExactFileAudit<'retained>,
}

fn audit_instance_directory_fast(
    instance_root: &Path,
    desired: &DesiredTree,
    retained: &BTreeMap<String, ImmutableManagedFile>,
) -> Result<InstanceAudit, String> {
    audit_instance_directory_with_mode(
        instance_root,
        desired,
        &ExactFileAudit::RetainedIdentity(retained),
    )
}

fn audit_instance_directory_with_mode(
    instance_root: &Path,
    desired: &DesiredTree,
    exact_audit: &ExactFileAudit<'_>,
) -> Result<InstanceAudit, String> {
    let mut audit = InstanceAudit::default();
    let mut encountered = BTreeSet::new();
    let mut namespace_budget = NamespaceAuditBudget {
        seen: 0,
        maximum: desired
            .files
            .len()
            .checked_add(desired.directories.len())
            .and_then(|authorized| {
                authorized.checked_add(match exact_audit {
                    ExactFileAudit::FullContent => MAX_UNKNOWN_INSTANCE_AUDIT_ENTRIES,
                    ExactFileAudit::RetainedIdentity(_) => 0,
                })
            })
            .ok_or_else(|| "Signed instance namespace limit overflowed".to_string())?,
    };

    match fs::symlink_metadata(instance_root) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                audit.unsafe_entries.push(UnsafeEntry {
                    path: ".".into(),
                    kind: UnsafeEntryKind::Symlink,
                });
            } else if is_reparse_point(&metadata) {
                audit.unsafe_entries.push(UnsafeEntry {
                    path: ".".into(),
                    kind: UnsafeEntryKind::ReparsePoint,
                });
            } else if !metadata.is_dir() {
                audit.unsafe_entries.push(UnsafeEntry {
                    path: ".".into(),
                    kind: UnsafeEntryKind::ExpectedDirectoryIsFile,
                });
            } else {
                let root_guard = GuardedDirectoryChain::root_only(instance_root)
                    .map_err(|error| error.to_string())?;
                let context = DirectoryScanContext {
                    instance_root,
                    desired,
                    exact_audit,
                };
                scan_directory(
                    &context,
                    None,
                    &root_guard,
                    &mut namespace_budget,
                    &mut encountered,
                    &mut audit,
                )?;
                recheck_guarded_directory(instance_root, None, &root_guard)?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "Cannot inspect instance root {}: {error}",
                instance_root.display()
            ));
        }
    }

    for (key, file) in &desired.files {
        if !encountered.contains(key) {
            audit.missing_files.push(file.path.clone());
        }
    }
    for key in &desired.required_directories {
        if !encountered.contains(key) {
            if let Some(path) = desired.directories.get(key) {
                audit.missing_directories.push(path.clone());
            }
        }
    }
    audit.finish();
    Ok(audit)
}

fn scan_directory(
    context: &DirectoryScanContext<'_, '_>,
    relative_parent: Option<&RelativeManagedPath>,
    directory_guard: &GuardedDirectoryChain,
    namespace_budget: &mut NamespaceAuditBudget,
    encountered: &mut BTreeSet<String>,
    audit: &mut InstanceAudit,
) -> Result<(), String> {
    let DirectoryScanContext {
        instance_root,
        desired,
        exact_audit,
    } = context;
    let guarded_path = directory_guard.leaf().path();
    let initial_names = sorted_directory_names_bounded(
        guarded_path,
        namespace_budget
            .maximum
            .saturating_sub(namespace_budget.seen),
    )?;
    namespace_budget.seen = namespace_budget
        .seen
        .checked_add(initial_names.len())
        .ok_or_else(|| "Instance namespace entry count overflowed".to_string())?;

    let mut names_by_key = BTreeMap::<String, String>::new();
    let mut decoded = Vec::with_capacity(initial_names.len());
    let relative_parent_text = relative_parent.map_or("", RelativeManagedPath::as_str);
    for name_os in &initial_names {
        let Some(name) = name_os.to_str().map(str::to_owned) else {
            audit.unsafe_entries.push(UnsafeEntry {
                path: non_unicode_path(relative_parent_text, name_os),
                kind: UnsafeEntryKind::NonCanonicalName,
            });
            continue;
        };
        let relative = join_manifest_path(relative_parent_text, &name);
        let key = path_key(&relative);
        if let Some(previous) = names_by_key.insert(path_key(&name), relative.clone()) {
            audit.unsafe_entries.push(UnsafeEntry {
                path: previous,
                kind: UnsafeEntryKind::CaseCollision,
            });
            audit.unsafe_entries.push(UnsafeEntry {
                path: relative.clone(),
                kind: UnsafeEntryKind::CaseCollision,
            });
        }
        let managed_relative = match RelativeManagedPath::new(&relative) {
            Ok(path) => path,
            Err(_) => {
                audit.unsafe_entries.push(UnsafeEntry {
                    path: relative,
                    kind: UnsafeEntryKind::NonCanonicalName,
                });
                continue;
            }
        };
        decoded.push((managed_relative, relative, key));
    }

    for (managed_relative, relative, key) in decoded {
        encountered.insert(key.clone());
        let path = managed_relative.join_to(instance_root);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("Cannot inspect managed entry {}: {error}", path.display()))?;
        let case_mismatch = desired
            .canonical_path(&key)
            .is_some_and(|canonical| canonical != relative);
        if case_mismatch {
            audit.unsafe_entries.push(UnsafeEntry {
                path: relative.clone(),
                kind: UnsafeEntryKind::CaseMismatch,
            });
        }

        if metadata.file_type().is_symlink() {
            audit.unsafe_entries.push(UnsafeEntry {
                path: relative,
                kind: UnsafeEntryKind::Symlink,
            });
            continue;
        }
        if is_reparse_point(&metadata) {
            audit.unsafe_entries.push(UnsafeEntry {
                path: relative,
                kind: UnsafeEntryKind::ReparsePoint,
            });
            continue;
        }

        if let Some(preserved) = desired.preserved_roots.get(&key) {
            if !case_mismatch && preserved == &relative {
                if metadata.is_dir() {
                    let preserved_guard =
                        match GuardedDirectoryChain::open(instance_root, &managed_relative) {
                            Ok(guard) => guard,
                            Err(_) => {
                                audit.unsafe_entries.push(UnsafeEntry {
                                    path: relative,
                                    kind: unsafe_directory_kind(&path),
                                });
                                continue;
                            }
                        };
                    recheck_guarded_directory(
                        instance_root,
                        Some(&managed_relative),
                        &preserved_guard,
                    )?;
                    continue;
                }
                audit.unsafe_entries.push(UnsafeEntry {
                    path: relative,
                    kind: UnsafeEntryKind::ExpectedDirectoryIsFile,
                });
                continue;
            }
        }

        if metadata.is_dir() {
            let child_guard = match GuardedDirectoryChain::open(instance_root, &managed_relative) {
                Ok(guard) => guard,
                Err(_) => {
                    audit.unsafe_entries.push(UnsafeEntry {
                        path: relative,
                        kind: unsafe_directory_kind(&path),
                    });
                    continue;
                }
            };
            if desired.files.contains_key(&key) {
                audit.unsafe_entries.push(UnsafeEntry {
                    path: relative.clone(),
                    kind: UnsafeEntryKind::ExpectedFileIsDirectory,
                });
            } else if !desired.directories.contains_key(&key) && !case_mismatch {
                audit.unknown_directories.push(relative.clone());
            }
            scan_directory(
                context,
                Some(&managed_relative),
                &child_guard,
                namespace_budget,
                encountered,
                audit,
            )?;
            recheck_guarded_directory(instance_root, Some(&managed_relative), &child_guard)?;
            continue;
        }

        if !metadata.is_file() {
            audit.unsafe_entries.push(UnsafeEntry {
                path: relative,
                kind: UnsafeEntryKind::UnsupportedFileType,
            });
            continue;
        }
        if desired.directories.contains_key(&key) {
            audit.unsafe_entries.push(UnsafeEntry {
                path: relative,
                kind: UnsafeEntryKind::ExpectedDirectoryIsFile,
            });
            continue;
        }
        if case_mismatch {
            // Still open it through a guarded parent so a hard link cannot hide
            // behind an unsafe spelling.
            if ImmutableManagedFile::open(instance_root, &managed_relative).is_err() {
                audit.unsafe_entries.push(UnsafeEntry {
                    path: relative,
                    kind: UnsafeEntryKind::UnsafeRegularFile,
                });
            }
            continue;
        }

        let Some(expected) = desired.files.get(&key) else {
            if ImmutableManagedFile::open(instance_root, &managed_relative).is_err() {
                audit.unsafe_entries.push(UnsafeEntry {
                    path: relative,
                    kind: UnsafeEntryKind::UnsafeRegularFile,
                });
            } else {
                audit.unknown_files.push(relative);
            }
            continue;
        };
        match expected.policy {
            DesiredFilePolicy::ValidatedMutable => {
                if ImmutableManagedFile::open(instance_root, &expected.relative).is_err() {
                    audit.unsafe_entries.push(UnsafeEntry {
                        path: relative,
                        kind: UnsafeEntryKind::UnsafeRegularFile,
                    });
                } else {
                    audit
                        .validated_mutable_candidates
                        .push(expected.path.clone());
                }
            }
            DesiredFilePolicy::Exact => {
                match audit_exact_file(instance_root, &key, expected, exact_audit) {
                    Ok(None) => audit.verified_exact.push(expected.path.clone()),
                    Ok(Some(kind)) => audit.modified_files.push(ModifiedFile {
                        path: expected.path.clone(),
                        kind,
                    }),
                    Err(HashFailure::UnsafeFile) => audit.unsafe_entries.push(UnsafeEntry {
                        path: relative,
                        kind: UnsafeEntryKind::UnsafeRegularFile,
                    }),
                    Err(HashFailure::ChangedDuringRead) => audit.unsafe_entries.push(UnsafeEntry {
                        path: relative,
                        kind: UnsafeEntryKind::ChangedDuringRead,
                    }),
                }
            }
        }
    }
    if sorted_directory_names_bounded(guarded_path, initial_names.len())? != initial_names {
        return Err(format!(
            "Managed directory contents changed during audit: {}",
            guarded_path.display()
        ));
    }
    recheck_guarded_directory(instance_root, relative_parent, directory_guard)?;
    Ok(())
}

enum HashFailure {
    UnsafeFile,
    ChangedDuringRead,
}

fn audit_exact_file(
    instance_root: &Path,
    key: &str,
    expected: &DesiredFile,
    mode: &ExactFileAudit<'_>,
) -> Result<Option<ModifiedKind>, HashFailure> {
    match mode {
        ExactFileAudit::FullContent => hash_exact_file(instance_root, expected),
        ExactFileAudit::RetainedIdentity(retained) => {
            let retained = retained.get(key).ok_or(HashFailure::UnsafeFile)?;
            retained
                .revalidate()
                .map_err(|_| HashFailure::ChangedDuringRead)?;
            let reopened = ImmutableManagedFile::open(instance_root, &expected.relative)
                .map_err(|_| HashFailure::UnsafeFile)?;
            if reopened.info().size != expected.size {
                return Ok(Some(ModifiedKind::Size));
            }
            if retained.info().size != expected.size
                || reopened.info().identity != retained.info().identity
                || reopened.info().size != retained.info().size
            {
                return Err(HashFailure::ChangedDuringRead);
            }
            reopened
                .revalidate()
                .map_err(|_| HashFailure::ChangedDuringRead)?;
            retained
                .revalidate()
                .map_err(|_| HashFailure::ChangedDuringRead)?;
            Ok(None)
        }
    }
}

fn hash_exact_file(
    instance_root: &Path,
    expected: &DesiredFile,
) -> Result<Option<ModifiedKind>, HashFailure> {
    exact_content_read_started();
    let mut file = ImmutableManagedFile::open(instance_root, &expected.relative)
        .map_err(|_| HashFailure::UnsafeFile)?;
    if file.info().size != expected.size {
        return Ok(Some(ModifiedKind::Size));
    }
    let digest = file
        .sha256(expected.size)
        .map_err(|_| HashFailure::ChangedDuringRead)?;
    if digest.size != expected.size || digest.sha256 != expected.sha256 {
        return Ok(Some(ModifiedKind::Sha256));
    }
    Ok(None)
}

#[cfg(test)]
std::thread_local! {
    static FORBID_EXACT_CONTENT_READ: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn exact_content_read_started() {
    FORBID_EXACT_CONTENT_READ.with(|forbidden| {
        assert!(
            !forbidden.get(),
            "admission-window exact audit attempted to read file contents"
        );
    });
}

#[cfg(not(test))]
#[inline(always)]
fn exact_content_read_started() {}

fn recheck_guarded_directory(
    root: &Path,
    relative: Option<&RelativeManagedPath>,
    guard: &GuardedDirectoryChain,
) -> Result<(), String> {
    let reopened = match relative {
        Some(relative) => GuardedDirectoryChain::open(root, relative),
        None => GuardedDirectoryChain::root_only(root),
    }
    .map_err(|error| error.to_string())?;
    if reopened.leaf().info().identity != guard.leaf().info().identity {
        return Err(format!(
            "Managed directory identity changed during audit: {}",
            guard.leaf().path().display()
        ));
    }
    Ok(())
}

fn unsafe_directory_kind(path: &Path) -> UnsafeEntryKind {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => UnsafeEntryKind::Symlink,
        Ok(metadata) if is_reparse_point(&metadata) => UnsafeEntryKind::ReparsePoint,
        Ok(metadata) if !metadata.is_dir() => UnsafeEntryKind::ChangedDuringRead,
        Ok(_) => UnsafeEntryKind::UnsafeDirectory,
        Err(_) => UnsafeEntryKind::ChangedDuringRead,
    }
}

struct NamespaceAuditBudget {
    seen: usize,
    maximum: usize,
}

fn sorted_directory_names_bounded(
    path: &Path,
    maximum: usize,
) -> Result<Vec<std::ffi::OsString>, String> {
    let mut names = Vec::with_capacity(maximum.min(4096));
    for entry in fs::read_dir(path).map_err(|error| {
        format!(
            "Cannot enumerate managed directory {}: {error}",
            path.display()
        )
    })? {
        if names.len() == maximum {
            return Err(format!(
                "Managed instance namespace exceeds its signed entry bound at {}",
                path.display()
            ));
        }
        names.push(
            entry
                .map_err(|error| {
                    format!(
                        "Cannot enumerate managed directory {}: {error}",
                        path.display()
                    )
                })?
                .file_name(),
        );
    }
    names.sort();
    Ok(names)
}

fn parent_paths(path: &str) -> Vec<String> {
    let parts: Vec<_> = path.split('/').collect();
    (1..parts.len()).map(|end| parts[..end].join("/")).collect()
}

fn parent_paths_inclusive(path: &str) -> Vec<String> {
    let parts: Vec<_> = path.split('/').collect();
    (1..=parts.len())
        .map(|end| parts[..end].join("/"))
        .collect()
}

fn path_key(path: &str) -> String {
    path.to_lowercase()
}

fn is_within_key(path: &str, root: &str) -> bool {
    path == root || path.starts_with(&format!("{root}/"))
}

fn join_manifest_path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

fn path_order(left: &String, right: &String) -> std::cmp::Ordering {
    path_key(left).cmp(&path_key(right)).then(left.cmp(right))
}

fn non_unicode_path(parent: &str, name: &std::ffi::OsStr) -> String {
    join_manifest_path(parent, &format!("<non-unicode:{}>", name.to_string_lossy()))
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Write, path::PathBuf};

    struct TestDirectory {
        container: PathBuf,
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            // The sentinel also watches the exact root's parent non-recursively. Give every test
            // a private parent so unrelated parallel temp-directory activity cannot dirty it.
            let container = std::env::temp_dir().join(format!(
                "fragment-reconciler-container-{}",
                uuid::Uuid::new_v4()
            ));
            let path = container.join("instance");
            fs::create_dir_all(&path).unwrap();
            Self { container, path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write(&self, relative: &str, bytes: &[u8]) {
            let path = self
                .path
                .join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut file = fs::File::create(path).unwrap();
            file.write_all(bytes).unwrap();
        }

        fn directory(&self, relative: &str) {
            fs::create_dir_all(
                self.path
                    .join(relative.replace('/', std::path::MAIN_SEPARATOR_STR)),
            )
            .unwrap();
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.container);
        }
    }

    fn exact(path: &str, bytes: &[u8]) -> ManifestFile {
        ManifestFile {
            path: path.into(),
            size: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
            executable: false,
            policy: FilePolicy::Exact,
        }
    }

    fn mutable(path: &str, bytes: &[u8]) -> ManifestFile {
        ManifestFile {
            policy: FilePolicy::ValidatedMutable,
            ..exact(path, bytes)
        }
    }

    fn desired(files: Vec<ManifestFile>, strict: &[&str], preserved: &[&str]) -> DesiredTree {
        DesiredTree::from_parts(
            &files,
            &strict
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
            &preserved
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn launch_lease(
        root: &TestDirectory,
        desired: DesiredTree,
        exact_files: BTreeMap<String, ImmutableManagedFile>,
    ) -> LaunchInstanceLease {
        let change_sentinel = RecursiveChangeSentinel::arm(root.path()).unwrap();
        LaunchInstanceLease {
            instance_root: root.path().to_path_buf(),
            anchor: GuardedDirectoryChain::root_only(root.path()).unwrap(),
            desired,
            exact_files,
            mutable_seals: BTreeMap::new(),
            change_sentinel,
        }
    }

    struct ForbidExactContentRead;

    impl ForbidExactContentRead {
        fn arm() -> Self {
            FORBID_EXACT_CONTENT_READ.with(|forbidden| {
                assert!(!forbidden.replace(true));
            });
            Self
        }
    }

    impl Drop for ForbidExactContentRead {
        fn drop(&mut self) {
            FORBID_EXACT_CONTENT_READ.with(|forbidden| forbidden.set(false));
        }
    }

    #[test]
    fn rejects_strict_and_preserved_overlap_even_for_preconstructed_manifests() {
        let result = DesiredTree::from_parts(&[], &["mods".into()], &["mods/player-owned".into()]);

        assert!(result.is_err());
    }

    #[test]
    fn detects_unknown_entries_everywhere_not_only_in_strict_roots() {
        let root = TestDirectory::new();
        root.write("mods/guard.jar", b"guard");
        root.write("outside.txt", b"unknown");
        root.write("other/nested.txt", b"unknown");
        let tree = desired(vec![exact("mods/guard.jar", b"guard")], &["mods"], &[]);

        let audit = audit_instance_directory(root.path(), &tree).unwrap();

        assert_eq!(audit.unknown_files, ["other/nested.txt", "outside.txt"]);
        assert_eq!(audit.unknown_directories, ["other"]);
        assert_eq!(audit.verified_exact, ["mods/guard.jar"]);
    }

    #[test]
    fn preserved_subtree_is_opaque_and_optional() {
        let root = TestDirectory::new();
        root.write("mods/guard.jar", b"guard");
        root.write("saves/world/anything.dat", b"player-owned");
        root.write("screenshots/picture.png", b"player-owned");
        let tree = desired(
            vec![exact("mods/guard.jar", b"guard")],
            &["mods"],
            &["saves", "screenshots", "logs"],
        );

        let audit = audit_instance_directory(root.path(), &tree).unwrap();

        assert!(!audit.needs_reconciliation());
        assert_eq!(audit.verified_exact, ["mods/guard.jar"]);
    }

    #[test]
    fn reports_modified_and_missing_files_separately() {
        let root = TestDirectory::new();
        root.write("mods/guard.jar", b"wrong");
        let tree = desired(
            vec![
                exact("mods/guard.jar", b"guard"),
                exact("config/project.toml", b"config"),
            ],
            &["mods", "config"],
            &[],
        );

        let audit = audit_instance_directory(root.path(), &tree).unwrap();

        assert_eq!(
            audit.modified_files,
            [ModifiedFile {
                path: "mods/guard.jar".into(),
                kind: ModifiedKind::Sha256,
            }]
        );
        assert_eq!(audit.missing_files, ["config/project.toml"]);
        assert_eq!(audit.missing_directories, ["config"]);
    }

    #[test]
    fn accepts_a_present_empty_strict_root_and_reports_an_absent_one() {
        let root = TestDirectory::new();
        root.directory("shaderpacks");
        let tree = desired(vec![], &["shaderpacks", "resourcepacks"], &[]);

        let audit = audit_instance_directory(root.path(), &tree).unwrap();

        assert_eq!(audit.missing_directories, ["resourcepacks"]);
        assert!(audit.unknown_directories.is_empty());
    }

    #[test]
    fn mutable_file_is_a_candidate_not_an_exact_hash_failure() {
        let root = TestDirectory::new();
        root.write("options.txt", b"player changed this");
        let tree = desired(
            vec![mutable("options.txt", b"signed default")],
            &["config"],
            &[],
        );
        root.directory("config");

        let audit = audit_instance_directory(root.path(), &tree).unwrap();

        assert_eq!(audit.validated_mutable_candidates, ["options.txt"]);
        assert!(audit.modified_files.is_empty());
    }

    #[test]
    fn final_fast_audit_never_reads_large_exact_file_contents() {
        const LARGE_LOGICAL_SIZE: u64 = 512 * 1024 * 1024;
        let root = TestDirectory::new();
        root.directory("mods");
        let absolute = root.path().join("mods/large.jar");
        fs::File::create(&absolute)
            .unwrap()
            .set_len(LARGE_LOGICAL_SIZE)
            .unwrap();
        let tree = desired(
            vec![ManifestFile {
                path: "mods/large.jar".into(),
                size: LARGE_LOGICAL_SIZE,
                // Deliberately not the sparse file's digest: this lease models content which was
                // authenticated before admission. The armed hook proves the final pass cannot
                // fall back to the slow content reader.
                sha256: "0".repeat(64),
                executable: false,
                policy: FilePolicy::Exact,
            }],
            &["mods"],
            &[],
        );
        let relative = RelativeManagedPath::new("mods/large.jar").unwrap();
        let mut files = BTreeMap::new();
        files.insert(
            path_key("mods/large.jar"),
            ImmutableManagedFile::open(root.path(), &relative).unwrap(),
        );
        let lease = launch_lease(&root, tree, files);

        let _forbid_slow_reader = ForbidExactContentRead::arm();
        lease.revalidate_fast().unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn mutable_write_is_denied_until_the_suspended_resume_boundary_releases_its_seal() {
        use std::io::{Seek, SeekFrom};

        let root = TestDirectory::new();
        root.write("options.txt", b"baseline");
        let tree = desired(vec![mutable("options.txt", b"baseline")], &[], &[]);
        let relative = RelativeManagedPath::new("options.txt").unwrap();
        let mut mutable_seals = BTreeMap::new();
        mutable_seals.insert(
            path_key("options.txt"),
            ImmutableManagedFile::open(root.path(), &relative).unwrap(),
        );
        let change_sentinel = RecursiveChangeSentinel::arm(root.path()).unwrap();
        let mut lease = LaunchInstanceLease {
            instance_root: root.path().to_path_buf(),
            anchor: GuardedDirectoryChain::root_only(root.path()).unwrap(),
            desired: tree,
            exact_files: BTreeMap::new(),
            mutable_seals,
            change_sentinel,
        };
        lease.revalidate_fast().unwrap();

        let path = root.path().join("options.txt");
        assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
        lease.release_mutable_seals_for_resume().unwrap();

        let mut writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
        writer.seek(SeekFrom::Start(0)).unwrap();
        writer.write_all(b"modified").unwrap();
        writer.sync_all().unwrap();
        drop(writer);
        assert_eq!(fs::read(&path).unwrap(), b"modified");
    }

    #[cfg(windows)]
    #[test]
    fn mutable_named_stream_injection_dirties_the_sticky_gate() {
        let root = TestDirectory::new();
        root.write("options.txt", b"baseline");
        let tree = desired(vec![mutable("options.txt", b"baseline")], &[], &[]);
        let relative = RelativeManagedPath::new("options.txt").unwrap();
        let mut mutable_seals = BTreeMap::new();
        mutable_seals.insert(
            path_key("options.txt"),
            ImmutableManagedFile::open(root.path(), &relative).unwrap(),
        );
        let change_sentinel = RecursiveChangeSentinel::arm(root.path()).unwrap();
        let lease = LaunchInstanceLease {
            instance_root: root.path().to_path_buf(),
            anchor: GuardedDirectoryChain::root_only(root.path()).unwrap(),
            desired: tree,
            exact_files: BTreeMap::new(),
            mutable_seals,
            change_sentinel,
        };
        let path = root.path().join("options.txt");
        fs::write(format!("{}:payload", path.display()), b"hidden").unwrap();
        assert!(lease
            .change_sentinel
            .wait_until_dirty(std::time::Duration::from_secs(2)));
        assert!(lease.revalidate_fast().is_err());
        assert!(lease.revalidate_fast().is_err());
    }

    #[cfg(windows)]
    #[test]
    fn post_game_settlement_lease_fails_closed_on_concurrent_instance_mutation() {
        let root = TestDirectory::new();
        root.write("options.txt", b"baseline");
        let relative = RelativeManagedPath::new("options.txt").unwrap();
        let mut mutable_seals = BTreeMap::new();
        mutable_seals.insert(
            path_key("options.txt"),
            ImmutableManagedFile::open(root.path(), &relative).unwrap(),
        );
        let lease = PostGameInstanceLease {
            anchor: GuardedDirectoryChain::root_only(root.path()).unwrap(),
            exact_files: BTreeMap::new(),
            mutable_seals,
            change_sentinel: RecursiveChangeSentinel::arm(root.path()).unwrap(),
        };
        lease.revalidate().unwrap();
        root.write("late-foreign.jar", b"foreign");
        assert!(lease
            .change_sentinel
            .wait_until_dirty(std::time::Duration::from_secs(2)));
        assert!(lease.revalidate().is_err());
    }

    #[test]
    fn final_fast_audit_rejects_late_unknown_entries_stickily() {
        let root = TestDirectory::new();
        root.write("mods/guard.jar", b"guard");
        let tree = desired(vec![exact("mods/guard.jar", b"guard")], &["mods"], &[]);
        let relative = RelativeManagedPath::new("mods/guard.jar").unwrap();
        let mut files = BTreeMap::new();
        files.insert(
            path_key("mods/guard.jar"),
            ImmutableManagedFile::open(root.path(), &relative).unwrap(),
        );
        let lease = launch_lease(&root, tree, files);
        for index in 0..64 {
            root.write(&format!("late-{index:02}.bin"), b"unknown");
        }

        assert!(lease
            .change_sentinel
            .wait_until_dirty(std::time::Duration::from_secs(2)));
        let error = lease.revalidate_fast().unwrap_err();
        assert!(
            error.contains("changed after its baseline audit"),
            "{error}"
        );
        assert!(
            lease.revalidate_fast().is_err(),
            "a signaled notification must remain sticky"
        );
    }

    #[test]
    fn rejects_case_mismatch_and_file_directory_type_mismatch() {
        let root = TestDirectory::new();
        root.write("Mods/guard.jar", b"guard");
        root.write("config", b"not a directory");
        let tree = desired(
            vec![
                exact("mods/guard.jar", b"guard"),
                exact("config/project.toml", b"config"),
            ],
            &["mods", "config"],
            &[],
        );

        let audit = audit_instance_directory(root.path(), &tree).unwrap();

        assert!(audit.unsafe_entries.contains(&UnsafeEntry {
            path: "Mods".into(),
            kind: UnsafeEntryKind::CaseMismatch,
        }));
        assert!(audit.unsafe_entries.contains(&UnsafeEntry {
            path: "config".into(),
            kind: UnsafeEntryKind::ExpectedDirectoryIsFile,
        }));
    }

    #[test]
    fn hard_link_is_never_accepted_as_exact_or_unknown() {
        let root = TestDirectory::new();
        root.write("source.bin", b"guard");
        root.directory("mods");
        if fs::hard_link(
            root.path().join("source.bin"),
            root.path().join("mods/guard.jar"),
        )
        .is_err()
        {
            return;
        }
        let tree = desired(
            vec![exact("mods/guard.jar", b"guard")],
            &["mods"],
            &["source.bin"],
        );

        let audit = audit_instance_directory(root.path(), &tree).unwrap();

        assert!(audit.unsafe_entries.contains(&UnsafeEntry {
            path: "mods/guard.jar".into(),
            kind: UnsafeEntryKind::UnsafeRegularFile,
        }));
        assert!(audit.verified_exact.is_empty());
    }

    #[test]
    fn symlink_is_never_followed() {
        let root = TestDirectory::new();
        root.write("target.bin", b"guard");
        root.directory("mods");
        let link = root.path().join("mods/guard.jar");
        if !create_file_symlink(root.path().join("target.bin"), &link) {
            return;
        }
        let tree = desired(
            vec![exact("mods/guard.jar", b"guard")],
            &["mods"],
            &["target.bin"],
        );

        let audit = audit_instance_directory(root.path(), &tree).unwrap();

        assert!(audit.unsafe_entries.contains(&UnsafeEntry {
            path: "mods/guard.jar".into(),
            kind: UnsafeEntryKind::Symlink,
        }));
    }

    #[cfg(windows)]
    #[test]
    fn guarded_directory_cannot_be_swapped_while_enumerated() {
        let root = TestDirectory::new();
        root.directory("mods");
        let relative = RelativeManagedPath::new("mods").unwrap();
        let guard = GuardedDirectoryChain::open(root.path(), &relative).unwrap();
        let replacement = root.path().join("mods-replaced");

        assert!(fs::rename(root.path().join("mods"), &replacement).is_err());
        drop(guard);
        fs::rename(root.path().join("mods"), replacement).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn immutable_file_cannot_be_replaced_while_hashed() {
        let root = TestDirectory::new();
        root.write("mods/guard.jar", b"guard");
        let relative = RelativeManagedPath::new("mods/guard.jar").unwrap();
        let file = ImmutableManagedFile::open(root.path(), &relative).unwrap();
        let replacement = root.path().join("mods/guard-replaced.jar");

        assert!(fs::rename(root.path().join("mods/guard.jar"), &replacement).is_err());
        drop(file);
        fs::rename(root.path().join("mods/guard.jar"), replacement).unwrap();
    }

    #[cfg(unix)]
    fn create_file_symlink(target: PathBuf, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn create_file_symlink(target: PathBuf, link: &Path) -> bool {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }
}
