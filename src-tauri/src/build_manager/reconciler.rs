use super::{
    managed_fs::{GuardedDirectoryChain, ImmutableManagedFile, RelativeManagedPath},
    release::{FilePolicy, ManifestFile, ReleaseManifest},
    types::{BuildChannel, PresetId},
};
#[cfg(test)]
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

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
                &desired,
                Some(UnsafeEntryKind::Symlink),
            ));
        }
        Ok(metadata) if is_reparse_point(&metadata) => {
            return Ok(audit_unavailable_root(
                &desired,
                Some(UnsafeEntryKind::ReparsePoint),
            ));
        }
        Ok(_) => {
            return Ok(audit_unavailable_root(
                &desired,
                Some(UnsafeEntryKind::ExpectedDirectoryIsFile),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(audit_unavailable_root(&desired, None));
        }
        Err(error) => {
            return Err(format!(
                "Cannot inspect instance root {}: {error}",
                instance_root.display()
            ));
        }
    };
    let audit = audit_instance_directory(&instance_root, &desired)?;
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
    let mut audit = InstanceAudit::default();
    let mut encountered = BTreeSet::new();

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
                scan_directory(
                    instance_root,
                    None,
                    &root_guard,
                    desired,
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
    instance_root: &Path,
    relative_parent: Option<&RelativeManagedPath>,
    directory_guard: &GuardedDirectoryChain,
    desired: &DesiredTree,
    encountered: &mut BTreeSet<String>,
    audit: &mut InstanceAudit,
) -> Result<(), String> {
    let guarded_path = directory_guard.leaf().path();
    let initial_names = sorted_directory_names(guarded_path)?;

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
                instance_root,
                Some(&managed_relative),
                &child_guard,
                desired,
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
            DesiredFilePolicy::Exact => match hash_exact_file(instance_root, expected) {
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
            },
        }
    }
    if sorted_directory_names(guarded_path)? != initial_names {
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

fn hash_exact_file(
    instance_root: &Path,
    expected: &DesiredFile,
) -> Result<Option<ModifiedKind>, HashFailure> {
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

fn sorted_directory_names(path: &Path) -> Result<Vec<std::ffi::OsString>, String> {
    let mut names = fs::read_dir(path)
        .map_err(|error| {
            format!(
                "Cannot enumerate managed directory {}: {error}",
                path.display()
            )
        })?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            format!(
                "Cannot enumerate managed directory {}: {error}",
                path.display()
            )
        })?;
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

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("fragment-reconciler-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, relative: &str, bytes: &[u8]) {
            let path = self
                .0
                .join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let mut file = fs::File::create(path).unwrap();
            file.write_all(bytes).unwrap();
        }

        fn directory(&self, relative: &str) {
            fs::create_dir_all(
                self.0
                    .join(relative.replace('/', std::path::MAIN_SEPARATOR_STR)),
            )
            .unwrap();
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
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
