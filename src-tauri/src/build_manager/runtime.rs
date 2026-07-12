use super::{
    artifact_plan::PlannedJavaArchiveV2,
    cas::VerifiedCasObject,
    contracts::{validate_manifest_path, RuntimeLock},
    managed_fs::{
        move_managed_node_no_replace, open_or_create_lock_file, quarantine_node,
        ExclusiveManagedFile, FileIdentity, GuardedDirectoryChain, ImmutableManagedFile,
        ManagedFsError, ManagedLockFile, RelativeManagedPath,
    },
    storage::OwnedCasRoot,
};
#[cfg(test)]
use super::{
    contracts::RuntimeFile,
    storage::{inspect_existing_ancestors, open_regular_single_link},
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;
use zip::{CompressionMethod, ZipArchive};

const MAX_RUNTIME_ENTRIES: usize = 10_000;
const MAX_RUNTIME_FILE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RUNTIME_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_GENERATION_MARKER_BYTES: u64 = 16 * 1024;
const MAX_STAGING_CANDIDATES: usize = 32;

pub(super) struct RuntimeInstallation {
    generation: PathBuf,
    image: PathBuf,
    java: PathBuf,
    java_console: PathBuf,
    runtime_lock_sha256: String,
    binding: Option<RuntimeRootBinding>,
    _lease: Option<RuntimeInstallationLease>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeRootBinding {
    binding_nonce: Uuid,
    install_id: Uuid,
    install_root: PathBuf,
    install_root_identity: FileIdentity,
    objects_identity: FileIdentity,
}

/// Every signed Java file and every expected directory remains handle-leased for as long as the
/// capability is alive. On Windows the file handles deny writers/deletion; directory handles deny
/// renaming of the checked ancestors. Callers receive paths only together with this authority.
struct RuntimeInstallationLease {
    _install_root: GuardedDirectoryChain,
    _directories: Vec<GuardedDirectoryChain>,
    _marker: ImmutableManagedFile,
    _files: Vec<ImmutableManagedFile>,
}

impl fmt::Debug for RuntimeInstallation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeInstallation")
            .field("generation", &self.generation)
            .field("image", &self.image)
            .field("java", &self.java)
            .field("java_console", &self.java_console)
            .field("runtime_lock_sha256", &self.runtime_lock_sha256)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

impl PartialEq for RuntimeInstallation {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.image == other.image
            && self.java == other.java
            && self.java_console == other.java_console
            && self.runtime_lock_sha256 == other.runtime_lock_sha256
            && self.binding == other.binding
    }
}

impl Eq for RuntimeInstallation {}

#[cfg(test)]
impl Clone for RuntimeInstallation {
    fn clone(&self) -> Self {
        Self {
            generation: self.generation.clone(),
            image: self.image.clone(),
            java: self.java.clone(),
            java_console: self.java_console.clone(),
            runtime_lock_sha256: self.runtime_lock_sha256.clone(),
            binding: self.binding.clone(),
            // Test-only clones are intentionally not production launch authority. Native
            // revalidation reconstructs a fresh complete lease before any real spawn.
            _lease: None,
        }
    }
}

#[derive(Debug)]
pub(super) enum RuntimeInstallError {
    Rejected(String),
    DurabilityUnknown {
        destination: PathBuf,
        detail: String,
    },
}

impl fmt::Display for RuntimeInstallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(message) => formatter.write_str(message),
            Self::DurabilityUnknown {
                destination,
                detail,
            } => write!(
                formatter,
                "Java runtime state reached {}, but durability is unknown: {detail}",
                destination.display()
            ),
        }
    }
}

impl std::error::Error for RuntimeInstallError {}

impl From<String> for RuntimeInstallError {
    fn from(value: String) -> Self {
        Self::Rejected(value)
    }
}

impl From<&str> for RuntimeInstallError {
    fn from(value: &str) -> Self {
        Self::Rejected(value.to_owned())
    }
}

impl From<ManagedFsError> for RuntimeInstallError {
    fn from(value: ManagedFsError) -> Self {
        match value {
            ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination,
                detail,
            } => Self::DurabilityUnknown {
                destination,
                detail,
            },
            other => Self::Rejected(other.to_string()),
        }
    }
}

impl RuntimeRootBinding {
    fn capture(root: &OwnedCasRoot) -> Result<Self, String> {
        root.revalidate()?;
        let (binding_nonce, install_id, install_identity, objects_identity) = root.binding();
        let install_root = GuardedDirectoryChain::root_only(root.install_root())
            .map_err(|error| format!("Cannot bind Java install root: {error}"))?;
        if install_root.root_identity() != install_identity {
            return Err("Java install root differs from the owned CAS root".into());
        }
        Ok(Self {
            binding_nonce,
            install_id,
            install_root: install_root.root_path().to_path_buf(),
            install_root_identity: install_identity.clone(),
            objects_identity: objects_identity.clone(),
        })
    }

    fn validate_owned(&self, root: &OwnedCasRoot) -> Result<(), String> {
        root.revalidate()?;
        let (binding_nonce, install_id, install_identity, objects_identity) = root.binding();
        if binding_nonce != self.binding_nonce
            || install_id != self.install_id
            || install_identity != &self.install_root_identity
            || objects_identity != &self.objects_identity
            || root.install_root() != self.install_root
        {
            return Err("Java runtime binding differs from the live owned CAS root".into());
        }
        self.validate_current()
    }

    fn validate_current(&self) -> Result<(), String> {
        let root = GuardedDirectoryChain::root_only(&self.install_root)
            .map_err(|error| format!("Cannot revalidate Java install root: {error}"))?;
        root.revalidate()
            .map_err(|error| format!("Java install root changed: {error}"))?;
        if root.root_identity() != &self.install_root_identity {
            return Err("Java install root identity changed".into());
        }
        Ok(())
    }
}

impl RuntimeInstallation {
    pub(super) fn generation(&self) -> &Path {
        &self.generation
    }

    pub(super) fn image(&self) -> &Path {
        &self.image
    }

    pub(super) fn java(&self) -> &Path {
        &self.java
    }

    pub(super) fn java_console(&self) -> &Path {
        &self.java_console
    }

    pub(super) fn runtime_lock_sha256(&self) -> &str {
        &self.runtime_lock_sha256
    }

    #[cfg(test)]
    pub(super) fn synthetic(
        generation: PathBuf,
        image: PathBuf,
        java: PathBuf,
        java_console: PathBuf,
        runtime_lock_sha256: String,
    ) -> Self {
        Self {
            generation,
            image,
            java,
            java_console,
            runtime_lock_sha256,
            binding: None,
            _lease: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeGenerationMarker {
    schema_version: u8,
    runtime_lock_sha256: String,
    runtime_id: String,
    archive_sha256: String,
    file_count: usize,
}

/// Installs the exact Java archive declared by one sealed, root-bound artifact inventory.
///
/// Production callers cannot supply an archive path, runtime lock, or lock digest independently:
/// the CAS object is reopened through its opaque root capability and every value is derived from
/// the verified TUF inventory.
pub(super) fn install_runtime(
    owned_root: &OwnedCasRoot,
    archive_plan: &PlannedJavaArchiveV2<'_>,
    archive: &VerifiedCasObject,
) -> Result<RuntimeInstallation, RuntimeInstallError> {
    archive_plan.validate_root(owned_root)?;
    let lock = archive_plan.runtime_lock();
    let runtime_lock_sha256 = archive_plan.runtime_lock_sha256();
    if archive.sha256() != archive_plan.sha256()
        || archive.size() != archive_plan.size()
        || archive.sha256() != lock.java.archive.sha256
        || archive.size() != lock.java.archive.size
    {
        return Err("Verified CAS object is not the sealed Java runtime archive".into());
    }
    let mut archive = archive
        .open(owned_root)
        .map_err(|error| error.to_string())?;
    let installed =
        install_runtime_from_reader(owned_root, &mut archive, runtime_lock_sha256, lock)?;
    archive.revalidate().map_err(|error| {
        format!("Java runtime archive lease changed during installation: {error}")
    })?;
    archive_plan.validate_root(owned_root)?;
    Ok(installed)
}

#[cfg(test)]
fn install_runtime_from_path(
    install_root: &Path,
    archive_path: &Path,
    runtime_lock_sha256: &str,
    lock: &RuntimeLock,
) -> Result<RuntimeInstallation, String> {
    let selected = super::storage::select_install_directory(install_root)?;
    let owned_root = selected.into_owned_cas_root();
    let mut archive = fs::File::open(archive_path)
        .map_err(|error| format!("Cannot open test Java archive: {error}"))?;
    install_runtime_from_reader(&owned_root, &mut archive, runtime_lock_sha256, lock)
        .map_err(|error| error.to_string())
}

fn install_runtime_from_reader<R: Read + Seek>(
    owned_root: &OwnedCasRoot,
    archive: &mut R,
    runtime_lock_sha256: &str,
    lock: &RuntimeLock,
) -> Result<RuntimeInstallation, RuntimeInstallError> {
    validate_sha256(runtime_lock_sha256)?;
    lock.validate()?;
    verify_archive(archive, lock)?;

    owned_root.revalidate()?;
    let binding = RuntimeRootBinding::capture(owned_root)?;
    let install_root = owned_root.install_root();
    let java_root = relative("runtime/java")?;
    let java_guard = GuardedDirectoryChain::ensure(install_root, &java_root)?;
    java_guard.revalidate()?;

    // The lock is deliberately acquired before inspecting or mutating a generation. A second
    // launcher process must always revalidate the winning generation instead of trusting that a
    // successful rename by the first process implies valid contents.
    let runtime_guard = acquire_runtime_lock(install_root, runtime_lock_sha256)?;
    runtime_guard.revalidate()?;
    owned_root.revalidate()?;
    binding.validate_owned(owned_root)?;

    let generations = relative("runtime/java/generations")?;
    let quarantine = relative("runtime/java/quarantine")?;
    let generations_guard = GuardedDirectoryChain::ensure(install_root, &generations)?;
    let quarantine_guard = GuardedDirectoryChain::ensure(install_root, &quarantine)?;
    generations_guard.revalidate()?;
    quarantine_guard.revalidate()?;

    let generation = generations.join_component(runtime_lock_sha256)?;
    match audit_generation(&binding, &generation, runtime_lock_sha256, lock) {
        Ok(installed) => {
            runtime_guard.revalidate()?;
            binding.validate_owned(owned_root)?;
            return Ok(installed);
        }
        Err(audit_error) => match GuardedDirectoryChain::open(install_root, &generation) {
            Ok(existing) => {
                existing.revalidate()?;
                drop(existing);
                quarantine_node(install_root, generation.clone(), &quarantine)?;
                runtime_guard.revalidate()?;
                owned_root.revalidate()?;
            }
            Err(error) if managed_not_found(&error) => {}
            Err(_) => return Err(audit_error.into()),
        },
    }

    let staging = java_root.join_component(&format!(".staging-{}", Uuid::new_v4()))?;
    let image = staging.join_component("image")?;
    let staging_guard = GuardedDirectoryChain::create_exclusive(install_root, &staging)?;
    let image_guard = GuardedDirectoryChain::create_exclusive(install_root, &image)?;

    let mut directory_guards = Vec::new();
    let mut directories: Vec<_> = expected_directories(lock).into_iter().collect();
    directories.sort_by_key(|value| value.matches('/').count());
    for directory in directories {
        let managed = append_manifest(&image, &directory)?;
        directory_guards.push(GuardedDirectoryChain::ensure(install_root, &managed)?);
    }

    // These handles are deliberately exclusive only while bytes and directory entries are made
    // durable. They are dropped before the independent post-build audit reopens read-only leases.
    let extracted = extract_archive(archive, install_root, &image, lock)?;
    let marker = write_marker(install_root, &staging, runtime_lock_sha256, lock)?;
    for guard in &directory_guards {
        guard.sync_leaf()?;
    }
    image_guard.sync_leaf()?;
    staging_guard.sync_leaf()?;
    drop(marker);
    drop(extracted);
    drop(directory_guards);
    drop(image_guard);
    drop(staging_guard);

    // Exact source audit is followed by a handle-based, no-replace move and a second exact audit
    // at the destination. No path-only pre-audit is ever treated as publication authority.
    drop(audit_generation(
        &binding,
        &staging,
        runtime_lock_sha256,
        lock,
    )?);
    runtime_guard.revalidate()?;
    owned_root.revalidate()?;

    match move_managed_node_no_replace(install_root, staging.clone(), generation.clone()) {
        Ok(_) => {}
        Err(ManagedFsError::Conflict(_)) => {
            // A winner is accepted only through the same full lease-producing audit. The valid
            // staging tree is retained; deleting it by path after a collision would reintroduce
            // the very race this sink is designed to remove.
            let winner = audit_generation(&binding, &generation, runtime_lock_sha256, lock)?;
            runtime_guard.revalidate()?;
            binding.validate_owned(owned_root)?;
            return Ok(winner);
        }
        Err(error) => return Err(error.into()),
    }

    runtime_guard.revalidate()?;
    owned_root.revalidate()?;
    binding.validate_owned(owned_root)?;
    let installed = audit_generation(&binding, &generation, runtime_lock_sha256, lock)?;
    runtime_guard.revalidate()?;
    owned_root.revalidate()?;
    Ok(installed)
}

/// Reconstructs the opaque runtime capability only after a complete marker/tree/entrypoint audit.
/// Call this immediately before every processor or game spawn; a path-only value retained from an
/// earlier install operation is never launch authority on its own.
pub(super) fn revalidate_runtime_installation(
    installed: &RuntimeInstallation,
    lock: &RuntimeLock,
) -> Result<RuntimeInstallation, String> {
    validate_sha256(&installed.runtime_lock_sha256)?;
    lock.validate()?;
    let binding = installed
        .binding
        .as_ref()
        .ok_or_else(|| "Synthetic Java runtime is not native launch authority".to_string())?;
    if installed._lease.is_none() {
        return Err("Java runtime capability has no retained filesystem lease".into());
    }
    binding.validate_current()?;
    let generation = relative("runtime/java/generations")
        .and_then(|value| value.join_component(&installed.runtime_lock_sha256))
        .map_err(|error| error.to_string())?;
    if generation.join_to(&binding.install_root) != installed.generation {
        return Err("Java runtime capability is outside its root-bound generation".into());
    }
    let verified = audit_generation(binding, &generation, &installed.runtime_lock_sha256, lock)?;
    if &verified != installed {
        return Err("Java runtime capability paths differ from the verified generation".into());
    }
    binding.validate_current()?;
    Ok(verified)
}

/// Audits the one canonical Java generation beneath an already validated Fragment install.
/// Missing state is not an error, but an existing malformed/mismatched generation fails closed.
/// This is deliberately the only path used by the artifact availability scanner to claim that
/// the signed Java archive is no longer required.
pub(super) fn audit_installed_runtime_generation(
    owned_root: &OwnedCasRoot,
    runtime_lock_sha256: &str,
    lock: &RuntimeLock,
) -> Result<Option<RuntimeInstallation>, String> {
    owned_root.revalidate()?;
    validate_sha256(runtime_lock_sha256)?;
    lock.validate()?;
    let binding = RuntimeRootBinding::capture(owned_root)?;
    let generation = relative("runtime/java/generations")
        .and_then(|value| value.join_component(runtime_lock_sha256))
        .map_err(|error| error.to_string())?;
    let result = match audit_generation(&binding, &generation, runtime_lock_sha256, lock) {
        Ok(installed) => Some(installed),
        Err(_) => match GuardedDirectoryChain::open(owned_root.install_root(), &generation) {
            Ok(existing) => {
                // Ordinary content/marker damage is repairable. A linked/reparse/file generation
                // is not: it cannot be opened as a real guarded directory and fails closed below.
                existing
                    .revalidate()
                    .map_err(|error| format!("Unsafe Java generation: {error}"))?;
                None
            }
            Err(error) if managed_not_found(&error) => None,
            Err(error) => return Err(format!("Cannot inspect Java runtime generation: {error}")),
        },
    };
    owned_root.revalidate()?;
    Ok(result)
}

fn audit_generation(
    binding: &RuntimeRootBinding,
    generation_relative: &RelativeManagedPath,
    runtime_lock_sha256: &str,
    lock: &RuntimeLock,
) -> Result<RuntimeInstallation, String> {
    validate_sha256(runtime_lock_sha256)?;
    lock.validate()?;
    binding.validate_current()?;
    let root = &binding.install_root;
    let image_relative = generation_relative
        .join_component("image")
        .map_err(|error| error.to_string())?;

    let mut expected_by_directory = expected_directory_entries(&image_relative, lock)?;
    expected_by_directory.insert(
        generation_relative.as_str().to_owned(),
        HashSet::from(["image".to_owned(), "generation.json".to_owned()]),
    );

    let mut directory_paths = expected_by_directory.keys().cloned().collect::<Vec<_>>();
    directory_paths.sort();
    let mut directory_leases = Vec::with_capacity(directory_paths.len());
    let mut directory_expectations = Vec::with_capacity(directory_paths.len());
    let mut directory_relatives = Vec::with_capacity(directory_paths.len());
    for directory in directory_paths {
        let relative = relative(&directory).map_err(|error| error.to_string())?;
        let expected = expected_by_directory
            .get(&directory)
            .expect("directory key came from the map");
        directory_leases.push(audit_exact_directory(root, &relative, expected)?);
        directory_expectations.push(expected.clone());
        directory_relatives.push(relative);
    }

    let marker_relative = generation_relative
        .join_component("generation.json")
        .map_err(|error| error.to_string())?;
    let mut marker = ImmutableManagedFile::open(root, &marker_relative)
        .map_err(|error| format!("Cannot lease Java generation marker: {error}"))?;
    let marker_bytes = marker
        .read_bounded(MAX_GENERATION_MARKER_BYTES)
        .map_err(|error| format!("Cannot read Java generation marker: {error}"))?;
    let decoded: RuntimeGenerationMarker = serde_json::from_slice(&marker_bytes)
        .map_err(|error| format!("Java generation marker is invalid: {error}"))?;
    if decoded.schema_version != 1
        || decoded.runtime_lock_sha256 != runtime_lock_sha256
        || decoded.runtime_id != lock.id
        || decoded.archive_sha256 != lock.java.archive.sha256
        || decoded.file_count != lock.java.files.len()
    {
        return Err("Java generation marker does not match runtime lock".into());
    }

    let mut files = Vec::with_capacity(lock.java.files.len());
    for expected in &lock.java.files {
        let managed =
            append_manifest(&image_relative, &expected.path).map_err(|error| error.to_string())?;
        let mut leased = ImmutableManagedFile::open(root, &managed).map_err(|error| {
            format!("Cannot lease Java runtime file {}: {error}", expected.path)
        })?;
        let digest = leased
            .sha256(expected.size)
            .map_err(|error| format!("Cannot hash Java runtime file {}: {error}", expected.path))?;
        if digest.size != expected.size || digest.sha256 != expected.sha256 {
            return Err(format!(
                "Java runtime file hash/size mismatch: {}",
                expected.path
            ));
        }
        files.push(leased);
    }

    marker
        .revalidate()
        .map_err(|error| format!("Java generation marker changed: {error}"))?;
    for (directory, expected) in directory_leases.iter().zip(&directory_expectations) {
        audit_exact_directory_entries(directory, expected)?;
        directory
            .revalidate()
            .map_err(|error| format!("Java runtime directory changed: {error}"))?;
    }
    for file in &files {
        file.revalidate()
            .map_err(|error| format!("Java runtime file changed: {error}"))?;
    }
    // Snapshot chains deliberately deny writers only during the exact two-pass audit. Retaining
    // their root handles for the whole game would freeze unrelated launcher state under the same
    // install root. Replace them with rename-denying, write-compatible guarded chains; the exact
    // files themselves remain immutable leases, and every spawn performs a fresh two-pass audit.
    drop(directory_leases);
    let mut directory_leases = Vec::with_capacity(directory_relatives.len());
    for relative in &directory_relatives {
        let lease = GuardedDirectoryChain::open(root, relative)
            .map_err(|error| format!("Cannot retain Java runtime directory lease: {error}"))?;
        lease
            .revalidate()
            .map_err(|error| format!("Java runtime directory changed after audit: {error}"))?;
        directory_leases.push(lease);
    }
    let install_root_lease = GuardedDirectoryChain::root_only(root)
        .map_err(|error| format!("Cannot lease Java install root: {error}"))?;
    if install_root_lease.root_identity() != &binding.install_root_identity {
        return Err("Java install root identity differs from its owned CAS binding".into());
    }
    binding.validate_current()?;

    let generation = generation_relative.join_to(root);
    let image = image_relative.join_to(root);
    let java = append_manifest(&image_relative, &lock.java.executable)
        .map_err(|error| error.to_string())?
        .join_to(root);
    let java_console = append_manifest(&image_relative, &lock.java.console_executable)
        .map_err(|error| error.to_string())?
        .join_to(root);
    Ok(RuntimeInstallation {
        generation,
        image,
        java,
        java_console,
        runtime_lock_sha256: runtime_lock_sha256.to_owned(),
        binding: Some(binding.clone()),
        _lease: Some(RuntimeInstallationLease {
            _install_root: install_root_lease,
            _directories: directory_leases,
            _marker: marker,
            _files: files,
        }),
    })
}

fn relative(value: &str) -> Result<RelativeManagedPath, ManagedFsError> {
    RelativeManagedPath::new(value)
}

fn append_manifest(
    base: &RelativeManagedPath,
    manifest_path: &str,
) -> Result<RelativeManagedPath, ManagedFsError> {
    validate_manifest_path(manifest_path).map_err(ManagedFsError::InvalidPath)?;
    let mut joined = base.clone();
    for component in manifest_path.split('/') {
        joined = joined.join_component(component)?;
    }
    Ok(joined)
}

fn managed_not_found(error: &ManagedFsError) -> bool {
    matches!(
        error,
        ManagedFsError::Io { source, .. }
            if source.kind() == std::io::ErrorKind::NotFound
    )
}

fn expected_directory_entries(
    image: &RelativeManagedPath,
    lock: &RuntimeLock,
) -> Result<HashMap<String, HashSet<String>>, String> {
    let mut result = HashMap::<String, HashSet<String>>::new();
    result.entry(image.as_str().to_owned()).or_default();
    for file in &lock.java.files {
        validate_manifest_path(&file.path)?;
        let components = file.path.split('/').collect::<Vec<_>>();
        let mut parent = image.clone();
        for directory in &components[..components.len() - 1] {
            result
                .entry(parent.as_str().to_owned())
                .or_default()
                .insert((*directory).to_owned());
            parent = parent
                .join_component(directory)
                .map_err(|error| error.to_string())?;
            result.entry(parent.as_str().to_owned()).or_default();
        }
        result
            .entry(parent.as_str().to_owned())
            .or_default()
            .insert(
                components
                    .last()
                    .expect("a validated manifest path has a file name")
                    .to_string(),
            );
    }
    Ok(result)
}

fn audit_exact_directory(
    root: &Path,
    relative: &RelativeManagedPath,
    expected: &HashSet<String>,
) -> Result<GuardedDirectoryChain, String> {
    let guard = GuardedDirectoryChain::open_snapshot(root, relative)
        .map_err(|error| format!("Cannot lease Java runtime directory: {error}"))?;
    audit_exact_directory_entries(&guard, expected)?;
    guard
        .revalidate()
        .map_err(|error| format!("Java runtime directory changed during audit: {error}"))?;
    Ok(guard)
}

fn audit_exact_directory_entries(
    guard: &GuardedDirectoryChain,
    expected: &HashSet<String>,
) -> Result<(), String> {
    let mut actual = HashSet::new();
    let mut collision_keys = HashSet::new();
    for entry in fs::read_dir(guard.leaf().path())
        .map_err(|error| format!("Cannot enumerate Java runtime directory: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Cannot inspect Java runtime entry: {error}"))?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| "Java runtime directory contains a non-Unicode name".to_string())?
            .to_owned();
        let parsed = RelativeManagedPath::new(&name)
            .map_err(|error| format!("Java runtime entry name is unsafe: {error}"))?;
        if !collision_keys.insert(parsed.collision_key().to_owned()) || !actual.insert(name) {
            return Err("Java runtime directory contains a casing/collision duplicate".into());
        }
    }
    if &actual != expected {
        return Err(format!(
            "Java runtime directory inventory mismatch at {}",
            guard.leaf().path().display()
        ));
    }
    Ok(())
}

fn verify_archive<R: Read + Seek>(archive: &mut R, lock: &RuntimeLock) -> Result<(), String> {
    archive
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("Cannot rewind managed Java archive: {error}"))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    let mut total = 0_u64;
    loop {
        let read = archive
            .read(&mut buffer)
            .map_err(|error| format!("Cannot hash managed Java archive: {error}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| "Managed Java archive size overflowed".to_string())?;
        if total > lock.java.archive.size {
            return Err("Managed Java archive exceeds its signed size".into());
        }
        hash.update(&buffer[..read]);
    }
    if total != lock.java.archive.size
        || format!("{:x}", hash.finalize()) != lock.java.archive.sha256
    {
        return Err("Managed Java archive SHA-256 does not match runtime lock".into());
    }
    Ok(())
}

fn extract_archive<R: Read + Seek>(
    reader: &mut R,
    install_root: &Path,
    image: &RelativeManagedPath,
    lock: &RuntimeLock,
) -> Result<Vec<ImmutableManagedFile>, RuntimeInstallError> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("Cannot rewind managed Java ZIP: {error}"))?;
    let mut archive =
        ZipArchive::new(reader).map_err(|error| format!("Managed Java ZIP is invalid: {error}"))?;
    if archive.offset() != 0
        || archive.len() > MAX_RUNTIME_ENTRIES
        || archive
            .has_overlapping_files()
            .map_err(|error| format!("Cannot inspect overlapping Java ZIP entries: {error}"))?
    {
        return Err("Managed Java ZIP has an unsafe layout".into());
    }

    let expected: HashMap<_, _> = lock
        .java
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let expected_directories = expected_directories(lock);
    let prefix = format!("{}/", lock.java.archive.strip_prefix);
    let mut files = Vec::with_capacity(expected.len());
    let mut seen = HashSet::new();
    let mut total = 0_u64;

    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("Cannot read Java ZIP entry {index}: {error}"))?;
        validate_zip_entry_name(&entry)?;
        if entry.encrypted() {
            return Err(format!("Encrypted Java ZIP entry is forbidden: {}", entry.name()).into());
        }
        if !entry.name().starts_with(&prefix) {
            return Err(format!("Java ZIP entry is outside stripPrefix: {}", entry.name()).into());
        }
        let relative = entry.name()[prefix.len()..].trim_end_matches('/');
        validate_entry_mode(&entry)?;
        if entry.is_dir() {
            if !relative.is_empty() && !expected_directories.contains(relative) {
                return Err(format!("Unexpected Java ZIP directory: {relative}").into());
            }
            continue;
        }
        if !entry.is_file() || relative.is_empty() {
            return Err(format!("Unsupported Java ZIP entry: {}", entry.name()).into());
        }
        validate_manifest_path(relative)?;
        let expected_file = expected
            .get(relative)
            .ok_or_else(|| format!("Unexpected Java ZIP file: {relative}"))?;
        if !seen.insert(relative.to_owned())
            || entry.size() != expected_file.size
            || entry.size() > MAX_RUNTIME_FILE_BYTES
            || !matches!(
                entry.compression(),
                CompressionMethod::Stored | CompressionMethod::Deflated
            )
        {
            return Err(format!("Java ZIP metadata mismatch: {relative}").into());
        }
        total = total
            .checked_add(entry.size())
            .ok_or_else(|| "Java ZIP total size overflowed".to_string())?;
        if total > MAX_RUNTIME_TOTAL_BYTES {
            return Err("Java ZIP exceeds the extracted size limit".into());
        }
        files.push((index, relative.to_owned(), (*expected_file).clone()));
    }
    if seen.len() != expected.len() {
        return Err("Managed Java ZIP is missing signed runtime files".into());
    }

    let mut output_files = Vec::with_capacity(files.len());
    for (index, relative, expected_file) in files {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("Cannot reopen Java ZIP entry {relative}: {error}"))?;
        let destination = append_manifest(image, &relative)?;
        let mut output = ExclusiveManagedFile::create(install_root, destination)?;
        let mut hash = Sha256::new();
        let mut written = 0_u64;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let read = entry.read(&mut buffer).map_err(|error| {
                format!("Cannot decompress Java runtime file {relative}: {error}")
            })?;
            if read == 0 {
                break;
            }
            written = written
                .checked_add(read as u64)
                .ok_or_else(|| "Java extraction byte counter overflowed".to_string())?;
            if written > expected_file.size {
                return Err(format!("Java runtime file exceeded signed size: {relative}").into());
            }
            hash.update(&buffer[..read]);
            output
                .file_mut()
                .write_all(&buffer[..read])
                .map_err(|error| format!("Cannot write Java runtime file {relative}: {error}"))?;
        }
        if written != expected_file.size || format!("{:x}", hash.finalize()) != expected_file.sha256
        {
            return Err(format!("Java runtime file hash/size mismatch: {relative}").into());
        }
        output_files.push(output.seal_in_place()?);
    }
    Ok(output_files)
}

fn validate_zip_entry_name<R: Read>(entry: &zip::read::ZipFile<'_, R>) -> Result<(), String> {
    let name = entry.name();
    if entry.name_raw() != name.as_bytes()
        || !name.is_ascii()
        || name.contains('\\')
        || name.starts_with('/')
        || name.contains('\0')
        || name.nfc().collect::<String>() != name
        || name
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(format!("Unsafe Java ZIP entry name: {name}"));
    }
    Ok(())
}

fn validate_entry_mode<R: Read>(entry: &zip::read::ZipFile<'_, R>) -> Result<(), String> {
    if let Some(mode) = entry.unix_mode() {
        let file_type = mode & 0o170_000;
        let valid = if entry.is_dir() {
            file_type == 0 || file_type == 0o040_000
        } else {
            file_type == 0 || file_type == 0o100_000
        };
        if !valid {
            return Err(format!(
                "Special Java ZIP entry is forbidden: {}",
                entry.name()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
fn audit_runtime_tree(image: &Path, lock: &RuntimeLock) -> Result<(), String> {
    validate_runtime_directory(image, "Java runtime image")?;
    let expected: HashMap<_, _> = lock
        .java
        .files
        .iter()
        .map(|file| (file.path.to_lowercase(), file))
        .collect();
    let directories = expected_directories(lock);
    let mut seen = HashSet::new();
    audit_directory(image, image, &expected, &directories, &mut seen)?;
    if seen.len() != expected.len() {
        return Err("Managed Java generation is missing signed files".into());
    }
    validate_runtime_directory(image, "Java runtime image")
}

#[cfg(test)]
fn audit_directory(
    root: &Path,
    directory: &Path,
    expected: &HashMap<String, &RuntimeFile>,
    expected_directories: &HashSet<String>,
    seen: &mut HashSet<String>,
) -> Result<(), String> {
    validate_runtime_directory(directory, "Java runtime directory")?;
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("Cannot enumerate Java runtime generation: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Cannot inspect Java runtime entry: {error}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("Cannot inspect Java runtime entry: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("Java runtime generation contains a symlink".into());
        }
        #[cfg(windows)]
        if super::storage::is_windows_reparse_point(&metadata) {
            return Err("Java runtime generation contains a reparse point".into());
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "Java runtime entry escaped generation root".to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        validate_manifest_path(&relative)?;
        if metadata.is_dir() {
            if !expected_directories.contains(&relative) {
                return Err(format!("Unexpected Java runtime directory: {relative}"));
            }
            audit_directory(root, &path, expected, expected_directories, seen)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(format!("Unsupported Java runtime entry: {relative}"));
        }
        let key = relative.to_lowercase();
        let expected_file = expected
            .get(&key)
            .ok_or_else(|| format!("Unexpected Java runtime file: {relative}"))?;
        if expected_file.path != relative || !seen.insert(key) {
            return Err(format!(
                "Java runtime path casing/collision mismatch: {relative}"
            ));
        }
        verify_runtime_file(&path, expected_file)?;
    }
    validate_runtime_directory(directory, "Java runtime directory")
}

#[cfg(test)]
fn verify_runtime_file(path: &Path, expected: &RuntimeFile) -> Result<(), String> {
    let mut file = open_regular_single_link(path, false)?;
    if file
        .metadata()
        .map_err(|error| format!("Cannot inspect Java runtime file: {error}"))?
        .len()
        != expected.size
    {
        return Err(format!(
            "Java runtime file size mismatch: {}",
            expected.path
        ));
    }
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("Cannot hash Java runtime file: {error}"))?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    if format!("{:x}", hash.finalize()) != expected.sha256 {
        return Err(format!(
            "Java runtime file SHA-256 mismatch: {}",
            expected.path
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_generation(
    generation: &Path,
    runtime_lock_sha256: &str,
    lock: &RuntimeLock,
) -> Result<(), String> {
    validate_runtime_directory(generation, "Java generation")?;
    let image = generation.join("image");
    validate_runtime_directory(&image, "Java runtime image")?;
    validate_generation_layout(generation)?;

    let marker_path = generation.join("generation.json");
    let marker_file = open_regular_single_link(&marker_path, false)
        .map_err(|error| format!("Cannot open Java generation marker: {error}"))?;
    let mut marker_bytes = Vec::with_capacity(MAX_GENERATION_MARKER_BYTES as usize + 1);
    marker_file
        .take(MAX_GENERATION_MARKER_BYTES + 1)
        .read_to_end(&mut marker_bytes)
        .map_err(|error| format!("Cannot read Java generation marker: {error}"))?;
    if marker_bytes.len() as u64 > MAX_GENERATION_MARKER_BYTES {
        return Err("Java generation marker is oversized".into());
    }
    let marker: RuntimeGenerationMarker = serde_json::from_slice(&marker_bytes)
        .map_err(|error| format!("Java generation marker is invalid: {error}"))?;
    if marker.schema_version != 1
        || marker.runtime_lock_sha256 != runtime_lock_sha256
        || marker.runtime_id != lock.id
        || marker.archive_sha256 != lock.java.archive.sha256
        || marker.file_count != lock.java.files.len()
    {
        return Err("Java generation marker does not match runtime lock".into());
    }
    audit_runtime_tree(&image, lock)?;
    validate_generation_layout(generation)?;
    validate_runtime_directory(generation, "Java generation")?;
    validate_runtime_directory(&image, "Java runtime image")
}

fn write_marker(
    install_root: &Path,
    generation: &RelativeManagedPath,
    runtime_lock_sha256: &str,
    lock: &RuntimeLock,
) -> Result<ImmutableManagedFile, RuntimeInstallError> {
    let marker = RuntimeGenerationMarker {
        schema_version: 1,
        runtime_lock_sha256: runtime_lock_sha256.to_owned(),
        runtime_id: lock.id.clone(),
        archive_sha256: lock.java.archive.sha256.clone(),
        file_count: lock.java.files.len(),
    };
    let bytes = serde_json::to_vec_pretty(&marker)
        .map_err(|error| format!("Cannot serialize Java generation marker: {error}"))?;
    let path = generation.join_component("generation.json")?;
    let mut file = ExclusiveManagedFile::create(install_root, path)?;
    file.file_mut()
        .write_all(&bytes)
        .map_err(|error| format!("Cannot write Java generation marker: {error}"))?;
    file.seal_in_place().map_err(RuntimeInstallError::from)
}

fn acquire_runtime_lock(
    install_root: &Path,
    runtime_lock_sha256: &str,
) -> Result<ManagedLockFile, RuntimeInstallError> {
    let lock_root = relative("runtime/java/locks")?;
    let lock_root_guard = GuardedDirectoryChain::ensure(install_root, &lock_root)?;
    let path = lock_root.join_component(&format!("{runtime_lock_sha256}.lock"))?;
    let file = open_or_create_lock_file(install_root, &path)?;
    let started = Instant::now();
    loop {
        match file.file().try_lock_exclusive() {
            Ok(()) => break,
            Err(_) if started.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                return Err(format!(
                    "Java runtime generation is locked by another launcher process: {error}"
                )
                .into());
            }
        }
    }

    lock_root_guard.revalidate()?;
    file.revalidate()?;
    Ok(file)
}

#[cfg(test)]
fn validate_runtime_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{label} is not a real directory: {}",
            path.display()
        ));
    }
    #[cfg(windows)]
    if super::storage::is_windows_reparse_point(&metadata) {
        return Err(format!(
            "{label} is a Windows reparse point: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_generation_layout(generation: &Path) -> Result<(), String> {
    validate_runtime_directory(generation, "Java generation")?;
    let mut has_image = false;
    let mut has_marker = false;
    for entry in fs::read_dir(generation)
        .map_err(|error| format!("Cannot enumerate Java generation root: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("Cannot inspect Java generation root: {error}"))?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| "Java generation root contains a non-Unicode name".to_string())?
            .to_owned();
        match name.as_str() {
            "image" if !has_image => {
                validate_runtime_directory(&entry.path(), "Java runtime image")?;
                has_image = true;
            }
            "generation.json" if !has_marker => {
                // The handle-level regular/single-link check happens before marker contents are
                // read. Here we only enforce the exact generation envelope.
                has_marker = true;
            }
            _ => return Err(format!("Unexpected Java generation root entry: {name}")),
        }
    }
    if !has_image || !has_marker {
        return Err("Java generation root is incomplete".into());
    }
    validate_runtime_directory(generation, "Java generation")
}

#[cfg(test)]
fn verify_runtime_entrypoint(
    path: &Path,
    manifest_path: &str,
    lock: &RuntimeLock,
) -> Result<(), String> {
    let expected = lock
        .java
        .files
        .iter()
        .find(|file| file.path == manifest_path)
        .ok_or_else(|| {
            format!("Managed Java entrypoint is absent from runtime lock: {manifest_path}")
        })?;
    inspect_existing_ancestors(path)?;
    verify_runtime_file(path, expected)
}

#[cfg(test)]
fn cleanup_completed_staging(
    java_root: &Path,
    runtime_lock_sha256: &str,
    lock: &RuntimeLock,
) -> Result<(), String> {
    validate_runtime_directory(java_root, "Java runtime root")?;
    let mut candidates = 0_usize;
    for entry in fs::read_dir(java_root)
        .map_err(|error| format!("Cannot enumerate Java runtime staging: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Cannot inspect Java staging entry: {error}"))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(id) = name.strip_prefix(".staging-") else {
            continue;
        };
        if Uuid::parse_str(id).is_err() {
            continue;
        }
        candidates += 1;
        if candidates > MAX_STAGING_CANDIDATES {
            break;
        }

        let path = entry.path();
        // Validation proves this contains exactly the signed runtime image plus our bounded
        // marker. Everything incomplete, foreign, linked, or otherwise suspicious is retained.
        let _ = remove_valid_staging(&path, runtime_lock_sha256, lock);
    }
    validate_runtime_directory(java_root, "Java runtime root")
}

#[cfg(test)]
fn remove_valid_staging(
    path: &Path,
    runtime_lock_sha256: &str,
    lock: &RuntimeLock,
) -> Result<(), String> {
    validate_generation(path, runtime_lock_sha256, lock)?;
    let image = path.join("image");

    // Delete only paths named by the signed runtime lock. If any foreign entry appears, an
    // eventual remove_dir fails and the foreign entry is retained. Recursive deletion is never
    // used, so a reparse point cannot redirect cleanup into another tree.
    for expected in &lock.java.files {
        let file = image.join(path_from_manifest(&expected.path));
        inspect_existing_ancestors(&file)?;
        verify_runtime_file(&file, expected)?;
        fs::remove_file(&file)
            .map_err(|error| format!("Cannot remove signed Java staging file: {error}"))?;
    }

    let mut directories: Vec<_> = expected_directories(lock).into_iter().collect();
    directories.sort_by_key(|directory| std::cmp::Reverse(directory.matches('/').count()));
    for directory in directories {
        let directory = image.join(path_from_manifest(&directory));
        validate_runtime_directory(&directory, "Java staging directory")?;
        fs::remove_dir(&directory)
            .map_err(|error| format!("Cannot remove Java staging directory: {error}"))?;
    }
    validate_runtime_directory(&image, "Java runtime image")?;
    fs::remove_dir(&image).map_err(|error| format!("Cannot remove Java staging image: {error}"))?;

    let marker = path.join("generation.json");
    drop(open_regular_single_link(&marker, false)?);
    fs::remove_file(&marker)
        .map_err(|error| format!("Cannot remove Java staging marker: {error}"))?;
    validate_runtime_directory(path, "Java staging root")?;
    fs::remove_dir(path).map_err(|error| format!("Cannot remove Java staging root: {error}"))
}

fn expected_directories(lock: &RuntimeLock) -> HashSet<String> {
    let mut directories = HashSet::new();
    for file in &lock.java.files {
        let segments: Vec<_> = file.path.split('/').collect();
        for index in 1..segments.len() {
            directories.insert(segments[..index].join("/"));
        }
    }
    directories
}

#[cfg(test)]
fn path_from_manifest(path: &str) -> PathBuf {
    path.split('/').collect()
}

fn validate_sha256(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Runtime lock SHA-256 is invalid".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_manager::{
        artifact_plan::{ArtifactInventoryV2, ArtifactPlanV2},
        availability::VerifiedAvailabilityV2,
        cas::{cas_object_relative_path, verify_existing_object, ExpectedObject},
        contracts::{self, GameRuntimeLock},
        planner::tests::trusted,
        storage::select_install_directory,
        tuf::TrustedRelease,
        types::{BuildChannel, PresetId},
    };
    use std::{
        fs::File,
        sync::{Arc, Barrier},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };
    use zip::{write::SimpleFileOptions, ZipWriter};

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fragment-runtime-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn fixture(extra: Option<(&str, &[u8])>) -> (PathBuf, RuntimeLock, String) {
        let root = temp_root("fixture");
        fs::create_dir_all(&root).unwrap();
        let archive_path = root.join("temurin.zip");
        let java = b"java-console";
        let javaw = b"java-window";
        {
            let file = File::create(&archive_path).unwrap();
            let mut zip = ZipWriter::new(file);
            let options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            zip.add_directory("jdk-25.0.3+9-jre/bin/", options).unwrap();
            zip.start_file("jdk-25.0.3+9-jre/bin/java.exe", options)
                .unwrap();
            zip.write_all(java).unwrap();
            zip.start_file("jdk-25.0.3+9-jre/bin/javaw.exe", options)
                .unwrap();
            zip.write_all(javaw).unwrap();
            if let Some((name, bytes)) = extra {
                zip.start_file(name, options).unwrap();
                zip.write_all(bytes).unwrap();
            }
            zip.finish().unwrap();
        }
        let archive = fs::read(&archive_path).unwrap();
        let runtime_hash = format!("{:x}", Sha256::digest(b"runtime-lock"));
        let mut value = serde_json::json!({
            "schemaVersion": 1,
            "id": "temurin-jre-25.0.3+9-windows-x64-hotspot",
            "platform": "windows-x64",
            "java": {
                "major": 25,
                "architecture": "x64",
                "distribution": "eclipse-temurin",
                "imageType": "jre",
                "vm": "hotspot",
                "version": "25.0.3+9",
                "vendor": "Eclipse Temurin",
                "license": {
                    "spdx": "GPL-2.0-only WITH Classpath-exception-2.0",
                    "url": "https://openjdk.org/legal/gplv2+ce.html"
                },
                "archive": {
                    "url": "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.3%2B9/runtime.zip",
                    "checksumUrl": "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.3%2B9/runtime.zip.sha256.txt",
                    "signatureUrl": "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.3%2B9/runtime.zip.sig",
                    "signingKeyFingerprint": "3B04D753C9050D9A5D343F39843C48A565F8F04B",
                    "size": archive.len(),
                    "sha256": format!("{:x}", Sha256::digest(&archive)),
                    "format": "zip",
                    "stripPrefix": "jdk-25.0.3+9-jre"
                },
                "executable": "bin/javaw.exe",
                "consoleExecutable": "bin/java.exe",
                "files": [
                    { "path": "bin/java.exe", "size": java.len(), "sha256": format!("{:x}", Sha256::digest(java)) },
                    { "path": "bin/javaw.exe", "size": javaw.len(), "sha256": format!("{:x}", Sha256::digest(javaw)) }
                ]
            },
            "minecraft": {
                "version": "1.21.1",
                "versionManifestUrl": "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json",
                "versionJsonUrl": "https://piston-meta.mojang.com/1.21.1.json",
                "versionJsonSha1": "8344022e055c6c052047107a80e33d96c48e9fba"
            }
        });
        let game = contracts::tests::game_runtime_lock();
        value["minecraft"]["versionJsonUrl"] =
            game["provenance"]["minecraftVersionJson"]["url"].clone();
        value["minecraft"]["versionJsonSha1"] =
            game["provenance"]["minecraftVersionJson"]["sha1"].clone();
        let lock = RuntimeLock::parse_and_validate(&serde_json::to_vec(&value).unwrap()).unwrap();
        (archive_path, lock, runtime_hash)
    }

    fn trusted_for_runtime(lock: &RuntimeLock, runtime_hash: &str) -> TrustedRelease {
        let base = trusted('a', 1);
        let game_json = contracts::tests::verified_game_runtime_lock_for(
            runtime_hash,
            &lock.java.archive.sha256,
            &lock.extracted_tree_sha256().unwrap(),
        );
        let game_bytes = serde_json::to_vec(&game_json).unwrap();
        let game_lock = GameRuntimeLock::parse_and_validate(&game_bytes).unwrap();
        let mut manifest = base.manifest().clone();
        manifest.runtime.java.archive.size = lock.java.archive.size;
        manifest.runtime.java.archive.sha256 = lock.java.archive.sha256.clone();
        manifest.runtime.java.runtime_lock_sha256 = runtime_hash.to_owned();
        manifest.runtime.java.runtime_target = format!("runtime-windows-x64-{runtime_hash}.json");
        manifest.bind_runtime_lock(lock).unwrap();
        manifest.bind_game_runtime_lock(lock, &game_lock).unwrap();
        let mut evidence = base.evidence().clone();
        evidence.java_runtime_lock.name = manifest.runtime.java.runtime_target.clone();
        evidence.java_runtime_lock.sha256 = runtime_hash.to_owned();
        evidence.game_runtime_lock.length = game_bytes.len() as u64;
        TrustedRelease::new_for_test(
            base.channel(),
            base.current().clone(),
            manifest,
            lock.clone(),
            game_lock,
            base.tuf_root_version(),
            evidence,
        )
    }

    #[test]
    fn managed_durability_unknown_remains_a_typed_runtime_terminal_error() {
        let destination = PathBuf::from("runtime/java/generations/deadbeef");
        let mapped = RuntimeInstallError::from(ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination: destination.clone(),
            detail: "destination parent flush failed".into(),
        });
        assert!(matches!(
            mapped,
            RuntimeInstallError::DurabilityUnknown {
                destination: actual,
                detail
            } if actual == destination && detail.contains("parent flush")
        ));
    }

    #[test]
    fn sealed_java_plan_installs_only_its_root_bound_verified_cas_object() {
        let (archive_path, lock, runtime_hash) = fixture(None);
        let fixture_root = archive_path.parent().unwrap().to_path_buf();
        let install_path = fixture_root.join("install");
        let selected = select_install_directory(&install_path).unwrap();
        let install_id = selected.install_id();
        let owned_root = selected.into_owned_cas_root();
        let release = trusted_for_runtime(&lock, &runtime_hash);
        let inventory = ArtifactInventoryV2::build(
            &owned_root,
            &release,
            install_id,
            Uuid::new_v4(),
            BuildChannel::Stable,
            PresetId::Medium,
        )
        .unwrap();
        let availability = VerifiedAvailabilityV2::for_test(&inventory, [], false, false);
        let plan = ArtifactPlanV2::for_reconcile(&inventory, &availability, []).unwrap();
        let java_plan = plan.java_archive(&owned_root, &inventory).unwrap();

        let relative = cas_object_relative_path(&lock.java.archive.sha256).unwrap();
        let cached = relative.join_to(owned_root.managed_root());
        fs::create_dir_all(cached.parent().unwrap()).unwrap();
        fs::copy(&archive_path, &cached).unwrap();
        let expected = ExpectedObject {
            sha256: lock.java.archive.sha256.clone(),
            size: lock.java.archive.size,
        };
        let stale = verify_existing_object(&owned_root, &expected, 0).unwrap();
        fs::write(&cached, b"changed after verification").unwrap();
        assert!(install_runtime(&owned_root, &java_plan, &stale).is_err());

        fs::copy(&archive_path, &cached).unwrap();
        let foreign_path = fixture_root.join("foreign-install");
        let foreign_selected = select_install_directory(&foreign_path).unwrap();
        let foreign_root = foreign_selected.into_owned_cas_root();
        let foreign_cached = relative.join_to(foreign_root.managed_root());
        fs::create_dir_all(foreign_cached.parent().unwrap()).unwrap();
        fs::copy(&archive_path, &foreign_cached).unwrap();
        let foreign_object = verify_existing_object(&foreign_root, &expected, 0).unwrap();
        assert!(install_runtime(&owned_root, &java_plan, &foreign_object).is_err());

        let verified = verify_existing_object(&owned_root, &expected, 0).unwrap();
        let installed = install_runtime(&owned_root, &java_plan, &verified).unwrap();
        assert_eq!(fs::read(installed.java_console()).unwrap(), b"java-console");
        assert_eq!(fs::read(installed.java()).unwrap(), b"java-window");
        assert_eq!(installed.runtime_lock_sha256(), runtime_hash);

        drop(foreign_root);
        drop(owned_root);
        let _ = fs::remove_dir_all(fixture_root);
    }

    #[test]
    fn installs_and_reaudits_an_immutable_runtime_generation() {
        let (archive, lock, runtime_hash) = fixture(None);
        let install_root = archive.parent().unwrap().join("install");
        let installed =
            install_runtime_from_path(&install_root, &archive, &runtime_hash, &lock).unwrap();
        assert_eq!(fs::read(&installed.java_console).unwrap(), b"java-console");
        assert_eq!(fs::read(&installed.java).unwrap(), b"java-window");
        assert_eq!(
            revalidate_runtime_installation(&installed, &lock).unwrap(),
            installed
        );
        let mut forged = installed.clone();
        forged.java_console = forged.image.join("bin/forged.exe");
        assert!(revalidate_runtime_installation(&forged, &lock).is_err());
        let reinstall = install_runtime_from_path(&install_root, &archive, &runtime_hash, &lock);
        assert!(reinstall.is_ok(), "reinstall failed: {reinstall:?}");
        let _ = fs::remove_dir_all(archive.parent().unwrap());
    }

    #[test]
    fn pre_spawn_revalidation_rejects_a_reparse_generation_ancestor() {
        let (archive, lock, runtime_hash) = fixture(None);
        let fixture_root = archive.parent().unwrap().to_path_buf();
        let install_root = fixture_root.join("install");
        let installed =
            install_runtime_from_path(&install_root, &archive, &runtime_hash, &lock).unwrap();
        let generations = installed.generation.parent().unwrap().to_path_buf();
        let relocated = generations.with_file_name("generations-relocated");
        if fs::rename(&generations, &relocated).is_err() {
            // Windows production semantics: the retained ancestor/file leases deny the swap
            // before the pre-spawn audit even has to detect it.
            assert!(revalidate_runtime_installation(&installed, &lock).is_ok());
            drop(installed);
            let _ = fs::remove_dir_all(fixture_root);
            return;
        }

        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&relocated, &generations).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_dir(&relocated, &generations).is_ok();

        if linked {
            assert!(revalidate_runtime_installation(&installed, &lock).is_err());
            fs::remove_dir(&generations).unwrap();
        }
        fs::rename(&relocated, &generations).unwrap();
        assert!(revalidate_runtime_installation(&installed, &lock).is_ok());
        let _ = fs::remove_dir_all(fixture_root);
    }

    #[test]
    fn rejects_unsigned_extra_and_traversal_entries() {
        let (archive, lock, runtime_hash) =
            fixture(Some(("jdk-25.0.3+9-jre/bin/evil.dll", b"evil")));
        let install_root = archive.parent().unwrap().join("install");
        assert!(install_runtime_from_path(&install_root, &archive, &runtime_hash, &lock).is_err());
        let _ = fs::remove_dir_all(archive.parent().unwrap());

        let (archive, lock, runtime_hash) =
            fixture(Some(("jdk-25.0.3+9-jre/../escape.dll", b"evil")));
        let install_root = archive.parent().unwrap().join("install");
        assert!(install_runtime_from_path(&install_root, &archive, &runtime_hash, &lock).is_err());
        let _ = fs::remove_dir_all(archive.parent().unwrap());
    }

    #[test]
    fn serializes_concurrent_installers_and_revalidates_the_winner() {
        let (archive, lock, runtime_hash) = fixture(None);
        let fixture_root = archive.parent().unwrap().to_path_buf();
        let install_root = fixture_root.join("install");
        drop(super::super::storage::select_install_directory(&install_root).unwrap());
        let barrier = Arc::new(Barrier::new(4));
        let mut workers = Vec::new();
        for _ in 0..4 {
            let archive = archive.clone();
            let lock = lock.clone();
            let runtime_hash = runtime_hash.clone();
            let install_root = install_root.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                install_runtime_from_path(&install_root, &archive, &runtime_hash, &lock)
            }));
        }

        let generations: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("installer thread").unwrap().generation)
            .collect();
        assert!(generations.windows(2).all(|pair| pair[0] == pair[1]));
        assert!(validate_generation(&generations[0], &runtime_hash, &lock).is_ok());
        let _ = fs::remove_dir_all(fixture_root);
    }

    #[test]
    fn marker_is_bounded_and_must_be_a_single_link_regular_file() {
        let (archive, lock, runtime_hash) = fixture(None);
        let fixture_root = archive.parent().unwrap().to_path_buf();
        let install_root = fixture_root.join("install");
        let installed =
            install_runtime_from_path(&install_root, &archive, &runtime_hash, &lock).unwrap();
        let marker = installed.generation.join("generation.json");
        let alias = fixture_root.join("marker-hardlink.json");
        if fs::hard_link(&marker, &alias).is_ok() {
            assert!(validate_generation(&installed.generation, &runtime_hash, &lock).is_err());
            fs::remove_file(alias).unwrap();
        } else {
            assert!(revalidate_runtime_installation(&installed, &lock).is_ok());
        }

        let oversized = vec![b' '; MAX_GENERATION_MARKER_BYTES as usize + 1];
        if fs::write(&marker, &oversized).is_err() {
            assert!(revalidate_runtime_installation(&installed, &lock).is_ok());
            drop(installed);
            fs::write(&marker, &oversized).unwrap();
        }
        let generation = marker.parent().unwrap().to_path_buf();
        let error = validate_generation(&generation, &runtime_hash, &lock).unwrap_err();
        assert!(error.contains("oversized"));
        let _ = fs::remove_dir_all(fixture_root);
    }

    #[test]
    fn foreign_or_incomplete_staging_is_retained() {
        let (archive, lock, runtime_hash) = fixture(None);
        let fixture_root = archive.parent().unwrap().to_path_buf();
        let install_root = fixture_root.join("install");
        let installed =
            install_runtime_from_path(&install_root, &archive, &runtime_hash, &lock).unwrap();
        let java_root = install_root.join("runtime/java");
        let staging = java_root.join(format!(".staging-{}", Uuid::new_v4()));
        let generation = installed.generation.clone();
        drop(installed);
        fs::rename(&generation, &staging).unwrap();
        fs::write(staging.join("foreign.txt"), b"not launcher-owned").unwrap();

        cleanup_completed_staging(&java_root, &runtime_hash, &lock).unwrap();
        assert!(staging.exists());
        assert_eq!(
            fs::read(staging.join("foreign.txt")).unwrap(),
            b"not launcher-owned"
        );
        let _ = fs::remove_dir_all(fixture_root);
    }

    #[test]
    fn fully_valid_stale_staging_can_be_removed_without_following_links() {
        let (archive, lock, runtime_hash) = fixture(None);
        let fixture_root = archive.parent().unwrap().to_path_buf();
        let install_root = fixture_root.join("install");
        let installed =
            install_runtime_from_path(&install_root, &archive, &runtime_hash, &lock).unwrap();
        let java_root = install_root.join("runtime/java");
        let staging = java_root.join(format!(".staging-{}", Uuid::new_v4()));
        let generation = installed.generation.clone();
        drop(installed);
        fs::rename(&generation, &staging).unwrap();

        cleanup_completed_staging(&java_root, &runtime_hash, &lock).unwrap();
        assert!(!staging.exists());
        let _ = fs::remove_dir_all(fixture_root);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_linked_image_roots_and_cleanup_never_follows_links() {
        use std::os::unix::fs::symlink;

        let (archive, lock, runtime_hash) = fixture(None);
        let fixture_root = archive.parent().unwrap().to_path_buf();
        let install_root = fixture_root.join("install");
        let installed =
            install_runtime_from_path(&install_root, &archive, &runtime_hash, &lock).unwrap();
        let generation = installed.generation.clone();
        let image = installed.image.clone();
        drop(installed);
        let real_image = generation.join("image-real");
        fs::rename(&image, &real_image).unwrap();
        let external = fixture_root.join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("untouched"), b"safe").unwrap();
        symlink(&external, &image).unwrap();
        assert!(validate_generation(&generation, &runtime_hash, &lock).is_err());
        assert!(remove_valid_staging(&generation, &runtime_hash, &lock).is_err());
        assert_eq!(fs::read(external.join("untouched")).unwrap(), b"safe");
        assert!(generation.exists());
        let _ = fs::remove_dir_all(fixture_root);
    }
}
