use super::{
    contracts::{validate_manifest_path, RuntimeFile, RuntimeLock},
    storage::{
        inspect_existing_ancestors, open_or_create_regular_single_link, open_regular_single_link,
    },
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, OpenOptions},
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

#[derive(Debug, Clone)]
pub struct RuntimeInstallation {
    pub generation: PathBuf,
    pub image: PathBuf,
    pub java: PathBuf,
    pub java_console: PathBuf,
    pub runtime_lock_sha256: String,
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

pub fn install_runtime(
    install_root: &Path,
    archive_path: &Path,
    runtime_lock_sha256: &str,
    lock: &RuntimeLock,
) -> Result<RuntimeInstallation, String> {
    validate_sha256(runtime_lock_sha256)?;
    lock.validate()?;
    verify_archive(archive_path, lock)?;

    let java_root = install_root.join("runtime").join("java");
    inspect_existing_ancestors(&java_root)?;
    fs::create_dir_all(&java_root)
        .map_err(|error| format!("Cannot create managed Java runtime root: {error}"))?;
    inspect_existing_ancestors(&java_root)?;
    validate_runtime_directory(&java_root, "Java runtime root")?;

    // The lock is deliberately acquired before inspecting or mutating a generation. A second
    // launcher process must always revalidate the winning generation instead of trusting that a
    // successful rename by the first process implies valid contents.
    let _runtime_guard = acquire_runtime_lock(&java_root, runtime_lock_sha256)?;
    validate_runtime_directory(&java_root, "Java runtime root")?;

    let generations = java_root.join("generations");
    inspect_existing_ancestors(&generations)?;
    fs::create_dir_all(&generations)
        .map_err(|error| format!("Cannot create Java runtime generations: {error}"))?;
    inspect_existing_ancestors(&generations)?;
    validate_runtime_directory(&generations, "Java runtime generations")?;

    // Only fully signed, fully audited staging trees can be identified as ours after a crash.
    // Incomplete or suspicious .staging-* entries are retained rather than recursively removed.
    cleanup_completed_staging(&java_root, runtime_lock_sha256, lock)?;

    let generation = generations.join(runtime_lock_sha256);
    match fs::symlink_metadata(&generation) {
        Ok(_) if validate_generation(&generation, runtime_lock_sha256, lock).is_ok() => {
            return installation(generation, runtime_lock_sha256, lock);
        }
        Ok(_) => {
            validate_runtime_directory(&generation, "invalid Java generation")?;
            let quarantine_root = java_root.join("quarantine");
            inspect_existing_ancestors(&quarantine_root)?;
            fs::create_dir_all(&quarantine_root)
                .map_err(|error| format!("Cannot create Java quarantine: {error}"))?;
            inspect_existing_ancestors(&quarantine_root)?;
            validate_runtime_directory(&quarantine_root, "Java quarantine")?;

            let quarantine =
                quarantine_root.join(format!("{runtime_lock_sha256}-{}", Uuid::new_v4()));
            fs::rename(&generation, &quarantine)
                .map_err(|error| format!("Cannot quarantine invalid Java generation: {error}"))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("Cannot inspect Java generation: {error}")),
    }

    validate_runtime_directory(&java_root, "Java runtime root")?;
    validate_runtime_directory(&generations, "Java runtime generations")?;
    let staging = java_root.join(format!(".staging-{}", Uuid::new_v4()));
    fs::create_dir(&staging)
        .map_err(|error| format!("Cannot create Java extraction staging: {error}"))?;
    validate_runtime_directory(&staging, "Java extraction staging")?;
    let image = staging.join("image");
    fs::create_dir(&image)
        .map_err(|error| format!("Cannot create Java extraction image: {error}"))?;
    validate_runtime_directory(&image, "Java extraction image")?;

    let build_result = (|| -> Result<(), String> {
        extract_archive(archive_path, &image, lock)?;
        audit_runtime_tree(&image, lock)?;
        write_marker(&staging, runtime_lock_sha256, lock)?;
        // Validate through the exact same path used for an already installed generation before
        // making the directory visible as immutable state.
        validate_generation(&staging, runtime_lock_sha256, lock)
    })();
    if let Err(error) = build_result {
        // A partial extraction has no signed ownership proof, so it is retained for a later
        // operator cleanup instead of risking deletion of an attacker-injected/foreign tree.
        let _ = remove_valid_staging(&staging, runtime_lock_sha256, lock);
        return Err(error);
    }

    validate_runtime_directory(&generations, "Java runtime generations")?;
    if let Err(rename_error) = fs::rename(&staging, &generation) {
        // A concurrent winner (or a process that started with an older launcher) is acceptable
        // only after a complete marker and runtime-tree revalidation.
        if validate_generation(&generation, runtime_lock_sha256, lock).is_ok() {
            let _ = remove_valid_staging(&staging, runtime_lock_sha256, lock);
        } else {
            let _ = remove_valid_staging(&staging, runtime_lock_sha256, lock);
            return Err(format!(
                "Cannot atomically commit Java generation and no valid concurrent winner exists: {rename_error}"
            ));
        }
    }

    validate_generation(&generation, runtime_lock_sha256, lock)?;
    installation(generation, runtime_lock_sha256, lock)
}

fn installation(
    generation: PathBuf,
    runtime_lock_sha256: &str,
    lock: &RuntimeLock,
) -> Result<RuntimeInstallation, String> {
    // Do not let a caller receive paths derived from a generation that changed between the
    // install/audit phase and construction of the launch command.
    validate_generation(&generation, runtime_lock_sha256, lock)?;
    let image = generation.join("image");
    validate_runtime_directory(&generation, "Java generation")?;
    validate_runtime_directory(&image, "Java runtime image")?;

    let java = image.join(path_from_manifest(&lock.java.executable));
    let java_console = image.join(path_from_manifest(&lock.java.console_executable));
    verify_runtime_entrypoint(&java, &lock.java.executable, lock)?;
    verify_runtime_entrypoint(&java_console, &lock.java.console_executable, lock)?;

    // Repeat the root checks after opening and hashing both entrypoints. This is intentionally
    // immediately before returning the paths to the launch layer.
    validate_runtime_directory(&generation, "Java generation")?;
    validate_runtime_directory(&image, "Java runtime image")?;
    Ok(RuntimeInstallation {
        generation,
        image,
        java,
        java_console,
        runtime_lock_sha256: runtime_lock_sha256.to_owned(),
    })
}

fn verify_archive(path: &Path, lock: &RuntimeLock) -> Result<(), String> {
    let mut file = open_regular_single_link(path, false)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("Cannot inspect managed Java archive: {error}"))?;
    if metadata.len() != lock.java.archive.size {
        return Err("Managed Java archive size does not match runtime lock".into());
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("Cannot rewind managed Java archive: {error}"))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("Cannot hash managed Java archive: {error}"))?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    if format!("{:x}", hash.finalize()) != lock.java.archive.sha256 {
        return Err("Managed Java archive SHA-256 does not match runtime lock".into());
    }
    Ok(())
}

fn extract_archive(archive_path: &Path, image: &Path, lock: &RuntimeLock) -> Result<(), String> {
    let file = open_regular_single_link(archive_path, false)?;
    let mut archive =
        ZipArchive::new(file).map_err(|error| format!("Managed Java ZIP is invalid: {error}"))?;
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
            return Err(format!(
                "Encrypted Java ZIP entry is forbidden: {}",
                entry.name()
            ));
        }
        if !entry.name().starts_with(&prefix) {
            return Err(format!(
                "Java ZIP entry is outside stripPrefix: {}",
                entry.name()
            ));
        }
        let relative = entry.name()[prefix.len()..].trim_end_matches('/');
        validate_entry_mode(&entry)?;
        if entry.is_dir() {
            if !relative.is_empty() && !expected_directories.contains(relative) {
                return Err(format!("Unexpected Java ZIP directory: {relative}"));
            }
            continue;
        }
        if !entry.is_file() || relative.is_empty() {
            return Err(format!("Unsupported Java ZIP entry: {}", entry.name()));
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
            return Err(format!("Java ZIP metadata mismatch: {relative}"));
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

    for (index, relative, expected_file) in files {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("Cannot reopen Java ZIP entry {relative}: {error}"))?;
        let destination = image.join(path_from_manifest(&relative));
        if let Some(parent) = destination.parent() {
            inspect_existing_ancestors(parent)?;
            fs::create_dir_all(parent)
                .map_err(|error| format!("Cannot create Java runtime directory: {error}"))?;
            inspect_existing_ancestors(parent)?;
        }
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination)
            .map_err(|error| format!("Cannot create Java runtime file {relative}: {error}"))?;
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
                return Err(format!(
                    "Java runtime file exceeded signed size: {relative}"
                ));
            }
            hash.update(&buffer[..read]);
            output
                .write_all(&buffer[..read])
                .map_err(|error| format!("Cannot write Java runtime file {relative}: {error}"))?;
        }
        output
            .sync_all()
            .map_err(|error| format!("Cannot flush Java runtime file {relative}: {error}"))?;
        if written != expected_file.size || format!("{:x}", hash.finalize()) != expected_file.sha256
        {
            return Err(format!("Java runtime file hash/size mismatch: {relative}"));
        }
    }
    Ok(())
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
    generation: &Path,
    runtime_lock_sha256: &str,
    lock: &RuntimeLock,
) -> Result<(), String> {
    let marker = RuntimeGenerationMarker {
        schema_version: 1,
        runtime_lock_sha256: runtime_lock_sha256.to_owned(),
        runtime_id: lock.id.clone(),
        archive_sha256: lock.java.archive.sha256.clone(),
        file_count: lock.java.files.len(),
    };
    let bytes = serde_json::to_vec_pretty(&marker)
        .map_err(|error| format!("Cannot serialize Java generation marker: {error}"))?;
    let path = generation.join("generation.json");
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("Cannot create Java generation marker: {error}"))?;
    file.write_all(&bytes)
        .map_err(|error| format!("Cannot write Java generation marker: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("Cannot flush Java generation marker: {error}"))
}

fn acquire_runtime_lock(java_root: &Path, runtime_lock_sha256: &str) -> Result<fs::File, String> {
    let lock_root = java_root.join("locks");
    inspect_existing_ancestors(&lock_root)?;
    fs::create_dir_all(&lock_root)
        .map_err(|error| format!("Cannot create Java runtime lock directory: {error}"))?;
    inspect_existing_ancestors(&lock_root)?;
    validate_runtime_directory(&lock_root, "Java runtime lock directory")?;

    let path = lock_root.join(format!("{runtime_lock_sha256}.lock"));
    let file = open_or_create_regular_single_link(&path)
        .map_err(|error| format!("Cannot open Java runtime lock: {error}"))?;
    let started = Instant::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => break,
            Err(_) if started.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                return Err(format!(
                    "Java runtime generation is locked by another launcher process: {error}"
                ));
            }
        }
    }

    validate_runtime_directory(java_root, "Java runtime root")?;
    validate_runtime_directory(&lock_root, "Java runtime lock directory")?;
    Ok(file)
}

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
        let value = serde_json::json!({
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
        let lock = RuntimeLock::parse_and_validate(&serde_json::to_vec(&value).unwrap()).unwrap();
        (archive_path, lock, runtime_hash)
    }

    #[test]
    fn installs_and_reaudits_an_immutable_runtime_generation() {
        let (archive, lock, runtime_hash) = fixture(None);
        let install_root = archive.parent().unwrap().join("install");
        let installed = install_runtime(&install_root, &archive, &runtime_hash, &lock).unwrap();
        assert_eq!(fs::read(installed.java_console).unwrap(), b"java-console");
        assert_eq!(fs::read(installed.java).unwrap(), b"java-window");
        assert!(install_runtime(&install_root, &archive, &runtime_hash, &lock).is_ok());
        let _ = fs::remove_dir_all(archive.parent().unwrap());
    }

    #[test]
    fn rejects_unsigned_extra_and_traversal_entries() {
        let (archive, lock, runtime_hash) =
            fixture(Some(("jdk-25.0.3+9-jre/bin/evil.dll", b"evil")));
        let install_root = archive.parent().unwrap().join("install");
        assert!(install_runtime(&install_root, &archive, &runtime_hash, &lock).is_err());
        let _ = fs::remove_dir_all(archive.parent().unwrap());

        let (archive, lock, runtime_hash) =
            fixture(Some(("jdk-25.0.3+9-jre/../escape.dll", b"evil")));
        let install_root = archive.parent().unwrap().join("install");
        assert!(install_runtime(&install_root, &archive, &runtime_hash, &lock).is_err());
        let _ = fs::remove_dir_all(archive.parent().unwrap());
    }

    #[test]
    fn serializes_concurrent_installers_and_revalidates_the_winner() {
        let (archive, lock, runtime_hash) = fixture(None);
        let fixture_root = archive.parent().unwrap().to_path_buf();
        let install_root = fixture_root.join("install");
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
                install_runtime(&install_root, &archive, &runtime_hash, &lock)
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
        let installed = install_runtime(&install_root, &archive, &runtime_hash, &lock).unwrap();
        let marker = installed.generation.join("generation.json");
        let alias = fixture_root.join("marker-hardlink.json");
        fs::hard_link(&marker, &alias).unwrap();
        assert!(validate_generation(&installed.generation, &runtime_hash, &lock).is_err());
        fs::remove_file(alias).unwrap();

        fs::write(
            &marker,
            vec![b' '; MAX_GENERATION_MARKER_BYTES as usize + 1],
        )
        .unwrap();
        let error = validate_generation(&installed.generation, &runtime_hash, &lock).unwrap_err();
        assert!(error.contains("oversized"));
        let _ = fs::remove_dir_all(fixture_root);
    }

    #[test]
    fn foreign_or_incomplete_staging_is_retained() {
        let (archive, lock, runtime_hash) = fixture(None);
        let fixture_root = archive.parent().unwrap().to_path_buf();
        let install_root = fixture_root.join("install");
        let installed = install_runtime(&install_root, &archive, &runtime_hash, &lock).unwrap();
        let java_root = install_root.join("runtime/java");
        let staging = java_root.join(format!(".staging-{}", Uuid::new_v4()));
        fs::rename(&installed.generation, &staging).unwrap();
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
        let installed = install_runtime(&install_root, &archive, &runtime_hash, &lock).unwrap();
        let java_root = install_root.join("runtime/java");
        let staging = java_root.join(format!(".staging-{}", Uuid::new_v4()));
        fs::rename(&installed.generation, &staging).unwrap();

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
        let installed = install_runtime(&install_root, &archive, &runtime_hash, &lock).unwrap();
        let real_image = installed.generation.join("image-real");
        fs::rename(&installed.image, &real_image).unwrap();
        let external = fixture_root.join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("untouched"), b"safe").unwrap();
        symlink(&external, &installed.image).unwrap();
        assert!(validate_generation(&installed.generation, &runtime_hash, &lock).is_err());
        assert!(remove_valid_staging(&installed.generation, &runtime_hash, &lock).is_err());
        assert_eq!(fs::read(external.join("untouched")).unwrap(), b"safe");
        assert!(installed.generation.exists());
        let _ = fs::remove_dir_all(fixture_root);
    }
}
