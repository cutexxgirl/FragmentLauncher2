use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

const MAX_RELATIVE_UTF16: usize = 2_048;
const MAX_SEGMENT_UTF16: usize = 255;
pub(super) const MAX_MANAGED_PATH_COMPONENTS: usize = 64;
pub(super) const INSTANCE_MANAGED_PATH_PREFIX_COMPONENTS: usize = 2;
pub(super) const MAX_MANIFEST_PATH_COMPONENTS: usize =
    MAX_MANAGED_PATH_COMPONENTS - INSTANCE_MANAGED_PATH_PREFIX_COMPONENTS;
pub(super) const MAX_MANIFEST_PATH_BYTES: usize = 1_024;
/// Aggregate per-preset path topology budget: 200,000 files at average depth ten.
pub(super) const MAX_RELEASE_PATH_COMPONENTS: usize = 2_000_000;
pub(super) const MAX_RELEASE_MANAGED_PATHS: usize = 4_096;
pub(super) const MAX_MANAGED_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub(super) const MAX_MANAGED_RELEASE_BYTES: u64 = 2 * 1024 * 1024 * 1024 * 1024;
pub(super) const MAX_RECONCILE_MUTATIONS: usize = 400_000;
const MAX_ATOMIC_WRITE_BYTES: usize = 8 * 1024 * 1024;

pub(super) type ManagedFsResult<T> = Result<T, ManagedFsError>;

#[derive(Debug)]
pub(super) enum ManagedFsError {
    InvalidPath(String),
    UnsafeNode(String),
    Conflict(String),
    Unsupported(String),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    AppliedButDurabilityUnconfirmed {
        destination: PathBuf,
        detail: String,
    },
}

impl ManagedFsError {
    fn io(operation: &'static str, path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for ManagedFsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(message)
            | Self::UnsafeNode(message)
            | Self::Conflict(message)
            | Self::Unsupported(message) => formatter.write_str(message),
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} ({}): {source}", path.display()),
            Self::AppliedButDurabilityUnconfirmed {
                destination,
                detail,
            } => write!(
                formatter,
                "Managed rename reached {}, but directory durability could not be confirmed: {detail}",
                destination.display()
            ),
        }
    }
}

impl std::error::Error for ManagedFsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// A Windows-safe, manifest-style path relative to a managed root.
///
/// The serialized form always uses `/`. It deliberately rejects Windows aliases (ADS, trailing
/// dots/spaces and DOS device names) even on non-Windows hosts so manifests have one meaning.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct RelativeManagedPath {
    serialized: String,
    components: Vec<String>,
    collision_key: String,
}

impl RelativeManagedPath {
    pub(super) fn new(value: &str) -> ManagedFsResult<Self> {
        if value.is_empty() {
            return Err(ManagedFsError::InvalidPath(
                "Managed relative path is empty".into(),
            ));
        }
        if value.encode_utf16().count() > MAX_RELATIVE_UTF16 {
            return Err(ManagedFsError::InvalidPath(
                "Managed relative path exceeds the launcher limit".into(),
            ));
        }
        if value.starts_with('/')
            || value.ends_with('/')
            || value.contains("//")
            || value.contains('\\')
            || value.contains('\0')
        {
            return Err(ManagedFsError::InvalidPath(format!(
                "Managed path has an unsafe shape: {value:?}"
            )));
        }

        let components: Vec<_> = value.split('/').map(str::to_owned).collect();
        if components.len() > MAX_MANAGED_PATH_COMPONENTS {
            return Err(ManagedFsError::InvalidPath(
                "Managed relative path has too many components".into(),
            ));
        }
        for component in &components {
            validate_component(component)?;
        }

        Ok(Self {
            serialized: value.to_owned(),
            collision_key: components
                .iter()
                .map(|component| component.to_lowercase())
                .collect::<Vec<_>>()
                .join("/"),
            components,
        })
    }

    pub(super) fn as_str(&self) -> &str {
        &self.serialized
    }

    pub(super) fn collision_key(&self) -> &str {
        &self.collision_key
    }

    pub(super) fn to_path_buf(&self) -> PathBuf {
        self.components.iter().collect()
    }

    pub(super) fn join_to(&self, root: &Path) -> PathBuf {
        root.join(self.to_path_buf())
    }

    pub(super) fn parent(&self) -> Option<Self> {
        (self.components.len() > 1).then(|| {
            Self::new(&self.components[..self.components.len() - 1].join("/"))
                .expect("a validated path has a validated parent")
        })
    }

    pub(super) fn file_name(&self) -> &str {
        self.components
            .last()
            .expect("a managed relative path is non-empty")
    }

    pub(super) fn join_component(&self, component: &str) -> ManagedFsResult<Self> {
        validate_component(component)?;
        Self::new(&format!("{}/{component}", self.serialized))
    }

    pub(super) fn is_prefix_of(&self, other: &Self) -> bool {
        self.components.len() <= other.components.len()
            && self
                .components
                .iter()
                .zip(&other.components)
                .all(|(left, right)| left.to_lowercase() == right.to_lowercase())
    }
}

pub(super) fn validate_materializable_manifest_path(value: &str) -> ManagedFsResult<()> {
    if value.len() > MAX_MANIFEST_PATH_BYTES
        || value.split('/').count() > MAX_MANIFEST_PATH_COMPONENTS
    {
        return Err(ManagedFsError::InvalidPath(
            "Manifest path exceeds the materializable launcher bound".into(),
        ));
    }
    RelativeManagedPath::new(value).map(|_| ())
}

fn validate_component(component: &str) -> ManagedFsResult<()> {
    if component.is_empty() || component == "." || component == ".." {
        return Err(ManagedFsError::InvalidPath(format!(
            "Unsafe managed path component: {component:?}"
        )));
    }
    if component.encode_utf16().count() > MAX_SEGMENT_UTF16 {
        return Err(ManagedFsError::InvalidPath(format!(
            "Managed path component is too long: {component:?}"
        )));
    }
    if component.nfc().collect::<String>() != component {
        return Err(ManagedFsError::InvalidPath(format!(
            "Managed path component is not NFC-normalized: {component:?}"
        )));
    }
    if component.ends_with(['.', ' '])
        || component
            .chars()
            .any(|value| matches!(value, ':' | '<' | '>' | '"' | '|' | '?' | '*'))
        || component.chars().any(|value| value <= '\u{1f}')
    {
        return Err(ManagedFsError::InvalidPath(format!(
            "Managed path component has Windows-unsafe characters: {component:?}"
        )));
    }

    let stem = component
        .split_once('.')
        .map_or(component, |(stem, _)| stem)
        .trim_end_matches([' ', '.'])
        .to_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || is_numbered_device(&stem, "COM")
        || is_numbered_device(&stem, "LPT");
    if reserved {
        return Err(ManagedFsError::InvalidPath(format!(
            "Managed path uses a reserved Windows device name: {component:?}"
        )));
    }
    Ok(())
}

fn is_numbered_device(stem: &str, prefix: &str) -> bool {
    let Some(suffix) = stem.strip_prefix(prefix) else {
        return false;
    };
    matches!(
        suffix,
        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
    )
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct FileIdentity {
    pub(super) volume_serial_number: u64,
    pub(super) file_id: [u8; 16],
}

/// Handle-bound evidence for one resumable managed file at one instant.
///
/// Logical length and physical allocation are captured by the same `NodeInfo` query through the
/// retained no-follow file handle. The file and managed-root identities let callers reject stale
/// evidence after reopening a partial or selecting a different managed root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ManagedFileAllocationSnapshot {
    pub(super) identity: FileIdentity,
    pub(super) managed_root_identity: FileIdentity,
    pub(super) logical_size: u64,
    pub(super) allocated_size: u64,
}

impl ManagedFileAllocationSnapshot {
    pub(super) fn identity(&self) -> &FileIdentity {
        &self.identity
    }

    pub(super) fn managed_root_identity(&self) -> &FileIdentity {
        &self.managed_root_identity
    }

    pub(super) fn logical_size(&self) -> u64 {
        self.logical_size
    }

    pub(super) fn allocated_size(&self) -> u64 {
        self.allocated_size
    }
}

/// Hard limits for one recursive managed-directory removal.
///
/// `max_entries` includes the root directory and `max_depth` uses the root as depth zero. Bytes
/// are charged from the filesystem allocation size of every opened node, not merely logical file
/// lengths. The caller must choose limits from already-authorized workspace policy rather than
/// from the directory being removed. These limits bound the pre-mutation audited workload; they
/// are not a free-space or eventual physical-reclamation witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ManagedDirectoryRemovalLimits {
    pub(super) max_entries: usize,
    pub(super) max_allocated_bytes: u64,
    pub(super) max_depth: usize,
}

/// Snapshot of the namespace and allocation audited before destructive mutation.
///
/// `allocated_bytes` is never authority for current free space or proof that those bytes have
/// already been physically reclaimed. It may be consumed as sealed pre-move aggregate accounting
/// or reported after exact cleanup, but a detached/caller-constructed summary authorizes neither
/// a move nor a deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ManagedDirectoryRemovalSummary {
    pub(super) entries: usize,
    pub(super) allocated_bytes: u64,
    pub(super) max_depth: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ManagedNodeKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NodeInfo {
    pub(super) identity: FileIdentity,
    pub(super) kind: ManagedNodeKind,
    pub(super) attributes: u32,
    pub(super) reparse_tag: u32,
    pub(super) number_of_links: u32,
    pub(super) size: u64,
    pub(super) allocation_size: u64,
    pub(super) named_streams: u32,
    pub(super) case_sensitive_directory: bool,
}

impl NodeInfo {
    fn require_real_directory(&self, path: &Path) -> ManagedFsResult<()> {
        if self.kind != ManagedNodeKind::Directory || self.reparse_tag != 0 {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed directory is not a real directory: {}",
                path.display()
            )));
        }
        if self.case_sensitive_directory {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Case-sensitive managed directories are not supported: {}",
                path.display()
            )));
        }
        Ok(())
    }

    fn require_regular_single_link(&self, path: &Path) -> ManagedFsResult<()> {
        if self.kind != ManagedNodeKind::File || self.reparse_tag != 0 || self.number_of_links != 1
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed file is not a regular single-link file: {}",
                path.display()
            )));
        }
        Ok(())
    }
}

pub(super) struct GuardedDirectory {
    path: PathBuf,
    _handle: File,
    info: NodeInfo,
}

impl GuardedDirectory {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn info(&self) -> &NodeInfo {
        &self.info
    }

    fn open(path: &Path) -> ManagedFsResult<Self> {
        let handle = open_directory_nofollow(path, false)?;
        Self::from_handle(path, handle)
    }

    fn open_snapshot(path: &Path) -> ManagedFsResult<Self> {
        let handle = open_directory_snapshot_nofollow(path)?;
        Self::from_handle(path, handle)
    }

    fn from_handle(path: &Path, handle: File) -> ManagedFsResult<Self> {
        let info = node_info(&handle, path)?;
        info.require_real_directory(path)?;
        verify_handle_path(&handle, path)?;
        let stable_path = stable_handle_path(&handle, path)?;
        Ok(Self {
            path: stable_path,
            _handle: handle,
            info,
        })
    }

    fn open_child(&self, component: &str) -> ManagedFsResult<Self> {
        validate_component(component)?;
        let child = self.path.join(component);
        let opened = Self::open(&child)?;
        if opened.info.identity.volume_serial_number != self.info.identity.volume_serial_number {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed directory crossed a volume boundary: {}",
                child.display()
            )));
        }
        Ok(opened)
    }

    fn open_child_snapshot(&self, component: &str) -> ManagedFsResult<Self> {
        validate_component(component)?;
        let child = self.path.join(component);
        let opened = Self::open_snapshot(&child)?;
        if opened.info.identity.volume_serial_number != self.info.identity.volume_serial_number {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed snapshot directory crossed a volume boundary: {}",
                child.display()
            )));
        }
        Ok(opened)
    }

    fn sync_directory(&self) -> ManagedFsResult<()> {
        sync_directory_identity(&self.path, &self.info.identity)
    }
}

/// Holds every directory in a root-to-leaf chain. On Windows the handles intentionally omit
/// `FILE_SHARE_DELETE`, preventing the checked chain from being renamed while an operation runs.
pub(super) struct GuardedDirectoryChain {
    root: PathBuf,
    directories: Vec<GuardedDirectory>,
}

impl GuardedDirectoryChain {
    pub(super) fn root_only(root: &Path) -> ManagedFsResult<Self> {
        if !root.is_absolute() {
            return Err(ManagedFsError::InvalidPath(
                "Managed root must be absolute".into(),
            ));
        }
        let root = GuardedDirectory::open(root)?;
        Ok(Self {
            root: root.path.clone(),
            directories: vec![root],
        })
    }

    pub(super) fn open(root: &Path, relative: &RelativeManagedPath) -> ManagedFsResult<Self> {
        let mut chain = Self::root_only(root)?;
        for component in &relative.components {
            let child = chain.leaf().open_child(component)?;
            chain.directories.push(child);
        }
        Ok(chain)
    }

    /// Opens a read-only snapshot chain. On Windows these handles omit both share-write and
    /// share-delete so concurrent mutation of the audited directories is rejected by the OS.
    pub(super) fn root_snapshot(root: &Path) -> ManagedFsResult<Self> {
        if !root.is_absolute() {
            return Err(ManagedFsError::InvalidPath(
                "Managed root must be absolute".into(),
            ));
        }
        let root = GuardedDirectory::open_snapshot(root)?;
        Ok(Self {
            root: root.path.clone(),
            directories: vec![root],
        })
    }

    pub(super) fn open_snapshot(
        root: &Path,
        relative: &RelativeManagedPath,
    ) -> ManagedFsResult<Self> {
        let mut chain = Self::root_snapshot(root)?;
        for component in &relative.components {
            let child = chain.leaf().open_child_snapshot(component)?;
            chain.directories.push(child);
        }
        Ok(chain)
    }

    pub(super) fn ensure(root: &Path, relative: &RelativeManagedPath) -> ManagedFsResult<Self> {
        let mut chain = Self::root_only(root)?;
        for component in &relative.components {
            let child_path = chain.leaf().path.join(component);
            let (child, created) = match chain.leaf().open_child(component) {
                Ok(child) => (child, false),
                Err(ManagedFsError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    match fs::create_dir(&child_path) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                        Err(error) => {
                            return Err(ManagedFsError::io(
                                "Cannot create managed directory component",
                                &child_path,
                                error,
                            ));
                        }
                    }
                    (chain.leaf().open_child(component)?, true)
                }
                Err(error) => return Err(error),
            };
            if created {
                chain.leaf().sync_directory().map_err(|error| {
                    ManagedFsError::AppliedButDurabilityUnconfirmed {
                        destination: child_path.clone(),
                        detail: format!("created directory parent flush failed: {error}"),
                    }
                })?;
            }
            chain.directories.push(child);
        }
        Ok(chain)
    }

    /// Creates one previously-absent directory and immediately opens every ancestor plus the leaf
    /// through no-follow handles. Unlike `ensure`, a pre-existing random staging-name collision is
    /// rejected. Callers must still perform their exact content/identity audit before publication.
    pub(super) fn create_exclusive(
        root: &Path,
        relative: &RelativeManagedPath,
    ) -> ManagedFsResult<Self> {
        let parent_chain = Self::open_parent(root, relative)?;
        let path = relative.join_to(parent_chain.root_path());
        fs::create_dir(&path).map_err(|error| {
            ManagedFsError::io("Cannot create exclusive managed directory", &path, error)
        })?;
        let child = parent_chain.leaf().open_child(relative.file_name())?;
        parent_chain.leaf().sync_directory().map_err(|error| {
            ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: path.clone(),
                detail: format!("exclusive directory parent flush failed: {error}"),
            }
        })?;
        child.sync_directory().map_err(|error| {
            ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: path.clone(),
                detail: format!("new exclusive directory flush failed: {error}"),
            }
        })?;

        // Re-open as one complete root-to-leaf chain only after both durability barriers. The
        // parent_chain remains live until this succeeds, so the lexical parent cannot be swapped.
        let complete = Self::open(parent_chain.root_path(), relative)?;
        complete.revalidate()?;
        Ok(complete)
    }

    fn open_parent(root: &Path, relative: &RelativeManagedPath) -> ManagedFsResult<Self> {
        match relative.parent() {
            Some(parent) => Self::open(root, &parent),
            None => Self::root_only(root),
        }
    }

    fn open_parent_snapshot(root: &Path, relative: &RelativeManagedPath) -> ManagedFsResult<Self> {
        match relative.parent() {
            Some(parent) => Self::open_snapshot(root, &parent),
            None => Self::root_snapshot(root),
        }
    }

    pub(super) fn root_path(&self) -> &Path {
        &self.root
    }

    pub(super) fn root_identity(&self) -> &FileIdentity {
        &self
            .directories
            .first()
            .expect("a guarded chain always contains its root")
            .info
            .identity
    }

    pub(super) fn leaf(&self) -> &GuardedDirectory {
        self.directories
            .last()
            .expect("a guarded chain always contains its root")
    }

    /// Re-proves that every lexical directory still resolves to the exact handle-bound identity.
    /// This is needed on platforms where an open directory handle does not itself deny renames.
    pub(super) fn revalidate(&self) -> ManagedFsResult<()> {
        for directory in &self.directories {
            verify_handle_path(&directory._handle, &directory.path)?;
            let current = node_info(&directory._handle, &directory.path)?;
            current.require_real_directory(&directory.path)?;
            if current.identity != directory.info.identity
                || current.case_sensitive_directory != directory.info.case_sensitive_directory
            {
                return Err(ManagedFsError::UnsafeNode(format!(
                    "Managed directory identity changed: {}",
                    directory.path.display()
                )));
            }
        }
        Ok(())
    }

    pub(super) fn sync_leaf(&self) -> ManagedFsResult<()> {
        self.revalidate()?;
        self.leaf().sync_directory().map_err(|error| {
            ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: self.leaf().path().to_path_buf(),
                detail: format!("managed directory flush failed: {error}"),
            }
        })
    }
}

pub(super) fn ensure_directory_chain(
    root: &Path,
    relative: &RelativeManagedPath,
) -> ManagedFsResult<GuardedDirectoryChain> {
    GuardedDirectoryChain::ensure(root, relative)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FileDigest {
    pub(super) size: u64,
    pub(super) sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct FileDigests {
    pub(super) size: u64,
    pub(super) sha1: String,
    pub(super) sha256: String,
}

pub(super) struct ImmutableManagedFile {
    path: PathBuf,
    file: File,
    info: NodeInfo,
    _parent_chain: GuardedDirectoryChain,
}

impl ImmutableManagedFile {
    pub(super) fn open(root: &Path, relative: &RelativeManagedPath) -> ManagedFsResult<Self> {
        let parent_chain = GuardedDirectoryChain::open_parent(root, relative)?;
        let path = relative.join_to(parent_chain.root_path());
        let file = open_immutable_file_nofollow(&path)?;
        let info = node_info(&file, &path)?;
        info.require_regular_single_link(&path)?;
        verify_handle_path(&file, &path)?;
        if info.identity.volume_serial_number
            != parent_chain.leaf().info.identity.volume_serial_number
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed file crossed a volume boundary: {}",
                path.display()
            )));
        }
        Ok(Self {
            path,
            file,
            info,
            _parent_chain: parent_chain,
        })
    }

    pub(super) fn info(&self) -> &NodeInfo {
        &self.info
    }

    pub(super) fn revalidate(&self) -> ManagedFsResult<()> {
        self._parent_chain.revalidate()?;
        verify_handle_path(&self.file, &self.path)?;
        let current = node_info(&self.file, &self.path)?;
        current.require_regular_single_link(&self.path)?;
        if current.identity != self.info.identity || current.size != self.info.size {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Immutable managed file identity changed: {}",
                self.path.display()
            )));
        }
        Ok(())
    }

    pub(super) fn read_bounded(&mut self, limit: u64) -> ManagedFsResult<Vec<u8>> {
        if self.info.size > limit || self.info.size > usize::MAX as u64 {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed file exceeds the read limit: {}",
                self.path.display()
            )));
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|error| ManagedFsError::io("Cannot rewind managed file", &self.path, error))?;
        let mut bytes = Vec::with_capacity(self.info.size as usize);
        Read::by_ref(&mut self.file)
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| ManagedFsError::io("Cannot read managed file", &self.path, error))?;
        if bytes.len() as u64 != self.info.size {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed file size changed while it was read: {}",
                self.path.display()
            )));
        }
        Ok(bytes)
    }

    /// Cursor-independent bounded read for immutable leases shared across concurrent operations.
    pub(super) fn read_bounded_shared(&self, limit: u64) -> ManagedFsResult<Vec<u8>> {
        if self.info.size > limit || self.info.size > usize::MAX as u64 {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed file exceeds the read limit: {}",
                self.path.display()
            )));
        }
        let mut bytes = vec![0_u8; self.info.size as usize];
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let read = positional_read(
                &self.file,
                &mut bytes[offset..],
                u64::try_from(offset).expect("bounded file offset fits u64"),
            )
            .map_err(|error| ManagedFsError::io("Cannot read managed file", &self.path, error))?;
            if read == 0 {
                break;
            }
            offset += read;
        }
        bytes.truncate(offset);
        if bytes.len() as u64 != self.info.size {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed file size changed while it was read: {}",
                self.path.display()
            )));
        }
        Ok(bytes)
    }

    /// Streams this already leased, single-link source into a newly-created exclusive file.
    ///
    /// Both signed digests are calculated over the exact bytes that are written. The source and
    /// destination identities are checked again after EOF, so callers never need to materialize a
    /// potentially large CAS object in memory and never need to hard-link the shared CAS into a
    /// processor or instance workspace.
    pub(super) fn copy_to_exclusive(
        &mut self,
        destination: &mut ExclusiveManagedFile,
        limit: u64,
    ) -> ManagedFsResult<FileDigests> {
        if self.info.size > limit {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed file exceeds the copy limit: {}",
                self.path.display()
            )));
        }
        if self.info.identity == destination.info.identity {
            return Err(ManagedFsError::UnsafeNode(
                "Managed copy source and destination have the same filesystem identity".into(),
            ));
        }

        let destination_before = node_info(&destination.file, &destination.path)?;
        if destination_before.identity != destination.info.identity
            || destination_before.kind != ManagedNodeKind::File
            || destination_before.reparse_tag != 0
            || destination_before.number_of_links != 1
            || destination_before.size != 0
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed copy destination is not a fresh exclusive file: {}",
                destination.path.display()
            )));
        }

        self.file.seek(SeekFrom::Start(0)).map_err(|error| {
            ManagedFsError::io("Cannot rewind managed copy source", &self.path, error)
        })?;
        destination.file.seek(SeekFrom::Start(0)).map_err(|error| {
            ManagedFsError::io(
                "Cannot rewind managed copy destination",
                &destination.path,
                error,
            )
        })?;

        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let read = self.file.read(&mut buffer).map_err(|error| {
                ManagedFsError::io("Cannot read managed copy source", &self.path, error)
            })?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .ok_or_else(|| ManagedFsError::UnsafeNode("Managed copy size overflow".into()))?;
            if total > limit || total > self.info.size {
                return Err(ManagedFsError::UnsafeNode(format!(
                    "Managed copy source exceeded its signed size: {}",
                    self.path.display()
                )));
            }
            destination
                .file
                .write_all(&buffer[..read])
                .map_err(|error| {
                    ManagedFsError::io(
                        "Cannot write managed copy destination",
                        &destination.path,
                        error,
                    )
                })?;
            sha1.update(&buffer[..read]);
            sha256.update(&buffer[..read]);
        }
        if total != self.info.size {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed copy source size changed while it was read: {}",
                self.path.display()
            )));
        }

        verify_handle_path(&self.file, &self.path)?;
        let source_after = node_info(&self.file, &self.path)?;
        if source_after.identity != self.info.identity
            || source_after.size != self.info.size
            || source_after.kind != ManagedNodeKind::File
            || source_after.number_of_links != 1
            || source_after.reparse_tag != 0
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed copy source identity changed while it was read: {}",
                self.path.display()
            )));
        }
        verify_handle_path(&destination.file, &destination.path)?;
        let destination_after = node_info(&destination.file, &destination.path)?;
        if destination_after.identity != destination.info.identity
            || destination_after.identity == source_after.identity
            || destination_after.size != total
            || destination_after.kind != ManagedNodeKind::File
            || destination_after.number_of_links != 1
            || destination_after.reparse_tag != 0
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed copy destination identity changed while it was written: {}",
                destination.path.display()
            )));
        }

        Ok(FileDigests {
            size: total,
            sha1: format!("{:x}", sha1.finalize()),
            sha256: format!("{:x}", sha256.finalize()),
        })
    }

    pub(super) fn sha256(&mut self, limit: u64) -> ManagedFsResult<FileDigest> {
        if self.info.size > limit {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed file exceeds the hash limit: {}",
                self.path.display()
            )));
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|error| ManagedFsError::io("Cannot rewind managed file", &self.path, error))?;
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let read = self.file.read(&mut buffer).map_err(|error| {
                ManagedFsError::io("Cannot hash managed file", &self.path, error)
            })?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .ok_or_else(|| ManagedFsError::UnsafeNode("Managed file size overflow".into()))?;
            if total > limit {
                return Err(ManagedFsError::UnsafeNode(format!(
                    "Managed file exceeded the hash limit while reading: {}",
                    self.path.display()
                )));
            }
            digest.update(&buffer[..read]);
        }
        if total != self.info.size {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed file size changed while it was hashed: {}",
                self.path.display()
            )));
        }
        let after = node_info(&self.file, &self.path)?;
        if after.identity != self.info.identity
            || after.size != self.info.size
            || after.number_of_links != 1
            || after.reparse_tag != 0
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed file identity changed while it was hashed: {}",
                self.path.display()
            )));
        }
        let digest = digest.finalize();
        Ok(FileDigest {
            size: total,
            sha256: format!("{digest:x}"),
        })
    }

    /// Hashes both signed digests through the same immutable handle. On Windows the handle is
    /// opened without share-write/share-delete, so it also acts as a lease for the exact file
    /// until this value is dropped.
    pub(super) fn sha1_sha256(&mut self, limit: u64) -> ManagedFsResult<FileDigests> {
        if self.info.size > limit {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed file exceeds the hash limit: {}",
                self.path.display()
            )));
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|error| ManagedFsError::io("Cannot rewind managed file", &self.path, error))?;
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let read = self.file.read(&mut buffer).map_err(|error| {
                ManagedFsError::io("Cannot hash managed file", &self.path, error)
            })?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(read as u64)
                .ok_or_else(|| ManagedFsError::UnsafeNode("Managed file size overflow".into()))?;
            if total > limit {
                return Err(ManagedFsError::UnsafeNode(format!(
                    "Managed file exceeded the hash limit while reading: {}",
                    self.path.display()
                )));
            }
            sha1.update(&buffer[..read]);
            sha256.update(&buffer[..read]);
        }
        if total != self.info.size {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed file size changed while it was hashed: {}",
                self.path.display()
            )));
        }
        verify_handle_path(&self.file, &self.path)?;
        let after = node_info(&self.file, &self.path)?;
        if after.identity != self.info.identity
            || after.size != self.info.size
            || after.number_of_links != 1
            || after.reparse_tag != 0
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed file identity changed while it was hashed: {}",
                self.path.display()
            )));
        }
        Ok(FileDigests {
            size: total,
            sha1: format!("{:x}", sha1.finalize()),
            sha256: format!("{:x}", sha256.finalize()),
        })
    }
}

// A leased immutable file is itself the authority to read the already-opened no-follow handle.
// Implementing the standard cursor traits lets format readers (notably `zip`) consume that exact
// handle without falling back to a caller-supplied path and reopening a potentially replaced
// filesystem node.
impl Read for ImmutableManagedFile {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Seek for ImmutableManagedFile {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        self.file.seek(position)
    }
}

/// One-shot recursive structural/stream change detector used across the short server-admission
/// window. It is armed before the expensive baseline audit and deliberately never reset: any
/// matching mutation leaves the kernel notification permanently signalled and therefore fails
/// closed. Default-stream writes are excluded because Windows reports read-only `read_dir` as
/// `LAST_WRITE`; every admitted exact/mutable file is instead held without share-write. NTFS ADS
/// creation/write/resize remains covered explicitly by the STREAM_* notification bits.
///
/// Win32 does not report changes to the watched directory itself, so root ADS coverage uses a
/// non-recursive watch on its parent. That notification has no filename and deliberately treats a
/// sibling stream mutation as dirty too. Production callers must therefore retain the
/// install-wide operation lock which serializes every launcher-owned sibling for the lease; an
/// external same-user mutation remains an intentional fail-closed denial of launch.
#[cfg(windows)]
pub(super) struct RecursiveChangeSentinel {
    root: PathBuf,
    root_info: NodeInfo,
    root_guard: GuardedDirectoryChain,
    parent_guard: GuardedDirectoryChain,
    root_change: StickyChangeNotification,
    parent_change: StickyChangeNotification,
}

#[cfg(windows)]
struct StickyChangeNotification {
    handle: windows::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
// Kernel change-notification handles may be waited and closed from a different worker thread.
unsafe impl Send for StickyChangeNotification {}

#[cfg(windows)]
impl StickyChangeNotification {
    fn arm(
        path: &Path,
        recursive: bool,
        filter: windows::Win32::Storage::FileSystem::FILE_NOTIFY_CHANGE,
    ) -> ManagedFsResult<Self> {
        use std::os::windows::ffi::OsStrExt;
        use windows::{core::PCWSTR, Win32::Storage::FileSystem::FindFirstChangeNotificationW};

        if !path.is_absolute() {
            return Err(ManagedFsError::InvalidPath(
                "Change-notification path is not absolute".into(),
            ));
        }
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let handle =
            unsafe { FindFirstChangeNotificationW(PCWSTR(wide.as_ptr()), recursive, filter) }
                .map_err(|error| {
                    ManagedFsError::io(
                        "Cannot arm recursive filesystem change notification",
                        path,
                        windows_error_to_io(&error),
                    )
                })?;
        Ok(Self { handle })
    }

    fn require_clean(&self, path: &Path, scope: &str) -> ManagedFsResult<()> {
        use windows::Win32::{
            Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::Threading::WaitForSingleObject,
        };

        match unsafe { WaitForSingleObject(self.handle, 0) } {
            WAIT_TIMEOUT => Ok(()),
            WAIT_OBJECT_0 => Err(ManagedFsError::UnsafeNode(format!(
                "Managed filesystem changed after its baseline audit ({scope} notification): {}",
                path.display(),
            ))),
            WAIT_FAILED => Err(ManagedFsError::io(
                "Cannot poll filesystem change notification",
                path,
                std::io::Error::last_os_error(),
            )),
            other => Err(ManagedFsError::Unsupported(format!(
                "Unexpected filesystem change wait result {} for {}",
                other.0,
                path.display()
            ))),
        }
    }

    #[cfg(test)]
    fn wait_signalled(&self, timeout: std::time::Duration) -> bool {
        use windows::Win32::{Foundation::WAIT_OBJECT_0, System::Threading::WaitForSingleObject};
        let milliseconds = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
        (unsafe { WaitForSingleObject(self.handle, milliseconds) }) == WAIT_OBJECT_0
    }
}

#[cfg(windows)]
impl Drop for StickyChangeNotification {
    fn drop(&mut self) {
        use windows::Win32::Storage::FileSystem::FindCloseChangeNotification;
        let _ = unsafe { FindCloseChangeNotification(self.handle) };
    }
}

#[cfg(windows)]
impl RecursiveChangeSentinel {
    pub(super) fn arm(root: &Path) -> ManagedFsResult<Self> {
        use windows::Win32::Storage::FileSystem::{
            FILE_NOTIFY_CHANGE, FILE_NOTIFY_CHANGE_ATTRIBUTES, FILE_NOTIFY_CHANGE_CREATION,
            FILE_NOTIFY_CHANGE_DIR_NAME, FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_SECURITY,
            FILE_NOTIFY_CHANGE_SIZE,
        };
        // The windows crate version pinned by Tauri does not expose the three NTFS stream filter
        // constants, but their Win32 ABI values are stable in `winnt.h`.
        const FILE_NOTIFY_CHANGE_STREAM_NAME_BITS: u32 = 0x0000_0200;
        const FILE_NOTIFY_CHANGE_STREAM_SIZE_BITS: u32 = 0x0000_0400;
        const FILE_NOTIFY_CHANGE_STREAM_WRITE_BITS: u32 = 0x0000_0800;

        let root_guard = GuardedDirectoryChain::root_only(root)?;
        let stable_root = root_guard.leaf().path().to_path_buf();
        let parent = stable_root.parent().ok_or_else(|| {
            ManagedFsError::Unsupported("Cannot watch a filesystem root for launch changes".into())
        })?;
        let parent_guard = GuardedDirectoryChain::root_only(parent)?;
        let parent_filter = FILE_NOTIFY_CHANGE(
            FILE_NOTIFY_CHANGE_DIR_NAME.0
                | FILE_NOTIFY_CHANGE_ATTRIBUTES.0
                | FILE_NOTIFY_CHANGE_SECURITY.0
                // FindFirstChangeNotificationW does not report changes to the watched directory
                // itself. Root ADS mutations therefore belong to the non-recursive parent watch;
                // the recursive root watch covers streams on descendants only.
                | FILE_NOTIFY_CHANGE_STREAM_NAME_BITS
                | FILE_NOTIFY_CHANGE_STREAM_SIZE_BITS
                | FILE_NOTIFY_CHANGE_STREAM_WRITE_BITS,
        );
        // Arm the parent first so a rename/attribute/security change to the watched root cannot
        // hide in the small interval before the exact recursive root notification is installed.
        let parent_change =
            StickyChangeNotification::arm(parent_guard.leaf().path(), false, parent_filter)?;
        let root_filter = FILE_NOTIFY_CHANGE(
            FILE_NOTIFY_CHANGE_FILE_NAME.0
                | FILE_NOTIFY_CHANGE_DIR_NAME.0
                | FILE_NOTIFY_CHANGE_ATTRIBUTES.0
                | FILE_NOTIFY_CHANGE_SIZE.0
                | FILE_NOTIFY_CHANGE_CREATION.0
                | FILE_NOTIFY_CHANGE_SECURITY.0
                | FILE_NOTIFY_CHANGE_STREAM_NAME_BITS
                | FILE_NOTIFY_CHANGE_STREAM_SIZE_BITS
                | FILE_NOTIFY_CHANGE_STREAM_WRITE_BITS,
        );
        let root_change = StickyChangeNotification::arm(&stable_root, true, root_filter)?;
        let sentinel = Self {
            root: stable_root,
            root_info: root_guard.leaf().info().clone(),
            root_guard,
            parent_guard,
            root_change,
            parent_change,
        };
        sentinel.revalidate_clean()?;
        Ok(sentinel)
    }

    /// O(1) sticky-state and root-identity audit. No directory enumeration or file read occurs.
    pub(super) fn revalidate_clean(&self) -> ManagedFsResult<()> {
        self.parent_change.require_clean(&self.root, "parent")?;
        self.root_change
            .require_clean(&self.root, "recursive root")?;
        self.parent_guard.revalidate()?;
        self.root_guard.revalidate()?;
        let reopened = GuardedDirectoryChain::root_only(&self.root)?;
        if reopened.leaf().info() != &self.root_info {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed sentinel root metadata changed: {}",
                self.root.display()
            )));
        }
        self.parent_change.require_clean(&self.root, "parent")?;
        self.root_change.require_clean(&self.root, "recursive root")
    }

    #[cfg(test)]
    pub(super) fn wait_until_dirty(&self, timeout: std::time::Duration) -> bool {
        self.root_change.wait_signalled(timeout) || self.parent_change.wait_signalled(timeout)
    }
}

#[cfg(not(windows))]
pub(super) struct RecursiveChangeSentinel;

#[cfg(not(windows))]
impl RecursiveChangeSentinel {
    pub(super) fn arm(_root: &Path) -> ManagedFsResult<Self> {
        Err(ManagedFsError::Unsupported(
            "Recursive launch change sentinels require Windows".into(),
        ))
    }

    pub(super) fn revalidate_clean(&self) -> ManagedFsResult<()> {
        Err(ManagedFsError::Unsupported(
            "Recursive launch change sentinels require Windows".into(),
        ))
    }
}

pub(super) struct ExclusiveManagedFile {
    root: PathBuf,
    relative: RelativeManagedPath,
    path: PathBuf,
    file: File,
    info: NodeInfo,
    parent_chain: GuardedDirectoryChain,
}

/// One identity-stable writable file used for resumable CAS downloads.
///
/// The same no-follow, single-link handle is retained across resume inspection, every write,
/// hashing, fsync, and the final handle-based rename. Its guarded parent chain prevents a shard
/// directory from being redirected while the object is in flight.
pub(super) struct ResumableManagedFile {
    root: PathBuf,
    relative: RelativeManagedPath,
    path: PathBuf,
    file: File,
    info: NodeInfo,
    max_size: u64,
    parent_chain: GuardedDirectoryChain,
}

pub(super) enum ResumableCommitOutcome {
    Committed(CommittedManagedFile),
    DestinationExists(ResumableManagedFile),
}

impl ResumableManagedFile {
    pub(super) fn open_or_create(
        root: &Path,
        relative: RelativeManagedPath,
        max_size: u64,
    ) -> ManagedFsResult<Self> {
        let parent_chain = GuardedDirectoryChain::open_parent(root, &relative)?;
        let stable_root = parent_chain.root_path().to_path_buf();
        let path = relative.join_to(&stable_root);
        let mut opened = None;
        for _ in 0..3 {
            match open_resumable_file_nofollow(&path, true) {
                Ok(file) => {
                    opened = Some((file, true));
                    break;
                }
                Err(ManagedFsError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    match open_resumable_file_nofollow(&path, false) {
                        Ok(file) => {
                            opened = Some((file, false));
                            break;
                        }
                        Err(ManagedFsError::Io { source, .. })
                            if source.kind() == std::io::ErrorKind::NotFound =>
                        {
                            continue;
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            }
        }
        let (file, created) = opened.ok_or_else(|| {
            ManagedFsError::Conflict(format!(
                "Managed resumable file changed repeatedly while opening: {}",
                path.display()
            ))
        })?;
        let info = node_info(&file, &path)?;
        info.require_regular_single_link(&path)?;
        verify_handle_path(&file, &path)?;
        if info.identity.volume_serial_number
            != parent_chain.leaf().info.identity.volume_serial_number
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable file crossed a volume boundary: {}",
                path.display()
            )));
        }
        if created {
            file.sync_all().map_err(|error| {
                ManagedFsError::io("Cannot flush new managed resumable file", &path, error)
            })?;
            parent_chain.leaf().sync_directory().map_err(|error| {
                ManagedFsError::AppliedButDurabilityUnconfirmed {
                    destination: path.clone(),
                    detail: format!("new resumable file parent flush failed: {error}"),
                }
            })?;
        }
        Ok(Self {
            root: stable_root,
            relative,
            path,
            file,
            info,
            max_size,
            parent_chain,
        })
    }

    pub(super) fn open_existing(
        root: &Path,
        relative: RelativeManagedPath,
        max_size: u64,
    ) -> ManagedFsResult<Option<Self>> {
        let parent_chain = GuardedDirectoryChain::open_parent(root, &relative)?;
        let stable_root = parent_chain.root_path().to_path_buf();
        let path = relative.join_to(&stable_root);
        let file = match open_resumable_file_nofollow(&path, false) {
            Ok(file) => file,
            Err(ManagedFsError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        let info = node_info(&file, &path)?;
        info.require_regular_single_link(&path)?;
        verify_handle_path(&file, &path)?;
        if info.identity.volume_serial_number
            != parent_chain.leaf().info.identity.volume_serial_number
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable file crossed a volume boundary: {}",
                path.display()
            )));
        }
        Ok(Some(Self {
            root: stable_root,
            relative,
            path,
            file,
            info,
            max_size,
            parent_chain,
        }))
    }

    fn current_info_with_limit(&self, enforce_limit: bool) -> ManagedFsResult<NodeInfo> {
        self.parent_chain.revalidate()?;
        verify_handle_path(&self.file, &self.path)?;
        let current = node_info(&self.file, &self.path)?;
        current.require_regular_single_link(&self.path)?;
        if current.identity != self.info.identity || (enforce_limit && current.size > self.max_size)
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable file identity or size changed: {}",
                self.path.display()
            )));
        }
        Ok(current)
    }

    pub(super) fn len(&self) -> ManagedFsResult<u64> {
        Ok(self.current_info_with_limit(false)?.size)
    }

    pub(super) fn allocated_size(&self) -> ManagedFsResult<u64> {
        Ok(self.current_info_with_limit(false)?.allocation_size)
    }

    /// Captures logical length, physical allocation, file identity, and managed-root binding from
    /// the already-open resumable capability. This deliberately does not inspect the path through
    /// a second file handle, so sparse/compressed allocation evidence cannot be paired with a
    /// different namespace object between separate `len()` and `allocated_size()` calls.
    pub(super) fn allocation_snapshot(&self) -> ManagedFsResult<ManagedFileAllocationSnapshot> {
        self.parent_chain.revalidate()?;
        let current = node_info(&self.file, &self.path)?;
        current.require_regular_single_link(&self.path)?;
        if current.identity != self.info.identity {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable file identity changed: {}",
                self.path.display()
            )));
        }
        verify_handle_path_with_info(&self.file, &self.path, &current)?;

        let managed_root_identity = self.parent_chain.root_identity().clone();
        if current.identity.volume_serial_number != managed_root_identity.volume_serial_number {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable allocation snapshot crossed a volume boundary: {}",
                self.path.display()
            )));
        }
        Ok(ManagedFileAllocationSnapshot {
            identity: current.identity,
            managed_root_identity,
            logical_size: current.size,
            allocated_size: current.allocation_size,
        })
    }

    pub(super) fn truncate_zero(&mut self) -> ManagedFsResult<()> {
        self.current_info_with_limit(false)?;
        self.file.set_len(0).map_err(|error| {
            ManagedFsError::io("Cannot truncate managed resumable file", &self.path, error)
        })?;
        self.file.sync_all().map_err(|error| {
            ManagedFsError::io(
                "Cannot flush truncated managed resumable file",
                &self.path,
                error,
            )
        })?;
        let after = self.current_info_with_limit(true)?;
        if after.size != 0 {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable file did not truncate to zero: {}",
                self.path.display()
            )));
        }
        self.info = after;
        Ok(())
    }

    pub(super) fn write_all_at(
        &mut self,
        expected_offset: u64,
        bytes: &[u8],
    ) -> ManagedFsResult<u64> {
        let before = self.current_info_with_limit(true)?;
        if before.size != expected_offset {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable write offset no longer matches the file: {}",
                self.path.display()
            )));
        }
        let next = expected_offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| ManagedFsError::UnsafeNode("Managed resumable size overflow".into()))?;
        if next > self.max_size {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable write exceeds its signed limit: {}",
                self.path.display()
            )));
        }
        self.file
            .seek(SeekFrom::Start(expected_offset))
            .map_err(|error| {
                ManagedFsError::io("Cannot seek managed resumable file", &self.path, error)
            })?;
        self.file.write_all(bytes).map_err(|error| {
            ManagedFsError::io("Cannot write managed resumable file", &self.path, error)
        })?;
        let after = self.current_info_with_limit(true)?;
        if after.size != next {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable file size changed during write: {}",
                self.path.display()
            )));
        }
        self.info = after;
        Ok(next)
    }

    /// Compares the complete current partial with the prefix of an already authenticated source.
    /// Both handles are rewound and the resumable identity is revalidated after the comparison.
    pub(super) fn matches_reader_prefix<R: Read + Seek>(
        &mut self,
        source: &mut R,
        expected_size: u64,
    ) -> ManagedFsResult<bool> {
        let before = self.current_info_with_limit(true)?;
        if before.size > expected_size {
            return Ok(false);
        }
        self.file.seek(SeekFrom::Start(0)).map_err(|error| {
            ManagedFsError::io("Cannot rewind managed resumable prefix", &self.path, error)
        })?;
        source.seek(SeekFrom::Start(0)).map_err(|error| {
            ManagedFsError::io(
                "Cannot rewind authenticated prefix source",
                &self.path,
                error,
            )
        })?;
        let mut remaining = before.size;
        let mut left = vec![0_u8; 1024 * 1024];
        let mut right = vec![0_u8; 1024 * 1024];
        while remaining != 0 {
            let wanted = usize::try_from(remaining.min(left.len() as u64))
                .expect("bounded prefix chunk fits usize");
            self.file.read_exact(&mut left[..wanted]).map_err(|error| {
                ManagedFsError::io("Cannot read managed resumable prefix", &self.path, error)
            })?;
            source.read_exact(&mut right[..wanted]).map_err(|error| {
                ManagedFsError::io("Cannot read authenticated prefix source", &self.path, error)
            })?;
            if left[..wanted] != right[..wanted] {
                self.info = self.current_info_with_limit(true)?;
                return Ok(false);
            }
            remaining -= wanted as u64;
        }
        self.info = self.current_info_with_limit(true)?;
        Ok(self.info.size == before.size)
    }

    pub(super) fn matches_bytes_prefix(
        &mut self,
        source: &[u8],
        expected_size: u64,
    ) -> ManagedFsResult<bool> {
        let mut cursor = std::io::Cursor::new(source);
        self.matches_reader_prefix(&mut cursor, expected_size)
    }

    pub(super) fn sync_all(&mut self) -> ManagedFsResult<()> {
        self.current_info_with_limit(true)?;
        self.file.sync_all().map_err(|error| {
            ManagedFsError::io("Cannot flush managed resumable file", &self.path, error)
        })?;
        self.info = self.current_info_with_limit(true)?;
        Ok(())
    }

    /// Sets the final executable policy through the same identity-stable handle that is later
    /// committed. Windows has no POSIX executable bit, so a signed executable staging entry is
    /// rejected by the reconcile layer before this method is called there.
    pub(super) fn set_executable(&mut self, executable: bool) -> ManagedFsResult<()> {
        self.current_info_with_limit(true)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = self
                .file
                .metadata()
                .map_err(|error| {
                    ManagedFsError::io(
                        "Cannot inspect managed resumable permissions",
                        &self.path,
                        error,
                    )
                })?
                .permissions();
            let mode = permissions.mode();
            permissions.set_mode(if executable {
                mode | 0o111
            } else {
                mode & !0o111
            });
            self.file.set_permissions(permissions).map_err(|error| {
                ManagedFsError::io(
                    "Cannot set managed resumable permissions",
                    &self.path,
                    error,
                )
            })?;
        }
        #[cfg(not(unix))]
        {
            let _ = executable;
        }
        self.info = self.current_info_with_limit(true)?;
        Ok(())
    }

    pub(super) fn sha256(&mut self, expected_size: u64) -> ManagedFsResult<FileDigest> {
        let before = self.current_info_with_limit(true)?;
        if before.size != expected_size {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable file size differs from the signed size: {}",
                self.path.display()
            )));
        }
        self.file.seek(SeekFrom::Start(0)).map_err(|error| {
            ManagedFsError::io("Cannot rewind managed resumable file", &self.path, error)
        })?;
        let mut digest = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let read = self.file.read(&mut buffer).map_err(|error| {
                ManagedFsError::io("Cannot hash managed resumable file", &self.path, error)
            })?;
            if read == 0 {
                break;
            }
            total = total.checked_add(read as u64).ok_or_else(|| {
                ManagedFsError::UnsafeNode("Managed resumable hash size overflow".into())
            })?;
            if total > expected_size {
                return Err(ManagedFsError::UnsafeNode(format!(
                    "Managed resumable file exceeded its signed size: {}",
                    self.path.display()
                )));
            }
            digest.update(&buffer[..read]);
        }
        let after = self.current_info_with_limit(true)?;
        if total != expected_size || after.size != expected_size {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable file changed while hashing: {}",
                self.path.display()
            )));
        }
        self.info = after;
        Ok(FileDigest {
            size: total,
            sha256: format!("{:x}", digest.finalize()),
        })
    }

    /// Hashes both official digests through the exact writable handle that will later be renamed
    /// into the CAS. Keeping inspection, resume, hashing, fsync and activation on this one handle
    /// prevents a path replacement from swapping bytes between verification and commit.
    pub(super) fn sha1_sha256(&mut self, expected_size: u64) -> ManagedFsResult<FileDigests> {
        let before = self.current_info_with_limit(true)?;
        if before.size != expected_size {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable file size differs from the signed size: {}",
                self.path.display()
            )));
        }
        self.file.seek(SeekFrom::Start(0)).map_err(|error| {
            ManagedFsError::io("Cannot rewind managed resumable file", &self.path, error)
        })?;
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let read = self.file.read(&mut buffer).map_err(|error| {
                ManagedFsError::io("Cannot hash managed resumable file", &self.path, error)
            })?;
            if read == 0 {
                break;
            }
            total = total.checked_add(read as u64).ok_or_else(|| {
                ManagedFsError::UnsafeNode("Managed resumable hash size overflow".into())
            })?;
            if total > expected_size {
                return Err(ManagedFsError::UnsafeNode(format!(
                    "Managed resumable file exceeded its signed size: {}",
                    self.path.display()
                )));
            }
            sha1.update(&buffer[..read]);
            sha256.update(&buffer[..read]);
        }
        let after = self.current_info_with_limit(true)?;
        if total != expected_size || after.size != expected_size {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable file changed while hashing: {}",
                self.path.display()
            )));
        }
        self.info = after;
        Ok(FileDigests {
            size: total,
            sha1: format!("{:x}", sha1.finalize()),
            sha256: format!("{:x}", sha256.finalize()),
        })
    }

    pub(super) fn commit_no_replace_if<F>(
        mut self,
        destination: RelativeManagedPath,
        should_commit: F,
    ) -> ManagedFsResult<Option<ResumableCommitOutcome>>
    where
        F: FnOnce() -> bool,
    {
        self.sync_all()?;
        if self.relative == destination {
            return Err(ManagedFsError::Conflict(
                "Managed resumable source and destination are identical".into(),
            ));
        }
        let destination_parent = GuardedDirectoryChain::open_parent(&self.root, &destination)?;
        ensure_same_root_and_volume(&self.parent_chain, &destination_parent)?;
        let destination_path = destination.join_to(&self.root);
        // This is the last cancellation boundary. The partial is already durably flushed and
        // every source/destination identity has been revalidated; after the no-replace rename
        // starts, callers must report its applied/durability outcome instead of cancellation.
        if !should_commit() {
            return Ok(None);
        }
        match rename_handle_relative(
            &self.file,
            &destination_parent.leaf()._handle,
            destination.file_name(),
            &destination_path,
            ManagedRenameMode::NoReplace,
        ) {
            Ok(()) => {}
            Err(ManagedFsError::Conflict(_)) => {
                self.current_info_with_limit(true)?;
                return Ok(Some(ResumableCommitOutcome::DestinationExists(self)));
            }
            Err(error) => return Err(error),
        }
        if let Err(error) = verify_handle_path(&self.file, &destination_path) {
            return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: destination_path,
                detail: format!("renamed resumable handle did not resolve: {error}"),
            });
        }
        let after = node_info(&self.file, &destination_path).map_err(|error| {
            ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: destination_path.clone(),
                detail: format!("cannot verify renamed resumable handle: {error}"),
            }
        })?;
        if after.identity != self.info.identity
            || after.kind != ManagedNodeKind::File
            || after.reparse_tag != 0
            || after.number_of_links != 1
            || after.size > self.max_size
        {
            return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: destination_path,
                detail: "renamed resumable object identity changed".into(),
            });
        }
        flush_rename_parents(
            self.parent_chain.leaf(),
            destination_parent.leaf(),
            &destination_path,
        )?;
        Ok(Some(ResumableCommitOutcome::Committed(
            CommittedManagedFile {
                destination,
                identity: after.identity,
                size: after.size,
            },
        )))
    }

    pub(super) fn discard(self) -> ManagedFsResult<()> {
        let current = self.current_info_with_limit(false)?;
        let path = self.path.clone();
        let parent_chain = self.parent_chain;
        delete_open_file(&self.file, &path)?;
        drop(self.file);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(ManagedFsError::UnsafeNode(format!(
                    "A filesystem node appeared at a discarded resumable path: {}",
                    path.display()
                )))
            }
            Err(error) => {
                return Err(ManagedFsError::io(
                    "Cannot confirm managed resumable file removal",
                    &path,
                    error,
                ))
            }
        }
        if current.identity != self.info.identity {
            return Err(ManagedFsError::UnsafeNode(
                "Managed resumable file identity changed before discard".into(),
            ));
        }
        parent_chain.leaf().sync_directory().map_err(|error| {
            ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: path,
                detail: format!("discarded resumable file parent flush failed: {error}"),
            }
        })
    }
}

impl ExclusiveManagedFile {
    pub(super) fn create(root: &Path, relative: RelativeManagedPath) -> ManagedFsResult<Self> {
        let parent_chain = GuardedDirectoryChain::open_parent(root, &relative)?;
        let stable_root = parent_chain.root_path().to_path_buf();
        let path = relative.join_to(&stable_root);
        let file = create_exclusive_file(&path)?;
        let info = node_info(&file, &path)?;
        info.require_regular_single_link(&path)?;
        verify_handle_path(&file, &path)?;
        if info.identity.volume_serial_number
            != parent_chain.leaf().info.identity.volume_serial_number
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Exclusive managed file crossed a volume boundary: {}",
                path.display()
            )));
        }
        Ok(Self {
            root: stable_root,
            relative,
            path,
            file,
            info,
            parent_chain,
        })
    }

    pub(super) fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub(super) fn sync(self) -> ManagedFsResult<SyncedExclusiveManagedFile> {
        self.file.sync_all().map_err(|error| {
            ManagedFsError::io("Cannot flush exclusive managed file", &self.path, error)
        })?;
        let after = node_info(&self.file, &self.path)?;
        if after.identity != self.info.identity
            || after.kind != ManagedNodeKind::File
            || after.reparse_tag != 0
            || after.number_of_links != 1
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Exclusive managed file changed before commit: {}",
                self.path.display()
            )));
        }
        Ok(SyncedExclusiveManagedFile {
            root: self.root,
            source_relative: self.relative,
            file: self.file,
            info: after,
            source_parent_chain: self.parent_chain,
        })
    }

    /// Makes a newly-created file durable in place and turns its still-open exclusive handle into
    /// a transient immutable lease. Its original Windows share mode remains zero, so callers must
    /// drop it before reopening the final tree for consumers. This is for files published by
    /// moving an ancestor directory: both bytes and the directory entry become durable first.
    pub(super) fn seal_in_place(self) -> ManagedFsResult<ImmutableManagedFile> {
        self.file.sync_all().map_err(|error| {
            ManagedFsError::io("Cannot flush exclusive managed file", &self.path, error)
        })?;
        let after = node_info(&self.file, &self.path)?;
        after.require_regular_single_link(&self.path)?;
        verify_handle_path(&self.file, &self.path)?;
        if after.identity != self.info.identity {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Exclusive managed file changed before in-place seal: {}",
                self.path.display()
            )));
        }
        self.parent_chain.leaf().sync_directory().map_err(|error| {
            ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: self.path.clone(),
                detail: format!("sealed file parent flush failed: {error}"),
            }
        })?;
        self.parent_chain.revalidate()?;
        Ok(ImmutableManagedFile {
            path: self.path,
            file: self.file,
            info: after,
            _parent_chain: self.parent_chain,
        })
    }
}

pub(super) struct SyncedExclusiveManagedFile {
    root: PathBuf,
    source_relative: RelativeManagedPath,
    file: File,
    info: NodeInfo,
    source_parent_chain: GuardedDirectoryChain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManagedRenameMode {
    NoReplace,
    ReplaceExisting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CommittedManagedFile {
    pub(super) destination: RelativeManagedPath,
    pub(super) identity: FileIdentity,
    pub(super) size: u64,
}

impl SyncedExclusiveManagedFile {
    pub(super) fn rename_no_replace(
        self,
        destination: RelativeManagedPath,
    ) -> ManagedFsResult<CommittedManagedFile> {
        self.rename(destination, ManagedRenameMode::NoReplace)
    }

    pub(super) fn rename_replace_existing(
        self,
        destination: RelativeManagedPath,
    ) -> ManagedFsResult<CommittedManagedFile> {
        self.rename(destination, ManagedRenameMode::ReplaceExisting)
    }

    fn verify_exact_bytes(&mut self, expected: &[u8], limit: usize) -> ManagedFsResult<()> {
        if expected.len() > limit || expected.len() > MAX_ATOMIC_WRITE_BYTES {
            return Err(ManagedFsError::InvalidPath(
                "Atomic managed payload exceeds the configured limit".into(),
            ));
        }
        let source_path = self.source_path();
        self.file.seek(SeekFrom::Start(0)).map_err(|error| {
            ManagedFsError::io("Cannot rewind synced managed file", &source_path, error)
        })?;
        let mut actual = Vec::with_capacity(expected.len());
        Read::by_ref(&mut self.file)
            .take((limit as u64).saturating_add(1))
            .read_to_end(&mut actual)
            .map_err(|error| {
                ManagedFsError::io("Cannot verify synced managed file", &source_path, error)
            })?;
        if actual != expected {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Synced managed file bytes do not match the requested payload: {}",
                source_path.display()
            )));
        }
        let after = node_info(&self.file, &source_path)?;
        if after.identity != self.info.identity
            || after.kind != ManagedNodeKind::File
            || after.reparse_tag != 0
            || after.number_of_links != 1
            || after.size != expected.len() as u64
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Synced managed file identity changed during verification: {}",
                source_path.display()
            )));
        }
        Ok(())
    }

    fn source_path(&self) -> PathBuf {
        self.source_relative.join_to(&self.root)
    }

    fn rename(
        self,
        destination: RelativeManagedPath,
        mode: ManagedRenameMode,
    ) -> ManagedFsResult<CommittedManagedFile> {
        if self.source_relative == destination {
            return Err(ManagedFsError::Conflict(
                "Managed source and destination are identical".into(),
            ));
        }
        let destination_parent = GuardedDirectoryChain::open_parent(&self.root, &destination)?;
        ensure_same_root_and_volume(&self.source_parent_chain, &destination_parent)?;
        let destination_path = destination.join_to(&self.root);

        rename_handle(&self.file, &destination_path, mode)?;
        if let Err(error) = verify_handle_path(&self.file, &destination_path) {
            return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: destination_path,
                detail: format!("renamed handle did not resolve to the destination: {error}"),
            });
        }
        let after = node_info(&self.file, &destination_path).map_err(|error| {
            ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: destination_path.clone(),
                detail: format!("cannot verify renamed handle: {error}"),
            }
        })?;
        if after.identity != self.info.identity {
            return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: destination_path,
                detail: "renamed object identity changed".into(),
            });
        }

        flush_rename_parents(
            self.source_parent_chain.leaf(),
            destination_parent.leaf(),
            &destination_path,
        )?;
        Ok(CommittedManagedFile {
            destination,
            identity: after.identity,
            size: after.size,
        })
    }
}

pub(super) fn atomic_write_small(
    root: &Path,
    destination: RelativeManagedPath,
    bytes: &[u8],
    limit: usize,
) -> ManagedFsResult<CommittedManagedFile> {
    if bytes.len() > limit || bytes.len() > MAX_ATOMIC_WRITE_BYTES {
        return Err(ManagedFsError::InvalidPath(format!(
            "Atomic managed payload exceeds its limit: {} > {}",
            bytes.len(),
            limit.min(MAX_ATOMIC_WRITE_BYTES)
        )));
    }
    let destination_parent = GuardedDirectoryChain::open_parent(root, &destination)?;
    let stable_root = destination_parent.root_path().to_path_buf();
    let parent = destination.parent();

    let mut last_collision = None;
    for _ in 0..3 {
        let temporary_name = format!(".fragment-{}.tmp", Uuid::new_v4());
        let temporary = match &parent {
            Some(parent) => parent.join_component(&temporary_name)?,
            None => RelativeManagedPath::new(&temporary_name)?,
        };
        let mut exclusive = match ExclusiveManagedFile::create(&stable_root, temporary) {
            Ok(file) => file,
            Err(ManagedFsError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                last_collision = Some(source);
                continue;
            }
            Err(error) => return Err(error),
        };
        exclusive.file_mut().write_all(bytes).map_err(|error| {
            ManagedFsError::io(
                "Cannot write atomic managed payload",
                &exclusive.path,
                error,
            )
        })?;
        let mut synced = exclusive.sync()?;
        synced.verify_exact_bytes(bytes, limit)?;
        return synced.rename_replace_existing(destination);
    }
    Err(ManagedFsError::Conflict(format!(
        "Could not allocate a unique atomic managed temporary file: {}",
        last_collision
            .map(|error| error.to_string())
            .unwrap_or_else(|| "unexpected collision".into())
    )))
}

pub(super) struct ManagedLockFile {
    path: PathBuf,
    file: File,
    info: NodeInfo,
    _parent_chain: GuardedDirectoryChain,
}

impl ManagedLockFile {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn file(&self) -> &File {
        &self.file
    }

    pub(super) fn info(&self) -> &NodeInfo {
        &self.info
    }

    pub(super) fn revalidate(&self) -> ManagedFsResult<()> {
        self._parent_chain.revalidate()?;
        verify_handle_path(&self.file, &self.path)?;
        let current = node_info(&self.file, &self.path)?;
        current.require_regular_single_link(&self.path)?;
        if current.identity != self.info.identity {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed lock file identity changed: {}",
                self.path.display()
            )));
        }
        Ok(())
    }
}

pub(super) fn open_or_create_lock_file(
    root: &Path,
    relative: &RelativeManagedPath,
) -> ManagedFsResult<ManagedLockFile> {
    let parent_chain = GuardedDirectoryChain::open_parent(root, relative)?;
    let path = relative.join_to(parent_chain.root_path());
    let mut opened = None;
    for _ in 0..3 {
        match open_lock_file_nofollow(&path, true) {
            Ok(file) => {
                opened = Some((file, true));
                break;
            }
            Err(ManagedFsError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::AlreadyExists =>
            {
                match open_lock_file_nofollow(&path, false) {
                    Ok(file) => {
                        opened = Some((file, false));
                        break;
                    }
                    Err(ManagedFsError::Io { source, .. })
                        if source.kind() == std::io::ErrorKind::NotFound =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
    }
    let (file, created) = opened.ok_or_else(|| {
        ManagedFsError::Conflict(format!(
            "Managed lock file changed repeatedly while opening: {}",
            path.display()
        ))
    })?;
    let info = node_info(&file, &path)?;
    info.require_regular_single_link(&path)?;
    verify_handle_path(&file, &path)?;
    if info.identity.volume_serial_number != parent_chain.leaf().info.identity.volume_serial_number
    {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed lock file crossed a volume boundary: {}",
            path.display()
        )));
    }
    if created {
        file.sync_all().map_err(|error| {
            ManagedFsError::io("Cannot flush new managed lock file", &path, error)
        })?;
        parent_chain.leaf().sync_directory().map_err(|error| {
            ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: path.clone(),
                detail: format!("new lock file parent flush failed: {error}"),
            }
        })?;
    }
    Ok(ManagedLockFile {
        path,
        file,
        info,
        _parent_chain: parent_chain,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct QuarantinedNode {
    pub(super) source: RelativeManagedPath,
    pub(super) destination: RelativeManagedPath,
    pub(super) identity: FileIdentity,
    pub(super) kind: ManagedNodeKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MovedManagedNode {
    pub(super) source: RelativeManagedPath,
    pub(super) destination: RelativeManagedPath,
    pub(super) identity: FileIdentity,
    pub(super) kind: ManagedNodeKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct MovedManagedDirectory {
    pub(super) source: RelativeManagedPath,
    pub(super) destination: RelativeManagedPath,
    pub(super) identity: FileIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ConditionalManagedDirectoryMoveOutcome {
    Cancelled,
    Moved(MovedManagedDirectory),
}

/// Conditionally publishes one exact real directory at one absent managed destination.
///
/// The source and both lexical parent chains stay handle-bound throughout the operation. The
/// predicate is the final cancellation boundary: it runs only after every identity, volume and
/// destination-absence check, immediately before the handle rename. Once the rename begins this
/// function can only report the actual move result or `AppliedButDurabilityUnconfirmed`; it never
/// converts an applied namespace mutation into cancellation.
pub(super) fn move_managed_directory_no_replace_if<F>(
    root: &Path,
    source: RelativeManagedPath,
    destination: RelativeManagedPath,
    should_move: F,
) -> ManagedFsResult<ConditionalManagedDirectoryMoveOutcome>
where
    F: FnOnce() -> bool,
{
    if source.collision_key() == destination.collision_key() {
        return Err(ManagedFsError::Conflict(
            "Managed directory move source and destination collide on Windows".into(),
        ));
    }
    if source.is_prefix_of(&destination) {
        return Err(ManagedFsError::InvalidPath(
            "Managed directory move destination cannot be inside the source".into(),
        ));
    }

    let source_parent = GuardedDirectoryChain::open_parent(root, &source)?;
    let destination_parent = GuardedDirectoryChain::open_parent(root, &destination)?;
    ensure_same_root_and_volume(&source_parent, &destination_parent)?;

    // Flush through an identity-bound directory handle before acquiring DELETE access for the
    // final rename. The complete source guard is dropped only after the flush; the subsequently
    // opened rename handle must prove that it still names that same directory identity.
    let source_flush_guard = GuardedDirectoryChain::open(root, &source)?;
    source_flush_guard.revalidate()?;
    source_flush_guard.leaf().sync_directory()?;
    let flushed_source_identity = source_flush_guard.leaf().info.identity.clone();
    drop(source_flush_guard);

    let source_path = source.join_to(source_parent.root_path());
    let source_file = open_for_handle_rename(&source_path)?;
    let source_info = node_info(&source_file, &source_path)?;
    source_info.require_real_directory(&source_path)?;
    verify_handle_path(&source_file, &source_path)?;
    if source_info.identity != flushed_source_identity {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed directory move source changed after its durability flush: {}",
            source_path.display()
        )));
    }
    if source_info.identity.volume_serial_number
        != source_parent.leaf().info.identity.volume_serial_number
    {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed directory move source crossed a volume boundary: {}",
            source_path.display()
        )));
    }

    let destination_path = destination.join_to(source_parent.root_path());
    match fs::symlink_metadata(&destination_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(ManagedFsError::Conflict(format!(
                "Managed directory move destination already exists: {}",
                destination_path.display()
            )))
        }
        Err(error) => {
            return Err(ManagedFsError::io(
                "Cannot inspect managed directory move destination",
                &destination_path,
                error,
            ))
        }
    }

    // Re-prove every handle-bound authority after the source flush and destination check. There
    // must be no fallible validation or path lookup between the cancellation predicate and the
    // actual no-replace rename below.
    source_parent.revalidate()?;
    destination_parent.revalidate()?;
    ensure_same_root_and_volume(&source_parent, &destination_parent)?;
    verify_handle_path(&source_file, &source_path)?;
    let before_commit = node_info(&source_file, &source_path)?;
    before_commit.require_real_directory(&source_path)?;
    if before_commit.identity != source_info.identity
        || before_commit.case_sensitive_directory != source_info.case_sensitive_directory
    {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed directory move source identity changed before commit: {}",
            source_path.display()
        )));
    }

    if !should_move() {
        return Ok(ConditionalManagedDirectoryMoveOutcome::Cancelled);
    }
    rename_handle(
        &source_file,
        &destination_path,
        ManagedRenameMode::NoReplace,
    )?;

    if let Err(error) = verify_handle_path(&source_file, &destination_path) {
        return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination: destination_path,
            detail: format!("cannot verify published managed directory handle: {error}"),
        });
    }
    let after = node_info(&source_file, &destination_path).map_err(|error| {
        ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination: destination_path.clone(),
            detail: format!("cannot inspect published managed directory handle: {error}"),
        }
    })?;
    if after.identity != source_info.identity
        || after.kind != ManagedNodeKind::Directory
        || after.reparse_tag != 0
        || after.case_sensitive_directory
    {
        return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination: destination_path,
            detail: "published managed directory identity or classification changed".into(),
        });
    }
    flush_rename_parents(
        source_parent.leaf(),
        destination_parent.leaf(),
        &destination_path,
    )?;
    Ok(ConditionalManagedDirectoryMoveOutcome::Moved(
        MovedManagedDirectory {
            source,
            destination,
            identity: after.identity,
        },
    ))
}

/// Moves one exact managed node to one deterministic, currently absent destination.
///
/// This is the reversible primitive used by numbered journal backup slots. It opens the source
/// with no-follow semantics, performs a handle-based no-replace rename on Windows, and never
/// recursively traverses or deletes the source. Calling it again with source/destination swapped
/// restores the same filesystem object during rollback.
pub(super) fn move_managed_node_no_replace(
    root: &Path,
    source: RelativeManagedPath,
    destination: RelativeManagedPath,
) -> ManagedFsResult<MovedManagedNode> {
    move_managed_node_no_replace_with_expected(root, source, destination, None)
}

/// Moves a node only if the no-follow handle opened for the namespace commit still has the
/// identity and kind observed by the caller's audit.
pub(super) fn move_managed_node_no_replace_if_identity(
    root: &Path,
    source: RelativeManagedPath,
    destination: RelativeManagedPath,
    expected_identity: &FileIdentity,
) -> ManagedFsResult<MovedManagedNode> {
    let (current_identity, current_kind, _) = inspect_managed_node_nofollow(root, &source)?;
    if &current_identity != expected_identity {
        return Err(ManagedFsError::UnsafeNode(
            "Managed move source no longer has the audited identity".into(),
        ));
    }
    move_managed_node_no_replace_with_expected(
        root,
        source,
        destination,
        Some((expected_identity, current_kind)),
    )
}

/// Obtains a stable no-follow identity, native kind and exact reparse tag for one managed node.
/// The returned snapshot carries no path authority; destructive callers must pass it back to an
/// expected-identity/class handle operation.
pub(super) fn inspect_managed_node_nofollow(
    root: &Path,
    relative: &RelativeManagedPath,
) -> ManagedFsResult<(FileIdentity, ManagedNodeKind, u32)> {
    let parent = GuardedDirectoryChain::open_parent(root, relative)?;
    let path = relative.join_to(parent.root_path());
    let handle = open_for_handle_rename(&path)?;
    let info = node_info(&handle, &path)?;
    verify_handle_path_allow_reparse(&handle, &path)?;
    if info.identity.volume_serial_number != parent.leaf().info.identity.volume_serial_number {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed node crossed a volume boundary: {}",
            path.display()
        )));
    }
    Ok((info.identity, info.kind, info.reparse_tag))
}

/// Obtains the no-follow identity required to enter the bounded garbage-removal sink.
///
/// Unlike the general inspector, this deliberately accounts for named streams instead of
/// rejecting them. The returned identity is not deletion authority by itself: the garbage
/// remover reopens the exact node, requires the same identity and audits all stream allocation
/// under its own bounds before applying a disposition.
pub(super) fn inspect_managed_garbage_node_nofollow(
    root: &Path,
    relative: &RelativeManagedPath,
) -> ManagedFsResult<FileIdentity> {
    let parent = GuardedDirectoryChain::open_parent(root, relative)?;
    let path = relative.join_to(parent.root_path());
    let handle = open_node_for_recursive_removal(&path)?;
    let info = garbage_node_info(&handle, &path)?;
    verify_handle_path_allow_reparse(&handle, &path)?;
    if info.identity.volume_serial_number != parent.leaf().info.identity.volume_serial_number {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed garbage node crossed a volume boundary: {}",
            path.display()
        )));
    }
    Ok(info.identity)
}

fn move_managed_node_no_replace_with_expected(
    root: &Path,
    source: RelativeManagedPath,
    destination: RelativeManagedPath,
    expected: Option<(&FileIdentity, ManagedNodeKind)>,
) -> ManagedFsResult<MovedManagedNode> {
    if source.collision_key() == destination.collision_key() {
        return Err(ManagedFsError::Conflict(
            "Managed move source and destination collide on Windows".into(),
        ));
    }
    if source.is_prefix_of(&destination) {
        return Err(ManagedFsError::InvalidPath(
            "Managed move destination cannot be inside the source node".into(),
        ));
    }

    let source_parent = GuardedDirectoryChain::open_parent(root, &source)?;
    let destination_parent = GuardedDirectoryChain::open_parent(root, &destination)?;
    ensure_same_root_and_volume(&source_parent, &destination_parent)?;

    let source_path = source.join_to(source_parent.root_path());
    let source_file = open_for_handle_rename(&source_path)?;
    let source_info = node_info(&source_file, &source_path)?;
    if let Some((expected_identity, expected_kind)) = expected {
        if &source_info.identity != expected_identity || source_info.kind != expected_kind {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed move source no longer has the expected identity or kind: {}",
                source_path.display()
            )));
        }
    }
    if source_info.kind == ManagedNodeKind::File
        && source_info.reparse_tag == 0
        && source_info.number_of_links != 1
    {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Hard-linked managed files cannot be moved automatically: {}",
            source_path.display()
        )));
    }

    let destination_path = destination.join_to(source_parent.root_path());
    rename_handle(
        &source_file,
        &destination_path,
        ManagedRenameMode::NoReplace,
    )?;
    if let Err(error) = verify_handle_path_allow_reparse(&source_file, &destination_path) {
        return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination: destination_path,
            detail: format!("cannot verify moved managed handle: {error}"),
        });
    }
    let after = node_info(&source_file, &destination_path).map_err(|error| {
        ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination: destination_path.clone(),
            detail: format!("cannot inspect moved managed handle: {error}"),
        }
    })?;
    if after.identity != source_info.identity || after.kind != source_info.kind {
        return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination: destination_path,
            detail: "moved managed object identity changed".into(),
        });
    }
    if let Some((expected_identity, expected_kind)) = expected {
        if &after.identity != expected_identity || after.kind != expected_kind {
            return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: destination_path,
                detail: "moved managed object no longer has the expected identity or kind".into(),
            });
        }
    }
    flush_rename_parents(
        source_parent.leaf(),
        destination_parent.leaf(),
        &destination_path,
    )?;
    Ok(MovedManagedNode {
        source,
        destination,
        identity: after.identity,
        kind: after.kind,
    })
}

/// Hashes and deletes one exact regular single-link file through the same exclusive handle.
///
/// The operation is intended for signed transient processor sidecars. It never follows links and
/// never deletes a path merely because a prior path-based audit approved it. On Windows the file
/// is marked for deletion by handle while replacement, rename and writers are denied.
pub(super) fn remove_verified_managed_file(
    root: &Path,
    relative: &RelativeManagedPath,
    expected: &FileDigests,
) -> ManagedFsResult<()> {
    let parent_chain = GuardedDirectoryChain::open_parent(root, relative)?;
    let path = relative.join_to(parent_chain.root_path());
    let mut file = open_file_for_verified_removal(&path)?;
    let before = node_info(&file, &path)?;
    before.require_regular_single_link(&path)?;
    verify_handle_path(&file, &path)?;
    if before.identity.volume_serial_number
        != parent_chain.leaf().info.identity.volume_serial_number
    {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed removal crossed a volume boundary: {}",
            path.display()
        )));
    }
    if before.size != expected.size {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed removal size does not match the signed value: {}",
            path.display()
        )));
    }

    file.seek(SeekFrom::Start(0))
        .map_err(|error| ManagedFsError::io("Cannot rewind verified removal file", &path, error))?;
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            ManagedFsError::io("Cannot hash verified removal file", &path, error)
        })?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| ManagedFsError::UnsafeNode("Managed removal size overflow".into()))?;
        if total > expected.size {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed removal file exceeded its signed size: {}",
                path.display()
            )));
        }
        sha1.update(&buffer[..read]);
        sha256.update(&buffer[..read]);
    }
    let actual = FileDigests {
        size: total,
        sha1: format!("{:x}", sha1.finalize()),
        sha256: format!("{:x}", sha256.finalize()),
    };
    if &actual != expected {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed removal digests do not match the signed values: {}",
            path.display()
        )));
    }
    verify_handle_path(&file, &path)?;
    let after = node_info(&file, &path)?;
    if after.identity != before.identity
        || after.kind != ManagedNodeKind::File
        || after.size != before.size
        || after.number_of_links != 1
        || after.reparse_tag != 0
    {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed removal file changed while it was hashed: {}",
            path.display()
        )));
    }

    delete_open_file(&file, &path)?;
    drop(file);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(ManagedFsError::UnsafeNode(format!(
                "A filesystem node appeared at a just-deleted managed path: {}",
                path.display()
            )))
        }
        Err(error) => {
            return Err(ManagedFsError::io(
                "Cannot confirm verified managed removal",
                &path,
                error,
            ))
        }
    }
    parent_chain.leaf().sync_directory().map_err(|error| {
        ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination: path,
            detail: format!("verified removal parent flush failed: {error}"),
        }
    })
}

/// Recursively removes one exact, bounded managed directory tree.
///
/// This is the destructive primitive used by processor-workspace garbage collection. On Windows
/// it first opens the root and every descendant through no-follow, delete-capable handles which
/// deny concurrent writers and deletion. The complete tree is then audited (including a second
/// exact topology/identity pass) before the first delete disposition is issued. Consequently an
/// unsafe descendant, a stale root identity or a policy-bound violation cannot cause partial
/// deletion. Files and then directories are removed by their already-validated handles, with
/// directories ordered deepest-first, and the surviving parent directory is flushed last.
pub(super) fn remove_bounded_managed_directory_tree(
    root: &Path,
    relative: &RelativeManagedPath,
    expected_root_identity: &FileIdentity,
    limits: ManagedDirectoryRemovalLimits,
) -> ManagedFsResult<ManagedDirectoryRemovalSummary> {
    remove_bounded_managed_directory_tree_with(
        root,
        relative,
        expected_root_identity,
        limits,
        || Ok(()),
    )
}

#[cfg(windows)]
struct ManagedRemovalNode {
    path: PathBuf,
    depth: usize,
    handle: Option<File>,
    info: NodeInfo,
    children: Option<std::collections::BTreeSet<String>>,
}

#[cfg(windows)]
fn remove_bounded_managed_directory_tree_with<F>(
    root: &Path,
    relative: &RelativeManagedPath,
    expected_root_identity: &FileIdentity,
    limits: ManagedDirectoryRemovalLimits,
    before_delete: F,
) -> ManagedFsResult<ManagedDirectoryRemovalSummary>
where
    F: FnOnce() -> ManagedFsResult<()>,
{
    use std::collections::VecDeque;

    if limits.max_entries == 0 {
        return Err(ManagedFsError::InvalidPath(
            "Managed recursive-removal entry limit must include the root".into(),
        ));
    }

    // Keep the parent chain live for the complete operation. In particular, the exact root path
    // cannot be renamed together with an ancestor while we acquire and validate the tree handles.
    let parent_chain = GuardedDirectoryChain::open_parent(root, relative)?;
    let root_path = relative.join_to(parent_chain.root_path());
    let root_handle = open_node_for_recursive_removal(&root_path)?;
    let root_info = node_info(&root_handle, &root_path)?;
    root_info.require_real_directory(&root_path)?;
    verify_handle_path(&root_handle, &root_path)?;
    if &root_info.identity != expected_root_identity {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed recursive-removal root identity changed: {}",
            root_path.display()
        )));
    }
    if root_info.identity.volume_serial_number
        != parent_chain.leaf().info.identity.volume_serial_number
    {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed recursive-removal root crossed a volume boundary: {}",
            root_path.display()
        )));
    }
    if root_info.allocation_size > limits.max_allocated_bytes {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed recursive-removal tree exceeds its allocated-byte limit: {}",
            root_path.display()
        )));
    }

    let root_volume = root_info.identity.volume_serial_number;
    let mut summary = ManagedDirectoryRemovalSummary {
        entries: 1,
        allocated_bytes: root_info.allocation_size,
        max_depth: 0,
    };
    let mut nodes = vec![ManagedRemovalNode {
        path: root_path.clone(),
        depth: 0,
        handle: Some(root_handle),
        info: root_info,
        children: None,
    }];
    let mut pending_directories = VecDeque::from([0_usize]);

    // Audit and retain a DELETE-capable, no-follow handle for every node. No namespace or file
    // mutation happens anywhere in this phase, including on all error exits.
    while let Some(directory_index) = pending_directories.pop_front() {
        let directory_path = nodes[directory_index].path.clone();
        let directory_depth = nodes[directory_index].depth;
        let child_names = read_validated_directory_child_names(&directory_path)?;
        nodes[directory_index].children = Some(child_names.iter().cloned().collect());

        for child_name in child_names {
            let depth = directory_depth.checked_add(1).ok_or_else(|| {
                ManagedFsError::UnsafeNode("Managed recursive-removal depth overflowed".into())
            })?;
            if depth > limits.max_depth {
                return Err(ManagedFsError::UnsafeNode(format!(
                    "Managed recursive-removal tree exceeds its depth limit: {}",
                    directory_path.join(&child_name).display()
                )));
            }
            let path = directory_path.join(&child_name);
            let handle = open_node_for_recursive_removal(&path)?;
            let info = node_info(&handle, &path)?;
            match info.kind {
                ManagedNodeKind::Directory => info.require_real_directory(&path)?,
                ManagedNodeKind::File => {
                    use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY;
                    info.require_regular_single_link(&path)?;
                    // Legacy handle disposition can be rejected for a read-only file. Treat that
                    // attribute as unsafe during the all-or-nothing pre-audit so it can never be
                    // discovered only after earlier siblings have already been deleted.
                    if info.attributes & FILE_ATTRIBUTE_READONLY.0 != 0 {
                        return Err(ManagedFsError::UnsafeNode(format!(
                            "Read-only files require quarantine policy repair before recursive removal: {}",
                            path.display()
                        )));
                    }
                }
            }
            verify_handle_path(&handle, &path)?;
            if info.identity.volume_serial_number != root_volume {
                return Err(ManagedFsError::UnsafeNode(format!(
                    "Managed recursive-removal tree crossed a volume boundary: {}",
                    path.display()
                )));
            }

            let entries = summary.entries.checked_add(1).ok_or_else(|| {
                ManagedFsError::UnsafeNode(
                    "Managed recursive-removal entry count overflowed".into(),
                )
            })?;
            if entries > limits.max_entries {
                return Err(ManagedFsError::UnsafeNode(format!(
                    "Managed recursive-removal tree exceeds its entry limit: {}",
                    path.display()
                )));
            }
            let allocated_bytes = summary
                .allocated_bytes
                .checked_add(info.allocation_size)
                .ok_or_else(|| {
                    ManagedFsError::UnsafeNode(
                        "Managed recursive-removal allocated bytes overflowed".into(),
                    )
                })?;
            if allocated_bytes > limits.max_allocated_bytes {
                return Err(ManagedFsError::UnsafeNode(format!(
                    "Managed recursive-removal tree exceeds its allocated-byte limit: {}",
                    path.display()
                )));
            }
            summary.entries = entries;
            summary.allocated_bytes = allocated_bytes;
            summary.max_depth = summary.max_depth.max(depth);

            let is_directory = info.kind == ManagedNodeKind::Directory;
            let index = nodes.len();
            nodes.push(ManagedRemovalNode {
                path,
                depth,
                handle: Some(handle),
                info,
                children: None,
            });
            if is_directory {
                pending_directories.push_back(index);
            }
        }
    }

    before_delete()?;
    parent_chain.revalidate()?;

    // Re-prove every handle identity and exact directory membership after the complete audit and
    // immediately before the first destructive call. The exclusive handles make overwrite,
    // replacement and deletion attempts fail; this pass also catches a newly-created child.
    for node in &nodes {
        let handle = node
            .handle
            .as_ref()
            .expect("all recursive-removal handles are live before deletion");
        verify_handle_path(handle, &node.path)?;
        let current = node_info(handle, &node.path)?;
        if current != node.info {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed recursive-removal node changed during audit: {}",
                node.path.display()
            )));
        }
        if node.info.kind == ManagedNodeKind::Directory {
            let current_children = read_validated_directory_child_names(&node.path)?
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            if node.children.as_ref() != Some(&current_children) {
                return Err(ManagedFsError::UnsafeNode(format!(
                    "Managed recursive-removal directory membership changed during audit: {}",
                    node.path.display()
                )));
            }
        }
    }

    let mut file_indices = nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| (node.info.kind == ManagedNodeKind::File).then_some(index))
        .collect::<Vec<_>>();
    file_indices.sort_unstable_by_key(|&index| std::cmp::Reverse(nodes[index].depth));
    for index in file_indices {
        let node = &mut nodes[index];
        let handle = node
            .handle
            .take()
            .expect("an audited recursive-removal file has one live handle");
        delete_open_node(&handle, &node.path)?;
        drop(handle);
        confirm_managed_node_absent(&node.path)?;
    }

    let mut directory_indices = nodes
        .iter()
        .enumerate()
        .filter_map(|(index, node)| (node.info.kind == ManagedNodeKind::Directory).then_some(index))
        .collect::<Vec<_>>();
    directory_indices.sort_unstable_by_key(|&index| std::cmp::Reverse(nodes[index].depth));
    for index in directory_indices {
        let node = &mut nodes[index];
        if !read_validated_directory_child_names(&node.path)?.is_empty() {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed recursive-removal directory was not empty at deletion: {}",
                node.path.display()
            )));
        }
        let handle = node
            .handle
            .take()
            .expect("an audited recursive-removal directory has one live handle");
        delete_open_node(&handle, &node.path)?;
        drop(handle);
        confirm_managed_node_absent(&node.path)?;
    }

    parent_chain.leaf().sync_directory().map_err(|error| {
        ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination: root_path,
            detail: format!("recursive-removal parent flush failed: {error}"),
        }
    })?;
    Ok(summary)
}

#[cfg(not(windows))]
fn remove_bounded_managed_directory_tree_with<F>(
    _root: &Path,
    _relative: &RelativeManagedPath,
    _expected_root_identity: &FileIdentity,
    _limits: ManagedDirectoryRemovalLimits,
    _before_delete: F,
) -> ManagedFsResult<ManagedDirectoryRemovalSummary>
where
    F: FnOnce() -> ManagedFsResult<()>,
{
    Err(ManagedFsError::Unsupported(
        "Bounded managed-directory removal requires Windows handle semantics".into(),
    ))
}

/// Removes one already-authorized garbage node without weakening the strict recursive remover.
///
/// This sink is intended for completed reconcile-operation state only. Reparse points are opaque
/// leaves and are never enumerated, named streams fail closed before mutation, and read-only
/// nodes are deleted through `FileDispositionInfoEx`. The whole bounded namespace is
/// handle-audited twice before the first deletion, so an unsafe identity, hard link, named stream,
/// case collision or limit violation leaves the tree untouched.
pub(super) fn remove_bounded_managed_garbage_tree(
    root: &Path,
    relative: &RelativeManagedPath,
    expected_root_identity: &FileIdentity,
    limits: ManagedDirectoryRemovalLimits,
) -> ManagedFsResult<ManagedDirectoryRemovalSummary> {
    remove_bounded_managed_garbage_tree_with(
        root,
        relative,
        expected_root_identity,
        limits,
        || Ok(()),
        |_| Ok(()),
    )
}

#[cfg(windows)]
fn validate_garbage_node(info: &NodeInfo, path: &Path) -> ManagedFsResult<bool> {
    if info.named_streams != 0 {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Named streams are not removable garbage: {}",
            path.display()
        )));
    }
    if info.reparse_tag != 0 {
        if info.number_of_links != 1 {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Hard-linked reparse garbage is not removable: {}",
                path.display()
            )));
        }
        return Ok(false);
    }
    match info.kind {
        ManagedNodeKind::Directory => {
            info.require_real_directory(path)?;
            Ok(true)
        }
        ManagedNodeKind::File => {
            info.require_regular_single_link(path)?;
            Ok(false)
        }
    }
}

/// A non-cloneable, handle-owning proof that one exact subtree satisfied a bounded no-follow
/// audit. It is accounting evidence only; moving the subtree requires binding it to an exact
/// destination through `prepare_bounded_managed_tree_move`.
#[cfg(windows)]
pub(super) struct BoundedManagedTreeLease {
    managed_root: PathBuf,
    managed_root_identity: FileIdentity,
    source: RelativeManagedPath,
    source_path: PathBuf,
    handle: File,
    root_info: NodeInfo,
    snapshot: ManagedGarbageTreeSnapshot,
    limits: ManagedDirectoryRemovalLimits,
}

#[cfg(not(windows))]
pub(super) struct BoundedManagedTreeLease {
    summary: ManagedDirectoryRemovalSummary,
}

impl BoundedManagedTreeLease {
    pub(super) fn summary(&self) -> ManagedDirectoryRemovalSummary {
        #[cfg(windows)]
        {
            self.snapshot.summary
        }
        #[cfg(not(windows))]
        {
            self.summary
        }
    }

    #[cfg(windows)]
    pub(super) fn revalidate(&self) -> ManagedFsResult<()> {
        verify_handle_path_allow_reparse(&self.handle, &self.source_path)?;
        let current = garbage_node_info(&self.handle, &self.source_path)?;
        if current != self.root_info {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Bounded managed tree root changed: {}",
                self.source_path.display()
            )));
        }
        let mut accumulator = ManagedGarbageTreeAccumulator::new();
        audit_managed_garbage_node(
            &self.source_path,
            "",
            0,
            current.identity.volume_serial_number,
            self.limits,
            &self.handle,
            current,
            &mut accumulator,
        )?;
        if accumulator.finish() != self.snapshot {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Bounded managed tree changed after preflight: {}",
                self.source_path.display()
            )));
        }
        Ok(())
    }

    #[cfg(not(windows))]
    pub(super) fn revalidate(&self) -> ManagedFsResult<()> {
        Err(ManagedFsError::Unsupported(
            "Bounded managed-tree leases require Windows handle semantics".into(),
        ))
    }
}

/// Exact destination-bound capability for one whole-tree no-replace move.
#[cfg(windows)]
pub(super) struct BoundedManagedTreeMoveAuthority {
    lease: BoundedManagedTreeLease,
    destination: RelativeManagedPath,
    destination_path: PathBuf,
}

#[cfg(not(windows))]
pub(super) struct BoundedManagedTreeMoveAuthority;

pub(super) struct BoundedManagedTreeMoveRequest<'a> {
    pub(super) source: RelativeManagedPath,
    pub(super) expected_identity: &'a FileIdentity,
    pub(super) expected_kind: ManagedNodeKind,
    pub(super) expected_reparse_tag: u32,
    pub(super) destination_depth_within_cleanup_root: usize,
    pub(super) destination: RelativeManagedPath,
    pub(super) limits: ManagedDirectoryRemovalLimits,
}

#[cfg(windows)]
struct BoundedManagedTreeLeaseRequest<'a> {
    source: RelativeManagedPath,
    expected_identity: &'a FileIdentity,
    expected_kind: ManagedNodeKind,
    expected_reparse_tag: u32,
    limits: ManagedDirectoryRemovalLimits,
    move_capable: bool,
}

pub(super) fn lease_bounded_managed_tree(
    root: &Path,
    source: RelativeManagedPath,
    expected_identity: &FileIdentity,
    expected_kind: ManagedNodeKind,
    expected_reparse_tag: u32,
    limits: ManagedDirectoryRemovalLimits,
) -> ManagedFsResult<BoundedManagedTreeLease> {
    #[cfg(windows)]
    {
        lease_bounded_managed_tree_windows(
            root,
            BoundedManagedTreeLeaseRequest {
                source,
                expected_identity,
                expected_kind,
                expected_reparse_tag,
                limits,
                move_capable: false,
            },
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (
            root,
            source,
            expected_identity,
            expected_kind,
            expected_reparse_tag,
            limits,
        );
        Err(ManagedFsError::Unsupported(
            "Bounded managed-tree leases require Windows handle semantics".into(),
        ))
    }
}

#[cfg(windows)]
fn lease_bounded_managed_tree_windows(
    root: &Path,
    request: BoundedManagedTreeLeaseRequest<'_>,
) -> ManagedFsResult<BoundedManagedTreeLease> {
    let BoundedManagedTreeLeaseRequest {
        source,
        expected_identity,
        expected_kind,
        expected_reparse_tag,
        limits,
        move_capable,
    } = request;
    if limits.max_entries == 0 {
        return Err(ManagedFsError::InvalidPath(
            "Bounded managed-tree lease must include its root".into(),
        ));
    }
    let parent_chain = GuardedDirectoryChain::open_parent(root, &source)?;
    let source_path = source.join_to(parent_chain.root_path());
    let handle = if move_capable {
        open_node_for_recursive_removal(&source_path)?
    } else {
        open_node_for_bounded_tree_accounting(&source_path)?
    };
    let root_info = garbage_node_info(&handle, &source_path)?;
    verify_handle_path_allow_reparse(&handle, &source_path)?;
    if &root_info.identity != expected_identity
        || root_info.kind != expected_kind
        || root_info.reparse_tag != expected_reparse_tag
    {
        return Err(ManagedFsError::UnsafeNode(
            "Bounded managed-tree root no longer has its audited identity or class".into(),
        ));
    }
    if root_info.identity.volume_serial_number
        != parent_chain.leaf().info.identity.volume_serial_number
    {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Bounded managed tree crossed a volume boundary: {}",
            source_path.display()
        )));
    }
    let mut accumulator = ManagedGarbageTreeAccumulator::new();
    audit_managed_garbage_node(
        &source_path,
        "",
        0,
        root_info.identity.volume_serial_number,
        limits,
        &handle,
        root_info.clone(),
        &mut accumulator,
    )?;
    let lease = BoundedManagedTreeLease {
        managed_root: parent_chain.root_path().to_path_buf(),
        managed_root_identity: parent_chain.root_identity().clone(),
        source,
        source_path,
        handle,
        root_info,
        snapshot: accumulator.finish(),
        limits,
    };
    parent_chain.revalidate()?;
    lease.revalidate()?;
    Ok(lease)
}

pub(super) fn prepare_bounded_managed_tree_move(
    root: &Path,
    request: BoundedManagedTreeMoveRequest<'_>,
) -> ManagedFsResult<BoundedManagedTreeMoveAuthority> {
    let BoundedManagedTreeMoveRequest {
        source,
        expected_identity,
        expected_kind,
        expected_reparse_tag,
        destination_depth_within_cleanup_root,
        destination,
        limits,
    } = request;
    #[cfg(windows)]
    {
        if source.collision_key() == destination.collision_key() {
            return Err(ManagedFsError::Conflict(
                "Bounded managed-tree source and destination collide on Windows".into(),
            ));
        }
        if source.is_prefix_of(&destination) {
            return Err(ManagedFsError::InvalidPath(
                "Bounded managed-tree destination cannot be inside its source".into(),
            ));
        }
        let lease = lease_bounded_managed_tree_windows(
            root,
            BoundedManagedTreeLeaseRequest {
                source,
                expected_identity,
                expected_kind,
                expected_reparse_tag,
                limits,
                move_capable: true,
            },
        )?;
        let relocated_depth = lease
            .summary()
            .max_depth
            .checked_add(destination_depth_within_cleanup_root)
            .ok_or_else(|| {
                ManagedFsError::UnsafeNode("Bounded managed-tree relocated depth overflowed".into())
            })?;
        if relocated_depth > limits.max_depth {
            return Err(ManagedFsError::UnsafeNode(
                "Bounded managed tree would exceed cleanup depth after relocation".into(),
            ));
        }
        let destination_parent = GuardedDirectoryChain::open_parent_snapshot(root, &destination)?;
        if destination_parent.root_identity() != &lease.managed_root_identity {
            return Err(ManagedFsError::UnsafeNode(
                "Bounded managed-tree destination belongs to another managed root".into(),
            ));
        }
        let destination_path = destination.join_to(destination_parent.root_path());
        destination_parent.revalidate()?;
        Ok(BoundedManagedTreeMoveAuthority {
            lease,
            destination,
            destination_path,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = (
            root,
            source,
            expected_identity,
            expected_kind,
            expected_reparse_tag,
            destination_depth_within_cleanup_root,
            destination,
            limits,
        );
        Err(ManagedFsError::Unsupported(
            "Bounded managed-tree moves require Windows handle semantics".into(),
        ))
    }
}

impl BoundedManagedTreeMoveAuthority {
    #[cfg(windows)]
    pub(super) fn summary(&self) -> ManagedDirectoryRemovalSummary {
        self.lease.summary()
    }

    #[cfg(windows)]
    pub(super) fn revalidate(&self) -> ManagedFsResult<()> {
        self.lease.revalidate()
    }

    #[cfg(windows)]
    pub(super) fn move_no_replace(self) -> ManagedFsResult<MovedManagedNode> {
        self.revalidate()?;
        let source_parent = GuardedDirectoryChain::open_parent_snapshot(
            &self.lease.managed_root,
            &self.lease.source,
        )?;
        let destination_parent = GuardedDirectoryChain::open_parent_snapshot(
            &self.lease.managed_root,
            &self.destination,
        )?;
        ensure_same_root_and_volume(&source_parent, &destination_parent)?;
        if source_parent.root_identity() != &self.lease.managed_root_identity {
            return Err(ManagedFsError::UnsafeNode(
                "Bounded managed-tree root changed before move".into(),
            ));
        }
        source_parent.revalidate()?;
        destination_parent.revalidate()?;
        self.lease.revalidate()?;
        rename_handle_relative(
            &self.lease.handle,
            &destination_parent.leaf()._handle,
            self.destination.file_name(),
            &self.destination_path,
            ManagedRenameMode::NoReplace,
        )?;
        // The namespace mutation must become durable before the recursive post-move audit. If the
        // process dies during that audit, recovery can decide from the exact source/destination
        // namespaces instead of depending on an unflushed rename.
        flush_rename_parents(
            source_parent.leaf(),
            destination_parent.leaf(),
            &self.destination_path,
        )?;
        if let Err(error) =
            verify_handle_path_allow_reparse(&self.lease.handle, &self.destination_path)
        {
            return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: self.destination_path,
                detail: format!("cannot verify bounded moved-tree handle: {error}"),
            });
        }
        let after =
            garbage_node_info(&self.lease.handle, &self.destination_path).map_err(|error| {
                ManagedFsError::AppliedButDurabilityUnconfirmed {
                    destination: self.destination_path.clone(),
                    detail: format!("cannot inspect bounded moved-tree handle: {error}"),
                }
            })?;
        if after != self.lease.root_info {
            return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: self.destination_path,
                detail: "bounded moved-tree root identity changed".into(),
            });
        }
        let mut accumulator = ManagedGarbageTreeAccumulator::new();
        if let Err(error) = audit_managed_garbage_node(
            &self.destination_path,
            "",
            0,
            after.identity.volume_serial_number,
            self.lease.limits,
            &self.lease.handle,
            after.clone(),
            &mut accumulator,
        ) {
            return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: self.destination_path,
                detail: format!("cannot audit bounded tree after move: {error}"),
            });
        }
        if accumulator.finish() != self.lease.snapshot {
            return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: self.destination_path,
                detail: "bounded tree changed across its whole-tree move".into(),
            });
        }
        Ok(MovedManagedNode {
            source: self.lease.source,
            destination: self.destination,
            identity: after.identity,
            kind: after.kind,
        })
    }

    #[cfg(not(windows))]
    pub(super) fn summary(&self) -> ManagedDirectoryRemovalSummary {
        unreachable!("bounded managed-tree move authority is never constructed off Windows")
    }

    #[cfg(not(windows))]
    pub(super) fn revalidate(&self) -> ManagedFsResult<()> {
        Err(ManagedFsError::Unsupported(
            "Bounded managed-tree moves require Windows handle semantics".into(),
        ))
    }

    #[cfg(not(windows))]
    pub(super) fn move_no_replace(self) -> ManagedFsResult<MovedManagedNode> {
        Err(ManagedFsError::Unsupported(
            "Bounded managed-tree moves require Windows handle semantics".into(),
        ))
    }
}

#[cfg(windows)]
fn remove_bounded_managed_garbage_tree_with<F, G>(
    root: &Path,
    relative: &RelativeManagedPath,
    expected_root_identity: &FileIdentity,
    limits: ManagedDirectoryRemovalLimits,
    before_delete: F,
    before_first_leaf_disposition: G,
) -> ManagedFsResult<ManagedDirectoryRemovalSummary>
where
    F: FnOnce() -> ManagedFsResult<()>,
    G: FnOnce(&Path) -> ManagedFsResult<()>,
{
    if limits.max_entries == 0 {
        return Err(ManagedFsError::InvalidPath(
            "Managed garbage-removal entry limit must include the root".into(),
        ));
    }
    let parent_chain = GuardedDirectoryChain::open_parent(root, relative)?;
    let root_path = relative.join_to(parent_chain.root_path());
    let parent_volume = parent_chain.leaf().info.identity.volume_serial_number;
    let first =
        audit_managed_garbage_tree(&root_path, expected_root_identity, parent_volume, limits)?;
    before_delete()?;
    parent_chain.revalidate()?;
    let second =
        audit_managed_garbage_tree(&root_path, expected_root_identity, parent_volume, limits)?;
    if second != first {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed garbage tree changed between complete audits: {}",
            root_path.display()
        )));
    }
    parent_chain.revalidate()?;

    let mut before_first_leaf_disposition = Some(before_first_leaf_disposition);
    let mut applied = false;
    let deletion = delete_managed_garbage_tree_streaming(
        &root_path,
        expected_root_identity,
        parent_volume,
        limits,
        &mut before_first_leaf_disposition,
        &mut applied,
    );
    let deleted = match deletion {
        Ok(snapshot) => snapshot,
        Err(error) if applied => {
            return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: root_path.clone(),
                detail: format!("managed garbage deletion stopped after mutation: {error}"),
            })
        }
        Err(error) => return Err(error),
    };
    if deleted != second {
        return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination: root_path.clone(),
            detail: "managed garbage tree changed after its final complete audit".into(),
        });
    }

    parent_chain.leaf().sync_directory().map_err(|error| {
        ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination: root_path.clone(),
            detail: format!("managed garbage parent flush failed: {error}"),
        }
    })?;
    Ok(first.summary)
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ManagedGarbageTreeSnapshot {
    summary: ManagedDirectoryRemovalSummary,
    digest: [u8; 32],
}

#[cfg(windows)]
struct ManagedGarbageTreeAccumulator {
    summary: ManagedDirectoryRemovalSummary,
    discovered_entries: usize,
    digest: Sha256,
}

#[cfg(windows)]
impl ManagedGarbageTreeAccumulator {
    fn new() -> Self {
        Self {
            summary: ManagedDirectoryRemovalSummary {
                entries: 0,
                allocated_bytes: 0,
                max_depth: 0,
            },
            discovered_entries: 0,
            digest: Sha256::new(),
        }
    }

    fn charge_and_hash(
        &mut self,
        path: &Path,
        relative_key: &str,
        depth: usize,
        info: &NodeInfo,
        limits: ManagedDirectoryRemovalLimits,
    ) -> ManagedFsResult<bool> {
        if depth > limits.max_depth {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed garbage tree exceeds its depth limit: {}",
                path.display()
            )));
        }
        let entries = self.summary.entries.checked_add(1).ok_or_else(|| {
            ManagedFsError::UnsafeNode("Managed garbage entry count overflowed".into())
        })?;
        if entries > limits.max_entries {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed garbage tree exceeds its entry limit: {}",
                path.display()
            )));
        }
        if self.discovered_entries == 0 {
            self.discovered_entries = 1;
        }
        if entries > self.discovered_entries {
            return Err(ManagedFsError::UnsafeNode(
                "Managed garbage traversal charged an undiscovered entry".into(),
            ));
        }
        let allocated_bytes = self
            .summary
            .allocated_bytes
            .checked_add(info.allocation_size)
            .ok_or_else(|| {
                ManagedFsError::UnsafeNode("Managed garbage allocation overflowed".into())
            })?;
        if allocated_bytes > limits.max_allocated_bytes {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed garbage tree exceeds its allocated-byte limit: {}",
                path.display()
            )));
        }
        let key_len = u64::try_from(relative_key.len()).map_err(|_| {
            ManagedFsError::UnsafeNode("Managed garbage digest path length overflowed".into())
        })?;
        let digest_depth = u64::try_from(depth).map_err(|_| {
            ManagedFsError::UnsafeNode("Managed garbage digest depth overflowed".into())
        })?;
        self.digest.update(key_len.to_le_bytes());
        self.digest.update(relative_key.as_bytes());
        self.digest.update(digest_depth.to_le_bytes());
        self.digest
            .update(info.identity.volume_serial_number.to_le_bytes());
        self.digest.update(info.identity.file_id);
        self.digest.update([match info.kind {
            ManagedNodeKind::File => 0,
            ManagedNodeKind::Directory => 1,
        }]);
        self.digest.update(info.reparse_tag.to_le_bytes());
        self.digest.update(info.number_of_links.to_le_bytes());
        self.digest.update(info.size.to_le_bytes());
        self.digest.update(info.allocation_size.to_le_bytes());
        self.digest.update(info.named_streams.to_le_bytes());
        self.digest
            .update([u8::from(info.case_sensitive_directory)]);
        self.summary.entries = entries;
        self.summary.allocated_bytes = allocated_bytes;
        self.summary.max_depth = self.summary.max_depth.max(depth);
        validate_garbage_node(info, path)
    }

    fn remaining_discovery_capacity(
        &self,
        limits: ManagedDirectoryRemovalLimits,
    ) -> ManagedFsResult<usize> {
        limits
            .max_entries
            .checked_sub(self.discovered_entries)
            .ok_or_else(|| {
                ManagedFsError::UnsafeNode("Managed garbage discovery count underflowed".into())
            })
    }

    fn reserve_children(
        &mut self,
        count: usize,
        limits: ManagedDirectoryRemovalLimits,
    ) -> ManagedFsResult<()> {
        self.discovered_entries = self
            .discovered_entries
            .checked_add(count)
            .filter(|entries| *entries <= limits.max_entries)
            .ok_or_else(|| {
                ManagedFsError::UnsafeNode(
                    "Managed garbage discovery exceeds its entry limit".into(),
                )
            })?;
        Ok(())
    }

    fn finish(self) -> ManagedGarbageTreeSnapshot {
        debug_assert_eq!(self.summary.entries, self.discovered_entries);
        ManagedGarbageTreeSnapshot {
            summary: self.summary,
            digest: self.digest.finalize().into(),
        }
    }
}

#[cfg(windows)]
fn audit_managed_garbage_tree(
    root_path: &Path,
    expected_root_identity: &FileIdentity,
    parent_volume: u64,
    limits: ManagedDirectoryRemovalLimits,
) -> ManagedFsResult<ManagedGarbageTreeSnapshot> {
    let root_handle = open_node_for_recursive_removal(root_path)?;
    let root_info = garbage_node_info(&root_handle, root_path)?;
    verify_handle_path_allow_reparse(&root_handle, root_path)?;
    if &root_info.identity != expected_root_identity {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed garbage root identity changed: {}",
            root_path.display()
        )));
    }
    if root_info.identity.volume_serial_number != parent_volume {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed garbage root crossed a volume boundary: {}",
            root_path.display()
        )));
    }
    let root_volume = root_info.identity.volume_serial_number;
    let mut accumulator = ManagedGarbageTreeAccumulator::new();
    audit_managed_garbage_node(
        root_path,
        "",
        0,
        root_volume,
        limits,
        &root_handle,
        root_info,
        &mut accumulator,
    )?;
    Ok(accumulator.finish())
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn audit_managed_garbage_node(
    path: &Path,
    relative_key: &str,
    depth: usize,
    root_volume: u64,
    limits: ManagedDirectoryRemovalLimits,
    handle: &File,
    info: NodeInfo,
    accumulator: &mut ManagedGarbageTreeAccumulator,
) -> ManagedFsResult<()> {
    verify_handle_path_allow_reparse(handle, path)?;
    if info.identity.volume_serial_number != root_volume {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed garbage tree crossed a volume boundary: {}",
            path.display()
        )));
    }
    let traverse = accumulator.charge_and_hash(path, relative_key, depth, &info, limits)?;
    let child_names = if traverse {
        let remaining = accumulator.remaining_discovery_capacity(limits)?;
        let names = read_bounded_validated_directory_child_names(path, remaining)?;
        accumulator.reserve_children(names.len(), limits)?;
        names
    } else {
        Vec::new()
    };
    for child_name in &child_names {
        let child_path = path.join(child_name);
        let child_handle = open_node_for_recursive_removal(&child_path)?;
        let child_info = garbage_node_info(&child_handle, &child_path)?;
        let child_depth = depth.checked_add(1).ok_or_else(|| {
            ManagedFsError::UnsafeNode("Managed garbage-removal depth overflowed".into())
        })?;
        let child_key = if relative_key.is_empty() {
            child_name.clone()
        } else {
            format!("{relative_key}/{child_name}")
        };
        audit_managed_garbage_node(
            &child_path,
            &child_key,
            child_depth,
            root_volume,
            limits,
            &child_handle,
            child_info,
            accumulator,
        )?;
    }
    let current = garbage_node_info(handle, path)?;
    if current != info {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed garbage node changed during complete audit: {}",
            path.display()
        )));
    }
    if traverse
        && read_bounded_validated_directory_child_names(path, child_names.len())? != child_names
    {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed garbage directory membership changed during complete audit: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn delete_managed_garbage_tree_streaming<G>(
    root_path: &Path,
    expected_root_identity: &FileIdentity,
    parent_volume: u64,
    limits: ManagedDirectoryRemovalLimits,
    before_first_leaf_disposition: &mut Option<G>,
    applied: &mut bool,
) -> ManagedFsResult<ManagedGarbageTreeSnapshot>
where
    G: FnOnce(&Path) -> ManagedFsResult<()>,
{
    let root_handle = open_node_for_recursive_removal(root_path)?;
    let root_info = garbage_node_info(&root_handle, root_path)?;
    verify_handle_path_allow_reparse(&root_handle, root_path)?;
    if &root_info.identity != expected_root_identity
        || root_info.identity.volume_serial_number != parent_volume
    {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed garbage root changed before streaming deletion: {}",
            root_path.display()
        )));
    }
    let root_volume = root_info.identity.volume_serial_number;
    let mut accumulator = ManagedGarbageTreeAccumulator::new();
    delete_managed_garbage_node(
        root_path,
        "",
        0,
        root_volume,
        limits,
        root_handle,
        root_info,
        &mut accumulator,
        before_first_leaf_disposition,
        applied,
    )?;
    Ok(accumulator.finish())
}

#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn delete_managed_garbage_node<G>(
    path: &Path,
    relative_key: &str,
    depth: usize,
    root_volume: u64,
    limits: ManagedDirectoryRemovalLimits,
    handle: File,
    info: NodeInfo,
    accumulator: &mut ManagedGarbageTreeAccumulator,
    before_first_leaf_disposition: &mut Option<G>,
    applied: &mut bool,
) -> ManagedFsResult<()>
where
    G: FnOnce(&Path) -> ManagedFsResult<()>,
{
    verify_handle_path_allow_reparse(&handle, path)?;
    if info.identity.volume_serial_number != root_volume {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed garbage deletion crossed a volume boundary: {}",
            path.display()
        )));
    }
    let traverse = accumulator.charge_and_hash(path, relative_key, depth, &info, limits)?;
    let child_names = if traverse {
        let remaining = accumulator.remaining_discovery_capacity(limits)?;
        let names = read_bounded_validated_directory_child_names(path, remaining)?;
        accumulator.reserve_children(names.len(), limits)?;
        names
    } else {
        Vec::new()
    };
    for child_name in &child_names {
        let child_path = path.join(child_name);
        let child_handle = open_node_for_recursive_removal(&child_path)?;
        let child_info = garbage_node_info(&child_handle, &child_path)?;
        let child_depth = depth.checked_add(1).ok_or_else(|| {
            ManagedFsError::UnsafeNode("Managed garbage-removal depth overflowed".into())
        })?;
        let child_key = if relative_key.is_empty() {
            child_name.clone()
        } else {
            format!("{relative_key}/{child_name}")
        };
        delete_managed_garbage_node(
            &child_path,
            &child_key,
            child_depth,
            root_volume,
            limits,
            child_handle,
            child_info,
            accumulator,
            before_first_leaf_disposition,
            applied,
        )?;
    }
    if traverse {
        if !read_bounded_validated_directory_child_names(path, 0)?.is_empty() {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed garbage directory was not empty at disposition: {}",
                path.display()
            )));
        }
        let immediately_before = garbage_node_info(&handle, path)?;
        if immediately_before.identity != info.identity
            || immediately_before.kind != info.kind
            || immediately_before.reparse_tag != info.reparse_tag
            || immediately_before.named_streams != 0
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed garbage directory changed before disposition: {}",
                path.display()
            )));
        }
        delete_open_garbage_node(&handle, path)?;
        *applied = true;
        let after_disposition = garbage_node_info(&handle, path).map_err(|error| {
            ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: path.to_path_buf(),
                detail: format!("cannot audit garbage directory after disposition: {error}"),
            }
        })?;
        if after_disposition.identity != immediately_before.identity
            || after_disposition.kind != immediately_before.kind
            || after_disposition.reparse_tag != immediately_before.reparse_tag
            || after_disposition.allocation_size != immediately_before.allocation_size
            || after_disposition.named_streams != immediately_before.named_streams
        {
            return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: path.to_path_buf(),
                detail: "garbage directory stream state changed across disposition".into(),
            });
        }
    } else {
        let immediately_before = garbage_node_info(&handle, path)?;
        if immediately_before != info {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed garbage leaf changed before disposition: {}",
                path.display()
            )));
        }
        if let Some(hook) = before_first_leaf_disposition.take() {
            hook(path)?;
        }
        delete_open_garbage_node(&handle, path)?;
        *applied = true;
        let after_disposition = garbage_node_info(&handle, path).map_err(|error| {
            ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: path.to_path_buf(),
                detail: format!("cannot audit garbage leaf after disposition: {error}"),
            }
        })?;
        if after_disposition.identity != info.identity
            || after_disposition.kind != info.kind
            || after_disposition.reparse_tag != info.reparse_tag
            || after_disposition.size != info.size
            || after_disposition.allocation_size != info.allocation_size
            || after_disposition.named_streams != info.named_streams
            || (info.kind == ManagedNodeKind::File && after_disposition.number_of_links != 0)
        {
            return Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: path.to_path_buf(),
                detail: "garbage leaf stream/link state changed across disposition".into(),
            });
        }
    }
    drop(handle);
    confirm_managed_node_absent(path)
}

#[cfg(windows)]
fn read_bounded_validated_directory_child_names(
    path: &Path,
    max_children: usize,
) -> ManagedFsResult<Vec<String>> {
    let max_children = max_children.min(MAX_RECONCILE_MUTATIONS);
    let entries = fs::read_dir(path).map_err(|error| {
        ManagedFsError::io("Cannot enumerate managed garbage directory", path, error)
    })?;
    let mut names = Vec::new();
    let mut collision_keys = std::collections::BTreeSet::new();
    for entry in entries {
        if names.len() == max_children {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed garbage directory exceeds its remaining entry bound: {}",
                path.display()
            )));
        }
        let entry = entry.map_err(|error| {
            ManagedFsError::io("Cannot read managed garbage directory entry", path, error)
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            ManagedFsError::UnsafeNode(format!(
                "Managed garbage directory contains a non-Unicode name: {}",
                path.display()
            ))
        })?;
        validate_component(&name)?;
        if !collision_keys.insert(name.to_lowercase()) {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed garbage directory contains colliding names: {}",
                path.display()
            )));
        }
        names.push(name);
    }
    names.sort_unstable();
    Ok(names)
}

#[cfg(not(windows))]
fn remove_bounded_managed_garbage_tree_with<F, G>(
    _root: &Path,
    _relative: &RelativeManagedPath,
    _expected_root_identity: &FileIdentity,
    _limits: ManagedDirectoryRemovalLimits,
    _before_delete: F,
    _before_first_leaf_disposition: G,
) -> ManagedFsResult<ManagedDirectoryRemovalSummary>
where
    F: FnOnce() -> ManagedFsResult<()>,
    G: FnOnce(&Path) -> ManagedFsResult<()>,
{
    Err(ManagedFsError::Unsupported(
        "Bounded managed-garbage removal requires Windows handle semantics".into(),
    ))
}

#[cfg(windows)]
fn read_validated_directory_child_names(path: &Path) -> ManagedFsResult<Vec<String>> {
    let entries = fs::read_dir(path).map_err(|error| {
        ManagedFsError::io(
            "Cannot enumerate managed recursive-removal directory",
            path,
            error,
        )
    })?;
    let mut names = Vec::new();
    let mut collision_keys = std::collections::BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            ManagedFsError::io(
                "Cannot read managed recursive-removal directory entry",
                path,
                error,
            )
        })?;
        let name = entry.file_name().into_string().map_err(|_| {
            ManagedFsError::UnsafeNode(format!(
                "Managed recursive-removal directory contains a non-Unicode name: {}",
                path.display()
            ))
        })?;
        validate_component(&name)?;
        let collision_key = name.to_lowercase();
        if !collision_keys.insert(collision_key) {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed recursive-removal directory contains colliding names: {}",
                path.display()
            )));
        }
        names.push(name);
    }
    names.sort_unstable();
    Ok(names)
}

#[cfg(windows)]
fn confirm_managed_node_absent(path: &Path) -> ManagedFsResult<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(ManagedFsError::UnsafeNode(format!(
            "A filesystem node appeared at a just-deleted managed path: {}",
            path.display()
        ))),
        Err(error) => Err(ManagedFsError::io(
            "Cannot confirm managed recursive removal",
            path,
            error,
        )),
    }
}

/// Moves one exact filesystem object into an existing real quarantine directory. The source is
/// opened with no-follow semantics and renamed by handle on Windows. Reparse points are moved as
/// objects and are never traversed. This function never recursively deletes anything.
pub(super) fn quarantine_node(
    root: &Path,
    source: RelativeManagedPath,
    quarantine_directory: &RelativeManagedPath,
) -> ManagedFsResult<QuarantinedNode> {
    if source.is_prefix_of(quarantine_directory) {
        return Err(ManagedFsError::InvalidPath(
            "Quarantine directory cannot be inside the quarantined node".into(),
        ));
    }
    // Open the quarantine directory before choosing the child name, both to enforce that it is a
    // real directory and to avoid silently creating a misspelled/case-colliding destination.
    let _quarantine_guard = GuardedDirectoryChain::open(root, quarantine_directory)?;
    let destination = quarantine_directory.join_component(&Uuid::new_v4().to_string())?;
    let moved = move_managed_node_no_replace(root, source.clone(), destination.clone())?;
    Ok(QuarantinedNode {
        source,
        destination,
        identity: moved.identity,
        kind: moved.kind,
    })
}

/// Quarantines a node only if the handle opened for the rename still has the caller's audited
/// identity and kind. A mismatch is rejected before the namespace commit, leaving both the raced
/// source and the quarantine directory untouched. The expectation is checked again after rename
/// so a post-commit discrepancy is reported as applied-but-durability-unconfirmed without
/// returning a quarantine capability.
pub(super) fn quarantine_node_if_identity(
    root: &Path,
    source: RelativeManagedPath,
    quarantine_directory: &RelativeManagedPath,
    expected_identity: &FileIdentity,
    expected_kind: ManagedNodeKind,
) -> ManagedFsResult<QuarantinedNode> {
    if source.is_prefix_of(quarantine_directory) {
        return Err(ManagedFsError::InvalidPath(
            "Quarantine directory cannot be inside the quarantined node".into(),
        ));
    }
    let _quarantine_guard = GuardedDirectoryChain::open(root, quarantine_directory)?;
    let destination = quarantine_directory.join_component(&Uuid::new_v4().to_string())?;
    let moved = move_managed_node_no_replace_with_expected(
        root,
        source.clone(),
        destination.clone(),
        Some((expected_identity, expected_kind)),
    )?;
    Ok(QuarantinedNode {
        source,
        destination,
        identity: moved.identity,
        kind: moved.kind,
    })
}

fn ensure_same_root_and_volume(
    left: &GuardedDirectoryChain,
    right: &GuardedDirectoryChain,
) -> ManagedFsResult<()> {
    if left.root_path() != right.root_path() || left.root_identity() != right.root_identity() {
        return Err(ManagedFsError::UnsafeNode(
            "Managed rename roots do not identify the same directory".into(),
        ));
    }
    if left.leaf().info.identity.volume_serial_number
        != right.leaf().info.identity.volume_serial_number
    {
        return Err(ManagedFsError::UnsafeNode(
            "Managed rename cannot cross a volume boundary".into(),
        ));
    }
    Ok(())
}

fn flush_rename_parents(
    source_parent: &GuardedDirectory,
    destination_parent: &GuardedDirectory,
    destination: &Path,
) -> ManagedFsResult<()> {
    source_parent.sync_directory().map_err(|error| {
        ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination: destination.to_path_buf(),
            detail: format!("source directory flush failed: {error}"),
        }
    })?;
    if source_parent.info.identity != destination_parent.info.identity {
        destination_parent.sync_directory().map_err(|error| {
            ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: destination.to_path_buf(),
                detail: format!("destination directory flush failed: {error}"),
            }
        })?;
    }
    Ok(())
}

#[cfg(windows)]
fn positional_read(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buffer, offset)
}

#[cfg(unix)]
fn positional_read(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buffer, offset)
}

#[cfg(all(not(windows), not(unix)))]
fn positional_read(file: &File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    let mut clone = file.try_clone()?;
    clone.seek(SeekFrom::Start(offset))?;
    clone.read(buffer)
}

#[cfg(windows)]
fn open_directory_nofollow(path: &Path, delete: bool) -> ManagedFsResult<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
    };

    let mut access = FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0;
    if delete {
        access |= DELETE.0;
    }
    OpenOptions::new()
        .access_mode(access)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
        .map_err(|error| {
            ManagedFsError::io(
                "Cannot open managed directory without following links",
                path,
                error,
            )
        })
}

#[cfg(windows)]
fn open_directory_snapshot_nofollow(path: &Path) -> ManagedFsResult<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
    };

    OpenOptions::new()
        .access_mode(FILE_TRAVERSE.0 | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0)
        // Deny FILE_SHARE_DELETE to pin each parent namespace, but share write so the kernel's
        // relative target open and the identity-checked durability reopen can both succeed.
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
        .map_err(|error| {
            ManagedFsError::io(
                "Cannot open managed snapshot directory without following links",
                path,
                error,
            )
        })
}

#[cfg(not(windows))]
fn open_directory_nofollow(path: &Path, _delete: bool) -> ManagedFsResult<File> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| ManagedFsError::io("Cannot inspect managed directory", path, error))?;
    if !before.is_dir() || before.file_type().is_symlink() {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed directory is not a real directory: {}",
            path.display()
        )));
    }
    let file = File::open(path)
        .map_err(|error| ManagedFsError::io("Cannot open managed directory", path, error))?;
    let after = node_info(&file, path)?;
    if metadata_identity(&before) != after.identity {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed directory changed while opening: {}",
            path.display()
        )));
    }
    Ok(file)
}

#[cfg(not(windows))]
fn open_directory_snapshot_nofollow(path: &Path) -> ManagedFsResult<File> {
    open_directory_nofollow(path, false)
}

#[cfg(windows)]
fn open_immutable_file_nofollow(path: &Path) -> ManagedFsResult<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::{
        Foundation::GENERIC_READ,
        Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ},
    };
    OpenOptions::new()
        .access_mode(GENERIC_READ.0)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(|error| ManagedFsError::io("Cannot open immutable managed file", path, error))
}

#[cfg(not(windows))]
fn open_immutable_file_nofollow(path: &Path) -> ManagedFsResult<File> {
    let before = fs::symlink_metadata(path).map_err(|error| {
        ManagedFsError::io("Cannot inspect immutable managed file", path, error)
    })?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed file is not regular: {}",
            path.display()
        )));
    }
    let file = File::open(path)
        .map_err(|error| ManagedFsError::io("Cannot open immutable managed file", path, error))?;
    if metadata_identity(&before) != node_info(&file, path)?.identity {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed file changed while opening: {}",
            path.display()
        )));
    }
    Ok(file)
}

#[cfg(windows)]
fn create_exclusive_file(path: &Path) -> ManagedFsResult<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE},
        Storage::FileSystem::{DELETE, FILE_FLAG_OPEN_REPARSE_POINT, SYNCHRONIZE},
    };
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .access_mode(GENERIC_READ.0 | GENERIC_WRITE.0 | DELETE.0 | SYNCHRONIZE.0)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(|error| ManagedFsError::io("Cannot create exclusive managed file", path, error))
}

#[cfg(not(windows))]
fn create_exclusive_file(path: &Path) -> ManagedFsResult<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| ManagedFsError::io("Cannot create exclusive managed file", path, error))
}

#[cfg(windows)]
fn open_resumable_file_nofollow(path: &Path, create_new: bool) -> ManagedFsResult<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE},
        Storage::FileSystem::{DELETE, FILE_FLAG_OPEN_REPARSE_POINT, SYNCHRONIZE},
    };
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(create_new)
        .access_mode(GENERIC_READ.0 | GENERIC_WRITE.0 | DELETE.0 | SYNCHRONIZE.0)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
    options.open(path).map_err(|error| {
        ManagedFsError::io(
            "Cannot open managed resumable file without following links",
            path,
            error,
        )
    })
}

#[cfg(not(windows))]
fn open_resumable_file_nofollow(path: &Path, create_new: bool) -> ManagedFsResult<File> {
    if !create_new {
        let before = fs::symlink_metadata(path).map_err(|error| {
            ManagedFsError::io("Cannot inspect managed resumable file", path, error)
        })?;
        if !before.is_file() || before.file_type().is_symlink() {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable path is not a regular file: {}",
                path.display()
            )));
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| {
                ManagedFsError::io("Cannot open managed resumable file", path, error)
            })?;
        if metadata_identity(&before) != node_info(&file, path)?.identity {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed resumable file changed while opening: {}",
                path.display()
            )));
        }
        return Ok(file);
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| ManagedFsError::io("Cannot create managed resumable file", path, error))
}

#[cfg(windows)]
fn open_lock_file_nofollow(path: &Path, create_new: bool) -> ManagedFsResult<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE},
        Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
        },
    };
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(create_new)
        .access_mode(GENERIC_READ.0 | GENERIC_WRITE.0 | SYNCHRONIZE.0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
    options
        .open(path)
        .map_err(|error| ManagedFsError::io("Cannot open managed lock file", path, error))
}

#[cfg(not(windows))]
fn open_lock_file_nofollow(path: &Path, create_new: bool) -> ManagedFsResult<File> {
    if !create_new {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| ManagedFsError::io("Cannot inspect managed lock file", path, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed lock path is not a regular file: {}",
                path.display()
            )));
        }
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(create_new)
        .open(path)
        .map_err(|error| ManagedFsError::io("Cannot open managed lock file", path, error))
}

#[cfg(windows)]
fn open_for_handle_rename(path: &Path) -> ManagedFsResult<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
    };
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES.0 | DELETE.0 | SYNCHRONIZE.0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
        .map_err(|error| {
            ManagedFsError::io("Cannot open managed object for quarantine", path, error)
        })
}

#[cfg(not(windows))]
fn open_for_handle_rename(path: &Path) -> ManagedFsResult<File> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ManagedFsError::io("Cannot inspect managed object for quarantine", path, error)
    })?;
    if metadata.file_type().is_symlink() {
        return Err(ManagedFsError::Unsupported(format!(
            "Portable quarantine does not move symbolic links: {}",
            path.display()
        )));
    }
    OpenOptions::new().read(true).open(path).map_err(|error| {
        ManagedFsError::io("Cannot open managed object for quarantine", path, error)
    })
}

#[cfg(windows)]
fn open_file_for_verified_removal(path: &Path) -> ManagedFsResult<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::{
        Foundation::GENERIC_READ,
        Storage::FileSystem::{DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, SYNCHRONIZE},
    };
    OpenOptions::new()
        .read(true)
        .access_mode(GENERIC_READ.0 | DELETE.0 | SYNCHRONIZE.0)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(|error| {
            ManagedFsError::io("Cannot open managed file for verified removal", path, error)
        })
}

#[cfg(windows)]
fn open_node_for_bounded_tree_accounting(path: &Path) -> ManagedFsResult<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
    };

    // Accounting leases pin the accepted root namespace by denying share-delete, but do not ask
    // for DELETE access themselves. Sharing reads and writes keeps the root handle compatible
    // with the descendant parent-chain opens required by the same cumulative preflight. The
    // complete no-follow tree is audited again before the lease can authorize anything.
    OpenOptions::new()
        .access_mode(FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
        .map_err(|error| {
            ManagedFsError::io(
                "Cannot open managed node for bounded tree accounting",
                path,
                error,
            )
        })
}

#[cfg(windows)]
fn open_node_for_recursive_removal(path: &Path) -> ManagedFsResult<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, SYNCHRONIZE,
    };

    // FILE_SHARE_WRITE and FILE_SHARE_DELETE are deliberately absent. Every audited node remains
    // open this way until the destructive phase begins, so another process cannot overwrite,
    // truncate, rename or delete an accepted object behind the audit.
    OpenOptions::new()
        .access_mode(FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | DELETE.0 | SYNCHRONIZE.0)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
        .map_err(|error| {
            ManagedFsError::io(
                "Cannot open managed node for bounded recursive removal",
                path,
                error,
            )
        })
}

#[cfg(not(windows))]
fn open_file_for_verified_removal(path: &Path) -> ManagedFsResult<File> {
    open_immutable_file_nofollow(path)
}

#[cfg(windows)]
fn delete_open_file(file: &File, path: &Path) -> ManagedFsResult<()> {
    use std::{mem::size_of, os::windows::io::AsRawHandle};
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
        },
    };
    let handle = HANDLE(file.as_raw_handle().cast());
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(|error| {
        ManagedFsError::io(
            "Cannot mark verified managed file for deletion",
            path,
            windows_error_to_io(&error),
        )
    })
}

#[cfg(windows)]
fn delete_open_node(file: &File, path: &Path) -> ManagedFsResult<()> {
    delete_open_file(file, path)
}

#[cfg(windows)]
fn delete_open_garbage_node(file: &File, path: &Path) -> ManagedFsResult<()> {
    use std::{mem::size_of, os::windows::io::AsRawHandle};
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            FileDispositionInfoEx, SetFileInformationByHandle, FILE_DISPOSITION_FLAG_DELETE,
            FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
            FILE_DISPOSITION_INFO_EX,
        },
    };
    let handle = HANDLE(file.as_raw_handle().cast());
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: windows::Win32::Storage::FileSystem::FILE_DISPOSITION_INFO_EX_FLAGS(
            FILE_DISPOSITION_FLAG_DELETE.0
                | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS.0
                | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE.0,
        ),
    };
    unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfoEx,
            (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    }
    .map_err(|error| {
        ManagedFsError::io(
            "Cannot mark managed garbage node for deletion",
            path,
            windows_error_to_io(&error),
        )
    })
}

#[cfg(not(windows))]
fn delete_open_file(_file: &File, path: &Path) -> ManagedFsResult<()> {
    fs::remove_file(path)
        .map_err(|error| ManagedFsError::io("Cannot delete verified managed file", path, error))
}

#[cfg(windows)]
fn node_info(file: &File, path: &Path) -> ManagedFsResult<NodeInfo> {
    node_info_with_stream_policy(file, path, ManagedStreamPolicy::RejectNamed)
}

#[cfg(windows)]
fn garbage_node_info(file: &File, path: &Path) -> ManagedFsResult<NodeInfo> {
    node_info_with_stream_policy(file, path, ManagedStreamPolicy::AccountNamed)
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum ManagedStreamPolicy {
    RejectNamed,
    AccountNamed,
}

#[cfg(windows)]
fn node_info_with_stream_policy(
    file: &File,
    path: &Path,
    stream_policy: ManagedStreamPolicy,
) -> ManagedFsResult<NodeInfo> {
    use std::{mem::size_of, os::windows::io::AsRawHandle};
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            FileAttributeTagInfo, FileCaseSensitiveInfo, FileIdInfo, FileStandardInfo,
            GetFileInformationByHandleEx, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
            FILE_CASE_SENSITIVE_INFO, FILE_ID_INFO, FILE_STANDARD_INFO,
        },
    };

    let handle = HANDLE(file.as_raw_handle().cast());
    if handle.0.is_null() {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed handle is invalid: {}",
            path.display()
        )));
    }
    let (named_stream_allocation, named_streams) = match stream_policy {
        ManagedStreamPolicy::RejectNamed => {
            reject_named_data_streams(handle, path)?;
            (0, 0)
        }
        ManagedStreamPolicy::AccountNamed => named_stream_inventory(handle, path)?,
    };
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    }
    .map_err(|error| {
        ManagedFsError::io(
            "Cannot query managed file attributes",
            path,
            windows_error_to_io(&error),
        )
    })?;

    let mut standard = FILE_STANDARD_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&mut standard as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    }
    .map_err(|error| {
        ManagedFsError::io(
            "Cannot query managed file information",
            path,
            windows_error_to_io(&error),
        )
    })?;

    let mut identity = FILE_ID_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&mut identity as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .map_err(|error| {
        ManagedFsError::Unsupported(format!(
            "Filesystem does not expose stable 128-bit file identities for {}: {error}",
            path.display()
        ))
    })?;

    let kind = if standard.Directory {
        ManagedNodeKind::Directory
    } else {
        ManagedNodeKind::File
    };
    let is_reparse = attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0;
    let case_sensitive_directory = if kind == ManagedNodeKind::Directory && !is_reparse {
        let mut case = FILE_CASE_SENSITIVE_INFO::default();
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileCaseSensitiveInfo,
                (&mut case as *mut FILE_CASE_SENSITIVE_INFO).cast(),
                size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
            )
        }
        .map_err(|error| {
            ManagedFsError::Unsupported(format!(
                "Filesystem cannot report directory case sensitivity for {}: {error}",
                path.display()
            ))
        })?;
        case.Flags & 1 != 0
    } else {
        false
    };

    Ok(NodeInfo {
        identity: FileIdentity {
            volume_serial_number: identity.VolumeSerialNumber,
            file_id: identity.FileId.Identifier,
        },
        kind,
        attributes: attributes.FileAttributes,
        reparse_tag: if is_reparse { attributes.ReparseTag } else { 0 },
        number_of_links: standard.NumberOfLinks,
        size: standard.EndOfFile.max(0) as u64,
        allocation_size: (standard.AllocationSize.max(0) as u64)
            .checked_add(named_stream_allocation)
            .ok_or_else(|| {
                ManagedFsError::UnsafeNode(format!(
                    "Managed node stream allocation overflowed: {}",
                    path.display()
                ))
            })?,
        named_streams,
        case_sensitive_directory,
    })
}

#[cfg(windows)]
fn reject_named_data_streams(
    handle: windows::Win32::Foundation::HANDLE,
    path: &Path,
) -> ManagedFsResult<()> {
    query_named_stream_allocation(handle, path, ManagedStreamPolicy::RejectNamed)?;
    Ok(())
}

/// Returns the filesystem allocation charged to named streams while deliberately allowing them
/// on an already-authorized garbage node. The default unnamed stream is accounted by
/// `FILE_STANDARD_INFO` and is therefore excluded here. This parser is independently bounded so
/// attacker-controlled stream metadata cannot allocate unbounded launcher memory.
#[cfg(windows)]
fn named_stream_inventory(
    handle: windows::Win32::Foundation::HANDLE,
    path: &Path,
) -> ManagedFsResult<(u64, u32)> {
    query_named_stream_allocation(handle, path, ManagedStreamPolicy::AccountNamed)
}

#[cfg(windows)]
fn query_named_stream_allocation(
    handle: windows::Win32::Foundation::HANDLE,
    path: &Path,
    policy: ManagedStreamPolicy,
) -> ManagedFsResult<(u64, u32)> {
    use std::mem::size_of;
    use windows::Win32::Storage::FileSystem::{FileStreamInfo, GetFileInformationByHandleEx};

    const STREAM_METADATA_BYTES: usize = 64 * 1024;
    let words = STREAM_METADATA_BYTES.div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; words];
    let buffer = unsafe {
        std::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), STREAM_METADATA_BYTES)
    };
    let stream_query = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStreamInfo,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if let Err(error) = stream_query {
        let io = windows_error_to_io(&error);
        if io.raw_os_error() == Some(38) {
            return Ok((0, 0));
        }
        return Err(ManagedFsError::io(
            "Cannot enumerate managed garbage NTFS streams",
            path,
            io,
        ));
    }

    parse_managed_stream_buffer(buffer, path, policy)
}

#[cfg(windows)]
fn parse_managed_stream_buffer(
    buffer: &[u8],
    path: &Path,
    policy: ManagedStreamPolicy,
) -> ManagedFsResult<(u64, u32)> {
    use std::mem::{align_of, offset_of, size_of};
    use windows::Win32::Storage::FileSystem::FILE_STREAM_INFO;

    let header = offset_of!(FILE_STREAM_INFO, StreamName);
    let default_name = "::$DATA".encode_utf16().collect::<Vec<_>>();
    let mut named_allocation = 0_u64;
    let mut named_streams = 0_u32;
    let mut offset = 0_usize;
    let mut entries = 0_usize;
    loop {
        entries += 1;
        let entry_end = offset
            .checked_add(size_of::<FILE_STREAM_INFO>())
            .ok_or_else(|| {
                ManagedFsError::UnsafeNode("Managed garbage stream offset overflowed".into())
            })?;
        if entries > 128
            || entry_end > buffer.len()
            || !offset.is_multiple_of(align_of::<FILE_STREAM_INFO>())
        {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed garbage stream inventory is invalid: {}",
                path.display()
            )));
        }
        let entry = unsafe {
            std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<FILE_STREAM_INFO>())
        };
        let name_bytes = usize::try_from(entry.StreamNameLength).map_err(|_| {
            ManagedFsError::UnsafeNode("Managed garbage stream name length overflowed".into())
        })?;
        if name_bytes == 0 || !name_bytes.is_multiple_of(2) {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed garbage stream name is malformed: {}",
                path.display()
            )));
        }
        let name_start = offset.checked_add(header).ok_or_else(|| {
            ManagedFsError::UnsafeNode("Managed garbage stream name offset overflowed".into())
        })?;
        let name_end = name_start.checked_add(name_bytes).ok_or_else(|| {
            ManagedFsError::UnsafeNode("Managed garbage stream name length overflowed".into())
        })?;
        if name_end > buffer.len() {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed garbage stream name escaped its buffer: {}",
                path.display()
            )));
        }
        let name = buffer[name_start..name_end]
            .chunks_exact(2)
            .map(|pair| u16::from_ne_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        if entry.StreamSize < 0 || entry.StreamAllocationSize < 0 {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed garbage stream has a negative size: {}",
                path.display()
            )));
        }
        if name != default_name {
            if matches!(policy, ManagedStreamPolicy::RejectNamed) {
                return Err(ManagedFsError::UnsafeNode(format!(
                    "Named NTFS data streams are forbidden on managed nodes: {}",
                    path.display()
                )));
            }
            let allocation = u64::try_from(entry.StreamAllocationSize).map_err(|_| {
                ManagedFsError::UnsafeNode(format!(
                    "Managed garbage stream has a negative allocation: {}",
                    path.display()
                ))
            })?;
            named_allocation = named_allocation.checked_add(allocation).ok_or_else(|| {
                ManagedFsError::UnsafeNode(format!(
                    "Managed garbage stream allocation overflowed: {}",
                    path.display()
                ))
            })?;
            named_streams = named_streams.checked_add(1).ok_or_else(|| {
                ManagedFsError::UnsafeNode("Managed garbage stream count overflowed".into())
            })?;
        }
        if entry.NextEntryOffset == 0 {
            break;
        }
        let next = usize::try_from(entry.NextEntryOffset).map_err(|_| {
            ManagedFsError::UnsafeNode("Managed garbage stream offset overflowed".into())
        })?;
        let occupied = size_of::<FILE_STREAM_INFO>().max(name_end - offset);
        let minimum_next = occupied
            .checked_add(align_of::<FILE_STREAM_INFO>() - 1)
            .map(|value| value / align_of::<FILE_STREAM_INFO>() * align_of::<FILE_STREAM_INFO>())
            .ok_or_else(|| {
                ManagedFsError::UnsafeNode("Managed garbage stream extent overflowed".into())
            })?;
        if next < minimum_next || !next.is_multiple_of(align_of::<FILE_STREAM_INFO>()) {
            return Err(ManagedFsError::UnsafeNode(format!(
                "Managed garbage stream chain is malformed: {}",
                path.display()
            )));
        }
        offset = offset.checked_add(next).ok_or_else(|| {
            ManagedFsError::UnsafeNode("Managed garbage stream chain overflowed".into())
        })?;
    }
    Ok((named_allocation, named_streams))
}

#[cfg(windows)]
pub(super) fn validate_no_named_data_streams(file: &File, path: &Path) -> ManagedFsResult<()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;

    let handle = HANDLE(file.as_raw_handle().cast());
    if handle.0.is_null() {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed stream-audit handle is invalid: {}",
            path.display()
        )));
    }
    reject_named_data_streams(handle, path)
}

#[cfg(not(windows))]
pub(super) fn validate_no_named_data_streams(_file: &File, _path: &Path) -> ManagedFsResult<()> {
    Ok(())
}

#[cfg(unix)]
fn metadata_identity(metadata: &fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    let mut file_id = [0_u8; 16];
    file_id[..8].copy_from_slice(&metadata.ino().to_le_bytes());
    FileIdentity {
        volume_serial_number: metadata.dev(),
        file_id,
    }
}

#[cfg(all(not(windows), not(unix)))]
fn metadata_identity(metadata: &fs::Metadata) -> FileIdentity {
    let mut file_id = [0_u8; 16];
    file_id[..8].copy_from_slice(&metadata.len().to_le_bytes());
    FileIdentity {
        volume_serial_number: 0,
        file_id,
    }
}

#[cfg(not(windows))]
fn node_info(file: &File, path: &Path) -> ManagedFsResult<NodeInfo> {
    let metadata = file
        .metadata()
        .map_err(|error| ManagedFsError::io("Cannot query managed node", path, error))?;
    #[cfg(unix)]
    let links = {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink().try_into().unwrap_or(u32::MAX)
    };
    #[cfg(not(unix))]
    let links = 1;
    #[cfg(unix)]
    let allocation_size = {
        use std::os::unix::fs::MetadataExt;
        metadata.blocks().saturating_mul(512)
    };
    #[cfg(not(unix))]
    let allocation_size = metadata.len();
    Ok(NodeInfo {
        identity: metadata_identity(&metadata),
        kind: if metadata.is_dir() {
            ManagedNodeKind::Directory
        } else {
            ManagedNodeKind::File
        },
        attributes: 0,
        reparse_tag: 0,
        number_of_links: links,
        size: metadata.len(),
        allocation_size,
        named_streams: 0,
        case_sensitive_directory: false,
    })
}

#[cfg(windows)]
fn verify_handle_path(file: &File, expected: &Path) -> ManagedFsResult<()> {
    let info = node_info(file, expected)?;
    verify_handle_path_with_info(file, expected, &info)
}

#[cfg(windows)]
fn verify_handle_path_with_info(
    file: &File,
    expected: &Path,
    info: &NodeInfo,
) -> ManagedFsResult<()> {
    if info.reparse_tag != 0 {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed path is a reparse point: {}",
            expected.display()
        )));
    }
    verify_handle_path_allow_reparse(file, expected)
}

#[cfg(not(windows))]
fn verify_handle_path(file: &File, expected: &Path) -> ManagedFsResult<()> {
    let info = node_info(file, expected)?;
    verify_handle_path_with_info(file, expected, &info)
}

#[cfg(not(windows))]
fn verify_handle_path_with_info(
    _file: &File,
    expected: &Path,
    info: &NodeInfo,
) -> ManagedFsResult<()> {
    let expected_metadata = fs::symlink_metadata(expected)
        .map_err(|error| ManagedFsError::io("Cannot verify managed path", expected, error))?;
    if expected_metadata.file_type().is_symlink()
        || metadata_identity(&expected_metadata) != info.identity
    {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed path changed while opening: {}",
            expected.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn verify_handle_path_allow_reparse(file: &File, expected: &Path) -> ManagedFsResult<()> {
    let actual = final_path(file, expected)?;
    let lexical_matches = windows_path_key(&actual) == windows_path_key(expected);
    let canonical_matches = fs::canonicalize(expected)
        .ok()
        .is_some_and(|canonical| windows_path_key(&actual) == windows_path_key(&canonical));
    if !lexical_matches && !canonical_matches {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed handle resolved outside its lexical path: expected {}, got {}",
            expected.display(),
            actual.display()
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn verify_handle_path_allow_reparse(file: &File, expected: &Path) -> ManagedFsResult<()> {
    verify_handle_path(file, expected)
}

#[cfg(windows)]
fn stable_handle_path(file: &File, expected: &Path) -> ManagedFsResult<PathBuf> {
    final_path(file, expected)
}

#[cfg(not(windows))]
fn stable_handle_path(file: &File, expected: &Path) -> ManagedFsResult<PathBuf> {
    verify_handle_path(file, expected)?;
    fs::canonicalize(expected).map_err(|error| {
        ManagedFsError::io("Cannot canonicalize managed directory", expected, error)
    })
}

#[cfg(windows)]
fn final_path(file: &File, path: &Path) -> ManagedFsResult<PathBuf> {
    use std::{
        ffi::OsString,
        os::windows::{ffi::OsStringExt, io::AsRawHandle},
    };
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{GetFinalPathNameByHandleW, VOLUME_NAME_DOS},
    };
    let handle = HANDLE(file.as_raw_handle().cast());
    let mut buffer = vec![0_u16; 512];
    loop {
        let length =
            unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, VOLUME_NAME_DOS) } as usize;
        if length == 0 {
            return Err(ManagedFsError::io(
                "Cannot resolve managed handle path",
                path,
                std::io::Error::last_os_error(),
            ));
        }
        if length < buffer.len() {
            return Ok(PathBuf::from(OsString::from_wide(&buffer[..length])));
        }
        if length > 32_767 {
            return Err(ManagedFsError::UnsafeNode(
                "Managed handle path exceeds the Windows limit".into(),
            ));
        }
        buffer.resize(length + 1, 0);
    }
}

#[cfg(windows)]
fn windows_path_key(path: &Path) -> String {
    let mut value = path.to_string_lossy().replace('/', "\\");
    if let Some(rest) = value.strip_prefix("\\\\?\\UNC\\") {
        value = format!("\\\\{rest}");
    } else if let Some(rest) = value.strip_prefix("\\\\?\\") {
        value = rest.to_owned();
    }
    value.trim_end_matches('\\').to_lowercase()
}

#[cfg(windows)]
fn windows_error_to_io(error: &windows::core::Error) -> std::io::Error {
    let hresult = error.code().0 as u32;
    let raw = if hresult & 0xffff_0000 == 0x8007_0000 {
        hresult & 0x0000_ffff
    } else {
        hresult
    };
    std::io::Error::from_raw_os_error(raw as i32)
}

#[cfg(windows)]
fn sync_directory_identity(path: &Path, expected: &FileIdentity) -> ManagedFsResult<()> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
        .map_err(|error| {
            ManagedFsError::io("Cannot open managed directory for flush", path, error)
        })?;
    let info = node_info(&file, path)?;
    info.require_real_directory(path)?;
    if &info.identity != expected {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed directory identity changed before flush: {}",
            path.display()
        )));
    }
    file.sync_all()
        .map_err(|error| ManagedFsError::io("Cannot flush managed directory", path, error))
}

#[cfg(not(windows))]
fn sync_directory_identity(path: &Path, expected: &FileIdentity) -> ManagedFsResult<()> {
    let file = File::open(path).map_err(|error| {
        ManagedFsError::io("Cannot open managed directory for flush", path, error)
    })?;
    if &node_info(&file, path)?.identity != expected {
        return Err(ManagedFsError::UnsafeNode(format!(
            "Managed directory identity changed before flush: {}",
            path.display()
        )));
    }
    file.sync_all()
        .map_err(|error| ManagedFsError::io("Cannot flush managed directory", path, error))
}

#[cfg(windows)]
fn rename_handle(file: &File, destination: &Path, mode: ManagedRenameMode) -> ManagedFsResult<()> {
    rename_handle_windows(file, destination.as_os_str(), destination, mode)
}

#[cfg(windows)]
fn rename_handle_relative(
    file: &File,
    destination_parent: &File,
    destination_name: &str,
    destination: &Path,
    mode: ManagedRenameMode,
) -> ManagedFsResult<()> {
    validate_component(destination_name)?;
    rename_handle_relative_nt(
        file,
        destination_parent,
        destination_name,
        destination,
        mode,
    )
}

#[cfg(windows)]
fn rename_handle_windows(
    file: &File,
    destination_name: &std::ffi::OsStr,
    destination: &Path,
    mode: ManagedRenameMode,
) -> ManagedFsResult<()> {
    use std::{
        mem::{align_of, size_of},
        os::windows::{ffi::OsStrExt, io::AsRawHandle},
        ptr,
    };
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            FileRenameInfo, FileRenameInfoEx, SetFileInformationByHandle, FILE_RENAME_INFO,
            FILE_RENAME_INFO_0,
        },
    };

    let mut name: Vec<u16> = destination_name.encode_wide().collect();
    if name.is_empty() || name.len() > 32_767 {
        return Err(ManagedFsError::InvalidPath(
            "Managed rename destination has an invalid Windows length".into(),
        ));
    }
    let name_bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            ManagedFsError::InvalidPath("Managed rename destination is too long".into())
        })?;
    // Win32 FILE_RENAME_INFO requires a NUL-terminated FileName even though FileNameLength
    // deliberately excludes that terminator. The native handle-relative backend below is a
    // separate length-delimited contract and does not depend on this terminator.
    name.push(0);
    let buffer_size = size_of::<FILE_RENAME_INFO>()
        .checked_add(usize::try_from(name_bytes).map_err(|_| {
            ManagedFsError::InvalidPath("Managed rename byte length exceeds usize".into())
        })?)
        .ok_or_else(|| ManagedFsError::InvalidPath("Managed rename buffer overflow".into()))?;
    let words = buffer_size.div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; words];
    debug_assert!((storage.as_ptr() as usize).is_multiple_of(align_of::<FILE_RENAME_INFO>()));
    let rename = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        let anonymous = match mode {
            ManagedRenameMode::NoReplace => FILE_RENAME_INFO_0 {
                ReplaceIfExists: false,
            },
            ManagedRenameMode::ReplaceExisting => FILE_RENAME_INFO_0 { Flags: 0x0000_0001 },
        };
        ptr::write(&mut (*rename).Anonymous, anonymous);
        ptr::write(&mut (*rename).RootDirectory, HANDLE::default());
        ptr::write(&mut (*rename).FileNameLength, name_bytes);
        ptr::copy_nonoverlapping(name.as_ptr(), (*rename).FileName.as_mut_ptr(), name.len());
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle().cast()),
            match mode {
                ManagedRenameMode::NoReplace => FileRenameInfo,
                ManagedRenameMode::ReplaceExisting => FileRenameInfoEx,
            },
            rename.cast(),
            u32::try_from(buffer_size).map_err(|_| {
                ManagedFsError::InvalidPath("Managed rename buffer exceeds Win32 limit".into())
            })?,
        )
    }
    .map_err(|error| {
        let raw = windows_error_to_io(&error);
        if mode == ManagedRenameMode::NoReplace
            && matches!(raw.kind(), std::io::ErrorKind::AlreadyExists)
        {
            ManagedFsError::Conflict(format!(
                "Managed rename destination already exists: {}",
                destination.display()
            ))
        } else {
            ManagedFsError::io("Cannot rename managed object by handle", destination, raw)
        }
    })
}

/// Rename relative to an already validated destination-directory handle. The documented Win32
/// `SetFileInformationByHandle` contract requires `FILE_RENAME_INFO.RootDirectory == NULL`, so
/// parent-handle binding uses the native file-information API and its equivalent structure.
#[cfg(windows)]
fn rename_handle_relative_nt(
    file: &File,
    destination_parent: &File,
    destination_name: &str,
    destination: &Path,
    mode: ManagedRenameMode,
) -> ManagedFsResult<()> {
    use std::{mem::size_of, os::windows::io::AsRawHandle, ptr};
    use windows::{
        Wdk::Storage::FileSystem::{
            FileRenameInformation, FileRenameInformationEx, NtSetInformationFile,
            FILE_RENAME_INFORMATION, FILE_RENAME_INFORMATION_0,
        },
        Win32::{
            Foundation::{RtlNtStatusToDosError, HANDLE, STATUS_OBJECT_NAME_COLLISION},
            System::IO::IO_STATUS_BLOCK,
        },
    };

    let name: Vec<u16> = destination_name.encode_utf16().collect();
    if name.is_empty() || name.len() > 32_767 {
        return Err(ManagedFsError::InvalidPath(
            "Managed relative rename destination has an invalid Windows length".into(),
        ));
    }
    let name_bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| {
            ManagedFsError::InvalidPath("Managed relative rename destination is too long".into())
        })?;
    // Native FILE_RENAME_INFORMATION requires the complete fixed structure plus the full
    // length-delimited name. Its one-element trailing array makes this a harmless two-byte
    // over-allocation and matches the documented NtSetInformationFile contract.
    let buffer_size = size_of::<FILE_RENAME_INFORMATION>()
        .checked_add(name.len() * size_of::<u16>())
        .ok_or_else(|| {
            ManagedFsError::InvalidPath("Managed relative rename buffer overflow".into())
        })?;
    let words = buffer_size.div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; words];
    let rename = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let (anonymous, information_class) = match mode {
        ManagedRenameMode::NoReplace => (
            FILE_RENAME_INFORMATION_0 {
                ReplaceIfExists: false,
            },
            FileRenameInformation,
        ),
        ManagedRenameMode::ReplaceExisting => (
            FILE_RENAME_INFORMATION_0 { Flags: 0x0000_0001 },
            FileRenameInformationEx,
        ),
    };
    unsafe {
        ptr::write(&mut (*rename).Anonymous, anonymous);
        ptr::write(
            &mut (*rename).RootDirectory,
            HANDLE(destination_parent.as_raw_handle().cast()),
        );
        ptr::write(&mut (*rename).FileNameLength, name_bytes);
        ptr::copy_nonoverlapping(name.as_ptr(), (*rename).FileName.as_mut_ptr(), name.len());
    }
    let mut io_status = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtSetInformationFile(
            HANDLE(file.as_raw_handle().cast()),
            &mut io_status,
            rename.cast(),
            u32::try_from(buffer_size).map_err(|_| {
                ManagedFsError::InvalidPath(
                    "Managed relative rename buffer exceeds native Windows limit".into(),
                )
            })?,
            information_class,
        )
    };
    if status.0 >= 0 {
        return Ok(());
    }
    let dos_error = unsafe { RtlNtStatusToDosError(status) };
    let raw = i32::try_from(dos_error)
        .map(std::io::Error::from_raw_os_error)
        .unwrap_or_else(|_| {
            std::io::Error::other(format!(
                "native rename failed with NTSTATUS 0x{:08x} (DOS error {dos_error})",
                status.0 as u32
            ))
        });
    if mode == ManagedRenameMode::NoReplace
        && (status == STATUS_OBJECT_NAME_COLLISION
            || matches!(
                raw.kind(),
                std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::DirectoryNotEmpty
            ))
    {
        Err(ManagedFsError::Conflict(format!(
            "Managed relative rename destination already exists: {}",
            destination.display()
        )))
    } else {
        Err(ManagedFsError::io(
            "Cannot rename managed object relative to its destination-directory handle",
            destination,
            raw,
        ))
    }
}

#[cfg(not(windows))]
fn rename_handle(file: &File, destination: &Path, mode: ManagedRenameMode) -> ManagedFsResult<()> {
    let source =
        fs::read_link(format!("/proc/self/fd/{}", raw_file_descriptor(file))).map_err(|error| {
            ManagedFsError::io("Cannot resolve managed source handle", destination, error)
        })?;
    if mode == ManagedRenameMode::NoReplace && fs::symlink_metadata(destination).is_ok() {
        return Err(ManagedFsError::Conflict(format!(
            "Managed rename destination already exists: {}",
            destination.display()
        )));
    }
    fs::rename(&source, destination)
        .map_err(|error| ManagedFsError::io("Cannot rename managed object", destination, error))
}

#[cfg(not(windows))]
fn rename_handle_relative(
    file: &File,
    _destination_parent: &File,
    _destination_name: &str,
    destination: &Path,
    mode: ManagedRenameMode,
) -> ManagedFsResult<()> {
    rename_handle(file, destination, mode)
}

#[cfg(unix)]
fn raw_file_descriptor(file: &File) -> i32 {
    use std::os::unix::io::AsRawFd;
    file.as_raw_fd()
}

#[cfg(all(not(windows), not(unix)))]
fn raw_file_descriptor(_file: &File) -> i32 {
    -1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fragment-managed-fs-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    #[test]
    fn validates_windows_safe_relative_paths_on_every_host() {
        let valid = RelativeManagedPath::new("config/client/controls.txt").unwrap();
        assert_eq!(valid.as_str(), "config/client/controls.txt");
        assert_eq!(valid.collision_key(), "config/client/controls.txt");

        for invalid in [
            "",
            "/mods/a.jar",
            "mods/",
            "mods//a.jar",
            "mods\\a.jar",
            "mods/../a.jar",
            "mods/CON.txt",
            "mods/com1",
            "mods/LPT².log",
            "mods/a.jar:evil",
            "mods/bad?.jar",
            "mods/NUL .txt",
            "mods/trailing. ",
            "mods/e\u{301}.txt",
        ] {
            assert!(
                RelativeManagedPath::new(invalid).is_err(),
                "accepted unsafe path: {invalid:?}"
            );
        }
    }

    #[test]
    fn detects_case_collision_keys() {
        let left = RelativeManagedPath::new("mods/Example.JAR").unwrap();
        let right = RelativeManagedPath::new("MODS/example.jar").unwrap();
        assert_eq!(left.collision_key(), right.collision_key());
        assert_ne!(left, right);
    }

    #[cfg(windows)]
    fn assert_recursive_sentinel_dirty(label: &str, mutate: impl FnOnce(&Path)) {
        let container = temp_root(&format!("sentinel-{label}"));
        let root = container.join("instance");
        fs::create_dir_all(root.join("nested")).unwrap();
        let file = root.join("nested/file.bin");
        fs::write(&file, b"baseline").unwrap();
        let original_file_attributes = windows_file_attributes(&file);
        let original_root_attributes = windows_file_attributes(&root);
        let sentinel = RecursiveChangeSentinel::arm(&root).unwrap();
        sentinel.revalidate_clean().unwrap();

        mutate(&root);
        assert!(
            sentinel.wait_until_dirty(std::time::Duration::from_secs(2)),
            "{label} did not signal the recursive change sentinel"
        );
        let first = sentinel.revalidate_clean().unwrap_err().to_string();
        assert!(
            first.contains("changed after its baseline audit"),
            "{first}"
        );
        assert!(
            sentinel.revalidate_clean().is_err(),
            "{label} notification was reset instead of staying sticky"
        );

        // A read-only mutation is itself expected to dirty the sentinel, but must not make the
        // test fixture undeletable after the notification handle is closed. Restore the exact
        // original Win32 attributes rather than broadening permissions.
        if fs::symlink_metadata(&file).is_ok() {
            set_windows_file_attributes(&file, original_file_attributes);
        }
        if fs::symlink_metadata(&root).is_ok() {
            set_windows_file_attributes(&root, original_root_attributes);
        }
        drop(sentinel);
        fs::remove_dir_all(&container).unwrap();
    }

    #[cfg(windows)]
    fn windows_file_attributes(path: &Path) -> u32 {
        use std::os::windows::fs::MetadataExt;

        fs::metadata(path).unwrap().file_attributes()
    }

    #[cfg(windows)]
    fn set_windows_file_attributes(path: &Path, attributes: u32) {
        use std::os::windows::ffi::OsStrExt;
        use windows::{
            core::PCWSTR,
            Win32::Storage::FileSystem::{SetFileAttributesW, FILE_FLAGS_AND_ATTRIBUTES},
        };

        let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        wide.push(0);
        unsafe { SetFileAttributesW(PCWSTR(wide.as_ptr()), FILE_FLAGS_AND_ATTRIBUTES(attributes)) }
            .unwrap();
        assert_eq!(windows_file_attributes(path), attributes);
    }

    #[cfg(windows)]
    fn ensure_archive_attribute(path: &Path) -> u32 {
        use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_ARCHIVE;

        let attributes = windows_file_attributes(path) | FILE_ATTRIBUTE_ARCHIVE.0;
        set_windows_file_attributes(path, attributes);
        attributes
    }

    #[cfg(windows)]
    #[test]
    fn recursive_change_sentinel_ignores_benign_reads_and_closes_on_drop() {
        let container = temp_root("sentinel-benign-read");
        let root = container.join("instance");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/file.bin"), b"baseline").unwrap();
        let sentinel = RecursiveChangeSentinel::arm(&root).unwrap();

        assert_eq!(fs::read(root.join("nested/file.bin")).unwrap(), b"baseline");
        for directory in [&root, &root.join("nested")] {
            for entry in fs::read_dir(directory).unwrap() {
                let entry = entry.unwrap();
                let _ = fs::symlink_metadata(entry.path()).unwrap();
            }
        }
        sentinel.revalidate_clean().unwrap();
        assert!(
            fs::rename(&root, container.join("replacement")).is_err(),
            "the retained exact-root guard must deny a root path swap"
        );
        sentinel.revalidate_clean().unwrap();

        drop(sentinel);
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&container).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn recursive_change_sentinel_is_sticky_for_every_launch_mutation_class() {
        assert_recursive_sentinel_dirty("create", |root| {
            fs::write(root.join("nested/created.bin"), b"new").unwrap();
        });
        assert_recursive_sentinel_dirty("rename", |root| {
            fs::rename(
                root.join("nested/file.bin"),
                root.join("nested/renamed.bin"),
            )
            .unwrap();
        });
        assert_recursive_sentinel_dirty("delete", |root| {
            fs::remove_file(root.join("nested/file.bin")).unwrap();
        });
        assert_recursive_sentinel_dirty("attributes", |root| {
            let path = root.join("nested/file.bin");
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_readonly(true);
            fs::set_permissions(path, permissions).unwrap();
        });
        assert_recursive_sentinel_dirty("named-stream", |root| {
            let path = root.join("nested/file.bin");
            fs::write(format!("{}:payload", path.display()), b"hidden").unwrap();
        });
        assert_recursive_sentinel_dirty("root-attributes", |root| {
            let mut permissions = fs::metadata(root).unwrap().permissions();
            permissions.set_readonly(true);
            fs::set_permissions(root, permissions).unwrap();
        });
    }

    #[cfg(windows)]
    #[test]
    fn recursive_change_sentinel_sticks_on_transient_root_stream_with_archive_preset() {
        use std::{os::windows::fs::MetadataExt, time::Duration};

        let container = temp_root("sentinel-transient-root-stream");
        let root = container.join("instance");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/file.bin"), b"baseline").unwrap();

        let archive_attributes = ensure_archive_attribute(&root);

        let sentinel = RecursiveChangeSentinel::arm(&root).unwrap();
        sentinel.revalidate_clean().unwrap();
        let mut stream = root.as_os_str().to_os_string();
        stream.push(":payload");
        let stream = PathBuf::from(stream);
        fs::write(&stream, b"transient hidden payload").unwrap();
        fs::remove_file(&stream).unwrap();

        assert_eq!(
            fs::metadata(&root).unwrap().file_attributes(),
            archive_attributes,
            "the sticky proof must come from STREAM_* rather than an Archive-bit transition"
        );
        assert!(!stream.exists(), "the injected stream must already be gone");
        assert!(
            sentinel
                .parent_change
                .wait_signalled(Duration::from_secs(2)),
            "the parent STREAM_* watch must observe a transient ADS on the watched root"
        );
        assert!(sentinel.revalidate_clean().is_err());
        assert!(
            sentinel.revalidate_clean().is_err(),
            "a transient root stream notification must remain sticky"
        );

        drop(sentinel);
        fs::remove_dir_all(&container).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn recursive_change_sentinel_fails_closed_on_sibling_stream_in_lease_parent() {
        use std::{os::windows::fs::MetadataExt, time::Duration};

        let container = temp_root("sentinel-sibling-stream");
        let parent = container.join("exclusive-parent");
        let root = parent.join("instance");
        let sibling = parent.join("sibling.bin");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/file.bin"), b"baseline").unwrap();
        fs::write(&sibling, b"sibling").unwrap();
        let sibling_attributes = ensure_archive_attribute(&sibling);

        let sentinel = RecursiveChangeSentinel::arm(&root).unwrap();
        sentinel.revalidate_clean().unwrap();
        let mut stream = sibling.as_os_str().to_os_string();
        stream.push(":payload");
        let stream = PathBuf::from(stream);
        fs::write(&stream, b"transient sibling payload").unwrap();
        fs::remove_file(&stream).unwrap();

        assert_eq!(
            fs::metadata(&sibling).unwrap().file_attributes(),
            sibling_attributes,
            "the parent proof must come from STREAM_* rather than an Archive-bit transition"
        );
        assert!(
            sentinel
                .parent_change
                .wait_signalled(Duration::from_secs(2)),
            "a sibling stream in the serialized lease parent must fail closed"
        );
        assert!(sentinel.revalidate_clean().is_err());

        drop(sentinel);
        fs::remove_dir_all(&container).unwrap();
    }

    #[test]
    fn ensure_directory_chain_creates_and_guards_each_component() {
        let root = temp_root("ensure-directory");
        fs::create_dir_all(&root).unwrap();
        let relative = RelativeManagedPath::new("state/journals/stable").unwrap();
        let chain = ensure_directory_chain(&root, &relative).unwrap();
        assert!(relative.join_to(&root).is_dir());

        #[cfg(windows)]
        assert!(fs::rename(root.join("state"), root.join("moved")).is_err());

        drop(chain);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn atomic_write_small_replaces_or_creates_exact_payload() {
        let root = temp_root("atomic-small");
        fs::create_dir_all(root.join("state")).unwrap();
        let destination = RelativeManagedPath::new("state/active.json").unwrap();
        fs::write(destination.join_to(&root), b"old").unwrap();

        let first = atomic_write_small(&root, destination.clone(), b"new-state", 1024).unwrap();
        assert_eq!(first.destination, destination);
        assert_eq!(fs::read(destination.join_to(&root)).unwrap(), b"new-state");
        assert_eq!(fs::read_dir(root.join("state")).unwrap().count(), 1);

        let created = RelativeManagedPath::new("state/recovery.json").unwrap();
        atomic_write_small(&root, created.clone(), b"recovery", 1024).unwrap();
        assert_eq!(fs::read(created.join_to(&root)).unwrap(), b"recovery");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn atomic_write_terminates_an_alignment_exact_win32_rename_name() {
        use std::{mem::size_of, os::windows::ffi::OsStrExt};
        use windows::Win32::Storage::FileSystem::FILE_RENAME_INFO;

        let root = temp_root("atomic-rename-terminator");
        fs::create_dir_all(root.join("state")).unwrap();
        let stable_root = GuardedDirectoryChain::root_only(&root)
            .unwrap()
            .root_path()
            .to_path_buf();
        let destination = (1..=8)
            .map(|padding| {
                RelativeManagedPath::new(&format!("state/{}.json", "a".repeat(padding))).unwrap()
            })
            .find(|candidate| {
                let utf16_units = candidate
                    .join_to(&stable_root)
                    .as_os_str()
                    .encode_wide()
                    .count();
                (std::mem::offset_of!(FILE_RENAME_INFO, FileName) + utf16_units * size_of::<u16>())
                    .is_multiple_of(size_of::<usize>())
            })
            .expect("one short padding length must align the Win32 rename buffer exactly");

        atomic_write_small(&root, destination.clone(), b"first", 1024).unwrap();
        atomic_write_small(&root, destination.clone(), b"second", 1024).unwrap();
        assert_eq!(fs::read(destination.join_to(&root)).unwrap(), b"second");
        let names = fs::read_dir(root.join("state"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(names, vec![destination.file_name().to_owned()]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn managed_lock_file_is_reopened_with_the_same_identity() {
        let root = temp_root("lock-file");
        fs::create_dir_all(root.join("state")).unwrap();
        let relative = RelativeManagedPath::new("state/instance.lock").unwrap();
        let first = open_or_create_lock_file(&root, &relative).unwrap();
        let second = open_or_create_lock_file(&root, &relative).unwrap();
        assert_eq!(first.info().identity, second.info().identity);
        assert_eq!(
            fs::canonicalize(first.path()).unwrap(),
            fs::canonicalize(relative.join_to(&root)).unwrap()
        );
        assert_eq!(first.file().metadata().unwrap().len(), 0);
        drop(second);
        drop(first);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resumable_allocation_snapshot_binds_file_root_and_size_drift() {
        let root = temp_root("resumable-allocation-snapshot");
        fs::create_dir_all(root.join("cache/objects")).unwrap();
        let relative = RelativeManagedPath::new("cache/objects/object.part").unwrap();
        let mut partial =
            ResumableManagedFile::open_or_create(&root, relative.clone(), 1024 * 1024).unwrap();
        partial.write_all_at(0, &[0x5a; 16 * 1024]).unwrap();
        partial.sync_all().unwrap();

        let written = partial.allocation_snapshot().unwrap();
        assert_eq!(written.logical_size, 16 * 1024);
        assert!(written.allocated_size > 0);
        assert_eq!(
            written.identity.volume_serial_number,
            written.managed_root_identity.volume_serial_number
        );

        drop(partial);
        let mut reopened = ResumableManagedFile::open_existing(&root, relative, 1024 * 1024)
            .unwrap()
            .unwrap();
        assert_eq!(reopened.allocation_snapshot().unwrap(), written);

        reopened.truncate_zero().unwrap();
        let truncated = reopened.allocation_snapshot().unwrap();
        assert_eq!(truncated.identity, written.identity);
        assert_eq!(
            truncated.managed_root_identity,
            written.managed_root_identity
        );
        assert_eq!(truncated.logical_size, 0);
        assert!(truncated.allocated_size <= written.allocated_size);

        drop(reopened);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn resumable_allocation_snapshot_reports_sparse_physical_allocation() {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::{Foundation::HANDLE, System::IO::DeviceIoControl};

        // FSCTL_SET_SPARSE is stable across supported Windows versions. Keeping the constant
        // local avoids enabling the otherwise-unused, very broad Win32_System_Ioctl feature.
        const FSCTL_SET_SPARSE: u32 = 590_020;
        const LOGICAL_SIZE: u64 = 64 * 1024 * 1024;

        let root = temp_root("resumable-sparse-allocation-snapshot");
        fs::create_dir_all(root.join("cache/objects")).unwrap();
        let relative = RelativeManagedPath::new("cache/objects/sparse.part").unwrap();
        let mut partial =
            ResumableManagedFile::open_or_create(&root, relative, LOGICAL_SIZE).unwrap();
        let mut returned = 0_u32;
        unsafe {
            DeviceIoControl(
                HANDLE(partial.file.as_raw_handle().cast()),
                FSCTL_SET_SPARSE,
                None,
                0,
                None,
                0,
                Some(&mut returned),
                None,
            )
        }
        .unwrap();
        partial.file.set_len(LOGICAL_SIZE).unwrap();
        partial.sync_all().unwrap();

        let snapshot = partial.allocation_snapshot().unwrap();
        assert_eq!(snapshot.logical_size, LOGICAL_SIZE);
        assert!(snapshot.allocated_size < snapshot.logical_size);

        drop(partial);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exclusive_commit_and_immutable_hash_round_trip() {
        let root = temp_root("round-trip");
        fs::create_dir_all(root.join("staging")).unwrap();
        fs::create_dir_all(root.join("instances")).unwrap();
        let source = RelativeManagedPath::new("staging/object.tmp").unwrap();
        let destination = RelativeManagedPath::new("instances/object.bin").unwrap();

        let mut temporary = ExclusiveManagedFile::create(&root, source).unwrap();
        temporary.file_mut().write_all(b"fragment-spark2").unwrap();
        let committed = temporary
            .sync()
            .unwrap()
            .rename_no_replace(destination.clone())
            .unwrap();
        assert_eq!(committed.destination, destination);

        let mut immutable = ImmutableManagedFile::open(&root, &destination).unwrap();
        let digest = immutable.sha256(1024).unwrap();
        assert_eq!(digest.size, 15);
        assert_eq!(
            digest.sha256,
            format!("{:x}", Sha256::digest(b"fragment-spark2"))
        );
        assert_eq!(immutable.read_bounded(1024).unwrap(), b"fragment-spark2");

        drop(immutable);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn immutable_stream_copy_preserves_source_and_creates_an_independent_file() {
        let root = temp_root("stream-copy");
        fs::create_dir_all(root.join("cas")).unwrap();
        fs::create_dir_all(root.join("staging")).unwrap();
        let payload = vec![0x5a_u8; 2 * 1024 * 1024 + 17];
        fs::write(root.join("cas/object"), &payload).unwrap();

        let source_path = RelativeManagedPath::new("cas/object").unwrap();
        let destination_path = RelativeManagedPath::new("staging/object.tmp").unwrap();
        let mut source = ImmutableManagedFile::open(&root, &source_path).unwrap();
        let source_identity = source.info().identity.clone();
        let mut destination =
            ExclusiveManagedFile::create(&root, destination_path.clone()).unwrap();
        let destination_identity = destination.info.identity.clone();
        let copied = source
            .copy_to_exclusive(&mut destination, payload.len() as u64)
            .unwrap();

        assert_eq!(copied.size, payload.len() as u64);
        assert_eq!(copied.sha1, format!("{:x}", Sha1::digest(&payload)));
        assert_eq!(copied.sha256, format!("{:x}", Sha256::digest(&payload)));
        assert_ne!(source_identity, destination_identity);
        destination.sync().unwrap();
        assert_eq!(fs::read(source_path.join_to(&root)).unwrap(), payload);
        assert_eq!(
            fs::read(destination_path.join_to(&root)).unwrap(),
            fs::read(source_path.join_to(&root)).unwrap()
        );

        drop(source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn immutable_stream_copy_rejects_a_limit_below_the_source_size() {
        let root = temp_root("stream-copy-limit");
        fs::create_dir_all(root.join("cas")).unwrap();
        fs::create_dir_all(root.join("staging")).unwrap();
        fs::write(root.join("cas/object"), b"signed bytes").unwrap();
        let mut source =
            ImmutableManagedFile::open(&root, &RelativeManagedPath::new("cas/object").unwrap())
                .unwrap();
        let mut destination = ExclusiveManagedFile::create(
            &root,
            RelativeManagedPath::new("staging/object.tmp").unwrap(),
        )
        .unwrap();
        assert!(source.copy_to_exclusive(&mut destination, 4).is_err());
        assert_eq!(destination.info.size, 0);
        assert_eq!(fs::read(root.join("cas/object")).unwrap(), b"signed bytes");
        drop(destination);
        drop(source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn no_replace_commit_preserves_existing_destination() {
        let root = temp_root("no-replace");
        fs::create_dir_all(root.join("staging")).unwrap();
        fs::create_dir_all(root.join("instances")).unwrap();
        fs::write(root.join("instances/object.bin"), b"existing").unwrap();
        let mut temporary = ExclusiveManagedFile::create(
            &root,
            RelativeManagedPath::new("staging/object.tmp").unwrap(),
        )
        .unwrap();
        temporary.file_mut().write_all(b"replacement").unwrap();
        let result = temporary
            .sync()
            .unwrap()
            .rename_no_replace(RelativeManagedPath::new("instances/object.bin").unwrap());
        assert!(result.is_err());
        assert_eq!(
            fs::read(root.join("instances/object.bin")).unwrap(),
            b"existing"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn quarantine_moves_exact_file_without_deleting_it() {
        let root = temp_root("quarantine");
        fs::create_dir_all(root.join("instances")).unwrap();
        fs::create_dir_all(root.join("quarantine")).unwrap();
        fs::write(root.join("instances/foreign.jar"), b"foreign").unwrap();
        let source = RelativeManagedPath::new("instances/foreign.jar").unwrap();
        let quarantine = RelativeManagedPath::new("quarantine").unwrap();

        let moved = quarantine_node(&root, source.clone(), &quarantine).unwrap();
        assert_eq!(moved.source, source);
        assert!(!root.join("instances/foreign.jar").exists());
        assert_eq!(
            fs::read(moved.destination.join_to(&root)).unwrap(),
            b"foreign"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn identity_checked_quarantine_moves_the_expected_workspace_directory() {
        let root = temp_root("identity-quarantine-success");
        fs::create_dir_all(root.join("runtime/minecraft/workspaces/operation/outputs")).unwrap();
        fs::create_dir_all(root.join("runtime/minecraft/quarantine")).unwrap();
        fs::write(
            root.join("runtime/minecraft/workspaces/operation/outputs/slim.jar"),
            b"derived output",
        )
        .unwrap();
        let source = RelativeManagedPath::new("runtime/minecraft/workspaces/operation").unwrap();
        let quarantine = RelativeManagedPath::new("runtime/minecraft/quarantine").unwrap();
        let expected_identity = GuardedDirectoryChain::open(&root, &source)
            .unwrap()
            .leaf()
            .info
            .identity
            .clone();

        let moved = quarantine_node_if_identity(
            &root,
            source.clone(),
            &quarantine,
            &expected_identity,
            ManagedNodeKind::Directory,
        )
        .unwrap();

        assert_eq!(moved.identity, expected_identity);
        assert_eq!(moved.kind, ManagedNodeKind::Directory);
        assert!(!source.join_to(&root).exists());
        assert_eq!(
            fs::read(moved.destination.join_to(&root).join("outputs/slim.jar")).unwrap(),
            b"derived output"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn identity_checked_quarantine_leaves_a_raced_replacement_untouched() {
        let root = temp_root("identity-quarantine-raced-replacement");
        fs::create_dir_all(root.join("runtime/minecraft/workspaces/operation")).unwrap();
        fs::create_dir_all(root.join("runtime/minecraft/quarantine")).unwrap();
        fs::write(
            root.join("runtime/minecraft/workspaces/operation/original.marker"),
            b"original",
        )
        .unwrap();
        let source = RelativeManagedPath::new("runtime/minecraft/workspaces/operation").unwrap();
        let quarantine = RelativeManagedPath::new("runtime/minecraft/quarantine").unwrap();
        let expected_identity = GuardedDirectoryChain::open(&root, &source)
            .unwrap()
            .leaf()
            .info
            .identity
            .clone();
        let displaced = root.join("runtime/minecraft/workspaces/displaced-operation");
        fs::rename(source.join_to(&root), &displaced).unwrap();
        fs::create_dir(source.join_to(&root)).unwrap();
        fs::write(
            source.join_to(&root).join("replacement.marker"),
            b"replacement",
        )
        .unwrap();

        let error = quarantine_node_if_identity(
            &root,
            source.clone(),
            &quarantine,
            &expected_identity,
            ManagedNodeKind::Directory,
        )
        .unwrap_err();

        assert!(matches!(error, ManagedFsError::UnsafeNode(_)));
        assert_eq!(
            fs::read(source.join_to(&root).join("replacement.marker")).unwrap(),
            b"replacement"
        );
        assert_eq!(
            fs::read(displaced.join("original.marker")).unwrap(),
            b"original"
        );
        assert_eq!(fs::read_dir(quarantine.join_to(&root)).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deterministic_managed_move_can_restore_the_same_object() {
        let root = temp_root("move-restore");
        fs::create_dir_all(root.join("instances")).unwrap();
        fs::create_dir_all(root.join("backups/7")).unwrap();
        fs::write(root.join("instances/current.jar"), b"current").unwrap();
        let active = RelativeManagedPath::new("instances/current.jar").unwrap();
        let backup = RelativeManagedPath::new("backups/7/current.jar").unwrap();

        let moved = move_managed_node_no_replace(&root, active.clone(), backup.clone()).unwrap();
        assert_eq!(moved.source, active);
        assert_eq!(moved.destination, backup);
        assert!(!active.join_to(&root).exists());
        assert_eq!(fs::read(backup.join_to(&root)).unwrap(), b"current");

        let restored = move_managed_node_no_replace(&root, backup.clone(), active.clone()).unwrap();
        assert_eq!(restored.identity, moved.identity);
        assert_eq!(fs::read(active.join_to(&root)).unwrap(), b"current");
        assert!(!backup.join_to(&root).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deterministic_managed_move_never_replaces_an_existing_destination() {
        let root = temp_root("move-no-replace");
        fs::create_dir_all(root.join("instances")).unwrap();
        fs::create_dir_all(root.join("backups/1")).unwrap();
        fs::write(root.join("instances/source.jar"), b"source").unwrap();
        fs::write(root.join("backups/1/source.jar"), b"backup").unwrap();
        let source = RelativeManagedPath::new("instances/source.jar").unwrap();
        let destination = RelativeManagedPath::new("backups/1/source.jar").unwrap();

        assert!(move_managed_node_no_replace(&root, source.clone(), destination.clone()).is_err());
        assert_eq!(fs::read(source.join_to(&root)).unwrap(), b"source");
        assert_eq!(fs::read(destination.join_to(&root)).unwrap(), b"backup");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deterministic_managed_move_rejects_a_destination_inside_the_source() {
        let root = temp_root("move-into-self");
        fs::create_dir_all(root.join("instances/tree/child")).unwrap();
        let source = RelativeManagedPath::new("instances/tree").unwrap();
        let destination = RelativeManagedPath::new("instances/tree/child/moved").unwrap();
        assert!(move_managed_node_no_replace(&root, source, destination).is_err());
        assert!(root.join("instances/tree/child").is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn conditional_directory_move_cancels_before_the_namespace_commit() {
        let root = temp_root("conditional-directory-cancel");
        fs::create_dir_all(root.join("runtime/minecraft/staging/lock-hash/image")).unwrap();
        fs::create_dir_all(root.join("runtime/minecraft/generations")).unwrap();
        fs::write(
            root.join("runtime/minecraft/staging/lock-hash/image/client.jar"),
            b"verified client",
        )
        .unwrap();
        let source = RelativeManagedPath::new("runtime/minecraft/staging/lock-hash").unwrap();
        let destination =
            RelativeManagedPath::new("runtime/minecraft/generations/lock-hash").unwrap();
        let mut predicate_calls = 0;

        let outcome = move_managed_directory_no_replace_if(
            &root,
            source.clone(),
            destination.clone(),
            || {
                predicate_calls += 1;
                false
            },
        )
        .unwrap();

        assert_eq!(predicate_calls, 1);
        assert_eq!(outcome, ConditionalManagedDirectoryMoveOutcome::Cancelled);
        assert_eq!(
            fs::read(source.join_to(&root).join("image/client.jar")).unwrap(),
            b"verified client"
        );
        assert!(!destination.join_to(&root).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn conditional_directory_move_rejects_a_preexisting_destination_without_cancelling() {
        let root = temp_root("conditional-directory-collision");
        fs::create_dir_all(root.join("runtime/minecraft/staging/lock-hash")).unwrap();
        fs::create_dir_all(root.join("runtime/minecraft/generations/lock-hash")).unwrap();
        fs::write(
            root.join("runtime/minecraft/staging/lock-hash/source.marker"),
            b"source",
        )
        .unwrap();
        fs::write(
            root.join("runtime/minecraft/generations/lock-hash/existing.marker"),
            b"existing",
        )
        .unwrap();
        let source = RelativeManagedPath::new("runtime/minecraft/staging/lock-hash").unwrap();
        let destination =
            RelativeManagedPath::new("runtime/minecraft/generations/lock-hash").unwrap();
        let mut predicate_called = false;

        let error = move_managed_directory_no_replace_if(
            &root,
            source.clone(),
            destination.clone(),
            || {
                predicate_called = true;
                true
            },
        )
        .unwrap_err();

        assert!(!predicate_called);
        assert!(matches!(error, ManagedFsError::Conflict(_)));
        assert_eq!(
            fs::read(source.join_to(&root).join("source.marker")).unwrap(),
            b"source"
        );
        assert_eq!(
            fs::read(destination.join_to(&root).join("existing.marker")).unwrap(),
            b"existing"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn conditional_directory_move_never_replaces_a_commit_boundary_collision() {
        let root = temp_root("conditional-directory-racing-collision");
        fs::create_dir_all(root.join("runtime/minecraft/staging/lock-hash")).unwrap();
        fs::create_dir_all(root.join("runtime/minecraft/generations")).unwrap();
        fs::write(
            root.join("runtime/minecraft/staging/lock-hash/source.marker"),
            b"source",
        )
        .unwrap();
        let source = RelativeManagedPath::new("runtime/minecraft/staging/lock-hash").unwrap();
        let destination =
            RelativeManagedPath::new("runtime/minecraft/generations/lock-hash").unwrap();

        let error = move_managed_directory_no_replace_if(
            &root,
            source.clone(),
            destination.clone(),
            || {
                fs::create_dir(destination.join_to(&root)).unwrap();
                fs::write(
                    destination.join_to(&root).join("racing.marker"),
                    b"racing destination",
                )
                .unwrap();
                true
            },
        )
        .unwrap_err();

        assert!(matches!(error, ManagedFsError::Conflict(_)));
        assert_eq!(
            fs::read(source.join_to(&root).join("source.marker")).unwrap(),
            b"source"
        );
        assert_eq!(
            fs::read(destination.join_to(&root).join("racing.marker")).unwrap(),
            b"racing destination"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn conditional_directory_move_keeps_the_handle_bound_source_during_a_swap_attempt() {
        let root = temp_root("conditional-directory-source-swap");
        fs::create_dir_all(root.join("runtime/minecraft/staging/lock-hash/image")).unwrap();
        fs::create_dir_all(root.join("runtime/minecraft/generations")).unwrap();
        fs::write(
            root.join("runtime/minecraft/staging/lock-hash/image/client.jar"),
            b"original verified client",
        )
        .unwrap();
        let source = RelativeManagedPath::new("runtime/minecraft/staging/lock-hash").unwrap();
        let destination =
            RelativeManagedPath::new("runtime/minecraft/generations/lock-hash").unwrap();
        let displaced = root.join("runtime/minecraft/staging/displaced-lock-hash");
        let original_identity = GuardedDirectoryChain::open(&root, &source)
            .unwrap()
            .leaf()
            .info
            .identity
            .clone();
        let mut swap_succeeded = false;

        let outcome = move_managed_directory_no_replace_if(
            &root,
            source.clone(),
            destination.clone(),
            || {
                if fs::rename(source.join_to(&root), &displaced).is_ok() {
                    swap_succeeded = true;
                    fs::create_dir(source.join_to(&root)).unwrap();
                    fs::write(
                        source.join_to(&root).join("replacement.marker"),
                        b"replacement",
                    )
                    .unwrap();
                }
                true
            },
        )
        .unwrap();

        let ConditionalManagedDirectoryMoveOutcome::Moved(moved) = outcome else {
            panic!("a true final predicate must attempt the namespace commit");
        };
        assert_eq!(moved.identity, original_identity);
        assert_eq!(
            fs::read(destination.join_to(&root).join("image/client.jar")).unwrap(),
            b"original verified client"
        );
        if swap_succeeded {
            assert_eq!(
                fs::read(source.join_to(&root).join("replacement.marker")).unwrap(),
                b"replacement"
            );
        } else {
            assert!(!source.join_to(&root).exists());
        }
        assert!(!displaced.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verified_managed_removal_hashes_and_deletes_the_exact_file() {
        let root = temp_root("verified-remove");
        fs::create_dir_all(root.join("outputs")).unwrap();
        let relative = RelativeManagedPath::new("outputs/slim.jar.cache").unwrap();
        let bytes = b"signed transient sidecar";
        fs::write(relative.join_to(&root), bytes).unwrap();
        let expected = FileDigests {
            size: bytes.len() as u64,
            sha1: format!("{:x}", Sha1::digest(bytes)),
            sha256: format!("{:x}", Sha256::digest(bytes)),
        };

        remove_verified_managed_file(&root, &relative, &expected).unwrap();
        assert!(!relative.join_to(&root).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn verified_managed_removal_preserves_wrong_or_hardlinked_files() {
        let root = temp_root("verified-remove-reject");
        fs::create_dir_all(root.join("outputs")).unwrap();
        let relative = RelativeManagedPath::new("outputs/extra.jar.cache").unwrap();
        fs::write(relative.join_to(&root), b"unexpected").unwrap();
        let expected = FileDigests {
            size: 10,
            sha1: "0".repeat(40),
            sha256: "0".repeat(64),
        };
        assert!(remove_verified_managed_file(&root, &relative, &expected).is_err());
        assert_eq!(fs::read(relative.join_to(&root)).unwrap(), b"unexpected");

        let alias = root.join("outputs/alias.cache");
        fs::hard_link(relative.join_to(&root), &alias).unwrap();
        let actual = FileDigests {
            size: 10,
            sha1: format!("{:x}", Sha1::digest(b"unexpected")),
            sha256: format!("{:x}", Sha256::digest(b"unexpected")),
        };
        assert!(remove_verified_managed_file(&root, &relative, &actual).is_err());
        assert!(relative.join_to(&root).exists());
        assert!(alias.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    fn recursive_removal_fixture(label: &str) -> (PathBuf, RelativeManagedPath, FileIdentity) {
        let root = temp_root(label);
        fs::create_dir_all(root.join("quarantine/workspace/nested")).unwrap();
        fs::write(root.join("quarantine/workspace/root.bin"), b"root").unwrap();
        fs::write(root.join("quarantine/workspace/nested/child.bin"), b"child").unwrap();
        let relative = RelativeManagedPath::new("quarantine/workspace").unwrap();
        let identity = GuardedDirectoryChain::open(&root, &relative)
            .unwrap()
            .leaf()
            .info
            .identity
            .clone();
        (root, relative, identity)
    }

    #[cfg(windows)]
    fn generous_recursive_removal_limits() -> ManagedDirectoryRemovalLimits {
        ManagedDirectoryRemovalLimits {
            max_entries: 64,
            max_allocated_bytes: 64 * 1024 * 1024,
            max_depth: 8,
        }
    }

    #[cfg(windows)]
    #[test]
    fn bounded_recursive_removal_deletes_the_exact_safe_tree() {
        let (root, relative, identity) = recursive_removal_fixture("bounded-tree-safe");

        let summary = remove_bounded_managed_directory_tree(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
        )
        .unwrap();

        assert_eq!(summary.entries, 4);
        assert_eq!(summary.max_depth, 2);
        assert!(!relative.join_to(&root).exists());
        assert!(root.join("quarantine").is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn bounded_recursive_removal_rejects_wrong_root_identity_without_deletion() {
        let (root, relative, mut identity) =
            recursive_removal_fixture("bounded-tree-wrong-identity");
        identity.file_id[0] ^= 0xff;

        assert!(remove_bounded_managed_directory_tree(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
        )
        .is_err());
        assert_eq!(
            fs::read(relative.join_to(&root).join("nested/child.bin")).unwrap(),
            b"child"
        );
        assert_eq!(
            fs::read(relative.join_to(&root).join("root.bin")).unwrap(),
            b"root"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn bounded_recursive_removal_rejects_unsafe_descendants_without_partial_deletion() {
        // Hard links are rejected even when both names are inside the otherwise-safe tree.
        let (root, relative, identity) = recursive_removal_fixture("bounded-tree-hardlink");
        fs::hard_link(
            relative.join_to(&root).join("root.bin"),
            relative.join_to(&root).join("root-alias.bin"),
        )
        .unwrap();
        assert!(remove_bounded_managed_directory_tree(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
        )
        .is_err());
        assert_eq!(
            fs::read(relative.join_to(&root).join("nested/child.bin")).unwrap(),
            b"child"
        );
        fs::remove_dir_all(&root).unwrap();

        // A named stream is not represented by read_dir, so every opened node must independently
        // query its exact NTFS stream inventory before any deletion is allowed.
        let (root, relative, identity) = recursive_removal_fixture("bounded-tree-ads");
        fs::write(relative.join_to(&root).join("root.bin:payload"), b"hidden").unwrap();
        assert!(remove_bounded_managed_directory_tree(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
        )
        .is_err());
        assert_eq!(
            fs::read(relative.join_to(&root).join("nested/child.bin")).unwrap(),
            b"child"
        );
        fs::remove_dir_all(&root).unwrap();

        // Read-only is a known delete-disposition blocker. It is rejected during pre-audit so a
        // later sibling can never be the first place that reveals the attribute.
        let (root, relative, identity) = recursive_removal_fixture("bounded-tree-readonly");
        let read_only = relative.join_to(&root).join("root.bin");
        let original_attributes = windows_file_attributes(&read_only);
        let read_only_attributes =
            original_attributes | windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_READONLY.0;
        set_windows_file_attributes(&read_only, read_only_attributes);
        assert!(remove_bounded_managed_directory_tree(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
        )
        .is_err());
        assert_eq!(
            fs::read(relative.join_to(&root).join("nested/child.bin")).unwrap(),
            b"child"
        );
        set_windows_file_attributes(&read_only, original_attributes);
        fs::remove_dir_all(&root).unwrap();

        // Symlink creation is privilege-dependent on Windows developer mode. When available, a
        // directory reparse point must be rejected as an object and never traversed.
        use std::os::windows::fs::symlink_dir;
        let (root, relative, identity) = recursive_removal_fixture("bounded-tree-reparse");
        let outside = temp_root("bounded-tree-reparse-outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("outside.bin"), b"outside").unwrap();
        if symlink_dir(&outside, relative.join_to(&root).join("alias")).is_ok() {
            assert!(remove_bounded_managed_directory_tree(
                &root,
                &relative,
                &identity,
                generous_recursive_removal_limits(),
            )
            .is_err());
            assert_eq!(
                fs::read(relative.join_to(&root).join("nested/child.bin")).unwrap(),
                b"child"
            );
            assert_eq!(fs::read(outside.join("outside.bin")).unwrap(), b"outside");
        }
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn completed_garbage_rejects_already_open_writable_ads_before_any_disposition() {
        let (root, relative, identity) = recursive_removal_fixture("garbage-readonly-ads");
        let file = relative.join_to(&root).join("root.bin");
        fs::write(format!("{}:retired", file.display()), b"named-stream").unwrap();
        let writable_stream = OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("{}:retired", file.display()))
            .unwrap();

        assert!(remove_bounded_managed_garbage_tree(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
        )
        .is_err());
        assert_eq!(fs::read(&file).unwrap(), b"root");
        assert_eq!(
            fs::read(relative.join_to(&root).join("nested/child.bin")).unwrap(),
            b"child"
        );
        assert!(relative.join_to(&root).is_dir());
        drop(writable_stream);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn bounded_accounting_lease_allows_descendant_reopen_while_pinning_root() {
        let root = temp_root("bounded-accounting-descendant-reopen");
        fs::create_dir_all(root.join("operation/backup/nested")).unwrap();
        fs::write(root.join("operation/backup/nested/file.bin"), b"content").unwrap();
        let operation = RelativeManagedPath::new("operation").unwrap();
        let descendant = RelativeManagedPath::new("operation/backup/nested").unwrap();
        let (identity, kind, reparse_tag) =
            inspect_managed_node_nofollow(&root, &operation).unwrap();
        let lease = lease_bounded_managed_tree(
            &root,
            operation,
            &identity,
            kind,
            reparse_tag,
            generous_recursive_removal_limits(),
        )
        .unwrap();

        let (descendant_identity, descendant_kind, descendant_reparse_tag) =
            inspect_managed_node_nofollow(&root, &descendant).unwrap();
        assert_eq!(descendant_kind, ManagedNodeKind::Directory);
        assert_eq!(descendant_reparse_tag, 0);
        let reopened = GuardedDirectoryChain::open(&root, &descendant).unwrap();
        assert_eq!(reopened.leaf().info().identity, descendant_identity);
        drop(reopened);
        lease.revalidate().unwrap();
        drop(lease);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn bounded_tree_move_authority_is_exact_destination_bound_and_revalidates_contents() {
        let root = temp_root("bounded-tree-move-authority");
        fs::create_dir_all(root.join("instance/source/nested")).unwrap();
        fs::create_dir_all(root.join("operation/backup")).unwrap();
        fs::write(root.join("instance/source/nested/file.bin"), b"sealed").unwrap();
        let source = RelativeManagedPath::new("instance/source").unwrap();
        let destination = RelativeManagedPath::new("operation/backup/00000000.node").unwrap();
        let (expected_identity, expected_kind, expected_reparse_tag) =
            inspect_managed_node_nofollow(&root, &source).unwrap();
        let authority = prepare_bounded_managed_tree_move(
            &root,
            BoundedManagedTreeMoveRequest {
                source: source.clone(),
                expected_identity: &expected_identity,
                expected_kind,
                expected_reparse_tag,
                destination_depth_within_cleanup_root: 2,
                destination: destination.clone(),
                limits: generous_recursive_removal_limits(),
            },
        )
        .unwrap();
        assert_eq!(authority.summary().entries, 3);
        fs::write(root.join("instance/source/nested/file.bin"), b"changed").unwrap();
        assert!(authority.revalidate().is_err());
        drop(authority);
        assert!(source.join_to(&root).is_dir());
        assert!(!destination.join_to(&root).exists());

        let authority = prepare_bounded_managed_tree_move(
            &root,
            BoundedManagedTreeMoveRequest {
                source: source.clone(),
                expected_identity: &expected_identity,
                expected_kind,
                expected_reparse_tag,
                destination_depth_within_cleanup_root: 2,
                destination: destination.clone(),
                limits: generous_recursive_removal_limits(),
            },
        )
        .unwrap();
        let moved = authority.move_no_replace().unwrap();
        assert_eq!(moved.source, source);
        assert_eq!(moved.destination, destination);
        assert!(!moved.source.join_to(&root).exists());
        assert_eq!(
            fs::read(moved.destination.join_to(&root).join("nested/file.bin")).unwrap(),
            b"changed"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn bounded_tree_move_is_parent_handle_relative_and_no_replace() {
        let root = temp_root("bounded-tree-relative-no-replace");
        fs::create_dir_all(root.join("instance/source/nested")).unwrap();
        fs::write(root.join("instance/source/nested/file.bin"), b"source").unwrap();
        fs::create_dir(root.join("instance/existing.node")).unwrap();
        let source = RelativeManagedPath::new("instance/source").unwrap();
        let collision = RelativeManagedPath::new("instance/existing.node").unwrap();
        let destination = RelativeManagedPath::new("instance/backup.node").unwrap();
        let (expected_identity, expected_kind, expected_reparse_tag) =
            inspect_managed_node_nofollow(&root, &source).unwrap();

        let collision_authority = prepare_bounded_managed_tree_move(
            &root,
            BoundedManagedTreeMoveRequest {
                source: source.clone(),
                expected_identity: &expected_identity,
                expected_kind,
                expected_reparse_tag,
                destination_depth_within_cleanup_root: 1,
                destination: collision.clone(),
                limits: generous_recursive_removal_limits(),
            },
        )
        .unwrap();
        assert!(matches!(
            collision_authority.move_no_replace(),
            Err(ManagedFsError::Conflict(_))
        ));
        assert!(source.join_to(&root).is_dir());
        assert!(collision.join_to(&root).is_dir());

        let moved = prepare_bounded_managed_tree_move(
            &root,
            BoundedManagedTreeMoveRequest {
                source: source.clone(),
                expected_identity: &expected_identity,
                expected_kind,
                expected_reparse_tag,
                destination_depth_within_cleanup_root: 1,
                destination: destination.clone(),
                limits: generous_recursive_removal_limits(),
            },
        )
        .unwrap()
        .move_no_replace()
        .unwrap();
        assert_eq!(moved.source, source);
        assert_eq!(moved.destination, destination);
        assert!(!moved.source.join_to(&root).exists());
        assert_eq!(
            fs::read(moved.destination.join_to(&root).join("nested/file.bin")).unwrap(),
            b"source"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn bounded_tree_move_preflight_rejects_unsafe_or_over_limit_source_without_mutation() {
        let root = temp_root("bounded-tree-move-reject");
        fs::create_dir_all(root.join("instance/source")).unwrap();
        fs::create_dir_all(root.join("operation/backup")).unwrap();
        let source = RelativeManagedPath::new("instance/source").unwrap();
        let destination = RelativeManagedPath::new("operation/backup/00000000.node").unwrap();
        fs::write(source.join_to(&root).join("file.bin"), b"source").unwrap();
        let (expected_identity, expected_kind, expected_reparse_tag) =
            inspect_managed_node_nofollow(&root, &source).unwrap();
        fs::write(
            format!(
                "{}:hidden",
                source.join_to(&root).join("file.bin").display()
            ),
            b"stream",
        )
        .unwrap();
        assert!(prepare_bounded_managed_tree_move(
            &root,
            BoundedManagedTreeMoveRequest {
                source: source.clone(),
                expected_identity: &expected_identity,
                expected_kind,
                expected_reparse_tag,
                destination_depth_within_cleanup_root: 2,
                destination: destination.clone(),
                limits: generous_recursive_removal_limits(),
            },
        )
        .is_err());
        assert!(source.join_to(&root).is_dir());
        assert!(!destination.join_to(&root).exists());

        fs::remove_file(format!(
            "{}:hidden",
            source.join_to(&root).join("file.bin").display()
        ))
        .unwrap();
        let mut limits = generous_recursive_removal_limits();
        limits.max_entries = 1;
        assert!(prepare_bounded_managed_tree_move(
            &root,
            BoundedManagedTreeMoveRequest {
                source: source.clone(),
                expected_identity: &expected_identity,
                expected_kind,
                expected_reparse_tag,
                destination_depth_within_cleanup_root: 2,
                destination: destination.clone(),
                limits,
            },
        )
        .is_err());
        assert!(source.join_to(&root).join("file.bin").is_file());
        assert!(!destination.join_to(&root).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn bounded_tree_move_accounts_for_relocated_cleanup_depth() {
        fn create_source(root: &Path, label: &str, deepest: usize) -> RelativeManagedPath {
            let source = RelativeManagedPath::new(&format!("instance/{label}")).unwrap();
            let mut current = source.join_to(root);
            fs::create_dir_all(&current).unwrap();
            for _ in 1..deepest {
                current.push("d");
                fs::create_dir(&current).unwrap();
            }
            fs::write(current.join("leaf.bin"), b"leaf").unwrap();
            source
        }

        let root = temp_root("bounded-tree-relocated-depth");
        fs::create_dir_all(root.join("operation/backup")).unwrap();
        let mut limits = generous_recursive_removal_limits();
        limits.max_depth = 63;

        let accepted = create_source(&root, "accepted", 61);
        let (accepted_identity, accepted_kind, accepted_reparse_tag) =
            inspect_managed_node_nofollow(&root, &accepted).unwrap();
        let accepted_destination =
            RelativeManagedPath::new("operation/backup/00000000.node").unwrap();
        let authority = prepare_bounded_managed_tree_move(
            &root,
            BoundedManagedTreeMoveRequest {
                source: accepted.clone(),
                expected_identity: &accepted_identity,
                expected_kind: accepted_kind,
                expected_reparse_tag: accepted_reparse_tag,
                destination_depth_within_cleanup_root: 2,
                destination: accepted_destination,
                limits,
            },
        )
        .unwrap();
        assert_eq!(authority.summary().max_depth, 61);
        drop(authority);

        let rejected = create_source(&root, "rejected", 62);
        let (rejected_identity, rejected_kind, rejected_reparse_tag) =
            inspect_managed_node_nofollow(&root, &rejected).unwrap();
        let rejected_destination =
            RelativeManagedPath::new("operation/backup/00000001.node").unwrap();
        assert!(prepare_bounded_managed_tree_move(
            &root,
            BoundedManagedTreeMoveRequest {
                source: rejected.clone(),
                expected_identity: &rejected_identity,
                expected_kind: rejected_kind,
                expected_reparse_tag: rejected_reparse_tag,
                destination_depth_within_cleanup_root: 2,
                destination: rejected_destination,
                limits,
            },
        )
        .is_err());
        assert!(rejected.join_to(&root).is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn completed_garbage_removal_deletes_read_only_files() {
        let (root, relative, identity) = recursive_removal_fixture("garbage-readonly");
        let file = relative.join_to(&root).join("root.bin");
        let mut permissions = fs::metadata(&file).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&file, permissions).unwrap();

        let summary = remove_bounded_managed_garbage_tree(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
        )
        .unwrap();
        assert_eq!(summary.entries, 4);
        assert!(!relative.join_to(&root).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn garbage_identity_inspector_routes_root_ads_to_fail_closed_sweeper() {
        let root = temp_root("garbage-root-ads-inspection");
        fs::create_dir_all(&root).unwrap();
        let relative = RelativeManagedPath::new("obsolete.json").unwrap();
        let path = relative.join_to(&root);
        fs::write(&path, b"obsolete").unwrap();
        fs::write(format!("{}:audit", path.display()), b"named stream").unwrap();

        assert!(inspect_managed_node_nofollow(&root, &relative).is_err());
        let identity = inspect_managed_garbage_node_nofollow(&root, &relative).unwrap();
        assert!(remove_bounded_managed_garbage_tree(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
        )
        .is_err());
        assert_eq!(fs::read(&path).unwrap(), b"obsolete");
        assert_eq!(
            fs::read(format!("{}:audit", path.display())).unwrap(),
            b"named stream"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn completed_garbage_removal_deletes_reparse_leaf_without_touching_target() {
        use std::os::windows::fs::symlink_dir;

        let (root, relative, identity) = recursive_removal_fixture("garbage-reparse");
        let outside = temp_root("garbage-reparse-target");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("sentinel.bin"), b"outside").unwrap();
        if symlink_dir(&outside, relative.join_to(&root).join("alias")).is_err() {
            fs::remove_dir_all(root).unwrap();
            fs::remove_dir_all(outside).unwrap();
            return;
        }

        let summary = remove_bounded_managed_garbage_tree(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
        )
        .unwrap();
        assert_eq!(summary.entries, 5);
        assert!(!relative.join_to(&root).exists());
        assert_eq!(fs::read(outside.join("sentinel.bin")).unwrap(), b"outside");
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn completed_garbage_limits_fail_before_any_deletion() {
        let (root, relative, identity) = recursive_removal_fixture("garbage-bounded");
        let mut limits = generous_recursive_removal_limits();
        limits.max_entries = 2;
        assert!(remove_bounded_managed_garbage_tree(&root, &relative, &identity, limits).is_err());
        assert_eq!(
            fs::read(relative.join_to(&root).join("root.bin")).unwrap(),
            b"root"
        );
        assert_eq!(
            fs::read(relative.join_to(&root).join("nested/child.bin")).unwrap(),
            b"child"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn completed_garbage_detects_complete_audit_drift_before_deletion() {
        let (root, relative, identity) = recursive_removal_fixture("garbage-audit-drift");
        let file = relative.join_to(&root).join("root.bin");
        let error = remove_bounded_managed_garbage_tree_with(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
            || {
                fs::write(&file, b"changed between audits").unwrap();
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error, ManagedFsError::UnsafeNode(_)));
        assert_eq!(fs::read(&file).unwrap(), b"changed between audits");
        assert_eq!(
            fs::read(relative.join_to(&root).join("nested/child.bin")).unwrap(),
            b"child"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn completed_garbage_interruption_before_first_disposition_is_restartable() {
        let (root, relative, identity) = recursive_removal_fixture("garbage-restart");
        let error = remove_bounded_managed_garbage_tree_with(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
            || Ok(()),
            |_| Err(ManagedFsError::Conflict("injected interruption".into())),
        )
        .unwrap_err();
        assert!(matches!(error, ManagedFsError::Conflict(_)));
        assert!(relative.join_to(&root).join("root.bin").is_file());
        assert!(relative.join_to(&root).join("nested/child.bin").is_file());

        let summary = remove_bounded_managed_garbage_tree(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
        )
        .unwrap();
        assert_eq!(summary.entries, 4);
        assert!(!relative.join_to(&root).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn completed_garbage_reparse_swap_between_audits_never_touches_target() {
        use std::os::windows::fs::symlink_dir;

        let (root, relative, identity) = recursive_removal_fixture("garbage-reparse-swap");
        let outside = temp_root("garbage-reparse-swap-target");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("sentinel.bin"), b"outside").unwrap();
        let nested = relative.join_to(&root).join("nested");
        let result = remove_bounded_managed_garbage_tree_with(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
            || {
                fs::remove_file(nested.join("child.bin")).unwrap();
                fs::remove_dir(&nested).unwrap();
                symlink_dir(&outside, &nested).map_err(|error| {
                    ManagedFsError::io("Cannot inject garbage reparse swap", &nested, error)
                })?;
                Ok(())
            },
            |_| Ok(()),
        );
        match result {
            Err(error) => assert!(
                !matches!(
                    error,
                    ManagedFsError::AppliedButDurabilityUnconfirmed { .. }
                ),
                "reparse swap was misclassified as applied: {error:?}"
            ),
            Ok(_) => panic!("reparse swap unexpectedly passed both complete audits"),
        }
        assert_eq!(fs::read(outside.join("sentinel.bin")).unwrap(), b"outside");
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn completed_garbage_reports_post_audit_hardlink_race_as_applied_uncertain() {
        let (root, relative, identity) = recursive_removal_fixture("garbage-hardlink-race");
        let outside = temp_root("garbage-hardlink-race-outside");
        fs::create_dir_all(&outside).unwrap();
        let raced_link = outside.join("raced.bin");
        let error = remove_bounded_managed_garbage_tree_with(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
            || Ok(()),
            |path| {
                fs::hard_link(path, &raced_link).unwrap();
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ManagedFsError::AppliedButDurabilityUnconfirmed { .. }
        ));
        assert_eq!(fs::read(&raced_link).unwrap(), b"child");
        fs::remove_file(raced_link).unwrap();
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn completed_garbage_reports_post_audit_ads_race_as_applied_uncertain() {
        let (root, relative, identity) = recursive_removal_fixture("garbage-ads-race");
        let error = remove_bounded_managed_garbage_tree_with(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
            || Ok(()),
            |path| {
                fs::write(format!("{}:raced", path.display()), b"raced stream").unwrap();
                Ok(())
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ManagedFsError::AppliedButDurabilityUnconfirmed { .. }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn bounded_recursive_removal_limits_fail_before_any_deletion() {
        let mut limits = generous_recursive_removal_limits();
        limits.max_entries = 1;
        let (root, relative, identity) = recursive_removal_fixture("bounded-tree-entry-limit");
        assert!(
            remove_bounded_managed_directory_tree(&root, &relative, &identity, limits).is_err()
        );
        assert!(relative.join_to(&root).join("root.bin").is_file());
        assert!(relative.join_to(&root).join("nested/child.bin").is_file());
        fs::remove_dir_all(root).unwrap();

        let mut limits = generous_recursive_removal_limits();
        limits.max_depth = 1;
        let (root, relative, identity) = recursive_removal_fixture("bounded-tree-depth-limit");
        assert!(
            remove_bounded_managed_directory_tree(&root, &relative, &identity, limits).is_err()
        );
        assert!(relative.join_to(&root).join("root.bin").is_file());
        assert!(relative.join_to(&root).join("nested/child.bin").is_file());
        fs::remove_dir_all(root).unwrap();

        let root = temp_root("bounded-tree-byte-limit");
        fs::create_dir_all(root.join("quarantine/workspace")).unwrap();
        fs::write(
            root.join("quarantine/workspace/large.bin"),
            vec![0xa5; 1024 * 1024],
        )
        .unwrap();
        let relative = RelativeManagedPath::new("quarantine/workspace").unwrap();
        let root_guard = GuardedDirectoryChain::open(&root, &relative).unwrap();
        let identity = root_guard.leaf().info.identity.clone();
        let root_allocated = root_guard.leaf().info.allocation_size;
        drop(root_guard);
        let file = ImmutableManagedFile::open(
            &root,
            &RelativeManagedPath::new("quarantine/workspace/large.bin").unwrap(),
        )
        .unwrap();
        let exact_allocated = root_allocated + file.info().allocation_size;
        drop(file);
        assert!(exact_allocated > 0);
        let limits = ManagedDirectoryRemovalLimits {
            max_entries: 8,
            max_allocated_bytes: exact_allocated - 1,
            max_depth: 2,
        };
        assert!(
            remove_bounded_managed_directory_tree(&root, &relative, &identity, limits).is_err()
        );
        assert!(relative.join_to(&root).join("large.bin").is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn bounded_recursive_removal_holds_exclusive_handles_through_final_audit() {
        let (root, relative, identity) = recursive_removal_fixture("bounded-tree-concurrency");
        let workspace = relative.join_to(&root);
        let file = workspace.join("root.bin");
        let moved = root.join("quarantine/moved-workspace");

        let summary = remove_bounded_managed_directory_tree_with(
            &root,
            &relative,
            &identity,
            generous_recursive_removal_limits(),
            || {
                assert!(OpenOptions::new().write(true).open(&file).is_err());
                assert!(fs::rename(&workspace, &moved).is_err());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(summary.entries, 4);
        assert!(!workspace.exists());
        assert!(!moved.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hard_link_is_rejected_for_immutable_reads() {
        let root = temp_root("hard-link");
        fs::create_dir_all(root.join("instances")).unwrap();
        let original = root.join("instances/original.jar");
        fs::write(&original, b"linked").unwrap();
        fs::hard_link(&original, root.join("instances/alias.jar")).unwrap();
        let result = ImmutableManagedFile::open(
            &root,
            &RelativeManagedPath::new("instances/original.jar").unwrap(),
        );
        assert!(result.is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn stream_metadata_parser_rejects_truncated_odd_and_misaligned_chains() {
        use std::mem::size_of;
        use windows::Win32::Storage::FileSystem::FILE_STREAM_INFO;

        let label = Path::new("malformed-stream-metadata");
        let truncated = vec![0_u8; size_of::<FILE_STREAM_INFO>() - 1];
        assert!(
            parse_managed_stream_buffer(&truncated, label, ManagedStreamPolicy::AccountNamed,)
                .is_err()
        );

        let mut odd = vec![0_u8; size_of::<FILE_STREAM_INFO>()];
        let odd_entry = FILE_STREAM_INFO {
            StreamNameLength: 1,
            ..Default::default()
        };
        unsafe {
            std::ptr::write_unaligned(odd.as_mut_ptr().cast::<FILE_STREAM_INFO>(), odd_entry)
        };
        assert!(
            parse_managed_stream_buffer(&odd, label, ManagedStreamPolicy::AccountNamed).is_err()
        );

        let mut misaligned = vec![0_u8; size_of::<FILE_STREAM_INFO>()];
        let misaligned_entry = FILE_STREAM_INFO {
            NextEntryOffset: 1,
            ..Default::default()
        };
        unsafe {
            std::ptr::write_unaligned(
                misaligned.as_mut_ptr().cast::<FILE_STREAM_INFO>(),
                misaligned_entry,
            )
        };
        assert!(
            parse_managed_stream_buffer(&misaligned, label, ManagedStreamPolicy::AccountNamed,)
                .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn named_ntfs_stream_is_rejected_on_managed_files() {
        let root = temp_root("named-stream");
        fs::create_dir_all(root.join("objects")).unwrap();
        fs::write(root.join("objects/file.bin"), b"default stream").unwrap();
        fs::write(root.join("objects/file.bin:payload"), b"hidden payload").unwrap();
        let relative = RelativeManagedPath::new("objects/file.bin").unwrap();
        let error = match ImmutableManagedFile::open(&root, &relative) {
            Ok(_) => panic!("managed file with ADS was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("Named NTFS data streams"));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn empty_directory_stream_inventory_is_valid_but_directory_ads_is_rejected() {
        let root = temp_root("directory-stream");
        fs::create_dir_all(root.join("objects")).unwrap();
        GuardedDirectoryChain::open(&root, &RelativeManagedPath::new("objects").unwrap()).unwrap();

        fs::write(root.join("objects:payload"), b"hidden directory payload").unwrap();
        assert!(
            GuardedDirectoryChain::open(&root, &RelativeManagedPath::new("objects").unwrap(),)
                .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn immutable_handle_denies_concurrent_writers() {
        let root = temp_root("share-write");
        fs::create_dir_all(root.join("instances")).unwrap();
        fs::write(root.join("instances/locked.jar"), b"locked").unwrap();
        let relative = RelativeManagedPath::new("instances/locked.jar").unwrap();
        let immutable = ImmutableManagedFile::open(&root, &relative).unwrap();
        let path = relative.join_to(&root);
        let writer = OpenOptions::new().write(true).open(&path);
        assert!(writer.is_err());
        // NTFS share access is per stream. The base handle cannot prevent creation of a new ADS,
        // so launch code additionally retains the recursive STREAM_* notification sentinel.
        fs::write(format!("{}:payload", path.display()), b"hidden").unwrap();
        assert!(immutable.revalidate().is_err());
        drop(immutable);
        fs::write(&path, b"change").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"change");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn guarded_directory_denies_concurrent_rename() {
        let root = temp_root("share-delete");
        fs::create_dir_all(root.join("instances/stable")).unwrap();
        let guard = GuardedDirectoryChain::open(
            &root,
            &RelativeManagedPath::new("instances/stable").unwrap(),
        )
        .unwrap();
        let result = fs::rename(root.join("instances"), root.join("moved"));
        assert!(result.is_err());
        drop(guard);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exclusive_directory_and_in_place_seal_keep_exact_managed_nodes() {
        let root = temp_root("exclusive-directory-seal");
        fs::create_dir_all(&root).unwrap();
        let staging = RelativeManagedPath::new("staging").unwrap();
        let guard = GuardedDirectoryChain::create_exclusive(&root, &staging).unwrap();
        guard.revalidate().unwrap();
        assert!(GuardedDirectoryChain::create_exclusive(&root, &staging).is_err());

        let relative = RelativeManagedPath::new("staging/runtime.bin").unwrap();
        let mut created = ExclusiveManagedFile::create(&root, relative.clone()).unwrap();
        created.file_mut().write_all(b"sealed").unwrap();
        let mut sealed = created.seal_in_place().unwrap();
        assert_eq!(sealed.read_bounded(64).unwrap(), b"sealed");
        let digest = sealed.sha256(64).unwrap();
        assert_eq!(digest.size, 6);
        assert_eq!(digest.sha256, format!("{:x}", Sha256::digest(b"sealed")));
        sealed.revalidate().unwrap();

        let mutation = fs::write(relative.join_to(&root), b"changed-and-longer");
        if mutation.is_ok() {
            assert!(sealed.revalidate().is_err());
        } else {
            sealed.revalidate().unwrap();
        }
        drop(sealed);
        drop(guard);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn managed_lock_revalidation_prevents_or_detects_inode_replacement() {
        let root = temp_root("lock-replacement");
        fs::create_dir_all(root.join("locks")).unwrap();
        let relative = RelativeManagedPath::new("locks/runtime.lock").unwrap();
        let lock = open_or_create_lock_file(&root, &relative).unwrap();
        lock.revalidate().unwrap();
        let moved = root.join("locks/replaced.lock");
        let replacement = fs::rename(relative.join_to(&root), &moved);
        if replacement.is_ok() {
            fs::write(relative.join_to(&root), b"replacement").unwrap();
            assert!(lock.revalidate().is_err());
        } else {
            lock.revalidate().unwrap();
        }
        drop(lock);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn snapshot_directory_guard_allows_new_children_but_denies_directory_replacement() {
        let root = temp_root("snapshot-child-create");
        fs::create_dir_all(root.join("outputs/nested")).unwrap();
        let guard = GuardedDirectoryChain::open_snapshot(
            &root,
            &RelativeManagedPath::new("outputs/nested").unwrap(),
        )
        .unwrap();
        fs::write(root.join("outputs/nested/new.bin"), b"new")
            .expect("a processor must be able to create a signed child under a leased directory");
        assert!(fs::rename(root.join("outputs/nested"), root.join("outputs/moved")).is_err());
        drop(guard);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn final_directory_symlink_is_rejected_when_symlinks_are_available() {
        use std::os::windows::fs::symlink_dir;
        let root = temp_root("directory-link");
        let outside = temp_root("directory-link-outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        if symlink_dir(&outside, root.join("alias")).is_err() {
            let _ = fs::remove_dir_all(root);
            let _ = fs::remove_dir_all(outside);
            return;
        }
        let result =
            GuardedDirectoryChain::open(&root, &RelativeManagedPath::new("alias").unwrap());
        assert!(result.is_err());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }
}
