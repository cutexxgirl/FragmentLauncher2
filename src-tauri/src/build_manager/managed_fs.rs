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
const MAX_COMPONENTS: usize = 64;
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
        if components.len() > MAX_COMPONENTS {
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

    fn is_prefix_of(&self, other: &Self) -> bool {
        self.components.len() <= other.components.len()
            && self
                .components
                .iter()
                .zip(&other.components)
                .all(|(left, right)| left.to_lowercase() == right.to_lowercase())
    }
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

    pub(super) fn sync_all(&mut self) -> ManagedFsResult<()> {
        self.current_info_with_limit(true)?;
        self.file.sync_all().map_err(|error| {
            ManagedFsError::io("Cannot flush managed resumable file", &self.path, error)
        })?;
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

    pub(super) fn commit_no_replace(
        mut self,
        destination: RelativeManagedPath,
    ) -> ManagedFsResult<ResumableCommitOutcome> {
        self.sync_all()?;
        if self.relative == destination {
            return Err(ManagedFsError::Conflict(
                "Managed resumable source and destination are identical".into(),
            ));
        }
        let destination_parent = GuardedDirectoryChain::open_parent(&self.root, &destination)?;
        ensure_same_root_and_volume(&self.parent_chain, &destination_parent)?;
        let destination_path = destination.join_to(&self.root);
        match rename_handle(&self.file, &destination_path, ManagedRenameMode::NoReplace) {
            Ok(()) => {}
            Err(ManagedFsError::Conflict(_)) => {
                self.current_info_with_limit(true)?;
                return Ok(ResumableCommitOutcome::DestinationExists(self));
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
        Ok(ResumableCommitOutcome::Committed(CommittedManagedFile {
            destination,
            identity: after.identity,
            size: after.size,
        }))
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
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, SYNCHRONIZE,
    };

    OpenOptions::new()
        .access_mode(FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0)
        .share_mode(FILE_SHARE_READ.0)
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

#[cfg(not(windows))]
fn delete_open_file(_file: &File, path: &Path) -> ManagedFsResult<()> {
    fs::remove_file(path)
        .map_err(|error| ManagedFsError::io("Cannot delete verified managed file", path, error))
}

#[cfg(windows)]
fn node_info(file: &File, path: &Path) -> ManagedFsResult<NodeInfo> {
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
        case_sensitive_directory,
    })
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
        case_sensitive_directory: false,
    })
}

#[cfg(windows)]
fn verify_handle_path(file: &File, expected: &Path) -> ManagedFsResult<()> {
    let info = node_info(file, expected)?;
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
    let expected_metadata = fs::symlink_metadata(expected)
        .map_err(|error| ManagedFsError::io("Cannot verify managed path", expected, error))?;
    if expected_metadata.file_type().is_symlink()
        || metadata_identity(&expected_metadata) != node_info(file, expected)?.identity
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
    use std::{
        mem::{align_of, offset_of, size_of},
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

    let mut name: Vec<u16> = destination.as_os_str().encode_wide().collect();
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
    name.push(0);
    let offset = offset_of!(FILE_RENAME_INFO, FileName);
    let buffer_size = offset
        .checked_add(name.len() * size_of::<u16>())
        .ok_or_else(|| ManagedFsError::InvalidPath("Managed rename buffer overflow".into()))?;
    let words = buffer_size.div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; words];
    debug_assert_eq!(
        (storage.as_ptr() as usize) % align_of::<FILE_RENAME_INFO>(),
        0
    );
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
    fn immutable_handle_denies_concurrent_writers() {
        let root = temp_root("share-write");
        fs::create_dir_all(root.join("instances")).unwrap();
        fs::write(root.join("instances/locked.jar"), b"locked").unwrap();
        let relative = RelativeManagedPath::new("instances/locked.jar").unwrap();
        let immutable = ImmutableManagedFile::open(&root, &relative).unwrap();
        let writer = OpenOptions::new().write(true).open(relative.join_to(&root));
        assert!(writer.is_err());
        drop(immutable);
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
