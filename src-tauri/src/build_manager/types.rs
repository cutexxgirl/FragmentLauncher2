use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum BuildChannel {
    Stable,
    Dev,
}

impl BuildChannel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Dev => "dev",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum PresetId {
    Low,
    Medium,
    High,
}

impl PresetId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum BuildPhase {
    Checking,
    NotInstalled,
    Outdated,
    RepairNeeded,
    Ready,
    Authorizing,
    Downloading,
    Updating,
    Repairing,
    Verifying,
    Launching,
    Running,
    SubscriptionRequired,
    DevForbidden,
    AuthUnavailable,
    DiskInsufficient,
    LauncherUpdateRequired,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PrimaryAction {
    Download,
    Update,
    Repair,
    Play,
    Busy,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct TransferProgress {
    pub current_file: Option<String>,
    pub downloaded_bytes: u64,
    pub total_bytes: u64,
    pub speed_bytes_per_second: u64,
    pub remaining_bytes: u64,
    pub disk_free_bytes: u64,
    pub disk_required_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildStatus {
    pub channel: BuildChannel,
    pub preset: PresetId,
    pub phase: BuildPhase,
    pub primary_action: PrimaryAction,
    pub install_directory: Option<String>,
    pub installed_release_id: Option<String>,
    pub available_release_id: Option<String>,
    pub message: String,
    pub operation_active: bool,
    pub progress: TransferProgress,
}

impl BuildStatus {
    pub fn error(
        channel: BuildChannel,
        preset: PresetId,
        install_directory: Option<String>,
        message: String,
    ) -> Self {
        Self {
            channel,
            preset,
            phase: BuildPhase::Error,
            primary_action: PrimaryAction::Blocked,
            install_directory,
            installed_release_id: None,
            available_release_id: None,
            message,
            operation_active: false,
            progress: TransferProgress::default(),
        }
    }

    pub fn not_installed(
        channel: BuildChannel,
        preset: PresetId,
        install_directory: Option<String>,
        disk_free_bytes: u64,
    ) -> Self {
        Self {
            channel,
            preset,
            phase: BuildPhase::NotInstalled,
            primary_action: PrimaryAction::Blocked,
            install_directory,
            installed_release_id: None,
            available_release_id: None,
            message: "Загрузчик и TUF-клиент ещё не подключены: эта dev-ветка пока является безопасным каркасом.".into(),
            operation_active: false,
            progress: TransferProgress {
                disk_free_bytes,
                ..TransferProgress::default()
            },
        }
    }
}
