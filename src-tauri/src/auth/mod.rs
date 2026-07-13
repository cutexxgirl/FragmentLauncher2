mod client;
mod credential_store;
mod process_lock;
mod session;
mod types;

pub use session::{AuthError, AuthSessionManager};
pub(crate) use session::{NativeAccessFailure, NativeAccessToken};
pub use types::{
    AdmissionChannel, AuthSnapshot, EntitlementSnapshot, LauncherAdmissionReason,
    LauncherAdmissionSnapshot, LauncherProfile, LauncherRole, SubscriptionLevel,
    TelegramLoginSnapshot, TelegramPollSnapshot,
};
