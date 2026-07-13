//! Bounded post-spawn launch-ticket orchestration.
//!
//! The game process supplies only its server-created challenge binding through the secured local
//! pipe. Everything else in the request is the immutable identity and release context captured
//! before that process was spawned. The bearer capability and the returned ticket never leave
//! native memory.

use std::{fmt, sync::Arc, time::Duration};

use tokio::time::sleep;
use uuid::Uuid;

use super::{
    launch_guard_ipc::{LaunchGuardIssueFailure, LaunchGuardRequestBinding, LaunchGuardTicket},
    launch_ticket_client::{
        ExpectedLaunchIdentity, LaunchTicketClient, LaunchTicketClientError,
        LaunchTicketConflictReason, LaunchTicketRequestContext, ValidatedLaunchTicket,
    },
    types::{BuildChannel, PresetId},
};
use crate::auth::{
    AdmissionChannel, AuthError, AuthSessionManager, LaunchTicketAuthLease, NativeAccessToken,
    RunningLaunchIdentity,
};

const DEFAULT_RETRY_DELAY: Duration = Duration::from_millis(250);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Immutable authority for one already-running Minecraft process.
///
/// A service is deliberately scoped to one process launch. Reusing it for a different release,
/// install, channel, preset, or admitted identity is impossible without constructing a new value.
pub(crate) struct LaunchTicketIssuer {
    auth: Arc<AuthSessionManager>,
    client: LaunchTicketClient,
    running_identity: RunningLaunchIdentity,
    base: LaunchTicketBaseContext,
}

struct LaunchTicketBaseContext {
    channel: BuildChannel,
    preset: PresetId,
    release_id: String,
    launcher_instance_id: Uuid,
    expected_identity: ExpectedLaunchIdentity,
}

impl LaunchTicketIssuer {
    pub(crate) fn new(
        auth: Arc<AuthSessionManager>,
        running_identity: RunningLaunchIdentity,
        channel: BuildChannel,
        preset: PresetId,
        release_id: String,
        launcher_instance_id: Uuid,
    ) -> Result<Self, LaunchGuardIssueFailure> {
        running_identity
            .validate()
            .map_err(|_| LaunchGuardIssueFailure::Fatal)?;
        if running_identity.channel() != admission_channel(channel)
            || !valid_release_id(&release_id)
            || launcher_instance_id.is_nil()
        {
            return Err(LaunchGuardIssueFailure::Fatal);
        }

        let expected_identity = ExpectedLaunchIdentity::new(
            running_identity.user_id(),
            running_identity.device_session_id(),
            running_identity.launcher_nick().to_owned(),
            running_identity.launcher_role(),
        )
        .map_err(map_client_error)?;
        let client = LaunchTicketClient::new().map_err(map_client_error)?;

        Ok(Self {
            auth,
            client,
            running_identity,
            base: LaunchTicketBaseContext {
                channel,
                preset,
                release_id,
                launcher_instance_id,
                expected_identity,
            },
        })
    }

    /// Issues one ticket with a global maximum of two ticket POST attempts.
    ///
    /// The only second-attempt paths are an exact 401 capability rotation or one retryable result.
    /// They are mutually exclusive; a failure from attempt two is always terminal here.
    pub(crate) async fn issue(
        self,
        binding: LaunchGuardRequestBinding,
    ) -> Result<LaunchGuardTicket, LaunchGuardIssueFailure> {
        let context = self.request_context(binding)?;
        let lease = self
            .auth
            .launch_ticket_auth_lease(&self.running_identity)
            .await
            .map_err(map_auth_error)?;
        self.validate_lease_identity(&lease)?;

        match self
            .issue_once(&context, lease.access_token().clone())
            .await
        {
            Ok(ticket) => prepare_delivery(ticket, lease),
            Err(error) if error.requires_token_rotation() => {
                let rejected = lease
                    .into_rejected_token()
                    .ok_or(LaunchGuardIssueFailure::AccessDenied)?;
                let rotated = self
                    .auth
                    .launch_ticket_auth_lease_after_rejection_completion_safe(
                        rejected,
                        &self.running_identity,
                    )
                    .await
                    .map_err(map_auth_error)?;
                self.validate_lease_identity(&rotated)?;
                let ticket = self
                    .issue_once(&context, rotated.access_token().clone())
                    .await
                    .map_err(map_client_error)?;
                prepare_delivery(ticket, rotated)
            }
            Err(error) if error.is_retryable() => {
                sleep(retry_delay(error.retry_after())).await;
                let ticket = self
                    .issue_once(&context, lease.access_token().clone())
                    .await
                    .map_err(map_client_error)?;
                prepare_delivery(ticket, lease)
            }
            Err(error) => Err(map_client_error(error)),
        }
    }

    fn request_context(
        &self,
        binding: LaunchGuardRequestBinding,
    ) -> Result<LaunchTicketRequestContext, LaunchGuardIssueFailure> {
        LaunchTicketRequestContext::new(
            self.base.channel,
            self.base.preset,
            self.base.release_id.clone(),
            binding.challenge_id(),
            binding.connection_id(),
            self.base.launcher_instance_id,
            self.base.expected_identity.clone(),
        )
        .map_err(map_client_error)
    }

    async fn issue_once(
        &self,
        context: &LaunchTicketRequestContext,
        token: NativeAccessToken,
    ) -> Result<ValidatedLaunchTicket, LaunchTicketClientError> {
        self.client.issue(context, token.expose()).await
    }

    fn validate_lease_identity(
        &self,
        lease: &LaunchTicketAuthLease,
    ) -> Result<(), LaunchGuardIssueFailure> {
        if lease.running_identity() != &self.running_identity {
            return Err(LaunchGuardIssueFailure::Fatal);
        }
        Ok(())
    }
}

impl fmt::Debug for LaunchTicketIssuer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LaunchTicketIssuer([redacted])")
    }
}

fn prepare_delivery(
    ticket: ValidatedLaunchTicket,
    lease: LaunchTicketAuthLease,
) -> Result<LaunchGuardTicket, LaunchGuardIssueFailure> {
    ticket.revalidate_fresh().map_err(map_client_error)?;
    let (bytes, expires_at, expires_monotonic) =
        ticket.into_delivery_parts().map_err(map_client_error)?;
    LaunchGuardTicket::new_with_deadlines_and_guard(bytes, expires_at, expires_monotonic, lease)
        .map_err(|_| LaunchGuardIssueFailure::ChallengeRejected)
}

const fn admission_channel(channel: BuildChannel) -> AdmissionChannel {
    match channel {
        BuildChannel::Stable => AdmissionChannel::Stable,
        BuildChannel::Dev => AdmissionChannel::Dev,
    }
}

fn retry_delay(retry_after: Option<Duration>) -> Duration {
    retry_after
        .unwrap_or(DEFAULT_RETRY_DELAY)
        .min(MAX_RETRY_DELAY)
}

fn valid_release_id(value: &str) -> bool {
    value.len() == 28
        && value.starts_with("rel_")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn map_auth_error(error: AuthError) -> LaunchGuardIssueFailure {
    match error {
        AuthError::SignedOut | AuthError::CredentialChanged | AuthError::SessionChanged => {
            LaunchGuardIssueFailure::AccessDenied
        }
        AuthError::Api(_) | AuthError::ProcessLock(_) => LaunchGuardIssueFailure::Retryable,
        AuthError::Credentials(_)
        | AuthError::Contract(_)
        | AuthError::NoActiveChallenge
        | AuthError::OpenTelegramLogin => LaunchGuardIssueFailure::Fatal,
    }
}

fn map_client_error(error: LaunchTicketClientError) -> LaunchGuardIssueFailure {
    match error {
        LaunchTicketClientError::Authentication | LaunchTicketClientError::Forbidden(_) => {
            LaunchGuardIssueFailure::AccessDenied
        }
        LaunchTicketClientError::Conflict(
            LaunchTicketConflictReason::ReleaseChanged
            | LaunchTicketConflictReason::ChallengeRejected
            | LaunchTicketConflictReason::ChallengeConflict,
        ) => LaunchGuardIssueFailure::ChallengeRejected,
        LaunchTicketClientError::Conflict(
            LaunchTicketConflictReason::IdentityChanged
            | LaunchTicketConflictReason::NicknameRequired,
        ) => LaunchGuardIssueFailure::AccessDenied,
        LaunchTicketClientError::Retryable { .. } => LaunchGuardIssueFailure::Retryable,
        LaunchTicketClientError::Conflict(LaunchTicketConflictReason::Other)
        | LaunchTicketClientError::ResponseTooLarge
        | LaunchTicketClientError::InvalidContentType
        | LaunchTicketClientError::InvalidResponse
        | LaunchTicketClientError::Http(_)
        | LaunchTicketClientError::InvalidRequest
        | LaunchTicketClientError::ClientSetup => LaunchGuardIssueFailure::Fatal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_is_bounded_and_has_a_small_default() {
        assert_eq!(retry_delay(None), DEFAULT_RETRY_DELAY);
        assert_eq!(retry_delay(Some(Duration::ZERO)), Duration::ZERO);
        assert_eq!(retry_delay(Some(Duration::from_secs(60))), MAX_RETRY_DELAY);
    }

    #[test]
    fn release_id_validation_matches_the_ticket_contract() {
        assert!(valid_release_id("rel_0123456789abcdef01234567"));
        assert!(!valid_release_id("rel_0123456789ABCDEF01234567"));
        assert!(!valid_release_id("rel_0123456789abcdef0123456"));
        assert!(!valid_release_id("bad_0123456789abcdef01234567"));
    }

    #[test]
    fn client_errors_map_without_rendering_server_or_secret_text() {
        assert_eq!(
            map_client_error(LaunchTicketClientError::Authentication),
            LaunchGuardIssueFailure::AccessDenied
        );
        assert_eq!(
            map_client_error(LaunchTicketClientError::Conflict(
                LaunchTicketConflictReason::ChallengeRejected
            )),
            LaunchGuardIssueFailure::ChallengeRejected
        );
        assert_eq!(
            map_client_error(LaunchTicketClientError::Retryable {
                retry_after: Some(Duration::from_secs(1)),
            }),
            LaunchGuardIssueFailure::Retryable
        );
        assert_eq!(
            map_client_error(LaunchTicketClientError::InvalidResponse),
            LaunchGuardIssueFailure::Fatal
        );
    }

    #[test]
    fn auth_errors_have_only_coarse_ipc_outcomes() {
        assert_eq!(
            map_auth_error(AuthError::SessionChanged),
            LaunchGuardIssueFailure::AccessDenied
        );
        assert_eq!(
            map_auth_error(AuthError::Api("secret upstream detail".into())),
            LaunchGuardIssueFailure::Retryable
        );
        assert_eq!(
            map_auth_error(AuthError::Contract("secret contract detail".into())),
            LaunchGuardIssueFailure::Fatal
        );
    }
}
