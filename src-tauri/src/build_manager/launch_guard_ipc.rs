//! Child-bound local IPC for the future Fragment launch-guard mod.
//!
//! This module deliberately stops at the launcher side of the protocol. The Minecraft mod will
//! read the two bootstrap environment variables, open the pipe with
//! [`LAUNCH_GUARD_CLIENT_ACCESS_MASK`] (not `GENERIC_WRITE`), and send the fixed request frame.
//! The launch ticket itself is never placed in argv, the environment, a file, or a diagnostic.

use std::{
    ffi::OsString,
    fmt,
    future::Future,
    time::{Duration, Instant as MonotonicInstant, SystemTime},
};

use uuid::Uuid;
#[cfg(test)]
use zeroize::Zeroize;
use zeroize::Zeroizing;

pub(crate) const LAUNCH_GUARD_PIPE_ENV: &str = "FRAGMENT_LAUNCH_GUARD_PIPE";
pub(crate) const LAUNCH_GUARD_NONCE_ENV: &str = "FRAGMENT_LAUNCH_GUARD_NONCE";

/// Exact access mask the future guard must request from `CreateFileW`.
///
/// This grants `FILE_READ_DATA`, `FILE_WRITE_DATA`, `FILE_READ_ATTRIBUTES`,
/// `FILE_WRITE_ATTRIBUTES`, `READ_CONTROL`, and `SYNCHRONIZE`. It intentionally excludes
/// `FILE_APPEND_DATA`, whose named-pipe meaning overlaps `FILE_CREATE_PIPE_INSTANCE`.
pub(crate) const LAUNCH_GUARD_CLIENT_ACCESS_MASK: u32 = 0x0012_0183;

const REQUEST_MAGIC: [u8; 8] = *b"FRG2LGRQ";
const RESPONSE_MAGIC: [u8; 8] = *b"FRG2LGRS";
const ACK_MAGIC: [u8; 8] = *b"FRG2LGAK";
const PROTOCOL_VERSION: u16 = 1;
const BOOTSTRAP_NONCE_BYTES: usize = 32;
const UUID_BYTES: usize = 16;
const REQUEST_FRAME_BYTES: usize =
    REQUEST_MAGIC.len() + 2 + 2 + BOOTSTRAP_NONCE_BYTES + UUID_BYTES + UUID_BYTES;
const RESPONSE_HEADER_BYTES: usize = RESPONSE_MAGIC.len() + 2 + 2 + 2 + 2 + UUID_BYTES;
const ACK_FRAME_BYTES: usize = ACK_MAGIC.len() + 2 + 2 + UUID_BYTES;
const MAX_TICKET_BYTES: usize = 4096;
const MAX_TICKET_LIFETIME: Duration = Duration::from_secs(60);
// The ticket must survive the complete 2s ACK window plus a fail-closed scheduling margin.
const MIN_TICKET_REMAINING: Duration = Duration::from_secs(3);

#[derive(Clone, Copy)]
struct TicketFreshnessDeadlines {
    wall: SystemTime,
    monotonic: MonotonicInstant,
}

impl TicketFreshnessDeadlines {
    fn remaining(self) -> Option<Duration> {
        let wall_remaining = self
            .wall
            .duration_since(SystemTime::now())
            .ok()?
            .checked_sub(MIN_TICKET_REMAINING)?;
        let monotonic_remaining = self
            .monotonic
            .checked_duration_since(MonotonicInstant::now())?
            .checked_sub(MIN_TICKET_REMAINING)?;
        let remaining = wall_remaining.min(monotonic_remaining);
        (!remaining.is_zero()).then_some(remaining)
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct LaunchGuardBootstrap {
    pipe_name: String,
    nonce_text: Zeroizing<String>,
}

impl LaunchGuardBootstrap {
    pub(crate) fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    pub(crate) fn nonce_text(&self) -> &str {
        self.nonce_text.as_str()
    }

    /// Returns the only two launch-guard values permitted in the child environment.
    pub(crate) fn environment(&self) -> [(OsString, OsString); 2] {
        [
            (
                OsString::from(LAUNCH_GUARD_PIPE_ENV),
                OsString::from(&self.pipe_name),
            ),
            (
                OsString::from(LAUNCH_GUARD_NONCE_ENV),
                OsString::from(self.nonce_text.as_str()),
            ),
        ]
    }
}

impl fmt::Debug for LaunchGuardBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchGuardBootstrap")
            .field("pipe_name", &"[redacted]")
            .field("nonce", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LaunchGuardRequestBinding {
    challenge_id: Uuid,
    connection_id: Uuid,
}

impl LaunchGuardRequestBinding {
    pub(crate) fn challenge_id(self) -> Uuid {
        self.challenge_id
    }

    pub(crate) fn connection_id(self) -> Uuid {
        self.connection_id
    }
}

impl fmt::Debug for LaunchGuardRequestBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchGuardRequestBinding")
            .field("binding", &"[redacted]")
            .finish()
    }
}

/// A ticket that remains exclusively in memory until the exact child consumes it.
pub(crate) struct LaunchGuardTicket {
    bytes: Zeroizing<Vec<u8>>,
    expires_at: SystemTime,
    expires_monotonic: MonotonicInstant,
    _delivery_guard: Box<dyn Send + 'static>,
}

impl LaunchGuardTicket {
    #[cfg(test)]
    pub(crate) fn new(bytes: Vec<u8>, expires_at: SystemTime) -> Result<Self, String> {
        let bytes = Zeroizing::new(bytes);
        let remaining = expires_at
            .duration_since(SystemTime::now())
            .map_err(|_| "Launch ticket is already expired".to_string())?
            .min(MAX_TICKET_LIFETIME);
        let expires_monotonic = MonotonicInstant::now()
            .checked_add(remaining)
            .ok_or_else(|| "Launch ticket monotonic deadline overflowed".to_string())?;
        Self::from_zeroizing_with_deadlines_and_guard(bytes, expires_at, expires_monotonic, ())
    }

    /// Takes the original monotonic deadline produced while the HTTP response was validated.
    /// Reconstructing it later from wall time could extend a ticket after a wall-clock rollback.
    pub(crate) fn new_with_deadlines_and_guard<G>(
        bytes: Vec<u8>,
        expires_at: SystemTime,
        expires_monotonic: MonotonicInstant,
        delivery_guard: G,
    ) -> Result<Self, String>
    where
        G: Send + 'static,
    {
        Self::from_zeroizing_with_deadlines_and_guard(
            Zeroizing::new(bytes),
            expires_at,
            expires_monotonic,
            delivery_guard,
        )
    }

    fn from_zeroizing_with_deadlines_and_guard<G>(
        bytes: Zeroizing<Vec<u8>>,
        expires_at: SystemTime,
        expires_monotonic: MonotonicInstant,
        delivery_guard: G,
    ) -> Result<Self, String>
    where
        G: Send + 'static,
    {
        if bytes.is_empty() || bytes.len() > MAX_TICKET_BYTES {
            return Err("Launch ticket size is outside the IPC contract".into());
        }
        let wall_remaining = expires_at
            .duration_since(SystemTime::now())
            .map_err(|_| "Launch ticket is already expired".to_string())?;
        let monotonic_remaining = expires_monotonic
            .checked_duration_since(MonotonicInstant::now())
            .ok_or_else(|| "Launch ticket monotonic deadline is already expired".to_string())?;
        if monotonic_remaining > MAX_TICKET_LIFETIME
            || wall_remaining.is_zero()
            || monotonic_remaining.is_zero()
        {
            return Err("Launch ticket lifetime is outside the IPC contract".into());
        }
        Ok(Self {
            bytes,
            expires_at,
            expires_monotonic,
            _delivery_guard: Box::new(delivery_guard),
        })
    }

    fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    fn is_fresh_for_delivery(&self) -> bool {
        self.freshness_remaining().is_some()
    }

    /// Remaining time until the ticket can no longer safely survive a complete ACK window.
    ///
    /// The wall deadline catches clock jumps forward. The original monotonic deadline is the
    /// upper bound when wall time moves backward, so neither clock can extend the ticket.
    fn freshness_remaining(&self) -> Option<Duration> {
        self.freshness_deadlines().remaining()
    }

    fn freshness_deadlines(&self) -> TicketFreshnessDeadlines {
        TicketFreshnessDeadlines {
            wall: self.expires_at,
            monotonic: self.expires_monotonic,
        }
    }
}

impl fmt::Debug for LaunchGuardTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchGuardTicket")
            .field("bytes", &"[redacted]")
            .field("length", &self.bytes.len())
            .field("delivery_guard", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LaunchGuardIssueFailure {
    Retryable,
    AccessDenied,
    ChallengeRejected,
    Fatal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LaunchGuardBrokerOutcome {
    Delivered,
    Rejected(LaunchGuardIssueFailure),
    Cancelled,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WireStatus {
    Ticket = 0,
    Retryable = 1,
    AccessDenied = 2,
    ChallengeRejected = 3,
    Fatal = 4,
}

impl From<LaunchGuardIssueFailure> for WireStatus {
    fn from(failure: LaunchGuardIssueFailure) -> Self {
        match failure {
            LaunchGuardIssueFailure::Retryable => Self::Retryable,
            LaunchGuardIssueFailure::AccessDenied => Self::AccessDenied,
            LaunchGuardIssueFailure::ChallengeRejected => Self::ChallengeRejected,
            LaunchGuardIssueFailure::Fatal => Self::Fatal,
        }
    }
}

struct BootstrapNonce(Zeroizing<[u8; BOOTSTRAP_NONCE_BYTES]>);

impl BootstrapNonce {
    fn random() -> Self {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut bytes = [0_u8; BOOTSTRAP_NONCE_BYTES];
        bytes[..UUID_BYTES].copy_from_slice(first.as_bytes());
        bytes[UUID_BYTES..].copy_from_slice(second.as_bytes());
        Self(Zeroizing::new(bytes))
    }

    fn as_bytes(&self) -> &[u8; BOOTSTRAP_NONCE_BYTES] {
        &self.0
    }

    fn text(&self) -> Zeroizing<String> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(BOOTSTRAP_NONCE_BYTES * 2);
        for byte in self.0.iter().copied() {
            text.push(HEX[(byte >> 4) as usize] as char);
            text.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Zeroizing::new(text)
    }
}

impl fmt::Debug for BootstrapNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrapNonce([redacted])")
    }
}

fn decode_request(
    frame: &[u8],
    expected_nonce: &[u8; BOOTSTRAP_NONCE_BYTES],
) -> Result<LaunchGuardRequestBinding, String> {
    if frame.len() != REQUEST_FRAME_BYTES {
        return Err("Launch-guard request length is invalid".into());
    }
    if frame[..REQUEST_MAGIC.len()] != REQUEST_MAGIC {
        return Err("Launch-guard request magic is invalid".into());
    }
    let version_offset = REQUEST_MAGIC.len();
    let version = u16::from_be_bytes([frame[version_offset], frame[version_offset + 1]]);
    if version != PROTOCOL_VERSION {
        return Err("Launch-guard protocol version is unsupported".into());
    }
    if frame[version_offset + 2..version_offset + 4] != [0, 0] {
        return Err("Launch-guard request reserved bits are nonzero".into());
    }

    let nonce_offset = version_offset + 4;
    let received_nonce = &frame[nonce_offset..nonce_offset + BOOTSTRAP_NONCE_BYTES];
    if !constant_time_equal(received_nonce, expected_nonce) {
        return Err("Launch-guard bootstrap proof is invalid".into());
    }

    let challenge_offset = nonce_offset + BOOTSTRAP_NONCE_BYTES;
    let connection_offset = challenge_offset + UUID_BYTES;
    let challenge_id = Uuid::from_bytes(
        frame[challenge_offset..connection_offset]
            .try_into()
            .map_err(|_| "Launch-guard challenge ID is malformed")?,
    );
    let connection_id = Uuid::from_bytes(
        frame[connection_offset..connection_offset + UUID_BYTES]
            .try_into()
            .map_err(|_| "Launch-guard connection ID is malformed")?,
    );
    if challenge_id.is_nil() || connection_id.is_nil() {
        return Err("Launch-guard binding contains a nil ID".into());
    }
    Ok(LaunchGuardRequestBinding {
        challenge_id,
        connection_id,
    })
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn encode_response(
    status: WireStatus,
    delivery_id: Option<Uuid>,
    ticket: Option<&[u8]>,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let ticket = ticket.unwrap_or_default();
    let is_ticket = status == WireStatus::Ticket;
    if ticket.len() > MAX_TICKET_BYTES
        || is_ticket == ticket.is_empty()
        || is_ticket != delivery_id.is_some()
    {
        return Err("Launch-guard response violates the ticket contract".into());
    }
    let ticket_length = u16::try_from(ticket.len())
        .map_err(|_| "Launch-guard response length overflowed".to_string())?;
    let mut response = Vec::with_capacity(RESPONSE_HEADER_BYTES + ticket.len());
    response.extend_from_slice(&RESPONSE_MAGIC);
    response.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    response.extend_from_slice(&(status as u16).to_be_bytes());
    response.extend_from_slice(&ticket_length.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(delivery_id.unwrap_or(Uuid::nil()).as_bytes());
    response.extend_from_slice(ticket);
    Ok(Zeroizing::new(response))
}

fn decode_ack(frame: &[u8], expected_delivery_id: Uuid) -> Result<(), String> {
    if frame.len() != ACK_FRAME_BYTES {
        return Err("Launch-guard acknowledgement length is invalid".into());
    }
    if frame[..ACK_MAGIC.len()] != ACK_MAGIC {
        return Err("Launch-guard acknowledgement magic is invalid".into());
    }
    let version_offset = ACK_MAGIC.len();
    let version = u16::from_be_bytes([frame[version_offset], frame[version_offset + 1]]);
    if version != PROTOCOL_VERSION {
        return Err("Launch-guard acknowledgement version is unsupported".into());
    }
    if frame[version_offset + 2..version_offset + 4] != [0, 0] {
        return Err("Launch-guard acknowledgement reserved bits are nonzero".into());
    }
    let delivery_offset = version_offset + 4;
    let received = Uuid::from_bytes(
        frame[delivery_offset..delivery_offset + UUID_BYTES]
            .try_into()
            .map_err(|_| "Launch-guard acknowledgement ID is malformed")?,
    );
    if received != expected_delivery_id || received.is_nil() {
        return Err("Launch-guard acknowledgement ID is invalid".into());
    }
    Ok(())
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        ffi::{c_void, OsStr},
        mem::size_of,
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions},
        sync::watch,
        time::{sleep, timeout},
    };
    use windows::{
        core::{BOOL, PCWSTR, PWSTR},
        Win32::{
            Foundation::{
                GetHandleInformation, LocalFree, ERROR_PIPE_NOT_CONNECTED, HANDLE,
                HANDLE_FLAG_INHERIT, HLOCAL,
            },
            Security::{
                Authorization::{
                    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                    SDDL_REVISION_1,
                },
                GetTokenInformation, TokenLogonSid, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
                TOKEN_GROUPS, TOKEN_QUERY,
            },
            System::{
                Pipes::GetNamedPipeClientProcessId,
                Threading::{GetCurrentProcess, OpenProcessToken},
            },
        },
    };

    use super::super::process_supervisor::SuspendedProcessBinding;

    const IO_TIMEOUT: Duration = Duration::from_secs(5);
    const ACK_TIMEOUT: Duration = Duration::from_secs(2);
    const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(250);
    const MAX_FOREIGN_CONNECTIONS: usize = 3;
    const MAX_EXACT_REQUESTS: usize = 2;

    pub(crate) struct PendingLaunchGuardBroker {
        server: NamedPipeServer,
        nonce: BootstrapNonce,
    }

    impl PendingLaunchGuardBroker {
        /// Creates the secured first pipe instance before Java's environment is assembled.
        pub(crate) fn prepare() -> Result<(Self, LaunchGuardBootstrap), String> {
            let nonce = BootstrapNonce::random();
            let pipe_name = format!(
                r"\\.\pipe\fragment-launch-guard-{}",
                Uuid::new_v4().as_hyphenated()
            );
            let server = create_secured_server(&pipe_name)?;
            let bootstrap = LaunchGuardBootstrap {
                pipe_name,
                nonce_text: nonce.text(),
            };
            Ok((Self { server, nonce }, bootstrap))
        }

        /// Arms the broker with the exact suspended Java root.
        ///
        /// `SuspendedProcessBinding` owns non-inheritable duplicates of the root process and Job
        /// handles. The process supervisor must create it only after `IsProcessInJob` succeeds and
        /// pass it here before releasing any mutable seals and before `ResumeThread`.
        pub(crate) fn arm(
            self,
            binding: SuspendedProcessBinding,
        ) -> Result<ArmedLaunchGuardBroker, String> {
            if !binding.validate_exact_client_pid(binding.pid())? {
                return Err("Suspended launch-guard root binding is no longer valid".into());
            }
            Ok(ArmedLaunchGuardBroker {
                server: self.server,
                nonce: self.nonce,
                binding,
            })
        }
    }

    impl fmt::Debug for PendingLaunchGuardBroker {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("PendingLaunchGuardBroker([redacted])")
        }
    }

    pub(crate) struct ArmedLaunchGuardBroker {
        server: NamedPipeServer,
        nonce: BootstrapNonce,
        binding: SuspendedProcessBinding,
    }

    impl fmt::Debug for ArmedLaunchGuardBroker {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("ArmedLaunchGuardBroker")
                .field("root_pid", &self.binding.pid())
                .field("pipe", &"[redacted]")
                .finish()
        }
    }

    impl ArmedLaunchGuardBroker {
        /// Serves one logical launch request, with one exact-binding recovery attempt.
        ///
        /// The issuer future must be internally bounded. Once it starts, shutdown does not cancel
        /// it: auth-token rotation and an ambiguous Spark response must reach their completion-safe
        /// boundary. Shutdown is observed immediately before any ticket write.
        pub(crate) async fn serve<F, Fut>(
            mut self,
            mut shutdown: watch::Receiver<bool>,
            mut issue: F,
        ) -> Result<LaunchGuardBrokerOutcome, String>
        where
            F: FnMut(LaunchGuardRequestBinding) -> Fut + Send,
            Fut: Future<Output = Result<LaunchGuardTicket, LaunchGuardIssueFailure>> + Send,
        {
            let mut foreign_connections = 0_usize;
            let mut exact_requests = 0_usize;
            let mut expected_binding = None;
            let mut recoverable_ticket: Option<(Uuid, LaunchGuardTicket)> = None;

            loop {
                if drop_recoverable_if_stale(&mut recoverable_ticket) {
                    return Ok(LaunchGuardBrokerOutcome::Rejected(
                        LaunchGuardIssueFailure::Fatal,
                    ));
                }
                if !self.binding.validate_exact_client_pid(self.binding.pid())? {
                    return Ok(LaunchGuardBrokerOutcome::Cancelled);
                }
                if shutdown_is_set(&mut shutdown) {
                    return Ok(LaunchGuardBrokerOutcome::Cancelled);
                }
                {
                    let connect = self.server.connect();
                    tokio::pin!(connect);
                    loop {
                        let reconnect_wait = match recoverable_ticket.as_ref() {
                            Some((_, ticket)) => ticket
                                .freshness_remaining()
                                .map(|remaining| remaining.min(PROCESS_POLL_INTERVAL))
                                .unwrap_or(Duration::ZERO),
                            None => PROCESS_POLL_INTERVAL,
                        };
                        tokio::select! {
                            biased;
                            _ = wait_for_shutdown(&mut shutdown) => {
                                return Ok(LaunchGuardBrokerOutcome::Cancelled);
                            }
                            result = &mut connect => {
                                result.map_err(|_| "Launch-guard pipe connection failed".to_string())?;
                                break;
                            }
                            _ = sleep(reconnect_wait) => {
                                if !self.binding.validate_exact_client_pid(self.binding.pid())? {
                                    return Ok(LaunchGuardBrokerOutcome::Cancelled);
                                }
                                if drop_recoverable_if_stale(&mut recoverable_ticket) {
                                    return Ok(LaunchGuardBrokerOutcome::Rejected(
                                        LaunchGuardIssueFailure::Fatal,
                                    ));
                                }
                            }
                        }
                    }
                }

                let client_pid = client_pid(&self.server)?;
                if client_pid != self.binding.pid() {
                    foreign_connections += 1;
                    disconnect_for_retry(&self.server)?;
                    if foreign_connections >= MAX_FOREIGN_CONNECTIONS {
                        return Err("Too many foreign launch-guard pipe connections".into());
                    }
                    continue;
                }
                if !self.binding.validate_exact_client_pid(client_pid)? {
                    return Ok(LaunchGuardBrokerOutcome::Cancelled);
                }
                exact_requests += 1;
                if exact_requests > MAX_EXACT_REQUESTS {
                    let _ = write_response_frame(
                        &mut self.server,
                        WireStatus::Fatal,
                        None,
                        None,
                        &mut shutdown,
                    )
                    .await;
                    return Err("Launch-guard exceeded its exact request limit".into());
                }

                let recovery_deadlines = recoverable_ticket
                    .as_ref()
                    .map(|(_, ticket)| ticket.freshness_deadlines());
                let request_result = if let Some(deadlines) = recovery_deadlines {
                    tokio::select! {
                        biased;
                        result = read_request(
                            &mut self.server,
                            self.nonce.as_bytes(),
                            &mut shutdown,
                        ) => Some(result),
                        _ = wait_until_ticket_stale(deadlines) => None,
                    }
                } else {
                    Some(read_request(&mut self.server, self.nonce.as_bytes(), &mut shutdown).await)
                };
                let Some(request_result) = request_result else {
                    drop(recoverable_ticket.take());
                    return Ok(LaunchGuardBrokerOutcome::Rejected(
                        LaunchGuardIssueFailure::Fatal,
                    ));
                };
                let request = match request_result {
                    Ok(Some(request)) => request,
                    Ok(None) => return Ok(LaunchGuardBrokerOutcome::Cancelled),
                    Err(error) => {
                        let _ = write_response_frame(
                            &mut self.server,
                            WireStatus::Fatal,
                            None,
                            None,
                            &mut shutdown,
                        )
                        .await;
                        return Err(error);
                    }
                };
                if expected_binding.is_some_and(|expected| expected != request) {
                    let _ = write_response_frame(
                        &mut self.server,
                        WireStatus::Fatal,
                        None,
                        None,
                        &mut shutdown,
                    )
                    .await;
                    return Err("Launch-guard retried with a different binding".into());
                }
                expected_binding = Some(request);
                if !self.binding.validate_exact_client_pid(client_pid)? {
                    return Ok(LaunchGuardBrokerOutcome::Cancelled);
                }

                let issued = match recoverable_ticket.take() {
                    Some(delivery) => Ok(delivery),
                    None => issue(request).await.map(|ticket| (Uuid::new_v4(), ticket)),
                };
                if shutdown_is_set(&mut shutdown) {
                    drop(issued);
                    return Ok(LaunchGuardBrokerOutcome::Cancelled);
                }
                if !self.binding.validate_exact_client_pid(client_pid)? {
                    drop(issued);
                    return Ok(LaunchGuardBrokerOutcome::Cancelled);
                }

                match issued {
                    Ok((_delivery_id, ticket)) if !ticket.is_fresh_for_delivery() => {
                        write_response_frame(
                            &mut self.server,
                            WireStatus::ChallengeRejected,
                            None,
                            None,
                            &mut shutdown,
                        )
                        .await?;
                        return Ok(LaunchGuardBrokerOutcome::Rejected(
                            LaunchGuardIssueFailure::ChallengeRejected,
                        ));
                    }
                    Ok((delivery_id, ticket)) => {
                        let should_retry = match write_response_frame(
                            &mut self.server,
                            WireStatus::Ticket,
                            Some(delivery_id),
                            Some(ticket.bytes()),
                            &mut shutdown,
                        )
                        .await
                        {
                            Ok(()) => {
                                match read_ack(&mut self.server, delivery_id, &mut shutdown).await {
                                    AckRead::Acknowledged => {
                                        if !self.binding.validate_exact_client_pid(client_pid)? {
                                            return Ok(LaunchGuardBrokerOutcome::Cancelled);
                                        }
                                        if !ticket.is_fresh_for_delivery() {
                                            return Ok(LaunchGuardBrokerOutcome::Rejected(
                                                LaunchGuardIssueFailure::ChallengeRejected,
                                            ));
                                        }
                                        return Ok(LaunchGuardBrokerOutcome::Delivered);
                                    }
                                    AckRead::Cancelled => {
                                        return Ok(LaunchGuardBrokerOutcome::Cancelled);
                                    }
                                    AckRead::Invalid(error) => return Err(error),
                                    AckRead::TransportFailure => true,
                                }
                            }
                            Err(_) if shutdown_is_set(&mut shutdown) => {
                                return Ok(LaunchGuardBrokerOutcome::Cancelled);
                            }
                            Err(_) => true,
                        };
                        if should_retry {
                            if exact_requests >= MAX_EXACT_REQUESTS {
                                return Err(
                                    "Launch-guard ticket acknowledgement was not received".into()
                                );
                            }
                            recoverable_ticket = Some((delivery_id, ticket));
                            disconnect_for_retry(&self.server)?;
                        }
                    }
                    Err(failure) => {
                        let status = WireStatus::from(failure);
                        write_response_frame(&mut self.server, status, None, None, &mut shutdown)
                            .await?;
                        return Ok(LaunchGuardBrokerOutcome::Rejected(failure));
                    }
                }
            }
        }
    }

    fn drop_recoverable_if_stale(recoverable: &mut Option<(Uuid, LaunchGuardTicket)>) -> bool {
        if recoverable
            .as_ref()
            .is_some_and(|(_, ticket)| !ticket.is_fresh_for_delivery())
        {
            // `LaunchGuardTicket` zeroizes its bytes before releasing the opaque auth lease.
            drop(recoverable.take());
            true
        } else {
            false
        }
    }

    async fn wait_until_ticket_stale(deadlines: TicketFreshnessDeadlines) {
        while let Some(remaining) = deadlines.remaining() {
            sleep(remaining.min(PROCESS_POLL_INTERVAL)).await;
        }
    }

    async fn read_request(
        server: &mut NamedPipeServer,
        expected_nonce: &[u8; BOOTSTRAP_NONCE_BYTES],
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<Option<LaunchGuardRequestBinding>, String> {
        let mut frame = Zeroizing::new([0_u8; REQUEST_FRAME_BYTES]);
        let read = timeout(IO_TIMEOUT, server.read_exact(&mut frame[..]));
        tokio::select! {
            biased;
            _ = wait_for_shutdown(shutdown) => Ok(None),
            result = read => {
                result
                    .map_err(|_| "Launch-guard request timed out".to_string())?
                    .map_err(|_| "Launch-guard request frame is incomplete".to_string())?;
                decode_request(&frame[..], expected_nonce).map(Some)
            }
        }
    }

    async fn write_response_frame(
        server: &mut NamedPipeServer,
        status: WireStatus,
        delivery_id: Option<Uuid>,
        ticket: Option<&[u8]>,
        shutdown: &mut watch::Receiver<bool>,
    ) -> Result<(), String> {
        let response = encode_response(status, delivery_id, ticket)?;
        let write = async {
            server
                .write_all(response.as_slice())
                .await
                .map_err(|_| "Launch-guard response write failed".to_string())?;
            server
                .flush()
                .await
                .map_err(|_| "Launch-guard response flush failed".to_string())
        };
        tokio::select! {
            biased;
            _ = wait_for_shutdown(shutdown) => Err("Launch-guard response was cancelled".into()),
            result = timeout(IO_TIMEOUT, write) => {
                result
                    .map_err(|_| "Launch-guard response timed out".to_string())?
            }
        }
    }

    enum AckRead {
        Acknowledged,
        Cancelled,
        TransportFailure,
        Invalid(String),
    }

    async fn read_ack(
        server: &mut NamedPipeServer,
        delivery_id: Uuid,
        shutdown: &mut watch::Receiver<bool>,
    ) -> AckRead {
        let mut frame = Zeroizing::new([0_u8; ACK_FRAME_BYTES]);
        let read = timeout(ACK_TIMEOUT, server.read_exact(&mut frame[..]));
        tokio::select! {
            biased;
            _ = wait_for_shutdown(shutdown) => AckRead::Cancelled,
            result = read => match result {
                Ok(Ok(_)) => match decode_ack(&frame[..], delivery_id) {
                    Ok(()) => AckRead::Acknowledged,
                    Err(error) => AckRead::Invalid(error),
                },
                Ok(Err(_)) | Err(_) => AckRead::TransportFailure,
            }
        }
    }

    fn client_pid(server: &NamedPipeServer) -> Result<u32, String> {
        let mut pid = 0_u32;
        unsafe { GetNamedPipeClientProcessId(HANDLE(server.as_raw_handle()), &mut pid) }
            .map_err(|_| "Cannot identify the launch-guard pipe client".to_string())?;
        if pid == 0 {
            return Err("Windows returned an invalid launch-guard client ID".into());
        }
        Ok(pid)
    }

    fn disconnect_for_retry(server: &NamedPipeServer) -> Result<(), String> {
        match server.disconnect() {
            Ok(()) => Ok(()),
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_NOT_CONNECTED.0 as i32) => Ok(()),
            Err(_) => Err("Cannot reset the launch-guard pipe".into()),
        }
    }

    fn shutdown_is_set(shutdown: &mut watch::Receiver<bool>) -> bool {
        if *shutdown.borrow_and_update() {
            return true;
        }
        shutdown.has_changed().is_err()
    }

    async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow_and_update() {
                return;
            }
            if shutdown.changed().await.is_err() {
                return;
            }
        }
    }

    fn create_secured_server(pipe_name: &str) -> Result<NamedPipeServer, String> {
        let descriptor = launch_guard_security_descriptor()?;
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0 .0,
            bInheritHandle: BOOL::from(false),
        };
        let mut options = ServerOptions::new();
        options
            .pipe_mode(PipeMode::Message)
            .first_pipe_instance(true)
            .max_instances(1)
            .reject_remote_clients(true)
            .in_buffer_size(REQUEST_FRAME_BYTES as u32)
            .out_buffer_size((RESPONSE_HEADER_BYTES + MAX_TICKET_BYTES) as u32);
        let server = unsafe {
            options.create_with_security_attributes_raw(
                pipe_name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
        }
        .map_err(|_| "Cannot create the secured launch-guard pipe".to_string())?;
        let mut flags = 0_u32;
        unsafe { GetHandleInformation(HANDLE(server.as_raw_handle()), &mut flags) }
            .map_err(|_| "Cannot verify launch-guard pipe inheritance".to_string())?;
        if flags & HANDLE_FLAG_INHERIT.0 != 0 {
            return Err("Launch-guard pipe handle is inheritable".into());
        }
        Ok(server)
    }

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            if !self.0 .0.is_null() {
                let _ = unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
            }
        }
    }

    fn launch_guard_security_descriptor() -> Result<LocalSecurityDescriptor, String> {
        let logon_sid = current_logon_sid_string()?;
        // `D:P` protects the DACL from inherited ACEs. SYSTEM keeps operational recovery access;
        // the exact logon SID receives only the client rights documented above.
        let sddl =
            format!("D:P(A;;GA;;;SY)(A;;0x{LAUNCH_GUARD_CLIENT_ACCESS_MASK:08x};;;{logon_sid})");
        let wide = nul_terminated(OsStr::new(&sddl));
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .map_err(|_| "Cannot build the launch-guard pipe security descriptor".to_string())?;
        if descriptor.0.is_null() {
            return Err("Windows returned an empty launch-guard security descriptor".into());
        }
        Ok(LocalSecurityDescriptor(descriptor))
    }

    fn current_logon_sid_string() -> Result<String, String> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(|_| "Cannot open the launcher process token".to_string())?;
        if token.is_invalid() {
            return Err("Windows returned an invalid launcher token".into());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(token.0) };

        let mut needed = 0_u32;
        let _ = unsafe {
            GetTokenInformation(token_handle(&token), TokenLogonSid, None, 0, &mut needed)
        };
        if needed < size_of::<TOKEN_GROUPS>() as u32 {
            return Err("Windows did not report a valid logon SID size".into());
        }
        let words = (needed as usize)
            .checked_add(size_of::<usize>() - 1)
            .ok_or_else(|| "Logon SID buffer size overflowed".to_string())?
            / size_of::<usize>();
        let mut storage = Zeroizing::new(vec![0_usize; words]);
        unsafe {
            GetTokenInformation(
                token_handle(&token),
                TokenLogonSid,
                Some(storage.as_mut_ptr().cast::<c_void>()),
                needed,
                &mut needed,
            )
        }
        .map_err(|_| "Cannot read the launcher logon SID".to_string())?;
        let groups = unsafe { &*storage.as_ptr().cast::<TOKEN_GROUPS>() };
        if groups.GroupCount != 1 || groups.Groups[0].Sid.0.is_null() {
            return Err("Launcher token has no unique logon SID".into());
        }

        let mut allocated = PWSTR::null();
        unsafe { ConvertSidToStringSidW(groups.Groups[0].Sid, &mut allocated) }
            .map_err(|_| "Cannot encode the launcher logon SID".to_string())?;
        if allocated.is_null() {
            return Err("Windows returned an empty logon SID".into());
        }
        let sid = LocalWideString(allocated);
        let text = unsafe { sid.0.to_string() }
            .map_err(|_| "Launcher logon SID is not valid Unicode".to_string())?;
        if !valid_sid_text(&text) {
            return Err("Launcher logon SID has an invalid textual form".into());
        }
        Ok(text)
    }

    struct LocalWideString(PWSTR);

    impl Drop for LocalWideString {
        fn drop(&mut self) {
            if !self.0.is_null() {
                let _ = unsafe { LocalFree(Some(HLOCAL(self.0 .0.cast::<c_void>()))) };
            }
        }
    }

    fn valid_sid_text(text: &str) -> bool {
        text.starts_with("S-")
            && text.len() <= 184
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'S' || byte == b'-')
    }

    fn token_handle(handle: &OwnedHandle) -> HANDLE {
        HANDLE(handle.as_raw_handle())
    }

    fn nul_terminated(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    use tokio::sync::watch;

    pub(crate) struct PendingLaunchGuardBroker;

    impl PendingLaunchGuardBroker {
        pub(crate) fn prepare() -> Result<(Self, LaunchGuardBootstrap), String> {
            Err("Launch-guard IPC is supported only on Windows".into())
        }

        pub(crate) fn arm<T>(self, _binding: T) -> Result<ArmedLaunchGuardBroker, String> {
            Err("Launch-guard IPC is supported only on Windows".into())
        }
    }

    pub(crate) struct ArmedLaunchGuardBroker;

    impl ArmedLaunchGuardBroker {
        pub(crate) async fn serve<F, Fut>(
            self,
            _shutdown: watch::Receiver<bool>,
            _issue: F,
        ) -> Result<LaunchGuardBrokerOutcome, String>
        where
            F: FnMut(LaunchGuardRequestBinding) -> Fut + Send,
            Fut: Future<Output = Result<LaunchGuardTicket, LaunchGuardIssueFailure>> + Send,
        {
            Err("Launch-guard IPC is supported only on Windows".into())
        }
    }
}

pub(crate) use platform::{ArmedLaunchGuardBroker, PendingLaunchGuardBroker};

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_request_for_test(
        nonce: &[u8; BOOTSTRAP_NONCE_BYTES],
        challenge_id: Uuid,
        connection_id: Uuid,
    ) -> Zeroizing<Vec<u8>> {
        let mut frame = Vec::with_capacity(REQUEST_FRAME_BYTES);
        frame.extend_from_slice(&REQUEST_MAGIC);
        frame.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        frame.extend_from_slice(&0_u16.to_be_bytes());
        frame.extend_from_slice(nonce);
        frame.extend_from_slice(challenge_id.as_bytes());
        frame.extend_from_slice(connection_id.as_bytes());
        Zeroizing::new(frame)
    }

    fn encode_ack_for_test(delivery_id: Uuid) -> Zeroizing<Vec<u8>> {
        let mut frame = Vec::with_capacity(ACK_FRAME_BYTES);
        frame.extend_from_slice(&ACK_MAGIC);
        frame.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        frame.extend_from_slice(&0_u16.to_be_bytes());
        frame.extend_from_slice(delivery_id.as_bytes());
        Zeroizing::new(frame)
    }

    #[test]
    fn fixed_request_round_trips_exact_binding() {
        let nonce = [0x5a; BOOTSTRAP_NONCE_BYTES];
        let challenge_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let frame = encode_request_for_test(&nonce, challenge_id, connection_id);

        assert_eq!(frame.len(), REQUEST_FRAME_BYTES);
        let decoded = decode_request(frame.as_slice(), &nonce).unwrap();
        assert_eq!(decoded.challenge_id(), challenge_id);
        assert_eq!(decoded.connection_id(), connection_id);
    }

    #[test]
    fn request_rejects_wrong_nonce_reserved_bits_and_trailing_bytes() {
        let nonce = [0x11; BOOTSTRAP_NONCE_BYTES];
        let challenge_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let base = encode_request_for_test(&nonce, challenge_id, connection_id);

        let mut wrong_nonce = base.to_vec();
        wrong_nonce[REQUEST_MAGIC.len() + 4] ^= 1;
        assert!(decode_request(&wrong_nonce, &nonce).is_err());
        wrong_nonce.zeroize();

        let mut reserved = base.to_vec();
        reserved[REQUEST_MAGIC.len() + 2] = 1;
        assert!(decode_request(&reserved, &nonce).is_err());
        reserved.zeroize();

        let mut trailing = base.to_vec();
        trailing.push(0);
        assert!(decode_request(&trailing, &nonce).is_err());
        trailing.zeroize();
    }

    #[test]
    fn request_rejects_nil_identifiers() {
        let nonce = [0x22; BOOTSTRAP_NONCE_BYTES];
        let frame = encode_request_for_test(&nonce, Uuid::nil(), Uuid::new_v4());
        assert!(decode_request(frame.as_slice(), &nonce).is_err());
    }

    #[test]
    fn response_has_strict_header_and_bounded_ticket() {
        let ticket = b"header.payload.signature";
        let delivery_id = Uuid::new_v4();
        let response =
            encode_response(WireStatus::Ticket, Some(delivery_id), Some(ticket)).unwrap();

        assert_eq!(&response[..RESPONSE_MAGIC.len()], &RESPONSE_MAGIC);
        assert_eq!(
            u16::from_be_bytes([response[8], response[9]]),
            PROTOCOL_VERSION
        );
        assert_eq!(u16::from_be_bytes([response[10], response[11]]), 0);
        assert_eq!(
            u16::from_be_bytes([response[12], response[13]]) as usize,
            ticket.len()
        );
        assert_eq!(&response[16..32], delivery_id.as_bytes());
        assert_eq!(&response[RESPONSE_HEADER_BYTES..], ticket);
        assert!(encode_response(
            WireStatus::Ticket,
            Some(delivery_id),
            Some(&vec![0; MAX_TICKET_BYTES + 1])
        )
        .is_err());
        assert!(encode_response(WireStatus::Ticket, None, None).is_err());
        assert!(encode_response(WireStatus::Fatal, None, Some(ticket)).is_err());
        assert!(encode_response(WireStatus::Fatal, Some(delivery_id), None).is_err());
    }

    #[test]
    fn acknowledgement_is_fixed_and_bound_to_one_delivery() {
        let delivery_id = Uuid::new_v4();
        let frame = encode_ack_for_test(delivery_id);

        assert_eq!(frame.len(), ACK_FRAME_BYTES);
        decode_ack(frame.as_slice(), delivery_id).unwrap();
        assert!(decode_ack(frame.as_slice(), Uuid::new_v4()).is_err());

        let mut reserved = frame.to_vec();
        reserved[ACK_MAGIC.len() + 2] = 1;
        assert!(decode_ack(&reserved, delivery_id).is_err());
        reserved.zeroize();
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        struct SecretGuard(String);
        impl Drop for SecretGuard {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        let bootstrap = LaunchGuardBootstrap {
            pipe_name: r"\\.\pipe\secret-name".into(),
            nonce_text: Zeroizing::new("secret-nonce".into()),
        };
        let ticket = LaunchGuardTicket::new_with_deadlines_and_guard(
            b"secret-ticket".to_vec(),
            SystemTime::now() + Duration::from_secs(30),
            MonotonicInstant::now() + Duration::from_secs(30),
            SecretGuard("secret-guard".into()),
        )
        .unwrap();

        let bootstrap_debug = format!("{bootstrap:?}");
        let ticket_debug = format!("{ticket:?}");
        assert!(!bootstrap_debug.contains("secret-name"));
        assert!(!bootstrap_debug.contains("secret-nonce"));
        assert!(!ticket_debug.contains("secret-ticket"));
        assert!(!ticket_debug.contains("secret-guard"));
    }

    #[test]
    fn freshness_uses_wall_forward_fail_closed_and_monotonic_rollback_cap() {
        let rollback_capped = LaunchGuardTicket::new_with_deadlines_and_guard(
            b"rollback-capped".to_vec(),
            SystemTime::now() + Duration::from_secs(3_600),
            MonotonicInstant::now() + Duration::from_secs(4),
            (),
        )
        .unwrap();
        let remaining = rollback_capped
            .freshness_remaining()
            .expect("the original monotonic deadline remains authoritative");
        assert!(remaining <= Duration::from_secs(1));

        let forward_expired = LaunchGuardTicket::new_with_deadlines_and_guard(
            b"forward-expired".to_vec(),
            SystemTime::now() + Duration::from_secs(2),
            MonotonicInstant::now() + Duration::from_secs(30),
            (),
        )
        .unwrap();
        assert!(!forward_expired.is_fresh_for_delivery());
        assert!(forward_expired.freshness_remaining().is_none());
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn secured_pipe_ack_and_recovery_expiry_are_enforced_end_to_end() {
        use std::{
            ffi::OsString,
            fs,
            io::Read,
            process::{Command, Stdio},
            sync::{
                atomic::{AtomicBool, AtomicUsize, Ordering},
                Arc,
            },
        };

        use super::super::process_supervisor::{
            spawn_command_with_inheritance_lock, spawn_with_before_resume_identity, ProcessSpec,
        };
        use tokio::sync::watch;

        struct TempDirectory(std::path::PathBuf);
        impl Drop for TempDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        struct DeliveryGuard(Arc<AtomicBool>);
        impl Drop for DeliveryGuard {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        const TEST_TICKET: &str = "test-only-ticket-sentinel";
        let directory = std::env::temp_dir().join(format!(
            "fragment-launch-guard-e2e-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        fs::create_dir(&directory).unwrap();
        let directory = TempDirectory(directory);
        let source = directory.0.join("guard_probe.rs");
        let executable = directory.0.join("guard_probe.exe");
        fs::write(
            &source,
            r#"
use std::{ffi::c_void, ptr};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileW(
        name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security: *mut c_void,
        creation: u32,
        flags: u32,
        template: *mut c_void,
    ) -> *mut c_void;
    fn ReadFile(
        file: *mut c_void,
        buffer: *mut c_void,
        bytes_to_read: u32,
        bytes_read: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn WriteFile(
        file: *mut c_void,
        buffer: *const c_void,
        bytes_to_write: u32,
        bytes_written: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

const CLIENT_ACCESS: u32 = 0x0012_0183;
const EXPECTED_TICKET: &[u8] = b"test-only-ticket-sentinel";

fn fail(code: i32) -> ! {
    std::process::exit(code)
}

fn write_exact(handle: *mut c_void, bytes: &[u8], code: i32) {
    let mut written = 0_u32;
    let ok = unsafe {
        WriteFile(
            handle,
            bytes.as_ptr().cast(),
            bytes.len() as u32,
            &mut written,
            ptr::null_mut(),
        )
    };
    if ok == 0 || written as usize != bytes.len() {
        fail(code);
    }
}

fn main() {
    let pipe = std::env::var("FRAGMENT_LAUNCH_GUARD_PIPE").unwrap_or_else(|_| fail(10));
    let nonce = std::env::var("FRAGMENT_LAUNCH_GUARD_NONCE").unwrap_or_else(|_| fail(11));
    if nonce.len() != 64 {
        fail(12);
    }
    let mut nonce_bytes = [0_u8; 32];
    for (index, byte) in nonce_bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&nonce[index * 2..index * 2 + 2], 16)
            .unwrap_or_else(|_| fail(13));
    }
    let wide = pipe.encode_utf16().chain(std::iter::once(0)).collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            CLIENT_ACCESS,
            0,
            ptr::null_mut(),
            3,
            0,
            ptr::null_mut(),
        )
    };
    if handle as isize == -1 || handle.is_null() {
        fail(14);
    }

    let mut request = [0_u8; 76];
    request[..8].copy_from_slice(b"FRG2LGRQ");
    request[8..10].copy_from_slice(&1_u16.to_be_bytes());
    request[12..44].copy_from_slice(&nonce_bytes);
    request[44..60].fill(1);
    request[60..76].fill(2);
    write_exact(handle, &request, 15);
    nonce_bytes.fill(0);
    request.fill(0);

    let mut response = [0_u8; 4128];
    let mut read = 0_u32;
    let ok = unsafe {
        ReadFile(
            handle,
            response.as_mut_ptr().cast(),
            response.len() as u32,
            &mut read,
            ptr::null_mut(),
        )
    };
    if ok == 0 || read < 32 {
        fail(16);
    }
    let read = read as usize;
    if &response[..8] != b"FRG2LGRS"
        || u16::from_be_bytes([response[8], response[9]]) != 1
        || u16::from_be_bytes([response[10], response[11]]) != 0
        || response[14..16] != [0, 0]
    {
        fail(17);
    }
    let ticket_length = u16::from_be_bytes([response[12], response[13]]) as usize;
    if read != 32 + ticket_length || &response[32..read] != EXPECTED_TICKET {
        fail(18);
    }
    if std::env::args().any(|argument| argument == "--no-ack") {
        response.fill(0);
        std::thread::sleep(std::time::Duration::from_secs(30));
        return;
    }
    let mut ack = [0_u8; 28];
    ack[..8].copy_from_slice(b"FRG2LGAK");
    ack[8..10].copy_from_slice(&1_u16.to_be_bytes());
    ack[12..28].copy_from_slice(&response[16..32]);
    response.fill(0);
    write_exact(handle, &ack, 19);
    ack.fill(0);
    let _ = unsafe { CloseHandle(handle) };
    println!("guard-ok");
}
"#,
        )
        .unwrap();

        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
        let mut compilation_command = Command::new(rustc);
        compilation_command
            .arg("--edition=2021")
            .args(["--crate-name", "fragment_launch_guard_probe"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let compilation = spawn_command_with_inheritance_lock(&mut compilation_command)
            .unwrap()
            .wait_with_output()
            .unwrap();
        assert!(
            compilation.status.success(),
            "guard probe compilation failed: {}",
            String::from_utf8_lossy(&compilation.stderr)
        );

        let (pending, bootstrap) = PendingLaunchGuardBroker::prepare().unwrap();
        assert_eq!(bootstrap.environment().len(), 2);
        let environment = bootstrap.environment();
        let mut pending = Some(pending);
        let mut armed = None;
        let (mut child, mut pipes) = spawn_with_before_resume_identity(
            ProcessSpec {
                executable: &executable,
                arguments: &[],
                cwd: &directory.0,
                environment: &environment,
            },
            |binding| {
                armed = Some(
                    pending
                        .take()
                        .expect("the suspended gate owns one pending broker")
                        .arm(binding)?,
                );
                Ok(())
            },
        )
        .unwrap();
        let armed = armed.expect("the suspended gate must arm the broker");
        let guard_dropped = Arc::new(AtomicBool::new(false));
        let issue_guard_dropped = Arc::clone(&guard_dropped);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);

        let outcome = armed
            .serve(shutdown_rx, move |binding| {
                let issue_guard_dropped = Arc::clone(&issue_guard_dropped);
                async move {
                    assert_eq!(binding.challenge_id().as_bytes(), &[1_u8; 16]);
                    assert_eq!(binding.connection_id().as_bytes(), &[2_u8; 16]);
                    let ticket = LaunchGuardTicket::new_with_deadlines_and_guard(
                        TEST_TICKET.as_bytes().to_vec(),
                        SystemTime::now() + Duration::from_secs(30),
                        MonotonicInstant::now() + Duration::from_secs(30),
                        DeliveryGuard(issue_guard_dropped),
                    )
                    .unwrap();
                    assert!(!format!("{ticket:?}").contains(TEST_TICKET));
                    Ok(ticket)
                }
            })
            .await
            .unwrap();
        assert_eq!(outcome, LaunchGuardBrokerOutcome::Delivered);
        assert!(guard_dropped.load(Ordering::Acquire));

        let exit_code = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(code) = child.try_wait().unwrap() {
                    break code;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("guard probe must exit");
        assert_eq!(exit_code, 0);
        let mut stdout = String::new();
        pipes.stdout.read_to_string(&mut stdout).unwrap();
        let mut stderr = String::new();
        pipes.stderr.read_to_string(&mut stderr).unwrap();
        assert_eq!(stdout, "guard-ok\n");
        assert!(stderr.is_empty(), "guard probe stderr: {stderr}");
        assert!(!stdout.contains(TEST_TICKET));
        assert!(!stderr.contains(TEST_TICKET));

        // Regression: after an ambiguous delivery the exact same ticket and auth guard may be
        // retained for one reconnect, but never beyond the ticket's original freshness window.
        let (pending, bootstrap) = PendingLaunchGuardBroker::prepare().unwrap();
        let environment = bootstrap.environment();
        let arguments = [OsString::from("--no-ack")];
        let mut pending = Some(pending);
        let mut armed = None;
        let (mut no_ack_child, mut no_ack_pipes) = spawn_with_before_resume_identity(
            ProcessSpec {
                executable: &executable,
                arguments: &arguments,
                cwd: &directory.0,
                environment: &environment,
            },
            |binding| {
                armed = Some(
                    pending
                        .take()
                        .expect("the expiry gate owns one pending broker")
                        .arm(binding)?,
                );
                Ok(())
            },
        )
        .unwrap();
        let armed = armed.expect("the expiry gate must arm the broker");
        let guard_dropped = Arc::new(AtomicBool::new(false));
        let issue_guard_dropped = Arc::clone(&guard_dropped);
        let issue_calls = Arc::new(AtomicUsize::new(0));
        let issue_calls_for_broker = Arc::clone(&issue_calls);
        let (_expiry_shutdown_tx, expiry_shutdown_rx) = watch::channel(false);
        let started = MonotonicInstant::now();

        let outcome = tokio::time::timeout(
            Duration::from_secs(8),
            armed.serve(expiry_shutdown_rx, move |binding| {
                let issue_guard_dropped = Arc::clone(&issue_guard_dropped);
                let issue_calls = Arc::clone(&issue_calls_for_broker);
                async move {
                    issue_calls.fetch_add(1, Ordering::AcqRel);
                    assert_eq!(binding.challenge_id().as_bytes(), &[1_u8; 16]);
                    assert_eq!(binding.connection_id().as_bytes(), &[2_u8; 16]);
                    let lifetime = Duration::from_millis(5_500);
                    let ticket = LaunchGuardTicket::new_with_deadlines_and_guard(
                        TEST_TICKET.as_bytes().to_vec(),
                        SystemTime::now() + lifetime,
                        MonotonicInstant::now() + lifetime,
                        DeliveryGuard(issue_guard_dropped),
                    )
                    .unwrap();
                    assert!(!format!("{ticket:?}").contains(TEST_TICKET));
                    Ok(ticket)
                }
            }),
        )
        .await
        .expect("broker must not retain an expired recovery ticket")
        .unwrap();
        let elapsed = started.elapsed();
        assert_eq!(
            outcome,
            LaunchGuardBrokerOutcome::Rejected(LaunchGuardIssueFailure::Fatal)
        );
        assert_eq!(issue_calls.load(Ordering::Acquire), 1);
        assert!(guard_dropped.load(Ordering::Acquire));
        assert!(
            elapsed < Duration::from_secs(6),
            "recovery expiry took {elapsed:?}"
        );
        assert!(
            no_ack_child.try_wait().unwrap().is_none(),
            "the broker must expire while its exact Java root remains alive"
        );

        no_ack_child
            .terminate_and_reap(Duration::from_secs(5))
            .unwrap();
        let mut no_ack_stdout = String::new();
        no_ack_pipes
            .stdout
            .read_to_string(&mut no_ack_stdout)
            .unwrap();
        let mut no_ack_stderr = String::new();
        no_ack_pipes
            .stderr
            .read_to_string(&mut no_ack_stderr)
            .unwrap();
        assert!(!no_ack_stdout.contains(TEST_TICKET));
        assert!(!no_ack_stderr.contains(TEST_TICKET));

        // Shutdown always wins the bounded delivery/recovery waits and releases the authority
        // guard even though the Java root is still alive.
        let (pending, bootstrap) = PendingLaunchGuardBroker::prepare().unwrap();
        let environment = bootstrap.environment();
        let mut pending = Some(pending);
        let mut armed = None;
        let (mut shutdown_child, mut shutdown_pipes) = spawn_with_before_resume_identity(
            ProcessSpec {
                executable: &executable,
                arguments: &arguments,
                cwd: &directory.0,
                environment: &environment,
            },
            |binding| {
                armed = Some(
                    pending
                        .take()
                        .expect("the shutdown gate owns one pending broker")
                        .arm(binding)?,
                );
                Ok(())
            },
        )
        .unwrap();
        let armed = armed.expect("the shutdown gate must arm the broker");
        let guard_dropped = Arc::new(AtomicBool::new(false));
        let issue_guard_dropped = Arc::clone(&guard_dropped);
        let issue_calls = Arc::new(AtomicUsize::new(0));
        let issue_calls_for_broker = Arc::clone(&issue_calls);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let broker = tokio::spawn(async move {
            armed
                .serve(shutdown_rx, move |_| {
                    let issue_guard_dropped = Arc::clone(&issue_guard_dropped);
                    let issue_calls = Arc::clone(&issue_calls_for_broker);
                    async move {
                        issue_calls.fetch_add(1, Ordering::AcqRel);
                        let lifetime = Duration::from_secs(30);
                        LaunchGuardTicket::new_with_deadlines_and_guard(
                            TEST_TICKET.as_bytes().to_vec(),
                            SystemTime::now() + lifetime,
                            MonotonicInstant::now() + lifetime,
                            DeliveryGuard(issue_guard_dropped),
                        )
                        .map_err(|_| LaunchGuardIssueFailure::Fatal)
                    }
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while issue_calls.load(Ordering::Acquire) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("shutdown scenario must issue one ticket");
        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown_tx.send(true).unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(2), broker)
            .await
            .expect("shutdown must stop the broker promptly")
            .unwrap()
            .unwrap();
        assert_eq!(outcome, LaunchGuardBrokerOutcome::Cancelled);
        assert_eq!(issue_calls.load(Ordering::Acquire), 1);
        assert!(guard_dropped.load(Ordering::Acquire));
        assert!(shutdown_child.try_wait().unwrap().is_none());

        shutdown_child
            .terminate_and_reap(Duration::from_secs(5))
            .unwrap();
        let mut shutdown_stdout = String::new();
        shutdown_pipes
            .stdout
            .read_to_string(&mut shutdown_stdout)
            .unwrap();
        let mut shutdown_stderr = String::new();
        shutdown_pipes
            .stderr
            .read_to_string(&mut shutdown_stderr)
            .unwrap();
        assert!(!shutdown_stdout.contains(TEST_TICKET));
        assert!(!shutdown_stderr.contains(TEST_TICKET));
    }
}
