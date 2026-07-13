use super::{
    artifact_plan::PlannedGameGenerationBindingV2,
    contracts::{
        domain_digest, GameRuntimeFile, GameRuntimeLock, GameRuntimeSource,
        OfflineProcessorVerification, ProcessorArtifactState, RuntimeLock, VerifiedProcessorStep,
    },
    game_generation::GameGenerationProcessorBuild,
    game_runtime::{
        audit_existing_game_runtime_outputs, run_prepared_java_process, GameRuntimeOutputLease,
        JavaProcessLimits, JavaProcessOutput, ProcessorWorkspaceMonitorLimits, StreamCapture,
    },
    game_runtime_invocation::{prepare_processor_invocations, PreparedProcessorInvocation},
    game_runtime_materializer::ProcessorWorkspace,
    managed_fs::{
        ensure_directory_chain, remove_verified_managed_file, ExclusiveManagedFile, FileDigests,
        GuardedDirectoryChain, ImmutableManagedFile, RelativeManagedPath,
    },
    runtime::{revalidate_runtime_installation_for_root, RuntimeInstallation},
    storage::{is_windows_reparse_point, OwnedCasRoot},
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

const PROCESSOR_STEP_COUNT: usize = 5;
const EXECUTABLE_UPSTREAM_INDICES: [u8; PROCESSOR_STEP_COUNT] = [3, 5, 6, 8, 9];
const MAX_PARTIAL_OUTPUT_ENTRIES: usize = 128;
const PROCESSOR_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const PROCESSOR_MAX_STREAM_BYTES: u64 = 64 * 1024 * 1024;
const PROCESSOR_MAX_DIAGNOSTIC_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct OutputArtifact {
    path: String,
    size: u64,
    sha1: String,
    sha256: String,
}

impl OutputArtifact {
    fn managed_path(&self) -> Result<RelativeManagedPath, String> {
        RelativeManagedPath::new(&self.path)
            .map_err(|error| format!("Processor output path is unsafe: {error}"))
    }

    fn digests(&self) -> FileDigests {
        FileDigests {
            size: self.size,
            sha1: self.sha1.clone(),
            sha256: self.sha256.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct ProcessorStepContract {
    execution_index: u8,
    upstream_index: u8,
    id: String,
    written: Vec<OutputArtifact>,
    removed: Vec<OutputArtifact>,
    after_write: BTreeMap<String, OutputArtifact>,
    after_cleanup: BTreeMap<String, OutputArtifact>,
}

#[derive(Clone, Debug)]
struct ProcessorExecutionContract {
    steps: [ProcessorStepContract; PROCESSOR_STEP_COUNT],
    output_directories: BTreeMap<String, String>,
    final_outputs: BTreeMap<String, OutputArtifact>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProcessorStreamProof {
    pub(super) bytes: u64,
    pub(super) sha256: String,
    pub(super) diagnostic_truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProcessorStepProof {
    pub(super) execution_index: u8,
    pub(super) upstream_index: u8,
    pub(super) id: String,
    pub(super) stdout: ProcessorStreamProof,
    pub(super) stderr: ProcessorStreamProof,
    pub(super) transcript_sha256: String,
    pub(super) written_paths: Vec<String>,
    pub(super) removed_transient_paths: Vec<String>,
    pub(super) cumulative_outputs_sha256: String,
}

/// A path-redacted execution record. It deliberately contains no workspace, Java, cwd or argument
/// paths. The opaque transcript digest remains diagnostic only: fresh workspace roots are random,
/// and the canonical receipt demonstrates that transcripts may legitimately differ between
/// otherwise identical runs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProcessorExecutionProof {
    pub(super) java_runtime_lock_sha256: String,
    pub(super) game_runtime_lock_sha256: String,
    pub(super) generation_binding_sha256: String,
    pub(super) processor_receipt_sha256: String,
    pub(super) input_state_sha256: String,
    pub(super) steps: Vec<ProcessorStepProof>,
    pub(super) output_file_count: usize,
    pub(super) output_total_bytes: u64,
    pub(super) outputs_sha256: String,
}

/// Successful execution owns the sealed workspace and retains the exact-six output lease, so the
/// input/state guards cannot be separated from the proof. Call `revalidate_for_commit`
/// immediately before publishing it.
pub(super) struct ProcessorExecutionResult {
    workspace: ProcessorWorkspace,
    generation_binding: PlannedGameGenerationBindingV2,
    proof: ProcessorExecutionProof,
    outputs: GameRuntimeOutputLease,
}

impl ProcessorExecutionResult {
    pub(super) fn proof(&self) -> &ProcessorExecutionProof {
        &self.proof
    }

    pub(super) fn revalidate_for_commit(&mut self) -> Result<(), String> {
        let inputs = self.workspace.revalidate_inputs()?;
        if inputs.input_state_sha256 != self.proof.input_state_sha256 {
            return Err("Processor input state changed before output commit".into());
        }
        self.workspace.revalidate_execution_scratch()?;
        self.revalidate_output_proof()
    }

    fn revalidate_output_proof(&mut self) -> Result<(), String> {
        self.outputs.revalidate()?;
        if self.outputs.audit().file_count != self.proof.output_file_count
            || self.outputs.audit().total_bytes != self.proof.output_total_bytes
            || self.outputs.audit().outputs_sha256 != self.proof.outputs_sha256
        {
            return Err("Processor final output proof changed before commit".into());
        }
        Ok(())
    }

    fn validate_publish_binding(
        &self,
        build: &GameGenerationProcessorBuild<'_, '_>,
    ) -> Result<(), String> {
        let authority = build.authority();
        authority.validate_binding(&self.generation_binding)?;
        self.workspace.validate_binding_for_build(build)?;
        if self.workspace.generation_binding() != &self.generation_binding
            || self.proof.generation_binding_sha256 != authority.binding_digest()
            || self.proof.game_runtime_lock_sha256 != authority.game_runtime_lock_sha256()
            || self.proof.java_runtime_lock_sha256 != authority.runtime_lock_sha256()
            || self.proof.processor_receipt_sha256
                != verified_receipt_sha256(authority.game_runtime_lock())?
            || self.workspace.game_runtime_lock_sha256() != self.proof.game_runtime_lock_sha256
            || self.workspace.java_runtime_lock_sha256() != self.proof.java_runtime_lock_sha256
            || self.workspace.processor_receipt_sha256() != self.proof.processor_receipt_sha256
        {
            return Err("Processor result belongs to another sealed generation build".into());
        }
        Ok(())
    }

    /// Revalidates the complete processor workspace/result against the exact sealed generation
    /// type-state. This rejects transplanting an otherwise valid exact-six result between roots,
    /// releases, operations, runtime locks or game-runtime locks.
    pub(super) fn validate_for_publish(
        &mut self,
        build: &GameGenerationProcessorBuild<'_, '_>,
    ) -> Result<(), String> {
        self.validate_publish_binding(build)?;
        self.revalidate_for_commit()
    }

    /// Streams one exact signed derived file through its held processor-output handle into a
    /// fresh exclusive generation file. No workspace/output path is disclosed to the publisher,
    /// and no hardlink can cross this boundary.
    pub(super) fn copy_derived_output(
        &mut self,
        build: &GameGenerationProcessorBuild<'_, '_>,
        expected: &GameRuntimeFile,
        destination: &mut ExclusiveManagedFile,
    ) -> Result<FileDigests, String> {
        self.validate_publish_binding(build)?;
        let (path, size, sha1, sha256) =
            signed_derived_identity(build.authority().game_runtime_lock(), expected)?;
        let written = self
            .outputs
            .copy_expected_to(path, size, sha1, sha256, destination)?;
        self.validate_publish_binding(build)?;
        Ok(written)
    }

    /// Consumes the sealed processor result after every derived output has been copied. All input,
    /// output and workspace leases are dropped before the exact operation-bound workspace is
    /// removed by the bounded, handle-audited managed-tree GC.
    pub(super) fn remove_workspace_after_publish(
        mut self,
        build: &GameGenerationProcessorBuild<'_, '_>,
    ) -> Result<ProcessorExecutionProof, String> {
        self.validate_publish_binding(build)?;
        self.revalidate_output_proof()?;
        let proof = self.proof.clone();
        let binding = self.generation_binding.clone();
        let expected_identity = self.workspace.directory_identity();
        // Managed-tree GC must open every source node through delete-capable no-follow handles,
        // so every lease owned by the result has to be released first. Retain the sealed binding
        // and root identity as the cleanup acceptance contract.
        drop(self);
        validate_result_root_after_drop(build, &binding)?;
        build.remove_processor_workspace(&expected_identity)?;
        validate_result_root_after_drop(build, &binding)?;
        Ok(proof)
    }
}

fn validate_result_root_after_drop(
    build: &GameGenerationProcessorBuild<'_, '_>,
    binding: &PlannedGameGenerationBindingV2,
) -> Result<(), String> {
    build.root().revalidate()?;
    build.authority().validate_binding(binding)?;
    let (root_nonce, install_id, _, _) = build.root().binding();
    if root_nonce != binding.root_binding_nonce() || install_id != binding.install_id() {
        return Err("Processor result root changed before workspace cleanup".into());
    }
    Ok(())
}

trait RuntimeRevalidator {
    fn revalidate(
        &mut self,
        installed: &RuntimeInstallation,
    ) -> Result<RuntimeInstallation, String>;
}

trait PreparedProcessSpawner {
    fn spawn(
        &mut self,
        invocation: &PreparedProcessorInvocation,
        monitor_limits: ProcessorWorkspaceMonitorLimits,
        cancelled: Arc<AtomicBool>,
    ) -> Result<JavaProcessOutput, String>;
}

struct NativeProcessorHost<'a> {
    runtime_lock: &'a RuntimeLock,
    runtime: &'a RuntimeInstallation,
    root: &'a OwnedCasRoot,
}

impl RuntimeRevalidator for NativeProcessorHost<'_> {
    fn revalidate(
        &mut self,
        installed: &RuntimeInstallation,
    ) -> Result<RuntimeInstallation, String> {
        revalidate_runtime_installation_for_root(installed, self.runtime_lock, self.root)
    }
}

impl PreparedProcessSpawner for NativeProcessorHost<'_> {
    fn spawn(
        &mut self,
        invocation: &PreparedProcessorInvocation,
        monitor_limits: ProcessorWorkspaceMonitorLimits,
        cancelled: Arc<AtomicBool>,
    ) -> Result<JavaProcessOutput, String> {
        run_prepared_java_process(
            invocation,
            self.runtime_lock,
            self.runtime,
            self.root,
            processor_limits(),
            monitor_limits,
            cancelled,
        )
    }
}

fn processor_limits() -> JavaProcessLimits {
    JavaProcessLimits {
        timeout: PROCESSOR_TIMEOUT,
        max_stream_bytes: PROCESSOR_MAX_STREAM_BYTES,
        max_diagnostic_bytes: PROCESSOR_MAX_DIAGNOSTIC_BYTES,
    }
}

fn workspace_monitor_limits(
    step: &ProcessorStepContract,
) -> Result<ProcessorWorkspaceMonitorLimits, String> {
    let output_max_bytes = step
        .after_write
        .values()
        .try_fold(0_u64, |total, artifact| {
            total
                .checked_add(artifact.size)
                .ok_or_else(|| "Processor live output byte limit overflowed".to_string())
        })?;
    Ok(ProcessorWorkspaceMonitorLimits {
        output_max_entries: MAX_PARTIAL_OUTPUT_ENTRIES,
        output_max_bytes,
    })
}

/// Executes the pinned NeoForge 21.1.235 offline plan in one fresh, materialized workspace.
///
/// An error never publishes, resumes or broadly cleans the workspace. In particular, signed
/// transient sidecars are removed only after the complete post-step inventory has been proven.
pub(super) fn execute_game_runtime_processors(
    mut workspace: ProcessorWorkspace,
    build: &GameGenerationProcessorBuild<'_, '_>,
    runtime: &RuntimeInstallation,
    cancelled: Arc<AtomicBool>,
) -> Result<ProcessorExecutionResult, String> {
    let authority = build.authority();
    workspace.validate_for_build(build)?;
    if runtime.runtime_lock_sha256() != authority.runtime_lock_sha256() {
        return Err("Java runtime belongs to another sealed generation build".into());
    }
    let runtime_lock = authority.runtime_lock();
    let generation_binding = authority.binding();
    let initially_verified_runtime =
        revalidate_runtime_installation_for_root(runtime, runtime_lock, build.root())?;
    if &initially_verified_runtime != runtime {
        return Err("Java runtime root revalidation returned a different capability".into());
    }
    let mut host = NativeProcessorHost {
        runtime_lock,
        runtime,
        root: build.root(),
    };
    let executed = execute_with_host(&mut workspace, build, runtime, cancelled, &mut host)?;
    Ok(ProcessorExecutionResult {
        workspace,
        generation_binding,
        proof: executed.proof,
        outputs: executed.outputs,
    })
}

struct ExecutedProcessorArtifacts {
    proof: ProcessorExecutionProof,
    outputs: GameRuntimeOutputLease,
}

fn execute_with_host<H>(
    workspace: &mut ProcessorWorkspace,
    build: &GameGenerationProcessorBuild<'_, '_>,
    runtime: &RuntimeInstallation,
    cancelled: Arc<AtomicBool>,
    host: &mut H,
) -> Result<ExecutedProcessorArtifacts, String>
where
    H: RuntimeRevalidator + PreparedProcessSpawner,
{
    let authority = build.authority();
    let game_lock = authority.game_runtime_lock();
    let runtime_lock = authority.runtime_lock();
    game_lock.validate()?;
    runtime_lock.validate()?;
    require_not_cancelled(&cancelled)?;
    workspace.validate_for_build(build)?;

    let contract = ProcessorExecutionContract::from_lock(game_lock)?;
    workspace.prepare_execution_scratch()?;
    let initial_inputs = workspace.revalidate_inputs()?;
    let input_state_sha256 = initial_inputs.input_state_sha256;
    workspace.revalidate_execution_scratch()?;

    // Keep the exact signed output parent topology leased for the complete run. The materializer
    // already proved that `outputs` was empty; tools never receive authority to choose parents.
    let _output_directory_guards = prepare_output_topology(workspace, &contract)?;
    let initial_outputs = audit_partial_output_tree(
        workspace.outputs(),
        &contract.output_directories,
        &BTreeMap::new(),
    )?;
    let mut retained_lease = Some(initial_outputs);

    let mut proofs = Vec::with_capacity(PROCESSOR_STEP_COUNT);
    let mut retained = BTreeMap::new();
    for (position, step) in contract.steps.iter().enumerate() {
        require_not_cancelled(&cancelled)?;
        workspace.validate_for_build(build)?;
        if retained != expected_before_step(&contract.steps, position) {
            return Err("Internal processor cumulative output state diverged".into());
        }

        // This lease holds every previous output as an immutable, single-link file across the
        // process. The new signed paths remain writable, while rewrite/delete of an earlier result
        // is denied on Windows and detected on every supported platform.
        let mut prior_lease = retained_lease
            .take()
            .ok_or_else(|| "Processor output lease continuity was lost".to_string())?;
        prior_lease.revalidate()?;
        let input_before = workspace.revalidate_inputs()?;
        if input_before.input_state_sha256 != input_state_sha256 {
            return Err("Processor input state changed before a step".into());
        }
        workspace.revalidate_execution_scratch()?;

        // Runtime revalidation intentionally happens on every iteration. The invocation plan is
        // then rebuilt from the sealed workspace and the freshly revalidated runtime, lives only
        // through this one spawn, and is dropped before mutable workspace validation resumes.
        let verified_runtime = host.revalidate(runtime)?;
        if &verified_runtime != runtime {
            return Err("Java runtime revalidation returned a different capability".into());
        }
        let process = {
            let plan = prepare_processor_invocations(
                game_lock,
                runtime_lock,
                &verified_runtime,
                workspace,
            )?;
            let invocation = plan
                .invocations()
                .get(position)
                .ok_or_else(|| "Prepared processor invocation is missing".to_string())?;
            validate_prepared_invocation(invocation, step, workspace.outputs())?;
            require_not_cancelled(&cancelled)?;
            let output = host.spawn(
                invocation,
                workspace_monitor_limits(step)?,
                Arc::clone(&cancelled),
            )?;
            require_successful_exit(&step.id, step.upstream_index, &output)?;
            output
        };

        require_not_cancelled(&cancelled)?;
        // New signed paths are expected now. Prove only that every previously retained file kept
        // its exact identity; the raw after-write audit below proves the complete new namespace.
        prior_lease.revalidate_held_files()?;
        let input_after = workspace.revalidate_inputs()?;
        if input_after.input_state_sha256 != input_state_sha256 {
            return Err("Processor input state changed after a step".into());
        }
        workspace.revalidate_execution_scratch()?;

        // First prove the raw signed write-set, including both .jar.cache sidecars for step 6.
        let raw_lease = audit_partial_output_tree(
            workspace.outputs(),
            &contract.output_directories,
            &step.after_write,
        )?;
        require_not_cancelled(&cancelled)?;
        let mut cleaned_lease = if step.removed.is_empty() {
            // The raw exact inventory is already the cleaned inventory. Keeping this lease avoids
            // an unnecessary namespace window between adjacent processor steps.
            drop(prior_lease);
            raw_lease
        } else {
            // There is no wildcard cleanup. Each sidecar is opened without following links,
            // hashed through the deletion handle, checked as regular/single-link, then deleted by
            // that handle. Convert the raw lease into a persistent-output lease first: this drops
            // only the transient handles required for deletion while every retained output stays
            // immutable across the cleanup window.
            let mut persistent_lease = raw_lease.retain_expected_files(&step.after_cleanup)?;
            persistent_lease.revalidate()?;
            // The persistent subset includes every prior file, so directory snapshot handles from
            // the old lease can now be released before the deletion durability flush.
            drop(prior_lease);
            for transient in &step.removed {
                require_not_cancelled(&cancelled)?;
                remove_verified_managed_file(
                    workspace.outputs(),
                    &transient.managed_path()?,
                    &transient.digests(),
                )
                .map_err(|error| {
                    format!(
                        "Cannot remove verified processor transient {}: {error}",
                        transient.path
                    )
                })?;
            }
            let mut cleaned = audit_partial_output_tree(
                workspace.outputs(),
                &contract.output_directories,
                &step.after_cleanup,
            )?;
            cleaned.revalidate()?;
            persistent_lease.revalidate()?;
            drop(persistent_lease);
            cleaned
        };
        cleaned_lease.revalidate()?;
        workspace.revalidate_execution_scratch()?;
        let input_cleaned = workspace.revalidate_inputs()?;
        if input_cleaned.input_state_sha256 != input_state_sha256 {
            return Err("Processor input state changed during transient cleanup".into());
        }
        require_not_cancelled(&cancelled)?;

        proofs.push(step_proof(step, process, &cleaned_lease.audit)?);
        retained = step.after_cleanup.clone();
        retained_lease = Some(cleaned_lease);
    }

    if retained != contract.final_outputs {
        return Err("NeoForge processor run did not retain exactly six derived outputs".into());
    }
    require_not_cancelled(&cancelled)?;
    workspace.validate_for_build(build)?;
    let final_inputs = workspace.revalidate_inputs()?;
    if final_inputs.input_state_sha256 != input_state_sha256 {
        return Err("Processor input state changed before final audit".into());
    }
    workspace.revalidate_execution_scratch()?;

    // Use the independent full-runtime auditor for the publication lease, not merely the partial
    // per-step model used above. It requires the exact six signed files and exact directory tree.
    let mut retained_lease = retained_lease
        .take()
        .ok_or_else(|| "Final processor output lease is missing".to_string())?;
    retained_lease.revalidate()?;
    let mut outputs = audit_existing_game_runtime_outputs(game_lock, workspace.outputs())?;
    outputs.revalidate()?;
    drop(retained_lease);
    workspace.revalidate_execution_scratch()?;
    let final_inputs = workspace.revalidate_inputs()?;
    if final_inputs.input_state_sha256 != input_state_sha256 {
        return Err("Processor input state changed while final outputs were leased".into());
    }
    require_not_cancelled(&cancelled)?;
    workspace.validate_for_build(build)?;

    let proof = ProcessorExecutionProof {
        java_runtime_lock_sha256: runtime.runtime_lock_sha256().to_owned(),
        game_runtime_lock_sha256: authority.game_runtime_lock_sha256().to_owned(),
        generation_binding_sha256: authority.binding_digest().to_owned(),
        processor_receipt_sha256: verified_receipt_sha256(game_lock)?.to_owned(),
        input_state_sha256,
        steps: proofs,
        output_file_count: outputs.audit().file_count,
        output_total_bytes: outputs.audit().total_bytes,
        outputs_sha256: outputs.audit().outputs_sha256.clone(),
    };
    Ok(ExecutedProcessorArtifacts { proof, outputs })
}

fn verified_receipt_sha256(lock: &GameRuntimeLock) -> Result<&str, String> {
    match &lock.verification.offline_processors {
        OfflineProcessorVerification::Verified { receipt_sha256, .. } => Ok(receipt_sha256),
        OfflineProcessorVerification::Pending { .. } => {
            Err("Pending processor verification has no signed receipt".into())
        }
    }
}

fn signed_derived_identity<'lock>(
    lock: &'lock GameRuntimeLock,
    expected: &GameRuntimeFile,
) -> Result<(&'lock str, u64, &'lock str, &'lock str), String> {
    let signed = lock
        .files
        .iter()
        .find(|candidate| std::ptr::eq(*candidate, expected))
        .ok_or_else(|| {
            "Derived output reference does not belong to the sealed game runtime lock".to_string()
        })?;
    match &signed.source {
        GameRuntimeSource::Derived {
            size, sha1, sha256, ..
        } => Ok((&signed.path, *size, sha1, sha256)),
        GameRuntimeSource::Official { .. } => {
            Err("Processor result cannot publish an official game runtime file".into())
        }
    }
}

fn require_not_cancelled(cancelled: &AtomicBool) -> Result<(), String> {
    if cancelled.load(Ordering::Acquire) {
        Err("NeoForge processor execution was cancelled".into())
    } else {
        Ok(())
    }
}

fn require_successful_exit(
    processor_id: &str,
    upstream_index: u8,
    output: &JavaProcessOutput,
) -> Result<(), String> {
    if output.exit_code == 0 {
        Ok(())
    } else {
        Err(format!(
            "NeoForge processor {processor_id} (step {upstream_index}) exited with code {}",
            output.exit_code
        ))
    }
}

fn validate_prepared_invocation(
    invocation: &PreparedProcessorInvocation,
    step: &ProcessorStepContract,
    outputs_root: &Path,
) -> Result<(), String> {
    if invocation.execution_index() != step.execution_index
        || invocation.upstream_index() != step.upstream_index
        || invocation.id() != step.id
        || invocation.upstream_index() == 4
    {
        return Err("Prepared processor invocation disagrees with its signed step".into());
    }
    let expected = step
        .written
        .iter()
        .map(|artifact| {
            artifact
                .managed_path()
                .map(|path| path.join_to(outputs_root))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if invocation.expected_written_paths() != expected {
        return Err("Prepared processor invocation write-set is not the signed exact order".into());
    }
    Ok(())
}

fn step_proof(
    step: &ProcessorStepContract,
    process: JavaProcessOutput,
    audit: &PartialOutputAudit,
) -> Result<ProcessorStepProof, String> {
    Ok(ProcessorStepProof {
        execution_index: step.execution_index,
        upstream_index: step.upstream_index,
        id: step.id.clone(),
        stdout: stream_proof(process.stdout),
        stderr: stream_proof(process.stderr),
        transcript_sha256: process.transcript_sha256,
        written_paths: step
            .written
            .iter()
            .map(|artifact| artifact.path.clone())
            .collect(),
        removed_transient_paths: step
            .removed
            .iter()
            .map(|artifact| artifact.path.clone())
            .collect(),
        cumulative_outputs_sha256: audit.outputs_sha256.clone(),
    })
}

fn stream_proof(stream: StreamCapture) -> ProcessorStreamProof {
    ProcessorStreamProof {
        bytes: stream.bytes,
        sha256: stream.sha256,
        diagnostic_truncated: stream.truncated,
    }
}

impl ProcessorExecutionContract {
    fn from_lock(lock: &GameRuntimeLock) -> Result<Self, String> {
        lock.validate()?;
        let mut final_outputs = BTreeMap::new();
        for file in &lock.files {
            let GameRuntimeSource::Derived {
                size, sha1, sha256, ..
            } = &file.source
            else {
                continue;
            };
            insert_artifact(
                &mut final_outputs,
                OutputArtifact {
                    path: file.path.clone(),
                    size: *size,
                    sha1: sha1.clone(),
                    sha256: sha256.clone(),
                },
                "derived output",
            )?;
        }
        if final_outputs.len() != 6 {
            return Err("Processor execution contract requires exactly six derived outputs".into());
        }

        let receipt_steps = match &lock.verification.offline_processors {
            OfflineProcessorVerification::Verified { runs, .. } => &runs[0].steps,
            OfflineProcessorVerification::Pending { .. } => {
                return Err("Pending processor verification cannot be executed".into());
            }
        };
        if receipt_steps.len() != PROCESSOR_STEP_COUNT {
            return Err("Verified processor receipt must contain exactly five steps".into());
        }

        let mut transient_artifacts = BTreeMap::new();
        for step in receipt_steps {
            for artifact in &step.removed_transient_artifacts {
                insert_artifact(
                    &mut transient_artifacts,
                    artifact_from_state(artifact),
                    "processor transient",
                )?;
            }
        }
        if transient_artifacts.len() != 2 {
            return Err(
                "Processor execution contract requires exactly two transient sidecars".into(),
            );
        }
        if transient_artifacts
            .keys()
            .any(|key| final_outputs.contains_key(key))
        {
            return Err("Processor transient collides with a derived output".into());
        }

        let output_directories = expected_output_directories(final_outputs.values())?;
        for transient in transient_artifacts.values() {
            for directory in artifact_parent_directories(transient)? {
                let key = directory.collision_key().to_owned();
                if output_directories.get(&key) != Some(&directory.as_str().to_owned()) {
                    return Err("Processor transient escapes the fixed output topology".into());
                }
            }
        }

        let mut retained = BTreeMap::new();
        let mut steps = Vec::with_capacity(PROCESSOR_STEP_COUNT);
        for (position, receipt) in receipt_steps.iter().enumerate() {
            if receipt.execution_index as usize != position
                || receipt.upstream_index != EXECUTABLE_UPSTREAM_INDICES[position]
            {
                return Err("Processor receipt order is not exactly 3,5,6,8,9".into());
            }
            let written = receipt
                .written_paths
                .iter()
                .map(|path| {
                    let managed = RelativeManagedPath::new(path)
                        .map_err(|error| format!("Processor written path is unsafe: {error}"))?;
                    final_outputs
                        .get(managed.collision_key())
                        .or_else(|| transient_artifacts.get(managed.collision_key()))
                        .filter(|artifact| artifact.path == *path)
                        .cloned()
                        .ok_or_else(|| {
                            format!("Processor written path has no signed identity: {path}")
                        })
                })
                .collect::<Result<Vec<_>, String>>()?;

            let mut after_write = retained.clone();
            let mut written_keys = HashSet::new();
            for artifact in &written {
                let key = artifact.managed_path()?.collision_key().to_owned();
                if !written_keys.insert(key.clone())
                    || after_write.insert(key, artifact.clone()).is_some()
                {
                    return Err("Processor step attempts to rewrite or duplicate an output".into());
                }
            }
            let removed = receipt
                .removed_transient_artifacts
                .iter()
                .map(artifact_from_state)
                .collect::<Vec<_>>();
            let mut after_cleanup = after_write.clone();
            for artifact in &removed {
                let key = artifact.managed_path()?.collision_key().to_owned();
                if !written_keys.contains(&key)
                    || after_cleanup.remove(&key).as_ref() != Some(artifact)
                {
                    return Err(
                        "Processor transient cleanup is not part of this step write-set".into(),
                    );
                }
            }
            let id = signed_step_id(lock, receipt)?;
            steps.push(ProcessorStepContract {
                execution_index: receipt.execution_index,
                upstream_index: receipt.upstream_index,
                id,
                written,
                removed,
                after_write,
                after_cleanup: after_cleanup.clone(),
            });
            retained = after_cleanup;
        }
        if retained != final_outputs {
            return Err("Processor signed write-set does not converge to exact six outputs".into());
        }
        let steps: [ProcessorStepContract; PROCESSOR_STEP_COUNT] = steps
            .try_into()
            .map_err(|_| "Processor step count changed during contract construction".to_string())?;
        Ok(Self {
            steps,
            output_directories,
            final_outputs,
        })
    }
}

fn signed_step_id(
    lock: &GameRuntimeLock,
    receipt: &VerifiedProcessorStep,
) -> Result<String, String> {
    lock.provenance
        .processor_plans
        .upstream
        .steps
        .iter()
        .find(|step| step.upstream_index == receipt.upstream_index)
        .map(|step| step.id.clone())
        .ok_or_else(|| "Receipt step is absent from the signed upstream plan".to_string())
}

fn artifact_from_state(state: &ProcessorArtifactState) -> OutputArtifact {
    OutputArtifact {
        path: state.path.clone(),
        size: state.size,
        sha1: state.sha1.clone(),
        sha256: state.sha256.clone(),
    }
}

fn insert_artifact(
    artifacts: &mut BTreeMap<String, OutputArtifact>,
    artifact: OutputArtifact,
    label: &str,
) -> Result<(), String> {
    let path = artifact.managed_path()?;
    if artifacts
        .insert(path.collision_key().to_owned(), artifact)
        .is_some()
    {
        return Err(format!("{label} paths collide on Windows"));
    }
    Ok(())
}

fn expected_before_step(
    steps: &[ProcessorStepContract; PROCESSOR_STEP_COUNT],
    position: usize,
) -> BTreeMap<String, OutputArtifact> {
    position
        .checked_sub(1)
        .map_or_else(BTreeMap::new, |previous| {
            steps[previous].after_cleanup.clone()
        })
}

fn expected_output_directories<'a>(
    outputs: impl IntoIterator<Item = &'a OutputArtifact>,
) -> Result<BTreeMap<String, String>, String> {
    let mut directories = BTreeMap::new();
    for output in outputs {
        for parent in artifact_parent_directories(output)? {
            let key = parent.collision_key().to_owned();
            let canonical = parent.as_str().to_owned();
            if let Some(previous) = directories.insert(key, canonical.clone()) {
                if previous != canonical {
                    return Err("Processor output directories collide on Windows".into());
                }
            }
        }
    }
    Ok(directories)
}

fn artifact_parent_directories(
    artifact: &OutputArtifact,
) -> Result<Vec<RelativeManagedPath>, String> {
    let mut result = Vec::new();
    let mut parent = artifact.managed_path()?.parent();
    while let Some(directory) = parent {
        parent = directory.parent();
        result.push(directory);
    }
    Ok(result)
}

fn prepare_output_topology(
    workspace: &ProcessorWorkspace,
    contract: &ProcessorExecutionContract,
) -> Result<Vec<GuardedDirectoryChain>, String> {
    let mut directories = contract
        .output_directories
        .values()
        .map(|path| {
            RelativeManagedPath::new(path)
                .map_err(|error| format!("Processor output directory is unsafe: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    directories.sort_by(|left, right| {
        left.as_str()
            .split('/')
            .count()
            .cmp(&right.as_str().split('/').count())
            .then_with(|| left.as_str().cmp(right.as_str()))
    });
    directories
        .iter()
        .map(|relative| {
            ensure_directory_chain(workspace.outputs(), relative).map_err(|error| {
                format!(
                    "Cannot create controlled processor output directory {}: {error}",
                    relative.as_str()
                )
            })
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PartialOutputAudit {
    file_count: usize,
    total_bytes: u64,
    outputs_sha256: String,
}

struct HeldPartialOutput {
    key: String,
    expected: OutputArtifact,
    file: ImmutableManagedFile,
}

struct PartialFileLease {
    expected_files: BTreeMap<String, OutputArtifact>,
    held_files: Vec<HeldPartialOutput>,
}

impl PartialFileLease {
    fn revalidate(&mut self) -> Result<(), String> {
        revalidate_held_partial_files(&mut self.held_files, &self.expected_files)
    }
}

struct PartialOutputLease {
    root: PathBuf,
    expected_files: BTreeMap<String, OutputArtifact>,
    expected_directories: BTreeMap<String, String>,
    held_files: Vec<HeldPartialOutput>,
    audit: PartialOutputAudit,
    _root_guard: GuardedDirectoryChain,
    _directory_guards: Vec<GuardedDirectoryChain>,
}

impl PartialOutputLease {
    fn revalidate_held_files(&mut self) -> Result<(), String> {
        revalidate_held_partial_files(&mut self.held_files, &self.expected_files)
    }

    fn revalidate(&mut self) -> Result<(), String> {
        self.revalidate_held_files()?;
        validate_partial_inventory(&self.root, &self.expected_files, &self.expected_directories)
    }

    /// Consumes a proven larger inventory while retaining immutable handles for an exact subset.
    /// This is used only after the raw step-6 inventory (including both signed sidecars) passed;
    /// dropping the two transient handles enables handle-based deletion without releasing any
    /// persistent output lease.
    fn retain_expected_files(
        self,
        expected_files: &BTreeMap<String, OutputArtifact>,
    ) -> Result<PartialFileLease, String> {
        if expected_files
            .iter()
            .any(|(key, artifact)| self.expected_files.get(key) != Some(artifact))
        {
            return Err(
                "Retained processor outputs are not a subset of the proven inventory".into(),
            );
        }
        let PartialOutputLease {
            root: _,
            expected_files: _,
            expected_directories: _,
            mut held_files,
            audit: _,
            _root_guard: _,
            _directory_guards: _,
        } = self;
        held_files.retain(|held| expected_files.contains_key(&held.key));
        if held_files.len() != expected_files.len()
            || held_files
                .iter()
                .any(|held| expected_files.get(&held.key) != Some(&held.expected))
        {
            return Err("Persistent processor output lease subset is incomplete".into());
        }
        let mut retained = PartialFileLease {
            expected_files: expected_files.clone(),
            held_files,
        };
        // The namespace still contains the signed transients, so only retained file identities
        // may be checked until deletion completes and the exact cleaned audit is acquired.
        retained.revalidate()?;
        Ok(retained)
    }
}

fn revalidate_held_partial_files(
    held_files: &mut [HeldPartialOutput],
    expected_files: &BTreeMap<String, OutputArtifact>,
) -> Result<(), String> {
    let mut observed = BTreeMap::new();
    for held in held_files {
        let actual = hash_held_partial_output(&mut held.file, &held.expected)?;
        if observed.insert(held.key.clone(), actual).is_some() {
            return Err("Processor output lease contains a duplicate file".into());
        }
    }
    validate_exact_files(expected_files, &observed)
}

fn audit_partial_output_tree(
    root: &Path,
    expected_directories: &BTreeMap<String, String>,
    expected_files: &BTreeMap<String, OutputArtifact>,
) -> Result<PartialOutputLease, String> {
    let root_guard = GuardedDirectoryChain::root_snapshot(root)
        .map_err(|error| format!("Processor output root is unsafe: {error}"))?;
    let mut observed_files = BTreeMap::new();
    let mut seen_directories = BTreeSet::new();
    let mut held_files = Vec::with_capacity(expected_files.len());
    let mut directory_guards = Vec::with_capacity(expected_directories.len());
    let mut entry_count = 0_usize;
    scan_partial_output_tree(
        root_guard.root_path(),
        root_guard.root_path(),
        expected_files,
        expected_directories,
        &mut observed_files,
        &mut seen_directories,
        &mut held_files,
        &mut directory_guards,
        &mut entry_count,
    )?;
    validate_exact_files(expected_files, &observed_files)?;
    if seen_directories != expected_directories.keys().cloned().collect() {
        return Err("Processor output directory inventory is not exact".into());
    }
    let total_bytes = observed_files.values().try_fold(0_u64, |sum, output| {
        sum.checked_add(output.size)
            .ok_or_else(|| "Processor output byte count overflowed".to_string())
    })?;
    let audit = PartialOutputAudit {
        file_count: observed_files.len(),
        total_bytes,
        outputs_sha256: partial_outputs_digest(observed_files.values())?,
    };
    let mut lease = PartialOutputLease {
        root: root_guard.root_path().to_path_buf(),
        expected_files: expected_files.clone(),
        expected_directories: expected_directories.clone(),
        held_files,
        audit,
        _root_guard: root_guard,
        _directory_guards: directory_guards,
    };
    lease.revalidate()?;
    Ok(lease)
}

#[allow(clippy::too_many_arguments)]
fn scan_partial_output_tree(
    root: &Path,
    directory: &Path,
    expected_files: &BTreeMap<String, OutputArtifact>,
    expected_directories: &BTreeMap<String, String>,
    observed_files: &mut BTreeMap<String, OutputArtifact>,
    seen_directories: &mut BTreeSet<String>,
    held_files: &mut Vec<HeldPartialOutput>,
    directory_guards: &mut Vec<GuardedDirectoryChain>,
    entry_count: &mut usize,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("Cannot enumerate processor outputs: {error}"))?
    {
        *entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| "Processor output entry count overflowed".to_string())?;
        if *entry_count > MAX_PARTIAL_OUTPUT_ENTRIES {
            return Err("Processor output tree exceeds the entry limit".into());
        }
        let entry = entry.map_err(|error| format!("Cannot inspect processor output: {error}"))?;
        let absolute = entry.path();
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("Cannot inspect processor output metadata: {error}"))?;
        if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
            return Err("Link/reparse point is forbidden in processor outputs".into());
        }
        if metadata.is_file() && metadata.permissions().readonly() {
            return Err("Read-only file is forbidden in processor outputs".into());
        }
        let relative = relative_managed_path(root, &absolute)?;
        let key = relative.collision_key().to_owned();
        if metadata.is_dir() {
            let canonical = expected_directories.get(&key).ok_or_else(|| {
                format!(
                    "Unexpected processor output directory: {}",
                    relative.as_str()
                )
            })?;
            if relative.as_str() != canonical || !seen_directories.insert(key) {
                return Err("Processor output directory casing/collision mismatch".into());
            }
            let guard = GuardedDirectoryChain::open_snapshot(root, &relative)
                .map_err(|error| format!("Processor output directory is unsafe: {error}"))?;
            let stable_directory = guard.leaf().path().to_path_buf();
            directory_guards.push(guard);
            scan_partial_output_tree(
                root,
                &stable_directory,
                expected_files,
                expected_directories,
                observed_files,
                seen_directories,
                held_files,
                directory_guards,
                entry_count,
            )?;
        } else if metadata.is_file() {
            let expected = expected_files.get(&key).ok_or_else(|| {
                format!("Unexpected processor output file: {}", relative.as_str())
            })?;
            if relative.as_str() != expected.path {
                return Err("Processor output file casing differs from the signed path".into());
            }
            let mut file = ImmutableManagedFile::open(root, &relative)
                .map_err(|error| format!("Processor output file is unsafe: {error}"))?;
            let actual = hash_held_partial_output(&mut file, expected)?;
            if observed_files.insert(key.clone(), actual).is_some() {
                return Err("Processor output path was observed more than once".into());
            }
            held_files.push(HeldPartialOutput {
                key,
                expected: expected.clone(),
                file,
            });
        } else {
            return Err("Special file is forbidden in processor outputs".into());
        }
    }
    Ok(())
}

fn validate_partial_inventory(
    root: &Path,
    expected_files: &BTreeMap<String, OutputArtifact>,
    expected_directories: &BTreeMap<String, String>,
) -> Result<(), String> {
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut entries = 0_usize;
    scan_partial_inventory_only(
        root,
        root,
        expected_files,
        expected_directories,
        &mut files,
        &mut directories,
        &mut entries,
    )?;
    if files != expected_files.keys().cloned().collect()
        || directories != expected_directories.keys().cloned().collect()
    {
        return Err("Processor output namespace changed while leased".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn scan_partial_inventory_only(
    root: &Path,
    directory: &Path,
    expected_files: &BTreeMap<String, OutputArtifact>,
    expected_directories: &BTreeMap<String, String>,
    files: &mut BTreeSet<String>,
    directories: &mut BTreeSet<String>,
    entries: &mut usize,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("Cannot re-enumerate processor outputs: {error}"))?
    {
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| "Processor output entry count overflowed".to_string())?;
        if *entries > MAX_PARTIAL_OUTPUT_ENTRIES {
            return Err("Processor output tree exceeds the entry limit".into());
        }
        let entry = entry.map_err(|error| format!("Cannot inspect processor output: {error}"))?;
        let absolute = entry.path();
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("Cannot inspect processor output metadata: {error}"))?;
        if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
            return Err("Link/reparse point is forbidden in processor outputs".into());
        }
        if metadata.is_file() && metadata.permissions().readonly() {
            return Err("Read-only file is forbidden in processor outputs".into());
        }
        let relative = relative_managed_path(root, &absolute)?;
        let key = relative.collision_key().to_owned();
        if metadata.is_dir() {
            if expected_directories.get(&key).map(String::as_str) != Some(relative.as_str())
                || !directories.insert(key)
            {
                return Err("Processor output directory inventory changed".into());
            }
            scan_partial_inventory_only(
                root,
                &absolute,
                expected_files,
                expected_directories,
                files,
                directories,
                entries,
            )?;
        } else if metadata.is_file() {
            if expected_files.get(&key).map(|value| value.path.as_str()) != Some(relative.as_str())
                || !files.insert(key)
            {
                return Err("Processor output file inventory changed".into());
            }
        } else {
            return Err("Special file is forbidden in processor outputs".into());
        }
    }
    Ok(())
}

fn hash_held_partial_output(
    file: &mut ImmutableManagedFile,
    expected: &OutputArtifact,
) -> Result<OutputArtifact, String> {
    let digest = file
        .sha1_sha256(expected.size)
        .map_err(|error| format!("Cannot hash processor output {}: {error}", expected.path))?;
    let actual = OutputArtifact {
        path: expected.path.clone(),
        size: digest.size,
        sha1: digest.sha1,
        sha256: digest.sha256,
    };
    if &actual != expected {
        return Err(format!(
            "Processor output identity differs from the signed value: {}",
            expected.path
        ));
    }
    Ok(actual)
}

fn validate_exact_files(
    expected: &BTreeMap<String, OutputArtifact>,
    observed: &BTreeMap<String, OutputArtifact>,
) -> Result<(), String> {
    if expected != observed {
        return Err("Processor cumulative output file inventory is not exact".into());
    }
    Ok(())
}

fn partial_outputs_digest<'a>(
    outputs: impl IntoIterator<Item = &'a OutputArtifact>,
) -> Result<String, String> {
    domain_digest(
        "ru.fragmc.launcher.neoforge.partial-outputs.v1",
        &outputs.into_iter().collect::<Vec<_>>(),
    )
}

fn relative_managed_path(root: &Path, absolute: &Path) -> Result<RelativeManagedPath, String> {
    let serialized = absolute
        .strip_prefix(root)
        .map_err(|_| "Processor output escaped its controlled root".to_string())?
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .ok_or_else(|| "Processor output path is not Unicode".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?
        .join("/");
    RelativeManagedPath::new(&serialized)
        .map_err(|error| format!("Processor output path is unsafe: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        sync::Mutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn fixture_lock() -> GameRuntimeLock {
        GameRuntimeLock::parse_and_validate(include_bytes!(
            "../../tests/fixtures/game-runtime-lock-v2-release-canonical-verified.json"
        ))
        .expect("canonical game runtime lock must validate")
    }

    fn artifact(path: &str, bytes: &[u8]) -> OutputArtifact {
        let mut sha1 = Sha1::new();
        sha1.update(bytes);
        let mut sha256 = Sha256::new();
        sha256.update(bytes);
        OutputArtifact {
            path: path.to_owned(),
            size: bytes.len() as u64,
            sha1: format!("{:x}", sha1.finalize()),
            sha256: format!("{:x}", sha256.finalize()),
        }
    }

    fn test_root(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::current_dir()
            .unwrap()
            .join("target")
            .join(format!(
                "processor-executor-{label}-{}-{nonce}",
                std::process::id()
            ))
    }

    fn prepare_small_tree(
        label: &str,
        outputs: &[OutputArtifact],
    ) -> (
        PathBuf,
        BTreeMap<String, String>,
        BTreeMap<String, OutputArtifact>,
    ) {
        let root = test_root(label);
        fs::create_dir_all(&root).unwrap();
        let expected = outputs
            .iter()
            .cloned()
            .map(|output| {
                let key = output.managed_path().unwrap().collision_key().to_owned();
                (key, output)
            })
            .collect::<BTreeMap<_, _>>();
        let directories = expected_output_directories(expected.values()).unwrap();
        let mut ordered = directories.values().cloned().collect::<Vec<_>>();
        ordered.sort_by_key(|path| path.split('/').count());
        for directory in ordered {
            ensure_directory_chain(&root, &RelativeManagedPath::new(&directory).unwrap()).unwrap();
        }
        for output in outputs {
            fs::write(
                output.managed_path().unwrap().join_to(&root),
                match output.path.as_str() {
                    "a/one.bin" => b"one".as_slice(),
                    "a/b/two.bin" => b"two".as_slice(),
                    _ => panic!("unexpected test artifact"),
                },
            )
            .unwrap();
        }
        (root, directories, expected)
    }

    #[test]
    fn canonical_model_is_exact_five_steps_two_transients_and_six_final_outputs() {
        let contract = ProcessorExecutionContract::from_lock(&fixture_lock()).unwrap();
        assert_eq!(contract.steps.len(), 5);
        assert_eq!(
            contract
                .steps
                .iter()
                .map(|step| step.upstream_index)
                .collect::<Vec<_>>(),
            [3, 5, 6, 8, 9]
        );
        assert_eq!(contract.steps[0].after_cleanup.len(), 1);
        assert_eq!(contract.steps[1].after_cleanup.len(), 2);
        assert_eq!(contract.steps[2].after_write.len(), 6);
        assert_eq!(contract.steps[2].removed.len(), 2);
        assert!(contract.steps[2]
            .removed
            .iter()
            .all(|artifact| artifact.path.ends_with(".jar.cache")));
        assert_eq!(contract.steps[2].after_cleanup.len(), 4);
        assert_eq!(contract.steps[3].after_cleanup.len(), 5);
        assert_eq!(contract.steps[4].after_cleanup.len(), 6);
        assert_eq!(contract.steps[4].after_cleanup, contract.final_outputs);
    }

    #[test]
    fn publisher_accepts_only_a_derived_reference_from_the_exact_signed_lock() {
        let lock = fixture_lock();
        let derived = lock
            .files
            .iter()
            .find(|file| matches!(&file.source, GameRuntimeSource::Derived { .. }))
            .unwrap();
        let identity = signed_derived_identity(&lock, derived).unwrap();
        assert_eq!(identity.0, derived.path);

        let detached_clone = derived.clone();
        assert!(signed_derived_identity(&lock, &detached_clone)
            .unwrap_err()
            .contains("does not belong"));
        let official = lock
            .files
            .iter()
            .find(|file| matches!(&file.source, GameRuntimeSource::Official { .. }))
            .unwrap();
        assert!(signed_derived_identity(&lock, official)
            .unwrap_err()
            .contains("cannot publish an official"));
    }

    #[test]
    fn exact_inventory_rejects_missing_extra_and_wrong_identity() {
        let one = artifact("a/one.bin", b"one");
        let two = artifact("a/b/two.bin", b"two");
        let mut expected = BTreeMap::new();
        insert_artifact(&mut expected, one.clone(), "test").unwrap();
        insert_artifact(&mut expected, two.clone(), "test").unwrap();
        assert!(validate_exact_files(&expected, &expected).is_ok());

        let mut missing = expected.clone();
        missing.remove(one.managed_path().unwrap().collision_key());
        assert!(validate_exact_files(&expected, &missing).is_err());

        let mut extra = expected.clone();
        insert_artifact(&mut extra, artifact("a/three.bin", b"three"), "test").unwrap();
        assert!(validate_exact_files(&expected, &extra).is_err());

        let mut corrupt = expected.clone();
        let key = two.managed_path().unwrap().collision_key().to_owned();
        corrupt.get_mut(&key).unwrap().sha256 = "0".repeat(64);
        assert!(validate_exact_files(&expected, &corrupt).is_err());
    }

    #[test]
    fn partial_filesystem_lease_detects_addition_and_corruption() {
        let one = artifact("a/one.bin", b"one");
        let two = artifact("a/b/two.bin", b"two");
        let (root, directories, expected) =
            prepare_small_tree("lease-faults", &[one.clone(), two.clone()]);
        let mut lease = audit_partial_output_tree(&root, &directories, &expected).unwrap();
        assert_eq!(lease.audit.file_count, 2);

        let addition = root.join("a/extra.bin");
        match fs::write(&addition, b"extra") {
            Ok(()) => assert!(lease.revalidate().is_err()),
            Err(_) => lease.revalidate().unwrap(),
        }
        drop(lease);
        let _ = fs::remove_file(addition);

        let mut lease = audit_partial_output_tree(&root, &directories, &expected).unwrap();
        let target = one.managed_path().unwrap().join_to(&root);
        match fs::write(&target, b"bad") {
            Ok(()) => assert!(lease.revalidate().is_err()),
            Err(_) => lease.revalidate().unwrap(),
        }
        drop(lease);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn prior_file_lease_allows_new_signed_output_before_exact_raw_audit() {
        let one = artifact("a/one.bin", b"one");
        let two = artifact("a/b/two.bin", b"two");
        let root = test_root("prior-vs-raw");
        fs::create_dir_all(&root).unwrap();
        let all = [one.clone(), two.clone()];
        let directories = expected_output_directories(all.iter()).unwrap();
        let mut ordered = directories.values().cloned().collect::<Vec<_>>();
        ordered.sort_by_key(|path| path.split('/').count());
        for directory in ordered {
            ensure_directory_chain(&root, &RelativeManagedPath::new(&directory).unwrap()).unwrap();
        }

        fs::write(one.managed_path().unwrap().join_to(&root), b"one").unwrap();
        let mut before = BTreeMap::new();
        insert_artifact(&mut before, one, "test").unwrap();
        let mut prior = audit_partial_output_tree(&root, &directories, &before).unwrap();

        fs::write(two.managed_path().unwrap().join_to(&root), b"two").unwrap();
        assert!(prior.revalidate_held_files().is_ok());
        assert!(prior.revalidate().is_err());

        let mut after = before;
        insert_artifact(&mut after, two, "test").unwrap();
        let mut raw = audit_partial_output_tree(&root, &directories, &after).unwrap();
        raw.revalidate().unwrap();
        drop(raw);
        drop(prior);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn transient_cleanup_keeps_persistent_subset_leased_until_cleaned_audit() {
        let persistent = artifact("a/one.bin", b"one");
        let transient = artifact("a/b/two.bin", b"two");
        let (root, directories, raw_expected) =
            prepare_small_tree("transient-subset", &[persistent.clone(), transient.clone()]);
        let raw = audit_partial_output_tree(&root, &directories, &raw_expected).unwrap();
        let mut cleaned_expected = BTreeMap::new();
        insert_artifact(&mut cleaned_expected, persistent, "test").unwrap();
        let mut persistent_lease = raw.retain_expected_files(&cleaned_expected).unwrap();
        remove_verified_managed_file(
            &root,
            &transient.managed_path().unwrap(),
            &transient.digests(),
        )
        .unwrap();
        persistent_lease.revalidate().unwrap();
        let mut cleaned =
            audit_partial_output_tree(&root, &directories, &cleaned_expected).unwrap();
        cleaned.revalidate().unwrap();
        drop(cleaned);
        drop(persistent_lease);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn partial_audit_rejects_hard_link_and_unexpected_empty_directory() {
        let one = artifact("a/one.bin", b"one");
        let (root, directories, expected) =
            prepare_small_tree("hardlink", std::slice::from_ref(&one));
        let original = one.managed_path().unwrap().join_to(&root);
        let alias = root.join("a/alias.bin");
        if fs::hard_link(&original, &alias).is_ok() {
            assert!(audit_partial_output_tree(&root, &directories, &expected).is_err());
        }
        let _ = fs::remove_file(alias);
        fs::create_dir(root.join("unexpected")).unwrap();
        assert!(audit_partial_output_tree(&root, &directories, &expected).is_err());
        let _ = fs::remove_dir_all(root);
    }

    struct FakeRuntimeHost {
        runtime: RuntimeInstallation,
        events: Arc<Mutex<Vec<&'static str>>>,
        fail_revalidation: bool,
    }

    impl RuntimeRevalidator for FakeRuntimeHost {
        fn revalidate(
            &mut self,
            _installed: &RuntimeInstallation,
        ) -> Result<RuntimeInstallation, String> {
            self.events.lock().unwrap().push("revalidate");
            if self.fail_revalidation {
                Err("synthetic runtime fault".into())
            } else {
                Ok(self.runtime.clone())
            }
        }
    }

    fn synthetic_runtime() -> RuntimeInstallation {
        let base = std::env::current_dir().unwrap().join("target/fake-runtime");
        let image = base.join("image");
        RuntimeInstallation::synthetic(
            base,
            image.clone(),
            image.join("bin/javaw.exe"),
            image.join("bin/java.exe"),
            "a".repeat(64),
        )
    }

    fn with_revalidated_runtime<T, H, F>(
        host: &mut H,
        installed: &RuntimeInstallation,
        action: F,
    ) -> Result<T, String>
    where
        H: RuntimeRevalidator,
        F: FnOnce(&mut H, &RuntimeInstallation) -> Result<T, String>,
    {
        let verified = host.revalidate(installed)?;
        if &verified != installed {
            return Err("Java runtime revalidation returned a different capability".into());
        }
        action(host, &verified)
    }

    #[test]
    fn fake_host_proves_revalidation_precedes_prepare_and_spawn_and_fault_stops_chain() {
        let runtime = synthetic_runtime();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut host = FakeRuntimeHost {
            runtime: runtime.clone(),
            events: Arc::clone(&events),
            fail_revalidation: false,
        };
        with_revalidated_runtime(&mut host, &runtime, |host, _| {
            host.events.lock().unwrap().push("prepare");
            host.events.lock().unwrap().push("spawn");
            Ok(())
        })
        .unwrap();
        assert_eq!(*events.lock().unwrap(), ["revalidate", "prepare", "spawn"]);

        events.lock().unwrap().clear();
        host.fail_revalidation = true;
        assert!(with_revalidated_runtime(&mut host, &runtime, |host, _| {
            host.events.lock().unwrap().push("spawn");
            Ok(())
        })
        .is_err());
        assert_eq!(*events.lock().unwrap(), ["revalidate"]);
    }

    #[test]
    fn cancellation_and_nonzero_results_are_fail_closed() {
        let cancelled = AtomicBool::new(true);
        assert!(require_not_cancelled(&cancelled).is_err());
        cancelled.store(false, Ordering::Release);
        assert!(require_not_cancelled(&cancelled).is_ok());

        let nonzero = JavaProcessOutput {
            exit_code: 7,
            stdout: StreamCapture {
                bytes: 0,
                sha256: format!("{:x}", Sha256::digest([])),
                diagnostic: Vec::new(),
                truncated: false,
            },
            stderr: StreamCapture {
                bytes: 0,
                sha256: format!("{:x}", Sha256::digest([])),
                diagnostic: Vec::new(),
                truncated: false,
            },
            transcript_sha256: "b".repeat(64),
        };
        assert!(require_successful_exit("fake", 3, &nonzero)
            .unwrap_err()
            .contains("code 7"));
    }
}
