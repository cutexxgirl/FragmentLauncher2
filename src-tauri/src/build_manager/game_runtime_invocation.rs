use super::{
    contracts::{
        GameDerivedOutputKind, GameRuntimeLock, GameRuntimeRole, GameRuntimeSource,
        NormalizedProcessorArgument, OfflineProcessorVerification, ProcessorInput,
        ProcessorMaterializationAccess, ProcessorMaterializationId, RuntimeLock,
    },
    game_runtime::{reconstruct_executable_processor_steps, ExecutableProcessorStep},
    game_runtime_materializer::ProcessorWorkspace,
    managed_fs::RelativeManagedPath,
    runtime::RuntimeInstallation,
};
use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    marker::PhantomData,
    path::{Component, Path, PathBuf},
};

const EXECUTABLE_UPSTREAM_INDICES: [u8; 5] = [3, 5, 6, 8, 9];
#[cfg(windows)]
const MAX_WINDOWS_DIRECTORY_UTF16: usize = 32_767;

/// The only workspace shape accepted by the NeoForge processor invocation builder.
///
/// The materializer owns creation and filesystem auditing of these directories. This type closes
/// the lexical part of the contract: every input, output, temporary file, home directory and cwd
/// used in an invocation is derived from one absolute root and cannot be supplied independently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProcessorWorkspaceLayout {
    root: PathBuf,
    inputs: PathBuf,
    outputs: PathBuf,
    temp: PathBuf,
    state: PathBuf,
    home: PathBuf,
}

impl ProcessorWorkspaceLayout {
    fn new(root: &Path) -> Result<Self, String> {
        validate_absolute_lexical_path(root, "processor workspace root")?;
        let root = root.to_path_buf();
        let inputs = root.join("inputs");
        let outputs = root.join("outputs");
        let temp = root.join("temp");
        let state = root.join("state");
        let home = state.join("user-home");
        for (path, label) in [
            (&inputs, "processor inputs"),
            (&outputs, "processor outputs"),
            (&temp, "processor temp"),
            (&state, "processor state"),
            (&home, "processor home"),
        ] {
            validate_derived_path(&root, path, label)?;
        }
        Ok(Self {
            root,
            inputs,
            outputs,
            temp,
            state,
            home,
        })
    }

    fn from_materialized(workspace: &ProcessorWorkspace) -> Result<Self, String> {
        let layout = Self::new(workspace.root())?;
        if layout.inputs != workspace.inputs()
            || layout.outputs != workspace.outputs()
            || layout.temp != workspace.temp()
            || layout.state != workspace.state()
        {
            return Err(
                "Materialized processor workspace paths are internally inconsistent".into(),
            );
        }
        Ok(layout)
    }

    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) fn inputs(&self) -> &Path {
        &self.inputs
    }

    pub(super) fn outputs(&self) -> &Path {
        &self.outputs
    }

    pub(super) fn temp(&self) -> &Path {
        &self.temp
    }

    pub(super) fn state(&self) -> &Path {
        &self.state
    }

    pub(super) fn home(&self) -> &Path {
        &self.home
    }
}

/// A closed, immutable process specification for one signed NeoForge processor step.
///
/// There is deliberately no constructor and no mutable accessor. The executable is always the
/// console entrypoint from a verified `RuntimeInstallation`; arguments, cwd and environment can
/// only be produced by `prepare_processor_invocations`.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct PreparedProcessorInvocation {
    execution_index: u8,
    upstream_index: u8,
    id: String,
    executable: PathBuf,
    arguments: Vec<OsString>,
    cwd: PathBuf,
    environment: Vec<(OsString, OsString)>,
    expected_written_paths: Vec<PathBuf>,
}

impl PreparedProcessorInvocation {
    pub(super) fn execution_index(&self) -> u8 {
        self.execution_index
    }

    pub(super) fn upstream_index(&self) -> u8 {
        self.upstream_index
    }

    pub(super) fn id(&self) -> &str {
        &self.id
    }

    pub(super) fn executable(&self) -> &Path {
        &self.executable
    }

    pub(super) fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    pub(super) fn cwd(&self) -> &Path {
        &self.cwd
    }

    pub(super) fn environment(&self) -> &[(OsString, OsString)] {
        &self.environment
    }

    pub(super) fn expected_written_paths(&self) -> &[PathBuf] {
        &self.expected_written_paths
    }
}

/// Exactly five invocations, in the signed executable-plan order.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct PreparedProcessorPlan<'workspace> {
    invocations: [PreparedProcessorInvocation; 5],
    _workspace: PhantomData<&'workspace ProcessorWorkspace>,
}

impl PreparedProcessorPlan<'_> {
    pub(super) fn invocations(&self) -> &[PreparedProcessorInvocation; 5] {
        &self.invocations
    }
}

/// Constructs the only process specifications that the offline NeoForge executor may run.
///
/// Both locks are revalidated, the processor receipt is bound to the exact installed Temurin
/// runtime, and `SystemRoot` is obtained from the Windows API rather than inherited environment.
pub(super) fn prepare_processor_invocations<'workspace>(
    game_lock: &GameRuntimeLock,
    runtime_lock: &RuntimeLock,
    runtime: &RuntimeInstallation,
    workspace: &'workspace ProcessorWorkspace,
) -> Result<PreparedProcessorPlan<'workspace>, String> {
    let layout = ProcessorWorkspaceLayout::from_materialized(workspace)?;
    let system_root = trusted_windows_directory()?;
    let invocations = build_processor_invocations_with_system_root(
        game_lock,
        runtime_lock,
        runtime,
        &layout,
        &system_root,
    )?;
    Ok(PreparedProcessorPlan {
        invocations,
        _workspace: PhantomData,
    })
}

fn build_processor_invocations_with_system_root(
    game_lock: &GameRuntimeLock,
    runtime_lock: &RuntimeLock,
    runtime: &RuntimeInstallation,
    workspace: &ProcessorWorkspaceLayout,
    system_root: &Path,
) -> Result<[PreparedProcessorInvocation; 5], String> {
    game_lock.validate()?;
    runtime_lock.validate()?;
    bind_runtime_contract(game_lock, runtime_lock, runtime)?;
    validate_absolute_lexical_path(system_root, "trusted Windows directory")?;

    let bindings = ProcessorPathBindings::from_lock(game_lock, workspace)?;
    let receipt_steps = verified_receipt_steps(game_lock)?;
    let executable_steps = reconstruct_executable_processor_steps(game_lock)?;
    if executable_steps.len() != EXECUTABLE_UPSTREAM_INDICES.len() {
        return Err("NeoForge executable plan must contain exactly five steps".into());
    }

    let environment = fixed_environment(runtime, workspace, system_root)?;
    let mut invocations = Vec::with_capacity(EXECUTABLE_UPSTREAM_INDICES.len());
    for (position, step) in executable_steps.iter().enumerate() {
        if step.execution_index as usize != position
            || step.upstream_index != EXECUTABLE_UPSTREAM_INDICES[position]
            || step.upstream_index == 4
        {
            return Err("Only NeoForge processor steps 3,5,6,8,9 may be prepared".into());
        }
        let receipt = receipt_steps
            .get(position)
            .ok_or_else(|| "Verified processor receipt step is missing".to_string())?;
        if receipt.execution_index != step.execution_index
            || receipt.upstream_index != step.upstream_index
        {
            return Err(
                "Verified processor receipt order disagrees with the executable plan".into(),
            );
        }

        let arguments = render_invocation_arguments(step, runtime, workspace, &bindings)?;
        let expected_written_paths = receipt
            .written_paths
            .iter()
            .map(|path| resolve_managed(&workspace.outputs, path, "processor write-set path"))
            .collect::<Result<Vec<_>, _>>()?;
        invocations.push(PreparedProcessorInvocation {
            execution_index: step.execution_index,
            upstream_index: step.upstream_index,
            id: step.id.clone(),
            executable: runtime.java_console().to_path_buf(),
            arguments,
            cwd: workspace.root.clone(),
            environment: environment.clone(),
            expected_written_paths,
        });
    }

    let invocations: [PreparedProcessorInvocation; 5] = invocations
        .try_into()
        .map_err(|_| "NeoForge invocation count changed during preparation".to_string())?;
    Ok(invocations)
}

fn bind_runtime_contract(
    game_lock: &GameRuntimeLock,
    runtime_lock: &RuntimeLock,
    runtime: &RuntimeInstallation,
) -> Result<(), String> {
    for (path, label) in [
        (runtime.generation(), "Java generation"),
        (runtime.image(), "Java image"),
        (runtime.java(), "Java GUI entrypoint"),
        (runtime.java_console(), "Java console entrypoint"),
    ] {
        validate_absolute_lexical_path(path, label)?;
    }
    if runtime.image() != runtime.generation().join("image") {
        return Err("Verified Java image is not inside its generation".into());
    }
    let expected_java = resolve_managed(
        runtime.image(),
        &runtime_lock.java.executable,
        "Java GUI entrypoint",
    )?;
    let expected_java_console = resolve_managed(
        runtime.image(),
        &runtime_lock.java.console_executable,
        "Java console entrypoint",
    )?;
    if runtime.java() != expected_java || runtime.java_console() != expected_java_console {
        return Err("RuntimeInstallation entrypoints disagree with the runtime lock".into());
    }
    let extracted_tree_sha256 = runtime_lock.extracted_tree_sha256()?;
    game_lock.verification.offline_processors.bind_java_runtime(
        runtime.runtime_lock_sha256(),
        &runtime_lock.java.archive.sha256,
        &extracted_tree_sha256,
        &runtime_lock.java.version,
    )
}

fn verified_receipt_steps(
    game_lock: &GameRuntimeLock,
) -> Result<&[super::contracts::VerifiedProcessorStep], String> {
    match &game_lock.verification.offline_processors {
        OfflineProcessorVerification::Verified { runs, .. } => Ok(&runs[0].steps),
        OfflineProcessorVerification::Pending { .. } => {
            Err("Pending NeoForge processor verification cannot be executed".into())
        }
    }
}

fn render_invocation_arguments(
    step: &ExecutableProcessorStep,
    runtime: &RuntimeInstallation,
    workspace: &ProcessorWorkspaceLayout,
    bindings: &ProcessorPathBindings,
) -> Result<Vec<OsString>, String> {
    if step.classpath.is_empty() || step.classpath.first() != Some(&step.jar_path) {
        return Err("Processor tool must be the first classpath entry".into());
    }
    let classpath = step
        .classpath
        .iter()
        .map(|path| bindings.official_input(path))
        .collect::<Result<Vec<_>, _>>()?;
    let joined_classpath = std::env::join_paths(&classpath)
        .map_err(|error| format!("Processor classpath cannot be represented safely: {error}"))?;

    let mut arguments = fixed_jvm_prefix(runtime, workspace);
    arguments.push(OsString::from("-cp"));
    arguments.push(joined_classpath);
    arguments.push(OsString::from(&step.main_class));
    for argument in &step.arguments {
        arguments.push(render_processor_argument(argument, bindings)?);
    }
    Ok(arguments)
}

fn fixed_jvm_prefix(
    runtime: &RuntimeInstallation,
    workspace: &ProcessorWorkspaceLayout,
) -> Vec<OsString> {
    vec![
        path_property("java.home", runtime.image()),
        path_property("user.home", &workspace.home),
        path_property("java.io.tmpdir", &workspace.temp),
        OsString::from("-Duser.language=en"),
        OsString::from("-Duser.country=US"),
        OsString::from("-Duser.timezone=UTC"),
        OsString::from("-Dfile.encoding=UTF-8"),
    ]
}

fn fixed_environment(
    runtime: &RuntimeInstallation,
    workspace: &ProcessorWorkspaceLayout,
    system_root: &Path,
) -> Result<Vec<(OsString, OsString)>, String> {
    let java_bin = runtime
        .java_console()
        .parent()
        .ok_or_else(|| "Java console entrypoint has no parent directory".to_string())?;

    let environment = vec![
        (
            OsString::from("JAVA_HOME"),
            runtime.image().as_os_str().to_owned(),
        ),
        (OsString::from("PATH"), java_bin.as_os_str().to_owned()),
        (
            OsString::from("HOME"),
            workspace.home.as_os_str().to_owned(),
        ),
        (
            OsString::from("USERPROFILE"),
            workspace.home.as_os_str().to_owned(),
        ),
        (
            OsString::from("TEMP"),
            workspace.temp.as_os_str().to_owned(),
        ),
        (OsString::from("TMP"), workspace.temp.as_os_str().to_owned()),
        (OsString::from("LANG"), OsString::from("en_US.UTF-8")),
        (OsString::from("TZ"), OsString::from("UTC")),
        (
            OsString::from("SystemRoot"),
            system_root.as_os_str().to_owned(),
        ),
        (OsString::from("WINDIR"), system_root.as_os_str().to_owned()),
    ];
    let mut keys = HashSet::new();
    for (key, _) in &environment {
        let folded = key.to_string_lossy().to_ascii_lowercase();
        if !keys.insert(folded) {
            return Err("Processor environment contains a case-colliding key".into());
        }
    }
    Ok(environment)
}

fn path_property(name: &str, path: &Path) -> OsString {
    let mut value = OsString::from(format!("-D{name}="));
    value.push(path);
    value
}

fn render_processor_argument(
    argument: &NormalizedProcessorArgument,
    bindings: &ProcessorPathBindings,
) -> Result<OsString, String> {
    let value = match argument {
        NormalizedProcessorArgument::Literal { value } => return Ok(OsString::from(value)),
        NormalizedProcessorArgument::Path { path } => bindings.official_input(path)?,
        NormalizedProcessorArgument::Input { input } => match input {
            ProcessorInput::MinecraftClient => bindings.minecraft_client.clone(),
            ProcessorInput::MinecraftClientMappings => bindings.minecraft_client_mappings.clone(),
            ProcessorInput::ClientPatch => bindings.client_patch.clone(),
        },
        NormalizedProcessorArgument::Materialization {
            materialization: ProcessorMaterializationId::MinecraftClientMappings,
            access: ProcessorMaterializationAccess::Read,
        } => bindings.minecraft_client_mappings.clone(),
        NormalizedProcessorArgument::Materialization {
            access: ProcessorMaterializationAccess::Write,
            ..
        } => {
            return Err(
                "Write materialization is forbidden; DOWNLOAD_MOJMAPS must stay substituted".into(),
            );
        }
        NormalizedProcessorArgument::Output { output_kind } => {
            bindings.outputs.get(output_kind).cloned().ok_or_else(|| {
                format!("Processor references an unknown derived output: {output_kind:?}")
            })?
        }
    };
    Ok(value.into_os_string())
}

struct ProcessorPathBindings {
    official_inputs: HashMap<String, (String, PathBuf)>,
    minecraft_client: PathBuf,
    minecraft_client_mappings: PathBuf,
    client_patch: PathBuf,
    outputs: HashMap<GameDerivedOutputKind, PathBuf>,
}

impl ProcessorPathBindings {
    fn from_lock(
        game_lock: &GameRuntimeLock,
        workspace: &ProcessorWorkspaceLayout,
    ) -> Result<Self, String> {
        let mut official_inputs = HashMap::new();
        let mut official_collisions = HashMap::new();
        let mut outputs = HashMap::new();
        let mut output_collisions = HashMap::new();
        for file in &game_lock.files {
            let relative = RelativeManagedPath::new(&file.path)
                .map_err(|error| format!("Game runtime binding path is unsafe: {error}"))?;
            match &file.source {
                GameRuntimeSource::Official { .. } => {
                    register_collision_key(&mut official_collisions, &relative, "processor input")?;
                    official_inputs.insert(
                        relative.collision_key().to_owned(),
                        (
                            relative.as_str().to_owned(),
                            relative.join_to(&workspace.inputs),
                        ),
                    );
                }
                GameRuntimeSource::Derived { output_kind, .. } => {
                    register_collision_key(&mut output_collisions, &relative, "processor output")?;
                    if outputs
                        .insert(*output_kind, relative.join_to(&workspace.outputs))
                        .is_some()
                    {
                        return Err("Derived output kind is declared more than once".into());
                    }
                }
            }
        }
        if outputs.len() != 6 {
            return Err("Processor bindings require exactly six derived outputs".into());
        }

        let minecraft_client_path = unique_role_path(game_lock, GameRuntimeRole::MinecraftClient)?;
        let minecraft_mappings_path =
            unique_role_path(game_lock, GameRuntimeRole::MinecraftClientMappings)?;
        let materialization = &game_lock
            .provenance
            .processor_plans
            .translation
            .materializations[0];
        if materialization.path != minecraft_mappings_path {
            return Err("Mappings materialization path disagrees with its official input".into());
        }
        let client_patch_relative = format!(
            "processor-inputs/{}",
            game_lock.provenance.client_patch.entry
        );
        let client_patch = resolve_managed(
            &workspace.inputs,
            &client_patch_relative,
            "NeoForge client patch",
        )?;

        let bindings = Self {
            minecraft_client: resolve_declared_official(&official_inputs, &minecraft_client_path)?,
            minecraft_client_mappings: resolve_declared_official(
                &official_inputs,
                &minecraft_mappings_path,
            )?,
            client_patch,
            official_inputs,
            outputs,
        };
        Ok(bindings)
    }

    fn official_input(&self, path: &str) -> Result<PathBuf, String> {
        resolve_declared_official(&self.official_inputs, path)
    }
}

fn unique_role_path(game_lock: &GameRuntimeLock, role: GameRuntimeRole) -> Result<String, String> {
    let mut matches = game_lock.files.iter().filter(|file| {
        file.role == role && matches!(&file.source, GameRuntimeSource::Official { .. })
    });
    let path = matches
        .next()
        .ok_or_else(|| format!("Required official processor input role is missing: {role:?}"))?
        .path
        .clone();
    if matches.next().is_some() {
        return Err(format!(
            "Required official processor input role is ambiguous: {role:?}"
        ));
    }
    Ok(path)
}

fn resolve_declared_official(
    official_inputs: &HashMap<String, (String, PathBuf)>,
    path: &str,
) -> Result<PathBuf, String> {
    let relative = RelativeManagedPath::new(path)
        .map_err(|error| format!("Processor input path is unsafe: {error}"))?;
    let (declared, absolute) = official_inputs
        .get(relative.collision_key())
        .ok_or_else(|| format!("Processor input is not an official declared file: {path}"))?;
    if declared != path {
        return Err(format!(
            "Processor input casing disagrees with the signed declaration: {path}"
        ));
    }
    Ok(absolute.clone())
}

fn register_collision_key(
    seen: &mut HashMap<String, String>,
    path: &RelativeManagedPath,
    label: &str,
) -> Result<(), String> {
    if let Some(previous) = seen.insert(path.collision_key().to_owned(), path.as_str().to_owned()) {
        return Err(format!(
            "{label} paths collide on Windows: {previous} and {}",
            path.as_str()
        ));
    }
    Ok(())
}

fn resolve_managed(root: &Path, relative: &str, label: &str) -> Result<PathBuf, String> {
    validate_absolute_lexical_path(root, &format!("{label} root"))?;
    let relative = RelativeManagedPath::new(relative)
        .map_err(|error| format!("{label} is unsafe: {error}"))?;
    let result = relative.join_to(root);
    validate_derived_path(root, &result, label)?;
    Ok(result)
}

fn validate_derived_path(root: &Path, path: &Path, label: &str) -> Result<(), String> {
    validate_absolute_lexical_path(path, label)?;
    if path == root || !path.starts_with(root) {
        return Err(format!("{label} escaped its controlled root"));
    }
    Ok(())
}

fn validate_absolute_lexical_path(path: &Path, label: &str) -> Result<(), String> {
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return Err(format!("{label} must be absolute"));
    }
    if path.components().any(|component| {
        matches!(component, Component::CurDir | Component::ParentDir)
            || matches!(component, Component::Normal(value) if value.is_empty())
    }) {
        return Err(format!("{label} contains a lexical traversal component"));
    }
    Ok(())
}

#[cfg(windows)]
fn trusted_windows_directory() -> Result<PathBuf, String> {
    use std::os::windows::ffi::OsStringExt;

    #[link(name = "kernel32")]
    extern "system" {
        #[link_name = "GetWindowsDirectoryW"]
        fn get_windows_directory_w(buffer: *mut u16, size: u32) -> u32;
    }

    let mut buffer = vec![0_u16; 260];
    loop {
        let capacity = u32::try_from(buffer.len())
            .map_err(|_| "Windows directory buffer exceeds u32".to_string())?;
        // SAFETY: `buffer` is writable for exactly `capacity` UTF-16 code units and remains alive
        // for the duration of this synchronous Windows API call.
        let length = unsafe { get_windows_directory_w(buffer.as_mut_ptr(), capacity) } as usize;
        if length == 0 {
            return Err("Windows did not provide its trusted system directory".into());
        }
        if length < buffer.len() {
            let path = PathBuf::from(OsString::from_wide(&buffer[..length]));
            validate_absolute_lexical_path(&path, "trusted Windows directory")?;
            return Ok(path);
        }
        if length > MAX_WINDOWS_DIRECTORY_UTF16 {
            return Err("Windows directory exceeds the launcher UTF-16 limit".into());
        }
        buffer.resize(
            length
                .checked_add(1)
                .ok_or_else(|| "Windows directory length overflow".to_string())?,
            0,
        );
    }
}

#[cfg(not(windows))]
fn trusted_windows_directory() -> Result<PathBuf, String> {
    Err("NeoForge processor invocations are supported only on Windows".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_manager::contracts::domain_digest;
    use serde_json::json;
    use std::ffi::OsStr;

    const JVM_PREFIX_ARGUMENT_COUNT: usize = 7;

    const INSTALLER_TOOLS_CLASSPATH: &[&str] = &[
        "libraries/net/neoforged/installertools/installertools/2.1.2/installertools-2.1.2.jar",
        "libraries/net/neoforged/srgutils/1.0.0/srgutils-1.0.0.jar",
        "libraries/net/md-5/SpecialSource/1.11.0/SpecialSource-1.11.0.jar",
        "libraries/net/sf/jopt-simple/jopt-simple/5.0.4/jopt-simple-5.0.4.jar",
        "libraries/com/google/code/gson/gson/2.8.9/gson-2.8.9.jar",
        "libraries/de/siegmar/fastcsv/2.0.0/fastcsv-2.0.0.jar",
        "libraries/org/ow2/asm/asm-commons/9.3/asm-commons-9.3.jar",
        "libraries/net/neoforged/installertools/cli-utils/2.1.2/cli-utils-2.1.2.jar",
        "libraries/com/google/guava/guava/20.0/guava-20.0.jar",
        "libraries/com/opencsv/opencsv/4.4/opencsv-4.4.jar",
        "libraries/org/ow2/asm/asm-analysis/9.3/asm-analysis-9.3.jar",
        "libraries/org/ow2/asm/asm-tree/9.3/asm-tree-9.3.jar",
        "libraries/org/ow2/asm/asm/9.3/asm-9.3.jar",
        "libraries/org/apache/commons/commons-text/1.3/commons-text-1.3.jar",
        "libraries/org/apache/commons/commons-lang3/3.8.1/commons-lang3-3.8.1.jar",
        "libraries/commons-beanutils/commons-beanutils/1.9.3/commons-beanutils-1.9.3.jar",
        "libraries/org/apache/commons/commons-collections4/4.2/commons-collections4-4.2.jar",
        "libraries/commons-logging/commons-logging/1.2/commons-logging-1.2.jar",
        "libraries/commons-collections/commons-collections/3.2.2/commons-collections-3.2.2.jar",
    ];
    const JARSPLITTER_CLASSPATH: &[&str] = &[
        "libraries/net/neoforged/installertools/jarsplitter/2.1.2/jarsplitter-2.1.2.jar",
        "libraries/net/sf/jopt-simple/jopt-simple/5.0.4/jopt-simple-5.0.4.jar",
        "libraries/net/neoforged/srgutils/1.0.0/srgutils-1.0.0.jar",
        "libraries/net/neoforged/installertools/cli-utils/2.1.2/cli-utils-2.1.2.jar",
    ];

    fn synthetic_runtime_lock() -> RuntimeLock {
        RuntimeLock::parse_and_validate(
            serde_json::to_vec(&json!({
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
                        "url": "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.3%2B9/OpenJDK25U-jre_x64_windows_hotspot_25.0.3_9.zip",
                        "checksumUrl": "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.3%2B9/OpenJDK25U-jre_x64_windows_hotspot_25.0.3_9.zip.sha256.txt",
                        "signatureUrl": "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.3%2B9/OpenJDK25U-jre_x64_windows_hotspot_25.0.3_9.zip.sig",
                        "signingKeyFingerprint": "3B04D753C9050D9A5D343F39843C48A565F8F04B",
                        "size": 2,
                        "sha256": "a".repeat(64),
                        "format": "zip",
                        "stripPrefix": "jdk-25.0.3+9-jre"
                    },
                    "executable": "bin/javaw.exe",
                    "consoleExecutable": "bin/java.exe",
                    "files": [
                        {"path": "bin/java.exe", "size": 1, "sha256": "b".repeat(64)},
                        {"path": "bin/javaw.exe", "size": 1, "sha256": "c".repeat(64)}
                    ]
                },
                "minecraft": {
                    "version": "1.21.1",
                    "versionManifestUrl": "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json",
                    "versionJsonUrl": "https://piston-meta.mojang.com/v1/packages/8344022e055c6c052047107a80e33d96c48e9fba/1.21.1.json",
                    "versionJsonSha1": "8344022e055c6c052047107a80e33d96c48e9fba"
                }
            }))
            .expect("runtime fixture must serialize")
            .as_slice(),
        )
        .expect("runtime fixture must validate")
    }

    fn bound_game_lock(runtime_lock: &RuntimeLock, runtime_lock_sha256: &str) -> GameRuntimeLock {
        let mut value: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/game-runtime-lock-v2-release-canonical-verified.json"
        ))
        .expect("canonical game runtime fixture must parse");
        let java = &mut value["verification"]["offlineProcessors"]["java"];
        java["runtimeLockSha256"] = json!(runtime_lock_sha256);
        java["archiveSha256"] = json!(runtime_lock.java.archive.sha256);
        java["extractedTreeSha256"] =
            json!(runtime_lock.extracted_tree_sha256().expect("tree digest"));
        java["version"] = json!(runtime_lock.java.version);

        let receipt = &mut value["verification"]["offlineProcessors"];
        let mut payload = receipt.clone();
        payload
            .as_object_mut()
            .expect("receipt must be an object")
            .remove("receiptSha256");
        receipt["receiptSha256"] = json!(domain_digest(
            "ru.fragmc.spark2.neoforge.offline-receipt.v2",
            &payload,
        )
        .expect("receipt digest"));
        GameRuntimeLock::parse_and_validate(
            &serde_json::to_vec(&value).expect("game runtime fixture must serialize"),
        )
        .expect("bound game runtime fixture must validate")
    }

    fn fixture_context() -> (
        GameRuntimeLock,
        RuntimeLock,
        RuntimeInstallation,
        ProcessorWorkspaceLayout,
        PathBuf,
    ) {
        let runtime_lock = synthetic_runtime_lock();
        let runtime_lock_sha256 = "d".repeat(64);
        let game_lock = bound_game_lock(&runtime_lock, &runtime_lock_sha256);
        let base = std::env::current_dir()
            .expect("current directory")
            .join("target")
            .join("processor-invocation-golden");
        let generation = base.join("java-generation");
        let image = generation.join("image");
        let runtime = RuntimeInstallation::synthetic(
            generation,
            image.clone(),
            image.join("bin/javaw.exe"),
            image.join("bin/java.exe"),
            runtime_lock_sha256,
        );
        let workspace = ProcessorWorkspaceLayout::new(&base.join("workspace")).unwrap();
        let system_root = base.join("trusted-windows");
        (game_lock, runtime_lock, runtime, workspace, system_root)
    }

    fn input(workspace: &ProcessorWorkspaceLayout, path: &str) -> OsString {
        RelativeManagedPath::new(path)
            .unwrap()
            .join_to(workspace.inputs())
            .into_os_string()
    }

    fn output(workspace: &ProcessorWorkspaceLayout, path: &str) -> OsString {
        RelativeManagedPath::new(path)
            .unwrap()
            .join_to(workspace.outputs())
            .into_os_string()
    }

    fn expected_application_arguments(
        upstream_index: u8,
        workspace: &ProcessorWorkspaceLayout,
    ) -> Vec<OsString> {
        let literal = |value: &str| OsString::from(value);
        match upstream_index {
            3 => vec![
                literal("--task"),
                literal("MCP_DATA"),
                literal("--input"),
                input(workspace, "libraries/net/neoforged/neoform/1.21.1-20240808.144430/neoform-1.21.1-20240808.144430.zip"),
                literal("--output"),
                output(workspace, "libraries/net/neoforged/neoform/1.21.1-20240808.144430/neoform-1.21.1-20240808.144430-mappings.txt"),
                literal("--key"),
                literal("mappings"),
            ],
            5 => vec![
                literal("--task"),
                literal("MERGE_MAPPING"),
                literal("--left"),
                output(workspace, "libraries/net/neoforged/neoform/1.21.1-20240808.144430/neoform-1.21.1-20240808.144430-mappings.txt"),
                literal("--right"),
                input(workspace, "libraries/net/minecraft/client/1.21.1-20240808.144430/client-1.21.1-20240808.144430-mappings.txt"),
                literal("--output"),
                output(workspace, "libraries/net/neoforged/neoform/1.21.1-20240808.144430/neoform-1.21.1-20240808.144430-mappings-merged.txt"),
                literal("--classes"),
                literal("--fields"),
                literal("--methods"),
                literal("--reverse-right"),
            ],
            6 => vec![
                literal("--input"),
                input(workspace, "versions/1.21.1/1.21.1.jar"),
                literal("--slim"),
                output(workspace, "libraries/net/minecraft/client/1.21.1-20240808.144430/client-1.21.1-20240808.144430-slim.jar"),
                literal("--extra"),
                output(workspace, "libraries/net/minecraft/client/1.21.1-20240808.144430/client-1.21.1-20240808.144430-extra.jar"),
                literal("--srg"),
                output(workspace, "libraries/net/neoforged/neoform/1.21.1-20240808.144430/neoform-1.21.1-20240808.144430-mappings-merged.txt"),
            ],
            8 => vec![
                literal("--input"),
                output(workspace, "libraries/net/minecraft/client/1.21.1-20240808.144430/client-1.21.1-20240808.144430-slim.jar"),
                literal("--output"),
                output(workspace, "libraries/net/minecraft/client/1.21.1-20240808.144430/client-1.21.1-20240808.144430-srg.jar"),
                literal("--names"),
                output(workspace, "libraries/net/neoforged/neoform/1.21.1-20240808.144430/neoform-1.21.1-20240808.144430-mappings-merged.txt"),
                literal("--ann-fix"),
                literal("--ids-fix"),
                literal("--src-fix"),
                literal("--record-fix"),
            ],
            9 => vec![
                literal("--clean"),
                output(workspace, "libraries/net/minecraft/client/1.21.1-20240808.144430/client-1.21.1-20240808.144430-srg.jar"),
                literal("--output"),
                output(workspace, "libraries/net/neoforged/neoforge/21.1.235/neoforge-21.1.235-client.jar"),
                literal("--apply"),
                input(workspace, "processor-inputs/data/client.lzma"),
            ],
            _ => panic!("unexpected golden upstream index"),
        }
    }

    fn expected_classpath(upstream_index: u8) -> &'static [&'static str] {
        match upstream_index {
            3 | 5 => INSTALLER_TOOLS_CLASSPATH,
            6 => JARSPLITTER_CLASSPATH,
            8 => &["libraries/net/neoforged/AutoRenamingTool/2.0.3/AutoRenamingTool-2.0.3-all.jar"],
            9 => &["libraries/net/neoforged/installertools/binarypatcher/2.1.2/binarypatcher-2.1.2-fatjar.jar"],
            _ => panic!("unexpected golden upstream index"),
        }
    }

    #[test]
    fn canonical_fixture_prepares_exact_five_golden_invocations() {
        let (game_lock, runtime_lock, runtime, workspace, system_root) = fixture_context();
        let plan = build_processor_invocations_with_system_root(
            &game_lock,
            &runtime_lock,
            &runtime,
            &workspace,
            &system_root,
        )
        .unwrap();
        let expected_ids = [
            "MCP_DATA",
            "MERGE_MAPPING",
            "jarsplitter",
            "AutoRenamingTool",
            "binarypatcher",
        ];
        let prefix = fixed_jvm_prefix(&runtime, &workspace);
        assert_eq!(prefix.len(), JVM_PREFIX_ARGUMENT_COUNT);

        for (position, invocation) in plan.iter().enumerate() {
            let upstream_index = EXECUTABLE_UPSTREAM_INDICES[position];
            assert_eq!(invocation.execution_index(), position as u8);
            assert_eq!(invocation.upstream_index(), upstream_index);
            assert_eq!(invocation.id(), expected_ids[position]);
            assert_ne!(invocation.upstream_index(), 4);
            assert_eq!(invocation.executable(), runtime.java_console());
            assert_eq!(invocation.cwd(), workspace.root());

            let arguments = invocation.arguments();
            assert_eq!(&arguments[..JVM_PREFIX_ARGUMENT_COUNT], prefix.as_slice());
            assert_eq!(arguments[JVM_PREFIX_ARGUMENT_COUNT], OsStr::new("-cp"));
            let expected_classpath = expected_classpath(upstream_index)
                .iter()
                .map(|path| input(&workspace, path))
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            assert_eq!(
                arguments[JVM_PREFIX_ARGUMENT_COUNT + 1],
                std::env::join_paths(expected_classpath).unwrap()
            );
            let expected_main_class = match upstream_index {
                3 | 5 => "net.neoforged.installertools.ConsoleTool",
                6 => "net.neoforged.jarsplitter.ConsoleTool",
                8 => "net.neoforged.art.Main",
                9 => "net.neoforged.binarypatcher.ConsoleTool",
                _ => unreachable!(),
            };
            assert_eq!(
                arguments[JVM_PREFIX_ARGUMENT_COUNT + 2],
                OsStr::new(expected_main_class)
            );
            assert_eq!(
                &arguments[JVM_PREFIX_ARGUMENT_COUNT + 3..],
                expected_application_arguments(upstream_index, &workspace)
            );
        }
    }

    #[test]
    fn canonical_fixture_has_exact_fixed_environment_and_write_sets() {
        let (game_lock, runtime_lock, runtime, workspace, system_root) = fixture_context();
        let plan = build_processor_invocations_with_system_root(
            &game_lock,
            &runtime_lock,
            &runtime,
            &workspace,
            &system_root,
        )
        .unwrap();
        let expected_environment = fixed_environment(&runtime, &workspace, &system_root).unwrap();
        for invocation in &plan {
            assert_eq!(invocation.environment(), expected_environment);
        }
        assert_eq!(
            expected_environment
                .iter()
                .map(|(key, _)| key.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            [
                "JAVA_HOME",
                "PATH",
                "HOME",
                "USERPROFILE",
                "TEMP",
                "TMP",
                "LANG",
                "TZ",
                "SystemRoot",
                "WINDIR",
            ]
        );
        assert_eq!(
            expected_environment
                .iter()
                .find(|(key, _)| key == OsStr::new("PATH"))
                .expect("PATH must be present")
                .1
                .as_os_str(),
            runtime
                .java_console()
                .parent()
                .expect("java console parent")
                .as_os_str()
        );
        assert_eq!(plan[0].expected_written_paths().len(), 1);
        assert_eq!(plan[1].expected_written_paths().len(), 1);
        assert_eq!(plan[2].expected_written_paths().len(), 4);
        assert_eq!(plan[3].expected_written_paths().len(), 1);
        assert_eq!(plan[4].expected_written_paths().len(), 1);
    }

    #[test]
    fn renderer_rejects_escape_collisions_unknown_outputs_and_write_materialization() {
        let (game_lock, _runtime_lock, _runtime, workspace, _system_root) = fixture_context();
        assert!(resolve_managed(workspace.inputs(), "../escape", "test input").is_err());

        let mut collisions = HashMap::new();
        let first = RelativeManagedPath::new("Libraries/Tool.jar").unwrap();
        let second = RelativeManagedPath::new("libraries/tool.jar").unwrap();
        register_collision_key(&mut collisions, &first, "test").unwrap();
        assert!(register_collision_key(&mut collisions, &second, "test").is_err());

        let mut bindings = ProcessorPathBindings::from_lock(&game_lock, &workspace).unwrap();
        bindings
            .outputs
            .remove(&GameDerivedOutputKind::PatchedClient);
        let unknown = NormalizedProcessorArgument::Output {
            output_kind: GameDerivedOutputKind::PatchedClient,
        };
        assert!(render_processor_argument(&unknown, &bindings)
            .unwrap_err()
            .contains("unknown derived output"));

        let write = NormalizedProcessorArgument::Materialization {
            materialization: ProcessorMaterializationId::MinecraftClientMappings,
            access: ProcessorMaterializationAccess::Write,
        };
        assert!(render_processor_argument(&write, &bindings)
            .unwrap_err()
            .contains("Write materialization is forbidden"));
    }

    #[test]
    fn preparation_rejects_forged_java_console_and_unbound_runtime() {
        let (game_lock, runtime_lock, runtime, workspace, system_root) = fixture_context();
        let forged = RuntimeInstallation::synthetic(
            runtime.generation().to_path_buf(),
            runtime.image().to_path_buf(),
            runtime.java().to_path_buf(),
            runtime.image().join("bin/evil.exe"),
            runtime.runtime_lock_sha256().to_owned(),
        );
        assert!(build_processor_invocations_with_system_root(
            &game_lock,
            &runtime_lock,
            &forged,
            &workspace,
            &system_root,
        )
        .unwrap_err()
        .contains("entrypoints disagree"));

        let (game_lock, runtime_lock, runtime, workspace, system_root) = fixture_context();
        let unbound = RuntimeInstallation::synthetic(
            runtime.generation().to_path_buf(),
            runtime.image().to_path_buf(),
            runtime.java().to_path_buf(),
            runtime.java_console().to_path_buf(),
            "e".repeat(64),
        );
        assert!(build_processor_invocations_with_system_root(
            &game_lock,
            &runtime_lock,
            &unbound,
            &workspace,
            &system_root,
        )
        .is_err());
    }
}
