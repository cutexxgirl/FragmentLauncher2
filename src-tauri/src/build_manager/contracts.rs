use super::neoforge::{NEOFORGE_INSTALLER_SHA256, NEOFORGE_INSTALLER_URL};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use unicode_normalization::UnicodeNormalization;
use url::Url;

pub const JAVA_MAJOR: u8 = 25;
pub const JAVA_DISTRIBUTION: &str = "eclipse-temurin";
pub const JAVA_IMAGE_TYPE: &str = "jre";
pub const JAVA_VM: &str = "hotspot";

pub const MAX_GAME_RUNTIME_LOCK_BYTES: usize = 32 * 1024 * 1024;
const MAX_GAME_RUNTIME_FILES: usize = 20_000;
const MAX_GAME_RUNTIME_FILE_SIZE: u64 = 8 * 1024 * 1024 * 1024;
const MAX_GAME_RUNTIME_TOTAL_SIZE: u64 = 16 * 1024 * 1024 * 1024;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const UPSTREAM_PROCESSOR_INDICES: [u8; 6] = [3, 4, 5, 6, 8, 9];
const EXECUTABLE_PROCESSOR_INDICES: [u8; 5] = [3, 5, 6, 8, 9];
const PROCESSOR_RECIPE: &str = "spark2-neoforge-client-offline-v2";
const NEOFORGE_UPSTREAM_PLAN_SHA256: &str =
    "76240c5d986921bf1d9b7744ce5aa51c36a5621ba4456f6f77ad12c6d4c94c7c";
const NEOFORGE_TRANSLATION_SHA256: &str =
    "4b0a3ca779ac57c5dd8fcba122b649c1dd7ed48f443935f9df8bf16f326e0d0a";
const NEOFORGE_EXECUTABLE_PLAN_SHA256: &str =
    "ed14553396a9dc99a16852d0c4b055c70041acbcd500a44fcccfd049a28b70e5";
const NEOFORGE_MATERIALIZATION_GRAPH_SHA256: &str =
    "8aa3f424724e56b33913138c469b86fdb3c3372ef65389c477294690e62b6d98";
const PROCESSOR_INPUT_STATE_DOMAIN: &str = "ru.fragmc.spark2.neoforge.materialized-input-state.v2";
const PROCESSOR_TRANSCRIPT_DOMAIN: &str = "ru.fragmc.spark2.neoforge.transcript.v1";

const GAME_RUNTIME_ID: &str = "minecraft-1.21.1-neoforge-21.1.235-windows-x64";
const GAME_MAIN_CLASS: &str = "cpw.mods.bootstraplauncher.BootstrapLauncher";
const GAME_VERSION_NAME: &str = "neoforge-21.1.235";
const GAME_ASSET_INDEX_NAME: &str = "17";
const MINECRAFT_VERSION_JSON_URL: &str = "https://piston-meta.mojang.com/v1/packages/8344022e055c6c052047107a80e33d96c48e9fba/1.21.1.json";
const MINECRAFT_VERSION_JSON_SIZE: u64 = 38_408;
const MINECRAFT_VERSION_JSON_SHA1: &str = "8344022e055c6c052047107a80e33d96c48e9fba";
const MINECRAFT_VERSION_JSON_SHA256: &str =
    "f286cb00c18afb9d0c3c0a9ed898fe25b4fe8de023e898adc6247202c4adbf2c";
const MINECRAFT_CLIENT_URL: &str =
    "https://piston-data.mojang.com/v1/objects/30c73b1c5da787909b2f73340419fdf13b9def88/client.jar";
const MINECRAFT_CLIENT_SIZE: u64 = 26_836_906;
const MINECRAFT_CLIENT_SHA1: &str = "30c73b1c5da787909b2f73340419fdf13b9def88";
const MINECRAFT_CLIENT_SHA256: &str =
    "499f6897d1837516680f3114072d8106e11c9adcd933fe5cf051b551089b0c99";
const MINECRAFT_CLIENT_PATH: &str = "versions/1.21.1/1.21.1.jar";
const MINECRAFT_ASSET_INDEX_URL: &str =
    "https://piston-meta.mojang.com/v1/packages/63a8198cacdc21ca940567d5a292e7849f4e2b5c/17.json";
const MINECRAFT_ASSET_INDEX_SIZE: u64 = 449_557;
const MINECRAFT_ASSET_INDEX_SHA1: &str = "63a8198cacdc21ca940567d5a292e7849f4e2b5c";
const MINECRAFT_ASSET_INDEX_SHA256: &str =
    "f73e8267bc7644edb018503a9cce9bb3dd42032433e48fe68712d3538e3077e1";
const MINECRAFT_ASSET_OBJECT_COUNT: usize = 3_888;
const MINECRAFT_ASSET_OBJECT_BYTES: u64 = 821_204_427;
const MINECRAFT_ASSET_LOGICAL_COUNT: usize = 3_911;
const MINECRAFT_LOGGING_CONFIG_URL: &str = "https://piston-data.mojang.com/v1/objects/bd65e7d2e3c237be76cfbef4c2405033d7f91521/client-1.12.xml";
const MINECRAFT_LOGGING_CONFIG_SIZE: u64 = 888;
const MINECRAFT_LOGGING_CONFIG_SHA1: &str = "bd65e7d2e3c237be76cfbef4c2405033d7f91521";
const MINECRAFT_LOGGING_CONFIG_SHA256: &str =
    "03e30ee5bd5c1fc723d1049e2e4e8b3ad4c4992514f3206fc4b54637488b83e4";
const MINECRAFT_CLIENT_MAPPINGS_URL: &str =
    "https://piston-data.mojang.com/v1/objects/2244b6f072256667bcd9a73df124d6c58de77992/client.txt";
const MINECRAFT_CLIENT_MAPPINGS_SIZE: u64 = 9_598_610;
const MINECRAFT_CLIENT_MAPPINGS_SHA1: &str = "2244b6f072256667bcd9a73df124d6c58de77992";
const MINECRAFT_CLIENT_MAPPINGS_SHA256: &str =
    "140c47931cccc8fc9e4c22d7603e2d714d1a953a146f51ea7397d95c955536ec";
const MINECRAFT_CLIENT_MAPPINGS_PATH: &str = "libraries/net/minecraft/client/1.21.1-20240808.144430/client-1.21.1-20240808.144430-mappings.txt";
const NEOFORGE_INSTALLER_SIZE: u64 = 6_965_992;
const NEOFORGE_INSTALLER_SHA1: &str = "b832f29abee53f738600a9ebe22d8d41c8fafc3c";
const NEOFORGE_INSTALLER_PATH: &str = "installers/neoforge-21.1.235-installer.jar";
const NEOFORGE_INSTALL_PROFILE_SIZE: u64 = 130_522;
const NEOFORGE_INSTALL_PROFILE_SHA256: &str =
    "234a708aef21085a7854175c51d57e76070ec9b0928b2dcbd6662d86fd849682";
const NEOFORGE_VERSION_JSON_SIZE: u64 = 21_148;
const NEOFORGE_VERSION_JSON_SHA256: &str =
    "44c6470be41a146a7329094b3088691ad695a95f977705e5226312559a27c301";
const NEOFORGE_CLIENT_PATCH_SIZE: u64 = 3_239_759;
const NEOFORGE_CLIENT_PATCH_SHA256: &str =
    "e1f652a268d14d054cb8ced4af762c19db9c584d29859b426c966a2b7341cdbd";
const NEOFORGE_CLIENT_PATCH_MATERIALIZED_PATH: &str = "processor-inputs/data/client.lzma";
const NEOFORGE_UNIVERSAL_URL: &str = "https://maven.neoforged.net/releases/net/neoforged/neoforge/21.1.235/neoforge-21.1.235-universal.jar";
const NEOFORGE_UNIVERSAL_SIZE: u64 = 3_542_501;
const NEOFORGE_UNIVERSAL_SHA1: &str = "084bddfdd2a383aa5bfb696fce11b15482787691";
const NEOFORGE_UNIVERSAL_SHA256: &str =
    "dbded1a88b4a4f4e30a981672e58132dbd0cae64677e33a2ad867d00a4343d5e";
const NEOFORGE_DERIVED_CLIENT_PATH: &str =
    "libraries/net/neoforged/neoforge/21.1.235/neoforge-21.1.235-client.jar";
const NEOFORGE_DERIVED_OUTPUTS: [DerivedOutputSpec; 6] = [
    DerivedOutputSpec {
        output_kind: GameDerivedOutputKind::NeoformMappings,
        role: GameRuntimeRole::NeoforgeDerivedMappings,
        path: "libraries/net/neoforged/neoform/1.21.1-20240808.144430/neoform-1.21.1-20240808.144430-mappings.txt",
        size: 5_601_343,
        sha1: "c9fe69b8e39fc9ae8a56e6666204505866006cce",
        sha256: "8081431dcb7c2428db07582db7135be739fa50b123103b3eaf14b2ae16ea37a6",
        launch_required: false,
    },
    DerivedOutputSpec {
        output_kind: GameDerivedOutputKind::MergedMappings,
        role: GameRuntimeRole::NeoforgeDerivedMergedMappings,
        path: "libraries/net/neoforged/neoform/1.21.1-20240808.144430/neoform-1.21.1-20240808.144430-mappings-merged.txt",
        size: 5_636_727,
        sha1: "8184d8b290627ae54ab0eb980801bfe011f70175",
        sha256: "7bd3e2be95fa246778b90b078dbb78b5d1a7a98853baea5e1321a6c3d5383929",
        launch_required: false,
    },
    DerivedOutputSpec {
        output_kind: GameDerivedOutputKind::ClientSlim,
        role: GameRuntimeRole::NeoforgeDerivedClientSlim,
        path: "libraries/net/minecraft/client/1.21.1-20240808.144430/client-1.21.1-20240808.144430-slim.jar",
        size: 14_464_635,
        sha1: "b4fb33003ee0975bc4511ff09d5d4a268b33fc2b",
        sha256: "93224371dda52351038d0957e392729e692dce031f55ae29ea4b47d909433a5c",
        launch_required: false,
    },
    DerivedOutputSpec {
        output_kind: GameDerivedOutputKind::ClientExtra,
        role: GameRuntimeRole::NeoforgeDerivedClientExtra,
        path: "libraries/net/minecraft/client/1.21.1-20240808.144430/client-1.21.1-20240808.144430-extra.jar",
        size: 12_372_293,
        sha1: "db5c59932751d66c2f57c1c2de41b48712620975",
        sha256: "fd02f80f4eec9dfaa1714cb62595d013cbac03d52d19dd0623d1922b999c40b7",
        launch_required: true,
    },
    DerivedOutputSpec {
        output_kind: GameDerivedOutputKind::ClientSrg,
        role: GameRuntimeRole::NeoforgeDerivedClientSrg,
        path: "libraries/net/minecraft/client/1.21.1-20240808.144430/client-1.21.1-20240808.144430-srg.jar",
        size: 18_725_656,
        sha1: "a4827225b3c07662ca68b03ea20d11433a0c0488",
        sha256: "a649bd3ce77f122d0f83ae1b37b4b303e662470f928b9bee5fbc76580805ffd4",
        launch_required: true,
    },
    DerivedOutputSpec {
        output_kind: GameDerivedOutputKind::PatchedClient,
        role: GameRuntimeRole::NeoforgeDerivedClient,
        path: NEOFORGE_DERIVED_CLIENT_PATH,
        size: 5_673_824,
        sha1: "e0f4fc5d1ba94c4de11a296f835010e8e7b1a9b9",
        sha256: "4a36fc577de9408288e3641c68298279a30da731876c4a66fe1d6041602c2c5d",
        launch_required: true,
    },
];
const NEOFORGE_PROCESSOR_TRANSIENT_OUTPUTS: [TransientOutputSpec; 2] = [
    TransientOutputSpec {
        path: "libraries/net/minecraft/client/1.21.1-20240808.144430/client-1.21.1-20240808.144430-slim.jar.cache",
        size: 142,
        sha1: "c137e1f836d8023803505b6277e1978f5dc2d437",
        sha256: "f1720f546fb6ac1bc213573a80ec3ae8396849e62b0756e809cde4a0e12d6c03",
    },
    TransientOutputSpec {
        path: "libraries/net/minecraft/client/1.21.1-20240808.144430/client-1.21.1-20240808.144430-extra.jar.cache",
        size: 142,
        sha1: "8198c7d8b601f0ff562ba94d313f8d9d2014ddca",
        sha256: "0bb7f64bf320554c5e049e8053f5852e794f265cedfdeffa7019115dcaec9b7e",
    },
];
const NEOFORGE_MODULE_PATHS: [&str; 8] = [
    "libraries/cpw/mods/bootstraplauncher/2.0.2/bootstraplauncher-2.0.2.jar",
    "libraries/cpw/mods/securejarhandler/3.0.8/securejarhandler-3.0.8.jar",
    "libraries/org/ow2/asm/asm-commons/9.8/asm-commons-9.8.jar",
    "libraries/org/ow2/asm/asm-util/9.8/asm-util-9.8.jar",
    "libraries/org/ow2/asm/asm-analysis/9.8/asm-analysis-9.8.jar",
    "libraries/org/ow2/asm/asm-tree/9.8/asm-tree-9.8.jar",
    "libraries/org/ow2/asm/asm/9.8/asm-9.8.jar",
    "libraries/net/neoforged/JarJarFileSystems/0.4.1/JarJarFileSystems-0.4.1.jar",
];
const MINECRAFT_NEOFORGE_WINDOWS_LIBRARY_COUNT: usize = 106;
const MINECRAFT_NEOFORGE_RUNTIME_LIBRARY_COUNT: usize = 82;
const MINECRAFT_NEOFORGE_NATIVE_LIBRARY_COUNT: usize = 24;
const NEOFORGE_INSTALLER_ONLY_LIBRARY_COUNT: usize = 21;
const MINECRAFT_NEOFORGE_OFFICIAL_FILE_COUNT: usize = 4_022;
const MINECRAFT_NEOFORGE_OFFICIAL_BYTES: u64 = 951_471_493;
const NEOFORGE_DERIVED_OUTPUT_BYTES: u64 = 62_474_478;
const MINECRAFT_NEOFORGE_GAME_RUNTIME_FILE_COUNT: usize = 4_028;
const MINECRAFT_NEOFORGE_GAME_RUNTIME_BYTES: u64 = 1_013_945_971;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeLock {
    pub schema_version: u8,
    pub id: String,
    pub platform: String,
    pub java: RuntimeJava,
    pub minecraft: RuntimeMinecraft,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeJava {
    pub major: u8,
    pub architecture: String,
    pub distribution: String,
    pub image_type: String,
    pub vm: String,
    pub version: String,
    pub vendor: String,
    pub license: RuntimeLicense,
    pub archive: RuntimeArchive,
    pub executable: String,
    pub console_executable: String,
    pub files: Vec<RuntimeFile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeLicense {
    pub spdx: String,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeArchive {
    pub url: String,
    pub checksum_url: String,
    pub signature_url: String,
    pub signing_key_fingerprint: String,
    pub size: u64,
    pub sha256: String,
    pub format: String,
    pub strip_prefix: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeMinecraft {
    pub version: String,
    pub version_manifest_url: String,
    pub version_json_url: String,
    pub version_json_sha1: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GameRuntimeLock {
    pub schema_version: u8,
    pub id: String,
    pub platform: GameRuntimePlatform,
    pub identity: GameRuntimeIdentity,
    pub provenance: GameRuntimeProvenance,
    pub verification: GameRuntimeVerification,
    pub files: Vec<GameRuntimeFile>,
    pub launch: GameRuntimeLaunch,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GameRuntimePlatform {
    pub os: String,
    pub architecture: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GameRuntimeIdentity {
    pub kind: String,
    pub nickname_source: String,
    pub uuid_source: String,
    pub access_token: String,
    pub user_type: String,
    pub client_id: String,
    pub xuid: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GameRuntimeProvenance {
    pub resolver: GameRuntimeResolverProvenance,
    pub minecraft_version_json: GameOfficialArtifact,
    pub minecraft_client_mappings: GameOfficialArtifact,
    pub neo_forge_installer: GameOfficialArtifact,
    pub install_profile: EmbeddedInstallerEntry,
    pub neo_forge_version_json: NeoForgeVersionEntry,
    pub client_patch: EmbeddedInstallerEntry,
    pub processor_plans: GameRuntimeProcessorPlans,
    pub derived_outputs: Vec<GameDerivedOutputProvenance>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GameOfficialArtifact {
    pub kind: String,
    pub url: String,
    pub size: u64,
    pub sha1: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmbeddedInstallerEntry {
    pub entry: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NeoForgeVersionEntry {
    pub entry: String,
    pub size: u64,
    pub sha256: String,
    pub disposition: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GameRuntimeResolverProvenance {
    pub kind: String,
    pub profile: String,
    pub algorithm: String,
    pub resolver_artifact_sha256: String,
    pub inputs_sha256: String,
    pub graph_sha256: String,
    pub asset_graph_sha256: String,
    pub runtime_library_graph_sha256: String,
    pub installer_input_graph_sha256: String,
    pub download_graph_sha256: String,
    pub launch_sha256: String,
    pub upstream_plan_sha256: String,
    pub translation_sha256: String,
    pub executable_plan_sha256: String,
    pub materialization_graph_sha256: String,
    pub metadata_declaration_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GameRuntimeGraphFingerprints {
    inputs_sha256: String,
    graph_sha256: String,
    asset_graph_sha256: String,
    runtime_library_graph_sha256: String,
    installer_input_graph_sha256: String,
    download_graph_sha256: String,
    launch_sha256: String,
    upstream_plan_sha256: String,
    translation_sha256: String,
    executable_plan_sha256: String,
    materialization_graph_sha256: String,
    metadata_declaration_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessorInputStateEntry {
    path: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeTreeEntry {
    path: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GameRuntimeProcessorPlans {
    pub upstream: UpstreamProcessorPlan,
    pub translation: ProcessorTranslation,
    pub executable: ExecutableProcessorPlan,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpstreamProcessorPlan {
    pub kind: String,
    pub steps: Vec<UpstreamProcessorStep>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpstreamProcessorStep {
    pub upstream_index: u8,
    pub id: String,
    pub jar_path: String,
    pub main_class: String,
    pub classpath: Vec<String>,
    pub arguments: Vec<NormalizedProcessorArgument>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum NormalizedProcessorArgument {
    Literal {
        value: String,
    },
    Path {
        path: String,
    },
    Input {
        input: ProcessorInput,
    },
    Materialization {
        materialization: ProcessorMaterializationId,
        access: ProcessorMaterializationAccess,
    },
    Output {
        output_kind: GameDerivedOutputKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessorInput {
    MinecraftClient,
    MinecraftClientMappings,
    ClientPatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessorMaterializationId {
    MinecraftClientMappings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessorMaterializationAccess {
    Read,
    Write,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessorTranslation {
    pub kind: String,
    pub network_policy: String,
    pub rules: [ProcessorTranslationRule; 6],
    pub materializations: [ProcessorMaterialization; 1],
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "action",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProcessorTranslationRule {
    Execute {
        upstream_index: u8,
    },
    SubstitutedByVerifiedInput {
        upstream_index: u8,
        materialization: ProcessorMaterializationId,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessorMaterialization {
    pub id: ProcessorMaterializationId,
    pub path: String,
    pub source: GameOfficialArtifact,
    pub access: String,
    pub verify_after_execution: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutableProcessorPlan {
    pub kind: String,
    pub network_requirement: String,
    pub steps: Vec<ExecutableProcessorReference>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutableProcessorReference {
    pub execution_index: u8,
    pub upstream_index: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GameProcessorOutput {
    pub path: String,
    pub size: u64,
    pub sha1: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GameDerivedOutputProvenance {
    pub path: String,
    pub size: u64,
    pub sha1: String,
    pub sha256: String,
    pub launch_required: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GameRuntimeVerification {
    pub offline_processors: OfflineProcessorVerification,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "status",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum OfflineProcessorVerification {
    Pending {
        recipe: String,
        required_runs: u8,
        network_requirement: String,
        network_isolation: String,
        java: PendingProcessorJava,
        upstream_plan_sha256: String,
        translation_sha256: String,
        executable_plan_sha256: String,
        materialization_graph_sha256: String,
        expected_outputs: Vec<GameProcessorOutput>,
    },
    Verified {
        schema_version: u8,
        kind: String,
        recipe: String,
        graph_sha256: String,
        resolver_artifact_sha256: String,
        executor_artifact_sha256: String,
        upstream_plan_sha256: String,
        translation_sha256: String,
        executable_plan_sha256: String,
        materialization_graph_sha256: String,
        java: VerifiedProcessorJava,
        isolation: ProcessorIsolation,
        runs: Box<[VerifiedProcessorRun; 2]>,
        consensus_outputs: Vec<GameProcessorOutput>,
        receipt_sha256: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingProcessorJava {
    pub distribution: String,
    pub version: String,
    pub platform: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedProcessorJava {
    pub runtime_lock_sha256: String,
    pub archive_sha256: String,
    pub extracted_tree_sha256: String,
    pub version: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessorIsolation {
    pub network_requirement: String,
    pub network_isolation: String,
    pub workspaces: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedProcessorRun {
    pub ordinal: u8,
    pub work_root_identity_sha256: String,
    pub inputs_before_sha256: String,
    pub inputs_after_sha256: String,
    pub mappings_before: ProcessorArtifactState,
    pub mappings_after: ProcessorArtifactState,
    pub steps: Vec<VerifiedProcessorStep>,
    pub write_set: Vec<String>,
    pub write_set_sha256: String,
    pub outputs: Vec<GameProcessorOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessorArtifactState {
    pub path: String,
    pub size: u64,
    pub sha1: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedProcessorStep {
    pub execution_index: u8,
    pub upstream_index: u8,
    pub exit_code: i32,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub transcript_sha256: String,
    pub written_paths: Vec<String>,
    pub removed_transient_artifacts: Vec<ProcessorArtifactState>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GameRuntimeFile {
    pub path: String,
    pub role: GameRuntimeRole,
    pub source: GameRuntimeSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GameRuntimeRole {
    MinecraftVersionJson,
    MinecraftClient,
    MinecraftAssetIndex,
    MinecraftAsset,
    MinecraftLoggingConfig,
    MinecraftClientMappings,
    Library,
    NativeLibrary,
    NeoforgeInstaller,
    NeoforgeInstallerLibrary,
    NeoforgeUniversal,
    NeoforgeDerivedMappings,
    NeoforgeDerivedMergedMappings,
    NeoforgeDerivedClientSlim,
    NeoforgeDerivedClientExtra,
    NeoforgeDerivedClientSrg,
    NeoforgeDerivedClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GameDerivedOutputKind {
    NeoformMappings,
    MergedMappings,
    ClientSlim,
    ClientExtra,
    ClientSrg,
    PatchedClient,
}

#[derive(Debug, Clone, Copy)]
struct DerivedOutputSpec {
    output_kind: GameDerivedOutputKind,
    role: GameRuntimeRole,
    path: &'static str,
    size: u64,
    sha1: &'static str,
    sha256: &'static str,
    launch_required: bool,
}

#[derive(Debug, Clone, Copy)]
struct TransientOutputSpec {
    path: &'static str,
    size: u64,
    sha1: &'static str,
    sha256: &'static str,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GameRuntimeSource {
    Official {
        url: String,
        size: u64,
        sha1: String,
        sha256: String,
    },
    Derived {
        recipe: String,
        output_kind: GameDerivedOutputKind,
        launch_required: bool,
        size: u64,
        sha1: String,
        sha256: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GameRuntimeLaunch {
    pub main_class: String,
    pub version_name: String,
    pub version_type: String,
    pub asset_index_name: String,
    pub classpath: Vec<String>,
    pub module_path: Vec<String>,
    pub jvm_arguments: Vec<GameLaunchArgument>,
    pub game_arguments: Vec<GameLaunchArgument>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum GameLaunchArgument {
    Literal { value: String },
    Template { fragments: Vec<GameLaunchFragment> },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum GameLaunchFragment {
    Literal { value: String },
    Placeholder { name: GameLaunchPlaceholder },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum GameLaunchPlaceholder {
    FragmentNickname,
    FragmentUuid,
    GameDirectory,
    AssetsRoot,
    AssetsIndexName,
    VersionName,
    LibrariesDirectory,
    NativesDirectory,
    LoggingConfigPath,
    Classpath,
    ModulePath,
    LauncherName,
    LauncherVersion,
    OfflineAccessToken,
    OfflineUserType,
    OfflineClientId,
    OfflineXuid,
    VersionType,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutableSettingsFile {
    pub path: String,
    pub validator: MutableValidator,
    pub max_bytes: usize,
    pub unknown_key_policy: String,
    pub duplicate_key_policy: String,
    pub invalid_value_policy: String,
    pub fields: Vec<MutableSettingField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum MutableValidator {
    #[serde(rename = "minecraft-options-v1")]
    MinecraftOptionsV1,
    #[serde(rename = "structured-properties-v1")]
    StructuredPropertiesV1,
    #[serde(rename = "structured-json-v1")]
    StructuredJsonV1,
    #[serde(rename = "structured-toml-v1")]
    StructuredTomlV1,
    #[serde(rename = "shader-options-v1")]
    ShaderOptionsV1,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MutableSettingField {
    pub setting_id: String,
    pub scope: SettingScope,
    pub selector: SettingSelector,
    pub value: SettingValueRule,
    #[serde(default)]
    pub renamed_from: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SettingScope {
    Profile,
    Preset,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum SettingSelector {
    Exact { key: String },
    Prefix { prefix: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
pub enum SettingValueRule {
    Boolean,
    Integer {
        minimum: i64,
        maximum: i64,
    },
    Number {
        minimum: f64,
        maximum: f64,
    },
    String {
        max_length: usize,
        #[serde(default)]
        allowed_values: Option<Vec<String>>,
        #[serde(default)]
        allowed_prefixes: Option<Vec<String>>,
    },
}

impl RuntimeLock {
    pub fn parse_and_validate(bytes: &[u8]) -> Result<Self, String> {
        let lock: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("Runtime lock JSON is invalid: {error}"))?;
        lock.validate()?;
        Ok(lock)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.platform != "windows-x64"
            || self.java.major != JAVA_MAJOR
            || self.java.architecture != "x64"
            || self.java.distribution != JAVA_DISTRIBUTION
            || self.java.image_type != JAVA_IMAGE_TYPE
            || self.java.vm != JAVA_VM
            || !self.java.version.starts_with("25.")
        {
            return Err("Unsupported managed Java runtime identity".into());
        }
        if !valid_java25_version(&self.java.version)
            || self.id != format!("temurin-jre-{}-windows-x64-hotspot", self.java.version)
        {
            return Err("Managed Java version identity is invalid".into());
        }
        if self.java.vendor != "Eclipse Temurin"
            || self.java.license.spdx != "GPL-2.0-only WITH Classpath-exception-2.0"
            || self.java.license.url != "https://openjdk.org/legal/gplv2+ce.html"
            || self.java.archive.format != "zip"
            || self.java.archive.signing_key_fingerprint
                != "3B04D753C9050D9A5D343F39843C48A565F8F04B"
            || !self
                .java
                .archive
                .url
                .starts_with("https://github.com/adoptium/temurin25-binaries/releases/download/")
            || !self
                .java
                .archive
                .checksum_url
                .starts_with("https://github.com/adoptium/temurin25-binaries/releases/download/")
            || !self.java.archive.checksum_url.ends_with(".sha256.txt")
            || !self
                .java
                .archive
                .signature_url
                .starts_with("https://github.com/adoptium/temurin25-binaries/releases/download/")
            || !self.java.archive.signature_url.ends_with(".sig")
            || !is_sha256(&self.java.archive.sha256)
            || self.java.archive.size == 0
        {
            return Err("Managed Java archive identity is invalid".into());
        }
        validate_manifest_path(&self.java.archive.strip_prefix)?;
        validate_manifest_path(&self.java.executable)?;
        validate_manifest_path(&self.java.console_executable)?;

        let mut paths = HashSet::new();
        for file in &self.java.files {
            validate_manifest_path(&file.path)?;
            if !is_sha256(&file.sha256) {
                return Err(format!("Invalid runtime file SHA-256: {}", file.path));
            }
            let key = file.path.to_lowercase();
            if !paths.insert(key) {
                return Err(format!("Duplicate runtime path: {}", file.path));
            }
        }
        for path in &paths {
            let segments: Vec<_> = path.split('/').collect();
            for index in 1..segments.len() {
                if paths.contains(&segments[..index].join("/")) {
                    return Err(format!("Runtime file/directory collision: {path}"));
                }
            }
        }
        for executable in [&self.java.executable, &self.java.console_executable] {
            if !self
                .java
                .files
                .iter()
                .any(|file| file.path.eq_ignore_ascii_case(executable))
            {
                return Err(format!("Runtime entrypoint is missing: {executable}"));
            }
        }
        if self.minecraft.version != "1.21.1"
            || !self
                .minecraft
                .version_manifest_url
                .starts_with("https://piston-meta.mojang.com/")
            || !self
                .minecraft
                .version_json_url
                .starts_with("https://piston-meta.mojang.com/")
            || !is_lower_hex(&self.minecraft.version_json_sha1, 40)
        {
            return Err("Minecraft runtime identity is invalid".into());
        }
        Ok(())
    }

    pub fn extracted_tree_sha256(&self) -> Result<String, String> {
        self.validate()?;
        let mut files = self
            .java
            .files
            .iter()
            .map(|file| RuntimeTreeEntry {
                path: file.path.clone(),
                size: file.size,
                sha256: file.sha256.clone(),
            })
            .collect::<Vec<_>>();
        files.sort_by(|left, right| left.path.cmp(&right.path));
        domain_digest("ru.fragmc.spark2.java.extracted-tree.v1", &files)
    }
}

impl GameRuntimeLock {
    pub fn parse_and_validate(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_GAME_RUNTIME_LOCK_BYTES {
            return Err("Game runtime lock exceeds the launcher limit".into());
        }
        let lock: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("Game runtime lock JSON is invalid: {error}"))?;
        lock.validate()?;
        Ok(lock)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.id != GAME_RUNTIME_ID
            || self.platform.os != "windows"
            || self.platform.architecture != "x64"
        {
            return Err("Game runtime identity is invalid or unsupported".into());
        }
        if self.identity.kind != "fragment-custom-offline-v1"
            || self.identity.nickname_source != "fragment-admission"
            || self.identity.uuid_source != "fragment-admission"
            || self.identity.access_token != "0"
            || self.identity.user_type != "legacy"
            || !self.identity.client_id.is_empty()
            || !self.identity.xuid.is_empty()
        {
            return Err("Game runtime requires the Fragment custom/offline identity".into());
        }
        self.validate_provenance()?;
        let files = self.validate_files()?;
        self.provenance.processor_plans.validate(&files)?;
        self.validate_launch(&files)?;
        let fingerprints = self.compute_graph_fingerprints()?;
        let expected_processor_input_state_sha256 =
            self.compute_expected_processor_input_state_sha256()?;
        self.provenance.resolver.validate(&fingerprints)?;
        self.verification.offline_processors.validate(
            &fingerprints,
            &self.provenance.resolver.resolver_artifact_sha256,
            &expected_processor_input_state_sha256,
        )
    }

    fn compute_expected_processor_input_state_sha256(&self) -> Result<String, String> {
        let upstream_by_index = self
            .provenance
            .processor_plans
            .upstream
            .steps
            .iter()
            .map(|step| (step.upstream_index, step))
            .collect::<HashMap<_, _>>();
        let mut required_paths = HashSet::from([NEOFORGE_INSTALLER_PATH.to_owned()]);
        for reference in &self.provenance.processor_plans.executable.steps {
            let step = upstream_by_index
                .get(&reference.upstream_index)
                .ok_or_else(|| {
                    format!(
                        "Executable processor input step is missing: {}",
                        reference.upstream_index
                    )
                })?;
            required_paths.insert(step.jar_path.clone());
            required_paths.extend(step.classpath.iter().cloned());
            for argument in &step.arguments {
                match argument {
                    NormalizedProcessorArgument::Path { path } => {
                        required_paths.insert(path.clone());
                    }
                    NormalizedProcessorArgument::Input {
                        input: ProcessorInput::MinecraftClient,
                    } => {
                        required_paths.insert(MINECRAFT_CLIENT_PATH.to_owned());
                    }
                    NormalizedProcessorArgument::Input {
                        input: ProcessorInput::MinecraftClientMappings,
                    }
                    | NormalizedProcessorArgument::Materialization {
                        materialization: ProcessorMaterializationId::MinecraftClientMappings,
                        ..
                    } => {
                        required_paths.insert(MINECRAFT_CLIENT_MAPPINGS_PATH.to_owned());
                    }
                    NormalizedProcessorArgument::Literal { .. }
                    | NormalizedProcessorArgument::Input {
                        input: ProcessorInput::ClientPatch,
                    }
                    | NormalizedProcessorArgument::Output { .. } => {}
                }
            }
        }

        let official_by_path = self
            .files
            .iter()
            .filter(|file| matches!(&file.source, GameRuntimeSource::Official { .. }))
            .map(|file| (file.path.to_lowercase(), file))
            .collect::<HashMap<_, _>>();
        let mut state = required_paths
            .into_iter()
            .map(|path| {
                let file = official_by_path.get(&path.to_lowercase()).ok_or_else(|| {
                    format!(
                        "Processor input is not exactly bound to an official runtime file: {path}"
                    )
                })?;
                let GameRuntimeSource::Official { size, sha256, .. } = &file.source else {
                    return Err(format!(
                        "Processor input is not exactly bound to an official runtime file: {path}"
                    ));
                };
                if file.path != path {
                    return Err(format!(
                        "Processor input is not exactly bound to an official runtime file: {path}"
                    ));
                }
                Ok(ProcessorInputStateEntry {
                    path,
                    size: *size,
                    sha256: sha256.clone(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        state.push(ProcessorInputStateEntry {
            path: NEOFORGE_CLIENT_PATCH_MATERIALIZED_PATH.to_owned(),
            size: self.provenance.client_patch.size,
            sha256: self.provenance.client_patch.sha256.clone(),
        });
        state.sort_by(|left, right| left.path.cmp(&right.path));
        domain_digest(PROCESSOR_INPUT_STATE_DOMAIN, &state)
    }

    fn validate_provenance(&self) -> Result<(), String> {
        let provenance = &self.provenance;
        validate_official_artifact(&provenance.minecraft_version_json)?;
        validate_official_artifact(&provenance.minecraft_client_mappings)?;
        validate_official_artifact(&provenance.neo_forge_installer)?;
        if provenance.minecraft_version_json.kind != "official"
            || provenance.minecraft_version_json.url != MINECRAFT_VERSION_JSON_URL
            || provenance.minecraft_version_json.size != MINECRAFT_VERSION_JSON_SIZE
            || provenance.minecraft_version_json.sha1 != MINECRAFT_VERSION_JSON_SHA1
            || provenance.minecraft_version_json.sha256 != MINECRAFT_VERSION_JSON_SHA256
        {
            return Err("Minecraft version metadata provenance is invalid".into());
        }
        if provenance.neo_forge_installer.kind != "official"
            || provenance.neo_forge_installer.url != NEOFORGE_INSTALLER_URL
            || provenance.neo_forge_installer.size != NEOFORGE_INSTALLER_SIZE
            || provenance.neo_forge_installer.sha1 != NEOFORGE_INSTALLER_SHA1
            || provenance.neo_forge_installer.sha256 != NEOFORGE_INSTALLER_SHA256
        {
            return Err("NeoForge installer provenance is invalid".into());
        }
        if provenance.minecraft_client_mappings.kind != "official"
            || provenance.minecraft_client_mappings.url != MINECRAFT_CLIENT_MAPPINGS_URL
            || provenance.minecraft_client_mappings.size != MINECRAFT_CLIENT_MAPPINGS_SIZE
            || provenance.minecraft_client_mappings.sha1 != MINECRAFT_CLIENT_MAPPINGS_SHA1
            || provenance.minecraft_client_mappings.sha256 != MINECRAFT_CLIENT_MAPPINGS_SHA256
        {
            return Err("Minecraft client mappings provenance is invalid".into());
        }
        validate_embedded_entry(
            &provenance.install_profile,
            "install_profile.json",
            130_522,
            NEOFORGE_INSTALL_PROFILE_SHA256,
        )?;
        validate_game_runtime_path(&provenance.neo_forge_version_json.entry)?;
        if provenance.neo_forge_version_json.entry != "version.json"
            || provenance.neo_forge_version_json.size != 21_148
            || provenance.neo_forge_version_json.sha256 != NEOFORGE_VERSION_JSON_SHA256
            || provenance.neo_forge_version_json.disposition != "embedded-launch-metadata-only"
        {
            return Err("NeoForge embedded version metadata provenance is invalid".into());
        }
        validate_embedded_entry(
            &provenance.client_patch,
            "data/client.lzma",
            3_239_759,
            NEOFORGE_CLIENT_PATCH_SHA256,
        )?;
        if provenance.derived_outputs != expected_derived_output_provenance() {
            return Err("Signed derived output provenance is not the pinned six-output set".into());
        }
        Ok(())
    }

    fn validate_files(&self) -> Result<HashMap<String, &GameRuntimeFile>, String> {
        if self.files.is_empty() || self.files.len() > MAX_GAME_RUNTIME_FILES {
            return Err("Game runtime file count is invalid".into());
        }
        if self
            .files
            .windows(2)
            .any(|pair| pair[0].path >= pair[1].path)
        {
            return Err("Game runtime files must be strictly ASCII path-sorted".into());
        }

        let mut by_path = HashMap::with_capacity(self.files.len());
        let mut total_size = 0_u64;
        let mut sizes_by_sha256 = HashMap::new();
        let mut official_by_sha1: HashMap<String, (u64, String)> = HashMap::new();
        let mut official_sha1_by_sha256: HashMap<String, String> = HashMap::new();
        let mut official_count = 0_usize;
        let mut official_bytes = 0_u64;
        let mut derived_count = 0_usize;
        let mut derived_bytes = 0_u64;
        for file in &self.files {
            validate_game_runtime_file_path(&file.path)?;
            let key = file.path.to_lowercase();
            if by_path.insert(key.clone(), file).is_some() {
                return Err(format!("Duplicate game runtime path: {}", file.path));
            }
            let expected_derived = derived_output_spec(file.role);
            let size = match &file.source {
                GameRuntimeSource::Official {
                    url,
                    size,
                    sha1,
                    sha256,
                } => {
                    if expected_derived.is_some()
                        || validate_official_game_source(url, sha1).is_err()
                        || *size == 0
                        || *size > MAX_GAME_RUNTIME_FILE_SIZE
                        || !is_sha256(sha256)
                    {
                        return Err(format!(
                            "Invalid official game runtime source: {}",
                            file.path
                        ));
                    }
                    if official_by_sha1
                        .insert(sha1.clone(), (*size, sha256.clone()))
                        .is_some_and(|previous| previous != (*size, sha256.clone()))
                    {
                        return Err(format!(
                            "Official game runtime SHA-1 has conflicting metadata: {sha1}"
                        ));
                    }
                    if official_sha1_by_sha256
                        .insert(sha256.clone(), sha1.clone())
                        .is_some_and(|previous| previous != sha1.as_str())
                    {
                        return Err(format!(
                            "Official game runtime SHA-256 has conflicting SHA-1: {sha256}"
                        ));
                    }
                    official_count += 1;
                    official_bytes = official_bytes
                        .checked_add(*size)
                        .ok_or_else(|| "Official game runtime size overflow".to_string())?;
                    *size
                }
                GameRuntimeSource::Derived {
                    recipe,
                    output_kind,
                    launch_required,
                    size,
                    sha1,
                    sha256,
                } => {
                    let Some(expected) = expected_derived else {
                        return Err(format!(
                            "Derived source is forbidden for role {}",
                            game_runtime_role_name(file.role)
                        ));
                    };
                    if recipe != PROCESSOR_RECIPE
                        || *size == 0
                        || *size > MAX_GAME_RUNTIME_FILE_SIZE
                        || !is_lower_hex(sha1, 40)
                        || !is_sha256(sha256)
                        || file.path != expected.path
                        || *output_kind != expected.output_kind
                        || *launch_required != expected.launch_required
                        || *size != expected.size
                        || sha1 != expected.sha1
                        || sha256 != expected.sha256
                    {
                        return Err(format!(
                            "Invalid derived game runtime source: {}",
                            file.path
                        ));
                    }
                    derived_count += 1;
                    derived_bytes = derived_bytes
                        .checked_add(*size)
                        .ok_or_else(|| "Derived game runtime size overflow".to_string())?;
                    *size
                }
            };
            validate_game_file_destination(file)?;
            total_size = total_size
                .checked_add(size)
                .ok_or_else(|| "Game runtime total size overflow".to_string())?;
            if total_size > MAX_GAME_RUNTIME_TOTAL_SIZE {
                return Err("Game runtime total size exceeds the launcher limit".into());
            }
            let sha256 = match &file.source {
                GameRuntimeSource::Official { sha256, .. }
                | GameRuntimeSource::Derived { sha256, .. } => sha256,
            };
            if sizes_by_sha256
                .insert(sha256.clone(), size)
                .is_some_and(|previous| previous != size)
            {
                return Err(format!(
                    "Game runtime SHA-256 has conflicting sizes: {sha256}"
                ));
            }
        }

        if self.files.len() != MINECRAFT_NEOFORGE_GAME_RUNTIME_FILE_COUNT
            || total_size != MINECRAFT_NEOFORGE_GAME_RUNTIME_BYTES
            || official_count != MINECRAFT_NEOFORGE_OFFICIAL_FILE_COUNT
            || official_bytes != MINECRAFT_NEOFORGE_OFFICIAL_BYTES
            || derived_count != NEOFORGE_DERIVED_OUTPUTS.len()
            || derived_bytes != NEOFORGE_DERIVED_OUTPUT_BYTES
        {
            return Err(
                "Game runtime declaration counts/bytes do not match the pinned graph".into(),
            );
        }

        for path in by_path.keys() {
            let segments: Vec<_> = path.split('/').collect();
            for index in 1..segments.len() {
                if by_path.contains_key(&segments[..index].join("/")) {
                    return Err(format!("Game runtime file/directory collision: {path}"));
                }
            }
        }

        self.validate_required_files()?;
        Ok(by_path)
    }

    fn validate_required_files(&self) -> Result<(), String> {
        for role in [
            GameRuntimeRole::MinecraftClient,
            GameRuntimeRole::MinecraftAssetIndex,
            GameRuntimeRole::MinecraftLoggingConfig,
            GameRuntimeRole::MinecraftClientMappings,
            GameRuntimeRole::NeoforgeUniversal,
        ] {
            if self.files.iter().filter(|file| file.role == role).count() != 1 {
                return Err(format!(
                    "Game runtime requires exactly one {}",
                    game_runtime_role_name(role)
                ));
            }
        }
        for role in [
            GameRuntimeRole::MinecraftAsset,
            GameRuntimeRole::Library,
            GameRuntimeRole::NativeLibrary,
            GameRuntimeRole::NeoforgeInstallerLibrary,
        ] {
            if !self.files.iter().any(|file| file.role == role) {
                return Err(format!(
                    "Game runtime requires at least one {}",
                    game_runtime_role_name(role)
                ));
            }
        }

        let assets: Vec<_> = self
            .files
            .iter()
            .filter(|file| file.role == GameRuntimeRole::MinecraftAsset)
            .collect();
        let asset_bytes = assets.iter().try_fold(0_u64, |total, file| {
            let size = match &file.source {
                GameRuntimeSource::Official { size, .. }
                | GameRuntimeSource::Derived { size, .. } => *size,
            };
            total.checked_add(size)
        });
        if assets.len() != MINECRAFT_ASSET_OBJECT_COUNT
            || asset_bytes != Some(MINECRAFT_ASSET_OBJECT_BYTES)
        {
            return Err("Minecraft asset graph count or size is invalid".into());
        }
        let merged_library_count = self
            .files
            .iter()
            .filter(|file| {
                matches!(
                    file.role,
                    GameRuntimeRole::Library | GameRuntimeRole::NativeLibrary
                )
            })
            .count();
        if merged_library_count != MINECRAFT_NEOFORGE_WINDOWS_LIBRARY_COUNT {
            return Err("Windows game runtime library graph count is invalid".into());
        }
        for (role, expected) in [
            (
                GameRuntimeRole::Library,
                MINECRAFT_NEOFORGE_RUNTIME_LIBRARY_COUNT,
            ),
            (
                GameRuntimeRole::NativeLibrary,
                MINECRAFT_NEOFORGE_NATIVE_LIBRARY_COUNT,
            ),
            (
                GameRuntimeRole::NeoforgeInstallerLibrary,
                NEOFORGE_INSTALLER_ONLY_LIBRARY_COUNT,
            ),
        ] {
            if self.files.iter().filter(|file| file.role == role).count() != expected {
                return Err(format!(
                    "Game runtime {} count is invalid",
                    game_runtime_role_name(role)
                ));
            }
        }

        let version_files: Vec<_> = self
            .files
            .iter()
            .filter(|file| file.role == GameRuntimeRole::MinecraftVersionJson)
            .collect();
        if version_files.len() != 1
            || version_files[0].path != "versions/1.21.1/1.21.1.json"
            || !official_source_matches(
                &version_files[0].source,
                &self.provenance.minecraft_version_json,
            )
        {
            return Err("Game runtime must contain the pinned Minecraft version JSON".into());
        }

        let pinned_roles = [
            (
                GameRuntimeRole::MinecraftClient,
                MINECRAFT_CLIENT_PATH,
                MINECRAFT_CLIENT_URL,
                MINECRAFT_CLIENT_SIZE,
                MINECRAFT_CLIENT_SHA1,
                MINECRAFT_CLIENT_SHA256,
            ),
            (
                GameRuntimeRole::MinecraftAssetIndex,
                "assets/indexes/17.json",
                MINECRAFT_ASSET_INDEX_URL,
                MINECRAFT_ASSET_INDEX_SIZE,
                MINECRAFT_ASSET_INDEX_SHA1,
                MINECRAFT_ASSET_INDEX_SHA256,
            ),
            (
                GameRuntimeRole::MinecraftLoggingConfig,
                "assets/log_configs/client-1.12.xml",
                MINECRAFT_LOGGING_CONFIG_URL,
                MINECRAFT_LOGGING_CONFIG_SIZE,
                MINECRAFT_LOGGING_CONFIG_SHA1,
                MINECRAFT_LOGGING_CONFIG_SHA256,
            ),
            (
                GameRuntimeRole::MinecraftClientMappings,
                MINECRAFT_CLIENT_MAPPINGS_PATH,
                MINECRAFT_CLIENT_MAPPINGS_URL,
                MINECRAFT_CLIENT_MAPPINGS_SIZE,
                MINECRAFT_CLIENT_MAPPINGS_SHA1,
                MINECRAFT_CLIENT_MAPPINGS_SHA256,
            ),
            (
                GameRuntimeRole::NeoforgeUniversal,
                "libraries/net/neoforged/neoforge/21.1.235/neoforge-21.1.235-universal.jar",
                NEOFORGE_UNIVERSAL_URL,
                NEOFORGE_UNIVERSAL_SIZE,
                NEOFORGE_UNIVERSAL_SHA1,
                NEOFORGE_UNIVERSAL_SHA256,
            ),
        ];
        for (role, path, url, size, sha1, sha256) in pinned_roles {
            let files: Vec<_> = self.files.iter().filter(|file| file.role == role).collect();
            if files.len() != 1
                || files[0].path != path
                || !official_source_is_exact(&files[0].source, url, size, sha1, sha256)
            {
                return Err(format!(
                    "Game runtime pinned {} is invalid",
                    game_runtime_role_name(role)
                ));
            }
        }

        let installers: Vec<_> = self
            .files
            .iter()
            .filter(|file| file.role == GameRuntimeRole::NeoforgeInstaller)
            .collect();
        if installers.len() != 1
            || installers[0].path != NEOFORGE_INSTALLER_PATH
            || !official_source_matches(&installers[0].source, &self.provenance.neo_forge_installer)
        {
            return Err("Game runtime must contain the pinned NeoForge installer".into());
        }

        for expected in NEOFORGE_DERIVED_OUTPUTS {
            if self
                .files
                .iter()
                .filter(|file| file.role == expected.role)
                .count()
                != 1
            {
                return Err(format!(
                    "Game runtime requires exactly one {}",
                    game_runtime_role_name(expected.role)
                ));
            }
        }

        for asset in self
            .files
            .iter()
            .filter(|file| file.role == GameRuntimeRole::MinecraftAsset)
        {
            let GameRuntimeSource::Official { sha1, .. } = &asset.source else {
                return Err("Minecraft asset must use an official source".into());
            };
            if asset.path != format!("assets/objects/{}/{}", &sha1[..2], sha1) {
                return Err(format!(
                    "Minecraft asset path does not match SHA-1: {}",
                    asset.path
                ));
            }
        }
        Ok(())
    }

    fn validate_launch(&self, files: &HashMap<String, &GameRuntimeFile>) -> Result<(), String> {
        let launch = &self.launch;
        if launch.main_class != GAME_MAIN_CLASS
            || launch.version_name != GAME_VERSION_NAME
            || launch.version_type != "release"
            || launch.asset_index_name != GAME_ASSET_INDEX_NAME
            || launch.classpath.is_empty()
            || launch.classpath.len() > 1024
            || launch.module_path.len() > 1024
            || launch.jvm_arguments.is_empty()
            || launch.jvm_arguments.len() > 256
            || launch.game_arguments.is_empty()
            || launch.game_arguments.len() > 256
        {
            return Err("Game runtime launch identity or bounds are invalid".into());
        }
        validate_launch_paths(&launch.classpath, files, "classpath")?;
        validate_launch_paths(&launch.module_path, files, "module path")?;
        validate_critical_classpath_roles(&launch.classpath, files)?;
        if launch.module_path.len() != NEOFORGE_MODULE_PATHS.len()
            || launch
                .module_path
                .iter()
                .map(String::as_str)
                .ne(NEOFORGE_MODULE_PATHS)
        {
            return Err("NeoForge module path does not match pinned version metadata".into());
        }
        for argument in launch.jvm_arguments.iter().chain(&launch.game_arguments) {
            validate_launch_argument(argument)?;
        }

        validate_required_launch_pair(
            &launch.jvm_arguments,
            "-cp",
            LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::Classpath),
        )?;
        validate_required_template_argument(
            &launch.jvm_arguments,
            "-Djava.library.path=",
            GameLaunchPlaceholder::NativesDirectory,
        )?;
        for prefix in [
            "-Djna.tmpdir=",
            "-Dorg.lwjgl.system.SharedLibraryExtractPath=",
            "-Dio.netty.native.workdir=",
        ] {
            validate_required_template_argument(
                &launch.jvm_arguments,
                prefix,
                GameLaunchPlaceholder::NativesDirectory,
            )?;
        }
        validate_required_template_argument(
            &launch.jvm_arguments,
            "-Dlog4j.configurationFile=",
            GameLaunchPlaceholder::LoggingConfigPath,
        )?;
        for (prefix, placeholder) in [
            (
                "-Dminecraft.launcher.brand=",
                GameLaunchPlaceholder::LauncherName,
            ),
            (
                "-Dminecraft.launcher.version=",
                GameLaunchPlaceholder::LauncherVersion,
            ),
            (
                "-DlibraryDirectory=",
                GameLaunchPlaceholder::LibrariesDirectory,
            ),
        ] {
            validate_required_template_argument(&launch.jvm_arguments, prefix, placeholder)?;
        }
        validate_required_wrapped_template_argument(
            &launch.jvm_arguments,
            "-DignoreList=client-extra,",
            GameLaunchPlaceholder::VersionName,
            ".jar",
        )?;
        validate_required_launch_pair(
            &launch.jvm_arguments,
            "-p",
            LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::ModulePath),
        )?;
        validate_required_literal_argument(
            &launch.jvm_arguments,
            "-Djava.net.preferIPv6Addresses=system",
        )?;
        for (flag, value) in [
            ("--add-modules", "ALL-MODULE-PATH"),
            (
                "--add-opens",
                "java.base/java.util.jar=cpw.mods.securejarhandler",
            ),
            (
                "--add-opens",
                "java.base/java.lang.invoke=cpw.mods.securejarhandler",
            ),
            (
                "--add-exports",
                "java.base/sun.security.util=cpw.mods.securejarhandler",
            ),
            (
                "--add-exports",
                "jdk.naming.dns/com.sun.jndi.dns=java.naming",
            ),
        ] {
            validate_required_adjacent_literal_pair(&launch.jvm_arguments, flag, value)?;
        }
        validate_forbidden_jvm_arguments(&launch.jvm_arguments)?;
        validate_protected_jvm_argument_counts(&launch.jvm_arguments)?;
        validate_exact_jvm_arguments(&launch.jvm_arguments)?;

        let required_game_pairs = [
            (
                "--username",
                LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::FragmentNickname),
            ),
            (
                "--uuid",
                LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::FragmentUuid),
            ),
            (
                "--accessToken",
                LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::OfflineAccessToken),
            ),
            (
                "--userType",
                LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::OfflineUserType),
            ),
            (
                "--clientId",
                LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::OfflineClientId),
            ),
            (
                "--xuid",
                LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::OfflineXuid),
            ),
            (
                "--version",
                LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::VersionName),
            ),
            (
                "--versionType",
                LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::VersionType),
            ),
            (
                "--gameDir",
                LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::GameDirectory),
            ),
            (
                "--assetsDir",
                LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::AssetsRoot),
            ),
            (
                "--assetIndex",
                LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::AssetsIndexName),
            ),
            (
                "--launchTarget",
                LaunchValueExpectation::Literal("forgeclient"),
            ),
            (
                "--fml.neoForgeVersion",
                LaunchValueExpectation::Literal("21.1.235"),
            ),
            (
                "--fml.fmlVersion",
                LaunchValueExpectation::Literal("4.0.42"),
            ),
            ("--fml.mcVersion", LaunchValueExpectation::Literal("1.21.1")),
            (
                "--fml.neoFormVersion",
                LaunchValueExpectation::Literal("20240808.144430"),
            ),
        ];
        for (flag, expectation) in required_game_pairs {
            validate_required_launch_pair(&launch.game_arguments, flag, expectation)?;
        }
        validate_exact_game_arguments(&launch.game_arguments)?;

        for placeholder in [
            GameLaunchPlaceholder::Classpath,
            GameLaunchPlaceholder::ModulePath,
            GameLaunchPlaceholder::NativesDirectory,
            GameLaunchPlaceholder::LoggingConfigPath,
            GameLaunchPlaceholder::LibrariesDirectory,
            GameLaunchPlaceholder::LauncherName,
            GameLaunchPlaceholder::LauncherVersion,
        ] {
            require_placeholder_count(&launch.game_arguments, placeholder, 0, "game arguments")?;
        }
        for placeholder in [
            GameLaunchPlaceholder::FragmentNickname,
            GameLaunchPlaceholder::FragmentUuid,
            GameLaunchPlaceholder::OfflineAccessToken,
            GameLaunchPlaceholder::OfflineUserType,
            GameLaunchPlaceholder::OfflineClientId,
            GameLaunchPlaceholder::OfflineXuid,
            GameLaunchPlaceholder::VersionName,
            GameLaunchPlaceholder::VersionType,
            GameLaunchPlaceholder::GameDirectory,
            GameLaunchPlaceholder::AssetsRoot,
            GameLaunchPlaceholder::AssetsIndexName,
        ] {
            require_placeholder_count(&launch.game_arguments, placeholder, 1, "game arguments")?;
        }
        for placeholder in [
            GameLaunchPlaceholder::FragmentNickname,
            GameLaunchPlaceholder::FragmentUuid,
            GameLaunchPlaceholder::OfflineAccessToken,
            GameLaunchPlaceholder::OfflineUserType,
            GameLaunchPlaceholder::OfflineClientId,
            GameLaunchPlaceholder::OfflineXuid,
        ] {
            require_placeholder_count(&launch.jvm_arguments, placeholder, 0, "JVM arguments")?;
        }
        require_placeholder_count(
            &launch.jvm_arguments,
            GameLaunchPlaceholder::Classpath,
            1,
            "JVM arguments",
        )?;
        require_placeholder_count(
            &launch.jvm_arguments,
            GameLaunchPlaceholder::NativesDirectory,
            4,
            "JVM arguments",
        )?;
        require_placeholder_count(
            &launch.jvm_arguments,
            GameLaunchPlaceholder::LibrariesDirectory,
            1,
            "JVM arguments",
        )?;
        require_placeholder_count(
            &launch.jvm_arguments,
            GameLaunchPlaceholder::LauncherName,
            1,
            "JVM arguments",
        )?;
        require_placeholder_count(
            &launch.jvm_arguments,
            GameLaunchPlaceholder::LauncherVersion,
            1,
            "JVM arguments",
        )?;
        require_placeholder_count(
            &launch.jvm_arguments,
            GameLaunchPlaceholder::VersionName,
            1,
            "JVM arguments",
        )?;
        require_placeholder_count(
            &launch.jvm_arguments,
            GameLaunchPlaceholder::LoggingConfigPath,
            1,
            "JVM arguments",
        )?;
        require_placeholder_count(
            &launch.jvm_arguments,
            GameLaunchPlaceholder::ModulePath,
            usize::from(!launch.module_path.is_empty()),
            "JVM arguments",
        )?;
        Ok(())
    }
}

impl GameRuntimeResolverProvenance {
    fn validate(&self, expected: &GameRuntimeGraphFingerprints) -> Result<(), String> {
        if self.kind != "fragment-spark2-game-runtime-resolver-v1"
            || self.profile != GAME_RUNTIME_ID
            || self.algorithm != "minecraft-neoforge-windows-x64-graph-v1"
            || !is_sha256(&self.resolver_artifact_sha256)
            || self.inputs_sha256 != expected.inputs_sha256
            || self.graph_sha256 != expected.graph_sha256
            || self.asset_graph_sha256 != expected.asset_graph_sha256
            || self.runtime_library_graph_sha256 != expected.runtime_library_graph_sha256
            || self.installer_input_graph_sha256 != expected.installer_input_graph_sha256
            || self.download_graph_sha256 != expected.download_graph_sha256
            || self.launch_sha256 != expected.launch_sha256
            || self.upstream_plan_sha256 != expected.upstream_plan_sha256
            || self.translation_sha256 != expected.translation_sha256
            || self.executable_plan_sha256 != expected.executable_plan_sha256
            || self.materialization_graph_sha256 != expected.materialization_graph_sha256
            || self.metadata_declaration_sha256 != expected.metadata_declaration_sha256
        {
            return Err("Game runtime resolver fingerprint mismatch".into());
        }
        Ok(())
    }
}

impl GameRuntimeLock {
    fn compute_graph_fingerprints(&self) -> Result<GameRuntimeGraphFingerprints, String> {
        let mut files = self.files.iter().collect::<Vec<_>>();
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let projected_files = files
            .iter()
            .map(|file| project_game_runtime_file(file))
            .collect::<Result<Vec<_>, _>>()?;
        let by_roles = |roles: &[GameRuntimeRole]| {
            files
                .iter()
                .filter(|file| roles.contains(&file.role))
                .map(|file| project_game_runtime_file(file))
                .collect::<Result<Vec<_>, _>>()
        };
        let provenance = serde_json::json!({
            "minecraftVersionJson": &self.provenance.minecraft_version_json,
            "minecraftClientMappings": &self.provenance.minecraft_client_mappings,
            "neoForgeInstaller": &self.provenance.neo_forge_installer,
            "installProfile": &self.provenance.install_profile,
            "neoForgeVersionJson": &self.provenance.neo_forge_version_json,
            "clientPatch": &self.provenance.client_patch,
            "processorPlans": &self.provenance.processor_plans,
            "derivedOutputs": &self.provenance.derived_outputs,
        });
        let upstream_plan_sha256 = domain_digest(
            "ru.fragmc.spark2.neoforge.upstream-plan.v1",
            &self.provenance.processor_plans.upstream,
        )?;
        let translation_sha256 = domain_digest(
            "ru.fragmc.spark2.neoforge.translation.v1",
            &self.provenance.processor_plans.translation,
        )?;
        let executable_plan_sha256 = domain_digest(
            "ru.fragmc.spark2.neoforge.executable-plan.v2",
            &self.provenance.processor_plans.executable,
        )?;
        let materialization_graph_sha256 = domain_digest(
            "ru.fragmc.spark2.neoforge.materializations.v1",
            &self.provenance.processor_plans.translation.materializations,
        )?;
        for (actual, expected, label) in [
            (
                upstream_plan_sha256.as_str(),
                NEOFORGE_UPSTREAM_PLAN_SHA256,
                "upstream processor plan",
            ),
            (
                translation_sha256.as_str(),
                NEOFORGE_TRANSLATION_SHA256,
                "processor translation",
            ),
            (
                executable_plan_sha256.as_str(),
                NEOFORGE_EXECUTABLE_PLAN_SHA256,
                "executable processor plan",
            ),
            (
                materialization_graph_sha256.as_str(),
                NEOFORGE_MATERIALIZATION_GRAPH_SHA256,
                "processor materialization graph",
            ),
        ] {
            if actual != expected {
                return Err(format!("Pinned {label} digest is invalid"));
            }
        }

        Ok(GameRuntimeGraphFingerprints {
            inputs_sha256: expected_game_runtime_inputs_sha256()?,
            graph_sha256: domain_digest(
                "ru.fragmc.spark2.game-runtime.graph.v1",
                &serde_json::json!({
                    "schemaVersion": self.schema_version,
                    "id": &self.id,
                    "platform": &self.platform,
                    "identity": &self.identity,
                    "provenance": &provenance,
                    "files": &projected_files,
                    "launch": &self.launch,
                }),
            )?,
            asset_graph_sha256: domain_digest(
                "ru.fragmc.spark2.game-runtime.assets.v1",
                &by_roles(&[
                    GameRuntimeRole::MinecraftAsset,
                    GameRuntimeRole::MinecraftAssetIndex,
                ])?,
            )?,
            runtime_library_graph_sha256: domain_digest(
                "ru.fragmc.spark2.game-runtime.libraries.v1",
                &by_roles(&[
                    GameRuntimeRole::Library,
                    GameRuntimeRole::NativeLibrary,
                    GameRuntimeRole::NeoforgeUniversal,
                ])?,
            )?,
            installer_input_graph_sha256: domain_digest(
                "ru.fragmc.spark2.game-runtime.installer-inputs.v1",
                &by_roles(&[
                    GameRuntimeRole::NeoforgeInstaller,
                    GameRuntimeRole::NeoforgeInstallerLibrary,
                    GameRuntimeRole::MinecraftClientMappings,
                ])?,
            )?,
            download_graph_sha256: domain_digest(
                "ru.fragmc.spark2.game-runtime.downloads.v1",
                &projected_files,
            )?,
            launch_sha256: domain_digest("ru.fragmc.spark2.game-runtime.launch.v1", &self.launch)?,
            upstream_plan_sha256: upstream_plan_sha256.clone(),
            translation_sha256: translation_sha256.clone(),
            executable_plan_sha256: executable_plan_sha256.clone(),
            materialization_graph_sha256: materialization_graph_sha256.clone(),
            metadata_declaration_sha256: domain_digest(
                "ru.fragmc.spark2.game-runtime.metadata-declaration.v1",
                &serde_json::json!({
                    "schemaVersion": self.schema_version,
                    "id": &self.id,
                    "files": &projected_files,
                    "launch": &self.launch,
                    "processorPlans": &self.provenance.processor_plans,
                    "upstreamPlanSha256": upstream_plan_sha256,
                    "translationSha256": translation_sha256,
                    "executablePlanSha256": executable_plan_sha256,
                    "materializationGraphSha256": materialization_graph_sha256,
                    "stats": {
                        "logicalAssetCount": MINECRAFT_ASSET_LOGICAL_COUNT,
                        "uniqueAssetCount": MINECRAFT_ASSET_OBJECT_COUNT,
                        "uniqueAssetBytes": MINECRAFT_ASSET_OBJECT_BYTES,
                        "runtimeLibraryCount": MINECRAFT_NEOFORGE_RUNTIME_LIBRARY_COUNT,
                        "nativeLibraryCount": MINECRAFT_NEOFORGE_NATIVE_LIBRARY_COUNT,
                        "installerOnlyLibraryCount": NEOFORGE_INSTALLER_ONLY_LIBRARY_COUNT,
                        "officialFileCount": MINECRAFT_NEOFORGE_OFFICIAL_FILE_COUNT,
                        "derivedFileCount": NEOFORGE_DERIVED_OUTPUTS.len(),
                        "totalFileCount": MINECRAFT_NEOFORGE_GAME_RUNTIME_FILE_COUNT,
                        "officialBytes": MINECRAFT_NEOFORGE_OFFICIAL_BYTES,
                        "derivedBytes": NEOFORGE_DERIVED_OUTPUT_BYTES,
                    },
                }),
            )?,
        })
    }
}

impl GameRuntimeProcessorPlans {
    fn validate(&self, files: &HashMap<String, &GameRuntimeFile>) -> Result<(), String> {
        if self.upstream.kind != "neoforge-install-profile-client-v1"
            || self.upstream.steps.len() != UPSTREAM_PROCESSOR_INDICES.len()
        {
            return Err("NeoForge upstream processor plan is invalid".into());
        }
        let mut output_kinds = HashSet::new();
        for (position, step) in self.upstream.steps.iter().enumerate() {
            if step.upstream_index != UPSTREAM_PROCESSOR_INDICES[position]
                || !valid_processor_id(&step.id)
                || !valid_processor_main_class(&step.main_class)
                || step.classpath.is_empty()
                || step.classpath.len() > 64
                || step.arguments.is_empty()
                || step.arguments.len() > 64
            {
                return Err("NeoForge upstream processor step is invalid".into());
            }
            require_processor_library(files, &step.jar_path)?;
            let mut classpath = HashSet::new();
            for path in &step.classpath {
                require_processor_library(files, path)?;
                if !classpath.insert(path.to_lowercase()) {
                    return Err("NeoForge processor classpath contains duplicates".into());
                }
            }
            let tool_occurrences = step
                .classpath
                .iter()
                .filter(|path| path.eq_ignore_ascii_case(&step.jar_path))
                .count();
            if step.classpath.first() != Some(&step.jar_path) || tool_occurrences != 1 {
                return Err(
                    "NeoForge processor classpath must contain its tool exactly once first".into(),
                );
            }
            for argument in &step.arguments {
                match argument {
                    NormalizedProcessorArgument::Literal { value } => {
                        validate_launch_literal(value, true)?;
                    }
                    NormalizedProcessorArgument::Path { path } => {
                        require_processor_library(files, path)?;
                    }
                    NormalizedProcessorArgument::Input { .. }
                    | NormalizedProcessorArgument::Materialization { .. } => {}
                    NormalizedProcessorArgument::Output { output_kind } => {
                        output_kinds.insert(*output_kind);
                    }
                }
            }
        }
        if NEOFORGE_DERIVED_OUTPUTS
            .iter()
            .any(|output| !output_kinds.contains(&output.output_kind))
        {
            return Err("NeoForge upstream processor plan omits a derived output".into());
        }
        let download_mojmaps = &self.upstream.steps[1];
        let mapping_writes = download_mojmaps
            .arguments
            .iter()
            .filter(|argument| {
                matches!(
                    argument,
                    NormalizedProcessorArgument::Materialization {
                        materialization: ProcessorMaterializationId::MinecraftClientMappings,
                        access: ProcessorMaterializationAccess::Write,
                    }
                )
            })
            .count();
        if download_mojmaps.id != "DOWNLOAD_MOJMAPS" || mapping_writes != 1 {
            return Err("DOWNLOAD_MOJMAPS materialization contract is invalid".into());
        }

        if self.translation.kind != "spark2-neoforge-offline-translation-v1"
            || self.translation.network_policy != "networked-step-substituted"
        {
            return Err("NeoForge processor translation identity is invalid".into());
        }
        for (position, rule) in self.translation.rules.iter().enumerate() {
            match (position, rule) {
                (
                    1,
                    ProcessorTranslationRule::SubstitutedByVerifiedInput {
                        upstream_index: 4,
                        materialization: ProcessorMaterializationId::MinecraftClientMappings,
                    },
                ) => {}
                (_, ProcessorTranslationRule::Execute { upstream_index })
                    if *upstream_index == UPSTREAM_PROCESSOR_INDICES[position]
                        && *upstream_index != 4 => {}
                _ => return Err("NeoForge processor translation rule sequence is invalid".into()),
            }
        }
        let materialization = &self.translation.materializations[0];
        if materialization.id != ProcessorMaterializationId::MinecraftClientMappings
            || materialization.path != MINECRAFT_CLIENT_MAPPINGS_PATH
            || materialization.access != "read-only"
            || !materialization.verify_after_execution
            || !official_artifact_is_exact(
                &materialization.source,
                MINECRAFT_CLIENT_MAPPINGS_URL,
                MINECRAFT_CLIENT_MAPPINGS_SIZE,
                MINECRAFT_CLIENT_MAPPINGS_SHA1,
                MINECRAFT_CLIENT_MAPPINGS_SHA256,
            )
        {
            return Err("NeoForge mapping materialization is invalid".into());
        }
        let mappings = files
            .get(&MINECRAFT_CLIENT_MAPPINGS_PATH.to_lowercase())
            .ok_or_else(|| "Processor mapping materialization file is missing".to_string())?;
        if mappings.role != GameRuntimeRole::MinecraftClientMappings
            || !official_source_matches(&mappings.source, &materialization.source)
        {
            return Err("Processor mapping materialization is not bound to its file".into());
        }

        if self.executable.kind != "spark2-neoforge-client-offline-v2"
            || self.executable.network_requirement != "no-network-required"
            || self.executable.steps.len() != EXECUTABLE_PROCESSOR_INDICES.len()
            || self
                .executable
                .steps
                .iter()
                .enumerate()
                .any(|(index, step)| {
                    step.execution_index != index as u8
                        || step.upstream_index != EXECUTABLE_PROCESSOR_INDICES[index]
                })
        {
            return Err("NeoForge executable processor plan is invalid".into());
        }
        Ok(())
    }
}

impl OfflineProcessorVerification {
    fn validate(
        &self,
        expected: &GameRuntimeGraphFingerprints,
        resolver_artifact_sha256: &str,
        expected_input_state_sha256: &str,
    ) -> Result<(), String> {
        let expected_outputs = expected_processor_outputs();
        let expected_write_set = NEOFORGE_DERIVED_OUTPUTS
            .iter()
            .map(|output| output.path.to_owned())
            .collect::<Vec<_>>();
        let expected_write_set_sha256 = domain_digest(
            "ru.fragmc.spark2.neoforge.write-set.v1",
            &expected_write_set,
        )?;
        let expected_step_writes = [
            vec![NEOFORGE_DERIVED_OUTPUTS[0].path.to_owned()],
            vec![NEOFORGE_DERIVED_OUTPUTS[1].path.to_owned()],
            vec![
                NEOFORGE_DERIVED_OUTPUTS[2].path.to_owned(),
                NEOFORGE_PROCESSOR_TRANSIENT_OUTPUTS[0].path.to_owned(),
                NEOFORGE_DERIVED_OUTPUTS[3].path.to_owned(),
                NEOFORGE_PROCESSOR_TRANSIENT_OUTPUTS[1].path.to_owned(),
            ],
            vec![NEOFORGE_DERIVED_OUTPUTS[4].path.to_owned()],
            vec![NEOFORGE_DERIVED_OUTPUTS[5].path.to_owned()],
        ];
        let expected_transient_artifacts = expected_transient_artifact_states();
        let expected_removed_transient_artifacts =
            [vec![], vec![], expected_transient_artifacts, vec![], vec![]];
        match self {
            Self::Pending {
                recipe,
                required_runs,
                network_requirement,
                network_isolation,
                java,
                upstream_plan_sha256,
                translation_sha256,
                executable_plan_sha256,
                materialization_graph_sha256,
                expected_outputs: actual_outputs,
            } => {
                if recipe != PROCESSOR_RECIPE
                    || *required_runs != 2
                    || network_requirement != "no-network-required"
                    || network_isolation != "not-os-enforced"
                    || java.distribution != JAVA_DISTRIBUTION
                    || java.version != "25.0.3+9"
                    || java.platform != "windows-x64"
                    || upstream_plan_sha256 != &expected.upstream_plan_sha256
                    || translation_sha256 != &expected.translation_sha256
                    || executable_plan_sha256 != &expected.executable_plan_sha256
                    || materialization_graph_sha256 != &expected.materialization_graph_sha256
                    || actual_outputs != &expected_outputs
                {
                    return Err("Pending NeoForge processor verification is invalid".into());
                }
            }
            Self::Verified {
                schema_version,
                kind,
                recipe,
                graph_sha256,
                resolver_artifact_sha256: receipt_resolver_artifact_sha256,
                executor_artifact_sha256,
                upstream_plan_sha256,
                translation_sha256,
                executable_plan_sha256,
                materialization_graph_sha256,
                java,
                isolation,
                runs,
                consensus_outputs,
                receipt_sha256,
            } => {
                if *schema_version != 2
                    || kind != "spark2-neoforge-offline-processors-v2"
                    || recipe != PROCESSOR_RECIPE
                    || graph_sha256 != &expected.graph_sha256
                    || receipt_resolver_artifact_sha256 != resolver_artifact_sha256
                    || !is_sha256(executor_artifact_sha256)
                    || upstream_plan_sha256 != &expected.upstream_plan_sha256
                    || translation_sha256 != &expected.translation_sha256
                    || executable_plan_sha256 != &expected.executable_plan_sha256
                    || materialization_graph_sha256 != &expected.materialization_graph_sha256
                    || !is_sha256(&java.runtime_lock_sha256)
                    || !is_sha256(&java.archive_sha256)
                    || !is_sha256(&java.extracted_tree_sha256)
                    || java.version != "25.0.3+9"
                    || isolation.network_requirement != "no-network-required"
                    || isolation.network_isolation != "not-os-enforced"
                    || isolation.workspaces != "two-distinct-fresh"
                    || consensus_outputs != &expected_outputs
                    || !is_sha256(receipt_sha256)
                {
                    return Err("Verified NeoForge processor receipt is invalid".into());
                }
                if runs[0].work_root_identity_sha256 == runs[1].work_root_identity_sha256 {
                    return Err("NeoForge processor work roots are not distinct".into());
                }
                for (index, run) in runs.iter().enumerate() {
                    if run.ordinal != (index + 1) as u8
                        || !is_sha256(&run.work_root_identity_sha256)
                        || !is_sha256(&run.inputs_before_sha256)
                        || !is_sha256(&run.inputs_after_sha256)
                        || run.inputs_before_sha256 != expected_input_state_sha256
                        || run.inputs_after_sha256 != expected_input_state_sha256
                        || run.mappings_before != run.mappings_after
                        || run.steps.len() != 5
                        || run.write_set != expected_write_set
                        || run.write_set_sha256 != expected_write_set_sha256
                        || run.outputs.as_slice() != consensus_outputs.as_slice()
                    {
                        return Err("NeoForge processor runs disagree with consensus".into());
                    }
                    validate_processor_artifact_state(&run.mappings_before)?;
                    for (step_index, step) in run.steps.iter().enumerate() {
                        let expected_transcript_sha256 =
                            expected_processor_transcript_sha256(step)?;
                        if step.execution_index != step_index as u8
                            || step.upstream_index != EXECUTABLE_PROCESSOR_INDICES[step_index]
                            || step.exit_code != 0
                            || step.stdout_bytes > MAX_SAFE_JSON_INTEGER
                            || step.stderr_bytes > MAX_SAFE_JSON_INTEGER
                            || !is_sha256(&step.stdout_sha256)
                            || !is_sha256(&step.stderr_sha256)
                            || !is_sha256(&step.transcript_sha256)
                            || step.transcript_sha256 != expected_transcript_sha256
                            || step.written_paths.is_empty()
                            || step.written_paths.len() > 4
                            || step.written_paths != expected_step_writes[step_index]
                            || step.removed_transient_artifacts.len() > 2
                            || step.removed_transient_artifacts
                                != expected_removed_transient_artifacts[step_index]
                        {
                            return Err("NeoForge processor receipt step is invalid".into());
                        }
                        for path in &step.written_paths {
                            validate_game_runtime_file_path(path)?;
                        }
                        for artifact in &step.removed_transient_artifacts {
                            validate_game_runtime_file_path(&artifact.path)?;
                        }
                    }
                    for path in &run.write_set {
                        validate_game_runtime_file_path(path)?;
                    }
                }
                let mut receipt = serde_json::to_value(self)
                    .map_err(|error| format!("Cannot serialize processor receipt: {error}"))?;
                let serde_json::Value::Object(fields) = &mut receipt else {
                    return Err("Processor receipt serialization is invalid".into());
                };
                fields.remove("receiptSha256");
                let actual =
                    domain_digest("ru.fragmc.spark2.neoforge.offline-receipt.v2", &receipt)?;
                if &actual != receipt_sha256 {
                    return Err("NeoForge processor receipt self-digest is invalid".into());
                }
            }
        }
        Ok(())
    }

    pub fn bind_java_runtime(
        &self,
        runtime_lock_sha256: &str,
        archive_sha256: &str,
        extracted_tree_sha256: &str,
        version: &str,
    ) -> Result<(), String> {
        match self {
            Self::Verified { java, .. }
                if java.runtime_lock_sha256 == runtime_lock_sha256
                    && java.archive_sha256 == archive_sha256
                    && java.extracted_tree_sha256 == extracted_tree_sha256
                    && java.version == version =>
            {
                Ok(())
            }
            Self::Pending { .. } => {
                Err("Pending NeoForge processor verification is forbidden in a release".into())
            }
            _ => Err("NeoForge processor verification does not match managed Java".into()),
        }
    }
}

impl MutableSettingsFile {
    pub fn validate(&self) -> Result<(), String> {
        validate_manifest_path(&self.path)?;
        let lower = self.path.to_lowercase();
        if lower == "mods"
            || lower.starts_with("mods/")
            || lower == "resourcepacks"
            || lower.starts_with("resourcepacks/")
        {
            return Err("Mutable settings are forbidden under mods/resourcepacks".into());
        }
        if self.max_bytes < 64 || self.max_bytes > 1024 * 1024 {
            return Err("Mutable settings maxBytes is invalid".into());
        }
        if self.unknown_key_policy != "drop"
            || self.duplicate_key_policy != "reject"
            || self.invalid_value_policy != "use-default"
        {
            return Err("Unsupported mutable settings behavior".into());
        }
        if self.validator != MutableValidator::MinecraftOptionsV1 {
            return Err("Mutable validator is not implemented by this launcher".into());
        }
        if !self.path.eq_ignore_ascii_case("options.txt") {
            return Err("minecraft-options-v1 is valid only for options.txt".into());
        }
        if self.fields.is_empty() || self.fields.len() > 512 {
            return Err("Mutable settings field count is invalid".into());
        }

        let mut identities = HashSet::new();
        for field in &self.fields {
            if !valid_setting_id(&field.setting_id) || !identities.insert(&field.setting_id) {
                return Err(format!(
                    "Duplicate or invalid settingId: {}",
                    field.setting_id
                ));
            }
            for old_id in &field.renamed_from {
                if !valid_setting_id(old_id) || !identities.insert(old_id) {
                    return Err(format!("Duplicate or invalid renamed settingId: {old_id}"));
                }
            }
            if field.renamed_from.len() > 16 {
                return Err("Too many renamed mutable setting IDs".into());
            }
            match &field.selector {
                SettingSelector::Exact { key } if !valid_setting_string(key, 256, true) => {
                    return Err("Invalid exact mutable setting selector".into());
                }
                SettingSelector::Prefix { prefix } if !valid_setting_string(prefix, 256, true) => {
                    return Err("Invalid prefix mutable setting selector".into());
                }
                _ => {}
            }
            validate_rule(&field.value)?;
        }
        for left in 0..self.fields.len() {
            for right in left + 1..self.fields.len() {
                if selectors_overlap(&self.fields[left].selector, &self.fields[right].selector) {
                    return Err("Mutable setting selectors overlap".into());
                }
            }
        }
        Ok(())
    }
}

pub(super) fn validate_manifest_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.contains('\\')
        || path.starts_with('/')
        || path == "."
        || path.starts_with("../")
        || path.contains("/../")
        || path.nfc().collect::<String>() != path
    {
        return Err(format!("Unsafe manifest path: {path}"));
    }
    for segment in path.split('/') {
        let lower = segment.to_ascii_lowercase();
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.ends_with('.')
            || segment.ends_with(' ')
            || segment
                .chars()
                .any(|value| value.is_control() || "<>:\"|?*".contains(value))
            || is_reserved_windows_name(&lower)
        {
            return Err(format!("Unsafe manifest path: {path}"));
        }
    }
    Ok(())
}

fn validate_game_runtime_path(path: &str) -> Result<(), String> {
    validate_manifest_path(path)?;
    if path.len() > 1024 || path.split('/').any(|segment| segment.len() > 255) {
        return Err(format!("Game runtime path exceeds UTF-8 bounds: {path}"));
    }
    Ok(())
}

fn validate_game_runtime_file_path(path: &str) -> Result<(), String> {
    validate_game_runtime_path(path)?;
    if !matches!(
        path.split('/').next(),
        Some("assets" | "libraries" | "versions" | "installers")
    ) || path.split('/').any(|segment| {
        !segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+~-".contains(&byte))
            || segment.to_ascii_lowercase().starts_with(".fragment")
    }) {
        return Err(format!(
            "Game runtime file path is outside managed roots: {path}"
        ));
    }
    Ok(())
}

fn validate_official_artifact(artifact: &GameOfficialArtifact) -> Result<(), String> {
    if artifact.kind != "official"
        || artifact.size == 0
        || artifact.size > MAX_GAME_RUNTIME_FILE_SIZE
        || !is_sha256(&artifact.sha256)
        || validate_official_game_source(&artifact.url, &artifact.sha1).is_err()
    {
        return Err("Official game artifact provenance is invalid".into());
    }
    Ok(())
}

fn validate_embedded_entry(
    entry: &EmbeddedInstallerEntry,
    expected_path: &str,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(), String> {
    validate_game_runtime_path(&entry.entry)?;
    if entry.entry != expected_path
        || entry.size != expected_size
        || entry.sha256 != expected_sha256
    {
        return Err(format!(
            "NeoForge embedded entry is invalid: {}",
            entry.entry
        ));
    }
    Ok(())
}

fn official_source_matches(source: &GameRuntimeSource, artifact: &GameOfficialArtifact) -> bool {
    matches!(
        source,
        GameRuntimeSource::Official {
            url,
            size,
            sha1,
            sha256,
        } if url == &artifact.url
            && *size == artifact.size
            && sha1 == &artifact.sha1
            && sha256 == &artifact.sha256
    )
}

fn official_source_is_exact(
    source: &GameRuntimeSource,
    expected_url: &str,
    expected_size: u64,
    expected_sha1: &str,
    expected_sha256: &str,
) -> bool {
    matches!(
        source,
        GameRuntimeSource::Official {
            url,
            size,
            sha1,
            sha256,
        } if url == expected_url
            && *size == expected_size
            && sha1 == expected_sha1
            && sha256 == expected_sha256
    )
}

fn validate_launch_paths(
    paths: &[String],
    files: &HashMap<String, &GameRuntimeFile>,
    label: &str,
) -> Result<(), String> {
    let mut seen = HashSet::with_capacity(paths.len());
    for path in paths {
        validate_game_runtime_file_path(path)?;
        let key = path.to_lowercase();
        if !seen.insert(key.clone()) {
            return Err(format!("Duplicate game runtime {label} entry: {path}"));
        }
        if !files.contains_key(&key) {
            return Err(format!("Game runtime {label} entry is undeclared: {path}"));
        }
        if !matches!(
            files[&key].role,
            GameRuntimeRole::MinecraftClient
                | GameRuntimeRole::Library
                | GameRuntimeRole::NativeLibrary
        ) {
            return Err(format!(
                "Game runtime {label} contains a non-loadable role: {path}"
            ));
        }
    }
    Ok(())
}

fn validate_game_file_destination(file: &GameRuntimeFile) -> Result<(), String> {
    let GameRuntimeSource::Official { url, .. } = &file.source else {
        return Ok(());
    };
    let parsed = Url::parse(url).map_err(|_| "Official game source URL is invalid".to_string())?;
    let host = parsed.host_str().unwrap_or_default();
    let expected_host = match file.role {
        GameRuntimeRole::MinecraftVersionJson | GameRuntimeRole::MinecraftAssetIndex => {
            Some("piston-meta.mojang.com")
        }
        GameRuntimeRole::MinecraftClient
        | GameRuntimeRole::MinecraftLoggingConfig
        | GameRuntimeRole::MinecraftClientMappings => Some("piston-data.mojang.com"),
        GameRuntimeRole::MinecraftAsset => Some("resources.download.minecraft.net"),
        GameRuntimeRole::NeoforgeInstaller | GameRuntimeRole::NeoforgeUniversal => {
            Some("maven.neoforged.net")
        }
        _ => None,
    };
    if expected_host.is_some_and(|expected| host != expected) {
        return Err(format!(
            "Game runtime {} uses a forbidden official origin",
            file.path
        ));
    }
    if matches!(
        file.role,
        GameRuntimeRole::Library
            | GameRuntimeRole::NativeLibrary
            | GameRuntimeRole::NeoforgeInstallerLibrary
    ) && !matches!(host, "libraries.minecraft.net" | "maven.neoforged.net")
    {
        return Err(format!(
            "Game runtime library uses a forbidden official origin: {}",
            file.path
        ));
    }

    let expected_path = if matches!(
        file.role,
        GameRuntimeRole::Library
            | GameRuntimeRole::NativeLibrary
            | GameRuntimeRole::NeoforgeInstallerLibrary
    ) && host == "libraries.minecraft.net"
    {
        Some(format!("libraries{}", parsed.path()))
    } else if matches!(
        file.role,
        GameRuntimeRole::Library
            | GameRuntimeRole::NativeLibrary
            | GameRuntimeRole::NeoforgeInstallerLibrary
            | GameRuntimeRole::NeoforgeUniversal
    ) && host == "maven.neoforged.net"
    {
        parsed
            .path()
            .strip_prefix("/releases/")
            .map(|path| format!("libraries/{path}"))
    } else {
        None
    };
    if expected_path
        .as_deref()
        .is_some_and(|path| file.path != path)
    {
        return Err(format!(
            "Game runtime destination does not match its official URL: {}",
            file.path
        ));
    }
    let is_windows_native = [
        "-natives-windows.jar",
        "-natives-windows-arm64.jar",
        "-natives-windows-x86.jar",
    ]
    .iter()
    .any(|suffix| file.path.ends_with(suffix));
    if file.role == GameRuntimeRole::NativeLibrary && !is_windows_native {
        return Err(format!(
            "Native game runtime role has a non-native path: {}",
            file.path
        ));
    }
    if file.role == GameRuntimeRole::Library && is_windows_native {
        return Err(format!(
            "Game runtime library hides a native path: {}",
            file.path
        ));
    }
    Ok(())
}

fn validate_critical_classpath_roles(
    classpath: &[String],
    files: &HashMap<String, &GameRuntimeFile>,
) -> Result<(), String> {
    let roles: HashSet<_> = classpath
        .iter()
        .filter_map(|path| files.get(&path.to_lowercase()).map(|file| file.role))
        .collect();
    for role in [
        GameRuntimeRole::MinecraftClient,
        GameRuntimeRole::Library,
        GameRuntimeRole::NativeLibrary,
    ] {
        if !roles.contains(&role) {
            return Err(format!(
                "Game runtime classpath is missing critical role {}",
                game_runtime_role_name(role)
            ));
        }
    }
    let classpath: HashSet<_> = classpath.iter().map(|path| path.to_lowercase()).collect();
    for file in files.values() {
        if matches!(
            file.role,
            GameRuntimeRole::MinecraftClient
                | GameRuntimeRole::Library
                | GameRuntimeRole::NativeLibrary
        ) && !classpath.contains(&file.path.to_lowercase())
        {
            return Err(format!(
                "Game runtime classpath omits runtime file {}",
                file.path
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum LaunchValueExpectation<'a> {
    Literal(&'a str),
    Placeholder(GameLaunchPlaceholder),
}

fn validate_required_launch_pair(
    arguments: &[GameLaunchArgument],
    flag: &str,
    expected: LaunchValueExpectation<'_>,
) -> Result<(), String> {
    let positions: Vec<_> = arguments
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| {
            matches!(argument, GameLaunchArgument::Literal { value } if value == flag)
                .then_some(index)
        })
        .collect();
    if positions.len() != 1 {
        return Err(format!(
            "Game launch arguments require exactly one {flag} flag"
        ));
    }
    if !arguments
        .get(positions[0] + 1)
        .is_some_and(|argument| matches_launch_value(argument, expected))
    {
        return Err(format!(
            "Game launch flag {flag} is not followed by its required typed value"
        ));
    }
    Ok(())
}

fn matches_launch_value(
    argument: &GameLaunchArgument,
    expected: LaunchValueExpectation<'_>,
) -> bool {
    match expected {
        LaunchValueExpectation::Literal(expected) => {
            matches!(argument, GameLaunchArgument::Literal { value } if value == expected)
        }
        LaunchValueExpectation::Placeholder(expected) => matches!(
            argument,
            GameLaunchArgument::Template { fragments }
                if matches!(fragments.as_slice(), [GameLaunchFragment::Placeholder { name }] if *name == expected)
        ),
    }
}

fn validate_required_template_argument(
    arguments: &[GameLaunchArgument],
    literal_prefix: &str,
    placeholder: GameLaunchPlaceholder,
) -> Result<(), String> {
    let matches = arguments
        .iter()
        .filter(|argument| {
            matches!(
                argument,
                GameLaunchArgument::Template { fragments }
                    if matches!(
                        fragments.as_slice(),
                        [
                            GameLaunchFragment::Literal { value },
                            GameLaunchFragment::Placeholder { name }
                        ] if value == literal_prefix && *name == placeholder
                    )
            )
        })
        .count();
    if matches != 1 {
        return Err(format!(
            "Game JVM arguments require exactly one {literal_prefix}<{}> template",
            placeholder_name(placeholder)
        ));
    }
    Ok(())
}

fn validate_required_wrapped_template_argument(
    arguments: &[GameLaunchArgument],
    literal_prefix: &str,
    placeholder: GameLaunchPlaceholder,
    literal_suffix: &str,
) -> Result<(), String> {
    let matches = arguments
        .iter()
        .filter(|argument| {
            matches!(
                argument,
                GameLaunchArgument::Template { fragments }
                    if matches!(
                        fragments.as_slice(),
                        [
                            GameLaunchFragment::Literal { value: prefix },
                            GameLaunchFragment::Placeholder { name },
                            GameLaunchFragment::Literal { value: suffix }
                        ] if prefix == literal_prefix
                            && *name == placeholder
                            && suffix == literal_suffix
                    )
            )
        })
        .count();
    if matches != 1 {
        return Err("Game JVM wrapped launch template is missing or duplicated".into());
    }
    Ok(())
}

fn validate_required_literal_argument(
    arguments: &[GameLaunchArgument],
    expected: &str,
) -> Result<(), String> {
    if arguments
        .iter()
        .filter(|argument| {
            matches!(argument, GameLaunchArgument::Literal { value } if value == expected)
        })
        .count()
        != 1
    {
        return Err(format!(
            "Game JVM arguments require exactly one {expected} argument"
        ));
    }
    Ok(())
}

fn validate_required_adjacent_literal_pair(
    arguments: &[GameLaunchArgument],
    flag: &str,
    value: &str,
) -> Result<(), String> {
    let matches = arguments
        .windows(2)
        .filter(|pair| {
            matches_launch_value(&pair[0], LaunchValueExpectation::Literal(flag))
                && matches_launch_value(&pair[1], LaunchValueExpectation::Literal(value))
        })
        .count();
    if matches != 1 {
        return Err(format!(
            "Game JVM arguments require exactly one {flag} {value} pair"
        ));
    }
    Ok(())
}

fn validate_exact_game_arguments(arguments: &[GameLaunchArgument]) -> Result<(), String> {
    let expected = [
        LaunchValueExpectation::Literal("--username"),
        LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::FragmentNickname),
        LaunchValueExpectation::Literal("--version"),
        LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::VersionName),
        LaunchValueExpectation::Literal("--gameDir"),
        LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::GameDirectory),
        LaunchValueExpectation::Literal("--assetsDir"),
        LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::AssetsRoot),
        LaunchValueExpectation::Literal("--assetIndex"),
        LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::AssetsIndexName),
        LaunchValueExpectation::Literal("--uuid"),
        LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::FragmentUuid),
        LaunchValueExpectation::Literal("--accessToken"),
        LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::OfflineAccessToken),
        LaunchValueExpectation::Literal("--clientId"),
        LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::OfflineClientId),
        LaunchValueExpectation::Literal("--xuid"),
        LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::OfflineXuid),
        LaunchValueExpectation::Literal("--userType"),
        LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::OfflineUserType),
        LaunchValueExpectation::Literal("--versionType"),
        LaunchValueExpectation::Placeholder(GameLaunchPlaceholder::VersionType),
        LaunchValueExpectation::Literal("--fml.neoForgeVersion"),
        LaunchValueExpectation::Literal("21.1.235"),
        LaunchValueExpectation::Literal("--fml.fmlVersion"),
        LaunchValueExpectation::Literal("4.0.42"),
        LaunchValueExpectation::Literal("--fml.mcVersion"),
        LaunchValueExpectation::Literal("1.21.1"),
        LaunchValueExpectation::Literal("--fml.neoFormVersion"),
        LaunchValueExpectation::Literal("20240808.144430"),
        LaunchValueExpectation::Literal("--launchTarget"),
        LaunchValueExpectation::Literal("forgeclient"),
    ];
    if arguments.len() != expected.len()
        || arguments
            .iter()
            .zip(expected)
            .any(|(argument, expected)| !matches_launch_value(argument, expected))
    {
        return Err(
            "Game arguments do not match pinned Minecraft/NeoForge offline launch metadata".into(),
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum JvmArgumentExpectation<'a> {
    Literal(&'a str),
    Placeholder(GameLaunchPlaceholder),
    Template {
        prefix: &'a str,
        placeholder: GameLaunchPlaceholder,
        suffix: Option<&'a str>,
    },
}

fn validate_exact_jvm_arguments(arguments: &[GameLaunchArgument]) -> Result<(), String> {
    let expected = [
        JvmArgumentExpectation::Literal("-Djava.net.preferIPv6Addresses=system"),
        JvmArgumentExpectation::Template {
            prefix: "-DignoreList=client-extra,",
            placeholder: GameLaunchPlaceholder::VersionName,
            suffix: Some(".jar"),
        },
        JvmArgumentExpectation::Template {
            prefix: "-DlibraryDirectory=",
            placeholder: GameLaunchPlaceholder::LibrariesDirectory,
            suffix: None,
        },
        JvmArgumentExpectation::Literal("-p"),
        JvmArgumentExpectation::Placeholder(GameLaunchPlaceholder::ModulePath),
        JvmArgumentExpectation::Literal("--add-modules"),
        JvmArgumentExpectation::Literal("ALL-MODULE-PATH"),
        JvmArgumentExpectation::Literal("--add-opens"),
        JvmArgumentExpectation::Literal("java.base/java.util.jar=cpw.mods.securejarhandler"),
        JvmArgumentExpectation::Literal("--add-opens"),
        JvmArgumentExpectation::Literal("java.base/java.lang.invoke=cpw.mods.securejarhandler"),
        JvmArgumentExpectation::Literal("--add-exports"),
        JvmArgumentExpectation::Literal("java.base/sun.security.util=cpw.mods.securejarhandler"),
        JvmArgumentExpectation::Literal("--add-exports"),
        JvmArgumentExpectation::Literal("jdk.naming.dns/com.sun.jndi.dns=java.naming"),
        JvmArgumentExpectation::Literal(
            "-XX:HeapDumpPath=MojangTricksIntelDriversForPerformance_javaw.exe_minecraft.exe.heapdump",
        ),
        JvmArgumentExpectation::Template {
            prefix: "-Djava.library.path=",
            placeholder: GameLaunchPlaceholder::NativesDirectory,
            suffix: None,
        },
        JvmArgumentExpectation::Template {
            prefix: "-Djna.tmpdir=",
            placeholder: GameLaunchPlaceholder::NativesDirectory,
            suffix: None,
        },
        JvmArgumentExpectation::Template {
            prefix: "-Dorg.lwjgl.system.SharedLibraryExtractPath=",
            placeholder: GameLaunchPlaceholder::NativesDirectory,
            suffix: None,
        },
        JvmArgumentExpectation::Template {
            prefix: "-Dio.netty.native.workdir=",
            placeholder: GameLaunchPlaceholder::NativesDirectory,
            suffix: None,
        },
        JvmArgumentExpectation::Template {
            prefix: "-Dminecraft.launcher.brand=",
            placeholder: GameLaunchPlaceholder::LauncherName,
            suffix: None,
        },
        JvmArgumentExpectation::Template {
            prefix: "-Dminecraft.launcher.version=",
            placeholder: GameLaunchPlaceholder::LauncherVersion,
            suffix: None,
        },
        JvmArgumentExpectation::Literal("-cp"),
        JvmArgumentExpectation::Placeholder(GameLaunchPlaceholder::Classpath),
        JvmArgumentExpectation::Template {
            prefix: "-Dlog4j.configurationFile=",
            placeholder: GameLaunchPlaceholder::LoggingConfigPath,
            suffix: None,
        },
    ];
    if arguments.len() != expected.len()
        || arguments
            .iter()
            .zip(expected)
            .any(|(argument, expected)| !matches_jvm_argument(argument, expected))
    {
        return Err("JVM arguments do not match pinned Minecraft/NeoForge launch metadata".into());
    }
    Ok(())
}

fn matches_jvm_argument(
    argument: &GameLaunchArgument,
    expected: JvmArgumentExpectation<'_>,
) -> bool {
    match expected {
        JvmArgumentExpectation::Literal(value) => {
            matches_launch_value(argument, LaunchValueExpectation::Literal(value))
        }
        JvmArgumentExpectation::Placeholder(placeholder) => {
            matches_launch_value(argument, LaunchValueExpectation::Placeholder(placeholder))
        }
        JvmArgumentExpectation::Template {
            prefix,
            placeholder,
            suffix,
        } => match (argument, suffix) {
            (GameLaunchArgument::Template { fragments }, None) => matches!(
                fragments.as_slice(),
                [
                    GameLaunchFragment::Literal { value },
                    GameLaunchFragment::Placeholder { name }
                ] if value == prefix && *name == placeholder
            ),
            (GameLaunchArgument::Template { fragments }, Some(suffix)) => matches!(
                fragments.as_slice(),
                [
                    GameLaunchFragment::Literal { value },
                    GameLaunchFragment::Placeholder { name },
                    GameLaunchFragment::Literal { value: actual_suffix }
                ] if value == prefix && *name == placeholder && actual_suffix == suffix
            ),
            _ => false,
        },
    }
}

fn validate_forbidden_jvm_arguments(arguments: &[GameLaunchArgument]) -> Result<(), String> {
    for argument in arguments {
        let prefix = launch_static_prefix(argument);
        let normalized = prefix.trim_start().to_lowercase();
        if normalized.starts_with('@')
            || normalized.starts_with("-javaagent")
            || normalized.starts_with("-agentlib")
            || normalized.starts_with("-agentpath")
            || normalized.starts_with("-xbootclasspath")
            || normalized.starts_with("-djava.system.class.loader")
            || normalized.starts_with("-djdk.attach.allowattachself")
            || normalized.starts_with("-dloader.path")
            || normalized.starts_with("-dlegacyclasspath")
            || normalized.starts_with("-djava.class.path")
            || matches!(normalized.as_str(), "-jar" | "-m" | "--module" | "--source")
            || normalized.starts_with("--module=")
            || normalized.starts_with("--source=")
            || normalized == "-classpath"
            || normalized.starts_with("-classpath=")
            || normalized == "--class-path"
            || normalized.starts_with("--class-path=")
            || normalized == "--module-path"
            || normalized.starts_with("--module-path=")
            || normalized == "--upgrade-module-path"
            || normalized.starts_with("--upgrade-module-path=")
            || normalized.starts_with("-cp=")
            || normalized.starts_with("-p=")
            || normalized.starts_with("--patch-module")
        {
            return Err(format!("Forbidden signed JVM argument: {prefix}"));
        }
    }
    Ok(())
}

fn validate_protected_jvm_argument_counts(arguments: &[GameLaunchArgument]) -> Result<(), String> {
    for prefix in [
        "-Djava.library.path=",
        "-Djna.tmpdir=",
        "-Dorg.lwjgl.system.SharedLibraryExtractPath=",
        "-Dio.netty.native.workdir=",
        "-Dlog4j.configurationFile=",
        "-Dminecraft.launcher.brand=",
        "-Dminecraft.launcher.version=",
        "-DlibraryDirectory=",
        "-DignoreList=",
    ] {
        if arguments
            .iter()
            .filter(|argument| {
                launch_static_prefix(argument)
                    .to_lowercase()
                    .starts_with(&prefix.to_lowercase())
            })
            .count()
            != 1
        {
            return Err(format!(
                "Game JVM arguments require exactly one protected {prefix} argument"
            ));
        }
    }
    for (flag, expected) in [
        ("-cp", 1),
        ("-p", 1),
        ("--add-modules", 1),
        ("--add-opens", 2),
        ("--add-exports", 2),
    ] {
        if arguments
            .iter()
            .filter(|argument| {
                matches!(argument, GameLaunchArgument::Literal { value } if value == flag)
            })
            .count()
            != expected
        {
            return Err(format!(
                "Game JVM arguments require exactly {expected} protected {flag} flag(s)"
            ));
        }
    }
    Ok(())
}

fn launch_static_prefix(argument: &GameLaunchArgument) -> String {
    match argument {
        GameLaunchArgument::Literal { value } => value.clone(),
        GameLaunchArgument::Template { fragments } => {
            let mut prefix = String::new();
            for fragment in fragments {
                match fragment {
                    GameLaunchFragment::Literal { value } => prefix.push_str(value),
                    GameLaunchFragment::Placeholder { .. } => break,
                }
            }
            prefix
        }
    }
}

fn require_placeholder_count(
    arguments: &[GameLaunchArgument],
    placeholder: GameLaunchPlaceholder,
    expected: usize,
    location: &str,
) -> Result<(), String> {
    let actual = count_placeholder(arguments, placeholder);
    if actual != expected {
        return Err(format!(
            "{location} require {expected} {} placeholder(s), got {actual}",
            placeholder_name(placeholder)
        ));
    }
    Ok(())
}

fn validate_launch_argument(argument: &GameLaunchArgument) -> Result<(), String> {
    match argument {
        GameLaunchArgument::Literal { value } => validate_launch_literal(value, true),
        GameLaunchArgument::Template { fragments } => {
            if fragments.is_empty() || fragments.len() > 32 {
                return Err("Game launch template fragment count is invalid".into());
            }
            let mut size = 0_usize;
            let mut has_placeholder = false;
            for fragment in fragments {
                match fragment {
                    GameLaunchFragment::Literal { value } => {
                        validate_launch_literal(value, false)?;
                        size = size
                            .checked_add(value.len())
                            .ok_or_else(|| "Game launch template size overflow".to_string())?;
                    }
                    GameLaunchFragment::Placeholder { name } => {
                        has_placeholder = true;
                        size = size
                            .checked_add(placeholder_name(*name).len())
                            .ok_or_else(|| "Game launch template size overflow".to_string())?;
                    }
                }
            }
            if !has_placeholder || size > 8192 {
                return Err("Game launch template is invalid or oversized".into());
            }
            Ok(())
        }
    }
}

fn validate_launch_literal(value: &str, allow_empty: bool) -> Result<(), String> {
    if (!allow_empty && value.is_empty())
        || value.len() > 4096
        || value.nfc().collect::<String>() != value
        || value.chars().any(char::is_control)
        || value.contains("${")
    {
        return Err("Game launch literal is invalid".into());
    }
    Ok(())
}

fn count_placeholder(arguments: &[GameLaunchArgument], expected: GameLaunchPlaceholder) -> usize {
    arguments
        .iter()
        .filter_map(|argument| match argument {
            GameLaunchArgument::Literal { .. } => None,
            GameLaunchArgument::Template { fragments } => Some(fragments),
        })
        .flatten()
        .filter(|fragment| {
            matches!(
                fragment,
                GameLaunchFragment::Placeholder { name } if *name == expected
            )
        })
        .count()
}

fn placeholder_name(placeholder: GameLaunchPlaceholder) -> &'static str {
    match placeholder {
        GameLaunchPlaceholder::FragmentNickname => "fragmentNickname",
        GameLaunchPlaceholder::FragmentUuid => "fragmentUuid",
        GameLaunchPlaceholder::GameDirectory => "gameDirectory",
        GameLaunchPlaceholder::AssetsRoot => "assetsRoot",
        GameLaunchPlaceholder::AssetsIndexName => "assetsIndexName",
        GameLaunchPlaceholder::VersionName => "versionName",
        GameLaunchPlaceholder::LibrariesDirectory => "librariesDirectory",
        GameLaunchPlaceholder::NativesDirectory => "nativesDirectory",
        GameLaunchPlaceholder::LoggingConfigPath => "loggingConfigPath",
        GameLaunchPlaceholder::Classpath => "classpath",
        GameLaunchPlaceholder::ModulePath => "modulePath",
        GameLaunchPlaceholder::LauncherName => "launcherName",
        GameLaunchPlaceholder::LauncherVersion => "launcherVersion",
        GameLaunchPlaceholder::OfflineAccessToken => "offlineAccessToken",
        GameLaunchPlaceholder::OfflineUserType => "offlineUserType",
        GameLaunchPlaceholder::OfflineClientId => "offlineClientId",
        GameLaunchPlaceholder::OfflineXuid => "offlineXuid",
        GameLaunchPlaceholder::VersionType => "versionType",
    }
}

fn game_runtime_role_name(role: GameRuntimeRole) -> &'static str {
    match role {
        GameRuntimeRole::MinecraftVersionJson => "minecraft-version-json",
        GameRuntimeRole::MinecraftClient => "minecraft-client",
        GameRuntimeRole::MinecraftAssetIndex => "minecraft-asset-index",
        GameRuntimeRole::MinecraftAsset => "minecraft-asset",
        GameRuntimeRole::MinecraftLoggingConfig => "minecraft-logging-config",
        GameRuntimeRole::MinecraftClientMappings => "minecraft-client-mappings",
        GameRuntimeRole::Library => "library",
        GameRuntimeRole::NativeLibrary => "native-library",
        GameRuntimeRole::NeoforgeInstaller => "neoforge-installer",
        GameRuntimeRole::NeoforgeInstallerLibrary => "neoforge-installer-library",
        GameRuntimeRole::NeoforgeUniversal => "neoforge-universal",
        GameRuntimeRole::NeoforgeDerivedMappings => "neoforge-derived-mappings",
        GameRuntimeRole::NeoforgeDerivedMergedMappings => "neoforge-derived-merged-mappings",
        GameRuntimeRole::NeoforgeDerivedClientSlim => "neoforge-derived-client-slim",
        GameRuntimeRole::NeoforgeDerivedClientExtra => "neoforge-derived-client-extra",
        GameRuntimeRole::NeoforgeDerivedClientSrg => "neoforge-derived-client-srg",
        GameRuntimeRole::NeoforgeDerivedClient => "neoforge-derived-client",
    }
}

fn derived_output_spec(role: GameRuntimeRole) -> Option<&'static DerivedOutputSpec> {
    NEOFORGE_DERIVED_OUTPUTS
        .iter()
        .find(|output| output.role == role)
}

fn expected_processor_outputs() -> Vec<GameProcessorOutput> {
    NEOFORGE_DERIVED_OUTPUTS
        .iter()
        .map(|output| GameProcessorOutput {
            path: output.path.to_owned(),
            size: output.size,
            sha1: output.sha1.to_owned(),
            sha256: output.sha256.to_owned(),
        })
        .collect()
}

fn expected_derived_output_provenance() -> Vec<GameDerivedOutputProvenance> {
    NEOFORGE_DERIVED_OUTPUTS
        .iter()
        .map(|output| GameDerivedOutputProvenance {
            path: output.path.to_owned(),
            size: output.size,
            sha1: output.sha1.to_owned(),
            sha256: output.sha256.to_owned(),
            launch_required: output.launch_required,
        })
        .collect()
}

fn expected_transient_artifact_states() -> Vec<ProcessorArtifactState> {
    NEOFORGE_PROCESSOR_TRANSIENT_OUTPUTS
        .iter()
        .map(|output| ProcessorArtifactState {
            path: output.path.to_owned(),
            size: output.size,
            sha1: output.sha1.to_owned(),
            sha256: output.sha256.to_owned(),
        })
        .collect()
}

fn expected_processor_transcript_sha256(step: &VerifiedProcessorStep) -> Result<String, String> {
    domain_digest(
        PROCESSOR_TRANSCRIPT_DOMAIN,
        &serde_json::json!({
            "stdoutBytes": step.stdout_bytes,
            "stdoutSha256": &step.stdout_sha256,
            "stderrBytes": step.stderr_bytes,
            "stderrSha256": &step.stderr_sha256,
        }),
    )
}

fn validate_processor_artifact_state(state: &ProcessorArtifactState) -> Result<(), String> {
    validate_game_runtime_file_path(&state.path)?;
    if state.path != MINECRAFT_CLIENT_MAPPINGS_PATH
        || state.size != MINECRAFT_CLIENT_MAPPINGS_SIZE
        || state.sha1 != MINECRAFT_CLIENT_MAPPINGS_SHA1
        || state.sha256 != MINECRAFT_CLIENT_MAPPINGS_SHA256
    {
        return Err("Processor Mojang mappings state is not the pinned input".into());
    }
    Ok(())
}

fn valid_processor_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
}

fn valid_processor_main_class(value: &str) -> bool {
    let mut segments = value.split('.');
    let mut count = 0_usize;
    for segment in &mut segments {
        count += 1;
        let mut bytes = segment.bytes();
        if !bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'_' | b'$'))
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
        {
            return false;
        }
    }
    count >= 2
}

fn require_processor_library(
    files: &HashMap<String, &GameRuntimeFile>,
    path: &str,
) -> Result<(), String> {
    validate_game_runtime_file_path(path)?;
    let file = files
        .get(&path.to_lowercase())
        .ok_or_else(|| format!("Signed processor library is missing: {path}"))?;
    if !matches!(
        file.role,
        GameRuntimeRole::Library | GameRuntimeRole::NeoforgeInstallerLibrary
    ) || !matches!(file.source, GameRuntimeSource::Official { .. })
    {
        return Err(format!("Processor path is not an official library: {path}"));
    }
    Ok(())
}

fn official_artifact_is_exact(
    artifact: &GameOfficialArtifact,
    url: &str,
    size: u64,
    sha1: &str,
    sha256: &str,
) -> bool {
    artifact.kind == "official"
        && artifact.url == url
        && artifact.size == size
        && artifact.sha1 == sha1
        && artifact.sha256 == sha256
}

fn project_game_runtime_file(file: &GameRuntimeFile) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({
        "path": &file.path,
        "role": file.role,
        "source": serde_json::to_value(&file.source)
            .map_err(|error| format!("Cannot serialize game runtime source: {error}"))?,
    }))
}

pub(super) fn domain_digest<T: Serialize + ?Sized>(
    domain: &str,
    payload: &T,
) -> Result<String, String> {
    let envelope = serde_json::json!({
        "domain": domain,
        "payload": serde_json::to_value(payload)
            .map_err(|error| format!("Cannot serialize game runtime fingerprint: {error}"))?,
    });
    let mut canonical = String::new();
    write_canonical_json(&envelope, &mut canonical)?;
    Ok(format!("{:x}", Sha256::digest(canonical.as_bytes())))
}

fn write_canonical_json(value: &serde_json::Value, output: &mut String) -> Result<(), String> {
    match value {
        serde_json::Value::Null => output.push_str("null"),
        serde_json::Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        serde_json::Value::Number(value) => output.push_str(&value.to_string()),
        serde_json::Value::String(value) => output.push_str(
            &serde_json::to_string(value)
                .map_err(|error| format!("Cannot canonicalize JSON string: {error}"))?,
        ),
        serde_json::Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(']');
        }
        serde_json::Value::Object(fields) => {
            output.push('{');
            let mut keys = fields.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key)
                        .map_err(|error| format!("Cannot canonicalize JSON key: {error}"))?,
                );
                output.push(':');
                write_canonical_json(&fields[key], output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn expected_game_runtime_inputs_sha256() -> Result<String, String> {
    domain_digest(
        "ru.fragmc.spark2.game-runtime.metadata-inputs.v1",
        &serde_json::json!({
            "profile": GAME_RUNTIME_ID,
            "selectedVersionManifestEntry": {
                "id": "1.21.1",
                "url": MINECRAFT_VERSION_JSON_URL,
                "sha1": MINECRAFT_VERSION_JSON_SHA1,
            },
            "minecraftVersionJson": {
                "url": MINECRAFT_VERSION_JSON_URL,
                "size": MINECRAFT_VERSION_JSON_SIZE,
                "sha1": MINECRAFT_VERSION_JSON_SHA1,
                "sha256": MINECRAFT_VERSION_JSON_SHA256,
            },
            "assetIndex": {
                "url": MINECRAFT_ASSET_INDEX_URL,
                "size": MINECRAFT_ASSET_INDEX_SIZE,
                "sha1": MINECRAFT_ASSET_INDEX_SHA1,
                "sha256": MINECRAFT_ASSET_INDEX_SHA256,
            },
            "minecraftClientMappings": {
                "url": MINECRAFT_CLIENT_MAPPINGS_URL,
                "size": MINECRAFT_CLIENT_MAPPINGS_SIZE,
                "sha1": MINECRAFT_CLIENT_MAPPINGS_SHA1,
                "sha256": MINECRAFT_CLIENT_MAPPINGS_SHA256,
            },
            "neoForgeInstaller": {
                "url": NEOFORGE_INSTALLER_URL,
                "size": NEOFORGE_INSTALLER_SIZE,
                "sha1": NEOFORGE_INSTALLER_SHA1,
                "sha256": NEOFORGE_INSTALLER_SHA256,
            },
            "installProfile": {
                "entry": "install_profile.json",
                "size": NEOFORGE_INSTALL_PROFILE_SIZE,
                "sha256": NEOFORGE_INSTALL_PROFILE_SHA256,
            },
            "neoForgeVersionJson": {
                "entry": "version.json",
                "size": NEOFORGE_VERSION_JSON_SIZE,
                "sha256": NEOFORGE_VERSION_JSON_SHA256,
            },
            "clientPatch": {
                "entry": "data/client.lzma",
                "size": NEOFORGE_CLIENT_PATCH_SIZE,
                "sha256": NEOFORGE_CLIENT_PATCH_SHA256,
            },
        }),
    )
}

/// Parses one immutable Mojang/NeoForge artifact source. This is the shared trust boundary used
/// by contract validation, artifact planning and the production downloader: only the five exact
/// official origins, their role-independent canonical path forms and any path-embedded SHA-1 are
/// accepted. The returned URL is therefore safe to hand to the pinned official transport.
pub(super) fn validate_official_game_source(value: &str, sha1: &str) -> Result<Url, String> {
    if !is_lower_hex(sha1, 40) || !is_allowed_official_game_url(value) {
        return Err("Official game artifact source is invalid".into());
    }
    let url =
        Url::parse(value).map_err(|_| "Official game artifact source is invalid".to_string())?;
    if !official_source_is_bound(&url, sha1) {
        return Err("Official game artifact source is not bound to its SHA-1".into());
    }
    Ok(url)
}

pub(super) const OFFICIAL_GAME_HOSTS: [&str; 5] = [
    "libraries.minecraft.net",
    "maven.neoforged.net",
    "piston-data.mojang.com",
    "piston-meta.mojang.com",
    "resources.download.minecraft.net",
];

pub(super) fn official_game_host_is_allowed(host: &str) -> bool {
    OFFICIAL_GAME_HOSTS.contains(&host)
}

fn is_allowed_official_game_url(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.as_str() != value
        || value.contains('?')
        || value.contains('#')
        || value.contains('%')
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    let path = url.path();
    let lower_path = path.to_ascii_lowercase();
    if lower_path.contains("%2e")
        || lower_path.contains("%2f")
        || lower_path.contains("%5c")
        || percent_decode_path(path).is_none_or(|decoded| {
            decoded.contains('\\')
                || decoded
                    .split('/')
                    .any(|segment| segment == "." || segment == "..")
        })
    {
        return false;
    }
    match url.host_str() {
        Some("piston-meta.mojang.com") => valid_piston_meta_path(path),
        Some("piston-data.mojang.com") => valid_piston_data_path(path),
        Some("libraries.minecraft.net") => valid_segmented_url_path(path, false),
        Some("resources.download.minecraft.net") => valid_minecraft_resource_path(path),
        Some("maven.neoforged.net") => path
            .strip_prefix("/releases")
            .is_some_and(|suffix| valid_segmented_url_path(suffix, true)),
        _ => false,
    }
}

fn official_source_is_bound(url: &Url, sha1: &str) -> bool {
    match url.host_str() {
        Some("resources.download.minecraft.net") => {
            url.path() == format!("/{}/{}", &sha1[..2], sha1)
        }
        Some("piston-meta.mojang.com") if url.path().starts_with("/v1/packages/") => {
            url.path().split('/').nth(3) == Some(sha1)
        }
        Some("piston-data.mojang.com") if url.path().starts_with("/v1/objects/") => {
            url.path().split('/').nth(3) == Some(sha1)
        }
        _ => true,
    }
}

fn valid_piston_meta_path(path: &str) -> bool {
    if path == "/mc/game/version_manifest_v2.json" {
        return true;
    }
    let Some(rest) = path.strip_prefix("/v1/packages/") else {
        return false;
    };
    let mut segments = rest.split('/');
    let digest = segments.next().unwrap_or_default();
    let file = segments.next().unwrap_or_default();
    segments.next().is_none()
        && is_lower_hex(digest, 40)
        && file.ends_with(".json")
        && file
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
}

fn valid_piston_data_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/v1/objects/") else {
        return false;
    };
    let mut segments = rest.split('/');
    let digest = segments.next().unwrap_or_default();
    let file = segments.next().unwrap_or_default();
    segments.next().is_none()
        && is_lower_hex(digest, 40)
        && !file.is_empty()
        && file
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
}

fn valid_segmented_url_path(path: &str, allow_percent: bool) -> bool {
    let segments: Vec<_> = path.strip_prefix('/').unwrap_or(path).split('/').collect();
    segments.len() >= 2
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || b"._+~-".contains(&byte)
                        || (allow_percent && byte == b'%')
                })
        })
}

fn valid_minecraft_resource_path(path: &str) -> bool {
    let mut segments = path.strip_prefix('/').unwrap_or(path).split('/');
    let prefix = segments.next().unwrap_or_default();
    let digest = segments.next().unwrap_or_default();
    segments.next().is_none() && is_lower_hex(prefix, 2) && is_lower_hex(digest, 40)
}

fn percent_decode_path(path: &str) -> Option<String> {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push(hex_nibble(high)?.checked_mul(16)? + hex_nibble(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn is_reserved_windows_name(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or(segment);
    matches!(stem, "con" | "prn" | "aux" | "nul")
        || ["com", "lpt"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        })
}

pub(super) fn is_sha256(value: &str) -> bool {
    is_lower_hex(value, 64)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn valid_java25_version(value: &str) -> bool {
    let Some((feature, build)) = value.split_once('+') else {
        return false;
    };
    let mut parts = feature.split('.');
    parts.next() == Some("25")
        && parts.next().is_some_and(numeric_component)
        && parts.next().is_some_and(numeric_component)
        && parts.next().is_none()
        && numeric_component(build)
}

fn numeric_component(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

pub(super) fn valid_setting_id(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn validate_rule(rule: &SettingValueRule) -> Result<(), String> {
    match rule {
        SettingValueRule::Integer { minimum, maximum } if maximum < minimum => {
            Err("Integer setting range is invalid".into())
        }
        SettingValueRule::Number { minimum, maximum }
            if !minimum.is_finite() || !maximum.is_finite() || maximum < minimum =>
        {
            Err("Number setting range is invalid".into())
        }
        SettingValueRule::String {
            max_length,
            allowed_values,
            allowed_prefixes,
        } => {
            if !(1..=4096).contains(max_length) {
                return Err("String setting maxLength is invalid".into());
            }
            if allowed_values.is_none() && allowed_prefixes.is_none() {
                return Err("String settings require an allowlist".into());
            }
            if allowed_values
                .as_ref()
                .is_some_and(|values| values.len() > 512)
                || allowed_prefixes
                    .as_ref()
                    .is_some_and(|values| values.len() > 64)
            {
                return Err("String setting allowlist is too large".into());
            }
            for values in [allowed_values.as_ref(), allowed_prefixes.as_ref()]
                .into_iter()
                .flatten()
            {
                let unique: HashSet<_> = values.iter().collect();
                if unique.len() != values.len() {
                    return Err("String setting allowlist contains duplicates".into());
                }
                if values.is_empty()
                    || values
                        .iter()
                        .any(|value| !valid_setting_string(value, 4096, false))
                {
                    return Err("String setting allowlist contains an invalid value".into());
                }
            }
            if allowed_prefixes.as_ref().is_some_and(|values| {
                values
                    .iter()
                    .any(|value| value.is_empty() || value.chars().count() > 256)
            }) {
                return Err("String setting prefix is too long".into());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn valid_setting_string(value: &str, max_length: usize, trim: bool) -> bool {
    !value.is_empty()
        && value.nfc().collect::<String>() == value
        && value.chars().count() <= max_length
        && !value.chars().any(char::is_control)
        && (!trim || value.trim() == value)
}

fn selectors_overlap(left: &SettingSelector, right: &SettingSelector) -> bool {
    match (left, right) {
        (SettingSelector::Exact { key: left }, SettingSelector::Exact { key: right }) => {
            left == right
        }
        (SettingSelector::Prefix { prefix: left }, SettingSelector::Prefix { prefix: right }) => {
            left.starts_with(right) || right.starts_with(left)
        }
        (SettingSelector::Prefix { prefix }, SettingSelector::Exact { key })
        | (SettingSelector::Exact { key }, SettingSelector::Prefix { prefix }) => {
            key.starts_with(prefix)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn runtime_lock() -> serde_json::Value {
        serde_json::json!({
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
                    "size": 123,
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "format": "zip",
                    "stripPrefix": "jdk-25.0.3+9-jre"
                },
                "executable": "bin/javaw.exe",
                "consoleExecutable": "bin/java.exe",
                "files": [
                    {
                        "path": "bin/java.exe",
                        "size": 1,
                        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    },
                    {
                        "path": "bin/javaw.exe",
                        "size": 1,
                        "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    }
                ]
            },
            "minecraft": {
                "version": "1.21.1",
                "versionManifestUrl": "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json",
                "versionJsonUrl": "https://piston-meta.mojang.com/1.21.1.json",
                "versionJsonSha1": "8344022e055c6c052047107a80e33d96c48e9fba"
            }
        })
    }

    pub(crate) fn game_runtime_lock() -> serde_json::Value {
        let official = |url: &str, size: u64, sha1: &str, sha256: &str| {
            serde_json::json!({
                "kind": "official",
                "url": url,
                "size": size,
                "sha1": sha1,
                "sha256": sha256
            })
        };
        let version = official(
            MINECRAFT_VERSION_JSON_URL,
            MINECRAFT_VERSION_JSON_SIZE,
            MINECRAFT_VERSION_JSON_SHA1,
            MINECRAFT_VERSION_JSON_SHA256,
        );
        let installer = official(
            NEOFORGE_INSTALLER_URL,
            NEOFORGE_INSTALLER_SIZE,
            NEOFORGE_INSTALLER_SHA1,
            NEOFORGE_INSTALLER_SHA256,
        );
        let mappings = official(
            MINECRAFT_CLIENT_MAPPINGS_URL,
            MINECRAFT_CLIENT_MAPPINGS_SIZE,
            MINECRAFT_CLIENT_MAPPINGS_SHA1,
            MINECRAFT_CLIENT_MAPPINGS_SHA256,
        );
        let mut files = serde_json::json!([
            {
                "path": "versions/1.21.1/1.21.1.json",
                "role": "minecraft-version-json",
                "source": version.clone()
            },
            {
                "path": NEOFORGE_INSTALLER_PATH,
                "role": "neoforge-installer",
                "source": installer.clone()
            },
            {
                "path": MINECRAFT_CLIENT_PATH,
                "role": "minecraft-client",
                "source": official(
                    MINECRAFT_CLIENT_URL,
                    MINECRAFT_CLIENT_SIZE,
                    MINECRAFT_CLIENT_SHA1,
                    MINECRAFT_CLIENT_SHA256
                )
            },
            {
                "path": "assets/indexes/17.json",
                "role": "minecraft-asset-index",
                "source": official(
                    MINECRAFT_ASSET_INDEX_URL,
                    MINECRAFT_ASSET_INDEX_SIZE,
                    MINECRAFT_ASSET_INDEX_SHA1,
                    MINECRAFT_ASSET_INDEX_SHA256
                )
            },
            {
                "path": "assets/objects/33/3333333333333333333333333333333333333333",
                "role": "minecraft-asset",
                "source": official(
                    "https://resources.download.minecraft.net/33/3333333333333333333333333333333333333333",
                    12,
                    &"3".repeat(40),
                    &"3".repeat(64)
                )
            },
            {
                "path": "assets/log_configs/client-1.12.xml",
                "role": "minecraft-logging-config",
                "source": official(
                    MINECRAFT_LOGGING_CONFIG_URL,
                    MINECRAFT_LOGGING_CONFIG_SIZE,
                    MINECRAFT_LOGGING_CONFIG_SHA1,
                    MINECRAFT_LOGGING_CONFIG_SHA256
                )
            },
            {
                "path": MINECRAFT_CLIENT_MAPPINGS_PATH,
                "role": "minecraft-client-mappings",
                "source": mappings.clone()
            },
            {
                "path": "libraries/com/example/library/1.0/library-1.0.jar",
                "role": "library",
                "source": official(
                    "https://libraries.minecraft.net/com/example/library/1.0/library-1.0.jar",
                    14,
                    &"5".repeat(40),
                    &"5".repeat(64)
                )
            },
            {
                "path": "libraries/org/lwjgl/lwjgl/3.3.3/lwjgl-3.3.3-natives-windows.jar",
                "role": "native-library",
                "source": official(
                    "https://libraries.minecraft.net/org/lwjgl/lwjgl/3.3.3/lwjgl-3.3.3-natives-windows.jar",
                    15,
                    &"7".repeat(40),
                    &"7".repeat(64)
                )
            },
            {
                "path": "libraries/net/neoforged/neoforge/21.1.235/neoforge-21.1.235-universal.jar",
                "role": "neoforge-universal",
                "source": official(
                    NEOFORGE_UNIVERSAL_URL,
                    NEOFORGE_UNIVERSAL_SIZE,
                    NEOFORGE_UNIVERSAL_SHA1,
                    NEOFORGE_UNIVERSAL_SHA256
                )
            }
        ]);
        let file_list = files.as_array_mut().expect("files fixture is an array");
        for index in 0..(MINECRAFT_ASSET_OBJECT_COUNT - 1) {
            let sha1 = format!("{:040x}", index + 1);
            let size = if index + 1 == MINECRAFT_ASSET_OBJECT_COUNT - 1 {
                MINECRAFT_ASSET_OBJECT_BYTES - 12 - (MINECRAFT_ASSET_OBJECT_COUNT as u64 - 2)
            } else {
                1
            };
            file_list.push(serde_json::json!({
                "path": format!("assets/objects/{}/{}", &sha1[..2], sha1),
                "role": "minecraft-asset",
                "source": official(
                    &format!("https://resources.download.minecraft.net/{}/{}", &sha1[..2], sha1),
                    size,
                    &sha1,
                    &format!("{:064x}", index + 10_000)
                )
            }));
        }
        for (index, path) in NEOFORGE_MODULE_PATHS.iter().enumerate() {
            file_list.push(serde_json::json!({
                "path": path,
                "role": "library",
                "source": official(
                    &format!("https://libraries.minecraft.net/{}", path.strip_prefix("libraries/").unwrap()),
                    100 + index as u64,
                    &format!("{:040x}", index + 20_000),
                    &format!("{:064x}", index + 20_000)
                )
            }));
        }
        for index in 0..73 {
            let path = match index {
                0 => "libraries/net/sf/jopt-simple/jopt-simple/5.0.4/jopt-simple-5.0.4.jar"
                    .to_owned(),
                1 => "libraries/commons-logging/commons-logging/1.2/commons-logging-1.2.jar"
                    .to_owned(),
                _ => format!("libraries/com/example/runtime/{index}/runtime-{index}.jar"),
            };
            file_list.push(serde_json::json!({
                "path": path,
                "role": "library",
                "source": official(
                    &format!("https://libraries.minecraft.net/{}", path.strip_prefix("libraries/").unwrap()),
                    200 + index as u64,
                    &format!("{:040x}", index + 30_000),
                    &format!("{:064x}", index + 30_000)
                )
            }));
        }
        for index in 0..23 {
            let path =
                format!("libraries/com/example/native/{index}/native-{index}-natives-windows.jar");
            file_list.push(serde_json::json!({
                "path": path,
                "role": "native-library",
                "source": official(
                    &format!("https://libraries.minecraft.net/com/example/native/{index}/native-{index}-natives-windows.jar"),
                    400 + index as u64,
                    &format!("{:040x}", index + 40_000),
                    &format!("{:064x}", index + 40_000)
                )
            }));
        }
        let installer_library_paths = [
            "libraries/com/google/code/gson/gson/2.8.9/gson-2.8.9.jar",
            "libraries/com/google/guava/guava/20.0/guava-20.0.jar",
            "libraries/com/opencsv/opencsv/4.4/opencsv-4.4.jar",
            "libraries/commons-beanutils/commons-beanutils/1.9.3/commons-beanutils-1.9.3.jar",
            "libraries/commons-collections/commons-collections/3.2.2/commons-collections-3.2.2.jar",
            "libraries/de/siegmar/fastcsv/2.0.0/fastcsv-2.0.0.jar",
            "libraries/net/md-5/SpecialSource/1.11.0/SpecialSource-1.11.0.jar",
            "libraries/net/neoforged/AutoRenamingTool/2.0.3/AutoRenamingTool-2.0.3-all.jar",
            "libraries/net/neoforged/installertools/binarypatcher/2.1.2/binarypatcher-2.1.2-fatjar.jar",
            "libraries/net/neoforged/installertools/cli-utils/2.1.2/cli-utils-2.1.2.jar",
            "libraries/net/neoforged/installertools/installertools/2.1.2/installertools-2.1.2.jar",
            "libraries/net/neoforged/installertools/jarsplitter/2.1.2/jarsplitter-2.1.2.jar",
            "libraries/net/neoforged/neoform/1.21.1-20240808.144430/neoform-1.21.1-20240808.144430.zip",
            "libraries/net/neoforged/srgutils/1.0.0/srgutils-1.0.0.jar",
            "libraries/org/apache/commons/commons-collections4/4.2/commons-collections4-4.2.jar",
            "libraries/org/apache/commons/commons-lang3/3.8.1/commons-lang3-3.8.1.jar",
            "libraries/org/apache/commons/commons-text/1.3/commons-text-1.3.jar",
            "libraries/org/ow2/asm/asm-analysis/9.3/asm-analysis-9.3.jar",
            "libraries/org/ow2/asm/asm-commons/9.3/asm-commons-9.3.jar",
            "libraries/org/ow2/asm/asm-tree/9.3/asm-tree-9.3.jar",
            "libraries/org/ow2/asm/asm/9.3/asm-9.3.jar",
        ];
        assert_eq!(
            installer_library_paths.len(),
            NEOFORGE_INSTALLER_ONLY_LIBRARY_COUNT
        );
        for (index, path) in installer_library_paths.iter().enumerate() {
            file_list.push(serde_json::json!({
                "path": path,
                "role": "neoforge-installer-library",
                "source": official(
                    &format!("https://maven.neoforged.net/releases/{}", path.strip_prefix("libraries/").unwrap()),
                    500 + index as u64,
                    &format!("{:040x}", index + 50_000),
                    &format!("{:064x}", index + 50_000)
                )
            }));
        }
        for output in NEOFORGE_DERIVED_OUTPUTS {
            file_list.push(serde_json::json!({
                "path": output.path,
                "role": game_runtime_role_name(output.role),
                "source": {
                    "kind": "derived",
                    "recipe": PROCESSOR_RECIPE,
                    "outputKind": output.output_kind,
                    "launchRequired": output.launch_required,
                    "size": output.size,
                    "sha1": output.sha1,
                    "sha256": output.sha256
                }
            }));
        }
        let current_official_bytes = file_list
            .iter()
            .filter(|file| file["source"]["kind"] == "official")
            .map(|file| file["source"]["size"].as_u64().unwrap())
            .sum::<u64>();
        let padding = file_list
            .iter_mut()
            .find(|file| file["path"] == "libraries/com/example/runtime/2/runtime-2.jar")
            .expect("runtime padding file must exist");
        padding["source"]["size"] = serde_json::json!(
            padding["source"]["size"].as_u64().unwrap() + MINECRAFT_NEOFORGE_OFFICIAL_BYTES
                - current_official_bytes
        );
        file_list.sort_by(|left, right| {
            left["path"]
                .as_str()
                .unwrap()
                .cmp(right["path"].as_str().unwrap())
        });
        let classpath: Vec<_> = file_list
            .iter()
            .filter(|file| {
                matches!(
                    file["role"].as_str(),
                    Some("minecraft-client" | "library" | "native-library")
                )
            })
            .map(|file| file["path"].as_str().unwrap().to_owned())
            .collect();
        let literal = |value: &str| serde_json::json!({ "kind": "literal", "value": value });
        let placeholder = |name: &str| {
            serde_json::json!({
                "kind": "template",
                "fragments": [{ "kind": "placeholder", "name": name }]
            })
        };
        let jvm_arguments = vec![
            literal("-Djava.net.preferIPv6Addresses=system"),
            serde_json::json!({
                "kind": "template",
                "fragments": [
                    { "kind": "literal", "value": "-DignoreList=client-extra," },
                    { "kind": "placeholder", "name": "versionName" },
                    { "kind": "literal", "value": ".jar" }
                ]
            }),
            serde_json::json!({
                "kind": "template",
                "fragments": [
                    { "kind": "literal", "value": "-DlibraryDirectory=" },
                    { "kind": "placeholder", "name": "librariesDirectory" }
                ]
            }),
            literal("-p"),
            placeholder("modulePath"),
            literal("--add-modules"),
            literal("ALL-MODULE-PATH"),
            literal("--add-opens"),
            literal("java.base/java.util.jar=cpw.mods.securejarhandler"),
            literal("--add-opens"),
            literal("java.base/java.lang.invoke=cpw.mods.securejarhandler"),
            literal("--add-exports"),
            literal("java.base/sun.security.util=cpw.mods.securejarhandler"),
            literal("--add-exports"),
            literal("jdk.naming.dns/com.sun.jndi.dns=java.naming"),
            literal(
                "-XX:HeapDumpPath=MojangTricksIntelDriversForPerformance_javaw.exe_minecraft.exe.heapdump",
            ),
            serde_json::json!({
                "kind": "template",
                "fragments": [
                    { "kind": "literal", "value": "-Djava.library.path=" },
                    { "kind": "placeholder", "name": "nativesDirectory" }
                ]
            }),
            serde_json::json!({
                "kind": "template",
                "fragments": [
                    { "kind": "literal", "value": "-Djna.tmpdir=" },
                    { "kind": "placeholder", "name": "nativesDirectory" }
                ]
            }),
            serde_json::json!({
                "kind": "template",
                "fragments": [
                    { "kind": "literal", "value": "-Dorg.lwjgl.system.SharedLibraryExtractPath=" },
                    { "kind": "placeholder", "name": "nativesDirectory" }
                ]
            }),
            serde_json::json!({
                "kind": "template",
                "fragments": [
                    { "kind": "literal", "value": "-Dio.netty.native.workdir=" },
                    { "kind": "placeholder", "name": "nativesDirectory" }
                ]
            }),
            serde_json::json!({
                "kind": "template",
                "fragments": [
                    { "kind": "literal", "value": "-Dminecraft.launcher.brand=" },
                    { "kind": "placeholder", "name": "launcherName" }
                ]
            }),
            serde_json::json!({
                "kind": "template",
                "fragments": [
                    { "kind": "literal", "value": "-Dminecraft.launcher.version=" },
                    { "kind": "placeholder", "name": "launcherVersion" }
                ]
            }),
            literal("-cp"),
            placeholder("classpath"),
            serde_json::json!({
                "kind": "template",
                "fragments": [
                    { "kind": "literal", "value": "-Dlog4j.configurationFile=" },
                    { "kind": "placeholder", "name": "loggingConfigPath" }
                ]
            }),
        ];
        let mut game_arguments = Vec::new();
        for (flag, name) in [
            ("--username", "fragmentNickname"),
            ("--version", "versionName"),
            ("--gameDir", "gameDirectory"),
            ("--assetsDir", "assetsRoot"),
            ("--assetIndex", "assetsIndexName"),
            ("--uuid", "fragmentUuid"),
            ("--accessToken", "offlineAccessToken"),
            ("--clientId", "offlineClientId"),
            ("--xuid", "offlineXuid"),
            ("--userType", "offlineUserType"),
            ("--versionType", "versionType"),
        ] {
            game_arguments.push(literal(flag));
            game_arguments.push(placeholder(name));
        }
        for (flag, value) in [
            ("--fml.neoForgeVersion", "21.1.235"),
            ("--fml.fmlVersion", "4.0.42"),
            ("--fml.mcVersion", "1.21.1"),
            ("--fml.neoFormVersion", "20240808.144430"),
            ("--launchTarget", "forgeclient"),
        ] {
            game_arguments.push(literal(flag));
            game_arguments.push(literal(value));
        }
        let processor_step = |upstream_index: u8,
                              id: &str,
                              jar_path: &str,
                              main_class: &str,
                              classpath: Vec<&str>,
                              arguments: Vec<serde_json::Value>| {
            serde_json::json!({
                "upstreamIndex": upstream_index,
                "id": id,
                "jarPath": jar_path,
                "mainClass": main_class,
                "classpath": classpath,
                "arguments": arguments,
            })
        };
        let literal_argument =
            |value: &str| serde_json::json!({ "kind": "literal", "value": value });
        let path_argument = |path: &str| serde_json::json!({ "kind": "path", "path": path });
        let input_argument = |input: &str| serde_json::json!({ "kind": "input", "input": input });
        let materialization_argument = |access: &str| {
            serde_json::json!({
                "kind": "materialization",
                "materialization": "minecraft-client-mappings",
                "access": access,
            })
        };
        let output_argument =
            |output_kind: &str| serde_json::json!({ "kind": "output", "outputKind": output_kind });
        let installertools_jar =
            "libraries/net/neoforged/installertools/installertools/2.1.2/installertools-2.1.2.jar";
        let installertools_classpath = vec![
            installertools_jar,
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
        let processor_plans = serde_json::json!({
            "upstream": {
                "kind": "neoforge-install-profile-client-v1",
                "steps": [
                    processor_step(
                        3,
                        "MCP_DATA",
                        installertools_jar,
                        "net.neoforged.installertools.ConsoleTool",
                        installertools_classpath.clone(),
                        vec![
                            literal_argument("--task"),
                            literal_argument("MCP_DATA"),
                            literal_argument("--input"),
                            path_argument("libraries/net/neoforged/neoform/1.21.1-20240808.144430/neoform-1.21.1-20240808.144430.zip"),
                            literal_argument("--output"),
                            output_argument("neoform-mappings"),
                            literal_argument("--key"),
                            literal_argument("mappings"),
                        ],
                    ),
                    processor_step(
                        4,
                        "DOWNLOAD_MOJMAPS",
                        installertools_jar,
                        "net.neoforged.installertools.ConsoleTool",
                        installertools_classpath.clone(),
                        vec![
                            literal_argument("--task"),
                            literal_argument("DOWNLOAD_MOJMAPS"),
                            literal_argument("--version"),
                            literal_argument("1.21.1"),
                            literal_argument("--side"),
                            literal_argument("client"),
                            literal_argument("--output"),
                            materialization_argument("write"),
                        ],
                    ),
                    processor_step(
                        5,
                        "MERGE_MAPPING",
                        installertools_jar,
                        "net.neoforged.installertools.ConsoleTool",
                        installertools_classpath,
                        vec![
                            literal_argument("--task"),
                            literal_argument("MERGE_MAPPING"),
                            literal_argument("--left"),
                            output_argument("neoform-mappings"),
                            literal_argument("--right"),
                            materialization_argument("read"),
                            literal_argument("--output"),
                            output_argument("merged-mappings"),
                            literal_argument("--classes"),
                            literal_argument("--fields"),
                            literal_argument("--methods"),
                            literal_argument("--reverse-right"),
                        ],
                    ),
                    processor_step(
                        6,
                        "jarsplitter",
                        "libraries/net/neoforged/installertools/jarsplitter/2.1.2/jarsplitter-2.1.2.jar",
                        "net.neoforged.jarsplitter.ConsoleTool",
                        vec![
                            "libraries/net/neoforged/installertools/jarsplitter/2.1.2/jarsplitter-2.1.2.jar",
                            "libraries/net/sf/jopt-simple/jopt-simple/5.0.4/jopt-simple-5.0.4.jar",
                            "libraries/net/neoforged/srgutils/1.0.0/srgutils-1.0.0.jar",
                            "libraries/net/neoforged/installertools/cli-utils/2.1.2/cli-utils-2.1.2.jar",
                        ],
                        vec![
                            literal_argument("--input"),
                            input_argument("minecraft-client"),
                            literal_argument("--slim"),
                            output_argument("client-slim"),
                            literal_argument("--extra"),
                            output_argument("client-extra"),
                            literal_argument("--srg"),
                            output_argument("merged-mappings"),
                        ],
                    ),
                    processor_step(
                        8,
                        "AutoRenamingTool",
                        "libraries/net/neoforged/AutoRenamingTool/2.0.3/AutoRenamingTool-2.0.3-all.jar",
                        "net.neoforged.art.Main",
                        vec!["libraries/net/neoforged/AutoRenamingTool/2.0.3/AutoRenamingTool-2.0.3-all.jar"],
                        vec![
                            literal_argument("--input"),
                            output_argument("client-slim"),
                            literal_argument("--output"),
                            output_argument("client-srg"),
                            literal_argument("--names"),
                            output_argument("merged-mappings"),
                            literal_argument("--ann-fix"),
                            literal_argument("--ids-fix"),
                            literal_argument("--src-fix"),
                            literal_argument("--record-fix"),
                        ],
                    ),
                    processor_step(
                        9,
                        "binarypatcher",
                        "libraries/net/neoforged/installertools/binarypatcher/2.1.2/binarypatcher-2.1.2-fatjar.jar",
                        "net.neoforged.binarypatcher.ConsoleTool",
                        vec!["libraries/net/neoforged/installertools/binarypatcher/2.1.2/binarypatcher-2.1.2-fatjar.jar"],
                        vec![
                            literal_argument("--clean"),
                            output_argument("client-srg"),
                            literal_argument("--output"),
                            output_argument("patched-client"),
                            literal_argument("--apply"),
                            input_argument("client-patch"),
                        ],
                    ),
                ]
            },
            "translation": {
                "kind": "spark2-neoforge-offline-translation-v1",
                "networkPolicy": "networked-step-substituted",
                "rules": [
                    { "upstreamIndex": 3, "action": "execute" },
                    {
                        "upstreamIndex": 4,
                        "action": "substituted-by-verified-input",
                        "materialization": "minecraft-client-mappings"
                    },
                    { "upstreamIndex": 5, "action": "execute" },
                    { "upstreamIndex": 6, "action": "execute" },
                    { "upstreamIndex": 8, "action": "execute" },
                    { "upstreamIndex": 9, "action": "execute" }
                ],
                "materializations": [{
                    "id": "minecraft-client-mappings",
                    "path": MINECRAFT_CLIENT_MAPPINGS_PATH,
                    "source": mappings.clone(),
                    "access": "read-only",
                    "verifyAfterExecution": true
                }]
            },
            "executable": {
                "kind": PROCESSOR_RECIPE,
                "networkRequirement": "no-network-required",
                "steps": [
                    { "executionIndex": 0, "upstreamIndex": 3 },
                    { "executionIndex": 1, "upstreamIndex": 5 },
                    { "executionIndex": 2, "upstreamIndex": 6 },
                    { "executionIndex": 3, "upstreamIndex": 8 },
                    { "executionIndex": 4, "upstreamIndex": 9 }
                ]
            }
        });
        let derived_outputs = NEOFORGE_DERIVED_OUTPUTS
            .iter()
            .map(|output| {
                serde_json::json!({
                    "path": output.path,
                    "size": output.size,
                    "sha1": output.sha1,
                    "sha256": output.sha256,
                    "launchRequired": output.launch_required,
                })
            })
            .collect::<Vec<_>>();
        let expected_outputs = NEOFORGE_DERIVED_OUTPUTS
            .iter()
            .map(|output| {
                serde_json::json!({
                    "path": output.path,
                    "size": output.size,
                    "sha1": output.sha1,
                    "sha256": output.sha256,
                })
            })
            .collect::<Vec<_>>();
        let zero = "0".repeat(64);
        let mut lock = serde_json::json!({
            "schemaVersion": 1,
            "id": GAME_RUNTIME_ID,
            "platform": { "os": "windows", "architecture": "x64" },
            "identity": {
                "kind": "fragment-custom-offline-v1",
                "nicknameSource": "fragment-admission",
                "uuidSource": "fragment-admission",
                "accessToken": "0",
                "userType": "legacy",
                "clientId": "",
                "xuid": ""
            },
            "provenance": {
                "resolver": {
                    "kind": "fragment-spark2-game-runtime-resolver-v1",
                    "profile": GAME_RUNTIME_ID,
                    "algorithm": "minecraft-neoforge-windows-x64-graph-v1",
                    "resolverArtifactSha256": "b".repeat(64),
                    "inputsSha256": zero,
                    "graphSha256": zero,
                    "assetGraphSha256": zero,
                    "runtimeLibraryGraphSha256": zero,
                    "installerInputGraphSha256": zero,
                    "downloadGraphSha256": zero,
                    "launchSha256": zero,
                    "upstreamPlanSha256": zero,
                    "translationSha256": zero,
                    "executablePlanSha256": zero,
                    "materializationGraphSha256": zero,
                    "metadataDeclarationSha256": zero
                },
                "minecraftVersionJson": version.clone(),
                "minecraftClientMappings": mappings.clone(),
                "neoForgeInstaller": installer.clone(),
                "installProfile": {
                    "entry": "install_profile.json",
                    "size": 130522,
                    "sha256": NEOFORGE_INSTALL_PROFILE_SHA256
                },
                "neoForgeVersionJson": {
                    "entry": "version.json",
                    "size": 21148,
                    "sha256": NEOFORGE_VERSION_JSON_SHA256,
                    "disposition": "embedded-launch-metadata-only"
                },
                "clientPatch": {
                    "entry": "data/client.lzma",
                    "size": 3239759,
                    "sha256": NEOFORGE_CLIENT_PATCH_SHA256
                },
                "processorPlans": processor_plans,
                "derivedOutputs": derived_outputs
            },
            "verification": {
                "offlineProcessors": {
                    "status": "pending",
                    "recipe": PROCESSOR_RECIPE,
                    "requiredRuns": 2,
                    "networkRequirement": "no-network-required",
                    "networkIsolation": "not-os-enforced",
                    "java": {
                        "distribution": JAVA_DISTRIBUTION,
                        "version": "25.0.3+9",
                        "platform": "windows-x64"
                    },
                    "upstreamPlanSha256": zero,
                    "translationSha256": zero,
                    "executablePlanSha256": zero,
                    "materializationGraphSha256": zero,
                    "expectedOutputs": expected_outputs
                }
            },
            "files": files,
            "launch": {
                "mainClass": GAME_MAIN_CLASS,
                "versionName": GAME_VERSION_NAME,
                "versionType": "release",
                "assetIndexName": GAME_ASSET_INDEX_NAME,
                "classpath": classpath,
                "modulePath": NEOFORGE_MODULE_PATHS,
                "jvmArguments": jvm_arguments,
                "gameArguments": game_arguments
            }
        });
        let parsed: GameRuntimeLock =
            serde_json::from_value(lock.clone()).expect("fixture schema must deserialize");
        let fingerprints = parsed
            .compute_graph_fingerprints()
            .expect("fixture fingerprints must compute");
        let resolver = lock["provenance"]["resolver"]
            .as_object_mut()
            .expect("fixture resolver must be an object");
        for (field, value) in [
            ("inputsSha256", fingerprints.inputs_sha256.as_str()),
            ("graphSha256", fingerprints.graph_sha256.as_str()),
            ("assetGraphSha256", fingerprints.asset_graph_sha256.as_str()),
            (
                "runtimeLibraryGraphSha256",
                fingerprints.runtime_library_graph_sha256.as_str(),
            ),
            (
                "installerInputGraphSha256",
                fingerprints.installer_input_graph_sha256.as_str(),
            ),
            (
                "downloadGraphSha256",
                fingerprints.download_graph_sha256.as_str(),
            ),
            ("launchSha256", fingerprints.launch_sha256.as_str()),
            (
                "upstreamPlanSha256",
                fingerprints.upstream_plan_sha256.as_str(),
            ),
            (
                "translationSha256",
                fingerprints.translation_sha256.as_str(),
            ),
            (
                "executablePlanSha256",
                fingerprints.executable_plan_sha256.as_str(),
            ),
            (
                "materializationGraphSha256",
                fingerprints.materialization_graph_sha256.as_str(),
            ),
            (
                "metadataDeclarationSha256",
                fingerprints.metadata_declaration_sha256.as_str(),
            ),
        ] {
            resolver.insert(field.to_owned(), serde_json::json!(value));
        }
        let verification = lock["verification"]["offlineProcessors"]
            .as_object_mut()
            .expect("fixture verification must be an object");
        for (field, value) in [
            ("upstreamPlanSha256", fingerprints.upstream_plan_sha256),
            ("translationSha256", fingerprints.translation_sha256),
            ("executablePlanSha256", fingerprints.executable_plan_sha256),
            (
                "materializationGraphSha256",
                fingerprints.materialization_graph_sha256,
            ),
        ] {
            verification.insert(field.to_owned(), serde_json::json!(value));
        }
        lock
    }

    fn verified_game_runtime_lock() -> serde_json::Value {
        let mut lock = game_runtime_lock();
        let expected_input_state_sha256: String =
            serde_json::from_value::<GameRuntimeLock>(lock.clone())
                .expect("pending fixture schema must deserialize")
                .compute_expected_processor_input_state_sha256()
                .expect("processor input-state digest must compute");
        let resolver = lock["provenance"]["resolver"].clone();
        let outputs = lock["verification"]["offlineProcessors"]["expectedOutputs"].clone();
        let write_set = NEOFORGE_DERIVED_OUTPUTS
            .iter()
            .map(|output| serde_json::json!(output.path))
            .collect::<Vec<_>>();
        let write_set_sha256 = domain_digest("ru.fragmc.spark2.neoforge.write-set.v1", &write_set)
            .expect("write-set digest must compute");
        let mappings = serde_json::json!({
            "path": MINECRAFT_CLIENT_MAPPINGS_PATH,
            "size": MINECRAFT_CLIENT_MAPPINGS_SIZE,
            "sha1": MINECRAFT_CLIENT_MAPPINGS_SHA1,
            "sha256": MINECRAFT_CLIENT_MAPPINGS_SHA256,
        });
        let step_writes = [
            vec![NEOFORGE_DERIVED_OUTPUTS[0].path],
            vec![NEOFORGE_DERIVED_OUTPUTS[1].path],
            vec![
                NEOFORGE_DERIVED_OUTPUTS[2].path,
                NEOFORGE_PROCESSOR_TRANSIENT_OUTPUTS[0].path,
                NEOFORGE_DERIVED_OUTPUTS[3].path,
                NEOFORGE_PROCESSOR_TRANSIENT_OUTPUTS[1].path,
            ],
            vec![NEOFORGE_DERIVED_OUTPUTS[4].path],
            vec![NEOFORGE_DERIVED_OUTPUTS[5].path],
        ];
        let transient_artifacts = NEOFORGE_PROCESSOR_TRANSIENT_OUTPUTS
            .iter()
            .map(|artifact| {
                serde_json::json!({
                    "path": artifact.path,
                    "size": artifact.size,
                    "sha1": artifact.sha1,
                    "sha256": artifact.sha256,
                })
            })
            .collect::<Vec<_>>();
        let removed_transient_artifacts = [vec![], vec![], transient_artifacts, vec![], vec![]];
        let steps = EXECUTABLE_PROCESSOR_INDICES
            .iter()
            .enumerate()
            .map(|(execution_index, upstream_index)| {
                let stdout_bytes = execution_index as u64;
                let stderr_bytes = 0_u64;
                let stdout_sha256 = format!("{:064x}", execution_index + 101);
                let stderr_sha256 = format!("{:064x}", execution_index + 201);
                let transcript_sha256 = domain_digest(
                    PROCESSOR_TRANSCRIPT_DOMAIN,
                    &serde_json::json!({
                        "stdoutBytes": stdout_bytes,
                        "stdoutSha256": stdout_sha256,
                        "stderrBytes": stderr_bytes,
                        "stderrSha256": stderr_sha256,
                    }),
                )
                .expect("transcript digest must compute");
                serde_json::json!({
                    "executionIndex": execution_index,
                    "upstreamIndex": upstream_index,
                    "exitCode": 0,
                    "stdoutBytes": stdout_bytes,
                    "stderrBytes": stderr_bytes,
                    "stdoutSha256": stdout_sha256,
                    "stderrSha256": stderr_sha256,
                    "transcriptSha256": transcript_sha256,
                    "writtenPaths": step_writes[execution_index],
                    "removedTransientArtifacts": removed_transient_artifacts[execution_index],
                })
            })
            .collect::<Vec<_>>();
        let run = |ordinal: u8, work_root: &str| {
            serde_json::json!({
                "ordinal": ordinal,
                "workRootIdentitySha256": work_root,
                "inputsBeforeSha256": expected_input_state_sha256,
                "inputsAfterSha256": expected_input_state_sha256,
                "mappingsBefore": mappings.clone(),
                "mappingsAfter": mappings.clone(),
                "steps": steps.clone(),
                "writeSet": write_set.clone(),
                "writeSetSha256": write_set_sha256,
                "outputs": outputs.clone(),
            })
        };
        let mut receipt = serde_json::json!({
            "status": "verified",
            "schemaVersion": 2,
            "kind": "spark2-neoforge-offline-processors-v2",
            "recipe": PROCESSOR_RECIPE,
            "graphSha256": resolver["graphSha256"],
            "resolverArtifactSha256": resolver["resolverArtifactSha256"],
            "executorArtifactSha256": "c".repeat(64),
            "upstreamPlanSha256": resolver["upstreamPlanSha256"],
            "translationSha256": resolver["translationSha256"],
            "executablePlanSha256": resolver["executablePlanSha256"],
            "materializationGraphSha256": resolver["materializationGraphSha256"],
            "java": {
                "runtimeLockSha256": "d".repeat(64),
                "archiveSha256": "e".repeat(64),
                "extractedTreeSha256": "f".repeat(64),
                "version": "25.0.3+9"
            },
            "isolation": {
                "networkRequirement": "no-network-required",
                "networkIsolation": "not-os-enforced",
                "workspaces": "two-distinct-fresh"
            },
            "runs": [run(1, &"a".repeat(64)), run(2, &"b".repeat(64))],
            "consensusOutputs": outputs,
            "receiptSha256": "0".repeat(64)
        });
        let mut receipt_payload = receipt.clone();
        receipt_payload
            .as_object_mut()
            .expect("receipt payload must be an object")
            .remove("receiptSha256");
        receipt["receiptSha256"] = serde_json::json!(domain_digest(
            "ru.fragmc.spark2.neoforge.offline-receipt.v2",
            &receipt_payload,
        )
        .expect("receipt digest must compute"));
        lock["verification"]["offlineProcessors"] = receipt;
        lock
    }

    pub(crate) fn verified_game_runtime_lock_for(
        runtime_lock_sha256: &str,
        archive_sha256: &str,
        extracted_tree_sha256: &str,
    ) -> serde_json::Value {
        let mut lock = verified_game_runtime_lock();
        lock["verification"]["offlineProcessors"]["java"]["runtimeLockSha256"] =
            serde_json::json!(runtime_lock_sha256);
        lock["verification"]["offlineProcessors"]["java"]["archiveSha256"] =
            serde_json::json!(archive_sha256);
        lock["verification"]["offlineProcessors"]["java"]["extractedTreeSha256"] =
            serde_json::json!(extracted_tree_sha256);
        refresh_verified_receipt_digest(&mut lock);
        lock
    }

    fn refresh_verified_receipt_digest(lock: &mut serde_json::Value) {
        let receipt = lock["verification"]["offlineProcessors"]
            .as_object_mut()
            .expect("verified receipt must be an object");
        let mut payload = serde_json::Value::Object(receipt.clone());
        payload
            .as_object_mut()
            .expect("receipt payload must be an object")
            .remove("receiptSha256");
        receipt.insert(
            "receiptSha256".to_owned(),
            serde_json::json!(domain_digest(
                "ru.fragmc.spark2.neoforge.offline-receipt.v2",
                &payload,
            )
            .expect("receipt digest must compute")),
        );
    }

    #[test]
    fn accepts_the_pinned_java_25_identity() {
        let bytes = serde_json::to_vec(&runtime_lock()).expect("fixture must serialize");
        let lock = RuntimeLock::parse_and_validate(&bytes).expect("runtime lock must validate");
        assert_eq!(lock.java.major, 25);
        assert_eq!(lock.java.image_type, "jre");
    }

    #[test]
    fn game_runtime_metadata_input_fingerprint_matches_spark2() {
        assert_eq!(
            expected_game_runtime_inputs_sha256().unwrap(),
            "d5ae7f5dcbae9ed6833eebe9391ab28f32fc7409777f22485593ad4cb21c8b9a"
        );
    }

    #[test]
    fn stable_processor_subgraph_fingerprints_match_spark2() {
        let lock = game_runtime_lock();
        let resolver = &lock["provenance"]["resolver"];
        assert_eq!(
            resolver["upstreamPlanSha256"],
            "76240c5d986921bf1d9b7744ce5aa51c36a5621ba4456f6f77ad12c6d4c94c7c"
        );
        assert_eq!(
            resolver["translationSha256"],
            "4b0a3ca779ac57c5dd8fcba122b649c1dd7ed48f443935f9df8bf16f326e0d0a"
        );
        assert_eq!(
            resolver["executablePlanSha256"],
            "ed14553396a9dc99a16852d0c4b055c70041acbcd500a44fcccfd049a28b70e5"
        );
        assert_eq!(
            resolver["materializationGraphSha256"],
            "8aa3f424724e56b33913138c469b86fdb3c3372ef65389c477294690e62b6d98"
        );
        let write_set = NEOFORGE_DERIVED_OUTPUTS
            .iter()
            .map(|output| output.path)
            .collect::<Vec<_>>();
        assert_eq!(
            domain_digest("ru.fragmc.spark2.neoforge.write-set.v1", &write_set).unwrap(),
            "f6363e72a13c6e30a4444f23dbcfff11ddb5af1af4131be63ba3678cfe3f0e09"
        );
    }

    #[test]
    fn rejects_java_21_and_case_colliding_runtime_files() {
        let mut old_java = runtime_lock();
        old_java["java"]["major"] = serde_json::json!(21);
        let bytes = serde_json::to_vec(&old_java).expect("fixture must serialize");
        assert!(RuntimeLock::parse_and_validate(&bytes).is_err());

        let mut collision = runtime_lock();
        let duplicate = collision["java"]["files"][0].clone();
        collision["java"]["files"]
            .as_array_mut()
            .expect("files must be an array")
            .push(duplicate);
        let bytes = serde_json::to_vec(&collision).expect("fixture must serialize");
        assert!(RuntimeLock::parse_and_validate(&bytes).is_err());
    }

    #[test]
    fn accepts_unknown_optional_runtime_fields_but_rejects_unknown_schema() {
        let mut lock = runtime_lock();
        lock["futureTopLevel"] = serde_json::json!({ "enabled": true });
        lock["java"]["futureRuntimeMetadata"] = serde_json::json!("optional");
        lock["java"]["license"]["noticeUrl"] = serde_json::json!("https://example.invalid");
        lock["java"]["archive"]["fallbackUrl"] = serde_json::json!("https://evil.invalid");
        lock["java"]["files"][0]["mode"] = serde_json::json!("executable");
        lock["minecraft"]["releaseTime"] = serde_json::json!("future metadata");
        let bytes = serde_json::to_vec(&lock).expect("fixture must serialize");
        assert!(RuntimeLock::parse_and_validate(&bytes).is_ok());

        lock["schemaVersion"] = serde_json::json!(2);
        let bytes = serde_json::to_vec(&lock).expect("fixture must serialize");
        assert!(RuntimeLock::parse_and_validate(&bytes).is_err());
    }

    #[test]
    fn accepts_a_strict_fragment_custom_offline_game_runtime() {
        let lock = GameRuntimeLock::parse_and_validate(
            &serde_json::to_vec(&game_runtime_lock()).expect("fixture must serialize"),
        )
        .expect("game runtime lock must validate");
        assert_eq!(lock.identity.kind, "fragment-custom-offline-v1");
        assert_eq!(lock.identity.access_token, "0");
        assert!(lock.identity.client_id.is_empty());
        assert!(lock.identity.xuid.is_empty());
        assert!(lock
            .verification
            .offline_processors
            .bind_java_runtime(
                &"d".repeat(64),
                &"e".repeat(64),
                &"f".repeat(64),
                "25.0.3+9",
            )
            .unwrap_err()
            .contains("Pending"));
    }

    #[test]
    fn accepts_and_binds_a_verified_two_run_processor_receipt() {
        let lock = GameRuntimeLock::parse_and_validate(
            &serde_json::to_vec(&verified_game_runtime_lock()).expect("fixture must serialize"),
        )
        .expect("verified processor receipt must validate");
        lock.verification
            .offline_processors
            .bind_java_runtime(
                &"d".repeat(64),
                &"e".repeat(64),
                &"f".repeat(64),
                "25.0.3+9",
            )
            .expect("verified receipt must bind exact managed Java");
        assert!(lock
            .verification
            .offline_processors
            .bind_java_runtime(
                &"0".repeat(64),
                &"e".repeat(64),
                &"f".repeat(64),
                "25.0.3+9",
            )
            .is_err());
        assert!(lock
            .verification
            .offline_processors
            .bind_java_runtime(
                &"d".repeat(64),
                &"e".repeat(64),
                &"0".repeat(64),
                "25.0.3+9",
            )
            .is_err());
    }

    #[test]
    fn game_runtime_rejects_every_resolver_fingerprint_mismatch() {
        let base = game_runtime_lock();
        for field in [
            "inputsSha256",
            "graphSha256",
            "assetGraphSha256",
            "runtimeLibraryGraphSha256",
            "installerInputGraphSha256",
            "downloadGraphSha256",
            "launchSha256",
            "upstreamPlanSha256",
            "translationSha256",
            "executablePlanSha256",
            "materializationGraphSha256",
            "metadataDeclarationSha256",
        ] {
            let mut mismatched = base.clone();
            mismatched["provenance"]["resolver"][field] = serde_json::json!("f".repeat(64));
            assert!(
                GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&mismatched).unwrap())
                    .is_err(),
                "resolver mismatch must be rejected for {field}"
            );
        }
    }

    #[test]
    fn game_runtime_rejects_unknown_processor_fields_and_role_source_confusion() {
        let base = game_runtime_lock();

        let mut unknown_step = base.clone();
        unknown_step["provenance"]["processorPlans"]["upstream"]["steps"][0]["shellCommand"] =
            serde_json::json!("calc.exe");
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&unknown_step).unwrap())
                .is_err()
        );

        let derived_index = base["files"]
            .as_array()
            .unwrap()
            .iter()
            .position(|file| file["role"] == "neoforge-derived-client")
            .unwrap();
        let mut unknown_source = base.clone();
        unknown_source["files"][derived_index]["source"]["url"] =
            serde_json::json!("https://example.invalid/derived.jar");
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&unknown_source).unwrap())
                .is_err()
        );

        let mut wrong_recipe = base.clone();
        wrong_recipe["files"][derived_index]["source"]["recipe"] =
            serde_json::json!("neoforge-installer-offline-v1");
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&wrong_recipe).unwrap())
                .is_err()
        );

        let mut wrong_output_kind = base.clone();
        wrong_output_kind["files"][derived_index]["source"]["outputKind"] =
            serde_json::json!("client-slim");
        assert!(GameRuntimeLock::parse_and_validate(
            &serde_json::to_vec(&wrong_output_kind).unwrap()
        )
        .is_err());

        let mut derived_as_library = base.clone();
        derived_as_library["files"][derived_index]["role"] = serde_json::json!("library");
        assert!(GameRuntimeLock::parse_and_validate(
            &serde_json::to_vec(&derived_as_library).unwrap()
        )
        .is_err());

        let mut official_as_derived = base.clone();
        let official_index = official_as_derived["files"]
            .as_array()
            .unwrap()
            .iter()
            .position(|file| file["role"] == "library")
            .unwrap();
        official_as_derived["files"][official_index]["role"] =
            serde_json::json!("neoforge-derived-client-slim");
        assert!(GameRuntimeLock::parse_and_validate(
            &serde_json::to_vec(&official_as_derived).unwrap()
        )
        .is_err());

        let mut unsigned_tool = base;
        unsigned_tool["provenance"]["processorPlans"]["upstream"]["steps"][0]["jarPath"] =
            serde_json::json!(NEOFORGE_INSTALLER_PATH);
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&unsigned_tool).unwrap())
                .is_err()
        );
    }

    #[test]
    fn game_runtime_rejects_processor_plan_and_receipt_tampering() {
        let pending = game_runtime_lock();
        let mut alternate_valid_shape = pending.clone();
        alternate_valid_shape["provenance"]["processorPlans"]["upstream"]["steps"][0]["id"] =
            serde_json::json!("MCP_DATA_ALT");
        let alternate_typed: GameRuntimeLock = serde_json::from_value(alternate_valid_shape)
            .expect("alternate plan still has a structurally valid schema");
        assert!(alternate_typed.compute_graph_fingerprints().is_err());

        let mut tool_order = pending.clone();
        let classpath = tool_order["provenance"]["processorPlans"]["upstream"]["steps"][0]
            ["classpath"]
            .as_array_mut()
            .unwrap();
        let tool = classpath.remove(0);
        classpath.push(tool);
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&tool_order).unwrap()).is_err()
        );

        let mut network_step = pending.clone();
        network_step["provenance"]["processorPlans"]["upstream"]["steps"][1]["id"] =
            serde_json::json!("NOT_DOWNLOAD_MOJMAPS");
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&network_step).unwrap())
                .is_err()
        );

        let mut executable = pending.clone();
        executable["provenance"]["processorPlans"]["executable"]["steps"][1]["upstreamIndex"] =
            serde_json::json!(4);
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&executable).unwrap()).is_err()
        );

        let mut verification_binding = pending;
        verification_binding["verification"]["offlineProcessors"]["translationSha256"] =
            serde_json::json!("f".repeat(64));
        assert!(GameRuntimeLock::parse_and_validate(
            &serde_json::to_vec(&verification_binding).unwrap()
        )
        .is_err());

        let verified = verified_game_runtime_lock();
        let mut receipt_digest = verified.clone();
        receipt_digest["verification"]["offlineProcessors"]["receiptSha256"] =
            serde_json::json!("0".repeat(64));
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&receipt_digest).unwrap())
                .is_err()
        );

        let mut write_set = verified.clone();
        write_set["verification"]["offlineProcessors"]["runs"][0]["writeSet"]
            .as_array_mut()
            .unwrap()
            .reverse();
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&write_set).unwrap()).is_err()
        );

        let mut transient = verified.clone();
        transient["verification"]["offlineProcessors"]["runs"][0]["steps"][2]
            ["removedTransientArtifacts"][0]["sha256"] = serde_json::json!("0".repeat(64));
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&transient).unwrap()).is_err()
        );

        let mut mappings = verified.clone();
        mappings["verification"]["offlineProcessors"]["runs"][0]["mappingsAfter"]["sha256"] =
            serde_json::json!("0".repeat(64));
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&mappings).unwrap()).is_err()
        );

        let mut forged_inputs = verified.clone();
        for run in forged_inputs["verification"]["offlineProcessors"]["runs"]
            .as_array_mut()
            .unwrap()
        {
            run["inputsBeforeSha256"] = serde_json::json!("f".repeat(64));
            run["inputsAfterSha256"] = serde_json::json!("f".repeat(64));
        }
        refresh_verified_receipt_digest(&mut forged_inputs);
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&forged_inputs).unwrap())
                .is_err()
        );

        let mut forged_transcript = verified.clone();
        forged_transcript["verification"]["offlineProcessors"]["runs"][0]["steps"][0]
            ["transcriptSha256"] = serde_json::json!("f".repeat(64));
        refresh_verified_receipt_digest(&mut forged_transcript);
        assert!(GameRuntimeLock::parse_and_validate(
            &serde_json::to_vec(&forged_transcript).unwrap()
        )
        .is_err());

        let mut same_workspace = verified.clone();
        same_workspace["verification"]["offlineProcessors"]["runs"][1]["workRootIdentitySha256"] =
            same_workspace["verification"]["offlineProcessors"]["runs"][0]
                ["workRootIdentitySha256"]
                .clone();
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&same_workspace).unwrap())
                .is_err()
        );

        let mut unknown_receipt = verified;
        unknown_receipt["verification"]["offlineProcessors"]["runs"][0]["steps"][0]
            ["commandLine"] = serde_json::json!(["java", "-jar"]);
        assert!(GameRuntimeLock::parse_and_validate(
            &serde_json::to_vec(&unknown_receipt).unwrap()
        )
        .is_err());
    }

    #[test]
    fn game_runtime_rejects_unknown_fields_case_collisions_and_untrusted_urls() {
        let mut unknown = game_runtime_lock();
        unknown["identity"]["microsoftAccount"] = serde_json::json!(true);
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&unknown).unwrap()).is_err()
        );

        let mut collision = game_runtime_lock();
        let mut duplicate = collision["files"][0].clone();
        duplicate["path"] = serde_json::json!("VERSIONS/1.21.1/1.21.1.JSON");
        collision["files"].as_array_mut().unwrap().push(duplicate);
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&collision).unwrap()).is_err()
        );

        let mut untrusted = game_runtime_lock();
        untrusted["files"][2]["source"]["url"] =
            serde_json::json!("https://example.invalid/client.jar");
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&untrusted).unwrap()).is_err()
        );

        let mut unbound = game_runtime_lock();
        unbound["files"][2]["source"]["url"] = serde_json::json!(
            "https://piston-data.mojang.com/v1/objects/2222222222222222222222222222222222222222/client.jar"
        );
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&unbound).unwrap()).is_err()
        );
    }

    #[test]
    fn game_runtime_rejects_placeholder_scope_and_provenance_mismatches() {
        let mut wrong_scope = game_runtime_lock();
        wrong_scope["launch"]["jvmArguments"][1]["fragments"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "kind": "placeholder",
                "name": "fragmentUuid"
            }));
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&wrong_scope).unwrap())
                .is_err()
        );

        let mut mismatched = game_runtime_lock();
        mismatched["provenance"]["derivedOutputs"][0]["sha256"] = serde_json::json!("e".repeat(64));
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&mismatched).unwrap()).is_err()
        );
    }

    #[test]
    fn game_runtime_enforces_path_size_and_hash_bounds() {
        let mut long_path = game_runtime_lock();
        long_path["files"][6]["path"] = serde_json::json!(format!("{}.jar", "a".repeat(1021)));
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&long_path).unwrap()).is_err()
        );

        let mut oversized = game_runtime_lock();
        oversized["files"][6]["source"]["size"] = serde_json::json!(MAX_GAME_RUNTIME_FILE_SIZE + 1);
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&oversized).unwrap()).is_err()
        );

        let mut uppercase_hash = game_runtime_lock();
        uppercase_hash["files"][6]["source"]["sha256"] = serde_json::json!("A".repeat(64));
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&uppercase_hash).unwrap())
                .is_err()
        );
    }

    #[test]
    fn game_runtime_rejects_classpath_injection_unmanaged_files_and_extra_game_args() {
        let mut legacy_classpath = game_runtime_lock();
        legacy_classpath["launch"]["jvmArguments"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "kind": "literal",
                "value": "-DlegacyClassPath.file=C:/evil.jar"
            }));
        assert!(GameRuntimeLock::parse_and_validate(
            &serde_json::to_vec(&legacy_classpath).unwrap()
        )
        .is_err());

        let mut unmanaged = game_runtime_lock();
        unmanaged["files"][0]["path"] = serde_json::json!("options.txt");
        assert!(
            GameRuntimeLock::parse_and_validate(&serde_json::to_vec(&unmanaged).unwrap()).is_err()
        );

        let mut extra_game_argument = game_runtime_lock();
        extra_game_argument["launch"]["gameArguments"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({ "kind": "literal", "value": "--demo" }));
        assert!(GameRuntimeLock::parse_and_validate(
            &serde_json::to_vec(&extra_game_argument).unwrap()
        )
        .is_err());
    }

    #[test]
    fn accepts_spark2_release_canonical_verified_lock_fixture() {
        let bytes = include_bytes!(
            "../../tests/fixtures/game-runtime-lock-v2-release-canonical-verified.json"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            "9cdc76c6d62c4acfc50df8118a06c5556db3d0d420f2b14f2cdff565cf5b790d"
        );
        let lock = GameRuntimeLock::parse_and_validate(bytes)
            .expect("release canonical verified lock must validate");
        let expected_input_state_sha256 = lock
            .compute_expected_processor_input_state_sha256()
            .expect("release input-state digest must compute");
        assert_eq!(
            expected_input_state_sha256,
            "20fec19b3f653b795c99d19f81eaf26cfeee3fea628fcbb5341bfff4e8c2f838"
        );
        let resolver = &lock.provenance.resolver;
        for (actual, expected) in [
            (
                resolver.inputs_sha256.as_str(),
                "d5ae7f5dcbae9ed6833eebe9391ab28f32fc7409777f22485593ad4cb21c8b9a",
            ),
            (
                resolver.graph_sha256.as_str(),
                "345fa45f03dac17514fb1b5f0478ce7cff8707e9a12d02e326779f80d0af2115",
            ),
            (
                resolver.asset_graph_sha256.as_str(),
                "703069c481d8c718af6ee1a977d11154de37c9a8600c918c41155a565186327a",
            ),
            (
                resolver.runtime_library_graph_sha256.as_str(),
                "5702d4d81d7ef00f36b2eceb74f1bd8cd2fd139c3e0ff2801c3919f608bff5db",
            ),
            (
                resolver.installer_input_graph_sha256.as_str(),
                "bcb4dcc175b2bd39824b0027de90cb2fd4e09fc80de33a3a99f20d06deaae012",
            ),
            (
                resolver.download_graph_sha256.as_str(),
                "cbbb955688af601baede28dd9bbfd5ff1b7729787378e704017602fd73aa5b10",
            ),
            (
                resolver.launch_sha256.as_str(),
                "7ef64dc9a925e9edf372a9abd642a8d1719418768c4ab54ab8e35d47b90ded93",
            ),
            (
                resolver.upstream_plan_sha256.as_str(),
                NEOFORGE_UPSTREAM_PLAN_SHA256,
            ),
            (
                resolver.translation_sha256.as_str(),
                NEOFORGE_TRANSLATION_SHA256,
            ),
            (
                resolver.executable_plan_sha256.as_str(),
                NEOFORGE_EXECUTABLE_PLAN_SHA256,
            ),
            (
                resolver.materialization_graph_sha256.as_str(),
                NEOFORGE_MATERIALIZATION_GRAPH_SHA256,
            ),
            (
                resolver.metadata_declaration_sha256.as_str(),
                "d3935681db8b15f7a18e1976bfa15f9e9fa4eed4c671de90faf644ea7a415e97",
            ),
        ] {
            assert_eq!(actual, expected);
        }
        assert_eq!(
            resolver.resolver_artifact_sha256,
            "2be70ba8be14eded04da701a47456b28c2705de6504bccdf6adafc232b8da1cf"
        );
        lock.verification
            .offline_processors
            .bind_java_runtime(
                "d135386d574ea47405b34c19e8f9d43f55f9d207b3040302c168113e830e8e29",
                "a183e7280220ad5f6fe94ecbf025a5f10fc5797a0b18c600ed8f813c8158c530",
                "e3f526574b7fff9d20273fc9c183334e4e5287ef255912a6ffa418ccb9222d6b",
                "25.0.3+9",
            )
            .expect("release receipt must bind exact managed Java");
        match &lock.verification.offline_processors {
            OfflineProcessorVerification::Verified {
                resolver_artifact_sha256,
                executor_artifact_sha256,
                runs,
                receipt_sha256,
                ..
            } => {
                assert_eq!(
                    resolver_artifact_sha256,
                    "2be70ba8be14eded04da701a47456b28c2705de6504bccdf6adafc232b8da1cf"
                );
                assert_eq!(
                    executor_artifact_sha256,
                    "f5b57369631410ebac019a7d8e51988f46e95e339e308fe70c0f60e5edbc64fe"
                );
                assert_eq!(
                    receipt_sha256,
                    "091dbca682c3303ea2f1d69d0021be1323b49fad2e41d28d7a7f9e9019f49f68"
                );
                let expected_transient_artifacts = expected_transient_artifact_states();
                for run in runs.iter() {
                    assert_eq!(run.inputs_before_sha256, expected_input_state_sha256);
                    assert_eq!(run.inputs_after_sha256, expected_input_state_sha256);
                    assert_eq!(
                        &run.steps[2].removed_transient_artifacts,
                        &expected_transient_artifacts
                    );
                    for step in &run.steps {
                        assert_eq!(
                            step.transcript_sha256,
                            expected_processor_transcript_sha256(step)
                                .expect("release transcript digest must compute")
                        );
                    }
                    assert!(run
                        .steps
                        .iter()
                        .enumerate()
                        .all(|(index, step)| index == 2
                            || step.removed_transient_artifacts.is_empty()));
                }
            }
            OfflineProcessorVerification::Pending { .. } => panic!("expected verified receipt"),
        }
    }
}
