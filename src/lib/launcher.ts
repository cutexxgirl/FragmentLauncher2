import { invoke } from '@tauri-apps/api/core';

export type BuildChannel = 'stable' | 'dev';
export type BuildPreset = 'low' | 'medium' | 'high';
export type BuildPhase =
	| 'checking'
	| 'notInstalled'
	| 'outdated'
	| 'repairNeeded'
	| 'ready'
	| 'authorizing'
	| 'downloading'
	| 'updating'
	| 'repairing'
	| 'verifying'
	| 'launching'
	| 'running'
	| 'subscriptionRequired'
	| 'devForbidden'
	| 'authUnavailable'
	| 'diskInsufficient'
	| 'launcherUpdateRequired'
	| 'error';

export type BuildPrimaryAction =
	| 'download'
	| 'update'
	| 'repair'
	| 'play'
	| 'retry'
	| 'busy'
	| 'blocked';

export type BuildStatus = {
	operationId: string | null;
	revision: number;
	channel: BuildChannel;
	preset: BuildPreset;
	phase: BuildPhase;
	primaryAction: BuildPrimaryAction;
	installDirectory: string | null;
	installedReleaseId: string | null;
	availableReleaseId: string | null;
	message: string;
	operationActive: boolean;
	progress: {
		currentFile: string | null;
		downloadedBytes: number;
		totalBytes: number;
		speedBytesPerSecond: number;
		remainingBytes: number;
		diskFreeBytes: number;
		diskRequiredBytes: number;
	};
};

export function isPendingBuildInspection(status: BuildStatus): boolean {
	return (
		status.phase === 'checking' &&
		status.primaryAction === 'busy' &&
		!status.operationActive &&
		status.operationId === null
	);
}

export type ObservedBuildOperationStatus = {
	revision: number;
	fingerprint: string;
};

export function buildOperationStatusFingerprint(status: BuildStatus): string {
	return JSON.stringify([
		status.operationId,
		status.channel,
		status.preset,
		status.phase,
		status.primaryAction,
		status.installDirectory,
		status.installedReleaseId,
		status.availableReleaseId,
		status.message,
		status.operationActive,
		status.progress.currentFile,
		status.progress.downloadedBytes,
		status.progress.totalBytes,
		status.progress.speedBytesPerSecond,
		status.progress.remainingBytes,
		status.progress.diskFreeBytes,
		status.progress.diskRequiredBytes,
	]);
}

export function acceptsObservedOperationStatus(
	status: BuildStatus,
	observed: ObservedBuildOperationStatus | undefined,
): boolean {
	if (!observed) return true;
	if (status.revision > observed.revision) return true;
	return (
		status.revision === observed.revision &&
		buildOperationStatusFingerprint(status) === observed.fingerprint
	);
}

export type LauncherStatus = {
	appName: string;
	version: string;
	profile: string;
	servicesConnected: boolean;
	updaterReady: boolean;
};

export type TgWsProxyStatus = {
	supported: boolean;
	installed: boolean;
	running: boolean;
	version: string;
	path: string | null;
	shortcutPath: string | null;
	message: string;
};

const fallbackStatus: LauncherStatus = {
	appName: 'Fragment Launcher',
	version: '1.0.0',
	profile: 'singleplayer',
	servicesConnected: false,
	updaterReady: true,
};

const fallbackTgWsProxyStatus: TgWsProxyStatus = {
	supported: false,
	installed: false,
	running: false,
	version: 'v1.8.1',
	path: null,
	shortcutPath: null,
	message: 'TG WS Proxy доступен только в приложении лаунчера.',
};

export async function getLauncherStatus(): Promise<LauncherStatus> {
	try {
		return await invoke<LauncherStatus>('launcher_status');
	} catch {
		return fallbackStatus;
	}
}

export async function getBuildStatus(
	channel: BuildChannel,
	preset: BuildPreset,
	operationId?: string,
): Promise<BuildStatus> {
	return invoke<BuildStatus>('build_status', { channel, preset, operationId: operationId ?? null });
}

export async function startBuildOperation(
	channel: BuildChannel,
	preset: BuildPreset,
): Promise<BuildStatus> {
	return invoke<BuildStatus>('start_build_operation', { channel, preset });
}

export async function cancelBuildOperation(operationId: string): Promise<BuildStatus> {
	return invoke<BuildStatus>('cancel_build_operation', { operationId });
}

export async function setBuildInstallDirectory(
	path: string,
	channel: BuildChannel,
	preset: BuildPreset,
): Promise<BuildStatus> {
	return invoke<BuildStatus>('set_build_install_directory', { path, channel, preset });
}

export async function getTgWsProxyStatus(): Promise<TgWsProxyStatus> {
	try {
		return await invoke<TgWsProxyStatus>('tg_ws_proxy_status');
	} catch {
		return fallbackTgWsProxyStatus;
	}
}

export async function installTgWsProxy(): Promise<TgWsProxyStatus> {
	return await invoke<TgWsProxyStatus>('install_tg_ws_proxy');
}
