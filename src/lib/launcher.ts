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

export type BuildPrimaryAction = 'download' | 'update' | 'repair' | 'play' | 'busy' | 'blocked';

export type BuildStatus = {
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
): Promise<BuildStatus> {
	return invoke<BuildStatus>('build_status', { channel, preset });
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
