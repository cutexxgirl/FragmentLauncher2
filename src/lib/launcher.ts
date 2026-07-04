import { invoke } from '@tauri-apps/api/core';

export type LauncherStatus = {
	appName: string;
	version: string;
	profile: string;
	servicesConnected: boolean;
	updaterReady: boolean;
};

const fallbackStatus: LauncherStatus = {
	appName: 'Fragment Launcher',
	version: '1.0.0',
	profile: 'singleplayer',
	servicesConnected: false,
	updaterReady: true,
};

function isAllowedExternalUrl(url: string): boolean {
	return (
		url.startsWith('https://t.me/') ||
		url.startsWith('https://telegram.me/') ||
		url.startsWith('tg://')
	);
}

export async function getLauncherStatus(): Promise<LauncherStatus> {
	try {
		return await invoke<LauncherStatus>('launcher_status');
	} catch {
		return fallbackStatus;
	}
}

export async function openExternalUrl(url: string): Promise<void> {
	if (!isAllowedExternalUrl(url)) {
		throw new Error('External URL is not allowed');
	}

	try {
		await invoke('open_external_url', { url });
		return;
	} catch {
		window.open(url, '_blank', 'noopener,noreferrer');
	}
}
