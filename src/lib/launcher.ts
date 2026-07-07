import { invoke } from '@tauri-apps/api/core';

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

export function toTelegramAppUrl(url: string): string {
	if (url.startsWith('tg://')) {
		return url;
	}

	try {
		const parsedUrl = new URL(url);
		const host = parsedUrl.hostname.toLowerCase();

		if (host !== 't.me' && host !== 'telegram.me') {
			return url;
		}

		const [domain] = parsedUrl.pathname.split('/').filter(Boolean);

		if (!domain) {
			return url;
		}

		const telegramParams = new URLSearchParams({ domain });
		parsedUrl.searchParams.forEach((value, key) => {
			telegramParams.set(key, value);
		});

		return `tg://resolve?${telegramParams.toString()}`;
	} catch {
		return url;
	}
}

export async function openTelegramAppUrl(url: string): Promise<void> {
	await openExternalUrl(toTelegramAppUrl(url));
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
