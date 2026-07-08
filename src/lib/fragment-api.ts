export type SubscriptionLevel = 'none' | 'novice' | 'legend' | 'spark';

export type LauncherProfile = {
	userId: string;
	launcherNick: string | null;
	launcherNickUpdatedAt?: string | null;
	launcherNickNextChangeAt?: string | null;
	telegramId: string | null;
	username: string | null;
	firstName: string | null;
	lastName: string | null;
	avatarUrl?: string | null;
	telegramAvatarUrl?: string | null;
	photoUrl?: string | null;
	fid: string | null;
	subscriptionLevel: SubscriptionLevel;
	entitlement: {
		active: boolean;
		level: SubscriptionLevel;
		expiresAt: string | null;
		recalculatedAt: string | null;
	};
};

export type LauncherAuthSession = {
	tokenType: 'Bearer';
	accessToken: string;
	refreshToken: string;
	expiresIn: number;
	profile: LauncherProfile;
};

export type TelegramLoginChallenge = {
	challengeId: string;
	status: 'pending';
	expiresAt: string;
	pollToken: string;
	telegramLink: string;
};

export type TelegramLoginPollResult =
	| {
			status: 'pending' | 'expired' | 'consumed';
			expiresAt: string;
	  }
	| (LauncherAuthSession & {
			status: 'confirmed';
			expiresAt: string;
	  });

const API_BASE_URL = (
	import.meta.env.VITE_FRAGMENT_API_BASE_URL ?? 'https://fragmc.ru/fragment-api'
).replace(/\/+$/, '');

const SESSION_STORAGE_KEY = 'fragment.launcher.authSession.v1';

export function getUserAvatarUrl(userId: string): string {
	return `${API_BASE_URL}/users/${encodeURIComponent(userId)}/avatar`;
}

export function loadStoredAuthSession(): LauncherAuthSession | null {
	if (typeof localStorage === 'undefined') {
		return null;
	}

	const raw = localStorage.getItem(SESSION_STORAGE_KEY);
	if (!raw) {
		return null;
	}

	try {
		return JSON.parse(raw) as LauncherAuthSession;
	} catch {
		localStorage.removeItem(SESSION_STORAGE_KEY);
		return null;
	}
}

export function storeAuthSession(session: LauncherAuthSession) {
	if (typeof localStorage === 'undefined') {
		return;
	}

	localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
}

export function clearStoredAuthSession() {
	if (typeof localStorage === 'undefined') {
		return;
	}

	localStorage.removeItem(SESSION_STORAGE_KEY);
}

export async function createTelegramLoginChallenge(deviceName = 'Fragment Launcher') {
	return request<TelegramLoginChallenge>('/auth/telegram/challenges', {
		method: 'POST',
		body: JSON.stringify({ deviceName }),
	});
}

export async function pollTelegramLoginChallenge(challengeId: string, pollToken: string) {
	return request<TelegramLoginPollResult>(`/auth/telegram/challenges/${challengeId}/poll`, {
		method: 'POST',
		body: JSON.stringify({ pollToken }),
	});
}

export async function refreshAuthSession(refreshToken: string) {
	const refreshed = await request<Omit<LauncherAuthSession, 'refreshToken'>>('/auth/refresh', {
		method: 'POST',
		body: JSON.stringify({ refreshToken }),
	});

	return {
		...refreshed,
		refreshToken,
	} satisfies LauncherAuthSession;
}

export async function logoutAuthSession(refreshToken: string) {
	await request<{ ok: boolean }>('/auth/logout', {
		method: 'POST',
		body: JSON.stringify({ refreshToken }),
	});
}

export async function getCurrentProfile(accessToken: string) {
	return request<LauncherProfile>('/auth/me', {
		method: 'GET',
		headers: {
			authorization: `Bearer ${accessToken}`,
		},
	});
}

export async function updateLauncherNickname(accessToken: string, nickname: string | null) {
	return request<LauncherProfile>('/auth/me/nickname', {
		method: 'PATCH',
		headers: {
			authorization: `Bearer ${accessToken}`,
		},
		body: JSON.stringify({ nickname }),
	});
}

async function request<T>(path: string, init: RequestInit): Promise<T> {
	const response = await fetch(`${API_BASE_URL}${path}`, {
		...init,
		headers: {
			accept: 'application/json',
			'content-type': 'application/json',
			...(init.headers as Record<string, string> | undefined),
		},
	});

	if (!response.ok) {
		const payload = (await response.json().catch(() => null)) as
			| { message?: string; error?: string | { message?: string } }
			| null;
		const message =
			payload?.message ||
			(typeof payload?.error === 'string' ? payload.error : payload?.error?.message) ||
			`Fragment API responded with ${response.status}`;
		throw new Error(message);
	}

	return (await response.json()) as T;
}
