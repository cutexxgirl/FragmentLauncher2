import { invoke } from '@tauri-apps/api/core';

export type SubscriptionLevel = 'none' | 'novice' | 'legend' | 'spark';
export type LauncherRole = 'player' | 'tester' | 'developer';
export type AdmissionChannel = 'stable' | 'dev';

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
	launcherRole: LauncherRole;
	launcherPermissions: string[];
	subscriptionLevel: SubscriptionLevel;
	entitlement: {
		active: boolean;
		level: SubscriptionLevel;
		expiresAt: string | null;
		recalculatedAt: string | null;
	};
};

export type AuthSnapshot = {
	authenticated: boolean;
	profile: LauncherProfile | null;
};

export type TelegramLoginSnapshot = {
	expiresAt: string;
};

export type TelegramPollSnapshot =
	| { status: 'pending' | 'expired' | 'consumed'; expiresAt: string }
	| { status: 'confirmed'; expiresAt: string; auth: AuthSnapshot };

export type LauncherAdmissionReason =
	| 'subscription_required'
	| 'launcher_nickname_required'
	| 'dev_access_required'
	| 'account_banned'
	| 'entitlement_verification_unavailable'
	| 'launcher_admission_unavailable'
	| 'launcher_admission_busy'
	| 'invalid_session';

export type LauncherAdmissionSnapshot = {
	allowed: boolean;
	channel: AdmissionChannel;
	reason: LauncherAdmissionReason | null;
	profile: LauncherProfile | null;
	role: LauncherRole | null;
};

const LEGACY_WEBVIEW_SESSION_KEY = 'fragment.launcher.authSession.v1';

/** Delete-only cleanup. Legacy bearer/refresh tokens are never read or imported. */
export function discardLegacyWebviewAuthSession() {
	if (typeof localStorage !== 'undefined') {
		localStorage.removeItem(LEGACY_WEBVIEW_SESSION_KEY);
	}
}

export function restoreNativeAuth(): Promise<AuthSnapshot> {
	return invoke<AuthSnapshot>('auth_restore');
}

export function beginNativeTelegramLogin(): Promise<TelegramLoginSnapshot> {
	return invoke<TelegramLoginSnapshot>('auth_begin_login');
}

export function pollNativeTelegramLogin(): Promise<TelegramPollSnapshot> {
	return invoke<TelegramPollSnapshot>('auth_poll_login');
}

export function refreshNativeProfile(): Promise<AuthSnapshot> {
	return invoke<AuthSnapshot>('auth_refresh_profile');
}

export function updateNativeNickname(nickname: string | null): Promise<AuthSnapshot> {
	return invoke<AuthSnapshot>('auth_update_nickname', { nickname });
}

export function logoutNativeAuth(): Promise<AuthSnapshot> {
	return invoke<AuthSnapshot>('auth_logout');
}

export function requestNativeAdmission(
	channel: AdmissionChannel,
): Promise<LauncherAdmissionSnapshot> {
	return invoke<LauncherAdmissionSnapshot>('auth_admission', { channel });
}
