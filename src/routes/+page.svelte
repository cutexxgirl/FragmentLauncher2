<script lang="ts">
	import '$lib/styles/launcher.css';
	import { Gamepad2 } from '@lucide/svelte';
	import { onMount } from 'svelte';
	import { getCurrentWindow } from '@tauri-apps/api/window';
	import { LogicalSize } from '@tauri-apps/api/dpi';
	import { open } from '@tauri-apps/plugin-dialog';
	import {
		beginNativeTelegramLogin,
		discardLegacyWebviewAuthSession,
		logoutNativeAuth,
		pollNativeTelegramLogin,
		requestNativeAdmission,
		restoreNativeAuth,
		updateNativeNickname,
		type AuthSnapshot,
		type LauncherAdmissionReason,
		type LauncherProfile,
	} from '$lib/native-auth';
	import {
		getLauncherStatus,
		getBuildStatus,
		getTgWsProxyStatus,
		installTgWsProxy,
		setBuildInstallDirectory,
		type BuildChannel,
		type BuildStatus,
		type TgWsProxyStatus,
	} from '$lib/launcher';
	import {
		createBuildProfiles,
		feedImages,
		feedItems,
		presets,
		type BuildProfile,
		type PresetId,
		type SectionId,
	} from '$lib/launcher-ui';
	import AuthGate from '$lib/components/launcher/AuthGate.svelte';
	import BootScreen from '$lib/components/launcher/BootScreen.svelte';
	import HomeSection from '$lib/components/launcher/HomeSection.svelte';
	import LauncherSettingsWindow from '$lib/components/launcher/LauncherSettingsWindow.svelte';
	import MobileNav from '$lib/components/launcher/MobileNav.svelte';
	import ProfileWindow from '$lib/components/launcher/ProfileWindow.svelte';
	import SettingsWindow from '$lib/components/launcher/SettingsWindow.svelte';
	import Sidebar from '$lib/components/launcher/Sidebar.svelte';
	import StatsWindow from '$lib/components/launcher/StatsWindow.svelte';
	import SupportWindow from '$lib/components/launcher/SupportWindow.svelte';
	import TelegramHelpWindow from '$lib/components/launcher/TelegramHelpWindow.svelte';
	import TitleBar from '$lib/components/launcher/TitleBar.svelte';

	type BootPhase = 'boot' | 'expanding' | 'reveal' | 'ready';
	type AuthState = 'checking' | 'signed-out' | 'waiting' | 'signed-in' | 'error';

	const FIXED_WINDOW_SIZE = new LogicalSize(1244, 764);

	let bootProgress = $state(0.08);
	let bootLabel = $state('Поднимаем оболочку');
	let bootPhase = $state<BootPhase>('boot');
	let activeSection = $state<SectionId>('home');
	let selectedBuildId = $state('fragment-stable');
	let nickname = $state('');
	let nicknameSaveMessage = $state('');
	let nicknameSaving = $state(false);
	let supportTopic = $state('');
	let supportDescription = $state('');
	let attachCrashReport = $state(true);
	let attachLastLog = $state(true);
	let attachLastScreenshot = $state(false);
	let settingsVisible = $state(false);
	let launcherSettingsVisible = $state(false);
	let supportVisible = $state(false);
	let profileVisible = $state(false);
	let statsVisible = $state(false);
	let supportSent = $state(false);
	let launcherVersion = $state('1.0.0');
	let anonymizeAnalytics = $state(true);
	let includeDiagnosticsInSupport = $state(false);
	let appWindow = $state<ReturnType<typeof getCurrentWindow> | null>(null);
	let authSnapshot = $state<AuthSnapshot | null>(null);
	let authState = $state<AuthState>('checking');
	let showTelegramHelpPill = $state(false);
	let telegramHelpVisible = $state(false);
	let tgWsProxyStatus = $state<TgWsProxyStatus | null>(null);
	let tgWsProxyBusy = $state(false);
	let tgWsProxyMessage = $state('');
	let loginPollTimer: number | null = null;
	let telegramHelpTimer: number | null = null;

	let builds = $state<BuildProfile[]>(createBuildProfiles());
	let buildStatusRequestGeneration = 0;
	let buildStatus = $state<BuildStatus>({
		channel: 'stable',
		preset: 'medium',
		phase: 'checking',
		primaryAction: 'busy',
		installDirectory: null,
		installedReleaseId: null,
		availableReleaseId: null,
		message: 'Проверяем состояние сборки…',
		operationActive: false,
		progress: {
			currentFile: null,
			downloadedBytes: 0,
			totalBytes: 0,
			speedBytesPerSecond: 0,
			remainingBytes: 0,
			diskFreeBytes: 0,
			diskRequiredBytes: 0,
		},
	});

	let bootVisible = $derived(bootPhase !== 'ready');
	let launcherVisible = $derived(bootPhase === 'reveal' || bootPhase === 'ready');
	let userIsSignedIn = $derived(
		authState === 'signed-in' && authSnapshot?.authenticated === true && authSnapshot.profile !== null,
	);
	let appVisible = $derived(launcherVisible && userIsSignedIn);
	let authGateVisible = $derived(launcherVisible && !userIsSignedIn);
	let activeBuild = $derived(builds.find((build) => build.id === selectedBuildId) ?? builds[0]);
	let activeChannel = $derived<BuildChannel>(activeBuild.channel);
	let hasActiveSubscription = $derived(authSnapshot?.profile?.entitlement.active ?? false);
	let subscriptionName = $derived(
		({
			none: 'Нет доступа',
			novice: 'Новичок',
			legend: 'Легенда',
			spark: 'Искра',
		})[authSnapshot?.profile?.entitlement.level ?? 'none'],
	);
	let hasDevAccess = $derived(
		authSnapshot?.profile?.launcherPermissions?.includes('launcher.channel.dev') ?? false,
	);
	let visibleBuilds = $derived(builds.filter((build) => build.channel === 'stable' || hasDevAccess));
	let availableBuildsCount = $derived(
		builds.filter(
			(build) =>
				hasActiveSubscription && (build.channel === 'stable' || (build.channel === 'dev' && hasDevAccess)),
		).length,
	);
	let telegramAccount = $derived(formatTelegramAccount(authSnapshot?.profile ?? undefined));
	let telegramAvatarUrl = $derived(resolveTelegramAvatarUrl(authSnapshot?.profile ?? undefined));
	let savedLauncherNick = $derived(authSnapshot?.profile?.launcherNick ?? '');
	let nicknameDirty = $derived(normalizeLauncherNickname(nickname) !== savedLauncherNick);
	let supportReady = $derived(
		supportTopic.trim().length > 2 && supportDescription.trim().length > 12,
	);

	$effect(() => {
		if (!visibleBuilds.some((build) => build.id === selectedBuildId)) {
			selectedBuildId = 'fragment-stable';
		}
	});

	$effect(() => {
		if (authState === 'signed-in') {
			authSnapshot?.profile?.entitlement.active;
			authSnapshot?.profile?.launcherPermissions;
			void refreshBuildStatus();
		}
	});

	const navigation = [
		{ id: 'home', label: 'Главная', mobileLabel: 'Главная', icon: Gamepad2 },
	] satisfies Array<{ id: SectionId; label: string; mobileLabel: string; icon: typeof Gamepad2 }>;

	onMount(() => {
		discardLegacyWebviewAuthSession();
		if ('__TAURI_INTERNALS__' in window) {
			appWindow = getCurrentWindow();
			void configureFixedWindow();
		}

		void restoreAuthSession();
		void refreshBuildStatus();
		void runBootSequence();

		return () => {
			stopLoginPolling();
			stopTelegramHelpTimer();
		};
	});

	async function configureFixedWindow() {
		if (!appWindow) {
			return;
		}

		const windowTasks = [
			() => appWindow?.setSize(FIXED_WINDOW_SIZE),
			() => appWindow?.setMinSize(FIXED_WINDOW_SIZE),
			() => appWindow?.setMaxSize(FIXED_WINDOW_SIZE),
			() => appWindow?.setResizable(false),
			() => appWindow?.setMaximizable(false),
			() => appWindow?.center(),
		];

		for (const task of windowTasks) {
			try {
				await task();
			} catch (error) {
				console.warn('Window configuration step failed', error);
			}
		}
	}

	function setBootStep(progress: number, label: string) {
		bootProgress = progress;
		bootLabel = label;
	}

	function delay(ms: number) {
		return new Promise((resolve) => window.setTimeout(resolve, ms));
	}

	async function runBootSequence() {
		setBootStep(0.18, 'Готовим интерфейс');
		await delay(80);

		setBootStep(0.46, 'Подключаем локальный бэкенд');
		const launcherStatus = await getLauncherStatus();
		launcherVersion = launcherStatus.version;
		await delay(80);

		setBootStep(0.68, 'Проверяем профиль сборки');
		await delay(80);

		setBootStep(0.84, 'Разворачиваем лаунчер');
		bootPhase = 'expanding';
		await delay(620);

		setBootStep(1, 'Готово');
		await delay(80);
		bootPhase = 'reveal';
		await delay(420);
		bootPhase = 'ready';
	}

	async function restoreAuthSession() {
		authState = 'checking';
		try {
			const restored = await restoreNativeAuth();
			authSnapshot = restored;
			if (restored.authenticated && restored.profile) {
				syncNicknameFromProfile(restored.profile);
				authState = 'signed-in';
				resetTelegramHelpPill();
				telegramHelpVisible = false;
			} else {
				authState = 'signed-out';
			}
		} catch (error) {
			console.warn('Native auth restore failed', error);
			authSnapshot = null;
			authState = 'error';
		}
	}

	async function loginWithTelegram() {
		if (authState === 'checking' || authState === 'waiting') {
			return;
		}

		stopLoginPolling();
		showTelegramHelpPill = false;
		authState = 'waiting';
		scheduleTelegramHelpPill();

		try {
			const challenge = await beginNativeTelegramLogin();
			void pollLoginChallenge(challenge.expiresAt);
		} catch (error) {
			console.warn('Telegram login failed', error);
			stopTelegramHelpTimer();
			showTelegramHelpPill = true;
			authState = 'error';
		}
	}

	async function pollLoginChallenge(expiresAt: string) {
		if (authState !== 'waiting') {
			return;
		}

		if (Date.now() > new Date(expiresAt).getTime()) {
			authState = 'error';
			return;
		}

		try {
			const result = await pollNativeTelegramLogin();
			if (result.status === 'confirmed') {
				authSnapshot = result.auth;
				if (!result.auth.authenticated || !result.auth.profile) {
					authState = 'signed-out';
					return;
				}
				syncNicknameFromProfile(result.auth.profile);
				authState = 'signed-in';
				resetTelegramHelpPill();
				telegramHelpVisible = false;
				return;
			}

			if (result.status === 'expired' || result.status === 'consumed') {
				stopTelegramHelpTimer();
				showTelegramHelpPill = true;
				authState = 'error';
				return;
			}
		} catch (error) {
			console.warn('Telegram login poll failed', error);
			stopTelegramHelpTimer();
			showTelegramHelpPill = true;
			authState = 'error';
			return;
		}

		loginPollTimer = window.setTimeout(() => {
			void pollLoginChallenge(expiresAt);
		}, 1800);
	}

	async function logoutFromTelegram() {
		stopLoginPolling();
		nicknameSaveMessage = 'Завершаем сессию…';
		try {
			const signedOut = await logoutNativeAuth();
			if (signedOut.authenticated) {
				throw new Error('Native auth did not confirm logout');
			}
			authSnapshot = null;
			authState = 'signed-out';
			nickname = '';
			nicknameSaveMessage = '';
			resetTelegramHelpPill();
			telegramHelpVisible = false;
			settingsVisible = false;
			launcherSettingsVisible = false;
			supportVisible = false;
			profileVisible = false;
			statsVisible = false;
			activeSection = 'home';
		} catch (error) {
			console.warn('Native logout was not completed', error);
			nicknameSaveMessage = 'Не удалось безопасно выйти. Повторите попытку.';
		}
	}

	function stopLoginPolling() {
		if (loginPollTimer) {
			window.clearTimeout(loginPollTimer);
			loginPollTimer = null;
		}
	}

	function scheduleTelegramHelpPill() {
		stopTelegramHelpTimer();

		telegramHelpTimer = window.setTimeout(() => {
			if (authState === 'waiting') {
				showTelegramHelpPill = true;
			}

			telegramHelpTimer = null;
		}, 7000);
	}

	function stopTelegramHelpTimer() {
		if (telegramHelpTimer) {
			window.clearTimeout(telegramHelpTimer);
			telegramHelpTimer = null;
		}
	}

	function resetTelegramHelpPill() {
		stopTelegramHelpTimer();
		showTelegramHelpPill = false;
	}

	async function openTelegramHelp() {
		telegramHelpVisible = true;
		await refreshTgWsProxyStatus();
	}

	async function refreshTgWsProxyStatus() {
		tgWsProxyStatus = await getTgWsProxyStatus();
		tgWsProxyMessage = tgWsProxyStatus.running
			? 'TG WS Proxy работает. Подтвердите прокси в Telegram и повторите вход.'
			: tgWsProxyStatus.message;
	}

	async function installTelegramProxy() {
		if (tgWsProxyBusy) {
			return;
		}

		tgWsProxyBusy = true;
		tgWsProxyMessage = 'Скачиваем TG WS Proxy';

		try {
			tgWsProxyStatus = await installTgWsProxy();
			tgWsProxyMessage = tgWsProxyStatus.running
				? 'TG WS Proxy работает. Подтвердите прокси в Telegram и повторите вход.'
				: tgWsProxyStatus.message;
		} catch (error) {
			tgWsProxyMessage = error instanceof Error ? error.message : 'Не удалось установить TG WS Proxy';
		} finally {
			tgWsProxyBusy = false;
		}
	}

	function syncNicknameFromProfile(profile: LauncherProfile) {
		nickname = profile.launcherNick ?? '';
		nicknameSaveMessage = '';
	}

	function normalizeLauncherNickname(value: string) {
		return value.trim().replace(/[^a-zA-Z0-9_]/g, '').slice(0, 16);
	}

	async function saveLauncherNickname() {
		const currentProfile = authSnapshot?.profile;
		if (!currentProfile || nicknameSaving) {
			return;
		}

		const nextNickname = normalizeLauncherNickname(nickname);
		nickname = nextNickname;

		if (nextNickname === (currentProfile.launcherNick ?? '')) {
			nicknameSaveMessage = '';
			return;
		}

		nicknameSaving = true;
		nicknameSaveMessage = '';

		try {
			const updated = await updateNativeNickname(nextNickname || null);
			authSnapshot = updated;
			if (!updated.authenticated || !updated.profile) {
				authState = 'signed-out';
				return;
			}
			const profile = updated.profile;
			syncNicknameFromProfile(profile);
			nicknameSaveMessage = profile.launcherNick ? 'Ник сохранён' : 'Ник очищен';
		} catch (error) {
			nicknameSaveMessage = error instanceof Error ? error.message : 'Не удалось сохранить ник';
		} finally {
			nicknameSaving = false;
		}
	}

	function selectBuild(buildId: string) {
		const build = visibleBuilds.find((candidate) => candidate.id === buildId);
		if (!build) return;
		selectedBuildId = buildId;
		window.setTimeout(() => void refreshBuildStatus(), 0);
	}

	function openSection(section: SectionId) {
		if (section === 'support') {
			supportVisible = true;
			return;
		}

		if (section === 'profile') {
			profileVisible = true;
			return;
		}

		activeSection = section;
	}

	function closeProfileWindow() {
		profileVisible = false;
		nicknameSaveMessage = '';
	}

	function setPreset(presetId: PresetId) {
		activeBuild.preset = presetId;

		void refreshBuildStatus();
	}

	async function refreshBuildStatus() {
		if (!(typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window)) return;
		const requestGeneration = ++buildStatusRequestGeneration;
		const channel = activeChannel;
		const preset = activeBuild.preset;
		try {
			const localStatus = await getBuildStatus(channel, preset);
			if (!isCurrentBuildRequest(requestGeneration, channel, preset)) return;
			buildStatus = localStatus;
		} catch (error) {
			if (!isCurrentBuildRequest(requestGeneration, channel, preset)) return;
			buildStatus = errorBuildStatus(
				channel,
				preset,
				error instanceof Error ? error.message : 'Не удалось проверить сборку.',
			);
		}
	}

	async function chooseInstallDirectory() {
		try {
			const selected = await open({ directory: true, multiple: false, title: 'Папка Fragment' });
			if (typeof selected !== 'string') return;
			const requestGeneration = ++buildStatusRequestGeneration;
			const channel = activeChannel;
			const preset = activeBuild.preset;
			const localStatus = await setBuildInstallDirectory(selected, channel, preset);
			if (!isCurrentBuildRequest(requestGeneration, channel, preset)) return;
			buildStatus = localStatus;
		} catch (error) {
			buildStatus = errorBuildStatus(
				activeChannel,
				activeBuild.preset,
				error instanceof Error ? error.message : 'Не удалось выбрать папку Fragment.',
			);
		}
	}

	function errorBuildStatus(channel: BuildChannel, preset: PresetId, message: string): BuildStatus {
		return {
			channel,
			preset,
			phase: 'error',
			primaryAction: 'blocked',
			installDirectory: buildStatus.installDirectory,
			installedReleaseId: null,
			availableReleaseId: null,
			message,
			operationActive: false,
			progress: {
				currentFile: null,
				downloadedBytes: 0,
				totalBytes: 0,
				speedBytesPerSecond: 0,
				remainingBytes: 0,
				diskFreeBytes: 0,
				diskRequiredBytes: 0,
			},
		};
	}

	function isCurrentBuildRequest(
		requestGeneration: number,
		channel: BuildChannel,
		preset: PresetId,
	) {
		return (
			requestGeneration === buildStatusRequestGeneration &&
			channel === activeChannel &&
			preset === activeBuild.preset
		);
	}

	async function handlePrimaryBuildAction() {
		if (buildStatus.primaryAction === 'download' && !buildStatus.installDirectory) {
			await chooseInstallDirectory();
			return;
		}
		if (buildStatus.primaryAction === 'play') {
			const requestGeneration = ++buildStatusRequestGeneration;
			const channel = activeChannel;
			const preset = activeBuild.preset;
			buildStatus = {
				...buildStatus,
				phase: 'authorizing',
				primaryAction: 'busy',
				message: 'Проверяем право на запуск через FragmentApi…',
				operationActive: true,
			};
			try {
				const admission = await requestNativeAdmission(channel);
				if (!isCurrentBuildRequest(requestGeneration, channel, preset)) return;
				if (!admission.allowed) {
					if (admission.reason === 'invalid_session') {
						authSnapshot = null;
						authState = 'signed-out';
					}
					buildStatus = admissionDeniedBuildStatus(channel, preset, admission.reason);
					return;
				}
				if (admission.profile) {
					authSnapshot = { authenticated: true, profile: admission.profile };
				}
				buildStatus = errorBuildStatus(
					channel,
					preset,
					'FragmentApi подтвердил доступ, но запуск Java пока не подключён.',
				);
			} catch (error) {
				if (!isCurrentBuildRequest(requestGeneration, channel, preset)) return;
				buildStatus = {
					...errorBuildStatus(
						channel,
						preset,
						error instanceof Error ? error.message : 'FragmentApi не подтвердил право на запуск.',
					),
					phase: 'authUnavailable',
				};
			}
			return;
		}
		buildStatus = errorBuildStatus(
			activeChannel,
			activeBuild.preset,
			'Операция ещё не подключена в этой dev-ветке лаунчера.',
		);
	}

	function admissionDeniedBuildStatus(
		channel: BuildChannel,
		preset: PresetId,
		reason: LauncherAdmissionReason | null,
	): BuildStatus {
		const denied = (phase: BuildStatus['phase'], message: string) => ({
			...errorBuildStatus(channel, preset, message),
			phase,
		});
		switch (reason) {
			case 'subscription_required':
				return denied(
					'subscriptionRequired',
					'Для запуска нужна активная подписка либо подаренный доступ.',
				);
			case 'dev_access_required':
				return denied('devForbidden', 'Dev-сборку могут запускать только тестеры и разработчики.');
			case 'launcher_nickname_required':
				return denied('error', 'Перед запуском укажите игровой ник в профиле лаунчера.');
			case 'account_banned':
				return denied('error', 'Для этого аккаунта запуск Fragment запрещён.');
			case 'invalid_session':
				return denied('authUnavailable', 'Сессия завершена. Войдите через Telegram снова.');
			case 'entitlement_verification_unavailable':
			case 'launcher_admission_busy':
			case 'launcher_admission_unavailable':
			default:
				return denied(
					'authUnavailable',
					'Не удалось подтвердить право на запуск через FragmentApi. Попробуйте ещё раз.',
				);
		}
	}

	function submitSupportRequest(event: SubmitEvent) {
		event.preventDefault();

		if (!supportReady) {
			return;
		}

		supportSent = true;
	}

	async function minimize() {
		await appWindow?.minimize();
	}

	async function closeWindow() {
		await appWindow?.close();
	}

	async function startDrag() {
		await appWindow?.startDragging();
	}

	function formatTelegramAccount(profile: LauncherProfile | undefined) {
		if (!profile) {
			return 'Telegram не подключён';
		}

		if (profile.username) {
			return `@${profile.username}`;
		}

		return profile.telegramId ? `ID ${profile.telegramId}` : 'Telegram подключён, имя не указано';
	}

	function resolveTelegramAvatarUrl(profile: LauncherProfile | undefined) {
		if (!profile) {
			return null;
		}

		return (
			profile.avatarUrl ??
			profile.telegramAvatarUrl ??
			profile.photoUrl ??
			null
		);
	}
</script>

<svelte:head>
	<title>Fragment Launcher</title>
</svelte:head>

<div class:expanded={bootPhase !== 'boot'} class="window-stage fixed inset-0 overflow-hidden">
	<main
		class="app-shell absolute overflow-hidden rounded-[30px] border border-border bg-background text-foreground"
	>
		{#if bootVisible}
			<BootScreen {bootPhase} {bootProgress} {bootLabel} {startDrag} />
		{/if}

		{#if authGateVisible}
			<AuthGate
				{authState}
				showTelegramHelp={showTelegramHelpPill}
				{loginWithTelegram}
				{openTelegramHelp}
				{startDrag}
				{minimize}
				{closeWindow}
			/>
		{/if}

		{#if telegramHelpVisible}
			<TelegramHelpWindow
				proxyStatus={tgWsProxyStatus}
				proxyBusy={tgWsProxyBusy}
				proxyMessage={tgWsProxyMessage}
				closeTelegramHelp={() => (telegramHelpVisible = false)}
				{installTelegramProxy}
			/>
		{/if}

		<div class:visible={appVisible} class="launcher-layout">
			<Sidebar {navigation} setActiveSection={openSection} />

			<section class="main-surface flex min-w-0 flex-col">
				<TitleBar
					{startDrag}
					{minimize}
					{closeWindow}
					openSupport={() => (supportVisible = true)}
					openProfile={() => (profileVisible = true)}
					openStats={() => (statsVisible = true)}
					openSettings={() => (launcherSettingsVisible = true)}
				/>

				<MobileNav {navigation} {activeSection} setActiveSection={openSection} />

				<div class="workspace min-h-0 flex-1 overflow-y-auto px-6 py-6">
					{#if activeSection === 'home'}
						<HomeSection
							builds={visibleBuilds}
							{activeBuild}
							{selectedBuildId}
							{feedItems}
							{feedImages}
							{buildStatus}
							{selectBuild}
							openSettings={() => (settingsVisible = true)}
							primaryAction={handlePrimaryBuildAction}
						/>
					{/if}
				</div>
			</section>
		</div>

		{#if settingsVisible}
			<SettingsWindow
				{activeBuild}
				{presets}
				installDirectory={buildStatus.installDirectory}
				closeSettings={() => (settingsVisible = false)}
				{setPreset}
				{chooseInstallDirectory}
			/>
		{/if}

		{#if launcherSettingsVisible}
			<LauncherSettingsWindow
				{launcherVersion}
				bind:anonymizeAnalytics
				bind:includeDiagnosticsInSupport
				closeLauncherSettings={() => (launcherSettingsVisible = false)}
			/>
		{/if}

		{#if supportVisible}
			<SupportWindow
				bind:supportTopic
				bind:supportDescription
				bind:attachCrashReport
				bind:attachLastLog
				bind:attachLastScreenshot
				{supportReady}
				{supportSent}
				closeSupport={() => (supportVisible = false)}
				{submitSupportRequest}
			/>
		{/if}

		{#if profileVisible}
			<ProfileWindow
				{builds}
				bind:nickname
				{telegramAccount}
				{telegramAvatarUrl}
				{nicknameDirty}
				{nicknameSaving}
				{nicknameSaveMessage}
				{availableBuildsCount}
				subscriptionActive={hasActiveSubscription}
				{subscriptionName}
				{hasDevAccess}
				{saveLauncherNickname}
				{logoutFromTelegram}
				closeProfile={closeProfileWindow}
			/>
		{/if}

		{#if statsVisible}
			<StatsWindow {activeBuild} closeStats={() => (statsVisible = false)} />
		{/if}
	</main>
</div>
