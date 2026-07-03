<script lang="ts">
	import '$lib/styles/launcher.css';
	import { Gamepad2 } from '@lucide/svelte';
	import { onMount } from 'svelte';
	import { getCurrentWindow } from '@tauri-apps/api/window';
	import { LogicalSize } from '@tauri-apps/api/dpi';
	import {
		clearStoredAuthSession,
		createTelegramLoginChallenge,
		getCurrentProfile,
		loadStoredAuthSession,
		logoutAuthSession,
		pollTelegramLoginChallenge,
		refreshAuthSession,
		storeAuthSession,
		type LauncherAuthSession,
		type LauncherProfile,
	} from '$lib/fragment-api';
	import { getLauncherStatus } from '$lib/launcher';
	import {
		createBuildProfiles,
		feedImages,
		feedItems,
		presets,
		type BuildProfile,
		type PresetId,
		type SectionId,
	} from '$lib/launcher-ui';
	import BootScreen from '$lib/components/launcher/BootScreen.svelte';
	import HomeSection from '$lib/components/launcher/HomeSection.svelte';
	import LauncherSettingsWindow from '$lib/components/launcher/LauncherSettingsWindow.svelte';
	import MobileNav from '$lib/components/launcher/MobileNav.svelte';
	import ProfileWindow from '$lib/components/launcher/ProfileWindow.svelte';
	import SettingsWindow from '$lib/components/launcher/SettingsWindow.svelte';
	import Sidebar from '$lib/components/launcher/Sidebar.svelte';
	import StatsWindow from '$lib/components/launcher/StatsWindow.svelte';
	import SupportWindow from '$lib/components/launcher/SupportWindow.svelte';
	import TitleBar from '$lib/components/launcher/TitleBar.svelte';

	type BootPhase = 'boot' | 'expanding' | 'reveal' | 'ready';
	type AuthState = 'checking' | 'signed-out' | 'waiting' | 'signed-in' | 'error';

	const FIXED_WINDOW_SIZE = new LogicalSize(1244, 764);

	let bootProgress = $state(0.08);
	let bootLabel = $state('Поднимаем оболочку');
	let bootPhase = $state<BootPhase>('boot');
	let activeSection = $state<SectionId>('home');
	let selectedBuildId = $state('fragment-origin');
	let nickname = $state('FragmentPlayer');
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
	let authSession = $state<LauncherAuthSession | null>(null);
	let authState = $state<AuthState>('checking');
	let authError = $state('');
	let telegramLoginLink = $state<string | null>(null);
	let loginPollTimer: number | null = null;

	let builds = $state<BuildProfile[]>(createBuildProfiles());

	let bootVisible = $derived(bootPhase !== 'ready');
	let launcherVisible = $derived(bootPhase === 'reveal' || bootPhase === 'ready');
	let activeBuild = $derived(builds.find((build) => build.id === selectedBuildId) ?? builds[0]);
	let hasActiveSubscription = $derived(authSession?.profile.entitlement.active ?? false);
	let availableBuildsCount = $derived(
		builds.filter((build) => build.access === 'available' || hasActiveSubscription).length,
	);
	let telegramAccount = $derived(formatTelegramAccount(authSession?.profile));
	let supportReady = $derived(
		supportTopic.trim().length > 2 && supportDescription.trim().length > 12,
	);

	const navigation = [
		{ id: 'home', label: 'Главная', mobileLabel: 'Главная', icon: Gamepad2 },
	] satisfies Array<{ id: SectionId; label: string; mobileLabel: string; icon: typeof Gamepad2 }>;

	onMount(() => {
		if ('__TAURI_INTERNALS__' in window) {
			appWindow = getCurrentWindow();
			void configureFixedWindow();
		}

		void restoreAuthSession();
		void runBootSequence();

		return () => stopLoginPolling();
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
		const storedSession = loadStoredAuthSession();
		if (!storedSession) {
			authState = 'signed-out';
			return;
		}

		authState = 'checking';
		try {
			const profile = await getCurrentProfile(storedSession.accessToken);
			authSession = { ...storedSession, profile };
			storeAuthSession(authSession);
			authState = 'signed-in';
		} catch {
			try {
				const refreshed = await refreshAuthSession(storedSession.refreshToken);
				authSession = refreshed;
				storeAuthSession(refreshed);
				authState = 'signed-in';
			} catch {
				clearStoredAuthSession();
				authSession = null;
				authState = 'signed-out';
			}
		}
	}

	async function loginWithTelegram() {
		stopLoginPolling();
		authError = '';
		telegramLoginLink = null;
		authState = 'waiting';

		try {
			const challenge = await createTelegramLoginChallenge('Fragment Launcher');
			telegramLoginLink = challenge.telegramLink;
			window.open(challenge.telegramLink, '_blank', 'noopener,noreferrer');
			void pollLoginChallenge(challenge.challengeId, challenge.pollToken, challenge.expiresAt);
		} catch (error) {
			authError = error instanceof Error ? error.message : 'Не удалось начать вход через Telegram';
			authState = 'error';
		}
	}

	async function pollLoginChallenge(challengeId: string, pollToken: string, expiresAt: string) {
		if (authState !== 'waiting') {
			return;
		}

		if (Date.now() > new Date(expiresAt).getTime()) {
			authError = 'Ссылка для входа истекла. Создайте новую.';
			authState = 'error';
			return;
		}

		try {
			const result = await pollTelegramLoginChallenge(challengeId, pollToken);
			if (result.status === 'confirmed') {
				authSession = {
					tokenType: result.tokenType,
					accessToken: result.accessToken,
					refreshToken: result.refreshToken,
					expiresIn: result.expiresIn,
					profile: result.profile,
				};
				storeAuthSession(authSession);
				authState = 'signed-in';
				telegramLoginLink = null;
				return;
			}

			if (result.status === 'expired' || result.status === 'consumed') {
				authError = 'Ссылка для входа уже недействительна. Создайте новую.';
				authState = 'error';
				return;
			}
		} catch (error) {
			authError = error instanceof Error ? error.message : 'Не удалось проверить вход';
			authState = 'error';
			return;
		}

		loginPollTimer = window.setTimeout(() => {
			void pollLoginChallenge(challengeId, pollToken, expiresAt);
		}, 1800);
	}

	async function logoutFromTelegram() {
		const session = authSession;
		stopLoginPolling();
		authSession = null;
		authState = 'signed-out';
		authError = '';
		telegramLoginLink = null;
		clearStoredAuthSession();

		if (session) {
			await logoutAuthSession(session.refreshToken).catch(() => undefined);
		}
	}

	function stopLoginPolling() {
		if (loginPollTimer) {
			window.clearTimeout(loginPollTimer);
			loginPollTimer = null;
		}
	}

	function selectBuild(buildId: string) {
		selectedBuildId = buildId;
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

	function setPreset(presetId: PresetId) {
		const preset = presets.find((item) => item.id === presetId);

		activeBuild.preset = presetId;

		if (preset) {
			activeBuild.selectedRam = preset.ram;
		}
	}

	function setRamFromInput(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		activeBuild.selectedRam = Number(input.value);
	}

	function setJavaPath(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		activeBuild.javaPath = input.value;
	}

	function useSuggestedJavaPath() {
		activeBuild.javaPath = 'C:\\Program Files\\Eclipse Adoptium\\jdk-21\\bin\\javaw.exe';
	}

	function toggleMod(modId: string) {
		const mod = activeBuild.mods.find((item) => item.id === modId);

		if (mod) {
			mod.enabled = !mod.enabled;
		}
	}

	function addShaderFiles(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		const fileNames = Array.from(input.files ?? []).map((file) => file.name);

		activeBuild.shaders = [...new Set([...activeBuild.shaders, ...fileNames])].slice(0, 8);
		input.value = '';
	}

	function addResourcePackFiles(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		const fileNames = Array.from(input.files ?? []).map((file) => file.name);

		activeBuild.resourcePacks = [...new Set([...activeBuild.resourcePacks, ...fileNames])].slice(
			0,
			8,
		);
		input.value = '';
	}

	function removeShader(name: string) {
		activeBuild.shaders = activeBuild.shaders.filter((item) => item !== name);
	}

	function removeResourcePack(name: string) {
		activeBuild.resourcePacks = activeBuild.resourcePacks.filter((item) => item !== name);
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
			return 'Не подключён';
		}

		if (profile.username) {
			return `@${profile.username}`;
		}

		return profile.telegramId ? `ID ${profile.telegramId}` : 'Telegram подключён';
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

		<div class:visible={launcherVisible} class="launcher-layout">
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
							{builds}
							{activeBuild}
							{selectedBuildId}
							{feedItems}
							{feedImages}
							{selectBuild}
							openSettings={() => (settingsVisible = true)}
						/>
					{/if}
				</div>
			</section>
		</div>

		{#if settingsVisible}
			<SettingsWindow
				{builds}
				{activeBuild}
				{selectedBuildId}
				{presets}
				closeSettings={() => (settingsVisible = false)}
				{selectBuild}
				{setPreset}
				{setRamFromInput}
				{setJavaPath}
				{useSuggestedJavaPath}
				{toggleMod}
				{addShaderFiles}
				{addResourcePackFiles}
				{removeShader}
				{removeResourcePack}
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
				{availableBuildsCount}
				{authSession}
				{authState}
				{authError}
				{telegramLoginLink}
				{loginWithTelegram}
				{logoutFromTelegram}
				closeProfile={() => (profileVisible = false)}
			/>
		{/if}

		{#if statsVisible}
			<StatsWindow {activeBuild} closeStats={() => (statsVisible = false)} />
		{/if}
	</main>
</div>
