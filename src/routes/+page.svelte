<script lang="ts">
	import '$lib/styles/launcher.css';
	import { Gamepad2, MessageCircle, User } from '@lucide/svelte';
	import { onMount } from 'svelte';
	import { getCurrentWindow } from '@tauri-apps/api/window';
	import { LogicalSize } from '@tauri-apps/api/dpi';
	import { getLauncherStatus } from '$lib/launcher';
	import {
		createBuildProfiles,
		feedImages,
		feedItems,
		presets,
		type BuildProfile,
		type PresetId,
		type SectionId
	} from '$lib/launcher-ui';
	import BootScreen from '$lib/components/launcher/BootScreen.svelte';
	import DiagnosticsModal from '$lib/components/launcher/DiagnosticsModal.svelte';
	import HomeSection from '$lib/components/launcher/HomeSection.svelte';
	import MobileNav from '$lib/components/launcher/MobileNav.svelte';
	import ProfileSection from '$lib/components/launcher/ProfileSection.svelte';
	import SettingsWindow from '$lib/components/launcher/SettingsWindow.svelte';
	import Sidebar from '$lib/components/launcher/Sidebar.svelte';
	import SupportWindow from '$lib/components/launcher/SupportWindow.svelte';
	import TitleBar from '$lib/components/launcher/TitleBar.svelte';

	type BootPhase = 'boot' | 'expanding' | 'reveal' | 'ready';

	const FIXED_WINDOW_SIZE = new LogicalSize(1224, 764);

	let bootProgress = $state(0.08);
	let bootLabel = $state('Поднимаем оболочку');
	let bootPhase = $state<BootPhase>('boot');
	let activeSection = $state<SectionId>('home');
	let selectedBuildId = $state('fragment-origin');
	let nickname = $state('FragmentPlayer');
	let telegramAccount = $state('@fragment_player');
	let supportTopic = $state('');
	let supportDescription = $state('');
	let attachCrashReport = $state(true);
	let attachLastLog = $state(true);
	let attachLastScreenshot = $state(false);
	let sendDiagnostics = $state(true);
	let settingsVisible = $state(false);
	let supportVisible = $state(false);
	let diagnosticsNoticeDismissed = $state(false);
	let showDiagnosticsNotice = $state(false);
	let supportSent = $state(false);
	let appWindow = $state<ReturnType<typeof getCurrentWindow> | null>(null);

	let builds = $state<BuildProfile[]>(createBuildProfiles());

	let bootVisible = $derived(bootPhase !== 'ready');
	let launcherVisible = $derived(bootPhase === 'reveal' || bootPhase === 'ready');
	let activeBuild = $derived(builds.find((build) => build.id === selectedBuildId) ?? builds[0]);
	let activePreset = $derived(presets.find((preset) => preset.id === activeBuild.preset) ?? presets[1]);
	let availableBuildsCount = $derived(builds.filter((build) => build.access === 'available').length);
	let supportReady = $derived(supportTopic.trim().length > 2 && supportDescription.trim().length > 12);

	const navigation = [
		{ id: 'home', label: 'Главная', mobileLabel: 'Главная', icon: Gamepad2 },
		{ id: 'support', label: 'Поддержка', mobileLabel: 'Поддержка', icon: MessageCircle },
		{ id: 'profile', label: 'Профиль', mobileLabel: 'Профиль', icon: User }
	] satisfies Array<{ id: SectionId; label: string; mobileLabel: string; icon: typeof Gamepad2 }>;

	onMount(async () => {
		if ('__TAURI_INTERNALS__' in window) {
			appWindow = getCurrentWindow();
			await appWindow.setSize(FIXED_WINDOW_SIZE);
			await appWindow.setMinSize(FIXED_WINDOW_SIZE);
			await appWindow.setMaxSize(FIXED_WINDOW_SIZE);
			await appWindow.setResizable(false);
			await appWindow.setMaximizable(false);
			await appWindow.center();
		}

		await runBootSequence();
	});

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
		await getLauncherStatus();
		await delay(80);

		setBootStep(0.68, 'Проверяем профиль сборки');
		await appWindow?.setMinSize(FIXED_WINDOW_SIZE);
		await delay(80);

		setBootStep(0.84, 'Разворачиваем лаунчер');
		bootPhase = 'expanding';
		await delay(620);
		await appWindow?.setMaxSize(FIXED_WINDOW_SIZE);

		setBootStep(1, 'Готово');
		await delay(80);
		bootPhase = 'reveal';
		await delay(420);
		bootPhase = 'ready';
	}

	function selectBuild(buildId: string) {
		selectedBuildId = buildId;
	}

	function openSection(section: SectionId) {
		if (section === 'support') {
			supportVisible = true;
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

		activeBuild.resourcePacks = [...new Set([...activeBuild.resourcePacks, ...fileNames])].slice(0, 8);
		input.value = '';
	}

	function removeShader(name: string) {
		activeBuild.shaders = activeBuild.shaders.filter((item) => item !== name);
	}

	function removeResourcePack(name: string) {
		activeBuild.resourcePacks = activeBuild.resourcePacks.filter((item) => item !== name);
	}

	function setDiagnosticsEnabled(enabled: boolean) {
		sendDiagnostics = enabled;

		if (!enabled && !diagnosticsNoticeDismissed) {
			showDiagnosticsNotice = true;
		}
	}

	function dismissDiagnosticsNotice() {
		diagnosticsNoticeDismissed = true;
		showDiagnosticsNotice = false;
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
</script>

<svelte:head>
	<title>Fragment Launcher</title>
</svelte:head>

<div class:expanded={bootPhase !== 'boot'} class="window-stage fixed inset-0 overflow-hidden">
	<div class="window-shadow shadow-cast"></div>
	<div class="window-shadow shadow-contact"></div>

	<main
		class="app-shell absolute overflow-hidden rounded-[30px] border border-border bg-background text-foreground"
	>
		{#if bootVisible}
			<BootScreen {bootPhase} {bootProgress} {bootLabel} {startDrag} />
		{/if}

		<div
			class:visible={launcherVisible}
			class="launcher-layout"
		>
			<Sidebar {navigation} setActiveSection={openSection} />

			<section class="main-surface flex min-w-0 flex-col">
				<TitleBar
					{startDrag}
					{minimize}
					{closeWindow}
				/>

				<MobileNav
					{navigation}
					{activeSection}
					setActiveSection={openSection}
				/>

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
					{:else if activeSection === 'profile'}
						<ProfileSection
							{builds}
							bind:nickname
							{telegramAccount}
							{availableBuildsCount}
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

		{#if supportVisible}
			<SupportWindow
				{activeBuild}
				{activePreset}
				bind:supportTopic
				bind:supportDescription
				bind:attachCrashReport
				bind:attachLastLog
				bind:attachLastScreenshot
				{sendDiagnostics}
				{supportReady}
				{supportSent}
				closeSupport={() => (supportVisible = false)}
				{setDiagnosticsEnabled}
				{submitSupportRequest}
			/>
		{/if}

		{#if showDiagnosticsNotice}
			<DiagnosticsModal
				closeDiagnosticsNotice={() => (showDiagnosticsNotice = false)}
				{dismissDiagnosticsNotice}
			/>
		{/if}
	</main>
</div>
