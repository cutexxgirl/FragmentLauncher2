<script lang="ts">
	import {
		AlertTriangle,
		Bell,
		Check,
		CheckCircle2,
		ChevronRight,
		Cpu,
		FileText,
		FolderPlus,
		Gamepad2,
		HardDrive,
		Image,
		Info,
		Link2,
		MessageCircle,
		Minus,
		Monitor,
		Newspaper,
		Package,
		Play,
		Settings,
		ShieldCheck,
		SlidersHorizontal,
		Sparkles,
		Square,
		User,
		Wrench,
		X,
		Zap
	} from '@lucide/svelte';
	import { onMount } from 'svelte';
	import { getCurrentWindow } from '@tauri-apps/api/window';
	import { LogicalSize } from '@tauri-apps/api/dpi';
	import { getLauncherStatus, type LauncherStatus } from '$lib/launcher';

	type ResizeDirection =
		| 'East'
		| 'North'
		| 'NorthEast'
		| 'NorthWest'
		| 'South'
		| 'SouthEast'
		| 'SouthWest'
		| 'West';
	type BootPhase = 'boot' | 'expanding' | 'reveal' | 'ready';
	type SectionId = 'home' | 'build' | 'support' | 'profile';
	type PresetId = 'low' | 'medium' | 'high';

	type OptionalMod = {
		id: string;
		name: string;
		description: string;
		impact: string;
		enabled: boolean;
	};

	type BuildProfile = {
		id: string;
		name: string;
		subtitle: string;
		version: string;
		tag: string;
		description: string;
		access: 'available' | 'subscription';
		size: string;
		minecraft: string;
		selectedRam: number;
		javaPath: string;
		preset: PresetId;
		mods: OptionalMod[];
		shaders: string[];
		resourcePacks: string[];
	};

	type NewsItem = {
		title: string;
		text: string;
		date: string;
		tag: string;
	};

	const presets: Array<{
		id: PresetId;
		name: string;
		description: string;
		ram: number;
	}> = [
		{
			id: 'low',
			name: 'Слабый',
			description: 'Меньше эффектов, быстрый старт',
			ram: 4
		},
		{
			id: 'medium',
			name: 'Средний',
			description: 'Баланс графики и FPS',
			ram: 6
		},
		{
			id: 'high',
			name: 'Высокий',
			description: 'Максимум визуала',
			ram: 10
		}
	];

	const news: NewsItem[] = [
		{
			title: 'Готовим новый экран сборок',
			text: 'Добавили основу выбора сборки, пресеты производительности и место под будущую проверку файлов.',
			date: 'Сегодня',
			tag: 'Launcher'
		},
		{
			title: 'Опциональные моды вынесены отдельно',
			text: 'Теперь можно включать косметику, карту и графические улучшения без изменения базовой сборки.',
			date: 'Вчера',
			tag: 'Сборки'
		},
		{
			title: 'Техподдержка станет быстрее',
			text: 'Черновик обращения уже умеет прикладывать последний лог, краш-репорт и скриншот.',
			date: 'План',
			tag: 'Support'
		}
	];

	let status = $state<LauncherStatus>({
		appName: 'Fragment Launcher',
		version: '1.0.0',
		profile: 'singleplayer',
		servicesConnected: false,
		updaterReady: true
	});
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
	let diagnosticsNoticeDismissed = $state(false);
	let showDiagnosticsNotice = $state(false);
	let supportSent = $state(false);
	let shaderInput = $state<HTMLInputElement | null>(null);
	let resourcePackInput = $state<HTMLInputElement | null>(null);
	let appWindow = $state<ReturnType<typeof getCurrentWindow> | null>(null);

	let builds = $state<BuildProfile[]>([
		{
			id: 'fragment-origin',
			name: 'Fragment Origin',
			subtitle: 'Основная одиночная сборка',
			version: '1.20.1',
			tag: 'Stable',
			description: 'Базовый опыт Fragment: исследование, техника и аккуратные визуальные улучшения.',
			access: 'available',
			size: '18.4 ГБ',
			minecraft: 'Forge 47.3',
			selectedRam: 6,
			javaPath: 'C:\\Program Files\\Java\\jdk-21\\bin\\javaw.exe',
			preset: 'medium',
			mods: [
				{
					id: 'minimap',
					name: 'Миникарта',
					description: 'Навигация без вмешательства в баланс.',
					impact: 'легко',
					enabled: true
				},
				{
					id: 'ambient',
					name: 'Ambient FX',
					description: 'Погода, частицы и мягкая атмосфера.',
					impact: 'средне',
					enabled: true
				},
				{
					id: 'camera',
					name: 'Cinematic Camera',
					description: 'Плавная камера для скриншотов и видео.',
					impact: 'легко',
					enabled: false
				},
				{
					id: 'waystones',
					name: 'Waystones Lite',
					description: 'Удобные точки перемещения в одиночном мире.',
					impact: 'средне',
					enabled: false
				}
			],
			shaders: ['Fragment Soft Light.zip'],
			resourcePacks: ['Fragment UI Clean.zip']
		},
		{
			id: 'fragment-sky',
			name: 'Fragment Sky',
			subtitle: 'Экспериментальная небесная сборка',
			version: '1.20.1',
			tag: 'Beta',
			description: 'Легкий skyblock-вариант для коротких сессий и теста новых механик.',
			access: 'available',
			size: '12.1 ГБ',
			minecraft: 'Forge 47.3',
			selectedRam: 4,
			javaPath: 'C:\\Program Files\\Java\\jdk-21\\bin\\javaw.exe',
			preset: 'low',
			mods: [
				{
					id: 'sky-map',
					name: 'Sky Map',
					description: 'Маршруты островов и быстрые метки.',
					impact: 'легко',
					enabled: true
				},
				{
					id: 'clouds',
					name: 'Cloud Depth',
					description: 'Дополнительные облака и глубина неба.',
					impact: 'средне',
					enabled: false
				},
				{
					id: 'quests',
					name: 'Quest Hints',
					description: 'Подсказки по ранним цепочкам прогресса.',
					impact: 'легко',
					enabled: true
				}
			],
			shaders: [],
			resourcePacks: ['Sky Minimal UI.zip']
		},
		{
			id: 'fragment-visual',
			name: 'Fragment Visual',
			subtitle: 'Визуальный пресет для подписки',
			version: '1.20.1',
			tag: 'Plus',
			description: 'Расширенная графика, дополнительные анимации и набор шейдерных профилей.',
			access: 'subscription',
			size: '21.7 ГБ',
			minecraft: 'Forge 47.3',
			selectedRam: 10,
			javaPath: 'C:\\Program Files\\Java\\jdk-21\\bin\\javaw.exe',
			preset: 'high',
			mods: [
				{
					id: 'visual-fx',
					name: 'Visual FX Pack',
					description: 'Свет, отражения и улучшенные частицы.',
					impact: 'тяжело',
					enabled: true
				},
				{
					id: 'photo-mode',
					name: 'Photo Mode',
					description: 'Инструменты для постановочных скриншотов.',
					impact: 'средне',
					enabled: true
				},
				{
					id: 'motion',
					name: 'Motion Detail',
					description: 'Плавные анимации окружения.',
					impact: 'тяжело',
					enabled: false
				}
			],
			shaders: ['Fragment Cinematic.zip', 'Soft Shadows.zip'],
			resourcePacks: ['Fragment HD Surfaces.zip']
		}
	]);

	let bootVisible = $derived(bootPhase !== 'ready');
	let launcherVisible = $derived(bootPhase === 'reveal' || bootPhase === 'ready');
	let activeBuild = $derived(builds.find((build) => build.id === selectedBuildId) ?? builds[0]);
	let activePreset = $derived(presets.find((preset) => preset.id === activeBuild.preset) ?? presets[1]);
	let enabledModsCount = $derived(activeBuild.mods.filter((mod) => mod.enabled).length);
	let availableBuildsCount = $derived(builds.filter((build) => build.access === 'available').length);
	let supportReady = $derived(supportTopic.trim().length > 2 && supportDescription.trim().length > 12);

	const navigation = [
		{ id: 'home', label: 'Главная', mobileLabel: 'Главная', icon: Gamepad2 },
		{ id: 'build', label: 'Сборка', mobileLabel: 'Сборка', icon: SlidersHorizontal },
		{ id: 'support', label: 'Техподдержка', mobileLabel: 'Поддержка', icon: MessageCircle },
		{ id: 'profile', label: 'Профиль', mobileLabel: 'Профиль', icon: User }
	] satisfies Array<{ id: SectionId; label: string; mobileLabel: string; icon: typeof Gamepad2 }>;

	onMount(async () => {
		if ('__TAURI_INTERNALS__' in window) {
			appWindow = getCurrentWindow();
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
		status = await getLauncherStatus();
		await delay(80);

		setBootStep(0.68, 'Проверяем профиль сборки');
		await appWindow?.setMinSize(new LogicalSize(860, 620));
		await delay(80);

		setBootStep(0.84, 'Разворачиваем лаунчер');
		bootPhase = 'expanding';
		await delay(620);
		await appWindow?.setMinSize(new LogicalSize(1080, 680));

		setBootStep(1, 'Готово');
		await delay(80);
		bootPhase = 'reveal';
		await delay(420);
		bootPhase = 'ready';
	}

	function selectBuild(buildId: string) {
		selectedBuildId = buildId;
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

	async function toggleMaximize() {
		await appWindow?.toggleMaximize();
	}

	async function closeWindow() {
		await appWindow?.close();
	}

	async function startDrag() {
		await appWindow?.startDragging();
	}

	async function startResize(direction: ResizeDirection) {
		await appWindow?.startResizeDragging(direction);
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
		<button
			class="resize-edge resize-n"
			aria-label="Resize north"
			onmousedown={() => startResize('North')}
		></button>
		<button
			class="resize-edge resize-e"
			aria-label="Resize east"
			onmousedown={() => startResize('East')}
		></button>
		<button
			class="resize-edge resize-s"
			aria-label="Resize south"
			onmousedown={() => startResize('South')}
		></button>
		<button
			class="resize-edge resize-w"
			aria-label="Resize west"
			onmousedown={() => startResize('West')}
		></button>
		<button
			class="resize-corner resize-ne"
			aria-label="Resize northeast"
			onmousedown={() => startResize('NorthEast')}
		></button>
		<button
			class="resize-corner resize-nw"
			aria-label="Resize northwest"
			onmousedown={() => startResize('NorthWest')}
		></button>
		<button
			class="resize-corner resize-se"
			aria-label="Resize southeast"
			onmousedown={() => startResize('SouthEast')}
		></button>
		<button
			class="resize-corner resize-sw"
			aria-label="Resize southwest"
			onmousedown={() => startResize('SouthWest')}
		></button>

		{#if bootVisible}
			<div
				class:leaving={bootPhase === 'reveal'}
				class="boot-screen flex h-full min-h-0 flex-col justify-between bg-[radial-gradient(circle_at_72%_16%,rgba(240,179,93,0.28)_0,rgba(36,38,40,0.94)_34%,#101112_72%)] px-7 py-6"
				role="toolbar"
				aria-label="Boot window"
				tabindex="-1"
				onmousedown={startDrag}
			>
				<div class="flex items-center gap-3">
					<div class="brand-mark grid size-11 place-items-center rounded-[14px] bg-accent text-accent-foreground">
						<Sparkles size={20} strokeWidth={2.2} />
					</div>
					<div>
						<p class="text-sm font-medium text-muted">Fragment</p>
						<h1 class="text-xl font-semibold leading-tight">Launcher</h1>
					</div>
				</div>

				<div>
					<p class="text-xs font-semibold uppercase tracking-[0.18em] text-accent">Запуск</p>
					<p class="mt-3 text-2xl font-semibold">{bootLabel}</p>
					<div class="mt-6 h-2 overflow-hidden rounded-full bg-panel-strong">
						<div
							class="h-full rounded-full bg-accent transition-[width] duration-300 ease-out"
							style={`width: ${Math.round(bootProgress * 100)}%`}
						></div>
					</div>
					<div class="mt-3 flex items-center justify-between text-xs text-muted">
						<span>Локальный запуск</span>
						<span>{Math.round(bootProgress * 100)}%</span>
					</div>
				</div>
			</div>
		{/if}

		<div class:visible={launcherVisible} class="launcher-layout">
			<aside class="sidebar-surface flex min-h-0 flex-col gap-5 border-r border-border bg-panel/94 p-5">
				<div class="flex items-center gap-3">
					<div class="brand-mark grid size-11 place-items-center rounded-[14px] bg-accent text-accent-foreground">
						<Sparkles size={20} strokeWidth={2.2} />
					</div>
					<div>
						<p class="text-sm font-medium text-muted">Fragment</p>
						<h1 class="text-xl font-semibold leading-tight">Launcher</h1>
					</div>
				</div>

				<nav class="grid gap-2">
					{#each navigation as item}
						{@const Icon = item.icon}
						<button
							class:active={activeSection === item.id}
							class="nav-button"
							onclick={() => (activeSection = item.id)}
						>
							<Icon size={18} />
							<span>{item.label}</span>
						</button>
					{/each}
				</nav>

				<div class="selected-build-card mt-auto rounded-[22px] border border-border bg-background/52 p-4">
					<div class="flex items-start justify-between gap-3">
						<div>
							<p class="text-xs font-semibold uppercase tracking-[0.16em] text-muted">Выбрано</p>
							<p class="mt-2 text-base font-semibold">{activeBuild.name}</p>
							<p class="mt-1 text-sm text-muted">{activeBuild.minecraft}</p>
						</div>
						<span class="rounded-[12px] bg-accent/14 px-2.5 py-1 text-xs font-semibold text-accent">
							{activeBuild.tag}
						</span>
					</div>
					<div class="mt-4 grid grid-cols-2 gap-2 text-sm">
						<div class="rounded-[14px] bg-panel-strong/78 p-3">
							<p class="text-xs text-muted">ОЗУ</p>
							<p class="mt-1 font-semibold">{activeBuild.selectedRam} ГБ</p>
						</div>
						<div class="rounded-[14px] bg-panel-strong/78 p-3">
							<p class="text-xs text-muted">Моды</p>
							<p class="mt-1 font-semibold">{enabledModsCount}/{activeBuild.mods.length}</p>
						</div>
					</div>
				</div>

				<div class="rounded-[22px] border border-border bg-background/38 p-4">
					<p class="text-xs font-semibold uppercase tracking-[0.16em] text-muted">Версия</p>
					<p class="mt-2 text-lg font-semibold">{status.version}</p>
				</div>
			</aside>

			<section class="main-surface flex min-w-0 flex-col">
				<header
					class="titlebar flex h-[62px] select-none items-center justify-between border-b border-border px-5"
					role="toolbar"
					aria-label="Window title bar"
					tabindex="-1"
					onmousedown={startDrag}
					ondblclick={toggleMaximize}
				>
					<div class="flex min-w-0 items-center gap-3">
						<span class="status-dot size-2.5 rounded-full bg-success"></span>
						<div class="min-w-0">
							<p class="text-xs text-muted">Локальный режим</p>
							<p class="truncate text-sm font-medium">
								{activeBuild.name} - {activePreset.name}
							</p>
						</div>
					</div>

					<div class="flex items-center gap-2">
						<div class="hidden items-center gap-2 rounded-[16px] border border-border bg-panel/80 px-3 py-2 text-xs text-muted md:flex">
							<ShieldCheck size={15} class="text-success" />
							<span>Профиль готов</span>
						</div>
						<div class="flex items-center gap-1">
							<button
								class="window-control"
								aria-label="Minimize window"
								title="Свернуть"
								onmousedown={(event) => event.stopPropagation()}
								onclick={minimize}
							>
								<Minus size={15} />
							</button>
							<button
								class="window-control"
								aria-label="Maximize window"
								title="Развернуть"
								onmousedown={(event) => event.stopPropagation()}
								onclick={toggleMaximize}
							>
								<Square size={13} />
							</button>
							<button
								class="window-control close"
								aria-label="Close window"
								title="Закрыть"
								onmousedown={(event) => event.stopPropagation()}
								onclick={closeWindow}
							>
								<X size={16} />
							</button>
						</div>
					</div>
				</header>

				<nav class="mobile-nav-wrap">
					{#each navigation as item}
						{@const Icon = item.icon}
						<button
							class:active={activeSection === item.id}
							class="mobile-nav-button"
							onclick={() => (activeSection = item.id)}
						>
							<Icon size={16} />
							<span>{item.mobileLabel}</span>
						</button>
					{/each}
				</nav>

				<div class="workspace min-h-0 flex-1 overflow-y-auto px-6 py-6">
					{#if activeSection === 'home'}
						<div class="section-grid">
							<section class="hero-panel rounded-[28px] border border-border p-6">
								<div class="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
									<div class="max-w-2xl">
										<p class="text-xs font-semibold uppercase tracking-[0.18em] text-accent">
											Minecraft modpack
										</p>
										<h2 class="mt-3 text-[clamp(2rem,4vw,3.75rem)] font-semibold leading-[1.02]">
											{activeBuild.name}
										</h2>
										<p class="mt-4 max-w-2xl text-base leading-7 text-muted">
											{activeBuild.description} Настройки уже можно менять локально, а дизайн оставлен с
											запасом под будущие модули.
										</p>
									</div>

									<div class="play-dock rounded-[22px] border border-white/10 bg-background/58 p-3">
										<div class="mb-3 flex items-center gap-3 px-1">
											<div class="grid size-10 place-items-center rounded-[14px] bg-success/14 text-success">
												<CheckCircle2 size={20} />
											</div>
											<div>
												<p class="text-sm font-semibold">Готово к запуску</p>
												<p class="text-xs text-muted">ОЗУ {activeBuild.selectedRam} ГБ</p>
											</div>
										</div>
										<button class="play-button">
											<Play size={20} fill="currentColor" />
											<span>Играть</span>
										</button>
									</div>
								</div>
							</section>

							<div class="home-columns">
								<section class="panel-card rounded-[24px] border border-border p-4">
									<div class="section-head">
										<div>
											<p class="section-kicker">Сборки</p>
											<h3 class="section-title">Выбор профиля</h3>
										</div>
										<button class="ghost-icon-button" title="Настройки сборки" onclick={() => (activeSection = 'build')}>
											<Settings size={17} />
										</button>
									</div>

									<div class="mt-4 grid gap-3">
										{#each builds as build}
											<button
												class:active={selectedBuildId === build.id}
												class="build-select-row"
												onclick={() => selectBuild(build.id)}
											>
												<div class="flex min-w-0 items-center gap-3">
													<div class="build-icon">
														<Package size={18} />
													</div>
													<div class="min-w-0 text-left">
														<p class="truncate text-sm font-semibold">{build.name}</p>
														<p class="truncate text-xs text-muted">{build.subtitle}</p>
													</div>
												</div>
												<div class="flex items-center gap-2">
													<span class:locked={build.access === 'subscription'} class="access-pill">
														{build.access === 'available' ? 'Доступно' : 'Plus'}
													</span>
													<ChevronRight size={16} class="row-arrow" />
												</div>
											</button>
										{/each}
									</div>
								</section>

								<section class="news-block rounded-[24px] border border-border p-4">
									<div class="section-head">
										<div>
											<p class="section-kicker">Новости</p>
											<h3 class="section-title">Что нового</h3>
										</div>
										<div class="grid size-9 place-items-center rounded-[14px] bg-accent/14 text-accent">
											<Newspaper size={17} />
										</div>
									</div>

									<div class="mt-4 grid gap-3">
										{#each news as item}
											<article class="news-item rounded-[18px] bg-background/46 p-4">
												<div class="flex items-center justify-between gap-3">
													<span class="news-tag">{item.tag}</span>
													<span class="text-xs text-muted">{item.date}</span>
												</div>
												<h4 class="mt-3 text-sm font-semibold">{item.title}</h4>
												<p class="mt-2 text-sm leading-6 text-muted">{item.text}</p>
											</article>
										{/each}
									</div>
								</section>
							</div>

							<section class="status-grid">
								<div class="metric-card">
									<Cpu size={18} />
									<div>
										<p class="metric-label">Пресет</p>
										<p class="metric-value">{activePreset.name}</p>
									</div>
								</div>
								<div class="metric-card">
									<HardDrive size={18} />
									<div>
										<p class="metric-label">Размер</p>
										<p class="metric-value">{activeBuild.size}</p>
									</div>
								</div>
								<div class="metric-card">
									<Wrench size={18} />
									<div>
										<p class="metric-label">Опционально</p>
										<p class="metric-value">{enabledModsCount} модов</p>
									</div>
								</div>
							</section>
						</div>
					{:else if activeSection === 'build'}
						<div class="section-grid">
							<div class="page-heading">
								<div>
									<p class="section-kicker">Настройки сборки</p>
									<h2 class="page-title">{activeBuild.name}</h2>
								</div>
								<button class="play-button compact">
									<Play size={18} fill="currentColor" />
									<span>Играть</span>
								</button>
							</div>

							<div class="settings-layout">
								<section class="panel-card rounded-[24px] border border-border p-4">
									<div class="section-head">
										<div>
											<p class="section-kicker">Профиль</p>
											<h3 class="section-title">Выбор сборки</h3>
										</div>
									</div>
									<div class="mt-4 grid gap-3">
										{#each builds as build}
											<button
												class:active={selectedBuildId === build.id}
												class="build-card-button"
												onclick={() => selectBuild(build.id)}
											>
												<div class="flex items-start justify-between gap-3">
													<div class="text-left">
														<p class="text-base font-semibold">{build.name}</p>
														<p class="mt-1 text-sm leading-6 text-muted">{build.subtitle}</p>
													</div>
													<span class="build-tag">{build.tag}</span>
												</div>
												<div class="mt-4 flex flex-wrap gap-2 text-xs text-muted">
													<span>{build.version}</span>
													<span>{build.minecraft}</span>
													<span>{build.size}</span>
												</div>
											</button>
										{/each}
									</div>
								</section>

								<section class="panel-card settings-panel rounded-[24px] border border-border p-5">
									<div class="section-head">
										<div>
											<p class="section-kicker">Производительность</p>
											<h3 class="section-title">ОЗУ и пресет</h3>
										</div>
										<span class="rounded-[14px] bg-success/12 px-3 py-1.5 text-xs font-semibold text-success">
											{activeBuild.selectedRam} ГБ
										</span>
									</div>

									<div class="mt-5 grid gap-4">
										<div class="control-block">
											<div class="flex items-center justify-between gap-3">
												<label class="text-sm font-semibold" for="ram-range">Выделить памяти</label>
												<span class="text-sm text-muted">4-16 ГБ</span>
											</div>
											<input
												id="ram-range"
												class="range-control mt-4"
												type="range"
												min="4"
												max="16"
												step="1"
												value={activeBuild.selectedRam}
												oninput={setRamFromInput}
											/>
										</div>

										<div class="preset-grid">
											{#each presets as preset}
												<button
													class:active={activeBuild.preset === preset.id}
													class="preset-button"
													onclick={() => setPreset(preset.id)}
												>
													<span class="font-semibold">{preset.name}</span>
													<span>{preset.description}</span>
												</button>
											{/each}
										</div>

										<div class="control-block">
											<label class="text-sm font-semibold" for="java-path">Путь к Java</label>
											<div class="mt-3 flex flex-col gap-2 sm:flex-row">
												<input
													id="java-path"
													class="text-field"
													value={activeBuild.javaPath}
													oninput={setJavaPath}
													spellcheck="false"
												/>
												<button class="secondary-button shrink-0" onclick={useSuggestedJavaPath}>
													<FolderPlus size={17} />
													<span>Подставить</span>
												</button>
											</div>
										</div>
									</div>
								</section>
							</div>

							<div class="settings-layout bottom">
								<section class="panel-card rounded-[24px] border border-border p-5">
									<div class="section-head">
										<div>
											<p class="section-kicker">Опции</p>
											<h3 class="section-title">Опциональные моды</h3>
										</div>
										<span class="text-xs text-muted">Свои моды отключены</span>
									</div>

									<div class="mt-4 grid gap-3">
										{#each activeBuild.mods as mod}
											<button class="toggle-row" onclick={() => toggleMod(mod.id)}>
												<div class="min-w-0 text-left">
													<div class="flex flex-wrap items-center gap-2">
														<p class="text-sm font-semibold">{mod.name}</p>
														<span class="impact-pill">{mod.impact}</span>
													</div>
													<p class="mt-1 text-sm leading-6 text-muted">{mod.description}</p>
												</div>
												<span class:enabled={mod.enabled} class="switch" aria-hidden="true">
													<span></span>
												</span>
											</button>
										{/each}
									</div>
								</section>

								<section class="panel-card rounded-[24px] border border-border p-5">
									<div class="section-head">
										<div>
											<p class="section-kicker">Пользовательские файлы</p>
											<h3 class="section-title">Шейдеры и ресурспаки</h3>
										</div>
									</div>

									<div class="mt-4 grid gap-4">
										<div class="asset-block">
											<div class="flex items-center justify-between gap-3">
												<div class="flex items-center gap-2">
													<Zap size={17} class="text-accent" />
													<p class="text-sm font-semibold">Шейдеры</p>
												</div>
												<button class="mini-button" onclick={() => shaderInput?.click()}>
													<FolderPlus size={16} />
													<span>Добавить</span>
												</button>
												<input
													bind:this={shaderInput}
													hidden
													multiple
													type="file"
													accept=".zip"
													onchange={addShaderFiles}
												/>
											</div>
											<div class="mt-3 flex flex-wrap gap-2">
												{#if activeBuild.shaders.length}
													{#each activeBuild.shaders as shader}
														<button class="file-chip" onclick={() => removeShader(shader)}>
															<span>{shader}</span>
															<X size={13} />
														</button>
													{/each}
												{:else}
													<p class="text-sm text-muted">Пока не добавлены.</p>
												{/if}
											</div>
										</div>

										<div class="asset-block">
											<div class="flex items-center justify-between gap-3">
												<div class="flex items-center gap-2">
													<Image size={17} class="text-success" />
													<p class="text-sm font-semibold">Ресурспаки</p>
												</div>
												<button class="mini-button" onclick={() => resourcePackInput?.click()}>
													<FolderPlus size={16} />
													<span>Добавить</span>
												</button>
												<input
													bind:this={resourcePackInput}
													hidden
													multiple
													type="file"
													accept=".zip"
													onchange={addResourcePackFiles}
												/>
											</div>
											<div class="mt-3 flex flex-wrap gap-2">
												{#if activeBuild.resourcePacks.length}
													{#each activeBuild.resourcePacks as pack}
														<button class="file-chip" onclick={() => removeResourcePack(pack)}>
															<span>{pack}</span>
															<X size={13} />
														</button>
													{/each}
												{:else}
													<p class="text-sm text-muted">Пока не добавлены.</p>
												{/if}
											</div>
										</div>

										<div class="notice-line">
											<Info size={16} />
											<span>Свои моды нельзя добавлять, чтобы сборка оставалась стабильной и проверяемой.</span>
										</div>
									</div>
								</section>
							</div>
						</div>
					{:else if activeSection === 'support'}
						<div class="section-grid">
							<div class="page-heading">
								<div>
									<p class="section-kicker">Техподдержка</p>
									<h2 class="page-title">Новое обращение</h2>
								</div>
								<div class="rounded-[18px] border border-border bg-panel/72 px-4 py-3 text-sm text-muted">
									Ответ обычно приходит в Telegram
								</div>
							</div>

							<div class="support-layout">
								<form class="panel-card rounded-[24px] border border-border p-5" onsubmit={submitSupportRequest}>
									<div class="grid gap-4">
										<div>
											<label class="text-sm font-semibold" for="support-topic">Тема</label>
											<input
												id="support-topic"
												class="text-field mt-2"
												placeholder="Например: вылет при запуске мира"
												bind:value={supportTopic}
											/>
										</div>
										<div>
											<label class="text-sm font-semibold" for="support-description">Описание проблемы</label>
											<textarea
												id="support-description"
												class="text-area mt-2"
												placeholder="Что произошло, на каком этапе и повторяется ли ошибка?"
												bind:value={supportDescription}
											></textarea>
										</div>
									</div>

									<div class="mt-5 grid gap-3">
										<label class="attach-row">
											<input type="checkbox" bind:checked={attachCrashReport} />
											<span class="attach-icon"><AlertTriangle size={17} /></span>
											<span>
												<strong>Последний crash report</strong>
												<small>crash-2026-07-02.txt</small>
											</span>
										</label>
										<label class="attach-row">
											<input type="checkbox" bind:checked={attachLastLog} />
											<span class="attach-icon"><FileText size={17} /></span>
											<span>
												<strong>Последний лог</strong>
												<small>latest.log</small>
											</span>
										</label>
										<label class="attach-row">
											<input type="checkbox" bind:checked={attachLastScreenshot} />
											<span class="attach-icon"><Image size={17} /></span>
											<span>
												<strong>Последний скриншот из игры</strong>
												<small>screenshots/last.png</small>
											</span>
										</label>
									</div>

									<div class="mt-5 flex flex-col gap-3 rounded-[20px] bg-background/46 p-4 sm:flex-row sm:items-center sm:justify-between">
										<div>
											<p class="text-sm font-semibold">Данные для диагностики</p>
											<p class="mt-1 text-sm leading-6 text-muted">
												Характеристики ПК, версия Java и настройки сборки помогают быстрее найти причину.
											</p>
										</div>
										<button
											type="button"
											class:enabled={sendDiagnostics}
											class="switch large"
											aria-label="Отправлять диагностические данные"
											onclick={() => setDiagnosticsEnabled(!sendDiagnostics)}
										>
											<span></span>
										</button>
									</div>

									<div class="mt-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
										<p class="text-sm text-muted">
											{supportSent
												? 'Черновик обращения готов. Позже подключим отправку на сервер поддержки.'
												: 'Заполните тему и описание, чтобы подготовить обращение.'}
										</p>
										<button class="primary-button" disabled={!supportReady} type="submit">
											<MessageCircle size={17} />
											<span>Подготовить</span>
										</button>
									</div>
								</form>

								<aside class="panel-card rounded-[24px] border border-border p-5">
									<div class="section-head">
										<div>
											<p class="section-kicker">Пакет</p>
											<h3 class="section-title">Что приложится</h3>
										</div>
										<div class="grid size-9 place-items-center rounded-[14px] bg-success/12 text-success">
											<Check size={17} />
										</div>
									</div>

									<div class="mt-4 grid gap-3">
										<div class="support-summary-row">
											<span>Сборка</span>
											<strong>{activeBuild.name}</strong>
										</div>
										<div class="support-summary-row">
											<span>Пресет</span>
											<strong>{activePreset.name}</strong>
										</div>
										<div class="support-summary-row">
											<span>Диагностика</span>
											<strong>{sendDiagnostics ? 'включена' : 'отключена'}</strong>
										</div>
										<div class="support-summary-row">
											<span>Вложения</span>
											<strong>
												{Number(attachCrashReport) + Number(attachLastLog) + Number(attachLastScreenshot)}
											</strong>
										</div>
									</div>

									<div class="mt-5 rounded-[20px] bg-background/46 p-4">
										<div class="flex items-center gap-2 text-sm font-semibold">
											<Bell size={16} class="text-accent" />
											<span>Подсказка</span>
										</div>
										<p class="mt-2 text-sm leading-6 text-muted">
											Лучше описать последний успешный запуск и действие перед вылетом. Это экономит пару
											кругов переписки.
										</p>
									</div>
								</aside>
							</div>
						</div>
					{:else if activeSection === 'profile'}
						<div class="section-grid">
							<div class="page-heading">
								<div>
									<p class="section-kicker">Профиль</p>
									<h2 class="page-title">Игрок и подписка</h2>
								</div>
							</div>

							<div class="profile-layout">
								<section class="panel-card rounded-[24px] border border-border p-5">
									<div class="section-head">
										<div>
											<p class="section-kicker">Игрок</p>
											<h3 class="section-title">Основная информация</h3>
										</div>
										<div class="avatar-badge">
											<User size={20} />
										</div>
									</div>

									<div class="mt-5 grid gap-4">
										<div>
											<label class="text-sm font-semibold" for="nickname">Ник</label>
											<input id="nickname" class="text-field mt-2" bind:value={nickname} maxlength="24" />
										</div>
										<div class="rounded-[20px] bg-background/46 p-4">
											<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
												<div class="flex items-center gap-3">
													<div class="grid size-10 place-items-center rounded-[14px] bg-sky/14 text-sky">
														<Link2 size={18} />
													</div>
													<div>
														<p class="text-sm font-semibold">Telegram</p>
														<p class="text-sm text-muted">{telegramAccount}</p>
													</div>
												</div>
												<button class="secondary-button">
													<Link2 size={17} />
													<span>Перепривязать</span>
												</button>
											</div>
										</div>
									</div>
								</section>

								<section class="panel-card rounded-[24px] border border-border p-5">
									<div class="section-head">
										<div>
											<p class="section-kicker">Подписка</p>
											<h3 class="section-title">Fragment Plus</h3>
										</div>
										<span class="rounded-[14px] bg-accent/14 px-3 py-1.5 text-xs font-semibold text-accent">
											Активна
										</span>
									</div>

									<div class="mt-5 rounded-[22px] bg-background/46 p-4">
										<p class="text-sm text-muted">Доступные сборки</p>
										<p class="mt-2 text-3xl font-semibold">{availableBuildsCount}/{builds.length}</p>
										<p class="mt-2 text-sm leading-6 text-muted">
											Подписка открывает визуальные пресеты и будущие закрытые сборки.
										</p>
									</div>

									<div class="mt-4 grid gap-3">
										{#each builds as build}
											<div class="subscription-row">
												<div>
													<p class="text-sm font-semibold">{build.name}</p>
													<p class="text-xs text-muted">{build.subtitle}</p>
												</div>
												<span class:locked={build.access === 'subscription'} class="access-pill">
													{build.access === 'available' ? 'доступно' : 'Plus'}
												</span>
											</div>
										{/each}
									</div>
								</section>

								<section class="panel-card rounded-[24px] border border-border p-5">
									<div class="section-head">
										<div>
											<p class="section-kicker">Комфорт</p>
											<h3 class="section-title">Быстрые параметры</h3>
										</div>
									</div>

									<div class="mt-4 grid gap-3">
										<div class="quick-row">
											<Monitor size={18} />
											<div>
												<p class="text-sm font-semibold">Окно лаунчера</p>
												<p class="text-xs text-muted">Адаптивная сетка под текущий размер</p>
											</div>
										</div>
										<div class="quick-row">
											<ShieldCheck size={18} />
											<div>
												<p class="text-sm font-semibold">Приватность</p>
												<p class="text-xs text-muted">Диагностику можно выключить в обращении</p>
											</div>
										</div>
									</div>
								</section>
							</div>
						</div>
					{/if}
				</div>
			</section>
		</div>

		{#if showDiagnosticsNotice}
			<div class="modal-backdrop">
				<div class="privacy-modal rounded-[26px] border border-border bg-panel p-5">
					<div class="flex items-start gap-4">
						<div class="grid size-11 shrink-0 place-items-center rounded-[16px] bg-accent/14 text-accent">
							<Info size={21} />
						</div>
						<div>
							<p class="text-lg font-semibold">Диагностика помогает быстрее решить проблему</p>
							<p class="mt-3 text-sm leading-6 text-muted">
								Мы используем данные о железе, версии Java и настройках сборки только для поддержки и
								статистики. Они помогают понять, на каких ПК играют в Fragment, быстрее находить
								нестабильные места и улучшать продукт. Личные данные не публикуются и не передаются
								посторонним.
							</p>
							<div class="mt-5 flex flex-col gap-2 sm:flex-row sm:justify-end">
								<button class="secondary-button" onclick={() => (showDiagnosticsNotice = false)}>
									<span>Понятно</span>
								</button>
								<button class="primary-button" onclick={dismissDiagnosticsNotice}>
									<span>Больше не показывать</span>
								</button>
							</div>
						</div>
					</div>
				</div>
			</div>
		{/if}
	</main>
</div>

<style>
	.window-stage {
		--shell-height: 292px;
		--shell-width: 512px;
		pointer-events: none;
	}

	.window-stage.expanded {
		--shell-height: calc(100% - 56px);
		--shell-width: calc(100% - 56px);
	}

	.app-shell {
		top: 50%;
		left: 50%;
		width: var(--shell-width);
		height: var(--shell-height);
		pointer-events: auto;
		transform: translate(-50%, -50%);
		transition:
			width 620ms cubic-bezier(0.65, 0, 0.35, 1),
			height 620ms cubic-bezier(0.65, 0, 0.35, 1);
		filter: drop-shadow(0 18px 38px rgba(0, 0, 0, 0.34));
	}

	.boot-screen {
		position: absolute;
		inset: 0;
		z-index: 12;
		opacity: 1;
		transform: scale(1);
		transition:
			opacity 260ms ease,
			transform 420ms cubic-bezier(0.22, 1, 0.36, 1);
	}

	.boot-screen.leaving {
		opacity: 0;
		transform: scale(1.025);
		pointer-events: none;
	}

	.launcher-layout {
		position: absolute;
		inset: 0;
		display: grid;
		grid-template-columns: minmax(250px, 292px) minmax(0, 1fr);
		opacity: 0;
		pointer-events: none;
		transform: scale(0.985) translateY(8px);
		transition:
			opacity 320ms ease,
			transform 440ms cubic-bezier(0.22, 1, 0.36, 1);
	}

	.launcher-layout.visible {
		opacity: 1;
		pointer-events: auto;
		transform: scale(1) translateY(0);
	}

	.sidebar-surface,
	.main-surface {
		animation: launcher-surface-in 380ms cubic-bezier(0.22, 1, 0.36, 1) both;
	}

	.main-surface {
		background:
			radial-gradient(circle at 76% 4%, rgba(117, 199, 192, 0.16), transparent 32%),
			radial-gradient(circle at 22% 0%, rgba(240, 179, 93, 0.12), transparent 34%),
			var(--color-background);
		animation-delay: 70ms;
	}

	@keyframes launcher-surface-in {
		from {
			opacity: 0;
			transform: translateY(10px);
		}

		to {
			opacity: 1;
			transform: translateY(0);
		}
	}

	.window-shadow {
		position: absolute;
		pointer-events: none;
		border-radius: 34px;
	}

	.shadow-cast {
		top: 50%;
		left: 50%;
		width: var(--shell-width);
		height: var(--shell-height);
		background: transparent;
		box-shadow:
			0 28px 64px 10px rgba(0, 0, 0, 0.48),
			18px 20px 42px rgba(0, 0, 0, 0.28);
		opacity: 0.88;
		transform: translate(calc(-50% + 2px), calc(-50% + 4px));
		transition:
			width 620ms cubic-bezier(0.65, 0, 0.35, 1),
			height 620ms cubic-bezier(0.65, 0, 0.35, 1);
	}

	.shadow-contact {
		top: 50%;
		left: 50%;
		width: var(--shell-width);
		height: var(--shell-height);
		background: transparent;
		box-shadow: 0 22px 26px -18px rgba(0, 0, 0, 0.52);
		opacity: 0.82;
		transform: translate(-50%, -50%);
		transition:
			width 620ms cubic-bezier(0.65, 0, 0.35, 1),
			height 620ms cubic-bezier(0.65, 0, 0.35, 1);
	}

	.brand-mark {
		box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.32);
	}

	.nav-button {
		display: flex;
		height: 44px;
		align-items: center;
		gap: 12px;
		border-radius: 16px;
		padding: 0 14px;
		color: var(--color-muted);
		font-size: 0.9rem;
		font-weight: 600;
		transition:
			background-color 150ms ease,
			color 150ms ease,
			transform 150ms ease;
	}

	.nav-button:hover,
	.nav-button.active {
		background: var(--color-panel-strong);
		color: var(--color-foreground);
	}

	.nav-button.active {
		box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.05);
	}

	.mobile-nav-wrap {
		display: none;
		gap: 8px;
		border-bottom: 1px solid var(--color-border);
		background: rgba(16, 17, 18, 0.68);
		padding: 10px 18px;
	}

	.mobile-nav-button {
		display: inline-flex;
		min-width: 0;
		height: 42px;
		align-items: center;
		justify-content: center;
		gap: 7px;
		border-radius: 15px;
		background: rgba(35, 38, 41, 0.56);
		color: var(--color-muted);
		font-size: 0.72rem;
		font-weight: 700;
		transition:
			background-color 150ms ease,
			color 150ms ease;
	}

	.mobile-nav-button span {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.mobile-nav-button.active {
		background: rgba(240, 179, 93, 0.14);
		color: var(--color-foreground);
		box-shadow: inset 0 0 0 1px rgba(240, 179, 93, 0.28);
	}

	.titlebar {
		background: rgba(16, 17, 18, 0.72);
		backdrop-filter: blur(18px);
	}

	.status-dot {
		box-shadow: 0 0 0 5px rgba(116, 211, 169, 0.1);
	}

	.window-control {
		display: grid;
		width: 36px;
		height: 32px;
		place-items: center;
		border-radius: 13px;
		color: var(--color-muted);
		transition:
			background-color 140ms ease,
			color 140ms ease;
	}

	.window-control:hover {
		background: var(--color-panel-strong);
		color: var(--color-foreground);
	}

	.window-control.close:hover {
		background: #d95c57;
		color: white;
	}

	.workspace {
		scrollbar-width: thin;
		scrollbar-color: rgba(255, 255, 255, 0.16) transparent;
	}

	.section-grid {
		display: grid;
		gap: 18px;
	}

	.hero-panel {
		background:
			linear-gradient(135deg, rgba(240, 179, 93, 0.16), rgba(117, 199, 192, 0.08)),
			rgba(25, 27, 29, 0.72);
		box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.06);
	}

	.play-dock {
		width: min(100%, 280px);
	}

	.play-button,
	.primary-button,
	.secondary-button,
	.mini-button {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: 10px;
		border-radius: 16px;
		font-weight: 700;
		transition:
			transform 150ms ease,
			filter 150ms ease,
			background-color 150ms ease,
			color 150ms ease,
			border-color 150ms ease;
	}

	.play-button {
		min-height: 52px;
		width: 100%;
		background: var(--color-accent);
		color: var(--color-accent-foreground);
		font-size: 0.95rem;
		box-shadow: 0 14px 28px rgba(240, 179, 93, 0.16);
	}

	.play-button.compact {
		width: auto;
		min-width: 150px;
		padding: 0 18px;
	}

	.primary-button {
		min-height: 44px;
		background: var(--color-accent);
		color: var(--color-accent-foreground);
		padding: 0 16px;
	}

	.secondary-button {
		min-height: 44px;
		border: 1px solid var(--color-border);
		background: rgba(30, 32, 34, 0.84);
		color: var(--color-foreground);
		padding: 0 14px;
	}

	.mini-button {
		min-height: 34px;
		border: 1px solid var(--color-border);
		background: rgba(16, 17, 18, 0.5);
		color: var(--color-foreground);
		padding: 0 11px;
		font-size: 0.78rem;
	}

	.play-button:hover,
	.primary-button:hover,
	.secondary-button:hover,
	.mini-button:hover {
		filter: brightness(1.06);
		transform: translateY(-1px);
	}

	.primary-button:disabled {
		cursor: not-allowed;
		filter: grayscale(0.35) brightness(0.68);
		opacity: 0.7;
		transform: none;
	}

	.home-columns,
	.settings-layout,
	.support-layout,
	.profile-layout {
		display: grid;
		gap: 18px;
	}

	.home-columns {
		grid-template-columns: minmax(0, 0.92fr) minmax(340px, 1.08fr);
	}

	.settings-layout {
		grid-template-columns: minmax(260px, 0.82fr) minmax(0, 1.18fr);
	}

	.settings-layout.bottom {
		grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
	}

	.support-layout,
	.profile-layout {
		grid-template-columns: minmax(0, 1.35fr) minmax(280px, 0.65fr);
	}

	.profile-layout {
		align-items: start;
	}

	.profile-layout > :last-child {
		grid-column: 1 / -1;
	}

	.panel-card,
	.news-block {
		background: rgba(25, 27, 29, 0.78);
		box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.045);
	}

	.section-head,
	.page-heading {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
	}

	.page-heading {
		min-height: 58px;
	}

	.section-kicker {
		color: var(--color-accent);
		font-size: 0.7rem;
		font-weight: 800;
		letter-spacing: 0.16em;
		text-transform: uppercase;
	}

	.section-title {
		margin-top: 4px;
		font-size: 1.05rem;
		font-weight: 700;
	}

	.page-title {
		margin-top: 4px;
		font-size: clamp(1.6rem, 3vw, 2.45rem);
		font-weight: 750;
		line-height: 1.05;
	}

	.ghost-icon-button {
		display: grid;
		width: 38px;
		height: 38px;
		place-items: center;
		border-radius: 14px;
		background: rgba(16, 17, 18, 0.46);
		color: var(--color-muted);
		transition:
			background-color 150ms ease,
			color 150ms ease;
	}

	.ghost-icon-button:hover {
		background: var(--color-panel-strong);
		color: var(--color-foreground);
	}

	.build-select-row,
	.build-card-button {
		display: flex;
		width: 100%;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		border-radius: 18px;
		border: 1px solid transparent;
		background: rgba(16, 17, 18, 0.42);
		padding: 12px;
		transition:
			background-color 150ms ease,
			border-color 150ms ease,
			transform 150ms ease;
	}

	.build-card-button {
		display: block;
		padding: 15px;
	}

	.build-select-row:hover,
	.build-select-row.active,
	.build-card-button:hover,
	.build-card-button.active {
		border-color: rgba(240, 179, 93, 0.42);
		background: rgba(240, 179, 93, 0.1);
	}

	.build-icon {
		display: grid;
		width: 40px;
		height: 40px;
		flex: 0 0 auto;
		place-items: center;
		border-radius: 14px;
		background: rgba(255, 255, 255, 0.05);
		color: var(--color-accent);
	}

	.access-pill,
	.build-tag,
	.impact-pill,
	.news-tag {
		display: inline-flex;
		align-items: center;
		border-radius: 999px;
		font-size: 0.7rem;
		font-weight: 800;
	}

	.access-pill {
		background: rgba(116, 211, 169, 0.12);
		color: var(--color-success);
		padding: 5px 9px;
	}

	.access-pill.locked {
		background: rgba(240, 179, 93, 0.13);
		color: var(--color-accent);
	}

	.build-tag,
	.news-tag {
		background: rgba(255, 255, 255, 0.06);
		color: var(--color-muted);
		padding: 5px 9px;
	}

	.impact-pill {
		background: rgba(117, 199, 192, 0.12);
		color: var(--color-sky);
		padding: 4px 8px;
	}

	.news-item {
		border: 1px solid rgba(255, 255, 255, 0.04);
	}

	.status-grid {
		display: grid;
		grid-template-columns: repeat(3, minmax(0, 1fr));
		gap: 14px;
	}

	.metric-card {
		display: flex;
		align-items: center;
		gap: 12px;
		border: 1px solid var(--color-border);
		border-radius: 22px;
		background: rgba(25, 27, 29, 0.66);
		padding: 16px;
		color: var(--color-accent);
	}

	.metric-label {
		color: var(--color-muted);
		font-size: 0.76rem;
	}

	.metric-value {
		margin-top: 2px;
		color: var(--color-foreground);
		font-weight: 700;
	}

	.control-block,
	.asset-block {
		border-radius: 20px;
		background: rgba(16, 17, 18, 0.44);
		padding: 16px;
	}

	.range-control {
		width: 100%;
		accent-color: var(--color-accent);
	}

	.preset-grid {
		display: grid;
		grid-template-columns: repeat(3, minmax(0, 1fr));
		gap: 10px;
	}

	.preset-button {
		display: grid;
		gap: 6px;
		border-radius: 16px;
		border: 1px solid var(--color-border);
		background: rgba(16, 17, 18, 0.42);
		padding: 13px;
		text-align: left;
		color: var(--color-muted);
		transition:
			background-color 150ms ease,
			border-color 150ms ease,
			color 150ms ease;
	}

	.preset-button span:last-child {
		font-size: 0.74rem;
		line-height: 1.45;
	}

	.preset-button.active {
		border-color: rgba(240, 179, 93, 0.45);
		background: rgba(240, 179, 93, 0.12);
		color: var(--color-foreground);
	}

	.text-field,
	.text-area {
		width: 100%;
		border-radius: 16px;
		border: 1px solid var(--color-border);
		background: rgba(16, 17, 18, 0.56);
		color: var(--color-foreground);
		outline: none;
		transition:
			border-color 150ms ease,
			box-shadow 150ms ease;
	}

	.text-field {
		height: 44px;
		padding: 0 14px;
	}

	.text-area {
		min-height: 150px;
		resize: vertical;
		padding: 13px 14px;
		line-height: 1.6;
	}

	.text-field:focus,
	.text-area:focus {
		border-color: rgba(240, 179, 93, 0.55);
		box-shadow: 0 0 0 4px rgba(240, 179, 93, 0.09);
	}

	.toggle-row {
		display: flex;
		width: 100%;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
		border-radius: 18px;
		background: rgba(16, 17, 18, 0.42);
		padding: 14px;
	}

	.switch {
		position: relative;
		display: inline-flex;
		width: 48px;
		height: 28px;
		flex: 0 0 auto;
		align-items: center;
		border-radius: 999px;
		background: rgba(255, 255, 255, 0.12);
		padding: 3px;
		transition: background-color 150ms ease;
	}

	.switch span {
		width: 22px;
		height: 22px;
		border-radius: 50%;
		background: rgba(255, 255, 255, 0.82);
		transition: transform 150ms ease;
	}

	.switch.enabled {
		background: var(--color-success);
	}

	.switch.enabled span {
		background: var(--color-background);
		transform: translateX(20px);
	}

	.switch.large {
		width: 56px;
		height: 32px;
		border: 0;
	}

	.switch.large span {
		width: 26px;
		height: 26px;
	}

	.switch.large.enabled span {
		transform: translateX(24px);
	}

	.file-chip {
		display: inline-flex;
		max-width: 100%;
		align-items: center;
		gap: 8px;
		border-radius: 14px;
		background: rgba(255, 255, 255, 0.07);
		padding: 8px 10px;
		color: var(--color-foreground);
		font-size: 0.78rem;
	}

	.file-chip span {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.notice-line {
		display: flex;
		align-items: flex-start;
		gap: 10px;
		border-radius: 18px;
		background: rgba(240, 179, 93, 0.1);
		padding: 13px;
		color: var(--color-accent);
		font-size: 0.84rem;
		line-height: 1.55;
	}

	.attach-row {
		display: grid;
		grid-template-columns: auto 38px minmax(0, 1fr);
		align-items: center;
		gap: 12px;
		border-radius: 18px;
		background: rgba(16, 17, 18, 0.42);
		padding: 13px;
	}

	.attach-row input {
		accent-color: var(--color-accent);
	}

	.attach-icon {
		display: grid;
		width: 38px;
		height: 38px;
		place-items: center;
		border-radius: 14px;
		background: rgba(255, 255, 255, 0.06);
		color: var(--color-accent);
	}

	.attach-row strong,
	.attach-row small {
		display: block;
	}

	.attach-row strong {
		font-size: 0.9rem;
	}

	.attach-row small {
		margin-top: 2px;
		color: var(--color-muted);
		font-size: 0.76rem;
	}

	.support-summary-row,
	.subscription-row,
	.quick-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		border-radius: 18px;
		background: rgba(16, 17, 18, 0.42);
		padding: 13px;
	}

	.support-summary-row span {
		color: var(--color-muted);
		font-size: 0.84rem;
	}

	.support-summary-row strong {
		font-size: 0.88rem;
	}

	.avatar-badge {
		display: grid;
		width: 42px;
		height: 42px;
		place-items: center;
		border-radius: 16px;
		background: rgba(117, 199, 192, 0.13);
		color: var(--color-sky);
	}

	.quick-row {
		justify-content: flex-start;
		color: var(--color-accent);
	}

	.quick-row div {
		color: var(--color-foreground);
	}

	.modal-backdrop {
		position: absolute;
		inset: 0;
		z-index: 40;
		display: grid;
		place-items: center;
		background: rgba(0, 0, 0, 0.42);
		padding: 24px;
		backdrop-filter: blur(14px);
	}

	.privacy-modal {
		width: min(100%, 620px);
		box-shadow: 0 22px 70px rgba(0, 0, 0, 0.42);
	}

	.resize-edge,
	.resize-corner {
		position: absolute;
		z-index: 30;
		border: 0;
		background: transparent;
		padding: 0;
	}

	.resize-n,
	.resize-s {
		left: 18px;
		right: 18px;
		height: 8px;
	}

	.resize-n {
		top: 0;
		cursor: ns-resize;
	}

	.resize-s {
		bottom: 0;
		cursor: ns-resize;
	}

	.resize-e,
	.resize-w {
		top: 18px;
		bottom: 18px;
		width: 8px;
	}

	.resize-e {
		right: 0;
		cursor: ew-resize;
	}

	.resize-w {
		left: 0;
		cursor: ew-resize;
	}

	.resize-corner {
		width: 22px;
		height: 22px;
	}

	.resize-ne {
		top: 0;
		right: 0;
		cursor: nesw-resize;
	}

	.resize-nw {
		top: 0;
		left: 0;
		cursor: nwse-resize;
	}

	.resize-se {
		right: 0;
		bottom: 0;
		cursor: nwse-resize;
	}

	.resize-sw {
		bottom: 0;
		left: 0;
		cursor: nesw-resize;
	}

	@media (max-width: 1180px) {
		.launcher-layout {
			grid-template-columns: 236px minmax(0, 1fr);
		}

		.home-columns,
		.settings-layout,
		.settings-layout.bottom,
		.support-layout,
		.profile-layout {
			grid-template-columns: 1fr;
		}

		.profile-layout > :last-child {
			grid-column: auto;
		}
	}

	@media (max-width: 860px) {
		.window-stage.expanded {
			--shell-height: calc(100% - 28px);
			--shell-width: calc(100% - 28px);
		}

		.launcher-layout {
			grid-template-columns: 1fr;
		}

		.sidebar-surface {
			display: none;
		}

		.mobile-nav-wrap {
			display: grid;
			grid-template-columns: repeat(4, minmax(0, 1fr));
		}

		.workspace {
			padding: 18px;
		}

		.status-grid,
		.preset-grid {
			grid-template-columns: 1fr;
		}

		.page-heading {
			align-items: flex-start;
			flex-direction: column;
		}

		.section-head {
			align-items: center;
			flex-direction: row;
		}

		.play-dock,
		.play-button.compact {
			width: 100%;
		}
	}
</style>
