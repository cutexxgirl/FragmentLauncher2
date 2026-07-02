<script lang="ts">
	import { Download, Minus, Play, Settings, Sparkles, Square, X } from '@lucide/svelte';
	import { browser } from '$app/environment';
	import { onMount } from 'svelte';
	import { getCurrentWindow } from '@tauri-apps/api/window';
	import { LogicalSize, PhysicalPosition, PhysicalSize } from '@tauri-apps/api/dpi';
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
	let bootVisible = $derived(bootPhase !== 'ready');
	let launcherVisible = $derived(bootPhase === 'reveal' || bootPhase === 'ready');

	const appWindow = browser ? getCurrentWindow() : null;

	onMount(async () => {
		await runBootSequence();
	});

	function setBootStep(progress: number, label: string) {
		bootProgress = progress;
		bootLabel = label;
	}

	function smootherStep(value: number) {
		return value * value * value * (value * (value * 6 - 15) + 10);
	}

	function delay(ms: number) {
		return new Promise((resolve) => window.setTimeout(resolve, ms));
	}

	async function animateWindowSize(width: number, height: number, duration = 460) {
		if (!appWindow) {
			return;
		}

		const scaleFactor = await appWindow.scaleFactor();
		const startSize = await appWindow.outerSize();
		const startPosition = await appWindow.outerPosition();
		const targetSize = new LogicalSize(width, height).toPhysical(scaleFactor);
		const centerX = startPosition.x + startSize.width / 2;
		const centerY = startPosition.y + startSize.height / 2;
		const startedAt = performance.now();

		await new Promise<void>((resolve) => {
			let pendingResize: Promise<unknown> | undefined;

			const frame = (now: number) => {
				const t = Math.min(1, (now - startedAt) / duration);
				const eased = smootherStep(t);
				const nextWidth = Math.round(startSize.width + (targetSize.width - startSize.width) * eased);
				const nextHeight = Math.round(startSize.height + (targetSize.height - startSize.height) * eased);
				const nextX = Math.round(centerX - nextWidth / 2);
				const nextY = Math.round(centerY - nextHeight / 2);

				pendingResize = Promise.all([
					appWindow.setSize(new PhysicalSize(nextWidth, nextHeight)),
					appWindow.setPosition(new PhysicalPosition(nextX, nextY))
				]);

				if (t < 1) {
					requestAnimationFrame(frame);
					return;
				}

				pendingResize.finally(resolve);
			};

			requestAnimationFrame(frame);
		});
	}

	async function runBootSequence() {
		setBootStep(0.18, 'Готовим интерфейс');
		await delay(80);

		setBootStep(0.46, 'Подключаем локальный бекенд');
		status = await getLauncherStatus();
		await delay(80);

		setBootStep(0.68, 'Проверяем профиль сборки');
		await appWindow?.setMinSize(new LogicalSize(520, 320));
		await delay(80);

		setBootStep(0.84, 'Разворачиваем лаунчер');
		bootPhase = 'expanding';
		await animateWindowSize(1320, 800);
		await appWindow?.setMinSize(new LogicalSize(1100, 680));

		setBootStep(1, 'Готово');
		await delay(80);
		bootPhase = 'reveal';
		await delay(420);
		bootPhase = 'ready';
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

<div class="window-stage fixed inset-0 overflow-hidden">
	<div class="window-shadow shadow-cast"></div>
	<div class="window-shadow shadow-contact"></div>

<main
	class="app-shell absolute overflow-hidden rounded-[18px] border border-border bg-background text-foreground"
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
			class="boot-screen flex h-full min-h-0 flex-col justify-between bg-[radial-gradient(circle_at_70%_18%,#263243_0,#0c0f14_52%)] px-7 py-6"
			role="toolbar"
			aria-label="Boot window"
			tabindex="-1"
			onmousedown={startDrag}
		>
			<div class="flex items-center gap-3">
				<div class="grid size-10 place-items-center rounded-md bg-accent text-accent-foreground">
					<Sparkles size={20} strokeWidth={2.2} />
				</div>
				<div>
					<p class="text-sm font-medium text-muted">Fragment</p>
					<h1 class="text-xl font-semibold leading-tight">Launcher</h1>
				</div>
			</div>

			<div>
				<p class="text-xs uppercase tracking-[0.18em] text-accent">Запуск</p>
				<p class="mt-3 text-2xl font-semibold">{bootLabel}</p>
				<div class="mt-6 h-1.5 overflow-hidden rounded-full bg-panel-strong">
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
	<aside class="launcher-surface flex min-h-0 flex-col border-r border-border bg-panel px-6 py-5">
		<div class="flex items-center gap-3">
			<div class="grid size-10 place-items-center rounded-md bg-accent text-accent-foreground">
				<Sparkles size={20} strokeWidth={2.2} />
			</div>
			<div>
				<p class="text-sm font-medium text-muted">Fragment</p>
				<h1 class="text-xl font-semibold leading-tight">Launcher</h1>
			</div>
		</div>

		<nav class="mt-8 grid gap-2">
			<button class="flex h-10 items-center gap-3 rounded-md bg-panel-strong px-3 text-left text-sm font-medium">
				<Play size={17} />
				Играть
			</button>
			<button
				class="flex h-10 items-center gap-3 rounded-md px-3 text-left text-sm text-muted transition hover:bg-panel-strong hover:text-foreground"
			>
				<Download size={17} />
				Обновления
			</button>
			<button
				class="flex h-10 items-center gap-3 rounded-md px-3 text-left text-sm text-muted transition hover:bg-panel-strong hover:text-foreground"
			>
				<Settings size={17} />
				Настройки
			</button>
		</nav>

		<div class="mt-auto rounded-md border border-border bg-background/45 p-4">
			<p class="text-xs uppercase tracking-[0.18em] text-muted">Версия</p>
			<p class="mt-2 text-lg font-semibold">{status.version}</p>
		</div>
	</aside>

	<section class="launcher-surface flex min-w-0 flex-col bg-[radial-gradient(circle_at_68%_18%,#263243_0,#0c0f14_42%)]">
		<header
			class="flex h-14 select-none items-center justify-between border-b border-border px-5"
			role="toolbar"
			aria-label="Window title bar"
			tabindex="-1"
			onmousedown={startDrag}
			ondblclick={toggleMaximize}
		>
			<div class="flex items-center gap-3">
				<span class="size-2 rounded-full bg-success"></span>
				<div>
					<p class="text-xs text-muted">Профиль</p>
					<p class="text-sm font-medium">Одиночная сборка</p>
				</div>
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
		</header>

		<div class="grid flex-1 content-between px-8 py-8">
			<div class="max-w-3xl">
				<p class="text-sm font-medium uppercase tracking-[0.18em] text-accent">Minecraft modpack</p>
				<h2 class="mt-4 text-5xl font-semibold leading-[1.05]">Fragment Launcher</h2>
				<p class="mt-5 max-w-2xl text-base leading-7 text-muted">
					Каркас для одиночной сборки готов: локальный Tauri-бекенд, статический SvelteKit-фронтенд и
					место под обновления без подключения внешних сервисов.
				</p>
			</div>

			<div class="grid grid-cols-3 gap-4">
				<div class="rounded-md border border-border bg-panel/90 p-5">
					<p class="text-sm text-muted">Режим</p>
					<p class="mt-3 text-xl font-semibold">Singleplayer</p>
				</div>
				<div class="rounded-md border border-border bg-panel/90 p-5">
					<p class="text-sm text-muted">Сервисы</p>
					<p class="mt-3 text-xl font-semibold">
						{status.servicesConnected ? 'Подключены' : 'Отключены'}
					</p>
				</div>
				<div class="rounded-md border border-border bg-panel/90 p-5">
					<p class="text-sm text-muted">Updater</p>
					<p class="mt-3 text-xl font-semibold">{status.updaterReady ? 'Tauri' : 'Не настроен'}</p>
				</div>
			</div>

			<div class="flex items-center gap-3">
				<button
					class="inline-flex h-12 items-center gap-3 rounded-md bg-accent px-5 text-sm font-semibold text-accent-foreground transition hover:brightness-105"
				>
					<Play size={18} fill="currentColor" />
					Играть
				</button>
				<button
					class="inline-flex h-12 items-center gap-3 rounded-md border border-border bg-panel px-5 text-sm font-medium text-muted transition hover:text-foreground"
				>
					<Settings size={18} />
					Настройки
				</button>
			</div>
		</div>
	</section>
	</div>
</main>
</div>

<style>
	.window-stage {
		pointer-events: none;
	}

	.app-shell {
		inset: 24px 38px 38px 24px;
		pointer-events: auto;
		filter: drop-shadow(0 2px 5px rgba(0, 0, 0, 0.24));
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
		grid-template-columns: 320px 1fr;
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

	.launcher-surface {
		animation: launcher-surface-in 380ms cubic-bezier(0.22, 1, 0.36, 1) both;
	}

	.launcher-surface:nth-of-type(2) {
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
		border-radius: 20px;
	}

	.shadow-cast {
		inset: 24px 38px 38px 24px;
		background: transparent;
		box-shadow: 14px 16px 26px 6px rgba(0, 0, 0, 0.42);
		opacity: 0.9;
		transform: translate(2px, 2px);
		mask-image: linear-gradient(
			135deg,
			rgba(0, 0, 0, 0.08) 0%,
			rgba(0, 0, 0, 0.55) 38%,
			#000 100%
		);
		-webkit-mask-image: linear-gradient(
			135deg,
			rgba(0, 0, 0, 0.08) 0%,
			rgba(0, 0, 0, 0.55) 38%,
			#000 100%
		);
	}

	.shadow-contact {
		right: 62px;
		bottom: 31px;
		left: 44px;
		height: 30px;
		border-radius: 999px;
		background: rgba(0, 0, 0, 0.28);
		filter: blur(14px);
		opacity: 0.76;
		transform: translate(10px, 2px);
	}

	.window-control {
		display: grid;
		width: 34px;
		height: 30px;
		place-items: center;
		border-radius: 6px;
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
		background: #c94d4d;
		color: white;
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
		left: 10px;
		right: 10px;
		height: 6px;
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
		top: 10px;
		bottom: 10px;
		width: 6px;
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
		width: 12px;
		height: 12px;
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
</style>
