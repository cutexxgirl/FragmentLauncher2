<script lang="ts">
	import { Download, Minus, Play, Settings, Sparkles, Square, X } from '@lucide/svelte';
	import { browser } from '$app/environment';
	import { onMount } from 'svelte';
	import { getCurrentWindow } from '@tauri-apps/api/window';
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

	let status = $state<LauncherStatus>({
		appName: 'Fragment Launcher',
		version: '1.0.0',
		profile: 'singleplayer',
		servicesConnected: false,
		updaterReady: true
	});

	const appWindow = browser ? getCurrentWindow() : null;

	onMount(async () => {
		status = await getLauncherStatus();
	});

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
	class="app-shell absolute grid grid-cols-[320px_1fr] overflow-hidden rounded-[18px] border border-border bg-background text-foreground"
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

	<aside class="flex min-h-0 flex-col border-r border-border bg-panel px-6 py-5">
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

	<section class="flex min-w-0 flex-col bg-[radial-gradient(circle_at_68%_18%,#263243_0,#0c0f14_42%)]">
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

	.window-shadow {
		position: absolute;
		pointer-events: none;
		border-radius: 20px;
	}

	.shadow-cast {
		inset: 24px 38px 38px 24px;
		background: rgba(0, 0, 0, 0.42);
		filter: blur(24px);
		opacity: 0.55;
		transform: translate(12px, 14px);
		mask-image: linear-gradient(
			135deg,
			rgba(0, 0, 0, 0.18) 0%,
			rgba(0, 0, 0, 0.62) 44%,
			#000 100%
		);
		-webkit-mask-image: linear-gradient(
			135deg,
			rgba(0, 0, 0, 0.18) 0%,
			rgba(0, 0, 0, 0.62) 44%,
			#000 100%
		);
	}

	.shadow-contact {
		right: 62px;
		bottom: 31px;
		left: 44px;
		height: 30px;
		border-radius: 999px;
		background: radial-gradient(
			ellipse at 56% 50%,
			rgba(0, 0, 0, 0.28) 0%,
			rgba(0, 0, 0, 0.18) 42%,
			rgba(0, 0, 0, 0.06) 68%,
			transparent 86%
		);
		filter: blur(12px);
		opacity: 0.72;
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
