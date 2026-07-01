<script lang="ts">
	import { Download, Play, Settings, Sparkles } from '@lucide/svelte';
	import { onMount } from 'svelte';
	import { getLauncherStatus, type LauncherStatus } from '$lib/launcher';

	let status = $state<LauncherStatus>({
		appName: 'Fragment Launcher',
		version: '1.0.0',
		profile: 'singleplayer',
		servicesConnected: false,
		updaterReady: true
	});

	onMount(async () => {
		status = await getLauncherStatus();
	});
</script>

<main class="grid h-screen grid-cols-[320px_1fr] bg-background text-foreground">
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
		<header class="flex h-16 items-center justify-between border-b border-border px-8">
			<div>
				<p class="text-sm text-muted">Профиль</p>
				<p class="font-medium">Одиночная сборка</p>
			</div>
			<div class="flex items-center gap-2 rounded-md border border-border bg-panel px-3 py-2 text-sm">
				<span class="size-2 rounded-full bg-success"></span>
				Локально
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
