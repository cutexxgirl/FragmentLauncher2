<script lang="ts">
	import { Sparkles } from '@lucide/svelte';

	type BootPhase = 'boot' | 'expanding' | 'reveal' | 'ready';

	type Props = {
		bootPhase: BootPhase;
		bootProgress: number;
		bootLabel: string;
		startDrag: () => void | Promise<void>;
	};

	let { bootPhase, bootProgress, bootLabel, startDrag }: Props = $props();
</script>

<div
	class:leaving={bootPhase === 'reveal'}
	class="boot-screen flex h-full min-h-0 flex-col justify-between bg-[radial-gradient(circle_at_72%_16%,rgba(240,179,93,0.28)_0,rgba(36,38,40,0.94)_34%,#101112_72%)] px-7 py-6"
	role="toolbar"
	aria-label="Boot window"
	tabindex="-1"
	onmousedown={startDrag}
>
	<div class="flex items-center gap-3">
		<div
			class="brand-mark grid size-11 place-items-center rounded-[14px] bg-accent text-accent-foreground"
		>
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
