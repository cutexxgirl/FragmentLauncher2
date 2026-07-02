<script lang="ts">
	import { BarChart3, Headphones, Minus, Settings, SlidersHorizontal, User, X } from '@lucide/svelte';

	type Props = {
		startDrag: () => void | Promise<void>;
		minimize: () => void | Promise<void>;
		closeWindow: () => void | Promise<void>;
		openSupport: () => void;
		openProfile: () => void;
		openStats: () => void;
		openSettings: () => void;
	};

	let {
		startDrag,
		minimize,
		closeWindow,
		openSupport,
		openProfile,
		openStats,
		openSettings
	}: Props = $props();

	let menuOpen = $state(false);

	function runMenuAction(action: () => void) {
		menuOpen = false;
		action();
	}
</script>

<header
	class="titlebar flex h-[48px] select-none items-center justify-end px-4"
	role="toolbar"
	aria-label="Window title bar"
	tabindex="-1"
	onmousedown={startDrag}
>
	<div class="titlebar-controls flex items-center gap-1">
		<div class="titlebar-menu">
			<button
				class:active={menuOpen}
				class="window-control"
				aria-label="Launcher menu"
				title="Меню"
				onmousedown={(event) => event.stopPropagation()}
				onclick={() => (menuOpen = !menuOpen)}
			>
				<Settings size={16} />
			</button>

			{#if menuOpen}
				<div class="titlebar-dropdown">
					<button
						type="button"
						onmousedown={(event) => event.stopPropagation()}
						onclick={() => runMenuAction(openSupport)}
					>
						<Headphones size={15} />
						<span>Техподдержка</span>
					</button>
					<button
						type="button"
						onmousedown={(event) => event.stopPropagation()}
						onclick={() => runMenuAction(openProfile)}
					>
						<User size={15} />
						<span>Профиль</span>
					</button>
					<button
						type="button"
						onmousedown={(event) => event.stopPropagation()}
						onclick={() => runMenuAction(openStats)}
					>
						<BarChart3 size={15} />
						<span>Статистика</span>
					</button>
					<button
						type="button"
						onmousedown={(event) => event.stopPropagation()}
						onclick={() => runMenuAction(openSettings)}
					>
						<SlidersHorizontal size={15} />
						<span>Настройки</span>
					</button>
				</div>
			{/if}
		</div>

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
