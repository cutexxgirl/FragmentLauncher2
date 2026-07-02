<script lang="ts">
	import { Minus, Square, X } from '@lucide/svelte';

	type Props = {
		startDrag: () => void | Promise<void>;
		toggleMaximize: () => void | Promise<void>;
		minimize: () => void | Promise<void>;
		closeWindow: () => void | Promise<void>;
	};

	let { startDrag, toggleMaximize, minimize, closeWindow }: Props = $props();
</script>

<header
	class="titlebar flex h-[48px] select-none items-center justify-end px-4"
	role="toolbar"
	aria-label="Window title bar"
	tabindex="-1"
	onmousedown={startDrag}
	ondblclick={toggleMaximize}
>
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
