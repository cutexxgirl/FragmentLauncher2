<script lang="ts">
	import { Minus, X } from '@lucide/svelte';

	type AuthState = 'checking' | 'signed-out' | 'waiting' | 'signed-in' | 'error';

	type Props = {
		authState: AuthState;
		showTelegramHelp: boolean;
		loginWithTelegram: () => void | Promise<void>;
		openTelegramHelp: () => void | Promise<void>;
		startDrag: () => void | Promise<void>;
		minimize: () => void | Promise<void>;
		closeWindow: () => void | Promise<void>;
	};

	let {
		authState,
		showTelegramHelp,
		loginWithTelegram,
		openTelegramHelp,
		startDrag,
		minimize,
		closeWindow,
	}: Props = $props();

	let isChecking = $derived(authState === 'checking');
</script>

<section class="auth-gate" aria-label="Авторизация">
	<header
		class="auth-gate-titlebar"
		role="toolbar"
		aria-label="Window title bar"
		tabindex="-1"
		onmousedown={startDrag}
	>
		<div class="auth-gate-brand">
			<span class="auth-brand-mark">F</span>
			<span>Fragment Launcher</span>
		</div>

		<div class="titlebar-controls flex items-center gap-1">
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

	<div class="auth-gate-body">
		<button
			type="button"
			class="primary-button auth-login-button"
			disabled={isChecking}
			onclick={loginWithTelegram}
		>
			Войти через Telegram
		</button>
	</div>

	{#if showTelegramHelp}
		<button type="button" class="telegram-help-pill" onclick={openTelegramHelp}>
			Проблемы с подключением в Telegram?
		</button>
	{/if}
</section>
