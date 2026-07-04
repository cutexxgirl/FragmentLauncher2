<script lang="ts">
	import { AlertCircle, LoaderCircle, Minus, Send, ShieldCheck, X } from '@lucide/svelte';

	type AuthState = 'checking' | 'signed-out' | 'waiting' | 'signed-in' | 'error';

	type Props = {
		authState: AuthState;
		authError: string;
		loginWithTelegram: () => void | Promise<void>;
		startDrag: () => void | Promise<void>;
		minimize: () => void | Promise<void>;
		closeWindow: () => void | Promise<void>;
	};

	let { authState, authError, loginWithTelegram, startDrag, minimize, closeWindow }: Props = $props();

	let isChecking = $derived(authState === 'checking');
	let statusText = $derived(
		authState === 'checking'
			? 'Проверяем сохранённую сессию'
			: authState === 'waiting'
				? 'Ожидаем подтверждение в Telegram'
				: authState === 'error'
					? authError || 'Не удалось начать вход'
					: 'Telegram откроется в системном приложении или браузере',
	);
	let buttonText = $derived(
		authState === 'waiting' ? 'Открыть Telegram' : 'Войти через Telegram',
	);
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
		<div class="auth-login-panel">
			<div class:error={authState === 'error'} class:waiting={isChecking || authState === 'waiting'} class="auth-login-icon">
				{#if authState === 'error'}
					<AlertCircle size={24} />
				{:else if isChecking}
					<LoaderCircle class="spin-icon" size={24} />
				{:else}
					<ShieldCheck size={24} />
				{/if}
			</div>

			<div class="auth-login-copy">
				<p class="section-kicker">Аккаунт Fragment</p>
				<h1>Вход через Telegram</h1>
				<p>Подтвердите аккаунт в боте, и лаунчер сам продолжит запуск.</p>
			</div>

			<button
				type="button"
				class="primary-button auth-login-button"
				disabled={isChecking}
				onclick={loginWithTelegram}
			>
				{#if isChecking}
					<LoaderCircle class="spin-icon" size={17} />
				{:else}
					<Send size={17} />
				{/if}
				<span>{buttonText}</span>
			</button>

			<div class:danger={authState === 'error'} class:waiting={authState === 'waiting'} class="auth-status-line">
				{#if authState === 'error'}
					<AlertCircle size={15} />
				{:else if authState === 'waiting' || isChecking}
					<LoaderCircle class="spin-icon" size={15} />
				{:else}
					<ShieldCheck size={15} />
				{/if}
				<span>{statusText}</span>
			</div>
		</div>
	</div>
</section>
