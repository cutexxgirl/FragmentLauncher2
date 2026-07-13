<script lang="ts">
	import { AlertTriangle, CheckCircle2, Loader2, X } from '@lucide/svelte';
	import type { TgWsProxyStatus } from '$lib/launcher';

	type Props = {
		proxyStatus: TgWsProxyStatus | null;
		proxyBusy: boolean;
		proxyMessage: string;
		closeTelegramHelp: () => void;
		installTelegramProxy: () => void | Promise<void>;
	};

	let {
		proxyStatus,
		proxyBusy,
		proxyMessage,
		closeTelegramHelp,
		installTelegramProxy,
	}: Props = $props();

	let isRunning = $derived(proxyStatus?.running ?? false);
	let statusText = $derived(
		proxyMessage ||
			(proxyStatus?.message ?? 'Скачайте помощник, если Telegram не открывает вход.'),
	);
</script>

<div class="telegram-help-backdrop">
	<section class="telegram-help-window" aria-label="Помощь Telegram">
		<header class="settings-window-head">
			<div class="modal-title-row">
				<div>
					<h2 class="modal-title">Telegram</h2>
					<p class="modal-context">Помощник подключения</p>
				</div>
			</div>

			<button
				type="button"
				class="ghost-icon-button"
				aria-label="Закрыть"
				onclick={closeTelegramHelp}
			>
				<X size={17} />
			</button>
		</header>

		<div class="telegram-help-window-body">
			<ol class="telegram-help-steps">
				<li>
					<span>1</span>
					<p>Нажмите «Скачать» и дождитесь установки TG WS Proxy.</p>
				</li>
				<li>
					<span>2</span>
					<p>Лаунчер запустит утилиту и создаст ярлык на рабочем столе.</p>
				</li>
				<li>
					<span>3</span>
					<p>Подтвердите прокси в Telegram, затем повторите вход.</p>
				</li>
			</ol>

			<div class:ready={isRunning} class="telegram-help-status">
				{#if proxyBusy}
					<Loader2 class="telegram-help-spinner" size={17} />
				{:else if isRunning}
					<CheckCircle2 size={17} />
				{:else}
					<AlertTriangle size={17} />
				{/if}
				<span>{statusText}</span>
			</div>

			<div class="telegram-help-actions">
				<button
					type="button"
					class="primary-button"
					disabled={proxyBusy || isRunning}
					onclick={installTelegramProxy}
				>
					{#if proxyBusy}
						Устанавливаем
					{:else if isRunning}
						Работает
					{:else}
						Скачать
					{/if}
				</button>
			</div>
		</div>
	</section>
</div>
