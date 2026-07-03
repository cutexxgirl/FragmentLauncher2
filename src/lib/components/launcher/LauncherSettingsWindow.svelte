<script lang="ts">
	import { X } from '@lucide/svelte';

	type Props = {
		launcherVersion: string;
		anonymizeAnalytics: boolean;
		includeDiagnosticsInSupport: boolean;
		closeLauncherSettings: () => void;
	};

	let {
		launcherVersion,
		anonymizeAnalytics = $bindable(),
		includeDiagnosticsInSupport = $bindable(),
		closeLauncherSettings
	}: Props = $props();

	function closeFromBackdrop(event: MouseEvent) {
		if (event.target === event.currentTarget) {
			closeLauncherSettings();
		}
	}

	function closeFromKeyboard(event: KeyboardEvent) {
		if (event.key === 'Escape') {
			closeLauncherSettings();
		}
	}
</script>

<div
	class="launcher-settings-backdrop"
	role="button"
	tabindex="-1"
	onclick={closeFromBackdrop}
	onkeydown={closeFromKeyboard}
>
	<div
		class="launcher-settings-window"
		role="dialog"
		aria-modal="true"
		aria-label="Настройки лаунчера"
		tabindex="-1"
	>
		<header class="settings-window-head">
			<div class="modal-title-row">
				<h2 class="modal-title">Лаунчер</h2>
				<span class="modal-context">v{launcherVersion}</span>
			</div>
			<button type="button" class="ghost-icon-button" title="Закрыть настройки" onclick={closeLauncherSettings}>
				<X size={18} />
			</button>
		</header>

		<div class="launcher-settings-window-body">
			<div class="launcher-settings-list">
				<button
					type="button"
					class="toggle-row settings-toggle-row"
					onclick={() => (anonymizeAnalytics = !anonymizeAnalytics)}
				>
					<span>Анонимная аналитика</span>
					<span class:enabled={anonymizeAnalytics} class="switch" aria-hidden="true">
						<span></span>
					</span>
				</button>

				<button
					type="button"
					class="toggle-row settings-toggle-row"
					title="Прикладывать характеристики ПК к обращению"
					onclick={() => (includeDiagnosticsInSupport = !includeDiagnosticsInSupport)}
				>
					<span>Диагностика</span>
					<span class:enabled={includeDiagnosticsInSupport} class="switch" aria-hidden="true">
						<span></span>
					</span>
				</button>
			</div>
		</div>
	</div>
</div>
