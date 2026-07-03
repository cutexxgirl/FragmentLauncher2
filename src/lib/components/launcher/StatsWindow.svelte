<script lang="ts">
	import { X } from '@lucide/svelte';
	import type { BuildProfile } from '$lib/launcher-ui';

	type Props = {
		activeBuild: BuildProfile;
		closeStats: () => void;
	};

	let { activeBuild, closeStats }: Props = $props();

	function closeFromBackdrop(event: MouseEvent) {
		if (event.target === event.currentTarget) {
			closeStats();
		}
	}

	function closeFromKeyboard(event: KeyboardEvent) {
		if (event.key === 'Escape') {
			closeStats();
		}
	}
</script>

<div
	class="stats-backdrop"
	role="button"
	tabindex="-1"
	onclick={closeFromBackdrop}
	onkeydown={closeFromKeyboard}
>
	<div
		class="stats-window"
		role="dialog"
		aria-modal="true"
		aria-label="Статистика"
		tabindex="-1"
	>
		<header class="settings-window-head">
			<div class="modal-title-row">
				<h2 class="modal-title">Статистика</h2>
				<span class="modal-context">{activeBuild.name}</span>
			</div>
			<button type="button" class="ghost-icon-button" title="Закрыть статистику" onclick={closeStats}>
				<X size={18} />
			</button>
		</header>

		<div class="stats-window-body">
			<div class="stats-grid">
				<div class="support-summary-row">
					<span>Сборка</span>
					<strong>{activeBuild.name}</strong>
				</div>
				<div class="support-summary-row">
					<span>Запусков</span>
					<strong>0</strong>
				</div>
				<div class="support-summary-row">
					<span>Время</span>
					<strong>0 ч</strong>
				</div>
			</div>
		</div>
	</div>
</div>
