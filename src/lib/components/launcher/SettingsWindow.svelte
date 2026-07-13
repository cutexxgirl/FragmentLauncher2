<script lang="ts">
	import { X } from '@lucide/svelte';
	import BuildSection from '$lib/components/launcher/BuildSection.svelte';
	import type { BuildProfile, Preset, PresetId } from '$lib/launcher-ui';

	type Props = {
		activeBuild: BuildProfile;
		presets: Preset[];
		installDirectory: string | null;
		closeSettings: () => void;
		setPreset: (presetId: PresetId) => void;
		chooseInstallDirectory: () => void;
	};

	let {
		activeBuild,
		presets,
		installDirectory,
		closeSettings,
		setPreset,
		chooseInstallDirectory,
	}: Props = $props();

	function closeFromBackdrop(event: MouseEvent) {
		if (event.target === event.currentTarget) closeSettings();
	}

	function closeFromKeyboard(event: KeyboardEvent) {
		if (event.key === 'Escape') closeSettings();
	}
</script>

<div
	class="settings-backdrop"
	role="button"
	tabindex="-1"
	onclick={closeFromBackdrop}
	onkeydown={closeFromKeyboard}
>
	<div
		class="settings-window"
		role="dialog"
		aria-modal="true"
		aria-label="Настройки сборки"
		tabindex="-1"
	>
		<header class="settings-window-head">
			<div class="modal-title-row">
				<h2 class="modal-title">Настройки</h2>
				<span class="modal-context">{activeBuild.name}</span>
			</div>
			<button
				type="button"
				class="ghost-icon-button"
				title="Закрыть настройки"
				onclick={closeSettings}
			>
				<X size={18} />
			</button>
		</header>

		<div class="settings-window-body">
			<BuildSection
				{activeBuild}
				{presets}
				{installDirectory}
				{setPreset}
				{chooseInstallDirectory}
			/>
		</div>
	</div>
</div>
