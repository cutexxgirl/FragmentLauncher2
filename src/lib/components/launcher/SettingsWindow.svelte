<script lang="ts">
	import { X } from '@lucide/svelte';
	import BuildSection from '$lib/components/launcher/BuildSection.svelte';
	import type { BuildProfile, Preset, PresetId } from '$lib/launcher-ui';

	type Props = {
		builds: BuildProfile[];
		activeBuild: BuildProfile;
		selectedBuildId: string;
		presets: Preset[];
		closeSettings: () => void;
		selectBuild: (buildId: string) => void;
		setPreset: (presetId: PresetId) => void;
		setRamFromInput: (event: Event) => void;
		setJavaPath: (event: Event) => void;
		useSuggestedJavaPath: () => void;
		toggleMod: (modId: string) => void;
		addShaderFiles: (event: Event) => void;
		addResourcePackFiles: (event: Event) => void;
		removeShader: (name: string) => void;
		removeResourcePack: (name: string) => void;
	};

	let {
		builds,
		activeBuild,
		selectedBuildId,
		presets,
		closeSettings,
		selectBuild,
		setPreset,
		setRamFromInput,
		setJavaPath,
		useSuggestedJavaPath,
		toggleMod,
		addShaderFiles,
		addResourcePackFiles,
		removeShader,
		removeResourcePack
	}: Props = $props();
</script>

<div class="settings-backdrop">
	<div class="settings-window" role="dialog" aria-modal="true" aria-label="Настройки сборки" tabindex="-1">
		<header class="settings-window-head">
			<div>
				<p class="section-kicker">Настройки</p>
				<h2 class="page-title">{activeBuild.name}</h2>
			</div>
			<button type="button" class="ghost-icon-button" title="Закрыть настройки" onclick={closeSettings}>
				<X size={18} />
			</button>
		</header>

		<div class="settings-window-body">
			<BuildSection
				{builds}
				{activeBuild}
				{selectedBuildId}
				{presets}
				{selectBuild}
				{setPreset}
				{setRamFromInput}
				{setJavaPath}
				{useSuggestedJavaPath}
				{toggleMod}
				{addShaderFiles}
				{addResourcePackFiles}
				{removeShader}
				{removeResourcePack}
			/>
		</div>
	</div>
</div>
