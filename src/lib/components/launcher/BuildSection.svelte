<script lang="ts">
	import { Coffee, FolderOpen, HardDrive, ShieldCheck } from '@lucide/svelte';
	import type { BuildProfile, Preset, PresetId } from '$lib/launcher-ui';

	type Props = {
		activeBuild: BuildProfile;
		presets: Preset[];
		installDirectory: string | null;
		setPreset: (presetId: PresetId) => void;
		chooseInstallDirectory: () => void;
	};

	let {
		activeBuild,
		presets,
		installDirectory,
		setPreset,
		chooseInstallDirectory,
	}: Props = $props();

	let activePreset = $derived(presets.find((preset) => preset.id === activeBuild.preset));
</script>

<div class="settings-content secure-build-settings">
	<section class="panel-card settings-panel rounded-[20px] p-5">
		<div class="section-head">
			<div>
				<h3 class="section-title">Пресет качества</h3>
				<p class="mt-1 text-sm text-muted">Состав каждого пресета подписан Spark2.</p>
			</div>
			<span class="ram-badge">{activePreset?.ram ?? 0} ГБ</span>
		</div>

		<div class="preset-grid mt-4">
			{#each presets as preset}
				<button
					class:active={activeBuild.preset === preset.id}
					class="preset-button secure-preset-button"
					type="button"
					aria-pressed={activeBuild.preset === preset.id}
					onclick={() => setPreset(preset.id)}
				>
					<span class="font-semibold">{preset.name}</span>
					<small>{preset.description}</small>
					<small>{preset.ram} ГБ ОЗУ</small>
				</button>
			{/each}
		</div>
	</section>

	<section class="panel-card rounded-[20px] p-5">
		<div class="section-head">
			<div>
				<h3 class="section-title">Папка установки</h3>
				<p class="mt-1 text-sm text-muted">Можно выбрать любой подходящий локальный диск.</p>
			</div>
			<HardDrive size={20} class="text-accent" />
		</div>

		<div class="install-location-card mt-4">
			<div class="min-w-0">
				<p class="text-sm font-semibold">Fragment</p>
				<p class="install-location-path">
					{installDirectory ?? 'Папка будет выбрана перед первой загрузкой'}
				</p>
			</div>
			<button class="secondary-button" type="button" onclick={chooseInstallDirectory}>
				<FolderOpen size={17} />
				<span>Выбрать</span>
			</button>
		</div>
	</section>

	<div class="secure-runtime-grid">
		<section class="panel-card rounded-[20px] p-4">
			<div class="flex items-center gap-3">
				<Coffee size={20} class="text-accent" />
				<div>
					<p class="text-sm font-semibold">Управляемая Java 21</p>
					<p class="text-xs text-muted">Лаунчер установит и проверит runtime сам.</p>
				</div>
			</div>
		</section>
		<section class="panel-card rounded-[20px] p-4">
			<div class="flex items-center gap-3">
				<ShieldCheck size={20} class="text-success" />
				<div>
					<p class="text-sm font-semibold">Целостность Spark2</p>
					<p class="text-xs text-muted">Сторонние моды и пакеты блокируют запуск.</p>
				</div>
			</div>
		</section>
	</div>
</div>
