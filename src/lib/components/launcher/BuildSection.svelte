<script lang="ts">
	import { FolderPlus, Image, X, Zap } from '@lucide/svelte';
	import type { BuildProfile, Preset, PresetId } from '$lib/launcher-ui';

	type Props = {
		builds: BuildProfile[];
		activeBuild: BuildProfile;
		selectedBuildId: string;
		presets: Preset[];
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

	let shaderInput = $state<HTMLInputElement | null>(null);
	let resourcePackInput = $state<HTMLInputElement | null>(null);
</script>

<div class="settings-content">
	<div class="settings-layout">
		<section class="panel-card rounded-[20px] p-4">
			<div class="section-head">
				<h3 class="section-title">Сборка</h3>
			</div>

			<div class="settings-stack mt-3">
				{#each builds as build}
					<button
						class:active={selectedBuildId === build.id}
						class="build-card-button compact-build-button"
						title={build.subtitle}
						type="button"
						onclick={() => selectBuild(build.id)}
					>
						<div class="flex items-center justify-between gap-3">
							<p class="min-w-0 truncate text-left text-sm font-semibold">{build.name}</p>
							<span class="build-tag">{build.tag}</span>
						</div>
						<div class="build-meta-line">
							<span>{build.minecraft}</span>
							<span>{build.size}</span>
						</div>
					</button>
				{/each}
			</div>
		</section>

		<section class="panel-card settings-panel rounded-[20px] p-4">
			<div class="section-head">
				<h3 class="section-title">Память</h3>
				<span class="ram-badge">{activeBuild.selectedRam} ГБ</span>
			</div>

			<div class="settings-stack mt-3">
				<div class="control-block">
					<div class="flex items-center justify-between gap-3">
						<label class="text-sm font-semibold" for="ram-range">ОЗУ</label>
						<span class="text-sm text-muted">4-16 ГБ</span>
					</div>
					<input
						id="ram-range"
						class="range-control mt-3"
						type="range"
						min="4"
						max="16"
						step="1"
						value={activeBuild.selectedRam}
						oninput={setRamFromInput}
					/>
				</div>

				<div class="preset-grid compact-presets">
					{#each presets as preset}
						<button
							class:active={activeBuild.preset === preset.id}
							class="preset-button"
							title={preset.description}
							type="button"
							onclick={() => setPreset(preset.id)}
						>
							<span class="font-semibold">{preset.name}</span>
						</button>
					{/each}
				</div>

				<div class="java-inline">
					<label class="sr-only" for="java-path">Путь к Java</label>
					<input
						id="java-path"
						aria-label="Путь к Java"
						class="text-field"
						value={activeBuild.javaPath}
						oninput={setJavaPath}
						spellcheck="false"
					/>
					<button
						class="secondary-button icon-only-button"
						title="Подставить рекомендуемый путь"
						type="button"
						onclick={useSuggestedJavaPath}
					>
						<FolderPlus size={18} />
					</button>
				</div>
			</div>
		</section>
	</div>

	<div class="settings-layout bottom">
		<section class="panel-card rounded-[20px] p-4">
			<div class="section-head">
				<h3 class="section-title">Моды</h3>
			</div>

			<div class="settings-stack mt-3">
				{#each activeBuild.mods as mod}
					<button
						class="toggle-row compact-toggle-row"
						title={mod.description}
						type="button"
						onclick={() => toggleMod(mod.id)}
					>
						<div class="min-w-0 text-left">
							<div class="flex flex-wrap items-center gap-2">
								<p class="text-sm font-semibold">{mod.name}</p>
								<span class="impact-pill">{mod.impact}</span>
							</div>
						</div>
						<span class:enabled={mod.enabled} class="switch" aria-hidden="true">
							<span></span>
						</span>
					</button>
				{/each}
			</div>
		</section>

		<section class="panel-card rounded-[20px] p-4">
			<div class="section-head">
				<h3 class="section-title">Файлы</h3>
			</div>

			<div class="settings-stack mt-3">
				<div class="asset-block compact-asset-block">
					<div class="asset-head">
						<div class="flex min-w-0 items-center gap-2">
							<Zap size={17} class="text-accent" />
							<p class="text-sm font-semibold">Шейдеры</p>
						</div>
						<button
							class="mini-button icon-only-button"
							title="Добавить шейдеры"
							type="button"
							onclick={() => shaderInput?.click()}
						>
							<FolderPlus size={16} />
						</button>
						<input
							bind:this={shaderInput}
							hidden
							multiple
							type="file"
							accept=".zip"
							onchange={addShaderFiles}
						/>
					</div>
					<div class="file-chip-row">
						{#if activeBuild.shaders.length}
							{#each activeBuild.shaders as shader}
								<button class="file-chip" type="button" onclick={() => removeShader(shader)}>
									<span>{shader}</span>
									<X size={13} />
								</button>
							{/each}
						{:else}
							<span class="empty-chip">Пусто</span>
						{/if}
					</div>
				</div>

				<div class="asset-block compact-asset-block">
					<div class="asset-head">
						<div class="flex min-w-0 items-center gap-2">
							<Image size={17} class="text-success" />
							<p class="text-sm font-semibold">Ресурспаки</p>
						</div>
						<button
							class="mini-button icon-only-button"
							title="Добавить ресурспаки"
							type="button"
							onclick={() => resourcePackInput?.click()}
						>
							<FolderPlus size={16} />
						</button>
						<input
							bind:this={resourcePackInput}
							hidden
							multiple
							type="file"
							accept=".zip"
							onchange={addResourcePackFiles}
						/>
					</div>
					<div class="file-chip-row">
						{#if activeBuild.resourcePacks.length}
							{#each activeBuild.resourcePacks as pack}
								<button class="file-chip" type="button" onclick={() => removeResourcePack(pack)}>
									<span>{pack}</span>
									<X size={13} />
								</button>
							{/each}
						{:else}
							<span class="empty-chip">Пусто</span>
						{/if}
					</div>
				</div>
			</div>
		</section>
	</div>
</div>
