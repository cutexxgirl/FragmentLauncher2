<script lang="ts">
import { FolderPlus, Image, Info, Package, X, Zap } from '@lucide/svelte';
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

<div class="section-grid">
							<div class="page-heading">
								<div>
									<p class="section-kicker">Настройки сборки</p>
									<h2 class="page-title">{activeBuild.name}</h2>
								</div>
							</div>

							<div class="settings-layout">
								<section class="panel-card rounded-[24px] border border-border p-4">
									<div class="section-head">
										<div>
											<p class="section-kicker">Профиль</p>
											<h3 class="section-title">Выбор сборки</h3>
										</div>
									</div>
									<div class="mt-4 grid gap-3">
										{#each builds as build}
											<button
												class:active={selectedBuildId === build.id}
												class="build-card-button"
												onclick={() => selectBuild(build.id)}
											>
												<div class="flex items-start justify-between gap-3">
													<div class="text-left">
														<p class="text-base font-semibold">{build.name}</p>
														<p class="mt-1 text-sm leading-6 text-muted">{build.subtitle}</p>
													</div>
													<span class="build-tag">{build.tag}</span>
												</div>
												<div class="mt-4 flex flex-wrap gap-2 text-xs text-muted">
													<span>{build.version}</span>
													<span>{build.minecraft}</span>
													<span>{build.size}</span>
												</div>
											</button>
										{/each}
									</div>
								</section>

								<section class="panel-card settings-panel rounded-[24px] border border-border p-5">
									<div class="section-head">
										<div>
											<p class="section-kicker">Производительность</p>
											<h3 class="section-title">ОЗУ и пресет</h3>
										</div>
										<span class="rounded-[14px] bg-success/12 px-3 py-1.5 text-xs font-semibold text-success">
											{activeBuild.selectedRam} ГБ
										</span>
									</div>

									<div class="mt-5 grid gap-4">
										<div class="control-block">
											<div class="flex items-center justify-between gap-3">
												<label class="text-sm font-semibold" for="ram-range">Выделить памяти</label>
												<span class="text-sm text-muted">4-16 ГБ</span>
											</div>
											<input
												id="ram-range"
												class="range-control mt-4"
												type="range"
												min="4"
												max="16"
												step="1"
												value={activeBuild.selectedRam}
												oninput={setRamFromInput}
											/>
										</div>

										<div class="preset-grid">
											{#each presets as preset}
												<button
													class:active={activeBuild.preset === preset.id}
													class="preset-button"
													onclick={() => setPreset(preset.id)}
												>
													<span class="font-semibold">{preset.name}</span>
													<span>{preset.description}</span>
												</button>
											{/each}
										</div>

										<div class="control-block">
											<label class="text-sm font-semibold" for="java-path">Путь к Java</label>
											<div class="mt-3 flex flex-col gap-2 sm:flex-row">
												<input
													id="java-path"
													class="text-field"
													value={activeBuild.javaPath}
													oninput={setJavaPath}
													spellcheck="false"
												/>
												<button class="secondary-button shrink-0" onclick={useSuggestedJavaPath}>
													<FolderPlus size={17} />
													<span>Подставить</span>
												</button>
											</div>
										</div>
									</div>
								</section>
							</div>

							<div class="settings-layout bottom">
								<section class="panel-card rounded-[24px] border border-border p-5">
									<div class="section-head">
										<div>
											<p class="section-kicker">Опции</p>
											<h3 class="section-title">Опциональные моды</h3>
										</div>
										<span class="text-xs text-muted">Свои моды отключены</span>
									</div>

									<div class="mt-4 grid gap-3">
										{#each activeBuild.mods as mod}
											<button class="toggle-row" onclick={() => toggleMod(mod.id)}>
												<div class="min-w-0 text-left">
													<div class="flex flex-wrap items-center gap-2">
														<p class="text-sm font-semibold">{mod.name}</p>
														<span class="impact-pill">{mod.impact}</span>
													</div>
													<p class="mt-1 text-sm leading-6 text-muted">{mod.description}</p>
												</div>
												<span class:enabled={mod.enabled} class="switch" aria-hidden="true">
													<span></span>
												</span>
											</button>
										{/each}
									</div>
								</section>

								<section class="panel-card rounded-[24px] border border-border p-5">
									<div class="section-head">
										<div>
											<p class="section-kicker">Пользовательские файлы</p>
											<h3 class="section-title">Шейдеры и ресурспаки</h3>
										</div>
									</div>

									<div class="mt-4 grid gap-4">
										<div class="asset-block">
											<div class="flex items-center justify-between gap-3">
												<div class="flex items-center gap-2">
													<Zap size={17} class="text-accent" />
													<p class="text-sm font-semibold">Шейдеры</p>
												</div>
												<button class="mini-button" onclick={() => shaderInput?.click()}>
													<FolderPlus size={16} />
													<span>Добавить</span>
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
											<div class="mt-3 flex flex-wrap gap-2">
												{#if activeBuild.shaders.length}
													{#each activeBuild.shaders as shader}
														<button class="file-chip" onclick={() => removeShader(shader)}>
															<span>{shader}</span>
															<X size={13} />
														</button>
													{/each}
												{:else}
													<p class="text-sm text-muted">Пока не добавлены.</p>
												{/if}
											</div>
										</div>

										<div class="asset-block">
											<div class="flex items-center justify-between gap-3">
												<div class="flex items-center gap-2">
													<Image size={17} class="text-success" />
													<p class="text-sm font-semibold">Ресурспаки</p>
												</div>
												<button class="mini-button" onclick={() => resourcePackInput?.click()}>
													<FolderPlus size={16} />
													<span>Добавить</span>
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
											<div class="mt-3 flex flex-wrap gap-2">
												{#if activeBuild.resourcePacks.length}
													{#each activeBuild.resourcePacks as pack}
														<button class="file-chip" onclick={() => removeResourcePack(pack)}>
															<span>{pack}</span>
															<X size={13} />
														</button>
													{/each}
												{:else}
													<p class="text-sm text-muted">Пока не добавлены.</p>
												{/if}
											</div>
										</div>

										<div class="notice-line">
											<Info size={16} />
											<span>Свои моды нельзя добавлять, чтобы сборка оставалась стабильной и проверяемой.</span>
										</div>
									</div>
								</section>
							</div>
						</div>
