<script lang="ts">
import { CheckCircle2, ChevronRight, Cpu, HardDrive, Newspaper, Package, Play, Settings, Wrench } from '@lucide/svelte';
import type { BuildProfile, NewsItem, Preset, SectionId } from '$lib/launcher-ui';

type Props = {
  builds: BuildProfile[];
  activeBuild: BuildProfile;
  activePreset: Preset;
  selectedBuildId: string;
  enabledModsCount: number;
  news: NewsItem[];
  selectBuild: (buildId: string) => void;
  setActiveSection: (section: SectionId) => void;
};

let { builds, activeBuild, activePreset, selectedBuildId, enabledModsCount, news, selectBuild, setActiveSection }: Props = $props();
</script>

<div class="section-grid">
							<section class="hero-panel rounded-[28px] border border-border p-6">
								<div class="flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
									<div class="max-w-2xl">
										<p class="text-xs font-semibold uppercase tracking-[0.18em] text-accent">
											Minecraft modpack
										</p>
										<h2 class="mt-3 text-[clamp(2rem,4vw,3.75rem)] font-semibold leading-[1.02]">
											{activeBuild.name}
										</h2>
										<p class="mt-4 max-w-2xl text-base leading-7 text-muted">
											{activeBuild.description} Настройки уже можно менять локально, а дизайн оставлен с
											запасом под будущие модули.
										</p>
									</div>

									<div class="play-dock rounded-[22px] border border-white/10 bg-background/58 p-3">
										<div class="mb-3 flex items-center gap-3 px-1">
											<div class="grid size-10 place-items-center rounded-[14px] bg-success/14 text-success">
												<CheckCircle2 size={20} />
											</div>
											<div>
												<p class="text-sm font-semibold">Готово к запуску</p>
												<p class="text-xs text-muted">ОЗУ {activeBuild.selectedRam} ГБ</p>
											</div>
										</div>
										<button class="play-button">
											<Play size={20} fill="currentColor" />
											<span>Играть</span>
										</button>
									</div>
								</div>
							</section>

							<div class="home-columns">
								<section class="panel-card rounded-[24px] border border-border p-4">
									<div class="section-head">
										<div>
											<p class="section-kicker">Сборки</p>
											<h3 class="section-title">Выбор профиля</h3>
										</div>
										<button class="ghost-icon-button" title="Настройки сборки" onclick={() => setActiveSection('build')}>
											<Settings size={17} />
										</button>
									</div>

									<div class="mt-4 grid gap-3">
										{#each builds as build}
											<button
												class:active={selectedBuildId === build.id}
												class="build-select-row"
												onclick={() => selectBuild(build.id)}
											>
												<div class="flex min-w-0 items-center gap-3">
													<div class="build-icon">
														<Package size={18} />
													</div>
													<div class="min-w-0 text-left">
														<p class="truncate text-sm font-semibold">{build.name}</p>
														<p class="truncate text-xs text-muted">{build.subtitle}</p>
													</div>
												</div>
												<div class="flex items-center gap-2">
													<span class:locked={build.access === 'subscription'} class="access-pill">
														{build.access === 'available' ? 'Доступно' : 'Plus'}
													</span>
													<ChevronRight size={16} class="row-arrow" />
												</div>
											</button>
										{/each}
									</div>
								</section>

								<section class="news-block rounded-[24px] border border-border p-4">
									<div class="section-head">
										<div>
											<p class="section-kicker">Новости</p>
											<h3 class="section-title">Что нового</h3>
										</div>
										<div class="grid size-9 place-items-center rounded-[14px] bg-accent/14 text-accent">
											<Newspaper size={17} />
										</div>
									</div>

									<div class="mt-4 grid gap-3">
										{#each news as item}
											<article class="news-item rounded-[18px] bg-background/46 p-4">
												<div class="flex items-center justify-between gap-3">
													<span class="news-tag">{item.tag}</span>
													<span class="text-xs text-muted">{item.date}</span>
												</div>
												<h4 class="mt-3 text-sm font-semibold">{item.title}</h4>
												<p class="mt-2 text-sm leading-6 text-muted">{item.text}</p>
											</article>
										{/each}
									</div>
								</section>
							</div>

							<section class="status-grid">
								<div class="metric-card">
									<Cpu size={18} />
									<div>
										<p class="metric-label">Пресет</p>
										<p class="metric-value">{activePreset.name}</p>
									</div>
								</div>
								<div class="metric-card">
									<HardDrive size={18} />
									<div>
										<p class="metric-label">Размер</p>
										<p class="metric-value">{activeBuild.size}</p>
									</div>
								</div>
								<div class="metric-card">
									<Wrench size={18} />
									<div>
										<p class="metric-label">Опционально</p>
										<p class="metric-value">{enabledModsCount} модов</p>
									</div>
								</div>
							</section>
						</div>
