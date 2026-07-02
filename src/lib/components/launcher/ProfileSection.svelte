<script lang="ts">
import { Link2, Monitor, ShieldCheck, User } from '@lucide/svelte';
import type { BuildProfile } from '$lib/launcher-ui';

type Props = {
  builds: BuildProfile[];
  nickname: string;
  telegramAccount: string;
  availableBuildsCount: number;
};

let { builds, nickname = $bindable(), telegramAccount, availableBuildsCount }: Props = $props();
</script>

<div class="section-grid">
							<div class="page-heading">
								<div>
									<p class="section-kicker">Профиль</p>
									<h2 class="page-title">Игрок и подписка</h2>
								</div>
							</div>

							<div class="profile-layout">
								<section class="panel-card rounded-[24px] border border-border p-5">
									<div class="section-head">
										<div>
											<p class="section-kicker">Игрок</p>
											<h3 class="section-title">Основная информация</h3>
										</div>
										<div class="avatar-badge">
											<User size={20} />
										</div>
									</div>

									<div class="mt-5 grid gap-4">
										<div>
											<label class="text-sm font-semibold" for="nickname">Ник</label>
											<input id="nickname" class="text-field mt-2" bind:value={nickname} maxlength="24" />
										</div>
										<div class="rounded-[20px] bg-background/46 p-4">
											<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
												<div class="flex items-center gap-3">
													<div class="grid size-10 place-items-center rounded-[14px] bg-sky/14 text-sky">
														<Link2 size={18} />
													</div>
													<div>
														<p class="text-sm font-semibold">Telegram</p>
														<p class="text-sm text-muted">{telegramAccount}</p>
													</div>
												</div>
												<button class="secondary-button">
													<Link2 size={17} />
													<span>Перепривязать</span>
												</button>
											</div>
										</div>
									</div>
								</section>

								<section class="panel-card rounded-[24px] border border-border p-5">
									<div class="section-head">
										<div>
											<p class="section-kicker">Подписка</p>
											<h3 class="section-title">Fragment Plus</h3>
										</div>
										<span class="rounded-[14px] bg-accent/14 px-3 py-1.5 text-xs font-semibold text-accent">
											Активна
										</span>
									</div>

									<div class="mt-5 rounded-[22px] bg-background/46 p-4">
										<p class="text-sm text-muted">Доступные сборки</p>
										<p class="mt-2 text-3xl font-semibold">{availableBuildsCount}/{builds.length}</p>
										<p class="mt-2 text-sm leading-6 text-muted">
											Подписка открывает визуальные пресеты и будущие закрытые сборки.
										</p>
									</div>

									<div class="mt-4 grid gap-3">
										{#each builds as build}
											<div class="subscription-row">
												<div>
													<p class="text-sm font-semibold">{build.name}</p>
													<p class="text-xs text-muted">{build.subtitle}</p>
												</div>
												<span class:locked={build.access === 'subscription'} class="access-pill">
													{build.access === 'available' ? 'доступно' : 'Plus'}
												</span>
											</div>
										{/each}
									</div>
								</section>

								<section class="panel-card rounded-[24px] border border-border p-5">
									<div class="section-head">
										<div>
											<p class="section-kicker">Комфорт</p>
											<h3 class="section-title">Быстрые параметры</h3>
										</div>
									</div>

									<div class="mt-4 grid gap-3">
										<div class="quick-row">
											<Monitor size={18} />
											<div>
												<p class="text-sm font-semibold">Окно лаунчера</p>
												<p class="text-xs text-muted">Адаптивная сетка под текущий размер</p>
											</div>
										</div>
										<div class="quick-row">
											<ShieldCheck size={18} />
											<div>
												<p class="text-sm font-semibold">Приватность</p>
												<p class="text-xs text-muted">Диагностику можно выключить в обращении</p>
											</div>
										</div>
									</div>
								</section>
							</div>
						</div>
