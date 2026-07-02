<script lang="ts">
import { AlertTriangle, Bell, Check, FileText, Image, MessageCircle } from '@lucide/svelte';
import type { BuildProfile, Preset } from '$lib/launcher-ui';

type Props = {
  activeBuild: BuildProfile;
  activePreset: Preset;
  supportTopic: string;
  supportDescription: string;
  attachCrashReport: boolean;
  attachLastLog: boolean;
  attachLastScreenshot: boolean;
  sendDiagnostics: boolean;
  supportReady: boolean;
  supportSent: boolean;
  setDiagnosticsEnabled: (enabled: boolean) => void;
  submitSupportRequest: (event: SubmitEvent) => void;
};

let {
  activeBuild,
  activePreset,
  supportTopic = $bindable(),
  supportDescription = $bindable(),
  attachCrashReport = $bindable(),
  attachLastLog = $bindable(),
  attachLastScreenshot = $bindable(),
  sendDiagnostics,
  supportReady,
  supportSent,
  setDiagnosticsEnabled,
  submitSupportRequest
}: Props = $props();
</script>

<div class="section-grid">
							<div class="page-heading">
								<div>
									<p class="section-kicker">Техподдержка</p>
									<h2 class="page-title">Новое обращение</h2>
								</div>
								<div class="rounded-[18px] border border-border bg-panel/72 px-4 py-3 text-sm text-muted">
									Ответ обычно приходит в Telegram
								</div>
							</div>

							<div class="support-layout">
								<form class="panel-card rounded-[24px] border border-border p-5" onsubmit={submitSupportRequest}>
									<div class="grid gap-4">
										<div>
											<label class="text-sm font-semibold" for="support-topic">Тема</label>
											<input
												id="support-topic"
												class="text-field mt-2"
												placeholder="Например: вылет при запуске мира"
												bind:value={supportTopic}
											/>
										</div>
										<div>
											<label class="text-sm font-semibold" for="support-description">Описание проблемы</label>
											<textarea
												id="support-description"
												class="text-area mt-2"
												placeholder="Что произошло, на каком этапе и повторяется ли ошибка?"
												bind:value={supportDescription}
											></textarea>
										</div>
									</div>

									<div class="mt-5 grid gap-3">
										<label class="attach-row">
											<input type="checkbox" bind:checked={attachCrashReport} />
											<span class="attach-icon"><AlertTriangle size={17} /></span>
											<span>
												<strong>Последний crash report</strong>
												<small>crash-2026-07-02.txt</small>
											</span>
										</label>
										<label class="attach-row">
											<input type="checkbox" bind:checked={attachLastLog} />
											<span class="attach-icon"><FileText size={17} /></span>
											<span>
												<strong>Последний лог</strong>
												<small>latest.log</small>
											</span>
										</label>
										<label class="attach-row">
											<input type="checkbox" bind:checked={attachLastScreenshot} />
											<span class="attach-icon"><Image size={17} /></span>
											<span>
												<strong>Последний скриншот из игры</strong>
												<small>screenshots/last.png</small>
											</span>
										</label>
									</div>

									<div class="mt-5 flex flex-col gap-3 rounded-[20px] bg-background/46 p-4 sm:flex-row sm:items-center sm:justify-between">
										<div>
											<p class="text-sm font-semibold">Данные для диагностики</p>
											<p class="mt-1 text-sm leading-6 text-muted">
												Характеристики ПК, версия Java и настройки сборки помогают быстрее найти причину.
											</p>
										</div>
										<button
											type="button"
											class:enabled={sendDiagnostics}
											class="switch large"
											aria-label="Отправлять диагностические данные"
											onclick={() => setDiagnosticsEnabled(!sendDiagnostics)}
										>
											<span></span>
										</button>
									</div>

									<div class="mt-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
										<p class="text-sm text-muted">
											{supportSent
												? 'Черновик обращения готов. Позже подключим отправку на сервер поддержки.'
												: 'Заполните тему и описание, чтобы подготовить обращение.'}
										</p>
										<button class="primary-button" disabled={!supportReady} type="submit">
											<MessageCircle size={17} />
											<span>Подготовить</span>
										</button>
									</div>
								</form>

								<aside class="panel-card rounded-[24px] border border-border p-5">
									<div class="section-head">
										<div>
											<p class="section-kicker">Пакет</p>
											<h3 class="section-title">Что приложится</h3>
										</div>
										<div class="grid size-9 place-items-center rounded-[14px] bg-success/12 text-success">
											<Check size={17} />
										</div>
									</div>

									<div class="mt-4 grid gap-3">
										<div class="support-summary-row">
											<span>Сборка</span>
											<strong>{activeBuild.name}</strong>
										</div>
										<div class="support-summary-row">
											<span>Пресет</span>
											<strong>{activePreset.name}</strong>
										</div>
										<div class="support-summary-row">
											<span>Диагностика</span>
											<strong>{sendDiagnostics ? 'включена' : 'отключена'}</strong>
										</div>
										<div class="support-summary-row">
											<span>Вложения</span>
											<strong>
												{Number(attachCrashReport) + Number(attachLastLog) + Number(attachLastScreenshot)}
											</strong>
										</div>
									</div>

									<div class="mt-5 rounded-[20px] bg-background/46 p-4">
										<div class="flex items-center gap-2 text-sm font-semibold">
											<Bell size={16} class="text-accent" />
											<span>Подсказка</span>
										</div>
										<p class="mt-2 text-sm leading-6 text-muted">
											Лучше описать последний успешный запуск и действие перед вылетом. Это экономит пару
											кругов переписки.
										</p>
									</div>
								</aside>
							</div>
						</div>
