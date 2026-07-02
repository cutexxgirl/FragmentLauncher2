<script lang="ts">
	import { AlertTriangle, FileText, Image, MessageCircle } from '@lucide/svelte';
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

<div class="section-grid compact-section">
	<div class="page-heading">
		<div>
			<p class="section-kicker">Техподдержка</p>
			<h2 class="page-title">Новое обращение</h2>
		</div>
	</div>

	<div class="support-layout">
		<form class="panel-card rounded-[22px] border border-border p-4" onsubmit={submitSupportRequest}>
			<div class="grid gap-3">
				<div>
					<label class="text-sm font-semibold" for="support-topic">Тема</label>
					<input
						id="support-topic"
						class="text-field mt-2"
						placeholder="Вылет при запуске мира"
						bind:value={supportTopic}
					/>
				</div>
				<div>
					<label class="text-sm font-semibold" for="support-description">Описание</label>
					<textarea
						id="support-description"
						class="text-area support-textarea mt-2"
						placeholder="Что произошло и после какого действия?"
						bind:value={supportDescription}
					></textarea>
				</div>
			</div>

			<div class="mt-4 grid gap-2">
				<label class="attach-row">
					<input type="checkbox" bind:checked={attachCrashReport} />
					<span class="attach-icon"><AlertTriangle size={16} /></span>
					<span>
						<strong>Последний crash report</strong>
						<small>crash-2026-07-02.txt</small>
					</span>
				</label>
				<label class="attach-row">
					<input type="checkbox" bind:checked={attachLastLog} />
					<span class="attach-icon"><FileText size={16} /></span>
					<span>
						<strong>Последний лог</strong>
						<small>latest.log</small>
					</span>
				</label>
				<label class="attach-row">
					<input type="checkbox" bind:checked={attachLastScreenshot} />
					<span class="attach-icon"><Image size={16} /></span>
					<span>
						<strong>Последний скриншот</strong>
						<small>screenshots/last.png</small>
					</span>
				</label>
			</div>

			<div class="diagnostics-row mt-4">
				<div>
					<p class="text-sm font-semibold">Данные для диагностики</p>
					<p class="mt-1 text-sm leading-6 text-muted">
						Железо, Java и настройки сборки помогут быстрее найти причину.
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

			<div class="support-actions mt-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
				<p class="text-sm text-muted">
					{supportSent ? 'Черновик обращения готов.' : 'Заполните тему и описание.'}
				</p>
				<button class="primary-button compact-button" disabled={!supportReady} type="submit">
					<MessageCircle size={16} />
					<span>Подготовить</span>
				</button>
			</div>
		</form>

		<aside class="support-package panel-card rounded-[22px] border border-border p-4">
			<div>
				<p class="section-kicker">Пакет</p>
				<h3 class="section-title">Что приложится</h3>
			</div>

			<div class="mt-3 grid gap-2">
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
					<strong>{sendDiagnostics ? 'вкл.' : 'выкл.'}</strong>
				</div>
				<div class="support-summary-row">
					<span>Вложения</span>
					<strong>{Number(attachCrashReport) + Number(attachLastLog) + Number(attachLastScreenshot)}</strong>
				</div>
			</div>
		</aside>
	</div>
</div>
