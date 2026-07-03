<script lang="ts">
	type Props = {
		supportTopic: string;
		supportDescription: string;
		attachCrashReport: boolean;
		attachLastLog: boolean;
		attachLastScreenshot: boolean;
		supportReady: boolean;
		supportSent: boolean;
		submitSupportRequest: (event: SubmitEvent) => void;
	};

	let {
		supportTopic = $bindable(),
		supportDescription = $bindable(),
		attachCrashReport = $bindable(),
		attachLastLog = $bindable(),
		attachLastScreenshot = $bindable(),
		supportReady,
		supportSent,
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

			<div class="support-attachments mt-4">
				<button
					type="button"
					class:active={attachCrashReport}
					class="attach-button"
					onclick={() => (attachCrashReport = !attachCrashReport)}
				>
					Последний краш
				</button>
				<button
					type="button"
					class:active={attachLastLog}
					class="attach-button"
					onclick={() => (attachLastLog = !attachLastLog)}
				>
					Последний лог
				</button>
				<button
					type="button"
					class:active={attachLastScreenshot}
					class="attach-button"
					onclick={() => (attachLastScreenshot = !attachLastScreenshot)}
				>
					Последний скриншот
				</button>
			</div>

			<div class="support-actions mt-4">
				<button class="primary-button compact-button" disabled={!supportReady} type="submit">
					<span>{supportSent ? 'Готово' : 'Подготовить'}</span>
				</button>
			</div>
		</form>
	</div>
</div>
