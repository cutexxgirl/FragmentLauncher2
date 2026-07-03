<script lang="ts">
	import { FileWarning, Image, ScrollText } from '@lucide/svelte';

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

<div class="support-content">
	<div class="support-layout">
		<form class="panel-card support-form rounded-[22px] border border-border p-4" onsubmit={submitSupportRequest}>
			<div class="support-fields">
				<div>
					<label class="sr-only" for="support-topic">Тема</label>
					<input
						id="support-topic"
						aria-label="Тема"
						class="text-field"
						placeholder="Тема"
						bind:value={supportTopic}
					/>
				</div>
				<div>
					<label class="sr-only" for="support-description">Описание</label>
					<textarea
						id="support-description"
						aria-label="Описание"
						class="text-area support-textarea"
						placeholder="Что случилось?"
						bind:value={supportDescription}
					></textarea>
				</div>
			</div>

			<div class="support-attachments mt-4">
				<button
					type="button"
					class:active={attachCrashReport}
					class="attach-button"
					title="Приложить последний crash report"
					onclick={() => (attachCrashReport = !attachCrashReport)}
				>
					<FileWarning size={16} />
					<span>Краш</span>
				</button>
				<button
					type="button"
					class:active={attachLastLog}
					class="attach-button"
					title="Приложить последний лог"
					onclick={() => (attachLastLog = !attachLastLog)}
				>
					<ScrollText size={16} />
					<span>Лог</span>
				</button>
				<button
					type="button"
					class:active={attachLastScreenshot}
					class="attach-button"
					title="Приложить последний скриншот"
					onclick={() => (attachLastScreenshot = !attachLastScreenshot)}
				>
					<Image size={16} />
					<span>Скрин</span>
				</button>
			</div>

			<div class="support-actions mt-4">
				<button class="primary-button compact-button" disabled={!supportReady} type="submit">
					<span>{supportSent ? 'Готово' : 'Отправить'}</span>
				</button>
			</div>
		</form>
	</div>
</div>
