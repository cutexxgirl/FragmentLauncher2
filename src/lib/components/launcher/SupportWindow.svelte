<script lang="ts">
	import { X } from '@lucide/svelte';
	import SupportSection from '$lib/components/launcher/SupportSection.svelte';

	type Props = {
		supportTopic: string;
		supportDescription: string;
		attachCrashReport: boolean;
		attachLastLog: boolean;
		attachLastScreenshot: boolean;
		supportReady: boolean;
		supportSent: boolean;
		closeSupport: () => void;
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
		closeSupport,
		submitSupportRequest
	}: Props = $props();

	function closeFromBackdrop(event: MouseEvent) {
		if (event.target === event.currentTarget) {
			closeSupport();
		}
	}

	function closeFromKeyboard(event: KeyboardEvent) {
		if (event.key === 'Escape') {
			closeSupport();
		}
	}
</script>

<div
	class="support-backdrop"
	role="button"
	tabindex="-1"
	onclick={closeFromBackdrop}
	onkeydown={closeFromKeyboard}
>
	<div
		class="support-window"
		role="dialog"
		aria-modal="true"
		aria-label="Техподдержка"
		tabindex="-1"
	>
		<header class="settings-window-head">
			<div>
				<p class="section-kicker">Поддержка</p>
				<h2 class="page-title">Новое обращение</h2>
			</div>
			<button type="button" class="ghost-icon-button" title="Закрыть поддержку" onclick={closeSupport}>
				<X size={18} />
			</button>
		</header>

		<div class="support-window-body">
			<SupportSection
				bind:supportTopic
				bind:supportDescription
				bind:attachCrashReport
				bind:attachLastLog
				bind:attachLastScreenshot
				{supportReady}
				{supportSent}
				{submitSupportRequest}
			/>
		</div>
	</div>
</div>
