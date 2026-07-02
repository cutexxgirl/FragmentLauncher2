<script lang="ts">
	import { X } from '@lucide/svelte';
	import SupportSection from '$lib/components/launcher/SupportSection.svelte';
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
		closeSupport: () => void;
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
		closeSupport,
		setDiagnosticsEnabled,
		submitSupportRequest
	}: Props = $props();
</script>

<div class="support-backdrop">
	<div class="support-window" role="dialog" aria-modal="true" aria-label="Техподдержка" tabindex="-1">
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
				{activeBuild}
				{activePreset}
				bind:supportTopic
				bind:supportDescription
				bind:attachCrashReport
				bind:attachLastLog
				bind:attachLastScreenshot
				{sendDiagnostics}
				{supportReady}
				{supportSent}
				{setDiagnosticsEnabled}
				{submitSupportRequest}
			/>
		</div>
	</div>
</div>
