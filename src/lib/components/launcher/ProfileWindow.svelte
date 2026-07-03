<script lang="ts">
	import { X } from '@lucide/svelte';
	import ProfileSection from '$lib/components/launcher/ProfileSection.svelte';
	import type { BuildProfile } from '$lib/launcher-ui';

	type Props = {
		builds: BuildProfile[];
		nickname: string;
		telegramAccount: string;
		availableBuildsCount: number;
		closeProfile: () => void;
	};

	let {
		builds,
		nickname = $bindable(),
		telegramAccount,
		availableBuildsCount,
		closeProfile
	}: Props = $props();

	function closeFromBackdrop(event: MouseEvent) {
		if (event.target === event.currentTarget) {
			closeProfile();
		}
	}

	function closeFromKeyboard(event: KeyboardEvent) {
		if (event.key === 'Escape') {
			closeProfile();
		}
	}
</script>

<div
	class="profile-backdrop"
	role="button"
	tabindex="-1"
	onclick={closeFromBackdrop}
	onkeydown={closeFromKeyboard}
>
	<div
		class="profile-window"
		role="dialog"
		aria-modal="true"
		aria-label="Профиль"
		tabindex="-1"
	>
		<header class="settings-window-head">
			<div>
				<p class="section-kicker">Профиль</p>
				<h2 class="page-title">Игрок и подписка</h2>
			</div>
			<button type="button" class="ghost-icon-button" title="Закрыть профиль" onclick={closeProfile}>
				<X size={18} />
			</button>
		</header>

		<div class="profile-window-body">
			<ProfileSection
				{builds}
				bind:nickname
				{telegramAccount}
				{availableBuildsCount}
			/>
		</div>
	</div>
</div>
