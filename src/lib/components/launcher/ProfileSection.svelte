<script lang="ts">
	import { User } from '@lucide/svelte';
	import type { LauncherAuthSession } from '$lib/fragment-api';

	type Props = {
		nickname: string;
		telegramAccount: string;
		authSession: LauncherAuthSession | null;
		logoutFromTelegram: () => void;
	};

	let { nickname = $bindable(), telegramAccount, authSession, logoutFromTelegram }: Props = $props();

	function normalizeNickname(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		nickname = input.value.replace(/[^a-zA-Z0-9_]/g, '').slice(0, 30);
		input.value = nickname;
	}
</script>

<div class="profile-content">
	<section class="panel-card profile-main-card rounded-[22px] border border-border p-4">
		<div class="profile-identity-row">
			<div class="avatar-badge profile-row-icon">
				<User size={18} />
			</div>

			<div class="min-w-0 flex-1">
				<label class="sr-only" for="nickname">Ник</label>
				<input
					id="nickname"
					aria-label="Ник"
					class="text-field profile-name-input"
					bind:value={nickname}
					maxlength="30"
					placeholder="FragmentPlayer"
					spellcheck="false"
					oninput={normalizeNickname}
				/>
			</div>
		</div>

		{#if authSession?.profile}
			<div class="profile-telegram-row">
				<div class="min-w-0">
					<p class="text-sm font-semibold">Telegram</p>
					<p class="truncate text-sm text-muted">{telegramAccount}</p>
				</div>

				<button type="button" class="secondary-button profile-logout-button" onclick={logoutFromTelegram}>
					Выйти
				</button>
			</div>
		{/if}
	</section>
</div>
