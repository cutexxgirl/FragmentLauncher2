<script lang="ts">
	import { Link2, User } from '@lucide/svelte';
	import type { BuildProfile } from '$lib/launcher-ui';

	type Props = {
		builds: BuildProfile[];
		nickname: string;
		telegramAccount: string;
		telegramAvatarUrl: string | null;
		nicknameDirty: boolean;
		nicknameSaving: boolean;
		nicknameSaveMessage: string;
		availableBuildsCount: number;
		saveLauncherNickname: () => void | Promise<void>;
		logoutFromTelegram: () => void;
	};

	let {
		builds,
		nickname = $bindable(),
		telegramAccount,
		telegramAvatarUrl,
		nicknameDirty,
		nicknameSaving,
		nicknameSaveMessage,
		availableBuildsCount,
		saveLauncherNickname,
		logoutFromTelegram,
	}: Props = $props();

	let avatarFailed = $state(false);

	$effect(() => {
		telegramAvatarUrl;
		avatarFailed = false;
	});

	function normalizeNickname(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		nickname = input.value.replace(/[^a-zA-Z0-9_]/g, '').slice(0, 30);
		input.value = nickname;
	}

	function saveNicknameFromKeyboard(event: KeyboardEvent) {
		if (event.key === 'Enter') {
			event.preventDefault();
			void saveLauncherNickname();
		}
	}
</script>

<div class="profile-content">
	<div class="profile-layout">
		<section class="panel-card profile-main-card rounded-[22px] border border-border p-4">
			<div class="profile-identity-row">
				<div class:has-image={telegramAvatarUrl && !avatarFailed} class="avatar-badge profile-row-icon">
					{#if telegramAvatarUrl && !avatarFailed}
						<img
							class="profile-avatar-image"
							src={telegramAvatarUrl}
							alt=""
							referrerpolicy="no-referrer"
							onerror={() => (avatarFailed = true)}
						/>
					{:else}
						<User size={18} />
					{/if}
				</div>

				<div class="min-w-0 flex-1">
					<label class="sr-only" for="nickname">Псевдоним</label>
					<div class="profile-name-row">
						<input
							id="nickname"
							aria-label="Псевдоним"
							class="text-field profile-name-input"
							bind:value={nickname}
							maxlength="30"
							placeholder="Псевдоним"
							spellcheck="false"
							oninput={normalizeNickname}
							onkeydown={saveNicknameFromKeyboard}
						/>

						{#if nicknameDirty}
							<button
								type="button"
								class="mini-button profile-save-button"
								disabled={nicknameSaving}
								onclick={saveLauncherNickname}
							>
								{nicknameSaving ? '...' : 'Сохранить'}
							</button>
						{/if}
					</div>

					{#if nicknameSaveMessage}
						<p class="profile-nickname-note">{nicknameSaveMessage}</p>
					{/if}
				</div>
			</div>

			<div class="profile-link-row telegram-card rounded-[18px] p-0">
				<div class="flex min-w-0 items-center gap-3">
					<div class="profile-row-icon text-sky">
						<Link2 size={17} />
					</div>
					<div class="min-w-0">
						<p class="text-sm font-semibold">Telegram</p>
						<p class="truncate text-sm text-muted">{telegramAccount}</p>
					</div>
				</div>

				<button type="button" class="secondary-button profile-logout-button" onclick={logoutFromTelegram}>
					Выйти
				</button>
			</div>
		</section>

		<section class="panel-card subscription-card rounded-[22px] border border-border p-4">
			<div class="subscription-headline">
				<h3 class="section-title">Fragment Plus</h3>
				<span class="rounded-[13px] bg-accent/14 px-3 py-1 text-xs font-semibold text-accent">
					Активна
				</span>
			</div>

			<div class="subscription-summary mt-3">
				<strong>{availableBuildsCount}/{builds.length}</strong>
				<span>сборки</span>
			</div>

			<div class="subscription-builds mt-3">
				{#each builds as build}
					<div class="subscription-row">
						<p class="min-w-0 truncate text-sm font-semibold">{build.name}</p>
						<span class:locked={build.access === 'subscription'} class="access-pill">
							{build.access === 'available' ? 'доступно' : 'Plus'}
						</span>
					</div>
				{/each}
			</div>
		</section>
	</div>
</div>
