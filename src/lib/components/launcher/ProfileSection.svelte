<script lang="ts">
	import { CheckCircle2, LogOut, User } from '@lucide/svelte';
	import type { LauncherAuthSession, SubscriptionLevel } from '$lib/fragment-api';
	import type { BuildProfile } from '$lib/launcher-ui';

	type Props = {
		builds: BuildProfile[];
		nickname: string;
		telegramAccount: string;
		availableBuildsCount: number;
		authSession: LauncherAuthSession | null;
		logoutFromTelegram: () => void;
	};

	let {
		builds,
		nickname = $bindable(),
		telegramAccount,
		availableBuildsCount,
		authSession,
		logoutFromTelegram,
	}: Props = $props();

	const subscriptionNames: Record<SubscriptionLevel, string> = {
		none: 'Нет подписки',
		novice: 'Новичок',
		legend: 'Легенда',
		spark: 'Искра',
	};

	let profile = $derived(authSession?.profile ?? null);

	function normalizeNickname(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		nickname = input.value.replace(/[^a-zA-Z0-9_]/g, '').slice(0, 30);
		input.value = nickname;
	}
</script>

<div class="profile-content">
	<div class="profile-layout">
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

			{#if profile}
				<div class="telegram-auth-card rounded-[18px]">
					<div class="auth-state-row">
						<div class="profile-row-icon text-success">
							<CheckCircle2 size={17} />
						</div>
						<div class="min-w-0">
							<p class="text-sm font-semibold">Аккаунт подключён</p>
							<p class="truncate text-sm text-muted">{telegramAccount}</p>
						</div>
					</div>

					<div class="auth-detail-grid">
						<div>
							<span>FID</span>
							<strong>{profile.fid ?? 'не выдан'}</strong>
						</div>
						<div>
							<span>Подписка</span>
							<strong>
								{profile.entitlement.active
									? subscriptionNames[profile.entitlement.level]
									: 'Неактивна'}
							</strong>
						</div>
						<div>
							<span>Telegram ID</span>
							<strong>{profile.telegramId ?? 'неизвестен'}</strong>
						</div>
						<div>
							<span>Статус</span>
							<strong>{profile.entitlement.active ? 'Активна' : 'Неактивна'}</strong>
						</div>
					</div>

					<button type="button" class="secondary-button auth-action-button" onclick={logoutFromTelegram}>
						<LogOut size={16} />
						<span>Выйти</span>
					</button>
				</div>
			{/if}
		</section>

		<section class="panel-card subscription-card rounded-[22px] border border-border p-4">
			<div class="subscription-headline">
				<h3 class="section-title">Fragment Plus</h3>
				<span class="rounded-[13px] bg-accent/14 px-3 py-1 text-xs font-semibold text-accent">
					{profile?.entitlement.active ? 'Активна' : 'Неактивна'}
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
