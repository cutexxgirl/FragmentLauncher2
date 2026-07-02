<script lang="ts">
	import { Link2, User } from '@lucide/svelte';
	import type { BuildProfile } from '$lib/launcher-ui';

	type Props = {
		builds: BuildProfile[];
		nickname: string;
		telegramAccount: string;
		availableBuildsCount: number;
	};

	let { builds, nickname = $bindable(), telegramAccount, availableBuildsCount }: Props = $props();

	function normalizeNickname(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		nickname = input.value.replace(/[^a-zA-Z0-9_]/g, '').slice(0, 30);
		input.value = nickname;
	}
</script>

<div class="section-grid compact-section">
	<div class="page-heading">
		<div>
			<p class="section-kicker">Профиль</p>
			<h2 class="page-title">Игрок и подписка</h2>
		</div>
	</div>

	<div class="profile-layout">
		<section class="panel-card profile-main-card rounded-[22px] border border-border p-4">
			<div class="section-head">
				<div>
					<p class="section-kicker">Игрок</p>
					<h3 class="section-title">Основная информация</h3>
				</div>
				<div class="avatar-badge">
					<User size={18} />
				</div>
			</div>

			<div class="mt-4 grid gap-3">
				<div>
					<label class="text-sm font-semibold" for="nickname">Ник</label>
					<input
						id="nickname"
						class="text-field mt-2"
						bind:value={nickname}
						maxlength="30"
						placeholder="FragmentPlayer"
						spellcheck="false"
						oninput={normalizeNickname}
					/>
					<p class="mt-2 text-xs text-muted">Английские буквы, цифры и подчёркивание. До 30 символов.</p>
				</div>

				<div class="profile-link-row telegram-card rounded-[18px] bg-background/40 p-3">
					<div class="flex min-w-0 items-center gap-3">
						<div class="grid size-9 place-items-center rounded-[13px] bg-sky/14 text-sky">
							<Link2 size={17} />
						</div>
						<div class="min-w-0">
							<p class="text-sm font-semibold">Telegram</p>
							<p class="truncate text-sm text-muted">{telegramAccount}</p>
						</div>
					</div>
				</div>
			</div>
		</section>

		<section class="panel-card subscription-card rounded-[22px] border border-border p-4">
			<div class="section-head">
				<div>
					<p class="section-kicker">Подписка</p>
					<h3 class="section-title">Fragment Plus</h3>
				</div>
				<span class="rounded-[13px] bg-accent/14 px-3 py-1 text-xs font-semibold text-accent">
					Активна
				</span>
			</div>

			<div class="subscription-summary mt-4">
				<div>
					<p class="text-sm text-muted">Доступные сборки</p>
					<p class="mt-1 text-2xl font-semibold">{availableBuildsCount}/{builds.length}</p>
				</div>
			</div>

			<div class="mt-3 grid gap-2">
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
