<script lang="ts">
import { Sparkles } from '@lucide/svelte';
import type { BuildProfile, SectionId } from '$lib/launcher-ui';
import type { LauncherStatus } from '$lib/launcher';

type NavigationItem = {
  id: SectionId;
  label: string;
  mobileLabel: string;
  icon: any;
};

type Props = {
  navigation: NavigationItem[];
  activeSection: SectionId;
  activeBuild: BuildProfile;
  status: LauncherStatus;
  enabledModsCount: number;
  setActiveSection: (section: SectionId) => void;
};

let { navigation, activeSection, activeBuild, status, enabledModsCount, setActiveSection }: Props = $props();
</script>

<aside class="sidebar-surface flex min-h-0 flex-col gap-5 border-r border-border bg-panel/94 p-5">
				<div class="flex items-center gap-3">
					<div class="brand-mark grid size-11 place-items-center rounded-[14px] bg-accent text-accent-foreground">
						<Sparkles size={20} strokeWidth={2.2} />
					</div>
					<div>
						<p class="text-sm font-medium text-muted">Fragment</p>
						<h1 class="text-xl font-semibold leading-tight">Launcher</h1>
					</div>
				</div>

				<nav class="grid gap-2">
					{#each navigation as item}
						{@const Icon = item.icon}
						<button
							class:active={activeSection === item.id}
							class="nav-button"
							onclick={() => setActiveSection(item.id)}
						>
							<Icon size={18} />
							<span>{item.label}</span>
						</button>
					{/each}
				</nav>

				<div class="selected-build-card mt-auto rounded-[22px] border border-border bg-background/52 p-4">
					<div class="flex items-start justify-between gap-3">
						<div>
							<p class="text-xs font-semibold uppercase tracking-[0.16em] text-muted">Выбрано</p>
							<p class="mt-2 text-base font-semibold">{activeBuild.name}</p>
							<p class="mt-1 text-sm text-muted">{activeBuild.minecraft}</p>
						</div>
						<span class="rounded-[12px] bg-accent/14 px-2.5 py-1 text-xs font-semibold text-accent">
							{activeBuild.tag}
						</span>
					</div>
					<div class="mt-4 grid grid-cols-2 gap-2 text-sm">
						<div class="rounded-[14px] bg-panel-strong/78 p-3">
							<p class="text-xs text-muted">ОЗУ</p>
							<p class="mt-1 font-semibold">{activeBuild.selectedRam} ГБ</p>
						</div>
						<div class="rounded-[14px] bg-panel-strong/78 p-3">
							<p class="text-xs text-muted">Моды</p>
							<p class="mt-1 font-semibold">{enabledModsCount}/{activeBuild.mods.length}</p>
						</div>
					</div>
				</div>

				<div class="rounded-[22px] border border-border bg-background/38 p-4">
					<p class="text-xs font-semibold uppercase tracking-[0.16em] text-muted">Версия</p>
					<p class="mt-2 text-lg font-semibold">{status.version}</p>
				</div>
			</aside>
