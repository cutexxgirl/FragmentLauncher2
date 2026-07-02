<script lang="ts">
	import { Sparkles } from '@lucide/svelte';
	import type { SectionId } from '$lib/launcher-ui';

	type NavigationItem = {
		id: SectionId;
		label: string;
		mobileLabel: string;
		icon: any;
	};

	type Props = {
		navigation: NavigationItem[];
		setActiveSection: (section: SectionId) => void;
	};

	let { navigation, setActiveSection }: Props = $props();
</script>

<aside class="sidebar-surface flex min-h-0 flex-col border-r border-border">
	<div class="sidebar-brand" title="Fragment Launcher">
		<span class="brand-mark">
			<Sparkles size={24} strokeWidth={2.2} />
		</span>
	</div>

	<nav class="sidebar-nav" aria-label="Основная навигация">
		{#each navigation as item}
			{@const Icon = item.icon}
			<button
				class="nav-button"
				title={item.label}
				aria-label={item.label}
				onclick={() => setActiveSection(item.id)}
			>
				<Icon size={19} />
			</button>
		{/each}
	</nav>
</aside>
