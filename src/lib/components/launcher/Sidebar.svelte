<script lang="ts">
	import { PanelLeftClose, PanelLeftOpen } from '@lucide/svelte';
	import type { SectionId } from '$lib/launcher-ui';

	type NavigationItem = {
		id: SectionId;
		label: string;
		mobileLabel: string;
		icon: any;
	};

	type Props = {
		navigation: NavigationItem[];
		activeSection: SectionId;
		collapsed: boolean;
		setActiveSection: (section: SectionId) => void;
		toggleCollapsed: () => void;
	};

	let { navigation, activeSection, collapsed, setActiveSection, toggleCollapsed }: Props = $props();
</script>

<aside class:collapsed class="sidebar-surface flex min-h-0 flex-col border-r border-border">
	<nav class="sidebar-nav">
		{#each navigation as item}
			{@const Icon = item.icon}
			<button
				class:active={activeSection === item.id}
				class="nav-button"
				title={item.label}
				onclick={() => setActiveSection(item.id)}
			>
				<Icon size={18} />
				<span>{item.label}</span>
			</button>
		{/each}
	</nav>

	<button
		class="sidebar-collapse-button"
		title={collapsed ? 'Развернуть меню' : 'Свернуть меню'}
		onclick={toggleCollapsed}
	>
		{#if collapsed}
			<PanelLeftOpen size={18} />
		{:else}
			<PanelLeftClose size={18} />
			<span>Свернуть</span>
		{/if}
	</button>
</aside>
