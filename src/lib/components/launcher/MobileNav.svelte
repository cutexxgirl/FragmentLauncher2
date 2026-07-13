<script lang="ts">
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
		setActiveSection: (section: SectionId) => void;
	};

	let { navigation, activeSection, setActiveSection }: Props = $props();
</script>

<nav class="mobile-nav-wrap">
	{#each navigation as item}
		{@const Icon = item.icon}
		<button
			class:active={activeSection === item.id}
			class="mobile-nav-button"
			onclick={() => setActiveSection(item.id)}
		>
			<Icon size={16} />
			<span>{item.mobileLabel}</span>
		</button>
	{/each}
</nav>
