<script lang="ts">
	import {
		ChevronLeft,
		ChevronRight,
		Menu,
		Package,
		Play,
		RefreshCw,
		Settings
	} from '@lucide/svelte';
	import { onMount } from 'svelte';
	import type { BuildProfile, FeedCategory, FeedItem, Preset, SectionId } from '$lib/launcher-ui';

	type Props = {
		builds: BuildProfile[];
		activeBuild: BuildProfile;
		activePreset: Preset;
		selectedBuildId: string;
		feedItems: FeedItem[];
		selectBuild: (buildId: string) => void;
		setActiveSection: (section: SectionId) => void;
	};

	let {
		builds,
		activeBuild,
		activePreset,
		selectedBuildId,
		feedItems,
		selectBuild,
		setActiveSection
	}: Props = $props();

	let activeCategory = $state<FeedCategory>('news');
	let activeFeedIndex = $state(0);
	let activeImageIndex = $state(0);
	let buildMenuOpen = $state(false);

	let visibleFeed = $derived(feedItems.filter((item) => item.category === activeCategory));
	let activeFeedItem = $derived(visibleFeed[activeFeedIndex] ?? visibleFeed[0]);
	let imageCount = $derived(Math.min(activeFeedItem?.images.length ?? 0, 8));
	let activeImage = $derived(activeFeedItem?.images[activeImageIndex] ?? activeFeedItem?.images[0] ?? '');

	onMount(() => {
		const timer = window.setInterval(() => {
			nextImage();
		}, 4600);

		return () => window.clearInterval(timer);
	});

	function setCategory(category: FeedCategory) {
		activeCategory = category;
		activeFeedIndex = 0;
		activeImageIndex = 0;
	}

	function setFeedIndex(index: number) {
		activeFeedIndex = index;
		activeImageIndex = 0;
	}

	function previousImage() {
		if (!imageCount) return;
		activeImageIndex = (activeImageIndex - 1 + imageCount) % imageCount;
	}

	function nextImage() {
		if (!imageCount) return;
		activeImageIndex = (activeImageIndex + 1) % imageCount;
	}

	function openBuildSettings() {
		buildMenuOpen = false;
		setActiveSection('build');
	}
</script>

<div class="home-screen">
	<section class="hero-panel home-hero rounded-[26px] border border-border p-5">
		<div>
			<p class="section-kicker">Minecraft modpack</p>
			<h2 class="mt-3 text-[clamp(2rem,4vw,3.45rem)] font-semibold leading-[1.02]">
				{activeBuild.name}
			</h2>
			<p class="build-description mt-4 max-w-2xl text-sm leading-6 text-muted">
				{activeBuild.description}
			</p>
		</div>

		<div class="hero-meta">
			<span>{activeBuild.version}</span>
			<span>{activeBuild.minecraft}</span>
			<span>{activePreset.name}</span>
		</div>
	</section>

	<section class="feed-panel rounded-[24px] border border-border p-3">
		<div class="feed-tabs">
			<button class:active={activeCategory === 'news'} onclick={() => setCategory('news')}>Новости</button>
			<button
				class:active={activeCategory === 'announcements'}
				onclick={() => setCategory('announcements')}
			>
				Объявления
			</button>
		</div>

		{#if activeFeedItem}
			<div class="feed-image" style={`background: ${activeImage};`}>
				<div class="feed-image-controls">
					<button title="Предыдущая картинка" onclick={previousImage}>
						<ChevronLeft size={17} />
					</button>
					<button title="Следующая картинка" onclick={nextImage}>
						<ChevronRight size={17} />
					</button>
				</div>

				<div class="feed-dots">
					{#each Array(imageCount) as _, index}
						<button
							class:active={activeImageIndex === index}
							aria-label={`Картинка ${index + 1}`}
							onclick={() => (activeImageIndex = index)}
						></button>
					{/each}
				</div>
			</div>

			<div class="feed-body">
				<div class="feed-title-row">
					<span>{activeFeedItem.date}</span>
					<h3>{activeFeedItem.title}</h3>
				</div>
				<p>{activeFeedItem.headline}</p>
			</div>

			<div class="feed-list">
				{#each visibleFeed as item, index}
					<button class:active={activeFeedIndex === index} onclick={() => setFeedIndex(index)}>
						<span>{item.date}</span>
						<strong>{item.title}</strong>
					</button>
				{/each}
			</div>
		{/if}
	</section>

	<div class="home-actions">
		<button class="play-button home-play">
			<Play size={18} fill="currentColor" />
			<span>Играть</span>
		</button>

		<div class="build-menu">
			<button
				class:active={buildMenuOpen}
				class="build-menu-button"
				title="Сборка и действия"
				onclick={() => (buildMenuOpen = !buildMenuOpen)}
			>
				<Menu size={21} />
			</button>

			{#if buildMenuOpen}
				<div class="build-menu-popover">
					<div class="menu-builds">
						{#each builds as build}
							<button
								class:active={selectedBuildId === build.id}
								onclick={() => selectBuild(build.id)}
							>
								<Package size={15} />
								<span>{build.name}</span>
							</button>
						{/each}
					</div>

					<button class="menu-action" onclick={openBuildSettings}>
						<Settings size={16} />
						<span>Настройка</span>
					</button>
					<button class="menu-action">
						<RefreshCw size={16} />
						<span>Проверить файлы</span>
					</button>
				</div>
			{/if}
		</div>
	</div>
</div>
