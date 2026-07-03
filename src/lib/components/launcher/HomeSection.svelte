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
	import type { BuildProfile, FeedCategory, FeedItem } from '$lib/launcher-ui';

	type Props = {
		builds: BuildProfile[];
		activeBuild: BuildProfile;
		selectedBuildId: string;
		feedItems: FeedItem[];
		feedImages: string[];
		selectBuild: (buildId: string) => void;
		openSettings: () => void;
	};

	let {
		builds,
		activeBuild,
		selectedBuildId,
		feedItems,
		feedImages,
		selectBuild,
		openSettings
	}: Props = $props();

	let activeCategory = $state<FeedCategory>('news');
	let activeImageIndex = $state(0);
	let buildMenuOpen = $state(false);

	let visibleFeed = $derived(feedItems.filter((item) => item.category === activeCategory));
	let carouselImages = $derived(feedImages.slice(0, 8));
	let imageCount = $derived(carouselImages.length);
	let activeImage = $derived(carouselImages[activeImageIndex] ?? carouselImages[0] ?? '');
	let buildReleaseName = $derived(activeBuild.id === 'fragment-origin' ? 'Claws & Bloom' : '');

	onMount(() => {
		const timer = window.setInterval(() => {
			nextImage();
		}, 4600);

		return () => window.clearInterval(timer);
	});

	function setCategory(category: FeedCategory) {
		activeCategory = category;
	}

	function previousImage() {
		if (!imageCount) return;
		activeImageIndex = (activeImageIndex - 1 + imageCount) % imageCount;
	}

	function nextImage() {
		if (!imageCount) return;
		activeImageIndex = (activeImageIndex + 1) % imageCount;
	}

	function openSettingsWindow() {
		buildMenuOpen = false;
		openSettings();
	}
</script>

<div class="home-screen">
	<section class="home-hero home-hero-clean">
		<div>
			<h2 class="text-[clamp(2.35rem,5vw,4rem)] font-semibold leading-[1.02]">
				{activeBuild.name}
			</h2>
			{#if buildReleaseName}
				<p class="build-version-name mt-4">{buildReleaseName}</p>
			{/if}
		</div>
	</section>

	<section class="feed-panel rounded-[24px] border border-border">
		<div class="feed-image">
			{#key activeImageIndex}
				<div class="feed-slide" style={`background: ${activeImage};`}></div>
			{/key}

			<div class="feed-image-controls">
				<button type="button" title="Предыдущая картинка" onclick={previousImage}>
					<ChevronLeft size={17} />
				</button>
				<button type="button" title="Следующая картинка" onclick={nextImage}>
					<ChevronRight size={17} />
				</button>
			</div>

			<div class="feed-dots">
				{#each Array(imageCount) as _, index}
					<button
						type="button"
						class:active={activeImageIndex === index}
						aria-label={`Картинка ${index + 1}`}
						onclick={() => (activeImageIndex = index)}
					></button>
				{/each}
			</div>
		</div>

		<div class="feed-panel-body">
			<div class="feed-tabs">
				<button type="button" class:active={activeCategory === 'news'} onclick={() => setCategory('news')}>
					Новости
				</button>
				<button
					type="button"
					class:active={activeCategory === 'announcements'}
					onclick={() => setCategory('announcements')}
				>
					Объявления
				</button>
			</div>

			<div class="feed-list">
				{#each visibleFeed as item}
					<button type="button" aria-label={`Новость: ${item.title}`}>
						<span>{item.date}</span>
						<strong>{item.title}</strong>
					</button>
				{/each}
			</div>
		</div>
	</section>

	<div class="home-actions">
		<button type="button" class="play-button home-play">
			<Play size={18} fill="currentColor" />
			<span>Играть</span>
		</button>

		<div class="build-menu">
			<button
				type="button"
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
								type="button"
								class:active={selectedBuildId === build.id}
								onclick={() => selectBuild(build.id)}
							>
								<Package size={15} />
								<span>{build.name}</span>
							</button>
						{/each}
					</div>

					<button type="button" class="menu-action" onclick={openSettingsWindow}>
						<Settings size={16} />
						<span>Настройки</span>
					</button>
					<button type="button" class="menu-action">
						<RefreshCw size={16} />
						<span>Проверить файлы</span>
					</button>
				</div>
			{/if}
		</div>
	</div>
</div>
