<script lang="ts">
	import {
		ChevronLeft,
		ChevronRight,
		Download,
		HardDrive,
		LockKeyhole,
		LoaderCircle,
		Menu,
		Package,
		Play,
		RefreshCw,
		Settings,
		ShieldCheck,
		TriangleAlert,
	} from '@lucide/svelte';
	import { onMount } from 'svelte';
	import type { BuildStatus } from '$lib/launcher';
	import type { BuildProfile, FeedCategory, FeedItem } from '$lib/launcher-ui';

	type Props = {
		builds: BuildProfile[];
		activeBuild: BuildProfile;
		selectedBuildId: string;
		feedItems: FeedItem[];
		feedImages: string[];
		buildStatus: BuildStatus;
		selectBuild: (buildId: string) => void;
		openSettings: () => void;
		primaryAction: () => void;
	};

	let {
		builds,
		activeBuild,
		selectedBuildId,
		feedItems,
		feedImages,
		buildStatus,
		selectBuild,
		openSettings,
		primaryAction,
	}: Props = $props();

	let activeCategory = $state<FeedCategory>('news');
	let activeImageIndex = $state(0);
	let buildMenuOpen = $state(false);

	let visibleFeed = $derived(feedItems.filter((item) => item.category === activeCategory));
	let carouselImages = $derived(feedImages.slice(0, 8));
	let imageCount = $derived(carouselImages.length);
	let activeImage = $derived(carouselImages[activeImageIndex] ?? carouselImages[0] ?? '');
	let buildReleaseName = $derived(activeBuild.id === 'fragment-stable' ? 'Claws & Bloom' : '');
	let actionUnavailable = $derived(
		buildStatus.primaryAction === 'busy' || buildStatus.primaryAction === 'blocked',
	);
	let showStatusPopover = $derived(
		buildStatus.operationActive ||
			buildStatus.primaryAction === 'blocked' ||
			buildStatus.primaryAction === 'busy',
	);
	let projectedFreeBytes = $derived(
		Math.max(0, buildStatus.progress.diskFreeBytes - buildStatus.progress.diskRequiredBytes),
	);

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

	function runPrimaryAction() {
		if (actionUnavailable) return;
		primaryAction();
	}

	function formatBytes(value: number) {
		if (!Number.isFinite(value) || value <= 0) return '0 Б';
		const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
		const unit = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
		const amount = value / 1024 ** unit;
		return `${amount >= 10 || unit === 0 ? amount.toFixed(0) : amount.toFixed(1)} ${units[unit]}`;
	}

	function actionLabel() {
		switch (buildStatus.primaryAction) {
			case 'download':
				return 'Скачать';
			case 'update':
				return 'Обновить';
			case 'repair':
				return 'Исправить';
			case 'play':
				return 'Играть';
			case 'busy':
				return 'Подождите';
			default:
				return 'Недоступно';
		}
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
				<button
					type="button"
					class:active={activeCategory === 'news'}
					onclick={() => setCategory('news')}
				>
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
		<div class="primary-action-wrap">
			{#if showStatusPopover}
				<div class="operation-status-popover" id="build-action-status" role="status">
					<div class="operation-status-head">
						<strong>{buildStatus.message}</strong>
						{#if buildStatus.operationActive}
							<span>{formatBytes(buildStatus.progress.speedBytesPerSecond)}/с</span>
						{/if}
					</div>
					{#if buildStatus.operationActive}
						<div
							class="operation-progress-track"
							role="progressbar"
							aria-label="Прогресс загрузки сборки"
							aria-valuemin="0"
							aria-valuemax="100"
							aria-valuenow={buildStatus.progress.totalBytes > 0
								? Math.round(
										Math.min(
											100,
											(buildStatus.progress.downloadedBytes / buildStatus.progress.totalBytes) * 100,
										),
									)
								: 0}
						>
							<span
								style={`width: ${buildStatus.progress.totalBytes > 0 ? Math.min(100, (buildStatus.progress.downloadedBytes / buildStatus.progress.totalBytes) * 100) : 0}%`}
							></span>
						</div>
						<div class="operation-status-grid">
							<span>Загружено</span>
							<strong>{formatBytes(buildStatus.progress.downloadedBytes)}</strong>
							<span>Осталось скачать</span>
							<strong>{formatBytes(buildStatus.progress.remainingBytes)}</strong>
							<span><HardDrive size={13} /> Требуется</span>
							<strong>{formatBytes(buildStatus.progress.diskRequiredBytes)}</strong>
							<span><HardDrive size={13} /> Будет свободно</span>
							<strong>{formatBytes(projectedFreeBytes)}</strong>
						</div>
						{#if buildStatus.progress.currentFile}
							<p class="operation-current-file">{buildStatus.progress.currentFile}</p>
						{/if}
					{/if}
				</div>
			{/if}

			<button
				type="button"
				class="play-button home-play"
				class:blocked={actionUnavailable}
				aria-disabled={actionUnavailable}
				aria-describedby={showStatusPopover ? 'build-action-status' : undefined}
				onclick={runPrimaryAction}
			>
				{#if buildStatus.primaryAction === 'download'}
					<Download size={18} />
				{:else if buildStatus.primaryAction === 'update'}
					<RefreshCw size={18} />
				{:else if buildStatus.primaryAction === 'repair'}
					<ShieldCheck size={18} />
				{:else if buildStatus.primaryAction === 'busy'}
					<LoaderCircle size={18} class="spin-icon" />
				{:else if buildStatus.primaryAction === 'blocked' && buildStatus.phase === 'error'}
					<TriangleAlert size={18} />
				{:else if buildStatus.primaryAction === 'blocked'}
					<LockKeyhole size={18} />
				{:else}
					<Play size={18} fill="currentColor" />
				{/if}
				<span>{actionLabel()}</span>
			</button>
		</div>

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
						<span>Настройки сборки</span>
					</button>
					<button
						type="button"
						class="menu-action"
						disabled
						title="Будет подключено вместе с TUF-клиентом"
					>
						<RefreshCw size={16} />
						<span>Проверка файлов — следующий этап</span>
					</button>
				</div>
			{/if}
		</div>
	</div>
</div>
