export type SectionId = 'home' | 'support' | 'profile';
export type PresetId = 'low' | 'medium' | 'high';
export type FeedCategory = 'news' | 'announcements';

export type BuildProfile = {
	id: 'fragment-stable' | 'fragment-dev';
	channel: 'stable' | 'dev';
	name: string;
	preset: PresetId;
};

export type Preset = {
	id: PresetId;
	name: string;
	description: string;
	ram: number;
};

export type FeedItem = {
	id: string;
	category: FeedCategory;
	date: string;
	title: string;
};

export const feedImages: string[] = [
	'linear-gradient(135deg, rgba(240, 179, 93, 0.86), rgba(41, 48, 48, 0.92)), radial-gradient(circle at 78% 26%, rgba(255, 255, 255, 0.38), transparent 26%)',
	'linear-gradient(140deg, rgba(117, 199, 192, 0.72), rgba(17, 18, 19, 0.96)), radial-gradient(circle at 24% 34%, rgba(240, 179, 93, 0.32), transparent 28%)',
	'linear-gradient(150deg, rgba(72, 81, 86, 0.9), rgba(18, 18, 18, 0.96)), radial-gradient(circle at 66% 28%, rgba(240, 179, 93, 0.42), transparent 30%)',
	'linear-gradient(145deg, rgba(58, 63, 70, 0.92), rgba(16, 17, 18, 0.96)), radial-gradient(circle at 28% 25%, rgba(117, 199, 192, 0.42), transparent 25%)',
	'linear-gradient(135deg, rgba(240, 179, 93, 0.42), rgba(117, 199, 192, 0.34), rgba(12, 13, 14, 0.98))',
];

export const presets: Preset[] = [
	{
		id: 'low',
		name: 'Низкий',
		description: 'Для слабых ПК: меньше эффектов и быстрый старт',
		ram: 4,
	},
	{
		id: 'medium',
		name: 'Средний',
		description: 'Баланс качества изображения и FPS',
		ram: 6,
	},
	{
		id: 'high',
		name: 'Высокий',
		description: 'Максимальное качество для мощных систем',
		ram: 10,
	},
];

export const feedItems: FeedItem[] = [
	{ id: 'spark2', category: 'news', date: '11/07', title: 'Spark2: защищённые обновления' },
	{ id: 'neoforge', category: 'news', date: '11/07', title: 'NeoForge 21.1.235 и Java 21' },
	{
		id: 'quality-presets',
		category: 'announcements',
		date: '11/07',
		title: 'Три подписанных пресета качества',
	},
];

export function createBuildProfiles(): BuildProfile[] {
	return [
		{ id: 'fragment-stable', channel: 'stable', name: 'Fragment', preset: 'medium' },
		{ id: 'fragment-dev', channel: 'dev', name: 'Fragment Dev', preset: 'medium' },
	];
}
