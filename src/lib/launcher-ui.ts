export type SectionId = 'home' | 'build' | 'support' | 'profile';
export type PresetId = 'low' | 'medium' | 'high';
export type FeedCategory = 'news' | 'announcements';

export type OptionalMod = {
	id: string;
	name: string;
	description: string;
	impact: string;
	enabled: boolean;
};

export type BuildProfile = {
	id: string;
	name: string;
	subtitle: string;
	version: string;
	tag: string;
	description: string;
	access: 'available' | 'subscription';
	size: string;
	minecraft: string;
	selectedRam: number;
	javaPath: string;
	preset: PresetId;
	mods: OptionalMod[];
	shaders: string[];
	resourcePacks: string[];
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
	headline: string;
	images: string[];
};

export const presets: Preset[] = [
	{
		id: 'low',
		name: 'Слабый',
		description: 'Меньше эффектов, быстрый старт',
		ram: 4
	},
	{
		id: 'medium',
		name: 'Средний',
		description: 'Баланс графики и FPS',
		ram: 6
	},
	{
		id: 'high',
		name: 'Высокий',
		description: 'Максимум визуала',
		ram: 10
	}
];

export const feedItems: FeedItem[] = [
	{
		id: 'launcher-base',
		category: 'news',
		date: '02/07',
		title: 'Новая база лаунчера',
		headline: 'Сборки, профиль и поддержка собраны в первый рабочий каркас.',
		images: [
			'linear-gradient(135deg, rgba(240, 179, 93, 0.86), rgba(41, 48, 48, 0.92)), radial-gradient(circle at 78% 26%, rgba(255, 255, 255, 0.38), transparent 26%)',
			'linear-gradient(140deg, rgba(117, 199, 192, 0.72), rgba(17, 18, 19, 0.96)), radial-gradient(circle at 24% 34%, rgba(240, 179, 93, 0.32), transparent 28%)',
			'linear-gradient(150deg, rgba(72, 81, 86, 0.9), rgba(18, 18, 18, 0.96)), radial-gradient(circle at 66% 28%, rgba(240, 179, 93, 0.42), transparent 30%)'
		]
	},
	{
		id: 'optional-mods',
		category: 'news',
		date: '01/07',
		title: 'Опциональные моды',
		headline: 'Карта, камера и визуальные эффекты теперь живут отдельно от ядра сборки.',
		images: [
			'linear-gradient(145deg, rgba(58, 63, 70, 0.92), rgba(16, 17, 18, 0.96)), radial-gradient(circle at 28% 25%, rgba(117, 199, 192, 0.42), transparent 25%)',
			'linear-gradient(135deg, rgba(240, 179, 93, 0.52), rgba(18, 18, 18, 0.96)), radial-gradient(circle at 72% 18%, rgba(255, 255, 255, 0.3), transparent 22%)'
		]
	},
	{
		id: 'support-diagnostics',
		category: 'announcements',
		date: '30/06',
		title: 'Диагностика обращений',
		headline: 'Логи, crash report и скриншот можно подготовить в одном месте.',
		images: [
			'linear-gradient(140deg, rgba(117, 199, 192, 0.5), rgba(21, 23, 25, 0.96)), radial-gradient(circle at 72% 32%, rgba(240, 179, 93, 0.36), transparent 28%)',
			'linear-gradient(145deg, rgba(37, 41, 45, 0.96), rgba(12, 13, 14, 0.98)), radial-gradient(circle at 35% 30%, rgba(116, 211, 169, 0.34), transparent 26%)'
		]
	},
	{
		id: 'visual-pack',
		category: 'announcements',
		date: '28/06',
		title: 'Fragment Visual',
		headline: 'Плюс-сборка получит отдельные шейдерные профили и HD-поверхности.',
		images: [
			'linear-gradient(135deg, rgba(240, 179, 93, 0.42), rgba(117, 199, 192, 0.34), rgba(12, 13, 14, 0.98))',
			'linear-gradient(145deg, rgba(82, 71, 56, 0.86), rgba(18, 18, 18, 0.96)), radial-gradient(circle at 70% 36%, rgba(240, 179, 93, 0.5), transparent 28%)',
			'linear-gradient(145deg, rgba(56, 64, 69, 0.9), rgba(15, 16, 17, 0.98)), radial-gradient(circle at 28% 28%, rgba(117, 199, 192, 0.38), transparent 24%)'
		]
	}
];

export function createBuildProfiles(): BuildProfile[] {
	return [
		{
			id: 'fragment-origin',
			name: 'Fragment Origin',
			subtitle: 'Основная одиночная сборка',
			version: '1.20.1',
			tag: 'Stable',
			description: 'Базовый опыт Fragment: исследование, техника и аккуратные визуальные улучшения.',
			access: 'available',
			size: '18.4 ГБ',
			minecraft: 'Forge 47.3',
			selectedRam: 6,
			javaPath: 'C:\\Program Files\\Java\\jdk-21\\bin\\javaw.exe',
			preset: 'medium',
			mods: [
				{
					id: 'minimap',
					name: 'Миникарта',
					description: 'Навигация без вмешательства в баланс.',
					impact: 'легко',
					enabled: true
				},
				{
					id: 'ambient',
					name: 'Ambient FX',
					description: 'Погода, частицы и мягкая атмосфера.',
					impact: 'средне',
					enabled: true
				},
				{
					id: 'camera',
					name: 'Cinematic Camera',
					description: 'Плавная камера для скриншотов и видео.',
					impact: 'легко',
					enabled: false
				},
				{
					id: 'waystones',
					name: 'Waystones Lite',
					description: 'Удобные точки перемещения в одиночном мире.',
					impact: 'средне',
					enabled: false
				}
			],
			shaders: ['Fragment Soft Light.zip'],
			resourcePacks: ['Fragment UI Clean.zip']
		},
		{
			id: 'fragment-sky',
			name: 'Fragment Sky',
			subtitle: 'Экспериментальная небесная сборка',
			version: '1.20.1',
			tag: 'Beta',
			description: 'Легкий skyblock-вариант для коротких сессий и теста новых механик.',
			access: 'available',
			size: '12.1 ГБ',
			minecraft: 'Forge 47.3',
			selectedRam: 4,
			javaPath: 'C:\\Program Files\\Java\\jdk-21\\bin\\javaw.exe',
			preset: 'low',
			mods: [
				{
					id: 'sky-map',
					name: 'Sky Map',
					description: 'Маршруты островов и быстрые метки.',
					impact: 'легко',
					enabled: true
				},
				{
					id: 'clouds',
					name: 'Cloud Depth',
					description: 'Дополнительные облака и глубина неба.',
					impact: 'средне',
					enabled: false
				},
				{
					id: 'quests',
					name: 'Quest Hints',
					description: 'Подсказки по ранним цепочкам прогресса.',
					impact: 'легко',
					enabled: true
				}
			],
			shaders: [],
			resourcePacks: ['Sky Minimal UI.zip']
		},
		{
			id: 'fragment-visual',
			name: 'Fragment Visual',
			subtitle: 'Визуальный пресет для подписки',
			version: '1.20.1',
			tag: 'Plus',
			description: 'Расширенная графика, дополнительные анимации и набор шейдерных профилей.',
			access: 'subscription',
			size: '21.7 ГБ',
			minecraft: 'Forge 47.3',
			selectedRam: 10,
			javaPath: 'C:\\Program Files\\Java\\jdk-21\\bin\\javaw.exe',
			preset: 'high',
			mods: [
				{
					id: 'visual-fx',
					name: 'Visual FX Pack',
					description: 'Свет, отражения и улучшенные частицы.',
					impact: 'тяжело',
					enabled: true
				},
				{
					id: 'photo-mode',
					name: 'Photo Mode',
					description: 'Инструменты для постановочных скриншотов.',
					impact: 'средне',
					enabled: true
				},
				{
					id: 'motion',
					name: 'Motion Detail',
					description: 'Плавные анимации окружения.',
					impact: 'тяжело',
					enabled: false
				}
			],
			shaders: ['Fragment Cinematic.zip', 'Soft Shadows.zip'],
			resourcePacks: ['Fragment HD Surfaces.zip']
		}
	];
}
