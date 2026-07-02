export type SectionId = 'home' | 'build' | 'support' | 'profile';
export type PresetId = 'low' | 'medium' | 'high';

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

export type NewsItem = {
	title: string;
	text: string;
	date: string;
	tag: string;
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

export const news: NewsItem[] = [
	{
		title: 'Готовим новый экран сборок',
		text: 'Добавили основу выбора сборки, пресеты производительности и место под будущую проверку файлов.',
		date: 'Сегодня',
		tag: 'Launcher'
	},
	{
		title: 'Опциональные моды вынесены отдельно',
		text: 'Теперь можно включать косметику, карту и графические улучшения без изменения базовой сборки.',
		date: 'Вчера',
		tag: 'Сборки'
	},
	{
		title: 'Техподдержка станет быстрее',
		text: 'Черновик обращения уже умеет прикладывать последний лог, краш-репорт и скриншот.',
		date: 'План',
		tag: 'Support'
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
