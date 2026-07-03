<script lang="ts">
	import { Info } from '@lucide/svelte';

	type Props = {
		closeDiagnosticsNotice: () => void;
		dismissDiagnosticsNotice: () => void;
	};

	let { closeDiagnosticsNotice, dismissDiagnosticsNotice }: Props = $props();
</script>

<div class="modal-backdrop">
	<div class="privacy-modal rounded-[26px] border border-border bg-panel p-5">
		<div class="flex items-start gap-4">
			<div class="grid size-11 shrink-0 place-items-center rounded-[16px] bg-accent/14 text-accent">
				<Info size={21} />
			</div>
			<div>
				<p class="text-lg font-semibold">Диагностика помогает быстрее решить проблему</p>
				<p class="mt-3 text-sm leading-6 text-muted">
					Мы используем данные о железе, версии Java и настройках сборки только для поддержки и
					статистики. Они помогают понять, на каких ПК играют в Fragment, быстрее находить
					нестабильные места и улучшать продукт. Личные данные не публикуются и не передаются
					посторонним.
				</p>
				<div class="mt-5 flex flex-col gap-2 sm:flex-row sm:justify-end">
					<button class="secondary-button" onclick={closeDiagnosticsNotice}>
						<span>Понятно</span>
					</button>
					<button class="primary-button" onclick={dismissDiagnosticsNotice}>
						<span>Больше не показывать</span>
					</button>
				</div>
			</div>
		</div>
	</div>
</div>
