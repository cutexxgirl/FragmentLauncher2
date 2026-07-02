<script lang="ts">
import { Minus, ShieldCheck, Square, X } from '@lucide/svelte';
import type { BuildProfile, Preset } from '$lib/launcher-ui';

type Props = {
  activeBuild: BuildProfile;
  activePreset: Preset;
  startDrag: () => void | Promise<void>;
  toggleMaximize: () => void | Promise<void>;
  minimize: () => void | Promise<void>;
  closeWindow: () => void | Promise<void>;
};

let { activeBuild, activePreset, startDrag, toggleMaximize, minimize, closeWindow }: Props = $props();
</script>

<header
					class="titlebar flex h-[62px] select-none items-center justify-between border-b border-border px-5"
					role="toolbar"
					aria-label="Window title bar"
					tabindex="-1"
					onmousedown={startDrag}
					ondblclick={toggleMaximize}
				>
					<div class="flex min-w-0 items-center gap-3">
						<span class="status-dot size-2.5 rounded-full bg-success"></span>
						<div class="min-w-0">
							<p class="text-xs text-muted">Локальный режим</p>
							<p class="truncate text-sm font-medium">
								{activeBuild.name} - {activePreset.name}
							</p>
						</div>
					</div>

					<div class="flex items-center gap-2">
						<div class="hidden items-center gap-2 rounded-[16px] border border-border bg-panel/80 px-3 py-2 text-xs text-muted md:flex">
							<ShieldCheck size={15} class="text-success" />
							<span>Профиль готов</span>
						</div>
						<div class="flex items-center gap-1">
							<button
								class="window-control"
								aria-label="Minimize window"
								title="Свернуть"
								onmousedown={(event) => event.stopPropagation()}
								onclick={minimize}
							>
								<Minus size={15} />
							</button>
							<button
								class="window-control"
								aria-label="Maximize window"
								title="Развернуть"
								onmousedown={(event) => event.stopPropagation()}
								onclick={toggleMaximize}
							>
								<Square size={13} />
							</button>
							<button
								class="window-control close"
								aria-label="Close window"
								title="Закрыть"
								onmousedown={(event) => event.stopPropagation()}
								onclick={closeWindow}
							>
								<X size={16} />
							</button>
						</div>
					</div>
				</header>
