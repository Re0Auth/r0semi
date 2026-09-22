<script lang="ts">
	import { base } from '$app/paths';
	import '../app.css';

	let { children } = $props();
</script>

<div class="flex min-h-dvh flex-col">
	<header class="border-b border-line">
		<div class="mx-auto flex w-full max-w-2xl items-center px-5 py-4">
			<a href="{base}/" class="flex items-center gap-2.5 text-sm font-semibold tracking-tight">
				<span
					class="grid size-6 place-items-center rounded-md bg-ink font-mono text-[11px] font-bold text-canvas"
					aria-hidden="true">r0</span
				>
				<span>Re0Auth</span>
			</a>
		</div>
	</header>

	<main class="mx-auto w-full max-w-2xl flex-1 px-5 py-8">
		{@render children()}
	</main>

	<footer class="border-t border-line">
		<div class="mx-auto w-full max-w-2xl px-5 py-4 text-xs text-ink-faint">
			独立的音游数据授权与互通层 · Re0Auth 不托管你的上游凭据
		</div>
	</footer>
</div>
