<script lang="ts">
	import { base } from '$app/paths';
	import { page } from '$app/state';
	import '../app.css';

	let { children } = $props();

	// The path without the mount prefix, so `/app/grants` compares as `/grants`.
	const current = $derived(page.url.pathname.slice(base.length) || '/');
	const links = [
		{ href: `${base}/`, path: '/', label: '账号' },
		{ href: `${base}/grants`, path: '/grants', label: '应用' },
		{ href: `${base}/sources`, path: '/sources', label: '数据源' }
	];

	// A client-side navigation replaces the whole main region without moving
	// focus, so a keyboard or screen-reader user stays where the old page was.
	// Moving focus to the new main is the standard SPA fix; the first render is
	// skipped so loading the app does not yank focus from the address bar.
	let main: HTMLElement | undefined = $state();
	let firstRender = true;
	$effect(() => {
		page.url.pathname;
		if (firstRender) {
			firstRender = false;
			return;
		}
		main?.focus();
	});
</script>

<div class="flex min-h-dvh flex-col">
	<header class="border-b border-line">
		<div class="shell-x mx-auto flex w-full max-w-2xl flex-wrap items-center gap-x-5 gap-y-2 py-4 lg:max-w-4xl">
			<a
				href="{base}/"
				class="flex touch-manipulation items-center gap-2.5 text-sm font-semibold tracking-tight"
			>
				<span
					class="grid size-6 place-items-center rounded-md bg-ink font-mono text-2xs font-bold text-canvas"
					aria-hidden="true">r0</span
				>
				<span>Re0Auth</span>
			</a>
			<!--
				Persistent nav, so a subpage is never a dead end: before this, the only way
				out of /grants or /sources was the logo, and the only way in was two cards on
				the account page. Labels are short because they share a row with the brand on
				a 320px screen; the pages keep their full headings. aria-current carries the
				"you are here" state, so it is not left to colour alone.
			-->
			<nav class="flex items-center gap-4 text-sm" aria-label="主导航">
				{#each links as link (link.path)}
					<a
						href={link.href}
						aria-current={current === link.path ? 'page' : undefined}
						class="-my-1 touch-manipulation py-1 {current === link.path
							? 'font-medium text-ink'
							: 'text-ink-muted hover:text-ink'}"
					>
						{link.label}
					</a>
				{/each}
			</nav>
		</div>
	</header>

	<!--
		The frame steps once, at the point where a single column stops being the
		right shape for what the app actually contains: lists of cards. Below lg it
		stays a reading measure; at lg the extra width is handed to the pages, which
		recompose into two columns where they have the content for it and constrain
		specific elements (prose, the device form) to a comfortable measure where they
		do not. Widening the frame without that per-page work would just stretch every
		line of text.
	-->
	<main
		bind:this={main}
		tabindex="-1"
		class="shell-x shell-y mx-auto w-full max-w-2xl flex-1 py-8 outline-none lg:max-w-4xl"
	>
		<!--
			The arrival replays per navigation, so the wrapper is keyed on the path:
			the key changes and the animation runs again. Keyed on the path rather than
			the whole URL on purpose, because a query-only change is the same screen
			with different content, and blanking it to replay an entrance would read as
			a page load that did not happen.
		-->
		{#key page.url.pathname}
			<div class="enter">{@render children()}</div>
		{/key}
	</main>
</div>
