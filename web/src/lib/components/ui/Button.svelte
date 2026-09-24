<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLButtonAttributes } from 'svelte/elements';

	interface Props extends HTMLButtonAttributes {
		variant?: 'primary' | 'secondary' | 'danger' | 'quiet';
		loading?: boolean;
		children: Snippet;
	}

	let {
		variant = 'secondary',
		loading = false,
		disabled = false,
		children,
		class: klass = '',
		...rest
	}: Props = $props();

	// Filled buttons are reserved for the single affirmative action on a page.
	// A consent screen with two filled buttons asks the user to read; one with
	// one asks them to decide.
	//
	// The filled one is achromatic on purpose. It is the only treatment that can
	// never be confused with `danger` at a glance, it survives every colour-vision
	// simulation, and it leaves the accent free to mean "link" rather than
	// "button". Hover darkens the fill instead of fading it, so the label keeps
	// its contrast at every pointer position.
	// Every variant carries a pressed state as well as a hovered one, because hover
	// does not exist on touch and a tap that produces no visible change reads as a
	// tap that did not register. The press is a small scale rather than a colour
	// shift: the filled variant already sits at its theme's lightness extreme, so
	// there is no darker to go, and a scale reads as physical on all four variants
	// at once.
	const variants = {
		primary: 'border-transparent bg-action text-action-ink hover:bg-action-hover',
		secondary: 'border-line-strong bg-surface text-ink hover:bg-canvas active:bg-surface-sunken',
		danger:
			'border-danger/40 bg-danger-soft text-danger hover:border-danger hover:bg-danger/10 active:bg-danger/20 contrast-more:border-danger',
		quiet:
			'border-transparent bg-transparent text-ink-muted underline-offset-4 hover:text-ink hover:underline active:text-ink'
	} as const;
</script>

<button
	{...rest}
	disabled={disabled || loading}
	aria-busy={loading}
	class="inline-flex min-h-11 cursor-pointer touch-manipulation select-none items-center justify-center gap-2 rounded-lg border px-4 py-2 text-sm font-medium transition-[background-color,border-color,color,scale] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50 {variants[
		variant
	]} {klass}"
>
	{#if loading}
		<span
			aria-hidden="true"
			class="spinner size-4 rounded-full border-2 border-current border-t-transparent"
		></span>
	{/if}
	{@render children()}
</button>
