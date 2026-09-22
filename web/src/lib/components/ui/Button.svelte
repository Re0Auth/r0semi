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
	const variants = {
		primary: 'border-transparent bg-accent text-accent-ink hover:opacity-90',
		secondary: 'border-line-strong bg-surface text-ink hover:bg-canvas',
		danger: 'border-danger/40 bg-danger-soft text-danger hover:border-danger hover:bg-danger/10',
		quiet: 'border-transparent bg-transparent text-ink-muted underline-offset-4 hover:text-ink hover:underline'
	} as const;
</script>

<button
	{...rest}
	disabled={disabled || loading}
	aria-busy={loading}
	class="inline-flex min-h-10 items-center justify-center gap-2 rounded-lg border px-4 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50 {variants[
		variant
	]} {klass}"
>
	{#if loading}
		<span
			aria-hidden="true"
			class="size-4 animate-spin rounded-full border-2 border-current border-t-transparent"
		></span>
	{/if}
	{@render children()}
</button>
