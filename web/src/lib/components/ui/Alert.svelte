<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		tone?: 'info' | 'warn' | 'danger';
		title?: string;
		/** Rendered under the body; use for the actions that resolve the alert. */
		actions?: Snippet;
		children?: Snippet;
	}

	let { tone = 'info', title, actions, children }: Props = $props();

	const tones = {
		info: 'border-line-strong bg-canvas',
		warn: 'border-warn/40 bg-warn-soft',
		danger: 'border-danger/40 bg-danger-soft'
	} as const;

	// role="alert" so a screen reader announces a failure without the user having
	// to go looking for it. A failed consent decision is not something to discover
	// by scrolling. Derived rather than computed once, so it keeps up if a page
	// changes an alert's tone in place.
	const role = $derived(tone === 'info' ? 'status' : 'alert');
</script>

<div class="rounded-card border p-4 text-sm {tones[tone]}" {role}>
	{#if title}
		<p class="font-semibold">{title}</p>
	{/if}
	{#if children}
		<div class="mt-1 text-ink-muted {title ? '' : 'mt-0'}">
			{@render children()}
		</div>
	{/if}
	{#if actions}
		<div class="mt-3 flex flex-wrap gap-2">
			{@render actions()}
		</div>
	{/if}
</div>
