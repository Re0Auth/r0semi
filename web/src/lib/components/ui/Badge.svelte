<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		tone?: 'neutral' | 'accent' | 'warn' | 'danger' | 'ok';
		/**
		 * Prepend a caution glyph. Opt-in rather than derived from the tone, because
		 * tone and urgency are not the same thing: "可自动续期" is `warn` for emphasis
		 * but it is not a problem, and a glyph would misread it as one.
		 */
		attention?: boolean;
		children: Snippet;
	}

	let { tone = 'neutral', attention = false, children }: Props = $props();

	// Tone is never the only signal: every badge in this app also carries a word.
	// Colour is reinforcement, not information, so the page still reads in
	// greyscale or with colour blindness.
	// Under `prefers-contrast: more` the alpha borders become solid, so the tone is
	// still carried by a boundary rather than only by a tint.
	const tones = {
		neutral: 'border-line-strong bg-canvas text-ink-muted',
		accent: 'border-accent/30 bg-accent-soft text-accent contrast-more:border-accent',
		warn: 'border-warn/40 bg-warn-soft text-warn contrast-more:border-warn',
		danger: 'border-danger/40 bg-danger-soft text-danger contrast-more:border-danger',
		ok: 'border-ok/40 bg-ok/10 text-ok contrast-more:border-ok'
	} as const;
</script>

<span
	class="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap {tones[
		tone
	]}"
>
	{#if attention}
		<svg class="size-3 shrink-0" viewBox="0 0 12 12" fill="none" aria-hidden="true">
			<path
				d="M6 1.3 11.3 10.5H.7L6 1.3Z"
				stroke="currentColor"
				stroke-width="1.1"
				stroke-linejoin="round"
			/>
			<path d="M6 4.5v2.3" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" />
			<path d="M6 8.5v.1" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" />
		</svg>
	{/if}
	{@render children()}
</span>