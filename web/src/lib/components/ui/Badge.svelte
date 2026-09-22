<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		tone?: 'neutral' | 'accent' | 'warn' | 'danger' | 'ok';
		children: Snippet;
	}

	let { tone = 'neutral', children }: Props = $props();

	// Tone is never the only signal: every badge in this app also carries a word.
	// Colour is reinforcement, not information, so the page still reads in
	// greyscale or with colour blindness.
	const tones = {
		neutral: 'border-line-strong bg-canvas text-ink-muted',
		accent: 'border-accent/30 bg-accent-soft text-accent',
		warn: 'border-warn/40 bg-warn-soft text-warn',
		danger: 'border-danger/40 bg-danger-soft text-danger',
		ok: 'border-ok/40 bg-ok/10 text-ok'
	} as const;
</script>

<span
	class="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium whitespace-nowrap {tones[
		tone
	]}"
>
	{@render children()}
</span>
