<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLAttributes } from 'svelte/elements';

	interface Props extends HTMLAttributes<HTMLDivElement> {
		children: Snippet;
		class?: string;
	}

	// Unknown attributes are forwarded, so a page can mark a card with which
	// thing it is about (`data-binding`, `data-source`) without this component
	// having to know what those mean.
	let { children, class: klass = '', ...rest }: Props = $props();
</script>

<div {...rest} class="rounded-card border border-line bg-surface {klass}">
	{@render children()}
</div>
