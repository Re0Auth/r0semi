<script lang="ts">
	interface Props {
		value: string;
		/** What is being copied, for the accessible name: "复制账号 ID". */
		label: string;
	}

	let { value, label }: Props = $props();

	let copied = $state(false);
	let timer: ReturnType<typeof setTimeout> | undefined;

	async function copy() {
		try {
			await navigator.clipboard.writeText(value);
			copied = true;
			clearTimeout(timer);
			timer = setTimeout(() => (copied = false), 1500);
		} catch {
			// A denied clipboard leaves the value on screen to select by hand, which is
			// why the button needs no error state of its own.
		}
	}

	$effect(() => () => clearTimeout(timer));
</script>

<!--
	The affordance an identifier needs. These values exist to be quoted somewhere
	else, and asking someone to select a 40-character mono string by hand is the kind
	of friction that never shows up in a copy deck.

	Icon only until it has something to say, so a copy control next to every value
	does not turn a quiet page into a row of buttons. The visible word appears only
	as the confirmation, and the accessible name carries the label in both states.
-->
<button
	type="button"
	class="relative inline-flex min-h-6 shrink-0 cursor-pointer touch-manipulation items-center justify-center gap-1 rounded-md px-1 text-xs text-ink-faint transition-[color,scale] before:absolute before:-inset-1.5 before:content-[''] hover:text-ink active:scale-[0.98]"
	aria-label={copied ? `${label} 已复制` : `复制${label}`}
	onclick={copy}
>
	{#if copied}
		<span class="whitespace-nowrap">已复制</span>
	{:else}
		<svg class="size-3.5" viewBox="0 0 14 14" fill="none" aria-hidden="true">
			<rect x="4.7" y="4.7" width="7.3" height="7.3" rx="1.6" stroke="currentColor" stroke-width="1.2" />
			<path
				d="M9.3 2.5H3.7a1.2 1.2 0 0 0-1.2 1.2v5.6"
				stroke="currentColor"
				stroke-width="1.2"
				stroke-linecap="round"
			/>
		</svg>
	{/if}
</button>
