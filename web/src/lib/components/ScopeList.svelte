<script lang="ts">
	import type { ScopeView } from '$lib/api';
	import Badge from './ui/Badge.svelte';

	interface Props {
		scopes: ScopeView[];
		/** Which scopes are being granted, keyed by scope name. */
		selected: Record<string, boolean>;
		/** Which explicit-consent scopes were ticked on their own. */
		acknowledged: Record<string, boolean>;
		/** Render as a read-only list, for the confirmation steps. */
		readonly?: boolean;
		onToggle?: (scope: string, granted: boolean) => void;
		onAcknowledge?: (scope: string, ok: boolean) => void;
	}

	let { scopes, selected, acknowledged, readonly = false, onToggle, onAcknowledge }: Props = $props();

	// Every badge carries a word beside its colour, so the page still reads
	// correctly without colour: in greyscale, in high contrast, or with colour
	// blindness. Colour is reinforcement, never the information itself.
	const riskText: Record<ScopeView['risk'], string> = {
		low: '低风险',
		medium: '中风险',
		high: '高风险',
		critical: '极高风险'
	};
	const riskTone: Record<ScopeView['risk'], 'neutral' | 'accent' | 'warn' | 'danger'> = {
		low: 'neutral',
		medium: 'neutral',
		high: 'warn',
		critical: 'danger'
	};
</script>

<ul class="divide-y divide-line">
	{#each scopes as s (s.scope)}
		<li class="px-4 py-3">
			<div class="flex items-start gap-3">
				{#if !readonly}
					<input
						type="checkbox"
						id="scope-{s.scope}"
						checked={!!selected[s.scope]}
						onchange={(e) => onToggle?.(s.scope, e.currentTarget.checked)}
						class="mt-1 size-5 shrink-0 accent-[var(--color-accent)]"
					/>
				{/if}
				<div class="min-w-0 flex-1">
					<div class="flex flex-wrap items-center gap-2">
						{#if readonly}
							<span class="font-medium">{s.title || s.scope}</span>
						{:else}
							<label for="scope-{s.scope}" class="cursor-pointer font-medium">
								{s.title || s.scope}
							</label>
						{/if}
						<Badge tone={riskTone[s.risk]}>{riskText[s.risk]}</Badge>
						{#if s.explicit_consent}
							<Badge tone="danger">需单独确认</Badge>
						{/if}
					</div>
					<p class="mt-1 text-sm text-ink-muted">{s.description}</p>
					<p class="mt-1 font-mono text-xs text-ink-faint">{s.scope}</p>

					{#if s.explicit_consent && !readonly}
						<!--
							A second, deliberate tick for a scope the catalogue marks critical.
							The server enforces this independently (an unacknowledged critical
							scope is a 403), so this control is not what makes it safe — it is
							what makes it clear.
						-->
						<label
							class="mt-3 flex cursor-pointer items-start gap-2 rounded-lg border border-danger/40 bg-danger-soft p-3 text-sm"
						>
							<input
								type="checkbox"
								checked={!!acknowledged[s.scope]}
								onchange={(e) => onAcknowledge?.(s.scope, e.currentTarget.checked)}
								class="mt-0.5 size-4 shrink-0"
							/>
							<span>
								我理解 <code class="font-mono">{s.scope}</code> 的含义，并单独同意授予它。
							</span>
						</label>
					{/if}
				</div>
			</div>
		</li>
	{/each}
</ul>
