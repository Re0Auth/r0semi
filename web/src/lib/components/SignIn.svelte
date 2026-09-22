<script lang="ts">
	import { api, providerLabel, type IDPProvider } from '$lib/api';
	import Button from './ui/Button.svelte';

	interface Props {
		/** Called with the provider id once the browser is on its way out. */
		onleave?: () => void;
	}

	let { onleave }: Props = $props();

	let providers = $state<IDPProvider[]>([]);
	let loading = $state(true);
	let failed = $state<string | null>(null);
	let leaving = $state<string | null>(null);

	$effect(() => {
		let cancelled = false;
		api
			.listIDPProviders()
			.then((res) => {
				if (!cancelled) providers = res.data;
			})
			.catch((err) => {
				if (!cancelled) failed = err instanceof Error ? err.message : String(err);
			})
			.finally(() => {
				if (!cancelled) loading = false;
			});
		return () => {
			cancelled = true;
		};
	});

	function begin(provider: IDPProvider) {
		leaving = provider.id;
		onleave?.();
		// A full navigation, not a fetch: the session cookie is set by whatever
		// comes back from the provider, and this is a trip through a third party.
		window.location.assign(provider.start_url);
	}
</script>

{#if loading}
	<p class="text-sm text-ink-muted">正在读取登录方式…</p>
{:else if failed}
	<p class="text-sm text-danger">无法读取登录方式：{failed}</p>
{:else if providers.length === 0}
	<!--
		A deployment with no identity provider configured cannot create any account.
		Saying so is more useful than an empty box: it is a configuration problem,
		and it is the operator's, not the visitor's.
	-->
	<p class="text-sm text-ink-muted">此部署未配置任何身份提供方，因此暂时无法登录。</p>
{:else}
	<div class="flex flex-col gap-2">
		{#each providers as p (p.id)}
			<Button variant="secondary" loading={leaving === p.id} onclick={() => begin(p)}>
				使用 {providerLabel(p.id)} 登录
			</Button>
		{/each}
	</div>
{/if}
