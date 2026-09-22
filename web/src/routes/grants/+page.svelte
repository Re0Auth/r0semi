<script lang="ts">
	import { onMount } from 'svelte';
	import { base } from '$app/paths';
	import { api, ApiError, type Grant } from '$lib/api';
	import SignIn from '$lib/components/SignIn.svelte';
	import Alert from '$lib/components/ui/Alert.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import Card from '$lib/components/ui/Card.svelte';

	type Phase = 'loading' | 'anonymous' | 'ready' | 'failed';

	let phase = $state<Phase>('loading');
	let grants = $state<Grant[]>([]);
	let csrf = $state('');
	let detail = $state('');
	let actionError = $state('');
	// Revocation is destructive and irreversible from this page, so it takes two
	// clicks. An inline confirm rather than window.confirm: it keeps the context
	// on screen, and it is a real button a keyboard and a test can both reach.
	let confirming = $state<string | null>(null);
	let revoking = $state<string | null>(null);

	onMount(load);

	async function load() {
		try {
			// The session is fetched for its CSRF token: revoking is a write, and the
			// token is bound to the session, so there is nothing to fetch it from but
			// the session itself.
			const [session, list] = await Promise.all([api.currentSession(), api.listGrants()]);
			csrf = session.csrf_token;
			grants = list.data;
			phase = 'ready';
		} catch (err) {
			if (err instanceof ApiError && err.needsSignIn) {
				phase = 'anonymous';
				return;
			}
			detail = err instanceof Error ? err.message : String(err);
			phase = 'failed';
		}
	}

	async function revoke(grant: Grant) {
		revoking = grant.client_id;
		actionError = '';
		try {
			await api.revokeGrant(grant.client_id, csrf);
			// The list is what the server says it is; removing the entry locally and
			// trusting that is how a UI ends up disagreeing with its own backend.
			grants = grants.filter((g) => g.client_id !== grant.client_id);
			confirming = null;
		} catch (err) {
			if (err instanceof ApiError && err.needsSignIn) {
				phase = 'anonymous';
				return;
			}
			actionError = err instanceof Error ? err.message : String(err);
		} finally {
			revoking = null;
		}
	}

	function formatDate(iso: string): string {
		const date = new Date(iso);
		if (Number.isNaN(date.getTime())) return iso;
		return date.toLocaleString();
	}
</script>

<h1 class="text-lg font-semibold">已授权的应用</h1>
<p class="mt-1 text-sm text-ink-muted">这些应用现在可以以你的身份行动。</p>

{#if phase === 'loading'}
	<p class="mt-4 text-sm text-ink-muted">正在读取…</p>
{:else if phase === 'anonymous'}
	<div class="mt-4 flex flex-col gap-4">
		<Alert tone="warn" title="需要先登录">登录后才能看到已授权的应用。</Alert>
		<SignIn />
	</div>
{:else if phase === 'failed'}
	<p class="mt-4 text-sm text-danger">{detail}</p>
{:else}
	<div class="mt-4 flex flex-col gap-4">
		{#if actionError}
			<div class="rounded-card border border-danger/40 bg-danger-soft p-3 text-sm text-danger">
				{actionError}
			</div>
		{/if}

		{#if grants.length === 0}
			<Card>
				<p class="px-4 py-6 text-center text-sm text-ink-muted">
					还没有任何应用获得授权。
				</p>
			</Card>
		{:else}
			{#each grants as grant (grant.client_id)}
				<Card>
					<div class="flex flex-wrap items-start justify-between gap-3 border-b border-line px-4 py-3">
						<div class="min-w-0">
							<p class="font-medium">{grant.client_name || grant.client_id}</p>
							<p class="mt-0.5 font-mono text-xs text-ink-faint">{grant.client_id}</p>
						</div>
						<Badge tone={grant.has_refresh ? 'warn' : 'neutral'}>
							{grant.has_refresh ? '可自动续期' : '到期后需重新授权'}
						</Badge>
					</div>

					<ul class="divide-y divide-line">
						{#each grant.scopes as scope (scope.scope)}
							<li class="flex items-start gap-2 px-4 py-2">
								<span class="mt-1 size-1.5 shrink-0 rounded-full bg-ink-faint" aria-hidden="true"></span>
								<div class="min-w-0">
									<p class="text-sm">{scope.title || scope.scope}</p>
									<p class="font-mono text-xs text-ink-faint">{scope.scope}</p>
								</div>
							</li>
						{/each}
					</ul>

					<div class="flex flex-wrap items-center justify-between gap-3 border-t border-line px-4 py-3">
						<p class="text-xs text-ink-faint">
							{formatDate(grant.issued_at)} 起 · 最迟 {formatDate(grant.expires_at)} 失效
						</p>
						{#if confirming === grant.client_id}
							<div class="flex flex-wrap items-center gap-2">
								<span class="text-xs text-ink-muted">该应用会立即失去访问权限。</span>
								<Button variant="quiet" onclick={() => (confirming = null)}>取消</Button>
								<Button
									variant="danger"
									loading={revoking === grant.client_id}
									onclick={() => revoke(grant)}
								>
									确认撤销
								</Button>
							</div>
						{:else}
							<Button variant="secondary" onclick={() => (confirming = grant.client_id)}>撤销</Button>
						{/if}
					</div>
				</Card>
			{/each}
		{/if}

		<!--
			What revocation is NOT has to be said, because "撤销" is the kind of word
			people reasonably read as "undo everything". It revokes Re0Auth's tokens and
			nothing else: the data-source connections and any upstream session are a
			different action with a different, louder consequence.
		-->
		<p class="text-xs text-ink-faint">
			撤销只影响该应用在 Re0Auth 这里的授权。你的数据源绑定与上游登录不受影响，其他应用也照常工作。
			断开数据源连接在
			<a href="{base}/sources" class="text-accent underline-offset-4 hover:underline">数据源连接</a>
			页，作废上游登录也在那里（如果数据源支持）。
		</p>
	</div>
{/if}
