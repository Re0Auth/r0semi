<script lang="ts">
	import { onMount } from 'svelte';
	import { fade, fly } from 'svelte/transition';
	import { quartOut } from 'svelte/easing';
	import { api, ApiError, type Grant } from '$lib/api';
	import { messageOf } from '$lib/errors';
	import { focusFirstControl, restoreFocus } from '$lib/a11y';
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
			detail = messageOf(err);
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
			actionError = messageOf(err);
		} finally {
			revoking = null;
		}
	}

	// Backing out hands focus back to the 撤销 button, found by selector because the
	// confirmation re-creates it.
	function cancelRevoke(clientId: string) {
		confirming = null;
		void restoreFocus(`[data-revoke="${clientId}"]`);
	}

	function formatDate(iso: string): string {
		const date = new Date(iso);
		if (Number.isNaN(date.getTime())) return iso;
		return date.toLocaleString();
	}
</script>

<svelte:head>
	<title>已授权的应用 · Re0Auth</title>
</svelte:head>

<h1 class="text-page font-semibold text-balance">已授权的应用</h1>

<!-- Escape closes an open confirmation from anywhere, guarded so it cannot steal focus. -->
<svelte:window
	onkeydown={(e) => {
		if (e.key === 'Escape' && confirming !== null) cancelRevoke(confirming);
	}}
/>
{#if phase === 'loading'}
	<p class="mt-4 flex items-center gap-2 text-sm text-ink-muted">
		<span
			class="spinner size-3.5 shrink-0 rounded-full border-2 border-current border-t-transparent"
			aria-hidden="true"
		></span>
		正在读取已授权的应用…
	</p>
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
			<div class="rounded-card border border-danger/40 bg-danger-soft p-3 text-sm text-danger contrast-more:border-danger">
				{actionError}
			</div>
		{/if}

		{#if grants.length === 0}
			<Card>
				<p class="px-4 py-6 text-center text-base text-ink-muted">
					还没有应用获得授权。
				</p>
			</Card>
		{:else}
			<!-- Two up at lg: an authorization is a compact, self-contained thing, and a
			     single 420px column of them wastes the width a desktop has. `grid-cols-1`
			     rather than a bare `grid`, so the implicit track is `minmax(0, 1fr)` and an
			     unbreakable identifier cannot widen it past the frame. -->
			<div class="grid grid-cols-1 gap-4 lg:grid-cols-2 lg:items-start">
			{#each grants as grant (grant.client_id)}
				<Card>
					<div class="flex flex-wrap items-start justify-between gap-3 border-b border-line px-4 py-3">
						<div class="min-w-0">
							<p class="text-base font-medium">{grant.client_name || grant.client_id}</p>
							<p class="mt-0.5 font-mono text-xs break-all text-ink-faint">{grant.client_id}</p>
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
									<p class="font-mono text-xs break-all text-ink-faint">{scope.scope}</p>
								</div>
							</li>
						{/each}
					</ul>

					<div class="flex flex-wrap items-center justify-between gap-3 border-t border-line px-4 py-3">
						<p class="text-xs tabular-nums text-ink-faint">
							{formatDate(grant.issued_at)} 起 · 最迟 {formatDate(grant.expires_at)} 失效
						</p>
						{#if confirming === grant.client_id}
							<!--
								focusFirstControl puts focus on 取消, so a stray Enter cannot revoke.
								The entrance is short and the exit shorter, on the shared curve.
							-->
							<div
								class="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:flex-wrap sm:items-center"
								use:focusFirstControl
								in:fly={{ y: -4, duration: 200, easing: quartOut }}
								out:fade={{ duration: 140 }}
							>
								<span class="text-sm text-ink-muted">该应用会立即失去访问权限。</span>
								<Button
									variant="quiet"
									class="w-full sm:w-auto"
									onclick={() => cancelRevoke(grant.client_id)}>取消</Button
								>
								<Button
									variant="danger"
									class="w-full sm:w-auto"
									loading={revoking === grant.client_id}
									onclick={() => revoke(grant)}
								>
									确认撤销
								</Button>
							</div>
						{:else}
							<Button
								variant="secondary"
								class="w-full sm:w-auto"
								data-revoke={grant.client_id}
								onclick={() => (confirming = grant.client_id)}>撤销</Button
							>
						{/if}
					</div>
				</Card>
			{/each}
			</div>
		{/if}

		<!--
			What revocation is NOT has to be said, because "撤销" is the kind of word
			people reasonably read as "undo everything". It revokes Re0Auth's tokens and
			nothing else: the data-source connections and any upstream session are a
			different action with a different, louder consequence.
		-->
		<p class="max-w-text text-sm text-pretty text-ink-faint">
			撤销不影响数据源连接。
		</p>
	</div>
{/if}
