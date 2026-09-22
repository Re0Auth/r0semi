<script lang="ts">
	import { onMount } from 'svelte';
	import {
		api,
		ApiError,
		type AuthorizationRequest,
		type BindingRequirement
	} from '$lib/api';
	import ScopeList from '$lib/components/ScopeList.svelte';
	import SignIn from '$lib/components/SignIn.svelte';
	import Alert from '$lib/components/ui/Alert.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import Card from '$lib/components/ui/Card.svelte';

	// `gone` covers both "expired" and "not this browser's", which the server
	// deliberately reports as the same thing: a stolen handle should not be
	// confirmed to exist by a different answer.
	type Phase = 'loading' | 'anonymous' | 'gone' | 'ready' | 'failed';

	let phase = $state<Phase>('loading');
	let request = $state<AuthorizationRequest | null>(null);
	let missing = $state<BindingRequirement[]>([]);
	let selected = $state<Record<string, boolean>>({});
	let acknowledged = $state<Record<string, boolean>>({});
	let detail = $state('');
	let actionError = $state('');
	let busy = $state<'approve' | 'deny' | null>(null);

	onMount(load);

	async function load() {
		const id = new URLSearchParams(window.location.search).get('id');
		if (!id) {
			detail = '这个链接缺少 id 参数。';
			phase = 'gone';
			return;
		}
		try {
			const req = await api.getAuthorizationRequest(id);
			request = req;
			missing = req.missing_bindings ?? [];
			// A failed bind comes back as ?error=bind_failed on the URL the server
			// built. Surfacing it is why the flow bothers to carry it.
			if (new URLSearchParams(window.location.search).get('error')) {
				actionError = '连接没有完成：数据源可能拒绝了授权，或者你取消了。可以重试，或直接拒绝这次授权。';
			}
			// Everything is granted by default, and everything is unchecked as
			// individually acknowledged. Defaulting to granted matches what the
			// client asked for; defaulting an explicit-consent scope to acknowledged
			// would defeat the point of asking.
			selected = Object.fromEntries(req.scopes.map((s) => [s.scope, true]));
			acknowledged = Object.fromEntries(req.scopes.map((s) => [s.scope, false]));
			phase = 'ready';
		} catch (err) {
			applyLoadError(err);
		}
	}

	function applyLoadError(err: unknown) {
		if (err instanceof ApiError && err.needsSignIn) {
			phase = 'anonymous';
			return;
		}
		if (err instanceof ApiError && err.code === 'not_found') {
			detail = '这个授权请求已过期，或不属于当前浏览器。请回到应用里重新发起一次。';
			phase = 'gone';
			return;
		}
		detail = err instanceof Error ? err.message : String(err);
		phase = 'failed';
	}

	const granted = $derived(
		request ? request.scopes.filter((s) => selected[s.scope]).map((s) => s.scope) : []
	);
	// Only requirements whose scopes are still selected block approval. Unchecking
	// the game scope is a real decision: the player is choosing not to grant it,
	// so they should not be sent to bind a source that decision made unnecessary.
	const unmetBindings = $derived(
		missing.filter((m) => m.scopes.some((scope) => selected[scope]))
	);
	const unacknowledged = $derived(
		request
			? request.scopes.filter((s) => s.explicit_consent && selected[s.scope] && !acknowledged[s.scope])
			: []
	);
	const canApprove = $derived(
		granted.length > 0 && unmetBindings.length === 0 && unacknowledged.length === 0 && busy === null
	);

	async function decide(decision: 'approve' | 'deny') {
		if (!request) return;
		busy = decision;
		actionError = '';
		try {
			const result = await api.decideAuthorizationRequest(request.id, request.csrf_token, {
				decision,
				scopes: decision === 'approve' ? granted : undefined,
				explicit:
					decision === 'approve'
						? request.scopes
								.filter((s) => s.explicit_consent && acknowledged[s.scope])
								.map((s) => s.scope)
						: undefined
			});
			// Navigate to the string the server returned, verbatim. It was built and
			// validated against the client's registered redirect URIs on the server,
			// and this page must never assemble that URL itself — doing so is how a
			// redirect validation bug becomes an open redirect.
			window.location.assign(result.redirect_to);
		} catch (err) {
			busy = null;
			if (err instanceof ApiError && err.needsSignIn) {
				phase = 'anonymous';
				return;
			}
			if (err instanceof ApiError && err.code === 'not_found') {
				detail = '这个授权请求已过期。请回到应用里重新发起一次。';
				phase = 'gone';
				return;
			}
			if (err instanceof ApiError && err.code === 'explicit_consent_required') {
				actionError = '有一个需要单独确认的权限没有被勾选。请逐项确认，或取消它。';
				return;
			}
			actionError = err instanceof Error ? err.message : String(err);
		}
	}
</script>

<h1 class="text-lg font-semibold">授权请求</h1>

{#if phase === 'loading'}
	<p class="mt-4 text-sm text-ink-muted">正在读取授权请求…</p>
{:else if phase === 'anonymous'}
	<div class="mt-4 flex flex-col gap-4">
		<Alert tone="warn" title="需要先登录">登录后才能看到这个授权请求。</Alert>
		<SignIn />
	</div>
{:else if phase === 'gone'}
	<div class="mt-4">
		<Alert tone="warn" title="这个授权请求不可用">{detail}</Alert>
	</div>
{:else if phase === 'failed'}
	<div class="mt-4">
		<Alert tone="danger" title="读取失败">{detail}</Alert>
	</div>
{:else if request}
	<p class="mt-1 text-sm text-ink-muted">
		<strong class="font-medium text-ink">{request.client.name}</strong> 请求访问你的 Re0Auth 账号。
	</p>

	{#if unmetBindings.length > 0}
		<!--
			Progressive binding: the scopes on this screen cannot be served until the
			player has connected the sources below, so say that before asking for
			consent. The server decides this list and builds each bind URL; the page only
			navigates to it.
		-->
		<Alert tone="warn" title="需要先连接数据源">
			这些权限对应游戏数据，需要你先在数据源那边登录一次。连接完成后会回到这里，继续授权。
		</Alert>
		<Card class="mt-3">
			<ul class="divide-y divide-line">
				{#each unmetBindings as m (m.game + '/' + m.source)}
					<li class="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
						<div class="min-w-0">
							<p class="text-sm font-medium">{m.display_name}</p>
							<p class="mt-0.5 font-mono text-xs text-ink-faint">{m.game}/{m.source}</p>
							<p class="mt-1 text-xs text-ink-muted">{m.scopes.join(' · ')}</p>
						</div>
						<Button variant="primary" onclick={() => window.location.assign(m.bind_url)}
							>连接</Button
						>
					</li>
				{/each}
			</ul>
		</Card>
	{/if}

	<Card class="mt-4">
		<div class="border-b border-line px-4 py-3">
			<p class="text-sm font-medium">该应用将获得以下权限</p>
			<p class="mt-0.5 text-xs text-ink-faint">
				取消勾选即可缩小范围。至少保留一项，否则请直接拒绝。
			</p>
		</div>
		<ScopeList
			scopes={request.scopes}
			{selected}
			{acknowledged}
			onToggle={(scope, on) => (selected = { ...selected, [scope]: on })}
			onAcknowledge={(scope, on) => (acknowledged = { ...acknowledged, [scope]: on })}
		/>
		<div class="flex flex-col gap-3 border-t border-line px-4 py-3">
			{#if actionError}
				<Alert tone="danger" title="没有完成">{actionError}</Alert>
			{:else if unacknowledged.length > 0}
				<p class="text-xs text-danger">有权限需要单独确认后才能继续。</p>
			{:else if unmetBindings.length > 0}
				<p class="text-xs text-danger">请先连接上面列出的数据源，再继续授权。</p>
			{:else if granted.length === 0}
				<p class="text-xs text-ink-muted">你没有勾选任何权限。请至少保留一项，或拒绝这次请求。</p>
			{/if}
			<div class="flex flex-wrap items-center justify-end gap-2">
				<Button variant="secondary" loading={busy === 'deny'} disabled={busy !== null} onclick={() => decide('deny')}>
					拒绝
				</Button>
				<Button variant="primary" loading={busy === 'approve'} disabled={!canApprove} onclick={() => decide('approve')}>
					同意并继续
				</Button>
			</div>
		</div>
	</Card>

	<dl class="mt-4 space-y-1 text-xs text-ink-faint">
		<div class="flex gap-2">
			<dt class="shrink-0">应用标识</dt>
			<dd class="font-mono">{request.client.id}</dd>
		</div>
		<div class="flex gap-2">
			<dt class="shrink-0">授权请求</dt>
			<dd class="font-mono">{request.id}</dd>
		</div>
	</dl>

	<p class="mt-4 text-xs text-ink-faint">
		应用名称由 Re0Auth 登记，应用自己无法更改它。Re0Auth 不会把你的上游凭据交给这个应用——
		它拿到的是有范围限制、可撤销的短期令牌。连接数据源让你在数据源那边登录，凭据留在数据源自己手里。
	</p>
{/if}
