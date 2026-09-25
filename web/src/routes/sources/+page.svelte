<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { fade, fly } from 'svelte/transition';
	import { quartOut } from 'svelte/easing';
	import { base } from '$app/paths';
	import {
		api,
		ApiError,
		type Binding,
		type FederationSource,
		type UpstreamRevocation
	} from '$lib/api';
	import { messageOf } from '$lib/errors';
	import { focusFirstControl, restoreFocus } from '$lib/a11y';
	import SignIn from '$lib/components/SignIn.svelte';
	import Alert from '$lib/components/ui/Alert.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import Card from '$lib/components/ui/Card.svelte';

	type Phase = 'loading' | 'anonymous' | 'ready' | 'failed';

	let phase = $state<Phase>('loading');
	let bindings = $state<Binding[]>([]);
	let available = $state<FederationSource[]>([]);
	let csrf = $state('');
	let detail = $state('');
	let actionError = $state('');
	let outcome = $state<{ source: string; upstream: UpstreamRevocation; error?: string } | null>(null);
	let confirming = $state<string | null>(null);
	// Cascade gets its own confirmation state, separate from disconnecting, because
	// it is a different act with a different consequence. Sharing one would make the
	// louder action one click away from the quieter one.
	let cascadeConfirming = $state<string | null>(null);
	let working = $state<string | null>(null);

	onMount(load);

	async function load() {
		// A failed bind comes back as ?error=bind_failed on the return URL the
		// server built. Surfacing it is why the flow bothers to carry it.
		const bindError = new URLSearchParams(window.location.search).get('error');

		try {
			const [session, mine, all] = await Promise.all([
				api.currentSession(),
				api.listBindings(),
				api.listAllSources()
			]);
			csrf = session.csrf_token;
			bindings = mine.data;
			available = all.data;
			phase = 'ready';
			if (bindError) {
				actionError = '连接没有完成，数据源可能拒绝了授权或被取消。';
			}
		} catch (err) {
			if (err instanceof ApiError && err.needsSignIn) {
				phase = 'anonymous';
				return;
			}
			detail = messageOf(err);
			phase = 'failed';
		}
	}

	const key = (s: { game: string; source: string }) => `${s.game}/${s.source}`;

	// What is not connected yet. A retired source is left out: offering a button
	// that the server will refuse is worse than not offering it.
	const connectable = $derived(
		available.filter(
			(src) => src.status !== 'retired' && !bindings.some((b) => key(b) === key(src))
		)
	);

	function connect(src: FederationSource) {
		// A navigation, not a fetch: this leaves for the source's own authorization
		// page and comes back. return_to must be a same-origin relative path, which
		// the server enforces.
		const query = new URLSearchParams({
			game: src.game,
			source: src.source,
			return_to: `${base}/sources`
		});
		window.location.assign(`/bind?${query}`);
	}

	async function disconnect(binding: Binding) {
		const id = key(binding);
		working = id;
		actionError = '';
		outcome = null;
		try {
			const result = await api.unbindSource(binding.game, binding.source, csrf);
			bindings = bindings.filter((b) => key(b) !== id);
			confirming = null;
			// The source's half of the job is reported, not assumed. "Removed here,
			// still live there" is a different thing to tell someone than "done".
			if (result.upstream !== 'nothing') {
				outcome = { source: binding.display_name, upstream: result.upstream, error: result.upstream_error };
			}
		} catch (err) {
			if (err instanceof ApiError && err.needsSignIn) {
				phase = 'anonymous';
				return;
			}
			actionError = messageOf(err);
		} finally {
			working = null;
		}
	}

	const upstreamCopy: Record<UpstreamRevocation, { tone: 'info' | 'warn'; title: string; body: string }> = {
		done: {
			tone: 'info',
			title: '已断开',
			body: '数据源也已经撤销了它签发的凭据。'
		},
		unsupported: {
			tone: 'warn',
			title: '已断开，但上游仍有效',
			body: '该数据源声明其凭据长期有效、无法按客户端撤销。Re0Auth 这边已经断开，但你在这个数据源的登录仍然存在。'
		},
		unavailable: {
			tone: 'warn',
			title: '已断开，但没能通知数据源',
			body: 'Re0Auth 这边已经断开，但数据源没有响应撤销请求，它签发的凭据可能仍然有效。'
		},
		nothing: { tone: 'info', title: '已断开', body: '' }
	};

	// Cascade has exactly one outcome, because a failure is an error rather than a
	// result: nothing is removed unless the source confirmed, so there is no
	// "partly done" to report.
	async function cascade(binding: Binding) {
		const id = key(binding);
		working = id;
		actionError = '';
		outcome = null;
		try {
			await api.cascadeRevoke(binding.game, binding.source, csrf);
			bindings = bindings.filter((b) => key(b) !== id);
			cascadeConfirming = null;
			outcome = { source: binding.display_name, upstream: 'done' };
		} catch (err) {
			if (err instanceof ApiError && err.needsSignIn) {
				phase = 'anonymous';
				return;
			}
			// The binding is deliberately still there, so the wording must not sound
			// like a partial success.
			actionError =
				'没有登出：' +
				(messageOf(err)) +
				'。你的数据源连接仍然是连接着的，可以重试。';
		} finally {
			working = null;
		}
	}

	// Backing out of either confirmation hands focus back to the button that opened it,
	// found by selector because the confirmation re-creates that button.
	function cancelDisconnect(id: string) {
		confirming = null;
		void restoreFocus(`[data-disconnect="${id}"]`);
	}

	function cancelCascade(id: string) {
		cascadeConfirming = null;
		void restoreFocus(`[data-cascade="${id}"]`);
	}

	function formatDate(iso: string): string {
		const date = new Date(iso);
		return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
	}
</script>

<svelte:head>
	<title>数据源连接 · Re0Auth</title>
</svelte:head>

<h1 class="text-page font-semibold text-balance">数据源连接</h1>

<!--
	Escape closes whichever confirmation is open, guarded on the state so it cannot
	steal focus when neither is. Both are checkable here because they are independent
	states: the cascade panel and the disconnect prompt can be open at once.
-->
<svelte:window
	onkeydown={(e) => {
		if (e.key !== 'Escape') return;
		if (confirming !== null) cancelDisconnect(confirming);
		if (cascadeConfirming !== null) cancelCascade(cascadeConfirming);
	}}
/>

{#if phase === 'loading'}
	<p class="mt-4 flex items-center gap-2 text-sm text-ink-muted">
		<span
			class="spinner size-3.5 shrink-0 rounded-full border-2 border-current border-t-transparent"
			aria-hidden="true"
		></span>
		正在读取数据源连接…
	</p>
{:else if phase === 'anonymous'}
	<div class="mt-4 flex flex-col gap-4">
		<Alert tone="warn" title="需要先登录">登录后才能管理数据源连接。</Alert>
		<SignIn returnTo={`${page.url.pathname}${page.url.search}`} />
	</div>
{:else if phase === 'failed'}
	<p class="mt-4 text-sm text-danger">{detail}</p>
{:else}
	<!--
		Two columns at lg. Connected carries the consequences and connectable offers more,
		so side by side they read as the pair they are instead of one tall list with an
		empty right half. Auto-placement does the work: the sections are pinned to a
		column, and the page-level alerts and the footnote span both, so the pairing holds
		whether or not an alert is present. Below lg it is the same single stacked column.
	-->
	<div class="mt-4 flex flex-col gap-4 lg:grid lg:grid-cols-2 lg:items-start lg:gap-6">
		{#if actionError}
			<Alert tone="danger" title="没有完成" class="lg:col-span-2">{actionError}</Alert>
		{/if}
		{#if outcome}
			<Alert tone={upstreamCopy[outcome.upstream].tone} title="{outcome.source}：{upstreamCopy[outcome.upstream].title}" class="lg:col-span-2">
				{upstreamCopy[outcome.upstream].body}
				{#if outcome.error}
					<span class="font-mono text-xs">（{outcome.error}）</span>
				{/if}
			</Alert>
		{/if}

		<!-- Connected first: this is the part with consequences. -->
		<section class="lg:col-start-1">
			<h2 class="text-section font-semibold text-balance">已连接</h2>
			{#if bindings.length === 0}
				<Card class="mt-2">
					<p class="px-4 py-6 text-center text-base text-ink-muted">还没有连接数据源哦~</p>
				</Card>
			{:else}
				<div class="mt-2 flex flex-col gap-3">
					{#each bindings as binding (key(binding))}
						<!--
							The data attribute names which source this card is about. It is real
							markup — a card that cannot be addressed is hard to reason about — and it
							is also what lets a test assert something *about one source* rather than
							about the page as a whole.
						-->
						<Card data-binding={key(binding)}>
							<div class="flex flex-wrap items-start justify-between gap-3 border-b border-line px-4 py-3">
								<div class="min-w-0">
									<p class="text-base font-medium">{binding.display_name}</p>
									<p class="mt-0.5 font-mono text-xs break-all text-ink-faint">{key(binding)}</p>
								</div>
								<div class="flex flex-wrap gap-2">
									{#if binding.status === 'degraded'}
										<Badge tone="warn" attention>降级</Badge>
									{:else if binding.status === 'retired'}
										<Badge tone="danger" attention>已下线</Badge>
									{/if}
									<Badge
										tone={binding.token_class === 'long_lived' ? 'warn' : 'neutral'}
										attention={binding.token_class === 'long_lived'}
									>
										{binding.token_class === 'long_lived' ? '不可远程撤销' : '可远程撤销'}
									</Badge>
									{#if binding.has_refresh}
										<Badge tone="neutral">可自动续期</Badge>
									{/if}
								</div>
							</div>

							{#if !binding.configured}
								<p class="border-b border-line px-4 py-2 text-sm text-pretty text-warn">
									本部署已移除这个数据源，连接仍可断开。
								</p>
							{/if}

							{#if cascadeConfirming === key(binding)}
								<!--
									The loud one. It gets its own block, its own wording and its own verb in
									the button, so it cannot be mistaken for disconnecting — a different act
									with a different consequence, and one you cannot undo by connecting again.
								-->
								<div
									class="w-full border-t border-danger/40 bg-danger-soft px-4 py-3 contrast-more:border-danger"
									use:focusFirstControl
									in:fly={{ y: -4, duration: 200, easing: quartOut }}
									out:fade={{ duration: 140 }}
								>
									<p class="text-base font-medium text-danger">在数据源端登出全部设备</p>
									<p class="mt-1 text-base text-pretty">
										包括你现在正在用的这台，之后需要重新登录。
									</p>
									<div class="mt-3 flex flex-col gap-2 sm:flex-row sm:flex-wrap sm:items-center">
										<Button
											variant="quiet"
											class="w-full sm:w-auto"
											onclick={() => cancelCascade(key(binding))}>取消</Button
										>
										<Button
											variant="danger"
											class="w-full sm:w-auto"
											loading={working === key(binding)}
											onclick={() => cascade(binding)}
										>
											我明白，登出全部设备
										</Button>
									</div>
								</div>
							{/if}

							<div class="flex flex-wrap items-center justify-between gap-3 border-t border-line px-4 py-3">
								<p class="text-xs tabular-nums text-ink-faint">
									{binding.expiry ? `当前凭据最迟 ${formatDate(binding.expiry)} 失效` : '凭据没有公开的失效时间'}
								</p>
								{#if confirming === key(binding)}
									<!--
										focusFirstControl lands on 取消, so a stray Enter cannot disconnect.
										The entrance is short and the exit shorter, on the shared curve.
									-->
									<div
										class="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:flex-wrap sm:items-center"
										use:focusFirstControl
										in:fly={{ y: -4, duration: 200, easing: quartOut }}
										out:fade={{ duration: 140 }}
									>
										<span class="text-sm text-ink-muted">Re0Auth 会立即断开，并尝试通知数据源撤销。</span>
										<Button
											variant="quiet"
											class="w-full sm:w-auto"
											onclick={() => cancelDisconnect(key(binding))}>取消</Button
										>
										<Button
											variant="danger"
											class="w-full sm:w-auto"
											loading={working === key(binding)}
											onclick={() => disconnect(binding)}
										>
											确认断开
										</Button>
									</div>
								{:else}
									<div class="flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:flex-wrap sm:items-center">
										<!-- Offered only where the source advertised it, so there is no
										     button here that would fail. -->
										{#if binding.cascade_revocation}
											<Button
												variant="quiet"
												class="w-full sm:w-auto"
												data-cascade={key(binding)}
												onclick={() => (cascadeConfirming = key(binding))}
											>
												登出全部设备
											</Button>
										{/if}
										<Button
											variant="secondary"
											class="w-full sm:w-auto"
											data-disconnect={key(binding)}
											onclick={() => (confirming = key(binding))}>断开连接</Button
										>
									</div>
								{/if}
							</div>
						</Card>
					{/each}
				</div>
			{/if}
		</section>

		<section class="lg:col-start-2">
			<h2 class="text-section font-semibold text-balance">可连接</h2>
			{#if connectable.length === 0}
				<p class="mt-2 text-base text-ink-muted">没有可连接的数据源。</p>
			{:else}
				<div class="mt-2 flex flex-col gap-3">
					{#each connectable as src (key(src))}
						<Card data-source={key(src)}>
							<div class="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
								<div class="min-w-0">
									<p class="text-base font-medium">{src.display_name}</p>
									<p class="mt-0.5 font-mono text-xs break-all text-ink-faint">{key(src)}</p>
								</div>
								<div class="flex flex-wrap items-center gap-2">
									{#if src.status === 'degraded'}
										<Badge tone="warn" attention>降级</Badge>
									{/if}
									<Badge
										tone={src.token_class === 'long_lived' ? 'warn' : 'neutral'}
										attention={src.token_class === 'long_lived'}
									>
										{src.token_class === 'long_lived' ? '不可远程撤销' : '可远程撤销'}
									</Badge>
									<Button variant="primary" class="w-full sm:w-auto" onclick={() => connect(src)}>连接</Button>
								</div>
							</div>
						</Card>
					{/each}
				</div>
			{/if}
		</section>
	</div>
{/if}
