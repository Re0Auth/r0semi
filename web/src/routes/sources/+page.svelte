<script lang="ts">
	import { onMount } from 'svelte';
	import { base } from '$app/paths';
	import {
		api,
		ApiError,
		type Binding,
		type FederationSource,
		type UpstreamRevocation
	} from '$lib/api';
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
			detail = err instanceof Error ? err.message : String(err);
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
			actionError = err instanceof Error ? err.message : String(err);
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
				(err instanceof Error ? err.message : String(err)) +
				'。你的数据源连接仍然是连接着的，可以重试。';
		} finally {
			working = null;
		}
	}

	function formatDate(iso: string): string {
		const date = new Date(iso);
		return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
	}
</script>

<h1 class="text-lg font-semibold">数据源连接</h1>
<p class="mt-1 text-sm text-ink-muted">
	Re0Auth 只有先连接到数据源，才能替你读取那个游戏的数据。连接时你是在数据源那边完成登录，
	Re0Auth 拿到的只是它签发的令牌——令牌始终存在 Re0Auth 的保险库里，不会交给任何下游应用。
</p>

{#if phase === 'loading'}
	<p class="mt-4 text-sm text-ink-muted">正在读取…</p>
{:else if phase === 'anonymous'}
	<div class="mt-4 flex flex-col gap-4">
		<Alert tone="warn" title="需要先登录">登录后才能管理数据源连接。</Alert>
		<SignIn />
	</div>
{:else if phase === 'failed'}
	<p class="mt-4 text-sm text-danger">{detail}</p>
{:else}
	<div class="mt-4 flex flex-col gap-4">
		{#if actionError}
			<Alert tone="danger" title="没有完成">{actionError}</Alert>
		{/if}
		{#if outcome}
			<Alert tone={upstreamCopy[outcome.upstream].tone} title="{outcome.source}：{upstreamCopy[outcome.upstream].title}">
				{upstreamCopy[outcome.upstream].body}
				{#if outcome.error}
					<span class="font-mono text-xs">（{outcome.error}）</span>
				{/if}
			</Alert>
		{/if}

		<!-- Connected first: this is the part with consequences. -->
		<section>
			<h2 class="text-sm font-semibold">已连接</h2>
			{#if bindings.length === 0}
				<Card class="mt-2">
					<p class="px-4 py-6 text-center text-sm text-ink-muted">还没有连接任何数据源。</p>
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
									<p class="font-medium">{binding.display_name}</p>
									<p class="mt-0.5 font-mono text-xs text-ink-faint">{key(binding)}</p>
								</div>
								<div class="flex flex-wrap gap-2">
									{#if binding.status === 'degraded'}
										<Badge tone="warn">降级</Badge>
									{:else if binding.status === 'retired'}
										<Badge tone="danger">已下线</Badge>
									{/if}
									<Badge tone={binding.token_class === 'long_lived' ? 'warn' : 'neutral'}>
										{binding.token_class === 'long_lived' ? '长期有效凭据' : '可撤销凭据'}
									</Badge>
									{#if binding.has_refresh}
										<Badge tone="neutral">可自动续期</Badge>
									{/if}
								</div>
							</div>

							{#if !binding.configured}
								<p class="border-b border-line px-4 py-2 text-xs text-warn">
									这个数据源已不在本部署的配置中。连接仍然存在，也可以断开，只是已经没有东西可以描述它了。
								</p>
							{/if}

							{#if cascadeConfirming === key(binding)}
								<!--
									The loud one. It gets its own block, its own wording and its own verb in
									the button, so it cannot be mistaken for disconnecting — a different act
									with a different consequence, and one you cannot undo by connecting again.
								-->
								<div class="border-t border-danger/40 bg-danger-soft px-4 py-3">
									<p class="text-sm font-medium text-danger">在数据源端登出全部设备</p>
									<p class="mt-1 text-sm">
										数据源会作废它签发的登录凭据，因此<strong>你在这个数据源上的所有设备都会被登出</strong>，
										包括你现在正在用的这台。你需要重新登录。
									</p>
									<p class="mt-1 text-xs text-ink-muted">
										Re0Auth 自己做不到这件事，只能请求数据源执行。数据源没有响应的话，什么都不会变——
										连接会保留，可以重试。
									</p>
									<div class="mt-3 flex flex-wrap items-center gap-2">
										<Button variant="quiet" onclick={() => (cascadeConfirming = null)}>取消</Button>
										<Button
											variant="danger"
											loading={working === key(binding)}
											onclick={() => cascade(binding)}
										>
											我明白，登出全部设备
										</Button>
									</div>
								</div>
							{/if}

							<div class="flex flex-wrap items-center justify-between gap-3 border-t border-line px-4 py-3">
								<p class="text-xs text-ink-faint">
									{binding.expiry ? `当前凭据最迟 ${formatDate(binding.expiry)} 失效` : '凭据没有公开的失效时间'}
								</p>
								{#if confirming === key(binding)}
									<div class="flex flex-wrap items-center gap-2">
										<span class="text-xs text-ink-muted">Re0Auth 会立即断开，并尝试通知数据源撤销。</span>
										<Button variant="quiet" onclick={() => (confirming = null)}>取消</Button>
										<Button variant="danger" loading={working === key(binding)} onclick={() => disconnect(binding)}>
											确认断开
										</Button>
									</div>
								{:else}
									<div class="flex flex-wrap items-center gap-2">
										<!-- Offered only where the source advertised it, so there is no
										     button here that would fail. -->
										{#if binding.cascade_revocation}
											<Button variant="quiet" onclick={() => (cascadeConfirming = key(binding))}>
												登出全部设备
											</Button>
										{/if}
										<Button variant="secondary" onclick={() => (confirming = key(binding))}>断开连接</Button>
									</div>
								{/if}
							</div>
						</Card>
					{/each}
				</div>
			{/if}
		</section>

		<section>
			<h2 class="text-sm font-semibold">可连接</h2>
			{#if connectable.length === 0}
				<p class="mt-2 text-sm text-ink-muted">本部署没有提供其他可连接的数据源。</p>
			{:else}
				<div class="mt-2 flex flex-col gap-3">
					{#each connectable as src (key(src))}
						<Card data-source={key(src)}>
							<div class="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
								<div class="min-w-0">
									<p class="font-medium">{src.display_name}</p>
									<p class="mt-0.5 font-mono text-xs text-ink-faint">{key(src)}</p>
								</div>
								<div class="flex flex-wrap items-center gap-2">
									{#if src.status === 'degraded'}
										<Badge tone="warn">降级</Badge>
									{/if}
									<Badge tone={src.token_class === 'long_lived' ? 'warn' : 'neutral'}>
										{src.token_class === 'long_lived' ? '长期有效凭据' : '可撤销凭据'}
									</Badge>
									<Button variant="primary" onclick={() => connect(src)}>连接</Button>
								</div>
							</div>
						</Card>
					{/each}
				</div>
			{/if}
		</section>

		<p class="text-xs text-ink-faint">
			断开连接只影响 Re0Auth。它不会作废你在数据源那边的登录——那需要数据源自己执行，
			而且通常会把你所有设备都登出，所以它是一个单独的、写着后果的按钮。
		</p>
	</div>
{/if}
