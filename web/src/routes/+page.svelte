<script lang="ts">
	import { onMount } from 'svelte';
	import { base } from '$app/paths';
	import { api, ApiError, providerLabel, type IDPProvider, type Session } from '$lib/api';
	import SignIn from '$lib/components/SignIn.svelte';
	import Alert from '$lib/components/ui/Alert.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import Card from '$lib/components/ui/Card.svelte';

	type Phase = 'loading' | 'anonymous' | 'signed_in' | 'failed';

	let phase = $state<Phase>('loading');
	let session = $state<Session | null>(null);
	let providers = $state<IDPProvider[]>([]);
	let detail = $state('');
	let signingOut = $state(false);
	// Identity operations report here rather than through `phase`: a failed unlink
	// must not throw the whole account page away.
	let identityError = $state('');
	let confirmingUnlink = $state<string | null>(null);
	let unlinking = $state<string | null>(null);
	let linking = $state<string | null>(null);

	onMount(async () => {
		try {
			session = await api.currentSession();
			phase = 'signed_in';
			// The provider list is for the "link another identity" buttons. A failure
			// to load it must not make the account page unusable.
			providers = (await api.listIDPProviders().catch(() => ({ data: [] }))).data;
			// A link flow that failed comes back as ?error=... on the return URL.
			const error = new URLSearchParams(window.location.search).get('error');
			if (error) identityError = linkErrorMessage(error);
		} catch (err) {
			// 401 is not a failure here: it is the ordinary state of a visitor.
			if (err instanceof ApiError && err.needsSignIn) {
				phase = 'anonymous';
				return;
			}
			detail = err instanceof Error ? err.message : String(err);
			phase = 'failed';
		}
	});

	function linkErrorMessage(code: string): string {
		switch (code) {
			case 'identity_taken':
				return '这个身份已经绑定到另一个 Re0Auth 账号了。请先登录那个账号解绑，再回来绑定。';
			case 'not_signed_in':
				return '登录状态已过期，请重新登录。';
			case 'link_failed':
			case 'identity_failed':
			case 'exchange_failed':
				return '绑定没有完成，请重试。';
			default:
				return `绑定没有完成（${code}）。`;
		}
	}

	async function signOut() {
		if (!session) return;
		signingOut = true;
		try {
			await api.signOut(session.csrf_token);
			session = null;
			phase = 'anonymous';
		} catch (err) {
			detail = err instanceof Error ? err.message : String(err);
			phase = 'failed';
		} finally {
			signingOut = false;
		}
	}

	// Unlinking removes one way to sign in. The last one is refused by the server
	// (I-2), which is also why the button is only offered when another remains.
	async function unlink(id: string) {
		if (!session) return;
		unlinking = id;
		identityError = '';
		try {
			await api.unlinkIdentity(id, session.csrf_token);
			// Re-read rather than splice: the server may have re-nominated the
			// display primary, and the page must show what the server says.
			session = await api.currentSession();
			confirmingUnlink = null;
		} catch (err) {
			identityError = err instanceof Error ? err.message : String(err);
		} finally {
			unlinking = null;
		}
	}

	// Linking is the opposite of signing in: it adds an identity to the account
	// already signed in, instead of creating or entering one.
	function link(provider: IDPProvider) {
		linking = provider.id;
		const url = new URL(provider.start_url, window.location.origin);
		url.searchParams.set('mode', 'link');
		url.searchParams.set('return_to', `${base}/`);
		window.location.assign(url.toString());
	}</script>

<h1 class="text-lg font-semibold">你的 Re0Auth 账号</h1>

{#if phase === 'loading'}
	<p class="mt-4 text-sm text-ink-muted">正在读取…</p>
{:else if phase === 'failed'}
	<p class="mt-4 text-sm text-danger">{detail}</p>
{:else if phase === 'anonymous'}
	<p class="mt-4 text-sm text-ink-muted">
		Re0Auth 不设密码。选择一个身份提供方登录，账号会由它建立——首次登录即注册。
	</p>
	<div class="mt-4">
		<SignIn />
	</div>
{:else if session}
	<div class="mt-4 flex flex-col gap-4">
		{#if identityError}
			<Alert tone="danger" title="身份操作没有完成">{identityError}</Alert>
		{/if}
		<Card>
			<div class="border-b border-line px-4 py-3">
				<p class="text-xs font-medium text-ink-faint">账号 ID</p>
				<p class="mt-0.5 font-mono text-sm">{session.user_id}</p>
				<p class="mt-2 text-xs text-ink-faint">
					这是 Re0Auth 自己的标识，不是任何上游 ID。下游应用只能看到它。
				</p>
			</div>
			<ul class="divide-y divide-line">
				{#each session.identities as identity (identity.id)}
					<li class="flex flex-wrap items-center gap-3 px-4 py-3">
						{#if identity.avatar_url}
							<img
								src={identity.avatar_url}
								alt=""
								width="32"
								height="32"
								class="size-8 rounded-full border border-line"
							/>
						{/if}
						<div class="min-w-0 flex-1">
							<p class="truncate text-sm font-medium">{identity.display_name}</p>
							<p class="truncate text-xs text-ink-muted">
								{identity.provider}
								{#if identity.email}· {identity.email}{/if}
							</p>
						</div>
						{#if confirmingUnlink === identity.id}
							<div class="flex flex-wrap items-center gap-2">
								<span class="text-xs text-danger">解绑后这个身份不能再登录本账号。</span>
								<Button variant="quiet" onclick={() => (confirmingUnlink = null)}>取消</Button>
								<Button
									variant="danger"
									loading={unlinking === identity.id}
									onclick={() => unlink(identity.id)}
									>确认解绑</Button
								>
							</div>
						{:else if session.identities.length > 1}
							<Button variant="quiet" onclick={() => (confirmingUnlink = identity.id)}
								>解绑</Button
							>
						{/if}
					</li>
				{/each}
			</ul>
			{#if providers.length > 0}
				<div class="flex flex-col gap-2 border-t border-line px-4 py-3">
					<p class="text-xs text-ink-faint">
						绑定新身份是把新的 IdP 身份加到当前账号上，不是新建账号。全部门同一等，任意一个都可以登录。
					</p>
					<div class="flex flex-wrap gap-2">
						{#each providers as p (p.id)}
							<Button
								variant="secondary"
								loading={linking === p.id}
								onclick={() => link(p)}>绑定 {providerLabel(p.id)}</Button
							>
						{/each}
					</div>
				</div>
			{/if}
			<div class="flex justify-end border-t border-line px-4 py-3">
				<Button variant="secondary" loading={signingOut} onclick={signOut}>退出登录</Button>
			</div>
		</Card>

		<Card>
			<div class="flex items-center justify-between border-b border-line px-4 py-3">
				<p class="text-sm font-medium">已授权的应用</p>
				<a href="{base}/grants" class="text-xs text-accent underline-offset-4 hover:underline">管理</a>
			</div>
			<p class="px-4 py-3 text-xs text-ink-faint">
				查看哪些应用能以你的身份行动，并随时撤销它们。
			</p>
		</Card>

		<Card>
			<div class="flex items-center justify-between border-b border-line px-4 py-3">
				<p class="text-sm font-medium">数据源连接</p>
				<a href="{base}/sources" class="text-xs text-accent underline-offset-4 hover:underline">管理</a>
			</div>
			<p class="px-4 py-3 text-xs text-ink-faint">
				连接游戏数据源，Re0Auth 才能替你读取那些游戏的数据。
			</p>
		</Card>
	</div>
{/if}
