<script lang="ts">
	import { onMount } from 'svelte';
	import { fade, fly } from 'svelte/transition';
	import { quartOut } from 'svelte/easing';
	import { base } from '$app/paths';
	import { page } from '$app/state';
	import { api, ApiError, type IDPProvider, type Session } from '$lib/api';
	import { messageOf } from '$lib/errors';
	import { focusFirstControl, restoreFocus } from '$lib/a11y';
	import SignIn from '$lib/components/SignIn.svelte';
	import Alert from '$lib/components/ui/Alert.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import Card from '$lib/components/ui/Card.svelte';
	import CopyValue from '$lib/components/ui/CopyValue.svelte';

	type Phase = 'loading' | 'anonymous' | 'signed_in' | 'failed';

	let phase = $state<Phase>('loading');
	let session = $state<Session | null>(null);
	let providers = $state<IDPProvider[]>([]);
	let detail = $state('');
	let signingOut = $state(false);
	let exporting = $state(false);
	let deleting = $state(false);
	let confirmingDelete = $state(false);
	let deletionDone = $state(false);
	// A login or identity operation that failed reports here rather than through
	// `phase`: it must not throw the whole page away, and it has to be visible to a
	// visitor who is still anonymous, which is exactly the state a denied login
	// leaves them in.
	let authError = $state('');
	let confirmingUnlink = $state<string | null>(null);
	let unlinking = $state<string | null>(null);
	let linking = $state<string | null>(null);

	onMount(async () => {
		// A failed login or link comes back as ?error=... on the return URL. Read it
		// before probing the session: a denied *login* leaves the visitor anonymous,
		// and the reason must still be shown to them.
		const error = new URLSearchParams(window.location.search).get('error');
		if (error) authError = authErrorMessage(error);

		try {
			session = await api.currentSession();
			phase = 'signed_in';
			// The provider list is for the "link another identity" buttons. A failure
			// to load it must not make the account page unusable.
			providers = (await api.listIDPProviders().catch(() => ({ data: [] }))).data;
		} catch (err) {
			// 401 is not a failure here: it is the ordinary state of a visitor.
			if (err instanceof ApiError && err.needsSignIn) {
				phase = 'anonymous';
				return;
			}
			detail = messageOf(err);
			phase = 'failed';
		}
	});

	// authErrorMessage turns the code the login plane redirected back with into
	// something a person can act on. Login and linking share it because they share
	// the return URL.
	function authErrorMessage(code: string): string {
		switch (code) {
			case 'access_denied':
				return '登录已取消，或未获得授权。';
			case 'provider_unavailable':
				return '该登录方式暂时不可用，请稍后再试。';
			case 'identity_taken':
				return '这个身份已经绑定到另一个 Re0Auth 账号了。请先登录那个账号解绑，再回来绑定。';
			case 'not_signed_in':
				return '登录状态已过期，请重新登录。';
			case 'signup_failed':
			case 'link_failed':
			case 'identity_failed':
			case 'exchange_failed':
				return '登录没有完成，请重试。';
			default:
				return `登录没有完成（${code}）。`;
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
			if (err instanceof ApiError && err.needsSignIn) {
				// The session was already gone; that is the outcome the button asked
				// for, so show the signed-out page rather than an error.
				session = null;
				phase = 'anonymous';
				return;
			}
			detail = messageOf(err);
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
		authError = '';
		try {
			await api.unlinkIdentity(id, session.csrf_token);
			// Re-read rather than splice: the server may have re-nominated the
			// display primary, and the page must show what the server says.
			session = await api.currentSession();
			confirmingUnlink = null;
		} catch (err) {
			if (err instanceof ApiError && err.needsSignIn) {
				session = null;
				phase = 'anonymous';
				return;
			}
			authError = messageOf(err);
		} finally {
			unlinking = null;
		}
	}

	// Cancelling hands focus back to the 解绑 button for this identity. It is found by
	// selector because the confirmation re-creates it, so a cached node would be stale.
	function cancelUnlink(id: string) {
		confirmingUnlink = null;
		void restoreFocus(`[data-unlink="${id}"]`);
	}

	// Linking is the opposite of signing in: it adds an identity to the account
	// already signed in, instead of creating or entering one.
	function link(provider: IDPProvider) {
		linking = provider.id;
		const url = new URL(provider.start_url, window.location.origin);
		url.searchParams.set('mode', 'link');
		url.searchParams.set('return_to', `${base}/`);
		window.location.assign(url.toString());
	}

	// The data-protection half of the account page: what Re0Auth holds, and the
	// way to take it away. Both go through the same session-scoped API the rest of
	// the page uses; the download is a local blob, not a second server endpoint.
	async function exportData() {
		if (!session) return;
		exporting = true;
		authError = '';
		try {
			const data = await api.exportAccount();
			const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = `re0auth-account-${data.profile.user_id}.json`;
			a.click();
			URL.revokeObjectURL(url);
		} catch (err) {
			if (err instanceof ApiError && err.needsSignIn) {
				session = null;
				phase = 'anonymous';
				return;
			}
			authError = messageOf(err);
		} finally {
			exporting = false;
		}
	}

	async function deleteAccount() {
		if (!session) return;
		deleting = true;
		authError = '';
		try {
			await api.deleteAccount(session.csrf_token);
			// The session is gone server-side; show the signed-out page with a
			// closing statement rather than a silent disappearance.
			session = null;
			confirmingDelete = false;
			phase = 'anonymous';
			deletionDone = true;
		} catch (err) {
			if (err instanceof ApiError && err.needsSignIn) {
				session = null;
				phase = 'anonymous';
				return;
			}
			authError = messageOf(err);
		} finally {
			deleting = false;
		}
	}</script>

<svelte:head>
	<title>账号 · Re0Auth</title>
</svelte:head>

<h1 class="text-page font-semibold text-balance">你的 Re0Auth 账号</h1>

<!--
	Escape closes an open confirmation from anywhere on the page, the way a keyboard
	user expects a temporary surface to behave, rather than only while focus happens
	to be inside it. Guarded on the state so it cannot steal focus when nothing is open.
-->
<svelte:window
	onkeydown={(e) => {
		if (e.key === 'Escape' && confirmingUnlink !== null) cancelUnlink(confirmingUnlink);
	}}
/>

{#if phase === 'loading'}
	<p class="mt-4 flex items-center gap-2 text-sm text-ink-muted">
		<span
			class="spinner size-3.5 shrink-0 rounded-full border-2 border-current border-t-transparent"
			aria-hidden="true"
		></span>
		正在读取你的账号…
	</p>
{:else if phase === 'failed'}
	<p class="mt-4 text-sm text-danger">{detail}</p>
{:else if phase === 'anonymous'}
	{#if deletionDone}
		<div class="mt-4">
			<Alert tone="info" title="账号已删除">这个账号的数据已被清除，之后可以重新注册。</Alert>
		</div>
	{/if}
	{#if authError}
		<div class="mt-4">
			<Alert tone="danger" title="登录没有完成">{authError}</Alert>
		</div>
	{/if}
	<p class="mt-4 text-sm text-ink-muted">用外部账号登录，首次登录即注册。</p>
	<div class="mt-4">
		<SignIn returnTo={`${page.url.pathname}${page.url.search}`} />
	</div>
{:else if session}
	{#if authError}
		<div class="mt-4">
			<Alert tone="danger" title="身份操作没有完成">{authError}</Alert>
		</div>
	{/if}
	<!--
		One column again now that the two nav cards are gone. Composition follows
		content: a two-column grid existed to hold the identity card beside the two
		"manage" shortcuts, and with the shortcuts in the header nav there is nothing
		left to put in the second column.
	-->
	<div class="mt-4 flex flex-col gap-4">
		<Card>
			<div class="border-b border-line px-4 py-3">
				<p class="text-xs font-medium text-ink-faint">账号 ID</p>
				<div class="mt-0.5 flex items-center gap-1">
					<p class="font-mono text-sm break-all">{session.user_id}</p>
					<CopyValue value={session.user_id} label="账号 ID" />
				</div>
			</div>
			<ul class="divide-y divide-line">
				{#each session.identities as identity (identity.id)}
					<li class="flex flex-wrap items-center gap-3 px-4 py-3">
						<!--
							A monogram, not the provider's avatar URL. The CSP only allows
							same-origin images (which stops third-party tracking), so an
							external avatar rendered as a broken box; a letter is both
							always visible and always offline.
						-->
						<span
							class="grid size-8 shrink-0 place-items-center rounded-full border border-line bg-surface-sunken text-xs font-semibold"
							aria-hidden="true"
						>
							{identity.display_name.trim().charAt(0).toUpperCase() || '?'}
						</span>
						<div class="min-w-0 flex-1">
							<p class="truncate text-base font-medium">{identity.display_name}</p>
							<p class="truncate text-xs text-ink-muted">
								{identity.provider}
								{#if identity.email}· {identity.email}{/if}
							</p>
						</div>
						{#if confirmingUnlink === identity.id}
							<!--
								focusFirstControl lands on 取消 rather than 确认解绑, so a stray Enter
								cannot unlink anything. The entrance is short and the exit shorter, on
								the same curve the rest of the interface uses.
							-->
							<div
								class="flex flex-wrap items-center gap-2"
								use:focusFirstControl
								in:fly={{ y: -4, duration: 200, easing: quartOut }}
								out:fade={{ duration: 140 }}
							>
								<span class="text-sm text-danger">解绑后这个身份不能再登录本账号。</span>
								<Button variant="quiet" onclick={() => cancelUnlink(identity.id)}>取消</Button>
								<Button
									variant="danger"
									loading={unlinking === identity.id}
									onclick={() => unlink(identity.id)}
									>确认解绑</Button
								>
							</div>
						{:else if session.identities.length > 1}
							<Button
								variant="quiet"
								data-unlink={identity.id}
								onclick={() => (confirmingUnlink = identity.id)}>解绑</Button
							>
						{/if}
					</li>
				{/each}
			</ul>
			{#if providers.length > 0}
				<div class="flex flex-col gap-2 border-t border-line px-4 py-3">
					<div class="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
						{#each providers as p (p.id)}
							<Button
								variant="secondary"
								class="w-full sm:w-auto"
								loading={linking === p.id}
								onclick={() => link(p)}>绑定 {p.display_name}</Button
							>
						{/each}
					</div>
				</div>
			{/if}
			<div class="flex flex-col gap-2 border-t border-line px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
				<p class="text-xs text-ink-muted">
					退出只结束这个浏览器的会话；已经授权的应用仍然可以访问你的数据。
				</p>
				<Button
					variant="secondary"
					class="w-full sm:w-auto"
					loading={signingOut}
					onclick={signOut}>退出登录</Button
				>
			</div>
		</Card>

		<!--
			Data protection lives beside identity management, not buried in a settings
			page: export and erasure are the two rights that have to be reachable
			without reading documentation. Erasure is irreversible, so it is behind a
			second step and names exactly what it does.
		-->
		<Card>
			<div class="border-b border-line px-4 py-3">
				<p class="text-sm font-medium">数据与隐私</p>
			</div>
			<div class="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
				<p class="text-xs text-ink-muted">导出一份账号数据的 JSON 副本。不包含任何凭据。</p>
				<Button variant="secondary" class="w-full sm:w-auto" loading={exporting} onclick={exportData}>
					导出我的数据
				</Button>
			</div>
			{#if confirmingDelete}
				<div
					class="flex flex-col gap-3 border-t border-danger/40 bg-danger-soft px-4 py-3 contrast-more:border-danger sm:flex-row sm:items-center sm:justify-between"
					use:focusFirstControl
				>
					<p class="text-sm text-pretty">
						删除会清除账号、身份、数据源连接与已发出的令牌，且无法撤销。
					</p>
					<div class="flex flex-wrap gap-2">
						<Button variant="quiet" onclick={() => (confirmingDelete = false)}>取消</Button>
						<Button variant="danger" loading={deleting} onclick={deleteAccount}>确认删除账号</Button>
					</div>
				</div>
			{:else}
				<div class="flex flex-col gap-3 border-t border-line px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
					<p class="text-xs text-ink-muted">永久删除这个账号及其全部数据。</p>
					<Button variant="danger" class="w-full sm:w-auto" onclick={() => (confirmingDelete = true)}>
						删除账号
					</Button>
				</div>
			{/if}
		</Card>
	</div>
{/if}
