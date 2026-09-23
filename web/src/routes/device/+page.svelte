<script lang="ts">
	import { onMount } from 'svelte';
	import { api, ApiError, type DevicePending } from '$lib/api';
	import { messageOf } from '$lib/errors';
	import ScopeList from '$lib/components/ScopeList.svelte';
	import SignIn from '$lib/components/SignIn.svelte';
	import Alert from '$lib/components/ui/Alert.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import Card from '$lib/components/ui/Card.svelte';

	type Phase = 'code' | 'anonymous' | 'invalid' | 'pending' | 'done' | 'failed';

	let phase = $state<Phase>('code');
	let code = $state('');
	let pending = $state<DevicePending | null>(null);
	let selected = $state<Record<string, boolean>>({});
	let acknowledged = $state<Record<string, boolean>>({});
	let detail = $state('');
	let actionError = $state('');
	let checking = $state(false);
	let busy = $state<'approve' | 'deny' | null>(null);
	let outcome = $state<'approved' | 'denied' | null>(null);
	let remaining = $state<number | null>(null);

	onMount(() => {
		// verification_uri_complete arrives with the code already attached, which is
		// the whole reason RFC 8628 defines it: the user should not have to retype
		// something they are reading off a television.
		const fromUrl = new URLSearchParams(window.location.search).get('user_code');
		if (fromUrl) {
			code = fromUrl;
			void submit();
		}
	});

	async function submit() {
		const value = code.trim();
		if (!value) return;
		checking = true;
		actionError = '';
		try {
			const res = await api.getDeviceVerification(value);
			if (res.state === 'awaiting_code') {
				phase = 'code';
				return;
			}
			pending = res;
			selected = Object.fromEntries(res.scopes.map((s) => [s.scope, true]));
			acknowledged = Object.fromEntries(res.scopes.map((s) => [s.scope, false]));
			phase = 'pending';
		} catch (err) {
			if (err instanceof ApiError && err.needsSignIn) {
				phase = 'anonymous';
				return;
			}
			if (err instanceof ApiError && err.code === 'not_found') {
				detail = '这个代码无效或已过期。请回到你的设备上重新获取一个。';
				phase = 'invalid';
				return;
			}
			detail = messageOf(err);
			phase = 'failed';
		} finally {
			checking = false;
		}
	}

	// A device code is short-lived, and the user is being asked to make a decision
	// under that clock. Showing it is the difference between "this failed" and
	// "this expired while I was reading".
	$effect(() => {
		if (!pending) return;
		const expiresAt = new Date(pending.expires_at).getTime();
		const tick = () => {
			remaining = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
		};
		tick();
		const timer = setInterval(tick, 1000);
		return () => clearInterval(timer);
	});

	const countdown = $derived(
		remaining === null
			? null
			: `${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, '0')}`
	);

	const granted = $derived(
		pending ? pending.scopes.filter((s) => selected[s.scope]).map((s) => s.scope) : []
	);
	const unacknowledged = $derived(
		pending
			? pending.scopes.filter((s) => s.explicit_consent && selected[s.scope] && !acknowledged[s.scope])
			: []
	);
	const canApprove = $derived(granted.length > 0 && unacknowledged.length === 0 && busy === null);

	async function decide(decision: 'approve' | 'deny') {
		if (!pending) return;
		busy = decision;
		actionError = '';
		try {
			const res = await api.decideDevice(pending.csrf_token, {
				user_code: pending.user_code,
				decision,
				scopes:
					decision === 'approve'
						? pending.scopes.filter((s) => selected[s.scope]).map((s) => s.scope)
						: undefined,
				explicit:
					decision === 'approve'
						? pending.scopes
								.filter((s) => s.explicit_consent && acknowledged[s.scope])
								.map((s) => s.scope)
						: undefined
			});
			outcome = res.state;
			phase = 'done';
		} catch (err) {
			busy = null;
			if (err instanceof ApiError && err.needsSignIn) {
				phase = 'anonymous';
				return;
			}
			if (err instanceof ApiError && err.code === 'not_found') {
				detail = '这个代码已过期。请回到你的设备上重新获取一个。';
				phase = 'invalid';
				return;
			}
			actionError = messageOf(err);
		}
	}
</script>

<h1 class="text-lg font-semibold">设备登录</h1>
<p class="mt-1 text-sm text-ink-muted">输入你的设备上显示的代码，确认这次登录。</p>

{#if phase === 'anonymous'}
	<div class="mt-4 flex flex-col gap-4">
		<Alert tone="warn" title="需要先登录">登录后才能确认设备代码。</Alert>
		<SignIn />
	</div>
{:else if phase === 'invalid'}
	<div class="mt-4 flex flex-col gap-4">
		<Alert tone="warn" title="代码不可用">{detail}</Alert>
		<Button variant="secondary" onclick={() => (phase = 'code')}>换一个代码</Button>
	</div>
{:else if phase === 'failed'}
	<div class="mt-4">
		<Alert tone="danger" title="读取失败">{detail}</Alert>
	</div>
{:else if phase === 'done'}
	<div class="mt-4">
		<Alert tone={outcome === 'approved' ? 'info' : 'warn'} title={outcome === 'approved' ? '已批准' : '已拒绝'}>
			{outcome === 'approved'
				? '你的设备现在可以继续了，请回到设备的界面查看。'
				: '这次登录已被拒绝，你的设备不会获得任何权限。'}
		</Alert>
	</div>
{:else if phase === 'code'}
	<Card class="mt-4">
		<form
			class="flex flex-col gap-3 p-4"
			onsubmit={(e) => {
				e.preventDefault();
				void submit();
			}}
		>
			<label class="text-sm font-medium" for="user-code">设备代码</label>
			<input
				id="user-code"
				bind:value={code}
				autocomplete="one-time-code"
				autocapitalize="characters"
				spellcheck="false"
				placeholder="WDJB-MJHT"
				class="rounded-lg border border-line-strong bg-canvas px-3 py-2 font-mono text-lg tracking-widest uppercase"
			/>
			<div class="flex justify-end">
				<Button variant="primary" type="submit" loading={checking} disabled={!code.trim()}>继续</Button>
			</div>
		</form>
	</Card>
	<p class="mt-3 text-xs text-ink-faint">代码由你的设备生成，几分钟内有效。</p>
{:else if pending}
	<p class="mt-1 text-sm text-ink-muted">
		<strong class="font-medium text-ink">{pending.client.name}</strong> 正在请求访问你的账号。
	</p>

	<Card class="mt-4">
		<div class="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-3">
			<div>
				<p class="text-xs font-medium text-ink-faint">设备代码</p>
				<p class="mt-0.5 font-mono text-sm tracking-widest">{pending.user_code}</p>
			</div>
			{#if countdown}
				<p class="text-xs text-ink-muted">剩余 {countdown}</p>
			{/if}
		</div>
		<ScopeList
			scopes={pending.scopes}
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
			{:else if granted.length === 0}
				<p class="text-xs text-ink-muted">你没有勾选任何权限。请至少保留一项，或拒绝这次请求。</p>
			{/if}
			<div class="flex flex-wrap items-center justify-end gap-2">
				<Button variant="secondary" loading={busy === 'deny'} disabled={busy !== null} onclick={() => decide('deny')}>
					拒绝
				</Button>
				<Button variant="primary" loading={busy === 'approve'} disabled={!canApprove} onclick={() => decide('approve')}>
					批准登录
				</Button>
			</div>
		</div>
	</Card>

	<p class="mt-4 text-xs text-ink-faint">
		如果你没有在自己的设备上发起这次登录，请选择「拒绝」。
	</p>
{/if}
