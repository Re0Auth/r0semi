<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import {
		api,
		ApiError,
		type AdminClient,
		type KillSwitchReport
	} from '$lib/api';
	import { messageOf } from '$lib/errors';
	import SignIn from '$lib/components/SignIn.svelte';
	import Alert from '$lib/components/ui/Alert.svelte';
	import Badge from '$lib/components/ui/Badge.svelte';
	import Button from '$lib/components/ui/Button.svelte';
	import Card from '$lib/components/ui/Card.svelte';
	import CopyValue from '$lib/components/ui/CopyValue.svelte';

	// The operator plane. It is not linked from the player navigation on purpose:
	// a non-admin gets 404 from every endpoint, and advertising the URL would tell
	// them the plane exists.
	type Phase = 'loading' | 'anonymous' | 'denied' | 'ready' | 'failed';

	let phase = $state<Phase>('loading');
	let detail = $state('');
	let actionError = $state('');
	let csrf = $state('');
	let clients = $state<AdminClient[]>([]);
	let reauth = $state(false);
	let busy = $state<string | null>(null);

	let regName = $state('');
	let regType = $state<'public' | 'confidential'>('public');
	let regRedirects = $state('');
	let regScopes = $state('');
	let newSecret = $state('');

	const killTargets: Array<'all' | 'client' | 'subject' | 'bindings'> = [
		'all',
		'client',
		'subject',
		'bindings'
	];
	let ksTarget = $state<'all' | 'client' | 'subject' | 'bindings'>('client');
	let ksClientID = $state('');
	let ksSubject = $state('');
	let ksConfirming = $state(false);
	let report = $state<KillSwitchReport | null>(null);

	let deleteConfirming = $state<string | null>(null);

	onMount(load);

	async function load() {
		try {
			const session = await api.currentSession();
			csrf = session.csrf_token;
		} catch (err) {
			if (err instanceof ApiError && err.needsSignIn) {
				phase = 'anonymous';
				return;
			}
			detail = messageOf(err);
			phase = 'failed';
			return;
		}
		await refresh();
	}

	async function refresh() {
		try {
			const res = await api.listAdminClients();
			clients = res.data;
			if (res.csrf_token) csrf = res.csrf_token;
			phase = 'ready';
		} catch (err) {
			if (err instanceof ApiError && err.needsSignIn) {
				phase = 'anonymous';
				return;
			}
			// 404 is the documented answer for "not an operator": the plane is not
			// advertised to accounts that cannot use it.
			if (err instanceof ApiError && (err.status === 404 || err.status === 403)) {
				phase = 'denied';
				return;
			}
			detail = messageOf(err);
			phase = 'failed';
		}
	}

	// Every write goes through this, so the step-up answer has one handler rather
	// than one per button.
	async function write<T>(key: string, fn: () => Promise<T>): Promise<T | undefined> {
		busy = key;
		actionError = '';
		try {
			return await fn();
		} catch (err) {
			if (err instanceof ApiError && err.code === 'reauth_required') {
				reauth = true;
				return;
			}
			if (err instanceof ApiError && err.needsSignIn) {
				phase = 'anonymous';
				return;
			}
			actionError = messageOf(err);
		} finally {
			busy = null;
		}
	}

	async function reauthNow() {
		try {
			await api.signOut(csrf);
		} catch {
			// Whether the sign-out succeeded or the session was already gone, the
			// next load shows the sign-in screen; nothing here needs the error.
		}
		window.location.reload();
	}

	function splitList(raw: string): string[] {
		return raw
			.split(/[\s,]+/)
			.map((s) => s.trim())
			.filter(Boolean);
	}

	async function register() {
		const redirects = splitList(regRedirects);
		const scopes = splitList(regScopes);
		if (!regName.trim() || redirects.length === 0 || scopes.length === 0) {
			actionError = '名称、至少一个 redirect URI 和至少一个 scope 都是必填的。';
			return;
		}
		const result = await write('register', () =>
			api.registerAdminClient(csrf, {
				name: regName.trim(),
				type: regType,
				redirect_uris: redirects,
				scopes
			})
		);
		if (!result) return;
		newSecret = result.client_secret ?? '';
		regName = '';
		regRedirects = '';
		regScopes = '';
		await refresh();
	}

	async function setStatus(client: AdminClient, suspend: boolean) {
		const updated = await write(`${suspend ? 'suspend' : 'activate'}:${client.client_id}`, () =>
			suspend
				? api.suspendAdminClient(client.client_id, csrf)
				: api.activateAdminClient(client.client_id, csrf)
		);
		if (updated !== undefined || !actionError) await refresh();
	}

	async function remove(client: AdminClient) {
		const done = await write(`delete:${client.client_id}`, () =>
			api.deleteAdminClient(client.client_id, csrf)
		);
		deleteConfirming = null;
		if (done !== undefined || !actionError) await refresh();
	}

	async function kill() {
		const target =
			ksTarget === 'client'
				? { target: ksTarget, client_id: ksClientID.trim() }
				: ksTarget === 'subject'
					? { target: ksTarget, subject: ksSubject.trim() }
					: { target: ksTarget };
		const result = await write('kill', () => api.killSwitch(csrf, target));
		ksConfirming = false;
		if (result) report = result;
	}

	const killCopy: Record<typeof ksTarget, string> = {
		client: '吊销该客户端全部令牌并暂停它。',
		subject: '吊销该账号的令牌、会话与数据源绑定。',
		all: '吊销所有令牌、清空所有会话与数据源绑定。',
		bindings: '只断开所有数据源绑定，令牌与会话保留。'
	};
</script>

<svelte:head>
	<title>管理面 · Re0Auth</title>
</svelte:head>

<h1 class="text-page font-semibold text-balance">管理面</h1>

{#if phase === 'loading'}
	<p class="mt-4 text-sm text-ink-muted">正在读取…</p>
{:else if phase === 'anonymous'}
	<div class="mt-4 flex flex-col gap-4">
		<Alert tone="warn" title="需要先登录">管理面只对管理员开放。</Alert>
		<SignIn returnTo={`${page.url.pathname}${page.url.search}`} />
	</div>
{:else if phase === 'denied'}
	<p class="mt-4 text-sm text-ink-muted">这个账号没有管理权限。</p>
{:else if phase === 'failed'}
	<p class="mt-4 text-sm text-danger">{detail}</p>
{:else}
	<div class="mt-4 flex flex-col gap-4">
		{#if reauth}
			<Alert tone="warn" title="需要重新登录">
				这个操作需要较新的登录状态。请重新登录后继续。
				{#snippet actions()}
					<Button variant="secondary" onclick={reauthNow}>重新登录</Button>
				{/snippet}
			</Alert>
		{/if}
		{#if actionError}
			<Alert tone="danger" title="没有完成">{actionError}</Alert>
		{/if}

		<!-- Kill Switch first: in an incident it is the page's reason to exist. -->
		<Card>
			<div class="border-b border-line px-4 py-3">
				<p class="text-sm font-medium">Kill Switch</p>
				<p class="mt-0.5 text-xs text-ink-muted">{killCopy[ksTarget]}</p>
			</div>
			<fieldset class="flex flex-col gap-3 px-4 py-3">
				<legend class="sr-only">选择作用范围</legend>
				<div class="flex flex-wrap gap-3">
					{#each killTargets as value (value)}
						<label class="flex cursor-pointer items-center gap-2 text-sm">
							<input type="radio" name="kill-target" {value} bind:group={ksTarget} />
							{value}
						</label>
					{/each}
				</div>
				{#if ksTarget === 'client'}
					<label class="flex flex-col gap-1 text-sm">
						客户端 ID
						<input
							bind:value={ksClientID}
							placeholder="cli_…"
							class="rounded-lg border border-line-strong bg-surface-sunken px-3 py-2 font-mono text-sm"
						/>
					</label>
				{:else if ksTarget === 'subject'}
					<label class="flex flex-col gap-1 text-sm">
						账号 ID
						<input
							bind:value={ksSubject}
							placeholder="usr_…"
							class="rounded-lg border border-line-strong bg-surface-sunken px-3 py-2 font-mono text-sm"
						/>
					</label>
				{/if}
				{#if ksConfirming}
					<div class="rounded-card border border-danger/40 bg-danger-soft p-3">
						<p class="text-sm text-pretty">
							确认执行？{killCopy[ksTarget]}这一步无法撤销。
						</p>
						<div class="mt-3 flex flex-wrap gap-2">
							<Button variant="quiet" onclick={() => (ksConfirming = false)}>取消</Button>
							<Button variant="danger" loading={busy === 'kill'} onclick={kill}>确认执行</Button>
						</div>
					</div>
				{:else}
					<div class="flex justify-end">
						<Button variant="danger" onclick={() => (ksConfirming = true)}>执行 Kill Switch</Button>
					</div>
				{/if}
			</fieldset>
			{#if report}
				<div class="border-t border-line px-4 py-3 text-sm">
					<p>
						吊销令牌 {report.tokens_revoked} · 清空会话 {report.sessions_revoked} · 暂停客户端 {report.clients_suspended}
					</p>
					{#if report.bindings}
						<p class="mt-1 text-xs text-ink-muted">
							绑定 {report.bindings.revoked}/{report.bindings.total} 已撤销，失败 {report.bindings.failed}
						</p>
					{/if}
				</div>
			{/if}
		</Card>

		<!-- Register. The secret is shown once and cannot be recovered. -->
		<Card>
			<div class="border-b border-line px-4 py-3">
				<p class="text-sm font-medium">注册客户端</p>
			</div>
			<div class="flex flex-col gap-3 px-4 py-3">
				<label class="flex flex-col gap-1 text-sm">
					名称
					<input
						bind:value={regName}
						class="rounded-lg border border-line-strong bg-surface-sunken px-3 py-2 text-sm"
					/>
				</label>
				<label class="flex flex-col gap-1 text-sm">
					类型
					<select
						bind:value={regType}
						class="rounded-lg border border-line-strong bg-surface-sunken px-3 py-2 text-sm"
					>
						<option value="public">public</option>
						<option value="confidential">confidential</option>
					</select>
				</label>
				<label class="flex flex-col gap-1 text-sm">
					Redirect URI（每行一个）
					<textarea
						bind:value={regRedirects}
						rows="2"
						class="rounded-lg border border-line-strong bg-surface-sunken px-3 py-2 font-mono text-sm"
					></textarea>
				</label>
				<label class="flex flex-col gap-1 text-sm">
					Scope（空格或逗号分隔）
					<input
						bind:value={regScopes}
						class="rounded-lg border border-line-strong bg-surface-sunken px-3 py-2 font-mono text-sm"
					/>
				</label>
				<div class="flex justify-end">
					<Button variant="primary" loading={busy === 'register'} onclick={register}>注册</Button>
				</div>
				{#if newSecret}
					<Alert tone="warn" title="客户端密钥只显示这一次">
						把它交给应用并立刻保存；服务端只存哈希，之后无法再读出。
						<span class="mt-1 flex items-center gap-1 font-mono text-xs break-all">
							{newSecret}<CopyValue value={newSecret} label="客户端密钥" />
						</span>
					</Alert>
				{/if}
			</div>
		</Card>

		<Card>
			<div class="flex items-center justify-between border-b border-line px-4 py-3">
				<p class="text-sm font-medium">客户端（{clients.length}）</p>
				<Button variant="quiet" onclick={refresh}>刷新</Button>
			</div>
			{#if clients.length === 0}
				<p class="px-4 py-6 text-center text-sm text-ink-muted">还没有注册任何客户端。</p>
			{:else}
				<ul class="divide-y divide-line">
					{#each clients as client (client.client_id)}
						<li class="flex flex-col gap-2 px-4 py-3">
							<div class="flex flex-wrap items-center justify-between gap-2">
								<div class="min-w-0">
									<p class="text-sm font-medium">{client.name}</p>
									<p class="font-mono text-xs break-all text-ink-faint">{client.client_id}</p>
								</div>
								<div class="flex items-center gap-2">
									<Badge tone={client.type === 'confidential' ? 'neutral' : 'accent'}>{client.type}</Badge>
									<Badge tone={client.status === 'suspended' ? 'danger' : 'neutral'}>{client.status}</Badge>
								</div>
							</div>
							<p class="text-xs text-ink-muted">scopes: {client.allowed_scopes.join(' ')}</p>
							<p class="text-xs break-all text-ink-faint">{client.redirect_uris.join(' ')}</p>
							<div class="flex flex-wrap justify-end gap-2">
								<Button
									variant="quiet"
									loading={busy === `suspend:${client.client_id}`}
									disabled={client.status === 'suspended'}
									onclick={() => setStatus(client, true)}>暂停</Button
								>
								<Button
									variant="quiet"
									loading={busy === `activate:${client.client_id}`}
									disabled={client.status === 'active'}
									onclick={() => setStatus(client, false)}>恢复</Button
								>
								{#if deleteConfirming === client.client_id}
									<span class="self-center text-xs text-danger">删除后无法恢复。</span>
									<Button variant="quiet" onclick={() => (deleteConfirming = null)}>取消</Button>
									<Button
										variant="danger"
										loading={busy === `delete:${client.client_id}`}
										onclick={() => remove(client)}>确认删除</Button
									>
								{:else}
									<Button variant="danger" onclick={() => (deleteConfirming = client.client_id)}>
										删除
									</Button>
								{/if}
							</div>
						</li>
					{/each}
				</ul>
			{/if}
		</Card>
	</div>
{/if}
