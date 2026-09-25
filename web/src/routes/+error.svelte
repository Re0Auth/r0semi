<script lang="ts">
	import { page } from '$app/state';
	import { base } from '$app/paths';

	// SvelteKit's global error boundary. Without it an uncaught render error or an
	// unknown route falls back to its own unstyled page, which looks like the app
	// is broken rather than like something went wrong.
	const status = $derived(page.status);
	const message = $derived(
		page.error?.message && page.error.message !== 'Not Found'
			? page.error.message
			: status === 404
				? '这个页面不存在。'
				: '页面没有加载成功。'
	);
</script>

<svelte:head>
	<title>出错了 · Re0Auth</title>
</svelte:head>

<div class="mx-auto mt-12 max-w-text">
	<p class="font-mono text-xs text-ink-faint">{status}</p>
	<h1 class="mt-2 text-page font-semibold text-balance">{message}</h1>
	<p class="mt-3 text-base text-pretty text-ink-muted">
		可以返回账号首页重试；如果问题持续存在，请附上页面地址联系部署方。
	</p>
	<p class="mt-6">
		<a class="text-sm font-medium underline underline-offset-4" href="{base}/">返回账号首页</a>
	</p>
</div>
