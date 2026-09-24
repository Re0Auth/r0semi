import { tick } from 'svelte';

/*
 * Focus handling for inline disclosures: the two-step confirmations that replace
 * their own trigger (撤销 → 取消 / 确认撤销).
 *
 * Both halves are needed, and neither comes for free. Activating the trigger
 * removes that button from the document, so focus falls to `<body>`: a keyboard
 * user's next Tab restarts from the top of the page, and a screen reader never
 * lands on the sentence that says what is about to happen.
 */

/**
 * Move focus to the first control inside a surface that has just appeared.
 *
 * The markup for every confirmation puts the safe action (取消) first, so this
 * lands on the way out rather than on the destructive button — a stray Enter
 * should never be what revokes a token.
 */
export function focusFirstControl(node: HTMLElement) {
	const first = node.querySelector<HTMLElement>('button, [href], input, select, textarea');
	first?.focus();
}

/**
 * Hand focus back to the control that opened the surface, once it has closed.
 *
 * Takes a selector rather than the element itself on purpose: closing the surface
 * re-creates the trigger, so a node captured when it was clicked is detached by
 * the time focus needs returning and `.focus()` on it does nothing. It also
 * awaits `tick()`, because the replacement does not exist until the DOM updates.
 */
export async function restoreFocus(selector: string) {
	await tick();
	document.querySelector<HTMLElement>(selector)?.focus();
}
