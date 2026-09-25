/**
 * The /v1 client.
 *
 * Written by hand rather than generated from docs/openapi.yaml. That is a
 * deliberate, temporary trade: generated code would guarantee the shapes match,
 * but this file is small and every line of it is on the path that decides what a
 * consent screen says. When there are more endpoints than fit in one reading, the
 * generator starts to win.
 *
 * Three rules live here so that they live nowhere else:
 *
 *   1. Everything goes through `call`, so every response is parsed once and every
 *      failure becomes an ApiError carrying the RFC 9457 problem.
 *   2. Callers branch on `code`. `title` and `detail` are for humans and may be
 *      reworded without notice.
 *   3. Credentials are same-origin cookies, never JavaScript state. There is no
 *      token in memory, nothing in localStorage, and therefore nothing for an XSS
 *      to steal. Writes additionally need the CSRF token, which the server hands
 *      out with the session and which this module only ever forwards.
 */

/**
 * Codes the server can produce. Exhaustive; see docs/openapi.yaml.
 * TestFrontendProblemCodesMatchCatalogue in internal/httpapi fails the build if
 * this list and the server's catalogue disagree.
 */
export type ProblemCode =
	| 'cascade_unsupported'
	| 'explicit_consent_required'
	| 'internal_error'
	| 'invalid_request'
	| 'invalid_token'
	| 'last_identity'
	| 'not_acceptable'
	| 'not_found'
	| 'rate_limited'
	| 'scope_not_granted'
	| 'source_not_bound'
	| 'source_retired'
	| 'source_unavailable'
	| 'unauthenticated'
	| 'upstream_unavailable';

/**
 * Failures this module raises itself, before or instead of the server answering.
 * Kept in the same vocabulary so callers have one thing to switch on, and named
 * so nobody mistakes them for server codes.
 */
export type LocalProblemCode = 'network_error' | 'malformed_response';

export interface Problem {
	type: string;
	title: string;
	status: number;
	detail?: string;
	instance?: string;
	code: ProblemCode | LocalProblemCode;
	request_id?: string;
	required_scope?: string;
	game?: string;
	source?: string;
	bind_url?: string;
}

export class ApiError extends Error {
	readonly status: number;
	readonly problem: Problem;
	/** Seconds the server asked the client to wait, when it sent Retry-After. */
	readonly retryAfter?: number;

	constructor(status: number, problem: Problem, retryAfter?: number) {
		super(problem.detail ?? problem.title);
		this.name = 'ApiError';
		this.status = status;
		this.problem = problem;
		this.retryAfter = retryAfter;
	}

	get code(): ProblemCode | LocalProblemCode {
		return this.problem.code;
	}

	/** True when the only thing wrong is that nobody is signed in yet. */
	get needsSignIn(): boolean {
		return this.code === 'unauthenticated';
	}
}

export interface Identity {
	id: string;
	provider: string;
	display_name: string;
	email?: string;
	avatar_url?: string;
	linked_at: string;
}

export interface Session {
	user_id: string;
	primary_identity_id: string;
	csrf_token: string;
	identities: Identity[];
}

export interface IDPProvider {
	id: string;
	display_name: string;
	start_url: string;
}

export interface ScopeView {
	scope: string;
	title: string;
	description: string;
	risk: 'low' | 'medium' | 'high' | 'critical';
	explicit_consent: boolean;
}

export interface ClientRef {
	id: string;
	name: string;
}

export interface AuthorizationRequest {
	id: string;
	client: ClientRef;
	scopes: ScopeView[];
	/** Data sources this account must connect before approving is useful. */
	missing_bindings?: BindingRequirement[];
	csrf_token: string;
}

/** One data source the consent screen must ask the player to connect. */
export interface BindingRequirement {
	game: string;
	source: string;
	display_name: string;
	scopes: string[];
	/** Server-built; navigate to it verbatim. */
	bind_url: string;
}

export interface AuthorizationDecision {
	decision: 'approve' | 'deny';
	scopes?: string[];
	explicit?: string[];
}

export interface RedirectResult {
	redirect_to: string;
}

export interface DeviceAwaitingCode {
	state: 'awaiting_code';
}

export interface DevicePending {
	state: 'pending';
	user_code: string;
	client: ClientRef;
	scopes: ScopeView[];
	expires_at: string;
	csrf_token: string;
}

export type DeviceVerification = DeviceAwaitingCode | DevicePending;

export interface DeviceDecision {
	user_code: string;
	decision: 'approve' | 'deny';
	scopes?: string[];
	explicit?: string[];
}

export interface DeviceDecisionResult {
	state: 'approved' | 'denied';
}

export interface Grant {
	client_id: string;
	client_name: string;
	scopes: ScopeView[];
	/** Whether the client can renew on its own, or this access lapses by itself. */
	has_refresh: boolean;
	issued_at: string;
	expires_at: string;
}

export interface FederationResource {
	name: string;
	schema: string;
	scope: string;
}

/** One data source this deployment offers. Public discovery. */
export interface FederationSource {
	game: string;
	source: string;
	display_name: string;
	token_class: 'revocable' | 'long_lived' | '';
	status: 'active' | 'degraded' | 'retired' | '';
	raw: boolean;
	resources: FederationResource[];
}

/** One data source connected to this account. Holds no credential. */
export interface Binding {
	game: string;
	source: string;
	display_name: string;
	token_class: 'revocable' | 'long_lived' | '';
	status: 'active' | 'degraded' | 'retired' | '';
	has_refresh: boolean;
	expiry?: string;
	bindable: boolean;
	/** False when the binding outlived the source's entry in the deployment config. */
	configured: boolean;
	/** Whether this deployment has been told the source can end a whole session. */
	cascade_revocation: boolean;
}

/** What a data source did when told to drop the token it issued. */
export type UpstreamRevocation = 'done' | 'unsupported' | 'unavailable' | 'nothing';
export interface UnbindResult {
	upstream: UpstreamRevocation;
	upstream_error?: string;
}

/** The downloaded account document. Credentials are excluded by construction. */
export interface AccountExport {
	exported_at: string;
	profile: {
		user_id: string;
		primary_identity_id: string;
		created_at: string;
	};
	identities: Identity[];
	bindings: Binding[];
	grants: Grant[];
	notice: {
		credentials_excluded: boolean;
		reason: string;
	};
}

/** What the erasure removed, per store. */
export interface AccountDeletion {
	result: Record<string, unknown>;
}

function local(code: LocalProblemCode, detail: string): Problem {
	return { type: 'about:blank', title: 'Request failed', status: 0, code, detail };
}

function looksLikeProblem(value: unknown): value is Problem {
	return (
		typeof value === 'object' &&
		value !== null &&
		typeof (value as Problem).code === 'string' &&
		typeof (value as Problem).status === 'number'
	);
}

interface CallOptions {
	body?: unknown;
	csrf?: string;
}

/** Per-attempt deadline. A request that hangs forever is a dead end, not a wait. */
const REQUEST_TIMEOUT_MS = 15_000;
/** Total attempts for a retryable request. Only GETs are retried. */
const MAX_ATTEMPTS = 3;

/** Retry-After in seconds, from either the delta form or an HTTP date. */
function retryAfterSeconds(res: Response): number | undefined {
	const raw = res.headers.get('Retry-After');
	if (!raw) return undefined;
	const seconds = Number(raw);
	if (Number.isFinite(seconds) && seconds >= 0) return Math.ceil(seconds);
	const at = Date.parse(raw);
	if (Number.isNaN(at)) return undefined;
	return Math.max(0, Math.ceil((at - Date.now()) / 1000));
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function call<T>(
	method: 'GET' | 'POST' | 'DELETE',
	path: string,
	opts: CallOptions = {}
): Promise<T> {
	const headers: Record<string, string> = { Accept: 'application/json' };
	if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
	if (opts.csrf) headers['X-CSRF-Token'] = opts.csrf;

	let res: Response | undefined;
	for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
		try {
			res = await fetch(path, {
				method,
				headers,
				credentials: 'same-origin',
				signal: controller.signal,
				body: opts.body === undefined ? undefined : JSON.stringify(opts.body)
			});
		} catch (cause) {
			clearTimeout(timer);
			if (method === 'GET' && attempt < MAX_ATTEMPTS) {
				await sleep(200 * attempt);
				continue;
			}
			throw new ApiError(
				0,
				local('network_error', cause instanceof Error ? cause.message : 'network request failed')
			);
		}
		clearTimeout(timer);

		// Only idempotent requests are retried, and only on the statuses that mean
		// "try again", never on a 4xx the client caused.
		if (method === 'GET' && attempt < MAX_ATTEMPTS && [502, 503, 504].includes(res.status)) {
			const after = retryAfterSeconds(res) ?? 0;
			await sleep(Math.min(after * 1000, 2000) + 100 * attempt);
			continue;
		}
		break;
	}
	if (!res) throw new ApiError(0, local('network_error', 'network request failed'));

	if (res.status === 204) return undefined as T;

	const text = await res.text();
	let body: unknown;
	if (text) {
		try {
			body = JSON.parse(text);
		} catch {
			// A JSON content type that is not JSON means something between here and
			// the server answered instead: a proxy, a captive portal, an error page.
			// Saying so is more useful than a SyntaxError.
			throw new ApiError(
				res.status,
				local('malformed_response', `expected JSON, got ${res.headers.get('content-type') ?? 'no content type'}`)
			);
		}
	}

	if (!res.ok) {
		throw new ApiError(
			res.status,
			looksLikeProblem(body) ? body : local('malformed_response', `unexpected ${res.status} response shape`),
			retryAfterSeconds(res)
		);
	}
	return body as T;
}

export const api = {
	listIDPProviders: () => call<{ data: IDPProvider[] }>('GET', '/v1/idp/providers'),

	currentSession: () => call<Session>('GET', '/v1/sessions/current'),

	signOut: (csrf: string) => call<void>('POST', '/v1/sessions/sign_out', { csrf }),

	getAuthorizationRequest: (id: string) =>
		call<AuthorizationRequest>('GET', `/v1/authorization_requests/${encodeURIComponent(id)}`),

	decideAuthorizationRequest: (id: string, csrf: string, decision: AuthorizationDecision) =>
		call<RedirectResult>('POST', `/v1/authorization_requests/${encodeURIComponent(id)}/decision`, {
			body: decision,
			csrf
		}),

	getDeviceVerification: (userCode: string) =>
		call<DeviceVerification>(
			'GET',
			userCode ? `/v1/device/verification?user_code=${encodeURIComponent(userCode)}` : '/v1/device/verification'
		),

	decideDevice: (csrf: string, decision: DeviceDecision) =>
		call<DeviceDecisionResult>('POST', '/v1/device/decision', { body: decision, csrf }),

	listGrants: () => call<{ data: Grant[] }>('GET', '/v1/grants'),

	// Session-scoped, like grants: the ways an account can sign in are not a
	// downstream client's business.
	listIdentities: () => call<{ data: Identity[] }>('GET', '/v1/identities'),

	// 204. Removing the last identity is refused by the server with
	// 409 last_identity, so the UI can leave the last one's button off rather
	// than rely on a failure to teach the rule.
	unlinkIdentity: (id: string, csrf: string) =>
		call<void>('DELETE', `/v1/identities/${encodeURIComponent(id)}`, { csrf }),

	// 204 with no body, whether or not the client held anything: revoking is
	// idempotent, so a retry after a dropped response is not an error to reason
	// about.
	revokeGrant: (clientId: string, csrf: string) =>
		call<void>('DELETE', `/v1/grants/${encodeURIComponent(clientId)}`, { csrf }),

	listAllSources: () => call<{ data: FederationSource[] }>('GET', '/v1/sources'),

	listBindings: () => call<{ data: Binding[] }>('GET', '/v1/bindings'),

	// The account's own data, assembled by the server from the same view builders
	// the list endpoints use. no-store, session-scoped, and no CSRF because it
	// changes nothing.
	exportAccount: () => call<AccountExport>('GET', '/v1/account/export'),

	// Erasure is idempotent server-side; the acknowledgement is required by the
	// server so the act cannot happen without naming what it does.
	deleteAccount: (csrf: string) =>
		call<AccountDeletion>('DELETE', '/v1/account', {
			body: { acknowledge: 'deletes_my_account' },
			csrf
		}),

	// 200 with a body, not 204: whether the source was actually told is part of
	// the answer, and a bare success would overstate what happened.
	unbindSource: (game: string, source: string, csrf: string) =>
		call<UnbindResult>(
			'DELETE',
			`/v1/bindings/${encodeURIComponent(game)}/${encodeURIComponent(source)}`,
			{ csrf }
		),

	// The acknowledgement is required by the server, not by this client: ending
	// somebody's sessions on every device should not be reachable without writing
	// down that it means that. Sending it from here is the UI agreeing, not the UI
	// deciding.
	cascadeRevoke: (game: string, source: string, csrf: string) =>
		call<UnbindResult>(
			'POST',
			`/v1/bindings/${encodeURIComponent(game)}/${encodeURIComponent(source)}/cascade_revocation`,
			{ body: { acknowledge: 'signs_out_all_devices' }, csrf }
		)
};
