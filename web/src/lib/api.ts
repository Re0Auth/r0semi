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
	| 'reauth_required'
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

/** One downstream client, as the operator plane sees it. Never carries a secret. */
export interface AdminClient {
	client_id: string;
	name: string;
	type: 'public' | 'confidential';
	status: 'active' | 'suspended';
	redirect_uris: string[];
	allowed_scopes: string[];
	created_at: string;
}

export interface AdminRegistration {
	client: AdminClient;
	/** Present exactly once, at registration. The server cannot read it back. */
	client_secret?: string;
}

/**
 * One page of the operator's client inventory.
 *
 * The listing is cursor-paged: `data` is the page (ordered by `client_id`), and
 * `next_cursor` — absent on the last page — is echoed back as `cursor` to fetch
 * the one after it. It is not an offset, so a client registered between two
 * requests cannot make the next page repeat or skip a row.
 */
export interface AdminClientPage {
	data: AdminClient[];
	csrf_token: string;
	next_cursor?: string;
}

export interface KillSwitchReport {
	tokens_revoked: number;
	sessions_revoked: number;
	clients_suspended: number;
	bindings?: {
		total: number;
		revoked: number;
		cascade: number;
		unsupported: number;
		unavailable: number;
		orphaned: number;
		failed: number;
	};
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

/** Field predicates for `requireData`, small enough to read at the call site. */
const isString = (v: unknown): boolean => typeof v === 'string';
const isNumber = (v: unknown): boolean => typeof v === 'number';
const isArray = (v: unknown): boolean => Array.isArray(v);
const isObject = (v: unknown): v is Record<string, unknown> =>
	typeof v === 'object' && v !== null;
const isOneOf =
	(...allowed: string[]) =>
	(v: unknown): boolean =>
		typeof v === 'string' && allowed.includes(v);
const hasStrings = (v: unknown, ...keys: string[]): boolean =>
	isObject(v) && keys.every((key) => isString(v[key]));

/**
 * The one shape check every 2xx JSON body goes through.
 *
 * The type parameter only asserts a shape; JSON is not typed, and a response
 * whose field is missing (or is an object where the page iterates) throws inside
 * a render, where the only handler left is SvelteKit's error boundary — which
 * shows the JavaScript message instead of something a person can act on. Checking
 * at the boundary turns the same response into an ApiError every caller already
 * knows how to display.
 *
 * `shape` names each field a caller will read and the predicate it must satisfy.
 * It deliberately stays top-level: a body that is the wrong envelope entirely is
 * the failure this guards against, and validating every nested field would turn
 * one rule into a second schema that has to be kept in step with the server.
 */
function requireData<T>(
	value: unknown,
	what: string,
	shape: Record<string, (field: unknown) => boolean>
): T {
	if (!isObject(value)) {
		throw new ApiError(0, local('malformed_response', `${what} response is not a JSON object`));
	}
	for (const [field, valid] of Object.entries(shape)) {
		if (!valid(value[field])) {
			throw new ApiError(
				0,
				local('malformed_response', `${what} response is missing or has an invalid ${field}`)
			);
		}
	}
	return value as T;
}

/**
 * A list endpoint answers with `{ data: [...] }`, which is just the `data`
 * envelope every list shares; it is expressed through `requireData` so there is
 * one place that decides what a malformed body means.
 */
function requireDataList<T>(value: unknown, what: string): { data: T[] } {
	return requireData<{ data: T[] }>(value, what, { data: isArray });
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
	// One deadline per attempt, held outside the loop because it now has to outlive
	// `fetch`: that resolves as soon as the response headers arrive, so clearing the
	// timer there left the body with no deadline at all.
	let timer: ReturnType<typeof setTimeout> | undefined;
	for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
		const controller = new AbortController();
		timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
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

		// Only idempotent requests are retried, and only on the statuses that mean
		// "try again", never on a 4xx the client caused.
		if (method === 'GET' && attempt < MAX_ATTEMPTS && [502, 503, 504].includes(res.status)) {
			clearTimeout(timer);
			// The attempt is abandoned, but its body is still an open stream. Left
			// alone, the transport keeps the connection (and whatever it buffers)
			// busy delivering bytes nobody will ever read. Cancelling is how the
			// retry releases it instead of waiting for a response we no longer want.
			await res.body?.cancel().catch(() => {});
			const after = retryAfterSeconds(res) ?? 0;
			await sleep(Math.min(after * 1000, 2000) + 100 * attempt);
			continue;
		}
		break;
	}
	if (!res) throw new ApiError(0, local('network_error', 'network request failed'));

	// The deadline covers the body too. `fetch` above resolves on headers alone, so
	// a server that never finishes its body would otherwise hang the caller forever.
	try {
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
	} finally {
		clearTimeout(timer);
	}
}

export const api = {
	listIDPProviders: async () =>
		requireDataList<IDPProvider>(await call('GET', '/v1/idp/providers'), 'identity providers'),

	// The success shape is validated at the boundary, not merely asserted by the
	// type parameter. TypeScript cannot check JSON, and a missing csrf_token here
	// would turn every later write into an unexplainable 403.
	currentSession: async () => {
		const session = await call<Session>('GET', '/v1/sessions/current');
		return requireData<Session>(session, 'session', {
			user_id: isString,
			primary_identity_id: isString,
			csrf_token: isString,
			identities: isArray
		});
	},

	signOut: (csrf: string) => call<void>('POST', '/v1/sessions/sign_out', { csrf }),

	getAuthorizationRequest: async (id: string) => {
		const request = await call<AuthorizationRequest>(
			'GET',
			`/v1/authorization_requests/${encodeURIComponent(id)}`
		);
		return requireData<AuthorizationRequest>(request, 'authorization request', {
			id: isString,
			scopes: isArray,
			client: (v) => hasStrings(v, 'id', 'name'),
			// Used as the CSRF token of the decision; absent, the approval is a 403
			// with no explanation.
			csrf_token: isString
		});
	},

	decideAuthorizationRequest: async (id: string, csrf: string, decision: AuthorizationDecision) => {
		const result = await call<RedirectResult>(
			'POST',
			`/v1/authorization_requests/${encodeURIComponent(id)}/decision`,
			{ body: decision, csrf }
		);
		// This string is handed to window.location.assign verbatim. A missing one
		// would navigate to the literal "undefined"; refusing it keeps the page on
		// its own error message.
		return requireData<RedirectResult>(result, 'authorization decision', { redirect_to: isString });
	},

	getDeviceVerification: async (userCode: string) => {
		const res = await call<DeviceVerification>(
			'GET',
			userCode ? `/v1/device/verification?user_code=${encodeURIComponent(userCode)}` : '/v1/device/verification'
		);
		// The state is the branch the page switches on; anything else is a body it
		// cannot act on. A pending body is read field by field, so all of it is
		// checked here rather than throwing from the render.
		if (!isObject(res) || (res.state !== 'awaiting_code' && res.state !== 'pending')) {
			throw new ApiError(
				0,
				local('malformed_response', 'device verification response has an unknown state')
			);
		}
		if (res.state === 'pending') {
			return requireData<DevicePending>(res, 'device verification', {
				user_code: isString,
				client: (v) => hasStrings(v, 'id', 'name'),
				scopes: isArray,
				expires_at: isString,
				csrf_token: isString
			});
		}
		return res as DeviceAwaitingCode;
	},

	decideDevice: async (csrf: string, decision: DeviceDecision) => {
		const result = await call<DeviceDecisionResult>('POST', '/v1/device/decision', {
			body: decision,
			csrf
		});
		return requireData<DeviceDecisionResult>(result, 'device decision', {
			state: isOneOf('approved', 'denied')
		});
	},

	listGrants: async () => requireDataList<Grant>(await call('GET', '/v1/grants'), 'grants'),

	// Session-scoped, like grants: the ways an account can sign in are not a
	// downstream client's business.
	listIdentities: async () =>
		requireDataList<Identity>(await call('GET', '/v1/identities'), 'identities'),

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

	listAllSources: async () =>
		requireDataList<FederationSource>(await call('GET', '/v1/sources'), 'sources'),

	listBindings: async () => requireDataList<Binding>(await call('GET', '/v1/bindings'), 'bindings'),

	// The account's own data, assembled by the server from the same view builders
	// the list endpoints use. no-store, session-scoped, and no CSRF because it
	// changes nothing.
	exportAccount: async () => {
		const data = await call<AccountExport>('GET', '/v1/account/export');
		// The filename of the download is built from profile.user_id, so an export
		// that does not carry one must fail where the caller can catch it rather
		// than as a TypeError deep inside the download.
		return requireData<AccountExport>(data, 'account export', {
			profile: (v) => isObject(v) && isString(v.user_id) && v.user_id !== ''
		});
	},

	// Erasure is idempotent server-side; the acknowledgement is required by the
	// server so the act cannot happen without naming what it does.
	deleteAccount: async (csrf: string) => {
		const result = await call<AccountDeletion>('DELETE', '/v1/account', {
			body: { acknowledge: 'deletes_my_account' },
			csrf
		});
		return requireData<AccountDeletion>(result, 'account deletion', { result: isObject });
	},

	// Operator plane. Every write here needs a fresh authentication; a
	// `reauth_required` code means the operator must sign in again.
	//
	// The inventory is paged: pass the previous page's `next_cursor` back as
	// `cursor`. The server refuses a cursor it did not issue (400) rather than
	// restarting from the first page, so a caller must treat `next_cursor` as an
	// opaque value.
	listAdminClients: async (page?: { limit?: number; cursor?: string }) => {
		const params = new URLSearchParams();
		if (page?.limit !== undefined) params.set('limit', String(page.limit));
		if (page?.cursor) params.set('cursor', page.cursor);
		const query = params.toString();
		const res = await call<AdminClientPage>(
			'GET',
			`/v1/admin/clients${query ? `?${query}` : ''}`
		);
		const body = requireData<AdminClientPage>(res, 'admin clients', {
			data: isArray,
			csrf_token: isString
		});
		// The field is optional, so `requireData` does not check it; a value that
		// is present but not a string would otherwise be handed straight back to
		// the server as a cursor the caller never received.
		if (body.next_cursor !== undefined && !isString(body.next_cursor)) {
			throw new ApiError(
				0,
				local('malformed_response', 'admin clients response has an invalid next_cursor')
			);
		}
		return body;
	},

	registerAdminClient: async (
		csrf: string,
		body: { name: string; type: string; redirect_uris: string[]; scopes: string[] }
	) => {
		const result = await call<AdminRegistration>('POST', '/v1/admin/clients', { body, csrf });
		return requireData<AdminRegistration>(result, 'admin registration', {
			client: (v) => hasStrings(v, 'client_id', 'name')
		});
	},

	suspendAdminClient: (clientId: string, csrf: string) =>
		call<void>('POST', `/v1/admin/clients/${encodeURIComponent(clientId)}/suspend`, { csrf }),

	activateAdminClient: (clientId: string, csrf: string) =>
		call<void>('POST', `/v1/admin/clients/${encodeURIComponent(clientId)}/activate`, { csrf }),

	deleteAdminClient: (clientId: string, csrf: string) =>
		call<void>('DELETE', `/v1/admin/clients/${encodeURIComponent(clientId)}`, { csrf }),

	killSwitch: async (
		csrf: string,
		target: { target: 'all' | 'client' | 'subject' | 'bindings'; client_id?: string; subject?: string }
	) => {
		const report = await call<KillSwitchReport>('POST', '/v1/admin/kill_switch', {
			body: target,
			csrf
		});
		return requireData<KillSwitchReport>(report, 'kill switch report', {
			tokens_revoked: isNumber,
			sessions_revoked: isNumber,
			clients_suspended: isNumber
		});
	},

	// 200 with a body, not 204: whether the source was actually told is part of
	// the answer, and a bare success would overstate what happened.
	unbindSource: async (game: string, source: string, csrf: string) => {
		const result = await call<UnbindResult>(
			'DELETE',
			`/v1/bindings/${encodeURIComponent(game)}/${encodeURIComponent(source)}`,
			{ csrf }
		);
		return requireData<UnbindResult>(result, 'unbind result', {
			upstream: isOneOf('done', 'unsupported', 'unavailable', 'nothing')
		});
	},

	// The acknowledgement is required by the server, not by this client: ending
	// somebody's sessions on every device should not be reachable without writing
	// down that it means that. Sending it from here is the UI agreeing, not the UI
	// deciding.
	cascadeRevoke: async (game: string, source: string, csrf: string) => {
		const result = await call<UnbindResult>(
			'POST',
			`/v1/bindings/${encodeURIComponent(game)}/${encodeURIComponent(source)}/cascade_revocation`,
			{ body: { acknowledge: 'signs_out_all_devices' }, csrf }
		);
		return requireData<UnbindResult>(result, 'cascade revocation result', {
			upstream: isOneOf('done', 'unsupported', 'unavailable', 'nothing')
		});
	}
};
