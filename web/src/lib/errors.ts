import { ApiError } from './api';

/**
 * A human-readable error string, with the server's request id appended when it
 * gave one.
 *
 * The request id is the one part of a failure that makes it answerable: it
 * matches both the `X-Request-Id` response header and the server's own logs, so
 * a user can quote it and an operator can find the exact request. Every page
 * shows it the same way because it is assembled here.
 *
 * It also absorbs the `err instanceof Error ? err.message : String(err)` line
 * each page used to carry, which is why there is one of these and not six.
 */
export function messageOf(err: unknown): string {
	if (err instanceof ApiError) {
		const id = err.problem.request_id;
		return id ? `${err.message}（请求号 ${id}）` : err.message;
	}
	return err instanceof Error ? err.message : String(err);
}
