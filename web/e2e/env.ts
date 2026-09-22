// Ports and identifiers shared by the Playwright config, the server launcher and
// the specs.
//
// The launcher is plain JavaScript (node runs it directly), so it reads these
// from the environment with the same defaults — Playwright passes them through
// explicitly, which keeps the two in step without a build step.

export const appPort = Number(process.env.E2E_PORT ?? 18099);
export const idpPort = Number(process.env.E2E_IDP_PORT ?? 18098);

export const appBase = `http://127.0.0.1:${appPort}`;
export const idpBase = `http://127.0.0.1:${idpPort}`;

/** The downstream client seeded by the test config. Public: no client secret. */
export const CLIENT_ID = 'cli';
export const CLIENT_NAME = 'Phi CLI';

/** The client's registered redirect URI. Served by the fake server. */
export const CALLBACK_URL = `${idpBase}/callback`;

export const DEFAULT_SCOPES = 'account.id phigros.b30.read';
