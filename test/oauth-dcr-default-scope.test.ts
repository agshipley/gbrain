/**
 * DCR default scope (RFC 7591 §2) — regression guard for `your_scopes: []`.
 *
 * A client that registers through Dynamic Client Registration WITHOUT a
 * `scope` member (ChatGPT's MCP connector does this) must be registered with
 * DCR_DEFAULT_SCOPE ('read'), not ''. Pre-fix the empty registered scope
 * propagated through /authorize (clamped to the registered grant), the auth
 * code, the access + refresh tokens and every refresh — so every read
 * operation failed `insufficient_scope … your_scopes: []` and the grant never
 * self-healed. Explicit scope requests are unchanged; write/admin stay gated.
 */
import { describe, test, expect, beforeAll, afterAll, beforeEach } from 'bun:test';
import { PGLiteEngine } from '../src/core/pglite-engine.ts';
import { GBrainOAuthProvider } from '../src/core/oauth-provider.ts';
import { sqlQueryForEngine } from '../src/core/sql-query.ts';
import { hasScope, DCR_DEFAULT_SCOPE } from '../src/core/scope.ts';

let engine: PGLiteEngine;
let provider: GBrainOAuthProvider;
let sql: ReturnType<typeof sqlQueryForEngine>;

beforeAll(async () => {
  engine = new PGLiteEngine();
  await engine.connect({});
  await engine.initSchema();
  sql = sqlQueryForEngine(engine);
  provider = new GBrainOAuthProvider({ sql });
});
afterAll(async () => { await engine.disconnect(); });
beforeEach(async () => {
  await (engine as any).db.exec('DELETE FROM oauth_tokens');
  await (engine as any).db.exec('DELETE FROM oauth_codes');
  await (engine as any).db.exec('DELETE FROM oauth_clients');
});

// Production shape of the ChatGPT connector registration (public PKCE client,
// no `scope` member) — captured from the AbrainOAG oauth_clients row.
const REDIRECT = 'https://chatgpt.com/connector/oauth/pHte3024gEMH';
const chatgptRegistration = (scope?: string) => ({
  client_name: 'ChatGPT',
  redirect_uris: [REDIRECT],
  grant_types: ['authorization_code', 'refresh_token'],
  token_endpoint_auth_method: 'none',
  ...(scope !== undefined ? { scope } : {}),
});

let redirected = '';
const res = { redirect(url: string) { redirected = url; } } as any;

/** Full public-client flow: DCR → /authorize (no scope) → code exchange → verify. */
async function registerAuthorizeExchange(scope?: string) {
  const reg = await provider.clientsStore.registerClient!(chatgptRegistration(scope) as any);
  const client = (await provider.clientsStore.getClient(reg.client_id))!;
  await provider.authorize(client, { scopes: [], codeChallenge: 'c', redirectUri: REDIRECT, state: 's' } as any, res);
  const code = new URL(redirected).searchParams.get('code')!;
  const tokens = await provider.exchangeAuthorizationCode(client, code, undefined, REDIRECT);
  const info = await provider.verifyAccessToken(tokens.access_token);
  return { reg, client, tokens, info };
}

describe('DCR registration that omits scope (your_scopes: [] regression)', () => {
  test('DCR_DEFAULT_SCOPE is read', () => {
    expect(DCR_DEFAULT_SCOPE).toBe('read');
  });

  test('stored client scope defaults to read, and the registration response echoes it', async () => {
    const reg = await provider.clientsStore.registerClient!(chatgptRegistration() as any);
    expect(reg.scope).toBe('read');
    const rows = (await sql`SELECT scope FROM oauth_clients WHERE client_id = ${reg.client_id}`) as Array<{ scope: string }>;
    expect(rows[0].scope).toBe('read');
  });

  test('authorize without scope → code, access token and refresh all carry read', async () => {
    const { client, tokens, info } = await registerAuthorizeExchange();
    expect(info.scopes).toEqual(['read']);
    expect(hasScope(info.scopes, 'read')).toBe(true);
    const refreshed = await provider.exchangeRefreshToken(client, tokens.refresh_token!, undefined);
    const info2 = await provider.verifyAccessToken(refreshed.access_token);
    expect(info2.scopes).toEqual(['read']);
  });

  test('default grant does NOT satisfy write or admin (protected ops stay gated)', async () => {
    const { info } = await registerAuthorizeExchange();
    expect(hasScope(info.scopes, 'write')).toBe(false);
    expect(hasScope(info.scopes, 'admin')).toBe(false);
    expect(hasScope(info.scopes, 'sources_admin')).toBe(false);
    expect(hasScope(info.scopes, 'users_admin')).toBe(false);
    expect(hasScope(info.scopes, 'agent')).toBe(false);
  });

  test('explicit scope request is stored as sent (no default applied)', async () => {
    const reg = await provider.clientsStore.registerClient!(chatgptRegistration('read write') as any);
    expect(reg.scope).toBe('read write');
    const { info } = await registerAuthorizeExchange('read write');
    expect(info.scopes.sort()).toEqual(['read', 'write']);
  });

  test('explicit empty-string scope is treated as omitted', async () => {
    const reg = await provider.clientsStore.registerClient!(chatgptRegistration('') as any);
    expect(reg.scope).toBe('read');
  });

  test('unknown scope is still rejected (allowlist unchanged)', async () => {
    await expect(provider.clientsStore.registerClient!(chatgptRegistration('bogus') as any)).rejects.toThrow(/Unknown scope/);
  });
});
