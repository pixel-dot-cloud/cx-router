'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const siwc = require('../src/siwc');

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'test-key', alg: 'RS256', use: 'sig' };
const jwks = { keys: [jwk] };
const b64 = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');

function makeToken(payload, { alg = 'RS256', key = privateKey, kid = 'test-key' } = {}) {
  const head = b64({ alg, typ: 'JWT', kid });
  const body = b64(payload);
  const sig = alg === 'none' ? '' : crypto.sign('sha256', Buffer.from(`${head}.${body}`), key).toString('base64url');
  return `${head}.${body}.${sig}`;
}
const NOW = Date.UTC(2026, 9, 5, 12, 0, 0);
const good = (over = {}) => ({ iss: siwc.ISSUER, aud: 'oaiapp_test', sub: 'user-1', email: 'dad@example.com', nonce: 'n1', exp: NOW / 1000 + 3600, ...over });
const opts = (over = {}) => ({ jwks, issuer: siwc.ISSUER, audience: 'oaiapp_test', nonce: 'n1', now: NOW, ...over });

test('PKCE challenge matches the RFC 7636 test vector', () => {
  assert.equal(siwc.sha256b64url('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  const { verifier, challenge } = siwc.newPkce();
  assert.equal(siwc.sha256b64url(verifier), challenge);
});

test('authorize URL carries every required parameter; agent_name_hint only on first registration', () => {
  const base = { hostId: 'urn:uuid:x', redirectUri: 'http://127.0.0.1:1455/auth/callback', state: 's', nonce: 'n', challenge: 'c' };
  const first = new URL(siwc.buildAuthorizeUrl(base)).searchParams;
  assert.equal(first.get('client_id'), 'dynamic_agent_client');
  assert.equal(first.get('agent_name_hint'), 'cx-router');
  assert.equal(first.get('ext_agent_host_id'), 'urn:uuid:x');
  assert.equal(first.get('response_type'), 'code');
  assert.equal(first.get('redirect_uri'), base.redirectUri);
  assert.equal(first.get('resource'), 'https://api.openai.com/v1');
  assert.equal(first.get('scope'), 'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct');
  assert.equal(first.get('code_challenge_method'), 'S256');
  const again = new URL(siwc.buildAuthorizeUrl({ ...base, clientId: 'oaiapp_abc', idTokenHint: 'tok' })).searchParams;
  assert.equal(again.get('client_id'), 'oaiapp_abc');
  assert.equal(again.get('agent_name_hint'), null);
  assert.equal(again.get('id_token_hint'), 'tok');
});

test('verifyIdToken accepts a good token and rejects every bad one', () => {
  assert.equal(siwc.verifyIdToken(makeToken(good()), opts()).sub, 'user-1');
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  assert.throws(() => siwc.verifyIdToken(makeToken(good(), { key: other }), opts()), /bad signature/);
  assert.throws(() => siwc.verifyIdToken(makeToken(good({ iss: 'https://evil.example' })), opts()), /wrong issuer/);
  assert.throws(() => siwc.verifyIdToken(makeToken(good({ aud: 'someone-else' })), opts()), /wrong audience/);
  assert.throws(() => siwc.verifyIdToken(makeToken(good({ nonce: 'other' })), opts()), /nonce mismatch/);
  assert.throws(() => siwc.verifyIdToken(makeToken(good({ exp: NOW / 1000 - 3600 })), opts()), /expired/);
  assert.throws(() => siwc.verifyIdToken(makeToken(good(), { alg: 'none' }), opts()), /unsupported alg/);
  assert.throws(() => siwc.verifyIdToken(makeToken(good(), { kid: 'unknown' }), opts()), /key not found/);
  assert.throws(() => siwc.verifyIdToken('not.a.jwt.at.all', opts()), /malformed/);
});

// Fake browser: follows the authorize URL's redirect straight to the loopback callback.
function fakeBrowser(overrides = {}) {
  return (url) => {
    const q = new URL(url).searchParams;
    const cb = new URL(q.get('redirect_uri'));
    cb.searchParams.set('code', 'the-code');
    cb.searchParams.set('state', overrides.state ?? q.get('state'));
    cb.searchParams.set('scope', 'chatgpt.tokens.use.direct email offline_access openid profile resource.invoke');
    cb.searchParams.set('client_id', 'oaiapp_test');
    for (const [k, v] of Object.entries(overrides.params || {})) cb.searchParams.set(k, v);
    setTimeout(() => http.get(cb, (r) => r.resume()).on('error', () => {}), 20);
    overrides.seen?.push({ nonce: q.get('nonce') });
  };
}

function fakeFetch({ scope = 'chatgpt.tokens.use.direct email offline_access openid profile resource.invoke', calls, nonceBox }) {
  return async (url, init = {}) => {
    calls.push(String(url));
    const json = (o) => ({ ok: true, status: 200, json: async () => o });
    if (String(url).endsWith('/oauth/token')) {
      const form = new URLSearchParams(init.body);
      assert.equal(form.get('grant_type'), 'authorization_code');
      assert.equal(form.get('client_id'), 'oaiapp_test');
      assert.equal(form.get('code'), 'the-code');
      assert.ok(form.get('code_verifier') && form.get('redirect_uri') && form.get('resource') === 'https://api.openai.com/v1');
      return json({ access_token: 'AT', refresh_token: 'RT', id_token: makeToken(good({ nonce: nonceBox.nonce, exp: Date.now() / 1000 + 3600 })), token_type: 'Bearer', expires_in: 3600, scope });
    }
    if (String(url).endsWith('/.well-known/openid-configuration')) return json({ issuer: siwc.ISSUER, jwks_uri: `${siwc.ISSUER}/.well-known/jwks.json` });
    if (String(url).endsWith('/.well-known/jwks.json')) return json(jwks);
    throw new Error(`unexpected fetch ${url}`);
  };
}

test('login(): simulated happy path saves a 0600 credentials file and prints no tokens', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-siwc-'));
  const calls = [];
  const seen = [];
  const nonceBox = {};
  const logs = [];
  const browser = fakeBrowser({ seen });
  const r = await siwc.login({
    dir, port: 0, log: (l) => logs.push(l), fetchFn: fakeFetch({ calls, nonceBox }),
    openBrowser: (url) => { nonceBox.nonce = new URL(url).searchParams.get('nonce'); browser(url); },
  });
  assert.equal(r.email, 'dad@example.com');
  assert.equal(r.clientId, 'oaiapp_test');
  assert.ok(r.scopes.includes('chatgpt.tokens.use.direct'));
  assert.equal(fs.statSync(r.file).mode & 0o777, 0o600);
  const saved = JSON.parse(fs.readFileSync(r.file, 'utf8'));
  assert.equal(saved.access_token, 'AT');
  assert.equal(saved.refresh_token, 'RT');
  assert.ok(!logs.join('\n').includes('"AT"'));
  assert.ok(!('refresh_token' in r) && !('access_token' in r) && !('id_token' in r));
  assert.deepEqual(calls.map((u) => new URL(u).pathname), ['/api/accounts/oauth/token', '/.well-known/openid-configuration', '/.well-known/jwks.json']);
  assert.equal(siwc.listAccounts(dir)[0].email, 'dad@example.com');
  assert.ok(!('access_token' in siwc.listAccounts(dir)[0]));
});

test('login(): a state mismatch aborts before any request to OpenAI', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-siwc-'));
  const calls = [];
  await assert.rejects(
    siwc.login({ dir, port: 0, fetchFn: fakeFetch({ calls, nonceBox: {} }), openBrowser: fakeBrowser({ state: 'forged' }) }),
    /state mismatch/,
  );
  assert.equal(calls.length, 0);
  assert.deepEqual(siwc.listAccounts(dir), []);
});

test('login(): access_denied stops without exchanging a code; missing plan scope saves nothing', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-siwc-'));
  const calls = [];
  await assert.rejects(
    siwc.login({ dir, port: 0, fetchFn: fakeFetch({ calls, nonceBox: {} }), openBrowser: fakeBrowser({ params: { error: 'access_denied' } }) }),
    /access denied/,
  );
  assert.equal(calls.length, 0);

  const nonceBox = {};
  const browser = fakeBrowser();
  await assert.rejects(
    siwc.login({
      dir, port: 0, fetchFn: fakeFetch({ calls, nonceBox, scope: 'openid email' }),
      openBrowser: (url) => { nonceBox.nonce = new URL(url).searchParams.get('nonce'); browser(url); },
    }),
    /not granted/,
  );
  assert.deepEqual(siwc.listAccounts(dir), []);
});
