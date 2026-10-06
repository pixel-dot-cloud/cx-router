'use strict';
// "Sign in with ChatGPT" (SIWC) open-source plan-usage login, per
// https://developers.openai.com/siwc/token-sharing-open-source/sign-in
//
// Nothing here talks to OpenAI before the user has consented in the browser: login() opens the
// authorization URL (the consent screen) and only after the loopback callback does it exchange
// the code, load OpenAI's discovery document + JWKS, and verify the ID token.
// Tokens are never printed or logged.
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { cxHome } = require('./ca');

const ISSUER = 'https://auth.openai.com';
const AUTHORIZE_URL = `${ISSUER}/api/accounts/authorize`;
const TOKEN_URL = `${ISSUER}/api/accounts/oauth/token`;
const DISCOVERY_URL = `${ISSUER}/.well-known/openid-configuration`;
const RESOURCE = 'https://api.openai.com/v1';
const SCOPE = 'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct';
const REQUIRED_SCOPE = 'chatgpt.tokens.use.direct';
const APP_NAME = 'cx-router';
const DYNAMIC_CLIENT = 'dynamic_agent_client';
const CALLBACK_PATH = '/auth/callback';

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const randomToken = (bytes = 32) => b64url(crypto.randomBytes(bytes));
const sha256b64url = (s) => b64url(crypto.createHash('sha256').update(s).digest());

function newPkce() {
  const verifier = randomToken(48);
  return { verifier, challenge: sha256b64url(verifier) };
}

// Stable per-host id, persisted so the same host always sends the same value.
function getHostId(dir = cxHome()) {
  const file = path.join(dir, 'host-id');
  try {
    const existing = fs.readFileSync(file, 'utf8').trim();
    if (existing) return existing;
  } catch {
    // first run
  }
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const id = `urn:uuid:${crypto.randomUUID()}`;
  fs.writeFileSync(file, `${id}\n`, { mode: 0o600 });
  return id;
}

function buildAuthorizeUrl(p) {
  const q = new URLSearchParams({
    client_id: p.clientId || DYNAMIC_CLIENT,
    ext_agent_host_id: p.hostId,
    response_type: 'code',
    redirect_uri: p.redirectUri,
    scope: SCOPE,
    resource: RESOURCE,
    state: p.state,
    nonce: p.nonce,
    code_challenge_method: 'S256',
    code_challenge: p.challenge,
  });
  if (!p.clientId) q.set('agent_name_hint', p.agentName || APP_NAME); // new registration only
  if (p.idTokenHint) q.set('id_token_hint', p.idTokenHint);
  if (p.loginHint) q.set('login_hint', p.loginHint);
  return `${AUTHORIZE_URL}?${q.toString()}`;
}

function decodeJwt(token) {
  const parts = String(token).split('.');
  if (parts.length !== 3) throw new Error('malformed ID token');
  const json = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));
  return { header: json(parts[0]), payload: json(parts[1]), signed: `${parts[0]}.${parts[1]}`, signature: Buffer.from(parts[2], 'base64url') };
}

// Verifies signature (RS256/ES256 only), issuer, audience, expiry and nonce. Throws on any failure.
function verifyIdToken(idToken, { jwks, issuer, audience, nonce, now = Date.now(), skewSec = 60 }) {
  const { header, payload, signed, signature } = decodeJwt(idToken);
  if (header.alg !== 'RS256' && header.alg !== 'ES256') throw new Error(`ID token: unsupported alg ${header.alg}`);
  const keys = (jwks && jwks.keys) || [];
  const jwk = header.kid ? keys.find((k) => k.kid === header.kid) : keys.length === 1 ? keys[0] : undefined;
  if (!jwk) throw new Error('ID token: signing key not found in JWKS');
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const ok = header.alg === 'RS256'
    ? crypto.verify('sha256', Buffer.from(signed), key, signature)
    : crypto.verify('sha256', Buffer.from(signed), { key, dsaEncoding: 'ieee-p1363' }, signature);
  if (!ok) throw new Error('ID token: bad signature');
  if (payload.iss !== issuer) throw new Error('ID token: wrong issuer');
  const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!aud.includes(audience)) throw new Error('ID token: wrong audience');
  if (typeof payload.exp !== 'number' || payload.exp * 1000 < now - skewSec * 1000) throw new Error('ID token: expired');
  if (nonce !== undefined && payload.nonce !== nonce) throw new Error('ID token: nonce mismatch');
  if (!payload.sub) throw new Error('ID token: missing sub');
  return payload;
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function listen(server, port) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server.address().port));
  });
}

// Starts the loopback listener; resolves with the callback's query params once it arrives.
function startCallbackServer(port, timeoutMs = 5 * 60 * 1000) {
  let done;
  const result = new Promise((resolve, reject) => { done = { resolve, reject }; });
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');
    if (u.pathname !== CALLBACK_PATH) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end('<!doctype html><title>cx-router</title><p>Signed in. You can close this tab and return to the terminal.</p>');
    done.resolve(Object.fromEntries(u.searchParams.entries()));
  });
  const timer = setTimeout(() => done.reject(new Error('sign-in timed out')), timeoutMs);
  const close = () => { clearTimeout(timer); server.closeAllConnections?.(); server.close(); };
  return listen(server, port).then((actualPort) => ({ actualPort, result, close }));
}

function openInBrowser(url) {
  try {
    const child = spawn('xdg-open', [url], { stdio: 'ignore', detached: true });
    child.on('error', () => {});
    child.unref();
  } catch {
    // the URL is printed as well
  }
}

async function postForm(fetchFn, url, fields) {
  const res = await fetchFn(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: new URLSearchParams(fields).toString(),
    signal: AbortSignal.timeout(30000),
  });
  let body;
  try { body = await res.json(); } catch { body = {}; }
  if (!res.ok) throw new Error(`token endpoint: ${body.error || res.status}${body.error_description ? ` (${body.error_description})` : ''}`);
  return body;
}

async function getJson(fetchFn, url) {
  const res = await fetchFn(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(20000) });
  if (!res.ok) throw new Error(`GET ${new URL(url).pathname}: HTTP ${res.status}`);
  return res.json();
}

function saveCredentials(dir, record) {
  const accounts = path.join(dir, 'accounts');
  fs.mkdirSync(accounts, { recursive: true, mode: 0o700 });
  const id = sha256b64url(`${record.issuer}|${record.subject}|${record.client_id}`).slice(0, 16);
  const file = path.join(accounts, `${id}.json`);
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(tmp, file);
  return file;
}

// Full first-time sign-in. `fetchFn` and `openBrowser` are injectable for tests.
async function login({ dir = cxHome(), port = 1455, fetchFn = fetch, openBrowser = openInBrowser, log = () => {}, agentName = APP_NAME, now = Date.now } = {}) {
  const hostId = getHostId(dir);
  const { verifier, challenge } = newPkce();
  const state = randomToken(24);
  const nonce = randomToken(24);
  const cb = await startCallbackServer(port);
  try {
    const redirectUri = `http://127.0.0.1:${cb.actualPort}${CALLBACK_PATH}`;
    const url = buildAuthorizeUrl({ hostId, redirectUri, state, nonce, challenge, agentName });
    log('Opening the browser to sign in. If it does not open, visit this URL:');
    log(url);
    openBrowser(url);
    const params = await cb.result;

    if (!params.state || !safeEqual(params.state, state)) throw new Error('sign-in: state mismatch, aborting');
    if (params.error === 'access_denied') throw new Error('sign-in: access denied (ChatGPT plan use was not authorized)');
    if (params.error) throw new Error(`sign-in: ${params.error}`);
    if (!params.code) throw new Error('sign-in: callback had no code');
    if (!params.client_id || params.client_id === DYNAMIC_CLIENT) throw new Error('sign-in: registration incomplete (no issued client_id)');

    const tokens = await postForm(fetchFn, TOKEN_URL, {
      client_id: params.client_id, code: params.code, code_verifier: verifier,
      redirect_uri: redirectUri, resource: RESOURCE, grant_type: 'authorization_code',
    });
    for (const f of ['access_token', 'refresh_token', 'id_token']) if (!tokens[f]) throw new Error(`token response missing ${f}`);

    const discovery = await getJson(fetchFn, DISCOVERY_URL);
    if (discovery.issuer !== ISSUER) throw new Error('discovery: unexpected issuer');
    const jwks = await getJson(fetchFn, discovery.jwks_uri);
    const claims = verifyIdToken(tokens.id_token, { jwks, issuer: ISSUER, audience: params.client_id, nonce, now: now() });

    const granted = String(tokens.scope || params.scope || '').split(/[\s+]+/).filter(Boolean);
    if (!granted.includes(REQUIRED_SCOPE)) throw new Error(`sign-in: ${REQUIRED_SCOPE} was not granted; ChatGPT plan usage is not authorized`);

    const record = {
      email: claims.email || null,
      issuer: ISSUER,
      subject: claims.sub,
      client_id: params.client_id,
      ext_agent_host_id: hostId,
      id_token: tokens.id_token,
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
      token_type: tokens.token_type || 'Bearer',
      expires_in: tokens.expires_in,
      scopes: granted.sort(),
      saved_at: new Date(now()).toISOString(),
    };
    const file = saveCredentials(dir, record);
    return { email: record.email, subject: record.subject, clientId: record.client_id, scopes: record.scopes, file };
  } finally {
    cb.close();
  }
}

// Account list WITHOUT secrets.
function listAccounts(dir = cxHome()) {
  const accounts = path.join(dir, 'accounts');
  let files = [];
  try { files = fs.readdirSync(accounts).filter((f) => f.endsWith('.json')); } catch { return []; }
  return files.map((f) => {
    const r = JSON.parse(fs.readFileSync(path.join(accounts, f), 'utf8'));
    return { file: f, email: r.email, subject: r.subject, clientId: r.client_id, scopes: r.scopes, savedAt: r.saved_at };
  });
}

module.exports = {
  ISSUER, SCOPE, REQUIRED_SCOPE, CALLBACK_PATH, newPkce, sha256b64url, getHostId, buildAuthorizeUrl,
  verifyIdToken, login, listAccounts, saveCredentials,
};
