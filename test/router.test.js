'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const tls = require('node:tls');
const { initCA, leafFor } = require('../src/ca');
const { createRouter } = require('../src/router');

const HOST = 'api.anthropic.com';
const openClosers = [];
test.after(() => { for (const c of openClosers) c(); });

function listen(server, host = '127.0.0.1') {
  return new Promise((resolve) => server.listen(0, host, () => resolve(server.address().port)));
}

// Open a TLS connection to `host` through the router's CONNECT, trusting `ca`.
function connectThrough(routerPort, host, port, ca) {
  return new Promise((resolve, reject) => {
    const s = net.connect(routerPort, '127.0.0.1', () => s.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`));
    s.once('data', (d) => {
      if (!/^HTTP\/1\.1 200/.test(d.toString())) return reject(new Error(`CONNECT failed: ${d.toString().split('\r\n')[0]}`));
      resolve(tls.connect({ socket: s, servername: host, ca }));
    });
    s.on('error', reject);
  });
}

function request(secure, { method = 'GET', path: p = '/', headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const agent = new https.Agent({ keepAlive: false });
    agent.createConnection = () => secure;
    const req = https.request({ host: HOST, method, path: p, headers, agent }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push({ at: Date.now(), c }));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, chunks }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function setup(routerOpts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-test-'));
  const { certPath } = initCA(dir);
  const ca = fs.readFileSync(certPath);
  const seen = [];
  const { key, cert } = leafFor(dir, HOST);
  const upstream = https.createServer({ key, cert }, (req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, host: req.headers.host, body: Buffer.concat(chunks).toString() });
      if (req.url === '/stream') {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.write('event: a\n\n');
        setTimeout(() => { res.write('event: b\n\n'); res.end(); }, 150);
      } else {
        res.writeHead(201, { 'content-type': 'application/json', 'x-up': 'yes' });
        res.end(JSON.stringify({ ok: true }));
      }
    });
  });
  const upPort = await listen(upstream);
  const logs = [];
  const router = createRouter({ caDir: dir, upstream: { host: '127.0.0.1', port: upPort, ca }, log: (l) => logs.push(l), ...routerOpts });
  const rPort = await listen(router);
  const close = () => { router.close(); upstream.close(); router.closeAllConnections?.(); upstream.closeAllConnections?.(); };
  openClosers.push(close);
  return { dir, ca, seen, logs, rPort, close };
}

test('passthrough keeps method, path, auth header and body intact', async () => {
  const t = await setup();
  const secure = await connectThrough(t.rPort, HOST, 443, t.ca);
  const res = await request(secure, {
    method: 'POST', path: '/v1/messages?beta=true',
    headers: { authorization: 'Bearer sk-test-123', 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'claude-sonnet-5-5', messages: [] }),
  });
  assert.equal(res.status, 201);
  assert.equal(res.headers['x-up'], 'yes');
  assert.deepEqual(t.seen[0], {
    method: 'POST', url: '/v1/messages?beta=true', auth: 'Bearer sk-test-123', host: HOST,
    body: JSON.stringify({ model: 'claude-sonnet-5-5', messages: [] }),
  });
  secure.destroy();
  t.close();
});

test('streaming responses are not buffered', async () => {
  const t = await setup();
  const secure = await connectThrough(t.rPort, HOST, 443, t.ca);
  const res = await request(secure, { path: '/stream' });
  assert.equal(res.status, 200);
  const joined = Buffer.concat(res.chunks.map((x) => x.c)).toString();
  assert.match(joined, /event: a[\s\S]*event: b/);
  assert.ok(res.chunks.length >= 2 && res.chunks.at(-1).at - res.chunks[0].at >= 100, 'chunks arrive over time');
  secure.destroy();
  t.close();
});

test('other hosts are blind tunnels', async () => {
  const t = await setup();
  const echo = net.createServer((s) => s.on('data', (d) => s.write(Buffer.concat([Buffer.from('echo:'), d]))));
  const echoPort = await listen(echo);
  const reply = await new Promise((resolve, reject) => {
    const s = net.connect(t.rPort, '127.0.0.1', () => s.write(`CONNECT 127.0.0.1:${echoPort} HTTP/1.1\r\nHost: x\r\n\r\n`));
    let stage = 0;
    s.on('data', (d) => {
      if (stage === 0) { stage = 1; assert.match(d.toString(), /^HTTP\/1\.1 200/); s.write('hello'); } else { resolve(d.toString()); s.destroy(); }
    });
    s.on('error', reject);
  });
  assert.equal(reply, 'echo:hello');
  assert.ok(!fs.readdirSync(t.dir).some((f) => f.includes('127.0.0.1')), 'no certificate minted for a tunneled host');
  echo.close();
  t.close();
});

test('the CA refuses to mint certificates for other hosts', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-test-'));
  initCA(dir);
  assert.throws(() => leafFor(dir, 'example.com'), /refusing to mint/);
});

test('peekModel logs only the model name, never headers or bodies', async () => {
  const t = await setup({ peekModel: true });
  const secure = await connectThrough(t.rPort, HOST, 443, t.ca);
  await request(secure, {
    method: 'POST', path: '/v1/messages', headers: { authorization: 'Bearer SECRET-TOKEN', 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'gpt-6-luna', messages: [{ role: 'user', content: 'SECRET-PROMPT' }] }),
  });
  const all = t.logs.join('\n');
  assert.match(all, /model=gpt-6-luna/);
  assert.ok(!all.includes('SECRET-TOKEN') && !all.includes('SECRET-PROMPT'));
  secure.destroy();
  t.close();
});
