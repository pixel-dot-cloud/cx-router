'use strict';
// Loopback HTTP CONNECT proxy. Experiment A: pure passthrough.
//  - CONNECT to a MITM host (api.anthropic.com:443): terminate TLS with a name-constrained
//    local CA and forward every request byte-for-byte to the real host.
//  - CONNECT to anything else: blind TCP tunnel (never inspected).
//  - Plain http:// proxy requests: simple forward.
// Headers (auth included) and bodies are never logged. Only method, path, status, timing and,
// with peekModel, the `model` field of /v1/messages bodies.
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const tls = require('node:tls');
const { leafFor } = require('./ca');

const HOP = new Set([
  'connection', 'keep-alive', 'proxy-connection', 'proxy-authorization', 'te', 'trailer',
  'transfer-encoding', 'upgrade', 'expect',
]);
const MAX_PEEK_BYTES = 64 * 1024 * 1024;

function cleanHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h)) if (!HOP.has(k)) out[k] = v;
  return out;
}

function cleanRaw(raw) {
  const out = [];
  for (let i = 0; i < raw.length; i += 2) if (!HOP.has(raw[i].toLowerCase())) out.push(raw[i], raw[i + 1]);
  return out;
}

function splitHostPort(target) {
  const m = /^\[(.+)\]:(\d+)$/.exec(target) || /^([^:]+):?(\d*)$/.exec(target);
  return m ? [m[1], Number(m[2]) || 443] : [target, 443];
}

const pathOnly = (url) => url.split('?')[0];

function createRouter(opts) {
  const { caDir, mitmHosts = ['api.anthropic.com'], upstream = {}, peekModel = false, log = () => {} } = opts;

  function fail(res, err) {
    log(`upstream error: ${err && err.code ? err.code : 'unknown'}`);
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ type: 'error', error: { type: 'api_error', message: 'cx-router: upstream request failed' } }));
    } else {
      res.destroy();
    }
  }

  function forward(req, res) {
    const host = req.socket._cxHost;
    const started = Date.now();
    const send = (body, note) => {
      const headers = cleanHeaders(req.headers);
      headers.host = host;
      if (body) headers['content-length'] = String(body.length);
      const up = https.request(
        {
          host: upstream.host || host, port: upstream.port || 443, method: req.method, path: req.url,
          headers, servername: host, ca: upstream.ca, agent: false,
        },
        (ures) => {
          res.writeHead(ures.statusCode, ures.statusMessage, cleanRaw(ures.rawHeaders));
          ures.pipe(res);
          ures.on('end', () => log(`${req.method} ${host}${pathOnly(req.url)} -> ${ures.statusCode} ${Date.now() - started}ms${note || ''}`));
          ures.on('error', () => res.destroy());
        },
      );
      up.on('error', (e) => fail(res, e));
      res.on('close', () => { if (!res.writableEnded) up.destroy(); });
      if (body) up.end(body); else req.pipe(up);
    };

    if (peekModel && req.method === 'POST' && pathOnly(req.url).startsWith('/v1/messages')) {
      const chunks = [];
      let size = 0;
      req.on('data', (c) => {
        size += c.length;
        if (size > MAX_PEEK_BYTES) { req.destroy(); return; }
        chunks.push(c);
      });
      req.on('end', () => {
        const body = Buffer.concat(chunks);
        let note = '';
        try {
          const j = JSON.parse(body.toString('utf8'));
          if (j && typeof j.model === 'string') {
            const msgs = Array.isArray(j.messages) ? j.messages.length : 0;
            const tools = Array.isArray(j.tools) ? j.tools.length : 0;
            note = ` model=${j.model} msgs=${msgs} tools=${tools} stream=${j.stream === true}`;
          }
        } catch {
          // not JSON: forward untouched
        }
        send(body, note);
      });
      req.on('error', () => res.destroy());
      return;
    }
    send();
  }

  const mitmServer = http.createServer(forward);
  mitmServer.requestTimeout = 0;
  mitmServer.headersTimeout = 0;

  const tlsServers = new Map();
  for (const host of mitmHosts) {
    const { key, cert } = leafFor(caDir, host); // fail fast if the CA is missing
    const srv = tls.createServer({ key, cert, ALPNProtocols: ['http/1.1'] }, (secure) => {
      secure._cxHost = host;
      mitmServer.emit('connection', secure);
    });
    srv.on('tlsClientError', () => {});
    tlsServers.set(host, srv);
  }

  const proxy = http.createServer((req, res) => {
    if (req.url === '/__cx/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end('{"ok":true}');
    }
    let u;
    try { u = new URL(req.url); } catch { res.writeHead(400); return res.end(); }
    if (u.protocol !== 'http:') { res.writeHead(400); return res.end(); }
    const started = Date.now();
    const up = http.request(
      { host: u.hostname, port: u.port || 80, method: req.method, path: u.pathname + u.search, headers: cleanHeaders(req.headers), agent: false },
      (ures) => {
        res.writeHead(ures.statusCode, ures.statusMessage, cleanRaw(ures.rawHeaders));
        ures.pipe(res);
        ures.on('end', () => log(`${req.method} ${u.hostname}${u.pathname} -> ${ures.statusCode} ${Date.now() - started}ms (plain)`));
      },
    );
    up.on('error', (e) => fail(res, e));
    res.on('close', () => { if (!res.writableEnded) up.destroy(); });
    req.pipe(up);
  });
  proxy.requestTimeout = 0;

  proxy.on('connect', (req, clientSocket, head) => {
    const [host, port] = splitHostPort(req.url);
    clientSocket.on('error', () => {});
    const srv = port === 443 ? tlsServers.get(host) : undefined;
    if (srv) {
      log(`CONNECT ${host}:${port} (intercepted)`);
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) clientSocket.unshift(head);
      srv.emit('connection', clientSocket);
      return;
    }
    const opened = Date.now();
    const upstreamSock = net.connect(port, host, () => {
      log(`CONNECT ${host}:${port} (tunnel, not inspected)`);
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) upstreamSock.write(head);
      upstreamSock.pipe(clientSocket);
      clientSocket.pipe(upstreamSock);
    });
    upstreamSock.on('close', () => {
      log(`TUNNEL ${host}:${port} closed after ${((Date.now() - opened) / 1000).toFixed(1)}s up=${upstreamSock.bytesWritten}B down=${upstreamSock.bytesRead}B`);
    });
    upstreamSock.on('error', () => {
      if (!clientSocket.destroyed) {
        try { clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'); } catch { /* socket already gone */ }
      }
    });
    clientSocket.on('close', () => upstreamSock.destroy());
    upstreamSock.on('close', () => clientSocket.destroy());
  });

  return proxy;
}

module.exports = { createRouter };
