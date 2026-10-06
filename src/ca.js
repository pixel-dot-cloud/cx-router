'use strict';
// Local CA for the router. The CA is name-constrained: even if its key leaked, it
// could only ever produce certificates valid for ALLOWED_HOSTS (OpenSSL enforces this).
const { execFileSync } = require('node:child_process');
const { X509Certificate } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ALLOWED_HOSTS = ['api.anthropic.com'];

const cxHome = () => process.env.CX_HOME || path.join(os.homedir(), '.cx');

function openssl(args) {
  return execFileSync('openssl', args, { stdio: ['ignore', 'pipe', 'pipe'] });
}

function caPaths(dir) {
  return { keyPath: path.join(dir, 'ca.key'), certPath: path.join(dir, 'ca.pem') };
}

function initCA(dir = cxHome()) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  const { keyPath, certPath } = caPaths(dir);
  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) return { keyPath, certPath, created: false };
  const constraints = ALLOWED_HOSTS.map((h) => `permitted;DNS:${h}`).join(',');
  const oldUmask = process.umask(0o077);
  try {
    openssl([
      'req', '-x509', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-keyout', keyPath, '-out', certPath, '-days', '825', '-sha256',
      '-subj', '/CN=cx-router local CA (name-constrained)',
      '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
      '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
      '-addext', `nameConstraints=critical,${constraints}`,
    ]);
  } finally {
    process.umask(oldUmask);
  }
  fs.chmodSync(keyPath, 0o600);
  return { keyPath, certPath, created: true };
}

// Returns { key, cert } (PEM buffers) for a leaf valid for `host`, minting or renewing it.
function leafFor(dir, host) {
  if (!ALLOWED_HOSTS.includes(host)) throw new Error(`cx: refusing to mint a certificate for ${host}`);
  const leafKey = path.join(dir, `leaf-${host}.key`);
  const leafCert = path.join(dir, `leaf-${host}.pem`);
  if (fs.existsSync(leafKey) && fs.existsSync(leafCert)) {
    try {
      const c = new X509Certificate(fs.readFileSync(leafCert));
      if (new Date(c.validTo).getTime() - Date.now() > 2 * 86400e3) {
        return { key: fs.readFileSync(leafKey), cert: fs.readFileSync(leafCert) };
      }
    } catch {
      // unreadable: fall through and mint a new one
    }
  }
  const { keyPath, certPath } = caPaths(dir);
  const csr = path.join(dir, `leaf-${host}.csr`);
  const ext = path.join(dir, `leaf-${host}.ext`);
  fs.writeFileSync(
    ext,
    `subjectAltName=DNS:${host}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n`,
  );
  const oldUmask = process.umask(0o077);
  try {
    openssl([
      'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-keyout', leafKey, '-out', csr, '-subj', `/CN=${host}`,
    ]);
    openssl([
      'x509', '-req', '-in', csr, '-CA', certPath, '-CAkey', keyPath, '-CAcreateserial',
      '-out', leafCert, '-days', '30', '-sha256', '-extfile', ext,
    ]);
  } finally {
    process.umask(oldUmask);
    fs.rmSync(csr, { force: true });
    fs.rmSync(ext, { force: true });
  }
  return { key: fs.readFileSync(leafKey), cert: fs.readFileSync(leafCert) };
}

module.exports = { ALLOWED_HOSTS, cxHome, initCA, leafFor, caPaths };
