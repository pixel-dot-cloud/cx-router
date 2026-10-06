#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { cxHome, initCA, caPaths } = require('../src/ca');
const { createRouter } = require('../src/router');

const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 && args[i + 1] ? args[i + 1] : dflt;
};

function usage() {
  console.log(`cx - local router (experiment A: passthrough)

  cx login [--port N]      Sign in with ChatGPT (browser consent), saves credentials in ${cxHome()}/accounts
  cx accounts              list saved ChatGPT accounts (no secrets shown)
  cx ca init               create the name-constrained local CA in ${cxHome()}
  cx ca path               print the CA certificate path
  cx start [--port N] [--peek-model]
                           run the loopback proxy (default port 8319); --peek-model logs the
                           "model" field of /v1/messages requests (no headers or bodies are logged)`);
}

const [cmd, sub] = args;
if (cmd === 'login') {
  const { login } = require('../src/siwc');
  login({ port: Number(opt('--port', 1455)), log: (l) => console.log(l) })
    .then((r) => {
      console.log(`\nSigned in as ${r.email || r.subject}`);
      console.log(`client_id: ${r.clientId}`);
      console.log(`scopes: ${r.scopes.join(' ')}`);
      console.log(`credentials saved: ${r.file} (mode 0600)`);
    })
    .catch((e) => { console.error(`cx login failed: ${e.message}`); process.exit(1); });
} else if (cmd === 'accounts') {
  const { listAccounts } = require('../src/siwc');
  const rows = listAccounts();
  if (!rows.length) console.log('no saved accounts (run: cx login)');
  for (const r of rows) console.log(`${r.email || r.subject}  client_id=${r.clientId}  saved=${r.savedAt}  scopes=${(r.scopes || []).length}`);
} else if (cmd === 'ca' && sub === 'init') {
  const r = initCA();
  console.log(`${r.created ? 'created' : 'already exists'}: ${r.certPath}`);
} else if (cmd === 'ca' && sub === 'path') {
  console.log(caPaths(cxHome()).certPath);
} else if (cmd === 'start') {
  const port = Number(opt('--port', process.env.CX_PORT || 8319));
  initCA();
  const logPath = opt('--log-file', path.join(cxHome(), 'router.log'));
  const logStream = fs.createWriteStream(logPath, { flags: 'a', mode: 0o600 });
  const router = createRouter({
    caDir: cxHome(),
    peekModel: flag('--peek-model'),
    log: (line) => {
      const out = `${new Date().toISOString()} ${line}`;
      console.log(out);
      logStream.write(`${out}\n`);
    },
  });
  router.listen(port, '127.0.0.1', () => console.log(`cx router listening on 127.0.0.1:${port}`));
  for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => router.close(() => process.exit(0)));
} else {
  usage();
}
