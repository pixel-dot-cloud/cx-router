# cx-router

A small local router with one goal: let Claude Code subagents run OpenAI models that you pay for
through your own ChatGPT plan, using OpenAI's official
[Sign in with ChatGPT](https://developers.openai.com/siwc/token-sharing-open-source) plan-usage flow
for open-source and locally hosted apps.

**Status: work in progress.** Not affiliated with, endorsed by, or supported by Anthropic or OpenAI.

## Built
- **`cx login`**: browser sign-in with ChatGPT (OAuth + PKCE, loopback callback). It follows the
  published open-source flow: dynamic client registration, ID-token verification (signature, issuer,
  audience, expiry, nonce) and a check that ChatGPT plan usage was actually granted. Credentials are
  stored in `~/.cx/accounts/` with mode 0600. Tokens are never printed or logged.
- **`cx start`**: a loopback HTTP CONNECT proxy. Traffic to `api.anthropic.com` is terminated with a
  local, name-constrained CA and forwarded byte-for-byte; every other host is a blind TCP tunnel.
  Logs contain paths, statuses, timings and (for `/v1/messages`) the model name and counts, never
  headers, tokens or bodies.
- **`claude-x`**: launches `claude` through the router for that one process only
  (`HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS`). It never sets `ANTHROPIC_BASE_URL`.
- **`cx-kill`**: stops the router and any `claude-x` sessions; nothing system-wide is ever changed.
translating `gpt-*` requests (Anthropic Messages to OpenAI Responses and back) so those models can
back Claude Code subagents. Only the passthrough and the login exist so far.

## Security model

- The local CA is name-constrained to `api.anthropic.com`: even if its key leaked it could not sign a
  certificate for any other site. Nothing is added to your system trust store.
- The router listens on `127.0.0.1` only. A plain `claude` never goes through it.
- Sign-in must be completed by the owner of the ChatGPT account, in their own browser. This tool never
  sees a password. ChatGPT plan usage requires an eligible (Plus or Pro) plan, and the account owner
  sets the per-app usage cap in ChatGPT settings.

## Usage

```sh
node bin/cx.js ca init          # create the local CA in ~/.cx
node bin/cx.js login            # sign in with ChatGPT (browser consent)
node bin/cx.js start            # run the router (127.0.0.1:8319)
bin/claude-x                    # Claude Code through the router
bin/cx-kill                     # stop everything
npm test                        # tests (Node 22+, no dependencies)
```

## License

MIT
