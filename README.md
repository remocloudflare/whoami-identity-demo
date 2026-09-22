# Whoami Identity Demo

A fully standalone Cloudflare Worker that explains edge-authenticated identity and shows a bounded, sanitized request-inspector view. It owns its UI, API routes, assets, tests, and deployment configuration without any shared-Worker runtime dependency.

## What it serves

- `/` — “Who am I?” explainer and one-time PIN flow overview.
- `/headers` — safe request-inspector UI.
- `/api/headers` — JSON form of the same allowlisted projection.
- `/healthz` — plain-text health response.
- `/assets/*` — local inspector JavaScript and Factory-style penguin background.

The production hostname may be protected by a public One-time PIN policy. Access is an external hostname policy: this Worker does not create, configure, or bypass it.

## Security model

The inspector uses explicit allowlists. Identity values are control-character stripped and capped at 256 characters. JWT assertions, authorization cookies, generic authorization headers, arbitrary request headers, tokens, and secrets are not projected into HTML or JSON. Request-derived text is HTML-escaped, raw JSON is rendered with `textContent`, and responses include CSP, frame, MIME-sniffing, referrer, permissions, and cross-origin isolation headers.

The allowlisted groups are:

- Identity: authenticated user identity plus selected `X-User-*` claims.
- Edge: selected Cloudflare connection and forwarding metadata.
- Request metadata: host, user agent, accepted content/encoding/language, and referrer.

## Requirements

- Node.js 22 or newer
- npm

## Local development

```sh
npm install
npm test
npm run verify
npx wrangler dev
```

Offline verification calls the Worker module directly. Live verification sends ordinary unauthenticated requests and accepts an external Access redirect as evidence that the hostname policy is active; it never supplies credentials or bypass headers:

```sh
node scripts/verify.mjs live https://<public-hostname>
```

## Deployment ownership

### Deploy your own

The Worker itself has no secrets or account-specific bindings:

```sh
git clone https://github.com/remocloudflare/whoami-identity-demo.git
cd whoami-identity-demo
npm ci
npm run check
npx wrangler login
npm run deploy
```

This publishes an independent `workers.dev` deployment in your authenticated Cloudflare account. Cloudflare Access, One-time PIN, and a custom hostname are optional external policies; deploying this repository does not create them.

Worker source and Worker deployment are **Wrangler-managed**. Use `npm run check` before a release, then use either `npm run deploy` or `npx wrangler deploy --keep-vars` when an authorized operator deliberately deploys. The npm scripts are wrappers around Wrangler, not a second deployment owner.

Production custom-domain ownership and the existing Access OTP app are managed externally and intentionally **not** represented in this repository's Terraform. There is no Terraform in this repository; deploy this standalone Worker only through its Wrangler-backed npm scripts or Wrangler directly.

The checked-in Wrangler config intentionally contains no account ID, route, domain, Access audience, identity-provider ID, or secret. Confirm the intended Cloudflare account in your authenticated Wrangler session before deployment. This repository does not deploy automatically.

## Verification

```sh
npm run check
```

This runs the Node built-in test suite, offline verifier, and `wrangler deploy --dry-run`. It does not deploy.

## Attribution

Built by Remo Mattei · Sr. Cloudflare One Specialist Solutions Engineer.
