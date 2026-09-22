# Standalone release inventory

- Worker/repository name: `whoami-identity-demo`
- Owned surface: Whoami explainer, request inspector, sanitized header JSON API, health endpoint, local assets, tests, and deployment configuration
- Runtime boundary: fully standalone; no shared Worker, shared source tree, or external application runtime dependency

## Visible page structure retained

### `/` explainer

1. Sticky navigation: brand, Home, AI Gateway, Factory, Try it.
2. Hero: Access/verified-identity eyebrow, “Who am I?” title, explanation, primary identity CTA, and back-to-home link.
3. “What happens” section: lead plus three cards for edge verification, injected headers, and spoofing protection.
4. “The flow” section: four numbered steps and a request-header example panel.
5. Closing identity CTA.
6. Exact public attribution footer.

Deployment-specific domains were replaced by safe same-origin links, and the standalone project name replaced shared-site branding. The hierarchy, section ordering, controls, and visual language remain intact. The shared Factory-style penguin background is a local WebP asset.

### `/headers` inspector

1. Sticky navigation: brand, Home, Who am I, AI Gateway, Factory.
2. Request-inspector eyebrow, title, lead, and external-policy notice.
3. Edge summary chips.
4. Optional signed-in identity summary.
5. Injected identity card and empty-state guidance.
6. Cloudflare edge-header card.
7. Other request metadata card.
8. Refresh, Raw JSON, raw-view toggle, and same-origin Access logout controls.
9. Exact public attribution footer.

The raw panel still fetches `/api/headers`, but it writes JSON through `textContent`. All displayed request values pass through bounded allowlists and HTML escaping.

### `/api/headers`

The public response shape retains `ok`, `authenticated_by`, `your_warp_team`, `injected_identity`, `cloudflare_edge`, `edge_info`, `other_headers`, and `hasIdentity`. `authenticated_by` is intentionally `null`: the standalone Worker does not decode or expose the Access token issuer. JWTs, authorization cookies, generic authorization values, and unlisted headers are never returned.

### `/healthz`

Returns `whoami ok` as plain text with the shared security headers.

## Deployment ownership

Worker source and Worker deployment are **Wrangler-managed**. `npm run check` validates tests, offline behavior, and a Wrangler dry-run. `npm run deploy` is only a wrapper for `wrangler deploy --keep-vars`; npm is not a second deployment owner.

Production custom-domain ownership and the existing Access OTP app are managed externally and intentionally not in this repository's Terraform. There is no Terraform in this repository; deployment is owned only by this repository's Wrangler-backed npm scripts or Wrangler directly.

The repository intentionally omits account IDs, routes, domains, Access audiences, identity-provider IDs, and secrets.
