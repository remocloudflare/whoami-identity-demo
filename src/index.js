const FOOTER = 'Built by Remo Mattei · Sr. Cloudflare One Specialist Solutions Engineer.';
const MAX_HEADER_VALUE = 256;

const IDENTITY_HEADERS = Object.freeze([
  'cf-access-authenticated-user-email',
  'x-user-email',
  'x-user-name',
  'x-user-groups',
  'x-user-team',
  'x-forwarded-user',
]);
const EDGE_HEADERS = Object.freeze([
  'cf-connecting-ip',
  'cf-ipcountry',
  'cf-ray',
  'cf-visitor',
  'x-forwarded-for',
  'x-forwarded-proto',
  'true-client-ip',
]);
const SAFE_REQUEST_HEADERS = Object.freeze([
  'host',
  'user-agent',
  'accept',
  'accept-encoding',
  'accept-language',
  'referer',
]);
const HEADER_DESC = Object.freeze({
  'cf-connecting-ip': "The visitor's IP as Cloudflare sees it.",
  'true-client-ip': 'Enterprise alias for the client IP.',
  'cf-ipcountry': 'Two-letter country Cloudflare geolocated the visitor to.',
  'cf-ray': 'Unique identifier for this request through Cloudflare.',
  'cf-visitor': 'JSON hint of the original scheme the browser used.',
  'x-forwarded-for': 'Bounded proxy chain received by the origin.',
  'x-forwarded-proto': 'Protocol the edge received the request on.',
  'cf-access-authenticated-user-email': 'Verified identity Cloudflare Access injected after login.',
  'x-user-team': 'WARP or Zero Trust team injected by an upstream Gateway policy.',
  'x-user-email': 'Identity injected by an upstream Gateway policy.',
  'x-user-name': 'Display name injected by an upstream Gateway policy.',
  'x-user-groups': 'Groups injected by an upstream Gateway policy.',
  host: 'Hostname the browser requested.',
  'user-agent': 'Browser or client software string.',
  accept: 'Content types the client accepts.',
  'accept-encoding': 'Compression methods the client accepts.',
  'accept-language': 'Preferred languages sent by the client.',
  referer: 'Page the visitor came from.',
});

const SECURITY_HEADERS = Object.freeze({
  'cache-control': 'no-store, no-cache, must-revalidate, max-age=0',
  'content-security-policy': "default-src 'none'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; script-src 'self'; style-src 'unsafe-inline'",
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'camera=(), geolocation=(), microphone=(), payment=(), usb=()',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
});

export function sanitizeHeaderValue(value, maxLength = MAX_HEADER_VALUE) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, maxLength);
}

export function escapeHTML(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function projectHeaders(headers, allowlist) {
  const projected = Object.create(null);
  for (const name of allowlist) {
    const value = headers.get(name);
    if (value !== null) projected[name] = sanitizeHeaderValue(value);
  }
  return projected;
}

function classifyIp(ip) {
  if (!ip) return null;
  if (ip.includes(':')) {
    const normalized = ip.toLowerCase();
    if (normalized === '::1') return { label: 'Loopback', public: false };
    if (normalized.startsWith('fe80')) return { label: 'Link-local', public: false };
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return { label: 'Private (ULA)', public: false };
    return { label: 'Public', public: true };
  }
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return { label: 'Unknown', public: null };
  const [a, b] = octets;
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return { label: 'Private (RFC1918)', public: false };
  if (a === 100 && b >= 64 && b <= 127) return { label: 'Carrier NAT (CGNAT)', public: false };
  if (a === 127) return { label: 'Loopback', public: false };
  if (a === 169 && b === 254) return { label: 'Link-local', public: false };
  return { label: 'Public', public: true };
}

export function collectHeaders(request) {
  const identity = projectHeaders(request.headers, IDENTITY_HEADERS);
  const edge = projectHeaders(request.headers, EDGE_HEADERS);
  const other = projectHeaders(request.headers, SAFE_REQUEST_HEADERS);
  const cf = request.cf || {};
  const ip = edge['cf-connecting-ip'] || edge['true-client-ip'] || (edge['x-forwarded-for'] || '').split(',')[0].trim() || null;
  const ipv6 = ip?.includes(':') ? ip : null;
  const ipv4 = ip && !ipv6 ? ip : null;
  const edgeInfo = {
    ip,
    ipv4,
    ipv6,
    ipClass: classifyIp(ip),
    near: [cf.city, cf.region, cf.country].filter(Boolean).map((value) => sanitizeHeaderValue(value, 128)).join(', ') || null,
    city: cf.city ? sanitizeHeaderValue(cf.city, 128) : null,
    country: cf.country ? sanitizeHeaderValue(cf.country, 16) : null,
    colo: cf.colo ? sanitizeHeaderValue(cf.colo, 16) : null,
    asn: Number.isSafeInteger(cf.asn) ? `AS${cf.asn}` : null,
    asOrganization: cf.asOrganization ? sanitizeHeaderValue(cf.asOrganization, 128) : null,
    httpProtocol: cf.httpProtocol ? sanitizeHeaderValue(cf.httpProtocol, 32) : null,
    tlsVersion: cf.tlsVersion ? sanitizeHeaderValue(cf.tlsVersion, 32) : null,
    warp: false,
    hub: null,
  };
  return { identity, edge, other, edgeInfo, hasIdentity: Object.keys(identity).length > 0 };
}

function responseHeaders(contentType) {
  return { ...SECURITY_HEADERS, 'content-type': contentType };
}

function htmlResponse(body, status = 200) {
  return new Response(body, { status, headers: responseHeaders('text/html; charset=utf-8') });
}

export function handleHeadersJson(request) {
  const headers = collectHeaders(request);
  return new Response(JSON.stringify({
    ok: true,
    authenticated_by: null,
    your_warp_team: headers.identity['x-user-team'] || null,
    injected_identity: headers.identity,
    cloudflare_edge: headers.edge,
    edge_info: headers.edgeInfo,
    other_headers: headers.other,
    hasIdentity: headers.hasIdentity,
  }, null, 2), { headers: responseHeaders('application/json; charset=utf-8') });
}

const SHARED_CSS = `
:root{--bg:#0a0d14;--fg:#eef2f7;--mut:#93a0b2;--bd:#28303d;--acc:#f6821f;--acc2:#fbbf24;--ok:#34d399}
*{box-sizing:border-box}html,body{margin:0;min-height:100%}body{color:var(--fg);font-family:Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;line-height:1.5;background:#050505 url('/assets/factory-bg.webp') center top/cover fixed no-repeat}body:before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse at 50% 18%,rgba(249,115,22,.15),transparent 58%),linear-gradient(180deg,rgba(5,5,5,.7),rgba(5,5,5,.94));pointer-events:none;z-index:-1}a{color:inherit;text-decoration:none}.topnav{position:sticky;top:0;z-index:40;background:rgba(10,13,20,.82);backdrop-filter:blur(12px);border-bottom:1px solid var(--bd)}.topnav-in{max-width:1100px;margin:auto;padding:12px 22px;display:flex;align-items:center;gap:20px}.brand{font-weight:800;display:flex;align-items:center;gap:8px}.logo{width:28px;height:28px;border-radius:7px;background:linear-gradient(135deg,var(--acc),var(--acc2));color:#07090e;display:grid;place-items:center;font-weight:900;font-size:12px}.sp{flex:1}.topnav a:not(.brand){color:var(--mut);font-size:13.5px}.topnav a:hover{color:var(--fg)}footer{color:var(--mut);font-size:13px;text-align:center;margin-top:40px;padding:0 0 42px}`;

export function whoamiExplainerHTML() {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Who am I? · Cloudflare-verified identity</title><meta name="description" content="See how Cloudflare stamps a verified identity onto a request at the edge."><style>${SHARED_CSS}
.wrap{max-width:1100px;margin:auto;padding:0 24px}.hero{padding:66px 0 34px;text-align:center}.eyebrow{color:var(--ok);font-weight:700;letter-spacing:.14em;text-transform:uppercase;font-size:12px;margin:0 0 12px}.hero h1{font-size:clamp(34px,6vw,60px);line-height:1.03;margin:0 0 16px;font-weight:900;letter-spacing:-.03em;background:linear-gradient(135deg,#fff,#d1fae5 55%,var(--ok));background-clip:text;color:transparent}.hero p:not(.eyebrow){color:var(--mut);font-size:17px;max-width:680px;margin:0 auto 26px}.cta{display:inline-flex;align-items:center;gap:10px;background:linear-gradient(135deg,var(--ok),#10b981);color:#04120c;font-weight:800;padding:14px 26px;border-radius:13px}.section{padding:38px 0}.section h2{text-align:center;font-size:24px;margin:0 0 6px}.section h2 span{color:var(--ok)}.lead{text-align:center;color:var(--mut);max-width:640px;margin:0 auto 26px}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.card,.step,.hdemo{background:rgba(10,10,10,.82);border:1px solid var(--bd);border-radius:16px;padding:22px;backdrop-filter:blur(16px)}.card h3{margin:0 0 7px}.card p,.step p{color:var(--mut);font-size:13.5px}.ico{font-size:24px;margin-bottom:12px}.flow{display:flex;flex-wrap:wrap;gap:10px}.step{flex:1;min-width:160px;padding:15px}.step .n{color:var(--ok);font-family:ui-monospace,monospace;font-size:11px}.step h4{margin:5px 0}.step.win{border-color:rgba(52,211,153,.45)}.hdemo{margin-top:14px;font-family:ui-monospace,monospace;font-size:13px}.hdemo .k{color:var(--ok)}.hdemo .v{color:#d1fae5}@media(max-width:820px){.grid{grid-template-columns:1fr}}@media(max-width:600px){.topnav .optional{display:none}}
</style></head><body><nav class="topnav"><div class="topnav-in"><a class="brand" href="/"><span class="logo">id</span> Whoami Identity Demo</a><span class="sp"></span><a href="/">Home</a><a class="optional" href="/">AI Gateway</a><a class="optional" href="/">Factory</a><a href="/headers">Try it</a></div></nav><div class="wrap"><section class="hero"><p class="eyebrow">🪪 Cloudflare Access · Verified Identity</p><h1>Who am I?</h1><p>Sign in with a one-time PIN and watch Cloudflare stamp <strong style="color:var(--fg)">your verified identity</strong> onto the request — before it ever reaches the app. The app trusts the edge, and there is <strong style="color:var(--fg)">zero login code</strong> behind it.</p><a class="cta" href="/headers">See your identity →</a><div><a class="backlink" href="/">← Back to home</a></div></section><section class="section"><h2>What <span>happens</span></h2><p class="lead">Cloudflare Access authenticates at the edge, then injects a bounded identity claim the origin can trust.</p><div class="grid"><div class="card"><div class="ico">🛡️</div><h3>Verified at the edge</h3><p>A one-time PIN proves mailbox control. No app account or stored password is needed.</p></div><div class="card"><div class="ico">🪪</div><h3>Injected as headers</h3><p>Cloudflare adds the verified identity to the request in flight. The app reads who arrived without implementing login.</p></div><div class="card"><div class="ico">🔒</div><h3>Protected from spoofing</h3><p>The production hostname policy removes untrusted client claims and stamps trusted values after authentication.</p></div></div></section><section class="section" id="flow"><h2>The <span>flow</span></h2><div class="flow"><div class="step"><div class="n">01</div><h4>Open the demo</h4><p>You request <code>/headers</code>; Access can intercept before the app sees it.</p></div><div class="step"><div class="n">02</div><h4>One-time PIN</h4><p>Access verifies mailbox control at the protected hostname.</p></div><div class="step"><div class="n">03</div><h4>Headers injected</h4><p>Cloudflare stamps the verified identity as it forwards the request.</p></div><div class="step win"><div class="n">04</div><h4>App knows you</h4><p>The inspector lights up with the safe allowlisted identity projection.</p></div></div><div class="hdemo"><span># what the app receives after sign-in:</span><br><span class="k">Cf-Access-Authenticated-User-Email</span>: <span class="v">verified identity</span><br><span class="k">X-User-Team</span>: <span class="v">optional upstream team claim</span></div></section><section class="section" style="text-align:center"><a class="cta" href="/headers">Sign in &amp; see your identity →</a></section><footer>${FOOTER}</footer></div></body></html>`;
}

function renderRows(values, className = '') {
  return Object.entries(values).map(([key, value]) => `<div class="hrow ${className}"><span class="hk">${escapeHTML(key)}${HEADER_DESC[key] ? `<span class="hdesc">${escapeHTML(HEADER_DESC[key])}</span>` : ''}</span><span class="hv">${escapeHTML(value)}</span></div>`).join('');
}

export function headersHTML(request) {
  const headers = collectHeaders(request);
  const edgeInfo = headers.edgeInfo;
  const ipClass = edgeInfo.ipClass || {};
  const chips = [
    edgeInfo.ipv4 ? `<span class="chip ${ipClass.public === true ? 'pub' : ipClass.public === false ? 'priv' : ''}">🌐 IPv4 <b>${escapeHTML(edgeInfo.ipv4)}</b>${ipClass.label ? ` · ${escapeHTML(ipClass.label)}` : ''}</span>` : '',
    edgeInfo.ipv6 ? `<span class="chip">🌐 IPv6 <b>${escapeHTML(edgeInfo.ipv6)}</b></span>` : '',
    edgeInfo.near ? `<span class="chip">📌 near <b>${escapeHTML(edgeInfo.near)}</b></span>` : '',
    edgeInfo.colo ? `<span class="chip">📍 Colo <b>${escapeHTML(edgeInfo.colo)}</b></span>` : '',
    edgeInfo.httpProtocol ? `<span class="chip">🔗 <b>${escapeHTML(edgeInfo.httpProtocol)}</b></span>` : '',
    edgeInfo.tlsVersion ? `<span class="chip">🔒 <b>${escapeHTML(edgeInfo.tlsVersion)}</b></span>` : '',
  ].filter(Boolean).join('');
  const idRows = renderRows(headers.identity, 'id') || '<div class="empty"><b>No identity headers yet.</b><span>Identity appears only when the external hostname policy authenticates the request or an upstream Gateway policy injects an allowlisted claim.</span></div>';
  const edgeRows = renderRows(headers.edge) || '<div class="empty"><span>No Cloudflare edge headers seen.</span></div>';
  const otherRows = renderRows(headers.other) || '<div class="empty"><span>No other allowlisted request metadata.</span></div>';
  const signedIn = headers.identity['cf-access-authenticated-user-email'];
  const identitySummary = signedIn ? `<div class="idsum"><div class="idsum-item"><span class="idsum-l">Signed in as</span><span class="idsum-v">${escapeHTML(signedIn)}</span><span class="idsum-h">Verified identity provided by the external Access policy.</span></div></div>` : '';

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>What data is my request passing?</title><style>${SHARED_CSS}
.wrap{max-width:920px;margin:auto;padding:54px 22px 20px}.eyebrow{color:var(--acc);font-weight:800;letter-spacing:.22em;text-transform:uppercase;font-size:12.5px}h1{font-size:clamp(30px,5vw,50px);font-weight:900;letter-spacing:-.025em;margin:.35em 0 .2em;background:linear-gradient(120deg,#fff,var(--acc2));background-clip:text;color:transparent}.lead{color:var(--mut);font-size:17px;max-width:680px;margin:0 0 26px}.chips{display:flex;flex-wrap:wrap;gap:9px;margin-bottom:30px}.chip{background:rgba(255,255,255,.05);border:1px solid var(--bd);border-radius:99px;padding:7px 14px;font-size:13px;color:var(--mut)}.chip.pub{border-color:rgba(52,211,153,.5);color:#6ee7b7}.chip.priv{border-color:rgba(251,191,36,.5);color:#fcd34d}.chip b{color:var(--fg)}.idsum{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-bottom:30px}.idsum-item,.card{background:rgba(10,13,20,.82);border:1px solid var(--bd);border-radius:16px;backdrop-filter:blur(16px)}.idsum-item{padding:14px 16px}.idsum-l,.idsum-h{display:block;color:var(--mut);font-size:12px}.idsum-v{display:block;color:var(--acc2);font-family:ui-monospace,monospace;word-break:break-all;margin:5px 0}.card{padding:8px;margin-bottom:22px;overflow:hidden}.card.hl{border-color:rgba(52,211,153,.5)}.card h2{font-size:15px;margin:0;padding:14px 16px;display:flex;gap:9px}.card h2 small{color:var(--mut);font-weight:400;margin-left:auto}.hrow{display:grid;grid-template-columns:minmax(180px,240px) 1fr;gap:14px;padding:11px 16px;border-top:1px solid var(--bd);font-family:ui-monospace,monospace;font-size:13px;word-break:break-all}.hk{color:var(--mut)}.hdesc{display:block;margin-top:3px;font:11px/1.4 Inter,sans-serif;opacity:.7}.hrow.id{background:linear-gradient(90deg,rgba(52,211,153,.1),transparent)}.hrow.id .hk{color:var(--ok)}.hrow.id .hv{color:#d1fae5}.empty{padding:18px 16px;border-top:1px solid var(--bd);color:var(--mut);font-size:14px;display:flex;flex-direction:column;gap:6px}.actions{display:flex;gap:12px;flex-wrap:wrap;margin:6px 0 34px}.btn{border-radius:11px;padding:12px 20px;font-weight:800;font-size:14px;border:1px solid var(--bd);background:rgba(255,255,255,.05);color:var(--fg);font-family:inherit;cursor:pointer}.btn.p{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#0b0e14;border:0}pre{background:#070a10;border:1px solid var(--bd);border-radius:14px;padding:18px;overflow:auto;max-height:420px;color:#cbd5e1}.notice{color:var(--mut);font-size:12px;margin:-16px 0 24px}@media(max-width:560px){.sp{display:none}.topnav-in{flex-wrap:wrap}.hrow{grid-template-columns:1fr}}
</style></head><body><nav class="topnav"><div class="topnav-in"><a class="brand" href="/"><span class="logo">id</span> Whoami Identity Demo</a><span class="sp"></span><a href="/">Home</a><a href="/headers">Who am I</a><a href="/">AI Gateway</a><a href="/">Factory</a></div></nav><div class="wrap"><div class="eyebrow">⚡ Cloudflare · request inspector</div><h1>What data is my request passing?</h1><p class="lead">This page is the app's-eye view of the request. It shows a bounded allowlist of edge metadata and identity claims that reached the Worker.</p><p class="notice">Authentication is enforced outside this repository by the production hostname's Cloudflare Access policy.</p><div class="chips">${chips || '<span class="chip">edge details unavailable</span>'}</div>${identitySummary}<div class="card ${headers.hasIdentity ? 'hl' : ''}"><h2>🪪 Injected identity <small>${headers.hasIdentity ? 'allowlisted identity present' : 'none present yet'}</small></h2>${idRows}</div><div class="card"><h2>☁️ Cloudflare edge headers <small>added on the way in</small></h2>${edgeRows}</div><div class="card"><h2>📨 Everything else the origin received <small>safe allowlist only</small></h2>${otherRows}</div><div class="actions"><button class="btn p" data-action="refresh">↻ Refresh</button><a class="btn" href="/api/headers" target="_blank" rel="noopener">{ } Raw JSON</a><button class="btn" id="rawtog">▾ Show raw headers</button><a class="btn" href="/cdn-cgi/access/logout">⎋ Log out / switch identity</a></div><div id="rawwrap" hidden><pre id="raw">loading…</pre></div><footer>${FOOTER}</footer></div><script src="/assets/inspector.js" defer></script></body></html>`;
}

export async function handleRequest(request) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return new Response('Method not allowed', { status: 405, headers: { ...SECURITY_HEADERS, allow: 'GET, HEAD' } });
  const url = new URL(request.url);
  let response;
  if (url.pathname === '/') response = htmlResponse(whoamiExplainerHTML());
  else if (url.pathname === '/headers') response = htmlResponse(headersHTML(request));
  else if (url.pathname === '/api/headers') response = handleHeadersJson(request);
  else if (url.pathname === '/healthz') response = new Response('whoami ok', { headers: responseHeaders('text/plain; charset=utf-8') });
  else response = new Response('Not found', { status: 404, headers: responseHeaders('text/plain; charset=utf-8') });
  if (request.method === 'HEAD') return new Response(null, { status: response.status, headers: response.headers });
  return response;
}

export default { fetch: handleRequest };
