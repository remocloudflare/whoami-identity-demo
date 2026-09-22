import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import worker from '../src/index.js';

async function get(path = '/', headers = {}) {
  return worker.fetch(new Request(`https://demo.invalid${path}`, { headers }));
}

test('GET / serves the preserved Who am I explainer structure', async () => {
  const response = await get('/');
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.match(body, /<h1>Who am I\?<\/h1>/);
  assert.match(body, /What <span>happens<\/span>/);
  assert.match(body, /The <span>flow<\/span>/);
  assert.match(body, /See your identity/);
  assert.match(body, /Built by Remo Mattei · Sr\. Cloudflare One Specialist Solutions Engineer\./);
});

test('GET /api/headers projects only allowlisted identity and edge headers', async () => {
  const request = new Request('https://demo.invalid/api/headers', {
    headers: {
      'Cf-Access-Authenticated-User-Email': 'verified-user',
      'X-User-Team': 'Example Team',
      'CF-Connecting-IP': '203.0.113.9',
      'CF-Ray': 'example-ray',
      'X-Unlisted-Identity': 'must-not-appear',
    },
  });
  Object.defineProperty(request, 'cf', { value: { city: 'Test City', country: 'XX', colo: 'TST', asn: 64500 } });

  const response = await worker.fetch(request);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(body.injected_identity, {
    'cf-access-authenticated-user-email': 'verified-user',
    'x-user-team': 'Example Team',
  });
  assert.deepEqual(body.cloudflare_edge, {
    'cf-connecting-ip': '203.0.113.9',
    'cf-ray': 'example-ray',
  });
  assert.equal(body.edge_info.city, 'Test City');
  assert.equal(JSON.stringify(body).includes('must-not-appear'), false);
});

test('identity projection strips controls and bounds every value', async () => {
  const unsafe = `name\u0000\n${'x'.repeat(400)}`;
  const { sanitizeHeaderValue } = await import('../src/index.js');
  const sanitized = sanitizeHeaderValue(unsafe);

  assert.equal(/[\u0000-\u001f\u007f]/.test(sanitized), false);
  assert.equal(sanitized.length, 256);
  assert.equal(sanitized.startsWith('name  '), true);
});

test('GET /headers preserves inspector structure and safely renders identity', async () => {
  const response = await get('/headers', {
    'Cf-Access-Authenticated-User-Email': '<img src=x onerror=alert(1)>',
    'CF-Connecting-IP': '203.0.113.9',
  });
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.match(body, /What data is my request passing\?/);
  assert.match(body, /Injected identity/);
  assert.match(body, /Cloudflare edge headers/);
  assert.match(body, /Everything else the origin received/);
  assert.match(body, /Show raw headers/);
  assert.match(body, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(body, /<img src=x onerror=alert\(1\)>/);
  assert.match(body, /Built by Remo Mattei · Sr\. Cloudflare One Specialist Solutions Engineer\./);
});

test('routes expose health, reject unknown paths, and implement HEAD without a body', async () => {
  const health = await get('/healthz');
  assert.equal(health.status, 200);
  assert.equal(await health.text(), 'whoami ok');

  const missing = await get('/missing');
  assert.equal(missing.status, 404);

  const head = await worker.fetch(new Request('https://demo.invalid/', { method: 'HEAD' }));
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
});

test('inspector uses local static script and Factory penguin WebP asset', async () => {
  const script = await readFile(new URL('../public/assets/inspector.js', import.meta.url), 'utf8');
  const background = await readFile(new URL('../public/assets/factory-bg.webp', import.meta.url));

  assert.match(script, /textContent/);
  assert.doesNotMatch(script, /innerHTML|document\.write/);
  assert.equal(background.subarray(0, 4).toString('ascii'), 'RIFF');
  assert.equal(background.subarray(8, 12).toString('ascii'), 'WEBP');
  assert.ok(background.length > 1_000);
});

test('Wrangler config names only the standalone Worker and local assets', async () => {
  const raw = await readFile(new URL('../wrangler.jsonc', import.meta.url), 'utf8');
  const config = JSON.parse(raw);

  assert.equal(config.name, 'whoami-identity-demo');
  assert.equal(config.main, 'src/index.js');
  assert.equal(config.assets.directory, './public');
  assert.deepEqual(config.compatibility_flags, ['nodejs_compat']);
  assert.doesNotMatch(raw, /account_id|routes?|custom_domains?|access_aud|audience|idp|secret/i);
});

test('npm deployment scripts are wrappers around Wrangler only', async () => {
  const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(packageJson.scripts.check, 'npm test && node scripts/verify.mjs offline && wrangler deploy --dry-run');
  assert.equal(packageJson.scripts.deploy, 'wrangler deploy --keep-vars');
  assert.equal(packageJson.engines.node, '>=22');
});

test('offline verifier exercises routes without credentials', async () => {
  const verifier = await readFile(new URL('../scripts/verify.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(verifier, /CF_Authorization|Cf-Access-Jwt-Assertion|Authorization\s*:/i);

  const run = spawnSync(process.execPath, ['scripts/verify.mjs', 'offline'], {
    cwd: new URL('..', import.meta.url),
    encoding: 'utf8',
  });
  assert.equal(run.status, 0, run.stderr || run.stdout);
  assert.match(run.stdout, /offline verification passed/);
});

test('visible navigation and inspector controls retain the extracted page structure', async () => {
  const landing = await (await get('/')).text();
  assert.match(landing, />AI Gateway<\/a>/);
  assert.match(landing, />Factory<\/a>/);
  assert.match(landing, /Back to home/);

  const inspector = await (await get('/headers')).text();
  assert.match(inspector, />AI Gateway<\/a>/);
  assert.match(inspector, />Factory<\/a>/);
  assert.match(inspector, /Log out \/ switch identity/);
});

test('public documentation records standalone deployment ownership without legacy migration wording', async () => {
  const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
  const inventory = await readFile(new URL('../docs/extraction-inventory.md', import.meta.url), 'utf8');
  const combined = `${readme}\n${inventory}`;

  assert.match(combined, /fully standalone/i);
  const legacyTerms = ['roll' + 'back', 'itlinux' + '-mesh', 'demo' + '-factory', 'demo' + '-coder-nginx'];
  for (const term of legacyTerms) assert.doesNotMatch(combined, new RegExp(term, 'i'));
  assert.match(combined, /Wrangler-managed/);
  assert.match(combined, /no Terraform/i);
  assert.match(combined, /Access OTP.*managed externally/is);
  assert.match(readme, /npm run check/);
  assert.match(readme, /npm run deploy/);
  assert.match(readme, /npx wrangler deploy --keep-vars/);
});

test('HTML and JSON responses set security headers', async () => {
  for (const path of ['/', '/headers', '/api/headers', '/healthz']) {
    const response = await get(path);
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(response.headers.get('x-frame-options'), 'DENY');
    assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
    assert.match(response.headers.get('content-security-policy') || '', /default-src 'none'/);
    assert.match(response.headers.get('permissions-policy') || '', /camera=\(\)/);
  }
});

test('sensitive and arbitrary headers are absent from HTML and JSON projections', async () => {
  const sensitive = {
    cookie: 'session-value-must-not-leak',
    authorization: 'credential-value-must-not-leak',
    'cf-access-jwt-assertion': 'assertion-value-must-not-leak',
    'x-api-key': 'key-value-must-not-leak',
  };
  const html = await (await get('/headers', sensitive)).text();
  const json = await (await get('/api/headers', sensitive)).text();

  for (const marker of Object.values(sensitive)) {
    assert.equal(html.includes(marker), false);
    assert.equal(json.includes(marker), false);
  }
});
