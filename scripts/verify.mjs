import assert from 'node:assert/strict';
import worker from '../src/index.js';

const mode = process.argv[2] || 'offline';

async function offline() {
  const root = await worker.fetch(new Request('https://demo.invalid/'));
  assert.equal(root.status, 200);
  assert.match(await root.text(), /Who am I\?/);

  const inspector = await worker.fetch(new Request('https://demo.invalid/headers', {
    headers: {
      'Cf-Access-Authenticated-User-Email': 'verified-user',
      'X-User-Team': 'example-team',
      'X-Unlisted-Secret': 'must-not-leak',
    },
  }));
  assert.equal(inspector.status, 200);
  const inspectorBody = await inspector.text();
  assert.match(inspectorBody, /verified-user/);
  assert.doesNotMatch(inspectorBody, /must-not-leak/);

  const json = await worker.fetch(new Request('https://demo.invalid/api/headers', {
    headers: { 'X-Unlisted-Secret': 'must-not-leak' },
  }));
  assert.equal(json.status, 200);
  assert.equal((await json.text()).includes('must-not-leak'), false);

  const health = await worker.fetch(new Request('https://demo.invalid/healthz'));
  assert.equal(await health.text(), 'whoami ok');
  assert.match(root.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
  console.log('offline verification passed: /, /headers, /api/headers, /healthz');
}

async function live() {
  const supplied = process.argv[3] || process.env.VERIFY_BASE_URL;
  if (!supplied) throw new Error('live mode requires a base URL argument or VERIFY_BASE_URL');
  const base = new URL(supplied);
  if (base.protocol !== 'https:') throw new Error('live mode requires an https URL');
  const results = [];
  for (const path of ['/', '/headers', '/api/headers', '/healthz']) {
    const response = await fetch(new URL(path, base), { redirect: 'manual' });
    const isAccessChallenge = [301, 302, 303, 307, 308].includes(response.status);
    if (!response.ok && !isAccessChallenge) throw new Error(`${path} returned HTTP ${response.status}`);
    results.push(`${path}=${response.status}${isAccessChallenge ? ' (external access challenge)' : ''}`);
  }
  console.log(`live verification passed without bypassing Access: ${results.join(', ')}`);
}

if (mode === 'offline') await offline();
else if (mode === 'live') await live();
else throw new Error('mode must be offline or live');
