const toggle = document.querySelector('#rawtog');
const wrapper = document.querySelector('#rawwrap');
const output = document.querySelector('#raw');
const refresh = document.querySelector('[data-action="refresh"]');
let loaded = false;

refresh?.addEventListener('click', () => window.location.reload());

toggle?.addEventListener('click', async () => {
  wrapper.hidden = !wrapper.hidden;
  toggle.textContent = `${wrapper.hidden ? '▾ Show' : '▴ Hide'} raw headers`;
  if (wrapper.hidden || loaded) return;
  loaded = true;
  try {
    const response = await fetch('/api/headers', { credentials: 'same-origin' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    output.textContent = JSON.stringify(await response.json(), null, 2);
  } catch {
    output.textContent = 'Could not load /api/headers';
  }
});
