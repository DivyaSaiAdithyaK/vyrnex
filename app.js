const $ = (s) => document.querySelector(s), app = $('#app'); let me = null, tab = 'docs', panel = null, msg = '', filt = {};
const h = (t, a = {}, ...k) => { const e = document.createElement(t); for (const [x, v] of Object.entries(a)) x.startsWith('on') ? e.addEventListener(x.slice(2), v) : e.setAttribute(x, v); k.flat().forEach((c) => c != null && e.append(c)); return e; };
async function api(m, p, b, hdr) {
  const o = { method: m, credentials: 'same-origin', headers: { 'X-Requested-With': 'trustvault', ...(hdr || {}) } };
  if (b !== undefined) { if (hdr) o.body = b; else { o.body = JSON.stringify(b); o.headers['Content-Type'] = 'application/json'; } }
  const r = await fetch(p, o), j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || r.status); return j;
}
const act = (fn) => async (e) => { e?.preventDefault?.(); msg = ''; try { await fn(e); } catch (x) { msg = x.message; } render(); };
const fmt = (n) => n > 1048576 ? (n / 1048576).toFixed(1) + ' MB' : Math.ceil(n / 1024) + ' KB';
const inp = (id, ph, t = 'text') => h('input', { id, placeholder: ph, type: t });
const th = (a) => h('tr', {}, ...a.map((x) => h('th', {}, x)));

async function render() {
  app.replaceChildren();
  if (!me) { try { me = await api('GET', '/api/me'); } catch {} }
  if (!me) return app.append(h('main', {}, h('div', { class: 'card', style: 'max-width:360px;margin:60px auto' }, h('h3', {}, '🔐 TrustVault'),
    h('p', { class: 'mut' }, 'Confidential documents. Every access is decided by the server and recorded.'),
    h('form', { onsubmit: act(async () => { me = await api('POST', '/api/login', { username: $('#u').value, password: $('#p').value }); tab = 'docs'; }) },
      h('div', { class: 'row' }, inp('u', 'username')), h('div', { class: 'row' }, inp('p', 'password', 'password')), h('button', {}, 'Sign in')), h('p', { class: 'bad' }, msg))));
  const nav = h('header', {}, h('b', {}, '🔐 TrustVault'), h('span', { class: 'mut' }, `${me.username} · ${me.role}`),
    h('button', { class: 's tab' + (tab === 'docs' ? ' on' : ''), onclick: () => { tab = 'docs'; panel = null; render(); } }, 'Documents'),
    me.role === 'admin' ? h('button', { class: 's tab' + (tab === 'admin' ? ' on' : ''), onclick: () => { tab = 'admin'; render(); } }, 'Admin') : null,
    h('button', { onclick: act(async () => { await api('POST', '/api/logout', {}); me = null; panel = null; }) }, 'Sign out'));
  const main = h('main', {}); app.append(nav, main); if (msg) main.append(h('div', { class: 'card' }, h('b', {}, msg)));
  try { await (tab === 'admin' ? adminView(main) : docsView(main)); } catch (x) { if (x.message === 'login required') { me = null; return render(); } main.append(h('div', { class: 'card bad' }, x.message)); }
}
async function docsView(main) {
  const ks = [['q', 'name'], ['owner', 'owner'], ['category', 'category']];
  main.append(h('div', { class: 'card' }, h('h3', {}, 'Search'), h('form', { class: 'row', onsubmit: act(() => { filt = Object.fromEntries(['q', 'owner', 'category', 'from', 'to'].map((k) => [k, $('#f' + k).value])); }) },
    ...ks.map(([k, p]) => Object.assign(inp('f' + k, p), { value: filt[k] || '' })), Object.assign(inp('ffrom', '', 'date'), { value: filt.from || '' }), Object.assign(inp('fto', '', 'date'), { value: filt.to || '' }), h('button', {}, 'Search'))));
  if (me.role === 'owner') main.append(h('div', { class: 'card' }, h('h3', {}, 'Upload (pdf, png, jpg, docx, xlsx, txt, csv · max 5 MB)'),
    h('form', { class: 'row', onsubmit: act(async () => { const file = $('#file').files[0]; if (!file) throw new Error('choose a file');
      await api('POST', `/api/documents?name=${encodeURIComponent($('#uname').value)}&category=${encodeURIComponent($('#ucat').value)}`, file, { 'X-Filename': encodeURIComponent(file.name) }); }) },
      h('input', { id: 'file', type: 'file' }), inp('uname', 'display name'), inp('ucat', 'category'), h('button', {}, 'Upload'))));
  const docs = await api('GET', '/api/documents?' + new URLSearchParams(Object.entries(filt).filter(([, v]) => v)));
  const t = h('table', {}, th(['Name', 'Category', 'Owner', 'Your access', 'Size', 'Created', '']),
    ...docs.map((d) => h('tr', {}, h('td', {}, d.name), h('td', {}, d.category), h('td', {}, d.owner), h('td', {}, d.level), h('td', {}, fmt(d.size)), h('td', {}, d.created_at.slice(0, 10)),
      h('td', {}, h('a', { href: `/api/documents/${d.id}/download` }, h('button', { class: 's' }, 'Download')), ' ',
        d.level !== 'read' ? h('button', { class: 's', onclick: act(async () => { const n = prompt('New name', d.name); if (n) await api('PATCH', '/api/documents/' + d.id, { name: n }); }) }, 'Rename') : null, ' ',
        d.level === 'owner' ? [h('button', { class: 's', onclick: () => { panel = { id: d.id, name: d.name }; render(); } }, 'Share/History'), ' ',
          h('button', { class: 's d', onclick: act(async () => { if (confirm('Delete permanently?')) { await api('DELETE', '/api/documents/' + d.id); panel = null; } }) }, 'Delete')] : null))));
  main.append(h('div', { class: 'card' }, h('h3', {}, `Documents (${docs.length})`), docs.length ? t : h('p', { class: 'mut' }, 'Nothing here, or nothing shared with you yet.')));
  if (panel) { const [gr, au, dir] = await Promise.all([api('GET', `/api/documents/${panel.id}/grants`), api('GET', `/api/documents/${panel.id}/audit`), api('GET', '/api/users/directory')]);
    main.append(h('div', { class: 'card' }, h('h3', {}, 'Access: ' + panel.name),
      h('form', { class: 'row', onsubmit: act(() => api('POST', `/api/documents/${panel.id}/grants`, { username: $('#gu').value, level: $('#gl').value })) },
        h('select', { id: 'gu' }, ...dir.filter((u) => u.username !== me.username).map((u) => h('option', {}, u.username))), h('select', { id: 'gl' }, h('option', {}, 'read'), h('option', {}, 'edit')), h('button', {}, 'Grant')),
      h('table', {}, ...gr.map((g) => h('tr', {}, h('td', {}, g.username), h('td', {}, g.level), h('td', {}, h('button', { class: 's d', onclick: act(() => api('DELETE', `/api/documents/${panel.id}/grants/${g.user_id}`)) }, 'Revoke'))))),
      h('h3', { style: 'margin-top:14px' }, 'History'), auditTable(au)));
  }
}
const auditTable = (rows) => h('table', {}, th(['Time', 'Actor', 'Action', 'Detail', 'Outcome']),
  ...rows.map((r) => h('tr', {}, h('td', {}, r.ts.replace('T', ' ').slice(0, 19)), h('td', {}, r.actor || '-'), h('td', {}, r.action), h('td', {}, r.detail || ''), h('td', { class: r.outcome === 'ok' ? 'ok' : 'bad' }, r.outcome))));
async function adminView(main) {
  const [users, docs, log] = await Promise.all([api('GET', '/api/users'), api('GET', '/api/admin/documents'), api('GET', '/api/audit?limit=200')]);
  main.append(h('div', { class: 'card' }, h('h3', {}, 'Users'),
    h('form', { class: 'row', onsubmit: act(() => api('POST', '/api/users', { username: $('#nu').value, password: $('#np').value, role: $('#nr').value })) }, inp('nu', 'username'), inp('np', 'password (10+ chars)', 'password'),
      h('select', { id: 'nr' }, h('option', {}, 'viewer'), h('option', {}, 'owner'), h('option', {}, 'admin')), h('button', {}, 'Create')),
    h('table', {}, ...users.map((u) => h('tr', {}, h('td', {}, u.username), h('td', {}, u.role), h('td', { class: u.active ? 'ok' : 'bad' }, u.active ? 'active' : 'disabled'),
      h('td', {}, u.username === me.username ? '' : h('button', { class: 's', onclick: act(() => api('PATCH', '/api/users/' + u.id, { active: !u.active })) }, u.active ? 'Disable (kills sessions)' : 'Enable')))))));
  main.append(h('div', { class: 'card' }, h('h3', {}, 'All documents (metadata only — admins cannot read content)'),
    h('table', {}, th(['Name', 'Owner', 'Category', 'Grants', 'Created']), ...docs.map((d) => h('tr', {}, h('td', {}, d.name), h('td', {}, d.owner), h('td', {}, d.category), h('td', {}, d.grants), h('td', {}, d.created_at.slice(0, 10)))))));
  main.append(h('div', { class: 'card' }, h('h3', {}, 'Audit trail (including refused attempts)'),
    h('button', { class: 's', onclick: act(async () => { const v = await api('GET', '/api/audit/verify'); msg = v.ok ? '✔ Audit chain intact' : '✖ TAMPERING: chain broken at entry ' + v.broken_at; }) }, 'Verify integrity'), auditTable(log)));
}
render();
