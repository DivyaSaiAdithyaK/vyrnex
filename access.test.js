import { test, before, after } from 'node:test'; import assert from 'node:assert/strict'; import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import { createApp } from '../server.js';
let app, base; const PW = 'Password#12345', dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-')), PDF = Buffer.from('%PDF-1.4 secret');
before(async () => { app = createApp({ dataDir: dir }); for (const [u, r] of [['admin', 'admin'], ['alice', 'owner'], ['bob', 'owner'], ['carol', 'viewer']]) app.createUser(u, PW, r);
  await new Promise((r) => app.server.listen(0, r)); base = 'http://127.0.0.1:' + app.server.address().port; });
after(() => app.server.close());
async function call(cookie, m, p, body, hdr = {}) {
  const raw = Buffer.isBuffer(body); const r = await fetch(base + p, { method: m, headers: { 'X-Requested-With': 'trustvault', Cookie: cookie || '', ...(body && !raw ? { 'Content-Type': 'application/json' } : {}), ...hdr }, body: body ? (raw ? body : JSON.stringify(body)) : undefined });
  return { status: r.status, cookie: (r.headers.get('set-cookie') || '').split(';')[0], json: await r.clone().json().catch(() => null) };
}
const login = async (u) => (await call('', 'POST', '/api/login', { username: u, password: PW })).cookie;
const upload = async (c, name = 'a.pdf') => (await call(c, 'POST', '/api/documents?name=Secret&category=hr', PDF, { 'X-Filename': name })).json.id;

test('unauthenticated requests are refused', async () => { for (const p of ['/api/documents', '/api/me', '/api/audit']) assert.equal((await call('', 'GET', p)).status, 401); });
test('wrong password refused', async () => { assert.equal((await call('', 'POST', '/api/login', { username: 'alice', password: 'nope' })).status, 401); });
test("one user cannot reach another user's document by ANY route", async () => {
  const a = await login('alice'), b = await login('bob'), id = await upload(a);
  for (const [m, p, body] of [['GET', `/api/documents/${id}/download`], ['PATCH', `/api/documents/${id}`, { name: 'x' }], ['PUT', `/api/documents/${id}/content`, PDF],
    ['DELETE', `/api/documents/${id}`], ['GET', `/api/documents/${id}/grants`], ['POST', `/api/documents/${id}/grants`, { username: 'bob', level: 'read' }], ['GET', `/api/documents/${id}/audit`]])
    assert.equal((await call(b, m, p, body, { 'X-Filename': 'a.pdf' })).status, 404, `${m} ${p}`);
  assert.equal((await call(b, 'GET', '/api/documents')).json.length, 0);
  assert.equal((await call(a, 'GET', `/api/documents/${id}/download`)).status, 200);
});
test('admin cannot read document content', async () => { const id = await upload(await login('alice')); assert.equal((await call(await login('admin'), 'GET', `/api/documents/${id}/download`)).status, 404); });
test('viewer cannot upload; read grant cannot edit/delete/share', async () => {
  const a = await login('alice'), c = await login('carol'), id = await upload(a);
  assert.equal((await call(c, 'POST', '/api/documents', PDF, { 'X-Filename': 'a.pdf' })).status, 403);
  await call(a, 'POST', `/api/documents/${id}/grants`, { username: 'carol', level: 'read' });
  assert.equal((await call(c, 'GET', `/api/documents/${id}/download`)).status, 200);
  for (const [m, p, b] of [['PATCH', `/api/documents/${id}`, { name: 'x' }], ['DELETE', `/api/documents/${id}`], ['POST', `/api/documents/${id}/grants`, { username: 'bob', level: 'read' }]])
    assert.equal((await call(c, m, p, b)).status, 403, m);
});
test('revoking access works immediately with the SAME session', async () => {
  const a = await login('alice'), b = await login('bob'), id = await upload(a);
  await call(a, 'POST', `/api/documents/${id}/grants`, { username: 'bob', level: 'edit' });
  assert.equal((await call(b, 'GET', `/api/documents/${id}/download`)).status, 200);
  const uid = (await call(a, 'GET', `/api/documents/${id}/grants`)).json[0].user_id; await call(a, 'DELETE', `/api/documents/${id}/grants/${uid}`);
  assert.equal((await call(b, 'GET', `/api/documents/${id}/download`)).status, 404);
});
test('disabling a user kills their live session', async () => {
  const ad = await login('admin'), id = (await call(ad, 'POST', '/api/users', { username: 'dave', password: PW, role: 'viewer' })).json.id;
  const d = await call('', 'POST', '/api/login', { username: 'dave', password: PW }); assert.equal((await call(d.cookie, 'GET', '/api/me')).status, 200);
  await call(ad, 'PATCH', '/api/users/' + id, { active: false }); assert.equal((await call(d.cookie, 'GET', '/api/me')).status, 401);
  assert.equal((await call('', 'POST', '/api/login', { username: 'dave', password: PW })).status, 401);
});
test('upload validation: bad type, spoofed content, oversize', async () => {
  const a = await login('alice'), up = (n, b) => call(a, 'POST', '/api/documents', b, { 'X-Filename': n });
  assert.equal((await up('x.exe', PDF)).status, 415); assert.equal((await up('x.pdf', Buffer.from('MZ not a pdf'))).status, 415); assert.equal((await up('x.pdf', Buffer.alloc(6 * 1024 * 1024, 1))).status, 413);
});
test('search only returns documents the user may see', async () => { const a = await login('alice'), b = await login('bob'); await upload(a); assert.equal((await call(b, 'GET', '/api/documents?q=Secret&owner=alice')).json.length, 0); });
test('CSRF header required for mutations', async () => { assert.equal((await fetch(base + '/api/logout', { method: 'POST' })).status, 403); });
test('audit records refused attempts, chain verifies, tampering is blocked and detected', async () => {
  const ad = await login('admin'), log = (await call(ad, 'GET', '/api/audit?outcome=denied&limit=1000')).json; assert.ok(log.some((r) => r.action === 'download' && r.actor === 'bob'));
  assert.equal((await call(ad, 'GET', '/api/audit/verify')).json.ok, true);
  assert.throws(() => app.db.exec("UPDATE audit SET actor='x' WHERE id=1"), /append-only/); assert.throws(() => app.db.exec('DELETE FROM audit'), /append-only/);
  app.db.exec('DROP TRIGGER audit_no_update'); app.db.exec("UPDATE audit SET detail='forged' WHERE id=2");
  assert.equal((await call(ad, 'GET', '/api/audit/verify')).json.ok, false);
});
