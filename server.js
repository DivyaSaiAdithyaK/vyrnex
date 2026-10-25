// TrustVault — zero-dependency Node 22 server. EVERY document route goes through getDoc(); that is the one authorisation decision.
import http from 'node:http'; import { DatabaseSync } from 'node:sqlite'; import crypto from 'node:crypto';
import fs from 'node:fs'; import path from 'node:path'; import { fileURLToPath } from 'node:url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MAX_BYTES = 5 * 1024 * 1024, SESSION_MS = 8 * 3600e3;
const MAGIC = { pdf: [0x25,0x50,0x44,0x46], png: [0x89,0x50,0x4e,0x47], jpg: [0xff,0xd8,0xff], jpeg: [0xff,0xd8,0xff], docx: [0x50,0x4b], xlsx: [0x50,0x4b], txt: null, csv: null };
const RANK = { read: 1, edit: 2, owner: 3 };
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
export const hashPw = (p) => { const s = crypto.randomBytes(16); return s.toString('hex') + ':' + crypto.scryptSync(p, s, 64).toString('hex'); };
const DUMMY = hashPw('dummy');
const checkPw = (p, st) => { const [s, h] = st.split(':'); return crypto.timingSafeEqual(crypto.scryptSync(p, Buffer.from(s, 'hex'), 64), Buffer.from(h, 'hex')); };

export function createApp({ dbFile = ':memory:', dataDir = path.join(__dirname, 'data') } = {}) {
  fs.mkdirSync(path.join(dataDir, 'files'), { recursive: true });
  const db = new DatabaseSync(dbFile); db.exec(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));
  const one = (s, ...a) => db.prepare(s).get(...a), all = (s, ...a) => db.prepare(s).all(...a), run = (s, ...a) => db.prepare(s).run(...a);
  const fails = new Map();

  const auditRow = (r) => [r.prev_hash, r.ts, r.actor_id, r.actor, r.action, r.doc_id, r.detail, r.outcome].join('|');
  function audit(u, action, docId = null, detail = '', outcome = 'ok', actorName = null) {
    const last = one('SELECT hash FROM audit ORDER BY id DESC LIMIT 1');
    const r = { prev_hash: last ? last.hash : '0'.repeat(64), ts: new Date().toISOString(), actor_id: u ? u.id : null, actor: u ? u.username : actorName, action, doc_id: docId, detail, outcome };
    run('INSERT INTO audit(ts,actor_id,actor,action,doc_id,detail,outcome,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?)', r.ts, r.actor_id, r.actor, r.action, r.doc_id, r.detail, r.outcome, r.prev_hash, sha(auditRow(r)));
  }
  function verifyChain() {
    let prev = '0'.repeat(64);
    for (const r of all('SELECT * FROM audit ORDER BY id')) { if (r.prev_hash !== prev || sha(auditRow(r)) !== r.hash) return { ok: false, broken_at: r.id }; prev = r.hash; }
    return { ok: true };
  }
  function createUser(username, password, role) {
    if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username || '')) throw new HttpError(400, 'username: 3-32 chars, letters/digits/_.-');
    if (typeof password !== 'string' || password.length < 10) throw new HttpError(400, 'password must be at least 10 characters');
    if (!['admin', 'owner', 'viewer'].includes(role)) throw new HttpError(400, 'invalid role');
    try { return run('INSERT INTO users(username,pw_hash,role) VALUES(?,?,?)', username, hashPw(password), role).lastInsertRowid; }
    catch { throw new HttpError(409, 'username taken'); }
  }
  // ---- THE authorisation decision ----
  function getDoc(u, id, need, action) {
    const d = one('SELECT * FROM documents WHERE id=?', String(id));
    let level = null;
    if (d) { if (d.owner_id === u.id) level = 'owner'; else { const g = one('SELECT level FROM grants WHERE doc_id=? AND user_id=?', d.id, u.id); level = g ? g.level : null; } }
    if (!d || !level) { audit(u, action, String(id).slice(0, 64), 'no access', 'denied'); throw new HttpError(404, 'not found'); } // 404: do not reveal existence
    if (RANK[level] < RANK[need]) { audit(u, action, d.id, `needs ${need}, has ${level}`, 'denied'); throw new HttpError(403, 'forbidden'); }
    return { d, level };
  }
  const requireRole = (u, ...roles) => { if (!roles.includes(u.role)) { audit(u, 'role_denied', null, `needs ${roles}`, 'denied'); throw new HttpError(403, 'forbidden'); } };

  function validateUpload(filename, buf) {
    const ext = path.extname(String(filename || '')).slice(1).toLowerCase();
    if (!(ext in MAGIC)) throw new HttpError(415, 'file type not allowed (pdf, png, jpg, docx, xlsx, txt, csv)');
    if (!buf.length) throw new HttpError(400, 'empty file');
    if (buf.length > MAX_BYTES) throw new HttpError(413, 'file larger than 5 MB');
    const m = MAGIC[ext];
    if (m ? !m.every((b, i) => buf[i] === b) : buf.includes(0)) throw new HttpError(415, 'file content does not match its extension');
    return ext;
  }
  const clean = (s, max, fb) => String(s ?? fb).replace(/[\u0000-\u001f<>"\\/]/g, '').trim().slice(0, max) || fb;

  const routes = [];
  const R = (m, re, fn) => routes.push([m, new RegExp('^' + re + '$'), fn]);

  R('POST', '/api/login', async (c) => {
    const { username, password } = c.json, key = String(username).toLowerCase() + '|' + c.req.socket.remoteAddress, f = fails.get(key) || { n: 0, t: 0 };
    if (f.n >= 5 && Date.now() - f.t < 600e3) throw new HttpError(429, 'too many attempts, try later');
    const u = one('SELECT * FROM users WHERE username=?', String(username));
    const ok = checkPw(String(password), u ? u.pw_hash : DUMMY) && u && u.active;
    if (!ok) { fails.set(key, { n: f.n + 1, t: Date.now() }); audit(null, 'login', null, '', 'denied', String(username).slice(0, 64)); throw new HttpError(401, 'invalid credentials'); }
    fails.delete(key);
    const token = crypto.randomBytes(32).toString('hex');
    run('INSERT INTO sessions VALUES(?,?,?)', sha(token), u.id, Date.now() + SESSION_MS); audit(u, 'login');
    c.cookie = token; return { username: u.username, role: u.role, id: u.id };
  });
  R('POST', '/api/logout', (c) => { run('DELETE FROM sessions WHERE token_hash=?', c.tokenHash); audit(c.u, 'logout'); c.cookie = ''; return { ok: true }; });
  R('GET', '/api/me', (c) => ({ id: c.u.id, username: c.u.username, role: c.u.role }));
  R('GET', '/api/users/directory', (c) => all('SELECT id,username FROM users WHERE active=1 ORDER BY username'));

  // Admin
  R('GET', '/api/users', (c) => { requireRole(c.u, 'admin'); return all('SELECT id,username,role,active FROM users ORDER BY id'); });
  R('POST', '/api/users', (c) => { requireRole(c.u, 'admin'); const id = createUser(c.json.username, c.json.password, c.json.role); audit(c.u, 'user_create', null, `${c.json.username}:${c.json.role}`); c.status = 201; return { id: Number(id) }; });
  R('PATCH', '/api/users/(\\d+)', (c) => {
    requireRole(c.u, 'admin'); const id = +c.m[1], t = one('SELECT * FROM users WHERE id=?', id); if (!t) throw new HttpError(404, 'not found');
    if (id === c.u.id) throw new HttpError(400, 'cannot modify yourself');
    if (c.json.role) { if (!['admin', 'owner', 'viewer'].includes(c.json.role)) throw new HttpError(400, 'invalid role'); run('UPDATE users SET role=? WHERE id=?', c.json.role, id); }
    if (c.json.active !== undefined) { run('UPDATE users SET active=? WHERE id=?', c.json.active ? 1 : 0, id); if (!c.json.active) run('DELETE FROM sessions WHERE user_id=?', id); }
    audit(c.u, 'user_update', null, `${t.username}:${JSON.stringify(c.json)}`); return { ok: true };
  });
  R('GET', '/api/audit', (c) => {
    requireRole(c.u, 'admin'); const p = c.url.searchParams, w = [], a = [];
    for (const [k, col] of [['doc', 'doc_id'], ['action', 'action'], ['actor', 'actor'], ['outcome', 'outcome']]) if (p.get(k)) { w.push(`${col}=?`); a.push(p.get(k)); }
    return all(`SELECT * FROM audit ${w.length ? 'WHERE ' + w.join(' AND ') : ''} ORDER BY id DESC LIMIT ${Math.min(+p.get('limit') || 200, 1000)}`, ...a);
  });
  R('GET', '/api/audit/verify', (c) => { requireRole(c.u, 'admin'); return verifyChain(); });
  R('GET', '/api/admin/documents', (c) => { requireRole(c.u, 'admin'); return all('SELECT d.id,d.name,d.category,u.username owner,d.size,d.created_at,(SELECT COUNT(*) FROM grants g WHERE g.doc_id=d.id) grants FROM documents d JOIN users u ON u.id=d.owner_id ORDER BY d.created_at DESC'); }); // metadata only, never content

  // Documents
  R('GET', '/api/documents', (c) => {
    const p = c.url.searchParams, w = [], a = [c.u.id, c.u.id, c.u.id], like = (s) => '%' + s.replace(/[\\%_]/g, '\\$&') + '%';
    if (p.get('q')) { w.push("d.name LIKE ? ESCAPE '\\'"); a.push(like(p.get('q'))); }
    if (p.get('owner')) { w.push("u.username LIKE ? ESCAPE '\\'"); a.push(like(p.get('owner'))); }
    if (p.get('category')) { w.push('d.category=?'); a.push(p.get('category')); }
    if (p.get('from')) { w.push('d.created_at>=?'); a.push(p.get('from')); }
    if (p.get('to')) { w.push('d.created_at<=?'); a.push(p.get('to') + 'T23:59:59.999Z'); }
    return all(`SELECT d.id,d.name,d.category,d.ext,d.size,d.created_at,d.updated_at,u.username owner, CASE WHEN d.owner_id=? THEN 'owner' ELSE g.level END level
      FROM documents d JOIN users u ON u.id=d.owner_id LEFT JOIN grants g ON g.doc_id=d.id AND g.user_id=?
      WHERE (d.owner_id=? OR g.user_id IS NOT NULL) ${w.map((x) => 'AND ' + x).join(' ')} ORDER BY d.created_at DESC`, ...a);
  });
  R('POST', '/api/documents', (c) => {
    requireRole(c.u, 'owner');
    const fname = decodeURIComponent(c.req.headers['x-filename'] || ''), ext = validateUpload(fname, c.raw);
    const id = crypto.randomUUID(), disk = crypto.randomBytes(16).toString('hex'), now = new Date().toISOString(), p = c.url.searchParams;
    fs.writeFileSync(path.join(dataDir, 'files', disk), c.raw);
    run('INSERT INTO documents VALUES(?,?,?,?,?,?,?,?,?,?)', id, clean(p.get('name'), 120, clean(fname, 120, 'document')), clean(p.get('category'), 50, 'general').toLowerCase(), c.u.id, disk, ext, c.raw.length, sha(c.raw), now, now);
    audit(c.u, 'upload', id, `${fname} ${c.raw.length}B`); c.status = 201; return { id };
  });
  R('GET', '/api/documents/([\\w-]+)/download', (c) => {
    const { d } = getDoc(c.u, c.m[1], 'read', 'download'); const buf = fs.readFileSync(path.join(dataDir, 'files', d.disk_name));
    audit(c.u, 'download', d.id, d.name); c.raw_out = { buf, name: clean(d.name, 100, 'file').replace(/\s+/g, '_') + '.' + d.ext };
  });
  R('PATCH', '/api/documents/([\\w-]+)', (c) => {
    const { d } = getDoc(c.u, c.m[1], 'edit', 'update');
    run('UPDATE documents SET name=?,category=?,updated_at=? WHERE id=?', clean(c.json.name, 120, d.name), clean(c.json.category, 50, d.category).toLowerCase(), new Date().toISOString(), d.id);
    audit(c.u, 'update', d.id, JSON.stringify({ name: c.json.name, category: c.json.category })); return { ok: true };
  });
  R('PUT', '/api/documents/([\\w-]+)/content', (c) => {
    const { d } = getDoc(c.u, c.m[1], 'edit', 'replace');
    const fname = decodeURIComponent(c.req.headers['x-filename'] || ''), ext = validateUpload(fname, c.raw);
    if (ext !== d.ext) throw new HttpError(415, 'type must stay ' + d.ext);
    fs.writeFileSync(path.join(dataDir, 'files', d.disk_name), c.raw);
    run('UPDATE documents SET size=?,sha256=?,updated_at=? WHERE id=?', c.raw.length, sha(c.raw), new Date().toISOString(), d.id);
    audit(c.u, 'replace', d.id, `${c.raw.length}B sha256=${sha(c.raw).slice(0, 12)}`); return { ok: true };
  });
  R('DELETE', '/api/documents/([\\w-]+)', (c) => {
    const { d } = getDoc(c.u, c.m[1], 'owner', 'delete');
    run('DELETE FROM documents WHERE id=?', d.id); fs.rmSync(path.join(dataDir, 'files', d.disk_name), { force: true }); audit(c.u, 'delete', d.id, d.name); return { ok: true };
  });
  R('GET', '/api/documents/([\\w-]+)/grants', (c) => { const { d } = getDoc(c.u, c.m[1], 'owner', 'list_grants'); return all('SELECT u.id user_id,u.username,g.level FROM grants g JOIN users u ON u.id=g.user_id WHERE g.doc_id=?', d.id); });
  R('POST', '/api/documents/([\\w-]+)/grants', (c) => {
    const { d } = getDoc(c.u, c.m[1], 'owner', 'grant'); const t = one('SELECT id,username FROM users WHERE username=? AND active=1', String(c.json.username));
    if (!t) throw new HttpError(404, 'user not found'); if (t.id === d.owner_id) throw new HttpError(400, 'already the owner');
    if (!['read', 'edit'].includes(c.json.level)) throw new HttpError(400, 'level must be read or edit');
    run('INSERT INTO grants VALUES(?,?,?,?,?) ON CONFLICT(doc_id,user_id) DO UPDATE SET level=excluded.level', d.id, t.id, c.json.level, c.u.id, new Date().toISOString());
    audit(c.u, 'grant', d.id, `${t.username}:${c.json.level}`); return { ok: true };
  });
  R('DELETE', '/api/documents/([\\w-]+)/grants/(\\d+)', (c) => {
    const { d } = getDoc(c.u, c.m[1], 'owner', 'revoke'); const t = one('SELECT username FROM users WHERE id=?', +c.m[2]);
    run('DELETE FROM grants WHERE doc_id=? AND user_id=?', d.id, +c.m[2]); audit(c.u, 'revoke', d.id, t ? t.username : c.m[2]); return { ok: true };
  });
  R('GET', '/api/documents/([\\w-]+)/audit', (c) => { const { d } = getDoc(c.u, c.m[1], 'owner', 'view_audit'); return all('SELECT ts,actor,action,detail,outcome FROM audit WHERE doc_id=? ORDER BY id DESC LIMIT 200', d.id); });

  const STATIC = { '/': ['index.html', 'text/html; charset=utf-8'], '/app.js': ['app.js', 'text/javascript; charset=utf-8'] };
  const server = http.createServer(async (req, res) => {
    const send = (code, obj, extra = {}) => { res.writeHead(code, { 'Content-Type': 'application/json', ...extra }); res.end(JSON.stringify(obj)); };
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'");
    try {
      const url = new URL(req.url, 'http://x');
      if (req.method === 'GET' && STATIC[url.pathname]) { const [f, t] = STATIC[url.pathname]; res.writeHead(200, { 'Content-Type': t }); return res.end(fs.readFileSync(path.join(__dirname, 'public', f))); }
      if (!url.pathname.startsWith('/api/')) throw new HttpError(404, 'not found');
      if (req.method !== 'GET' && req.headers['x-requested-with'] !== 'trustvault') throw new HttpError(403, 'missing CSRF header');
      const route = routes.map(([m, re, fn]) => (m === req.method ? [re.exec(url.pathname), fn] : [null])).find(([m]) => m);
      if (!route) throw new HttpError(404, 'not found');
      const c = { req, url, m: route[0], status: 200 };
      const chunks = []; let n = 0; for await (const ch of req) { n += ch.length; if (n > MAX_BYTES + 1024) throw new HttpError(413, 'too large'); chunks.push(ch); }
      c.raw = Buffer.concat(chunks);
      if ((req.headers['content-type'] || '').startsWith('application/json')) { try { c.json = JSON.parse(c.raw.toString() || '{}'); } catch { throw new HttpError(400, 'bad json'); } } else c.json = {};
      if (url.pathname !== '/api/login') { // authenticate: every request re-checks session AND that the user is still active
        const tok = (/(?:^|; )tv=([0-9a-f]{64})/.exec(req.headers.cookie || '') || [])[1]; c.tokenHash = tok && sha(tok);
        c.u = tok && one('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>? AND u.active=1', c.tokenHash, Date.now());
        if (!c.u) throw new HttpError(401, 'login required');
      }
      const out = await route[1](c), flags = `Path=/; HttpOnly; SameSite=Strict${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`;
      if (c.raw_out) { res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${c.raw_out.name}"` }); return res.end(c.raw_out.buf); }
      send(c.status, out, c.cookie !== undefined ? { 'Set-Cookie': c.cookie ? `tv=${c.cookie}; Max-Age=${SESSION_MS / 1000}; ${flags}` : `tv=; Max-Age=0; ${flags}` } : {});
    } catch (e) { if (e instanceof HttpError) send(e.status, { error: e.message }, e.status === 413 ? { Connection: 'close' } : {}); else { console.error(e); send(500, { error: 'internal error' }); } }
  });
  return { server, db, createUser, verifyChain };
}

export function seed(app, dataDir) {
  if (app.db.prepare('SELECT COUNT(*) n FROM users').get().n) return;
  const pw = (r) => process.env[`SEED_${r}_PW`] || `${r}-Demo#2026`;
  app.createUser('admin', pw('ADMIN'), 'admin'); app.createUser('alice', pw('ALICE'), 'owner'); app.createUser('bob', pw('BOB'), 'owner'); app.createUser('carol', pw('CAROL'), 'viewer');
  const add = (owner, name, cat, text) => { const b = Buffer.from(text), id = crypto.randomUUID(), disk = crypto.randomBytes(16).toString('hex'), now = new Date().toISOString();
    fs.writeFileSync(path.join(dataDir, 'files', disk), b); app.db.prepare('INSERT INTO documents VALUES(?,?,?,?,?,?,?,?,?,?)').run(id, name, cat, owner, disk, 'txt', b.length, sha(b), now, now); };
  add(2, 'Alice salary letter', 'hr', 'CONFIDENTIAL: salary letter (demo data)'); add(3, 'Bob client contract', 'contracts', 'CONFIDENTIAL: contract (demo data)');
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data'); fs.mkdirSync(dataDir, { recursive: true });
  const app = createApp({ dbFile: path.join(dataDir, 'trustvault.db'), dataDir }); seed(app, dataDir);
  app.server.listen(process.env.PORT || 3000, () => console.log('TrustVault on :' + (process.env.PORT || 3000)));
}
