PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE,
  pw_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN('admin','owner','viewer')), active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL DEFAULT 'general',
  owner_id INTEGER NOT NULL REFERENCES users(id), disk_name TEXT NOT NULL, ext TEXT NOT NULL, size INTEGER NOT NULL,
  sha256 TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS grants(doc_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id), level TEXT NOT NULL CHECK(level IN('read','edit')),
  granted_by INTEGER NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(doc_id,user_id));
-- Append-only, hash-chained audit log. Triggers block UPDATE/DELETE; chain exposes any out-of-band edit.
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor_id INTEGER, actor TEXT,
  action TEXT NOT NULL, doc_id TEXT, detail TEXT, outcome TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'audit is append-only'); END;
CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_audit_doc ON audit(doc_id);
