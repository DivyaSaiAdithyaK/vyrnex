# 🔐 TrustVault — secure document sharing

Zero-dependency Node 22 app (built-in `node:sqlite`, `node:http`, `node:test`). No `npm install` needed.

## Run
```bash
npm start            # http://localhost:3000 — creates data/ and seeds demo users on first run
npm test             # 11 tests incl. cross-user access, revocation, audit tamper
```
**Deploy (Render / Railway / Fly):** use the `Dockerfile` (or "Node" runtime, start `node server.js`). Mount a persistent disk at `/data`
and set `DATA_DIR=/data`, `NODE_ENV=production`. Set `SEED_ADMIN_PW`, `SEED_ALICE_PW`, `SEED_BOB_PW`, `SEED_CAROL_PW` to override demo passwords.
Needs HTTPS (platforms provide it) because the cookie is `Secure` in production. Requires Node ≥ 22.13.

## Demo credentials (seed data)
| Role | User | Password |
|---|---|---|
| administrator | `admin` | `ADMIN-Demo#2026` |
| document owner | `alice` | `ALICE-Demo#2026` |
| document owner | `bob` | `BOB-Demo#2026` |
| viewer | `carol` | `CAROL-Demo#2026` |

## Permission model
| Capability | admin | owner | viewer |
|---|---|---|---|
| Create/disable users, change roles | ✅ | ❌ | ❌ |
| View audit trail + metadata of all docs | ✅ | own docs only | ❌ |
| Upload documents | ❌ | ✅ | ❌ |
| Read/edit/delete/share a document | **only if granted/owner** | own docs | only if granted `read`/`edit` |
Per document: **owner** (full, grant/revoke, delete) · **edit** (read, rename, replace content) · **read** (view/download). Admins deliberately **cannot read content**.
Single decision point: `getDoc()` in `server.js`. Re-evaluated on every request (no cached tokens/URLs), so revocation and user-disable are immediate.
Unauthorised access returns **404** (existence not revealed) and is written to the audit log; insufficient level returns 403.

## API (who may call)
| Endpoint | Allowed |
|---|---|
| `POST /api/login`, `POST /api/logout`, `GET /api/me` | anyone / any logged-in |
| `GET /api/users/directory` | any logged-in (usernames only, for sharing) |
| `GET/POST /api/users`, `PATCH /api/users/:id`, `GET /api/audit`, `GET /api/audit/verify`, `GET /api/admin/documents` | admin |
| `GET /api/documents?q=&owner=&category=&from=&to=` | any logged-in; returns only docs they own or were granted |
| `POST /api/documents` (raw body, `X-Filename` header, `?name=&category=`) | owner role |
| `GET /api/documents/:id/download` | read+ |
| `PATCH /api/documents/:id`, `PUT /api/documents/:id/content` | edit+ |
| `DELETE /api/documents/:id`, `GET/POST /api/documents/:id/grants`, `DELETE …/grants/:userId`, `GET …/audit` | document owner |
All mutating calls require header `X-Requested-With: trustvault` (CSRF) plus `SameSite=Strict` cookie.

## Audit trail
Every login (incl. failures), upload, download, rename, replace, delete, grant, revoke, user change **and every refused attempt**. Append-only via SQLite triggers
and **hash-chained** (`hash = sha256(prev_hash|fields)`); admin UI "Verify integrity" detects edits made outside the app. See `THREATS.md` for limits.

## Schema
`schema.sql` (applied automatically at start). Upload validation: extension allow-list, magic-byte check, 5 MB cap, random on-disk names, `attachment` + `nosniff` on download.
