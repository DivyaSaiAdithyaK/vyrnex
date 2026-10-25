# THREATS.md — how this could be broken (honest version)
| # | Attack | What I did | Status |
|---|---|---|---|
| 1 | IDOR: guess/enumerate doc IDs, call any route | All doc routes use `getDoc()`; UUIDs; 404 on no-access. Test loops over 7 routes | Closed (tested) |
| 2 | Forged/hidden-button calls (viewer uploads, read-grantee edits) | Role check + level check server-side | Closed (tested) |
| 3 | Revoked user keeps access via old session/link | No signed URLs; permission read from DB each request | Closed (tested) |
| 4 | Disabled/ex-employee session still works | Sessions deleted on disable AND join checks `active=1` | Closed (tested) |
| 5 | Admin abuse reading content | Admins have no content route; metadata only | Closed by design |
| 6 | Search leaks other users' docs | Search SQL is restricted to owned/granted rows before filters | Closed (tested) |
| 7 | Malicious upload (exe renamed .pdf, huge file, path traversal) | Allow-list, magic bytes, 5 MB, random disk names, nosniff | Mostly closed; no antivirus scan |
| 8 | Stored XSS via names | UI uses `textContent` only; CSP `default-src 'self'` | Closed |
| 9 | CSRF | SameSite=Strict + custom header | Closed |
| 10 | Audit tampering | Triggers block UPDATE/DELETE; hash chain detects tampering | **Partly accepted:** someone with raw DB write access can drop triggers and *recompute the whole chain*. Fix = ship hashes to external storage; not done |
| 11 | Brute-force login | 5 tries / 10 min per user+IP, scrypt | **Accepted:** counter is in memory (resets on restart, per-instance) |
| 12 | Username enumeration | Same error + dummy hash for unknown users | **Accepted:** `/api/users/directory` lists usernames to any logged-in user (needed for sharing) |
| 13 | Audit flooding (spam denied requests) | none | **Accepted**, no rate limit on authenticated requests |
| 14 | Files readable on disk if server compromised | none | **Accepted:** no encryption at rest |
| 15 | Stolen session cookie | HttpOnly, Secure (prod), 8 h expiry | **Accepted:** no 2FA, no IP binding |
| 16 | Demo credentials in README | needed for judges | **Accepted:** rotate via `SEED_*_PW` env vars |
| 17 | Grantee's copy after download | cannot be technically prevented | Out of scope; download is audited |
Not tested by me: concurrent race on grant/revoke (SQLite is synchronous here, so low risk), very large concurrent uploads (memory buffering).
