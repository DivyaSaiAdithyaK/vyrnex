# PROMPTS.md — fill in AS YOU WORK (≥5 dated entries, ≥2 about authz/access/audit)
Template per entry: **Date** · Prompt asked · What it produced · What was wrong (specifically) · What I did instead (commit link)

## Reused context file
Paste your standing instruction here (e.g. "Never add a doc route without calling getDoc(); return 404 on no access").

## 2026-10-25 — example entry (rewrite with your own real experience)
- **Asked:** build the upload endpoint with a 5 MB limit.
- **Produced:** limit enforced by throwing mid-stream.
- **Wrong:** client connection kept alive with unread body; the next request failed ("fetch failed") and the test hung 6 s.
- **Fixed:** send `Connection: close` on 413 — commit `<link>`.
