# Write-up
**Built:** TrustVault — roles (admin/owner/viewer), per-document read/edit grants to named users, upload/validate/search/manage, immutable hash-chained audit incl. refused attempts, admin activity view, 11 automated access tests.
**Deliberately not built:** AI sharing-suggestions (the machine must never widen access), file encryption at rest, 2FA, virus scanning, external audit anchoring, password reset, groups/folders (folders are the classic over-sharing trap; flat per-document grants only).
**Permission model (own words):** a document has one owner; anyone else needs an explicit grant row. One function decides. Admins run the system but are not trusted with content. Anything not explicitly allowed is a 404.
**AI usage / where it was wrong:** *(complete honestly — see PROMPTS.md)*
**Unfinished:** see THREATS.md "Accepted" rows.
