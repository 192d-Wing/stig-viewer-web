# Backlog

Last updated: 2026-11-17. This list is in priority order. Each item ships as its own PR.

## 1. Get `main` green again

PR #48 fixed the 8 e2e failures that were listed here: the SAML login test in
spec 01, and the catalog-diff and save-to-system specs 62 and 81. `main` was
green at `8c72fb5`.

One new failure came in with #44 (`baf173a`). In spec 66, "restore of a backup
with a corrupted entry returns 400", the restore does return 400. The check
that the users are unchanged then fails, but only on alice's `lastLogin`,
which every authenticated request updates.

- [ ] Merge PR #54, which leaves `lastLogin` out of that comparison. It is e2e-only.
- [ ] Confirm that `CI / e2e` passes on `main` after #53 (`d950934`) and #54.
- [ ] Don't run Playwright against the local dev stack on :5173. `resetDb` wipes its data.

## 2. Finish binding AC-8 to the login callbacks

This plan is approved, and the decisions below are settled. It builds on the
SAML `InResponseTo` check added in PR #49.

- [ ] Add a migration that adds the columns `oidc_state`, `oidc_nonce` and `oidc_pkce_verifier` to `login_notice_acks`.
- [ ] Store only the ack id in the `stig_oidc_state` cookie. Claim it with `claim_oidc`, which runs `DELETE … RETURNING` and only matches rows less than 10 minutes old.
- [ ] Add a new `stig_saml_req` cookie with path `/auth/saml`. Set `SameSite=None; Secure` in production and `Lax` in dev.
- [ ] Add `claim_saml`, which must match the response's `InResponseTo`. Refuse unsolicited, IdP-initiated responses, with no flag to allow them. Record refusals only as audit log lines.
- [ ] Add a `LoginBinding` enum and change `consume_ack` to take a binding.
- [ ] Remove `AuthState` and the `finish_*` helpers.
- [ ] Delete consumed ack rows once they are more than 10 minutes old.
- [ ] Add an acknowledge step to the `e2e-rs` auth_gate tests.
- [ ] **Migration number:** `main` now uses up to `040_audit_guard.sql`. This change and checklist sets (item 5) both need a new number from `041` on. Whichever merges second takes the next free one.

## 3. Add exclusive XML canonicalisation for SAML

PR #49 only accepts SAML responses that are already canonical as sent.
Responses from real IdPs therefore fail closed until this is done. The
priority is low because production uses OIDC only.

- [ ] Implement exclusive c14n in-house, as approved.
- [ ] Add a SAML replay cache.

## 4. Post-quantum cryptography and FIPS

The plan is approved, and these choices are made: aws-lc-rs 1.19 (FIPS 4.x),
ML-DSA-87 hybrid signing, X25519MLKEM768, CNSA 2.0, and FIPS 140-3 required.
Issue #32 tracks the remaining crypto-agility items. #50 and #52 closed its
integrity items for `/api/sign`, audit archive segments and backups.

- [ ] **Blocked:** decide what to do about peers that only support X25519, because FIPS mode drops X25519. We need to know which peers they are: the IdP, the SMTP relay, or particular webhook receivers. Then the architect can propose ways around it.
- [ ] Add a `fips` cargo feature and a startup guard in `fips.rs`. Gate algorithms whose FIPS validation is still pending behind `STIG_FIPS_PENDING_ALGS`.
- [ ] Move Ed25519, HMAC, digests, SAML RSA and session random-number generation to aws-lc-rs.
- [ ] Add ML-DSA hybrid signatures to the v2 envelope, for `/api/sign`, audit archive segments and backups.
- [ ] Move signed export bundles to the v2 envelope. They still use the single-signature v1 format (#32, item 3).
- [ ] Accept a list of trusted previous public keys, so that the signing key can be rotated without breaking verification of older archives and backups.
- [ ] Add a cross-implementation test vector for v2 bundles, checked by the reference verifier.
- [ ] Add a CI job that builds and tests in FIPS mode.
- [ ] Add a production Dockerfile.

## 5. Ship checklist sets ("My checklists")

These are named, multi-STIG checklists. They are stored on the server for each user, autosave as you edit, and can be saved to a system again and again. The work is on branch `feat/checklist-sets` as one local commit, `a8212fe`. It hasn't been pushed. All reviewers approved it except QA, whose remaining items are minor.

Before merging:

- [ ] Rebase onto `main`. The branch is now 40 commits behind.
- [ ] Renumber `038_checklist_sets.sql`. `main` already uses `038`, `039` and `040` (see item 2).
- [ ] Run e2e spec 82 and the specs it touches (81, 66, 06, 07, 08 and 80) on the rebased branch. Spec 81 passes on `main` again, so use `main` as the baseline. Spec 66 needs #54.
- [ ] Push and open the PR. Fetch `main` first.

Product decisions. Each is the current default and can be changed:

- [ ] **Rename audit event:** should the new name be recorded? It isn't today, because audit records hold only ids and counts. Recommendation: keep it out.
- [ ] **Default name:** it is `<STIG id> <YYYY-MM-DD>`.
- [ ] **When a checklist is created:** on the first edit of a library STIG, not when the STIG is opened.
- [ ] **Admins:** they can't see other users' checklists. A request for someone else's checklist returns 404 for everyone, admins included.
- [ ] **Moving to another system:** a linked checklist must be unlinked before it can be saved to a different system.

Follow-up fixes (minor, from review):

- [ ] **Lower the size limit.** It is 10,000 rules or 16 MiB per checklist, so one user can store about 800 MiB across 50 checklists. The security review suggests 4–8 MiB per checklist.
- [ ] **Duplicate checklist on a timed-out create.** If the request times out after the server has saved the checklist, the retry makes a second, empty one. Fix with an idempotency key, or by deduplicating on the server.
- [ ] **Conflict alert after a lost response.** If an autosave succeeds but its response is lost, the next save conflicts with the user's own change. "Keep my edits" recovers it, but the alert shouldn't appear at all.
- [ ] **Timeout coverage.** The 15 s timeout applies only to autosave requests, and only until the response headers arrive. Extend it to the other checklist-set requests and to response bodies that stall.

Test gaps:

- [ ] **Leaving the page:** the flushes on `pagehide` (a keepalive request) and on `visibilitychange` aren't tested. If more than about 64 KiB of edits are unsaved, only the browser's "leave page?" prompt protects them.
- [ ] **"My checklists" errors:** no tests cover an empty list, a failed rename or a cancelled delete.
- [ ] **Not yet checked in a real browser:**
  - the `beforeunload` prompt;
  - backoff after a real 429 response;
  - handling of a 401 during autosave;
  - a possible spurious conflict after a page is restored from the back/forward cache.

## 6. Open issues

- [ ] #37: cap the decompressed size of ZIP entries in uploads, library import and restore.
- [ ] #38: opt into zip's header-consistency checks. Do restore first.
- [ ] #39: `lopdf` 0.31, pulled in by `printpdf` (Dependabot alert #11, GHSA-6fj4-rcr3-r7rr).
- [ ] #32: crypto agility. The remaining items are in item 4.

## 7. Audit follow-ups from the #44 and #52 reviews

None of these has an issue yet. File each one before starting work on it.

- [ ] **Concurrent retention sweeps.** Two sweeps running at once can quarantine an archive segment that the other is still writing.
- [ ] **`test` maintenance mode.** `stig.audit_maintenance` accepts the `test` mode in every environment. Accept it only in test builds or with test routes enabled.
- [ ] **Separate database owner role (AU-9(4)).** The app role owns the audit tables, so it could drop the guard trigger. Run migrations as an owner role and give the app role only the rights it needs.
- [ ] **Audit-write failures.** Add a counter or metric for failed audit writes, so they don't go unnoticed.

## Smaller items

- [ ] Add the missing tests from PR #49's QA review:
  - prove that the oversized-field length check runs before decoding;
  - cover the handler's wiring to the global rate limiter;
  - cover the 413 response.
- [ ] DISA STIG downloads aren't checked against a checksum. Find out whether DISA publishes one, and pin or verify it if so.
- [ ] `notice.rs`: correct the wording about whether the notice file is overwritten or appended to.
- [ ] Deployment notes:
  - apply migrations `037` to `040`;
  - mount the STIG data as a named volume; the seed is read from `STIG_SEED_DIR`;
  - set `STIG_SYNC_ON_START` and `STIG_SYNC_INTERVAL_HOURS` as wanted;
  - with `SIGNING_KEY_HEX` set, a restore needs a signed backup unless `BACKUP_REQUIRE_SIGNATURE=false`;
  - if the app runs behind a proxy, set `STIG_TRUST_PROXY_HEADERS` and `STIG_TRUSTED_PROXY_HOPS`.
- [ ] Shrink `frontend/public/brand/org-emblem.png`, which is about 1.5 MB.
- [ ] Remove the scratchpad worktrees left over from this round of PRs (`git worktree list`).

## Done

- **CodeQL:** alert #8 is fixed. Alerts #9, #10 and #11 were dismissed as false positives; #9 and #11 are covered by PR #43's id validation.
- **Dependencies:**
  - #36 moved to zip 9.6.1 and rand 0.8.8, replacing Dependabot #13 and #16;
  - #42 moved Keycloak to 26.8;
  - #40 gave the CI workflow token least privilege and pinned the compose images by digest.
- **IDs and paths:** #43 validates STIG ids wherever they're created or read and closes the draft-fork path traversal (issue #31).
- **Auth:**
  - #49 fixed SAML signature wrapping;
  - #41 builds the test SAML session cookie with the shared helper.
- **Sync and seed:**
  - #45 puts the STIG data in a seed plus a volume, adds the sync-on-start switch and stale-URL warnings, and refreshes the sources;
  - #53 regenerated the seed with the fixed parser and replaced the retired bundles (issue #10).
- **Audit (issue #30):**
  - #46 records `authz.denied` events centrally and collapses repeats;
  - #47 adds the database guard on the audit tables;
  - #44 adds request context to audit events and records audit-log reads.
- **Integrity:**
  - #52 signs audit archive segments and makes them immutable, and verifies a backup's signature before restoring it;
  - #50 adds the v2 signing envelope and a reference verifier.
- **XSS:** #51 escapes search snippet text on every path.
- **CI and e2e:** #48 fixed the e2e failures on `main`. #33 (dev and CI housekeeping) is closed.
