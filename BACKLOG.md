# Backlog

Last updated: 2026-11-17. This list is in priority order. Each item ships as its own PR.

## 1. Fix the failing e2e tests on `main`

The `CI / e2e` check on `main` fails 8 of 437 tests. The same tests fail with
and without PR #49, so they were broken before it merged.

| Failing spec | First red on `main` | Likely cause |
|---|---|---|
| `01-auth-gate`: "Enter on SAML button navigates to the SAML login" (1 test) | `05b621d` or earlier | The test expects a 3xx redirect from `/auth/saml/login`, but SAML isn't configured in the e2e stack, so no redirect comes back. Either the test or the e2e stack's SAML config needs to change. |
| `62-catalog-diff`: diff modal with sections populated (1 test) | `8f1b353` (PR #45, sync-hygiene) | The diff button never appears. PR #45 changed how archive files are named (`archive_file_name` now appends a hash) and changed the seed and sync logic. |
| `81-save-to-system` (6 tests) | `8f1b353` (PR #45) | `locator.click` times out after 30 s. This is probably the same seed or data change from PR #45. |

- [ ] Download the CI artifacts (`test-failed-*.png`, `error-context.md`) and find the root cause of each failure.
- [ ] Open one small PR with the fixes. If a fix changes app code, not just a test, run it through the dev-team reviewers.
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
- [ ] **Migration number:** `038` is already taken by `038_checklist_sets.sql` on `feat/checklist-sets` (item 5). Whichever change merges second takes the next free number.

## 3. Add exclusive XML canonicalisation for SAML

PR #49 only accepts SAML responses that are already canonical as sent.
Responses from real IdPs therefore fail closed until this is done. The
priority is low because production uses OIDC only.

- [ ] Implement exclusive c14n in-house, as approved.
- [ ] Add a SAML replay cache.

## 4. Post-quantum cryptography and FIPS

The plan is approved, and these choices are made: aws-lc-rs 1.19 (FIPS 4.x),
ML-DSA-87 hybrid signing, X25519MLKEM768, CNSA 2.0, and FIPS 140-3 required.

- [ ] **Blocked:** decide what to do about peers that only support X25519, because FIPS mode drops X25519. We need to know which peers they are: the IdP, the SMTP relay, or particular webhook receivers. Then the architect can propose ways around it.
- [ ] Add a `fips` cargo feature and a startup guard in `fips.rs`. Gate algorithms whose FIPS validation is still pending behind `STIG_FIPS_PENDING_ALGS`.
- [ ] Move Ed25519, HMAC, digests, SAML RSA and session random-number generation to aws-lc-rs.
- [ ] Add a hybrid signature envelope.
- [ ] Add a CI job that builds and tests in FIPS mode.
- [ ] Add a production Dockerfile.

## 5. Ship checklist sets ("My checklists")

These are named, multi-STIG checklists. They are stored on the server for each user, autosave as you edit, and can be saved to a system again and again. The work is on branch `feat/checklist-sets` as one local commit, `a8212fe`, rebased onto `252cce9`. It hasn't been pushed yet. All reviewers approved it except QA, whose remaining items are minor.

Before merging:

- [ ] Run e2e spec 82 and the specs it touches (81, 66, 06, 07, 08 and 80) on the rebased branch. They passed before the rebase. Spec 81 also fails on `main` (see item 1), so get item 1 fixed first, or compare against that baseline.
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

## Smaller items

- [ ] Add the missing tests from PR #49's QA review:
  - prove that the oversized-field length check runs before decoding;
  - cover the handler's wiring to the global rate limiter;
  - cover the 413 response.
- [ ] Deployment notes: migration `037` must be applied. If the app runs behind a proxy, set `STIG_TRUST_PROXY_HEADERS` and `STIG_TRUSTED_PROXY_HOPS`.
- [ ] Shrink `frontend/public/brand/org-emblem.png`, which is about 1.5 MB.

## Done

- CodeQL: alert #8 is fixed. Alerts #9, #10 and #11 were dismissed as false positives; #9 and #11 are covered by PR #43's id validation.
- PR #49 fixed SAML signature wrapping and merged on 2026-11-17.
