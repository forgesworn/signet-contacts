# Changelog

## Unreleased

- **Security (B1): pairing verification code against a photographed-QR
  takeover.** `awaitPairingAck` has no author pin and accepts the first ack
  that decrypts and echoes the challenge, so a forged ack published from the
  QR's own `appPubkey`/`challenge` — before the owner's real ack lands — used
  to pair the app to the attacker's rail with nothing on screen to say so.
  New `pairingCode(appPubkey, challenge, grantId, railPubkey)` and
  `formatPairingCode(code)` in `src/wire/pairing-code.ts` (exported from
  `src/wire/index.ts` and the package root) build a 6-digit code from values
  — `grantId`, `railPubkey` — that exist only inside the real ack, never
  inside the photographed QR; `docs/WIRE.md` §3 states the consumer/producer
  rules, `SECURITY.md` names the threat as B1, and `docs/INTEGRATION.md`'s
  pairing walkthrough adds the confirm step before a pairing is used for
  anything. `vectors/pairing-code.json` freezes four cases. No wire message,
  ack, projection, or QR format changed.
- **Fix (B2): proposal resend.** Proposals ride one replaceable event per
  grant, so a second `propose` call used to overwrite the first before Signet
  had read it, and the client never resent — a suggestion sent while Signet
  was offline, or between two propose calls, was silently lost. `propose` now
  carries every still-pending proposal alongside new ones, rebuilt with its
  original `operationId`/`action`/`value`/`createdAt` so a resend is
  byte-identical in meaning to the first send; new proposals always come
  first, and resends are newest-`sentAt`-first, so new suggestions are never
  squeezed out by old stuck ones. See the `propose` doc comment
  (`src/client.ts`) and `docs/WIRE.md`'s proposal-batch section. No wire
  message or batch shape changed — a consumer resending an operationId a
  producer already applied is exactly the idempotency this wire already had.
- **Contract (docs only; no wire bytes, versions or tag derivations changed).**
  The capability-scoped v2 contract is frozen. `docs/WIRE.md` gains a per-message
  version table (§0): the app-access rail (pairing, ack, envelope, projection)
  is `v: 2`; proposal batches, app-introduction requests/replies and contact
  invites/exchange messages are `v: 1`. It replaces the earlier claims that every
  payload is `v: 2` and every routing tag is hashed — the app-introduction `d`
  tags are readable and carry the `grantId`, and the ack and contact-exchange
  events carry readable `p` tags. Adds an **Unsupported readers** statement
  (Kenspeckle v1, bare-NIP-44 readers, pre-contract SDK builds, older producers,
  any other `v`), the `checks[]` and `avatar.key` rows in the contact shape table,
  and the consent rule (§10): ordinary updates keep an existing approval; an
  extra capability, a wider directory, a longer staleness window or a new field
  class needs a fresh pairing. Contact invites and app introductions are marked
  final; the channel-check profile stays a draft outside the contract.
- **Breaking (wire, pre-release): field coverage is enforced on both sides.**
  One table, `FIELD_COVERAGE` (`src/wire/coverage.ts`), maps each projected-contact
  field to the capabilities it needs. `buildProjection` throws on a contact
  carrying a field its `scopes` do not cover, and `parseProjection` refuses such a
  projection whole (`parseProjectedContact` takes optional `scopes` to do the same
  per contact). `avatar`, `type` and `linkedPubkeys` are covered by no capability,
  so a projection carrying them is now refused; legacy full snapshots no longer
  parse. `vectors/projection.v2.json` is regenerated for the contract freeze:
  every case carries only covered fields, the full case gains the scopes it
  needs, and a new `uncovered` list holds projections a parser must refuse.
- **Breaking (API, pre-release):** `parseProjectedContact(raw, scopes)` now requires
  `scopes`, so no caller can parse a contact without the field-coverage check.
- Clarify identity-scoped grants and owner confirmation for cross-identity app
  proposals in consent copy and wire documentation; wire shape is unchanged.
- Document opaque, grant-local publication metadata for scoped projections.

- Replace broad contact-method access with separate phone, email, website,
  postal-address and other-method capabilities; legacy broad grants do not expand.
- Default directory access contains names and public keys only. Tiers and
  verification status need their own capabilities; omitted fields stay unknown.
- Support minimal projections. (Legacy full snapshots were parsed for a while;
  field coverage, below, now refuses them.)


This package has no published releases yet; consumers install it pinned to a
commit. Entries are therefore dated rather than versioned, and a wire change
that is not backwards compatible says so in its own words.

## 2026-09-16 — pre-release wire changes

**Breaking (wire): `ownerPubkey` is gone from the projection body (R-31).**
`ContactProjectionV2` no longer carries the directory owner's persona pubkey.
It was stable across every grant on a directory, so two colluding apps could
join their projections on it in one line — the exact link `scopedContactId`
exists to break — and on a `dependant` directory it was a minor's long-lived
public identity handed to every paired app. No part of this SDK ever read it.
A producer that sends the field anyway is not rejected: the parser drops it, so
nothing reaches a consumer. `vectors/projection.v2.json` was regenerated once
for this change and records the reason in its own `regenerated` field;
signet-app regenerates its parity fixtures to match.

**Behaviour: a projection is now ordered by `publishedAt` first, `maxClock` as
the tiebreak (R-30).** A block published from one of the owner's devices whose
contacts log is behind carries a Lamport frontier no higher than one the
consumer already holds; under the old `(maxClock, publishedAt)` order the whole
projection — block included — was refused until some later change happened to
be published. Safety state must not wait for the producer's log to converge, so
recency decides and the Lamport clock only breaks a same-second tie. An exact
tie on both is still ignored, and a revocation is still exempt from the check
entirely.

**Behaviour: the pairing ack is chosen from up to 10 candidates (I3).**
`awaitPairingAck` no longer fetches a single newest event: a third party who
photographed the pairing QR could park one junk kind-21237 addressed to the app
and keep the genuine ack out of a `limit: 1` answer for the whole window, while
the owner's device had already spent a grant slot on it. Each candidate is now
tried newest-first and the first that decrypts to the app's own key and carries
the pairing challenge wins. `RelayIo` gains an optional `fetchMany`; a transport
without one degrades to the previous single-candidate behaviour, and the
bundled `SimplePool` adapter implements it over `querySync` (falling back to one
`get` per relay).

**Behaviour: live updates (R-32).** `client.start(pairing)` subscribes to the
grant's projection slot through `RelayIo.subscribe` and polls every `pollMs`
(default 60 000 ms) as a fallback, so a new projection and a revocation
tombstone both arrive without the app asking. `onRevoked` fires from the live
path and the fetch path alike, once per revocation (a repeated tombstone does
not fire twice; a re-revocation after an un-revoke does). `client.stop()` unsubscribes and
clears the poll, and is idempotent; `start` returns a handle scoped to its own
subscription, and a poll tick the live socket has already covered is skipped. Previously `RelayIo.subscribe` was declared
and implemented but never called, so a consumer that wired `onRevoked` and
waited learned nothing until it happened to fetch again.

**Copy: `propose:add-ken` says what it does (R-28d).** The capability is
described as "Add contacts to your Ken list (recognised only, no access)" —
never "ask you to add", which described an owner decision the producer does not
make. `read:directory` also now names linked pubkeys, which every projected
contact carries.

**Bounds: `relay`, `challenge` and the raw pairing URI are capped in the
parsers (C-I7).** A relay URL is at most 256 characters (`MAX_RELAY_LEN`,
matching signet-app's own storage bound, so a pairing this SDK accepts can
never produce a grant that fails to sync to the owner's second device) as well
as `wss://`-or-loopback; a challenge is exactly 32 hex characters
(`CHALLENGE_HEX_CHARS`, replacing an open-ended `{16,}`); a pairing URI over
`MAX_PAIRING_URI_CHARS` (2048) is refused before its query string is parsed.
All three are hard parse failures, never silent truncations.

**Smaller things in the same pass.** `parseProjection` now sets `truncated`
itself when it has to cut an over-sent `contacts` list, so a consumer is never
handed a short list it believes is complete. `package.json` exports
`./vectors/*` (both repositories' parity tests read those files, and a bundler
enforcing `exports` could not) and relaxes `engines.node` to `>=18`, which is
what the platform globals this package uses actually require. Workstream
bookkeeping — "Fix round 1", "Controller correction", bare review-item numbers,
signet-app file paths — is out of the shipped source; the reasoning those
comments carried stays. British spelling throughout ("zeroised"). WIRE.md now
documents the web and Android App Link pairing carriers alongside the
`signet-grant:` scheme.

## 2026-09-18 — app introductions

- Add explicit invite issuance and delivery capabilities, separate from contact
  list access, plus bounded app-to-rail requests and issuance/queueing replies.
- Add `createAppInviteClient` with one outstanding request per grant. No peer
  completion status, check result or private invite attribution is returned.
- Producer policy permits five-minute first-request automatic acceptance only
  for eligible single-use app invites, with a per-app opt-out and grant revocation.
  Family/bot producer routing remains separate work.
