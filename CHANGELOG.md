# Changelog

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
path and the fetch path alike, exactly once. `client.stop()` unsubscribes and
clears the poll, and is idempotent. Previously `RelayIo.subscribe` was declared
and implemented but never called, so a consumer that wired `onRevoked` and
waited learned nothing until it happened to fetch again.

**Copy: `propose:add-ken` says what it does (R-28d).** The capability is
described as "Add contacts to your Ken list (recognised only, no access)" —
never "ask you to add", which described an owner decision the producer does not
make. `read:directory` also now names linked pubkeys, which every projected
contact carries.
