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
