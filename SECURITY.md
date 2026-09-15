# Security model

This is the threat model the contacts app-access wire (v2) was built against.
It is deliberately short: read it alongside `docs/WIRE.md` for the mechanism
behind each line, and the README's "Two honesty boundaries" for the two things
this wire cannot promise no matter how it is implemented.

- The grant's rail key is per-grant and freshly random; revoking one app's
  grant never affects any other app's rail, projection or proposal channel.
- The grant's rail **private** key travels inside the owner's own sealed
  backup (the contacts grants rail), so a second device can publish the same
  grant. It sits inside the same trust boundary that already protects the
  contacts themselves — anything that can open the vault can already open
  every rail inside it — so this is not a new exposure; without it a grant
  would silently be single-device.
- No app ever receives the owner's vault key, their Natural Person key, or the
  shared contacts npub — the rail key, and only the rail key, is what a
  connected app ever sees.
- A projection is sealed to the app's own pubkey inside the v2 vault envelope
  and padded into a fixed bucket; the event carries no `#p` tag, so neither
  the recipient nor the directory's real size is visible to anyone reading the
  relay.
- Routing tags (`projectionTag`, `proposalTag`, `scopedContactId`) are opaque
  SHA-256 digests — knowing the rail's npub is a prerequisite to finding
  anything to read at all.
- A projection excludes ECDH secrets, private notes, raw vouches/ceilings/blocks
  and every other directory **by construction** — the wire's own types have no
  field for them, not merely "the current builder happens not to fill them in".
- A proposal is a request, never a write: it is validated against the grant
  and mapped onto a canonical contact operation only after that check passes.
- `operationId` (32 random hex bytes minted per proposal) makes every proposal
  idempotent and safe to retry or replay.
- Revocation stops future reads and writes; it cannot recall plaintext an app
  has already decrypted — see the README's "Revocation is not recall".
- Blocked state is sticky inside the consumer client and never decays on a
  timer or an expired projection; only a newer, non-revoked projection may
  narrow it.
- Blocking inside this wire cannot stop someone publishing ordinary Nostr
  events, nor reaching the person through an unrelated identity or an
  application outside Signet's own enforcement boundary.
- **S7 — author pinning.** A projection's authenticity check compares
  `event.pubkey` against the grant's known rail pubkey; nothing here verifies
  the Schnorr signature itself. The real gate is the NIP-44 decrypt that
  follows: a relay is free to forge a `pubkey` on a fabricated event, and the
  only thing that buys it is one failed decrypt.
- **S8 — timing trade-off.** The rail pubkey IS on the wire, as `event.pubkey`,
  and the app learns it from the ack. A relay colluding with the app it serves
  can therefore watch that grant's publish cadence. This is the accepted
  per-app-channel timing trade-off (exploration §5.1): a separate rail per app
  buys unlinkability *between* apps at the cost of one relay being able to
  time a single app's own channel.
- The `railSecretKey`/`appSecretKey` values committed in
  `vectors/envelope.v2.json` are fixed **test keys only**, generated once for a
  reproducible fixture — never reuse them for anything real.
