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
- No app ever receives the owner's vault key, their Natural Person key, the
  shared contacts npub, or the persona pubkey of whoever's directory it is
  reading — the rail key, and only the rail key, is what a connected app ever
  sees. A projection deliberately carries no owner pubkey (R-31): it would have
  been identical in every grant on that directory, so two colluding apps could
  have joined on it in one line, and on a dependant directory it would have
  been a minor's long-lived public identity.
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
- `operationId` (16 random bytes, 32 hex characters, minted per proposal) is the
  idempotency key: a producer that has already applied one does nothing on a
  retry. Idempotency by id alone is not a ceiling, so the producer also refuses
  an `add-ken` for a pubkey its directory already holds, caps how many contacts
  one grant may create, and drops app-created records first when a projection
  has to be truncated — an app cannot grow a directory without bound, nor push
  the owner's own contacts out of a different app's view.
- Revocation stops future reads and writes; it cannot recall plaintext an app
  has already decrypted — see the README's "Revocation is not recall".
- Blocked state is sticky inside the consumer client and never decays on a
  timer or an expired projection; only a newer, non-revoked projection may
  narrow it — and "newer" is decided by when a snapshot was published, not by
  how much of the owner's log the publishing device had seen (R-30), so a block
  entered on a device that is behind still applies at once. Stickiness survives
  a restart only if the client was given persistent storage; the default store
  is in-memory (see the README).
- Blocking inside this wire cannot stop someone publishing ordinary Nostr
  events, nor reaching the person through an unrelated identity or an
  application outside Signet's own enforcement boundary.
- **S7 — author pinning.** A projection's authenticity check compares
  `event.pubkey` against the grant's known rail pubkey; nothing here verifies
  the Schnorr signature itself. The real gate is the NIP-44 decrypt that
  follows: a relay is free to forge a `pubkey` on a fabricated event, and the
  only thing that buys it is one failed decrypt.
- **S4 — freshness is advisory, and enforced only by the consumer.**
  `expiresAt` is a value the producer wrote and `isFresh` is a check the
  consuming app chooses to make; nothing stops an app that ignores it from
  keeping a directory indefinitely. The wire cannot take a projection back, so
  the staleness window is a promise about how often the producer refreshes, not
  a permission that lapses.
- **S5 — a revocation reaches an app only when that app next reads.** The
  owner's device stamps the grant revoked locally whether or not the relay
  accepted the tombstone, which is the right local-authority choice: a failed
  publish must not leave a grant live. The residual is on the consumer's side.
  A client running `start()` sees the tombstone within seconds; one that is
  offline, or that only fetches at launch, keeps a valid-looking directory
  until its own projection expires — up to `MAX_STALENESS_SECONDS` (7 days) in
  the worst case. "Disconnected" on the owner's screen therefore means "no
  further updates, and no further reads once its copy expires", not "erased".
- **S8 — timing trade-off.** The rail pubkey IS on the wire, as `event.pubkey`,
  and the app learns it from the ack. A relay colluding with the app it serves
  can therefore watch that grant's publish cadence. This is the accepted
  per-app-channel timing trade-off (exploration §5.1): a separate rail per app
  buys unlinkability *between* apps at the cost of one relay being able to
  time a single app's own channel.
- **S9 — the rendezvous relay is chosen by the app being paired.** The pairing
  URI names the relay the ack is published to, so approving a grant makes the
  owner's device dial a host the requesting app picked; it is validated for
  scheme and length, not for who runs it. This is the same posture as the
  shipped v1 companion rail, and is accepted: pairing needs a meeting point
  both sides can reach, the ack is sealed to the app's own key and signed by a
  throwaway one, and nothing about the owner's identity is on that leg.
- The `railSecretKey`/`appSecretKey` values committed in
  `vectors/envelope.v2.json` are fixed **test keys only**, generated once for a
  reproducible fixture — never reuse them for anything real.
