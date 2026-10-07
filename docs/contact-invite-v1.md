# Contact invite/exchange v1

Status: **final** for the first release. This profile implements contacts spec
§§4–5. Its messages are versioned `v: 1` independently of the v2 app-access rail
(see the version table in `WIRE.md` §0); its frozen fixture is
`vectors/contact-invite-v1.json`. No compatibility with any other invite protocol
is claimed, and a message with any other `v` is rejected.

## Invite and mailbox

An invite is UTF-8 JSON with v=1, recipient (64 lowercase hex), secret (32 random
bytes as lowercase hex), and 1–8 wss relay URLs. Optional expiry is Unix seconds;
optional public caption is at most 200 characters, without controls/bidi markers.
Private names, intended recipient and single-use/standing policy never enter it.
URLs use WHATWG URL serialization, preserving input order and removing duplicates.

Mailbox secret key: HKDF-SHA256, IKM=invite secret bytes,
salt=UTF8(`signet-contacts:mailbox:v1`), empty info, output 32 bytes. Reject zero
or scalars >= secp256k1 order; generate another invite secret instead of reducing.
Use the x-only secp256k1 public key. Keep this key on the app, never Heartwood.

## Transcript and words

`invite.ts` defines allowlisted request, acceptance and reveal shapes. IDs are
16 random bytes as lowercase hex; nonces are independent 32 random bytes. Times
are Unix seconds. A request lasts at most 30 days. Accept/reveal must occur within
its interval and reveal cannot predate acceptance. Stored completed words remain
valid after request expiry.

Hash encodings are SHA256 over UTF-8 JSON arrays (no spaces):

- Commitment: [`signet-contacts:commit:v1`, id, requester, recipient, nonceA].
- Message hash: [`signet-contacts:message:v1`, parsed message]. Parser field order
  is normative; unknown fields are dropped. Relay normalization above applies.
  The optional `card` (below) is **excluded**: hash the parsed message with `card`
  removed.
- Word material: [`signet-contacts:words-material:v1`, requestHash, acceptanceHash,
  nonceA]. Reveal timestamp is deliberately excluded: choosing a later reveal
  time must not give the requester another attempt at matching words.

Feed material hash bytes to spoken-token **2.1.0** `deriveDirectionalPair`,
namespace `signet-contacts:exchange:v1`, roles=[lower pubkey, higher pubkey],
counter=0, words/count=3 with its default en-v1 2048-word list. Local role is
“You say”; the other role is “They say”. Copy only the local role.

Applications must pin the first accepted request and acceptance hashes before
revealing nonceA. A second acceptance is not a retry if its hash changed. Transport
signature verification and recipient checks are mandatory before state changes.

## Contact card (optional, additive)

A request or an acceptance may carry `card`, a self-declared name and a pointer
to a photo the sender chooses to share. It is never on the reveal.

```
card?: { name?: string; photo?: { key: string; server: string; hash: string } }
```

- `name`: remove control characters (U+0000–U+001F, U+007F–U+009F) and bidi
  characters (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069), trim, then
  require 1–100 characters (UTF-16 code units). Otherwise drop `name`.
- `photo.key` and `photo.hash`: exactly 64 lowercase hex. `key` decrypts the blob
  whose SHA-256 is `hash`.
- `photo.server`: a URL that parses, is `https:`, has no username, password or
  fragment, and is at most 512 characters. It is stored as the WHATWG URL
  serialisation (`href`), which must also fit in 512 characters.
- Parsing is a strict allowlist: unknown card and photo fields are dropped. An
  invalid `photo` drops `photo` only; a card left with no valid field is dropped;
  a card whose JSON exceeds 1024 bytes, as received or once normalised, is
  dropped. **An invalid card never invalidates the message.**
- `createContactRequest({ …, card })` and `createContactAcceptance(request, nonce,
  now, card)` validate on create and throw `Invalid contact card`: a bad card from
  your own code is a bug, not input. An acceptance never inherits the requester's
  card.

**The card is not part of any hash.** It is excluded from `contactMessageHash`,
and therefore from `requestHash`, `acceptanceHash`, the commitment and the
verification words. A message with a card hashes identically to the same message
without one. That is what keeps older parsers, which drop the field, in agreement
on every hash: mixed versions still complete exchanges, they simply do not get the
card.

**Authenticity** comes from the persona-signed kind-13 seal that carries the
message, not from the card or the transcript. The adapter verifies the seal and
requires `message.from` to equal the seal signer, and `message.to` to equal the
decrypting identity. Treat the name as self-declared: anyone holding the invite
can claim any name. Do not fetch `photo.server` before the user has accepted the
exchange. Vectors: `vectors/contact-card-v1.json`.

## Encrypted transport

A standard NIP-59 wrap addressed to a shared mailbox exposes the identity seal's
pubkey to every invite holder. This profile deliberately uses an additional layer:

1. Identity signs kind-13 seal with empty tags and canonical message JSON content.
2. Fresh ephemeral key encrypts the entire signed seal to the real recipient
   identity with NIP-44 v2. Packet is {v:1,key:ephemeralPubkey,ciphertext}.
3. A different fresh ephemeral key encrypts that packet to the mailbox, and signs
   kind 1059 with only the mailbox p tag. Seal/wrap timestamps are randomized up
   to two days earlier. Message times remain inside encryption.

This is a contacts-specific inner packet, **not** something ordinary NIP-59
unwrapEvent can open directly. The adapter verifies each signature and checks
message.from against the seal signer and message.to against the decrypting key.
Outer opening is local-only. Identity opening performs one identity-key decrypt
and occurs only on explicit inbox access. Sending/accepting uses one identity
signature; encryption keys are ephemeral and immediately wiped.

Bounds: 8192-byte message, 20000-character packet/ciphertext, 32000-character
outer ciphertext; 32 identity decrypts per unlock, 128 pending per invite, 8 per
sender after opening. Automatic app-introduction acceptance window is 300 seconds.
The parsers and the bundled adapter enforce the size bounds; the app must enforce
the counters and policies.

Invites and pending nonce/reply-mailbox state belong in the private contacts
vault. Subscribe through separate connections per identity. Decline/revoke sends
nothing. Pasted npubs without an invite never cause requests. A mailbox packet
alone is not evidence of Kith or verification.
