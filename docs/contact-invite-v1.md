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
