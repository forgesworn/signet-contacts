# Contacts app-access wire — v2 contract

This is the language-neutral specification of the wire `@forgesworn/signet-contacts`
implements. It exists so an implementation in a language other than TypeScript
(a Dart mobile client, for instance) can be built without reading the SDK's own
source — everything here is normative for a byte-compatible implementation.

**Status: frozen.** The capability-scoped v2 contract below — the message
versions in §0, the capability list in §6 and the consent rule in §10 — is the
contract for the first release. Changing any of it needs a new message version
and, for anything that widens what an app can read, a fresh pairing.

## 0. Message versions

"v2" names the **app-access rail** (pairing, ack, vault envelope, projection);
`WIRE_VERSION = 2` in the SDK. It is **not** a claim that every payload carries
`"v": 2`. Each message kind is versioned on its own, and a reader must require
exactly the `v` in this table for that kind — any other value is rejected
(`null`, or the `bad-version` warning for a pairing URI), never coerced or
negotiated.

| Message | `v` | Carrier | Routing tag | Tag form | Defined in |
|---|---|---|---|---|---|
| Pairing URI | `v=2` (query string) | QR code or link, not an event | — | — | §3; `src/wire/pairing.ts` |
| Pairing ack | `2` | kind `21237`, ephemeral key → app, NIP-44 | `["p", appPubkey]` | readable (the app pubkey is already public in the QR) | §3, §5; `src/wire/ack.ts` |
| Vault envelope | `2` | the projection event's `content` | — | — | §1; `src/wire/envelope.ts` |
| Projection body | `2` | kind `30078`, rail → app, inside the vault envelope | `d` = `projectionTag(grantId)` | **hashed** | §5; `src/wire/projection.ts` |
| Proposal batch, and each proposal in it | `1` | kind `30078`, app → rail, NIP-44 | `d` = `proposalTag(grantId, appPubkey)` | **hashed** | §5; `src/wire/proposal.ts` |
| App-introduction request | `1` | kind `30078`, app → rail, NIP-44 | `d` = `signet:contacts:app-invite:<grantId>` | **readable** | App introductions; `src/wire/app-invite.ts` |
| App-introduction reply | `1` | kind `30078`, rail → app, NIP-44 | `d` = `signet:contacts:app-invite:<grantId>:<requestId>` | **readable** | App introductions; `src/wire/app-invite.ts` |
| Contact invite | `1` | QR code or link, not an event | — | — | `docs/contact-invite-v1.md`; `src/wire/invite.ts` |
| Contact request / acceptance / reveal | `1` | kind-13 seal inside a sealed packet inside kind `1059` | `["p", mailboxPubkey]` | readable (the mailbox key is derived from the invite secret, so it means something only to invite holders) | `docs/contact-invite-v1.md`; `src/wire/invite.ts` |
| Sealed contact packet | `1` | inner layer of that kind `1059` | — | — | `docs/contact-invite-v1.md`; `src/adapters/invite-nostr-tools.ts` |
| Channel-check request / accept / reveal | `1` | the host app's own authenticated channel | — | — | `docs/channel-check-v1.md` — **draft, outside this contract** |

A **readable** tag is visible to anyone reading the relay. The app-introduction
tags carry the `grantId` in the clear, so a relay observer who sees one can
compute that grant's `projectionTag` and link the two slots. The payloads stay
NIP-44 encrypted; only the routing is linkable. Separate message versions are
deliberate: a version number is meaningful only within its own message kind.

### Unsupported readers

None of the following is supported, and none of them fails open:

- **Kenspeckle v1 companion-rail readers.** A `v=1` `signet-grant:` URI or a
  `v: 1` kind-21237 ack belongs to that older rail. This SDK refuses both
  (`bad-version` / `null`), and a v1 reader handed a v2 URI, ack or projection
  cannot parse it — it sees no pairing at all, never a partial grant.
- **Readers expecting a bare NIP-44 projection.** A plain `nip44Decrypt` of a
  projection's `content` fails; such a reader sees nothing (§1).
- **Pre-release builds of this SDK from before this contract** — any build that
  still knows `signet.contacts.read:methods`, or that requires tier or
  verification fields on every contact. They drop capability tokens they do not
  know, so they believe the grant is narrower than the owner approved; they
  never see `checks`; and one that requires tier or check fields may reject a
  current, smaller snapshot. Update the SDK, then pair again.
- **Producers of legacy full snapshots** — ones that send `type`,
  `linkedPubkeys`, `avatar`, or tier and verification fields without the
  capabilities that cover them. The consumer refuses the whole projection
  (§10), so the app sees no update rather than more than was granted.
- **Older producers.** A producer that does not know a capability token rejects
  a pairing request carrying it, so `awaitPairingAck` returns `null`, the same
  as a timeout or a refusal.
- **A message with any other `v`** than the table gives for its kind. It is
  dropped. A future version is a new pairing (rail) or a new profile (invites),
  never a silent upgrade.
- **Standard NIP-59 `unwrapEvent`.** It cannot open a contact-exchange packet;
  the extra inner layer is deliberate (`docs/contact-invite-v1.md`).

## 1. Sealing — the vault envelope (R-4)

A projection's `content` is **not** a bare NIP-44 ciphertext. It is
signet-app's v2 vault envelope, the same format every other private-state rail
in signet-app uses:

1. A random 32-byte AES-256-GCM content key is generated per publish.
2. The plaintext body is length-prefixed (4-byte big-endian length) and
   zero-padded up to the smallest of the fixed buckets `[4096, 8192, 16384,
   32768, 65536]` that fits it.
3. The padded body is AES-256-GCM encrypted under the content key with a fresh
   12-byte IV.
4. The content key itself is wrapped with **NIP-44, to the recipient** — for
   this wire, the app's own pubkey, encrypted by the rail key's signer. This
   is what makes the projection *unreadable by anyone but the app it was
   sealed to*, even though the projection event carries no `#p` tag.
5. The four pieces are serialised as JSON: `{ "v": 2, "k": <NIP-44 ciphertext
   of base64(contentKey)>, "iv": <base64 IV>, "ct": <base64 AES-GCM
   ciphertext>, "b": <bucket size> }`. This JSON string is the event's
   `content`.

An implementer must unwrap `k` (NIP-44-decrypt it against the rail pubkey) to
recover the content key, decrypt `ct` under AES-256-GCM with `iv`, strip the
4-byte length prefix, and read exactly that many bytes as the UTF-8 body. A
plain `nip44Decrypt(event.content)` will not work — it will try to decrypt the
envelope's outer JSON as if it were the whole ciphertext and fail.

The padding is *why* `MAX_WIRE_BYTES` is 65532, not 65536: nostr-tools' NIP-44
v2 implementation rejects plaintext over 65535 bytes, and the top bucket is
65536 with a 4-byte length prefix inside it, so 65532 UTF-8 bytes is the most
a projection body can be and still fit through both ceilings.

Frozen test vector: `vectors/envelope.v2.json` (real NIP-44 + AES-GCM under
injected deterministic randomness, so the fixture is byte-identical on every
regeneration). Its `railSecretKey`/`appSecretKey` are fixed **test keys only**
— never reuse them.

## 2. Events

| Event | Kind | Author | `d` tag | `#p` tag | Encryption direction |
|---|---|---|---|---|---|
| Pairing ack | `21237` | a throwaway **ephemeral** key, never the owner's or the rail's | — | `["p", appPubkey]` | ephemeral → app (NIP-44, plain — no vault envelope) |
| Projection | `30078` | the grant's **rail** key | `projectionTag(grantId)` | none | rail → app (NIP-44, v2 vault envelope) |
| Proposal | `30078` | the **app**'s own key | `proposalTag(grantId, appPubkey)` | none | app → rail (NIP-44, plain — no vault envelope) |

Both replaceable kind-30078 events carry no `#p` tag on purpose: the recipient
of a projection, and the size of the directory behind it, both stay off the
wire (Kenspeckle v1 precedent). Only the ack — addressed to a specific app so
it can find it — carries a `p` tag, and it is discarded (an ephemeral key is
never author-pinnable; see S7 in `SECURITY.md`).

Only the projection goes through the vault envelope of §1. The ack and the
proposal are ordinary NIP-44 payloads.

## 3. Pairing URI

Scheme: `signet-grant:`. An app builds one URI and renders it as a QR code;
Signet parses it, shows the owner a consent screen, and (on approval) publishes
the ack. Parameter order is **binding** — `vectors/pairing.v2.json` pins the
exact string byte-for-byte:

```
signet-grant://pair?v=2&app=<64-hex>&name=<sanitised, ≤64 chars>&caps=<comma-separated capability tokens>&dir=owner|dependant&relay=<wss://…, ≤256 chars>&t=<unix seconds>&challenge=<exactly 32 hex chars>
```

The whole URI is refused above `MAX_PAIRING_URI_CHARS` (2048) before its query
string is parsed. `v` must be the literal string `2` and is checked first: a parser that read a
`v=1` Kenspeckle URI as v2 would silently grant capabilities never asked for,
so a wrong or missing `v` is a hard rejection, not a default. `t` must be
within `PAIRING_FRESHNESS_SECONDS` (300s) of the reader's clock. `challenge` is
exactly `CHALLENGE_HEX_CHARS` (32) hex characters — 128 bits, the width every
random identifier on this wire uses — validated case-insensitively and compared
byte-for-byte, case preserved, on the way back in the ack: it is the app's own
anti-replay nonce. `relay` is at most `MAX_RELAY_LEN` (256) characters as well
as `wss://` (or loopback `ws://`). Both are hard rejections, never
truncations — a truncated relay URL is a different relay, and a truncated nonce
is a weaker one.

### Carriers — the same query string, three ways (M10)

`buildPairingUri` emits the `signet-grant://pair?…` form, which is what a QR
code should carry. Signet accepts the identical query string through two other
carriers, and every parser here reads whatever follows the first `?`, so all
three parse identically:

| Carrier | Shape | When |
|---|---|---|
| Custom scheme | `signet-grant://pair?v=2&…` | a QR code, or any handoff where the phone already has Signet installed |
| Web carrier | `https://<signet host>/?pair=1&v=2&…` | a same-device link, and the fallback when no app is installed |
| Verified App Link | `https://mysignet.app/pair?v=2&…` | Android, where the OS opens the installed app directly with no chooser |

Only the parameters after `?` are normative; `pair=1` on the web carrier is a
routing marker for Signet's own dispatcher, not part of this wire, and the
`mysignet.app` host is signet-app's deployment rather than something an
implementation should hard-code. A consumer building a desktop-to-phone handoff
wants the web carrier: take `buildPairingUri`'s output, keep the query string,
and put it behind the https URL Signet publishes, with `pair=1` added.

### Ack delivery — several candidates, never one (I3)

A consumer waiting for its ack asks for up to **`ACK_CANDIDATE_LIMIT` = 10**
kind-21237 events tagged `["p", appPubkey]`, takes them newest first, and
accepts the first that both decrypts under its own key and echoes its own
`challenge`. Every other candidate costs one failed decrypt and nothing else.

This is not an optimisation. The app pubkey and the rendezvous relay are both
printed in the QR code the consumer displays on screen, and the ack is carried
by a throwaway ephemeral key, so anyone who photographs that QR can publish a
junk kind-21237 addressed to the app. A reader that asked for the single newest
match could be kept away from the genuine ack for the whole pairing window by
one such event — while Signet, which has already published its ack, has minted,
stored and spent one of the owner's grant slots on a pairing that can never
complete. An implementation that can only fetch one event per relay should
query each relay separately rather than one merged newest.

That is the denial-of-service case. The graver one is a **takeover**: a
photographer who publishes a forged ack encrypted to the app and echoing the
app's own challenge, addressed to arrive before the owner's real one, wins —
`awaitPairingAck` accepts the first candidate that decrypts and matches. The
app is then paired to the attacker's rail, not the owner's: it fetches a
projection the attacker writes, sends every proposal to the attacker's
channel, and never sees the owner's directory or blocks, with nothing on
either screen to say the pairing went to the wrong party.

There is deliberately no author pin on an ack: the carrier key is ephemeral and
the reader has never seen it before. NIP-44 and the challenge are the gate —
which is exactly what a forged ack can also satisfy, so a further check is
needed once an ack is accepted at all.

### Pairing verification code (B1, F1)

Once `awaitPairingAck` resolves, the consumer can compute a short code from
values a photographed QR does not carry:
`pairingCode(appPubkey, challenge, pairing.grantId, pairing.railPubkey)` —
`src/wire/pairing-code.ts`. `grantId` and `railPubkey` exist only inside the
real ack, minted the moment Signet approves the grant, so a code built from
them (rather than from `appPubkey`/`challenge` alone, which the photographer
already has) differs between the owner's real pairing and an attacker's forged
one.

The code flows **ONE way**: app screen → person → producer, never back the
other direction. If Signet ALSO displayed its own code, an attacker who can
see the owner's screen, pairing with an app that missed the real ack (kind
21237 is ephemeral; a backgrounded app or a dropped socket loses it), could
read the owner's code off Signet, grind a grantId/railPubkey to match, and
publish a forged ack the app then accepts — the
1-in-1,000,000 claim only holds while the attacker must commit to an ack
*before* anything about the owner's code exists to copy. Keeping the code on
one screen only is what keeps that commitment forced.

A consumer:

- **MUST**, once `awaitPairingAck` resolves, show `pairingCode(appPubkey,
  challenge, pairing.grantId, pairing.railPubkey)` and **MUST NOT** use the
  pairing — fetch, propose, or persist it as paired — until the user confirms
  it (the app's own "Continue", pressed only after the user has typed the code
  into Signet and Signet has confirmed it there).
- **MUST** always show the code, and **MUST NOT** hide it based on anything the
  ack itself claims about the producer's version — the ack may be the
  attacker's.
- On a mismatch or a cancel, **MUST** discard the pairing and start again with
  a new challenge.
- Same-device `https://mysignet.app/pair` hand-off shows no QR and is not
  exposed to a photographer, but the web `?pair=1` carrier IS shown as a QR
  for a desktop-to-phone hand-off, so it carries the same exposure and gets the
  same rule. The code is shown in every case, whether or not that particular
  carrier was the exposed one.

A producer (Signet):

- **MUST NOT** display its own code. Showing it would hand an attacker who won
  the race exactly what they need to forge a second, matching ack.
- **MUST** instead ask the person to type the code the app is showing, compute
  `pairingCode` itself, and compare with `matchesPairingCode` — on a match,
  confirm the pairing on screen; on a mismatch, revoke the grant and say so.
- A producer that predates this check neither shows nor asks for a code at
  all; that pairing cannot be verified this way.

## 4. Tag derivations

The app-access rail's routing tags — the projection and proposal `d` tags —
and the scoped contact id are domain-separated SHA-256 digests truncated to 128
bits (32 lowercase hex characters), so they are opaque on the relay: a scraper
of kind 30078 sees a random-looking `d` tag for these two slots. This is **not**
true of every tag on the wire: the app-introduction `d` tags are readable and
the ack and contact-exchange events carry a readable `p` tag (§0).

```
projectionTag(grantId)              = sha256hex('signet:contacts:proj:' + grantId)[0..32]
proposalTag(grantId, appPubkey)     = sha256hex('signet:contacts:prop:' + grantId + ':' + appPubkey)[0..32]
scopedContactId(grantId, contactId) = sha256hex('signet:contacts:cid:' + grantId.length + ':' + grantId + ':' + contactId.length + ':' + contactId)[0..32]
```

`scopedContactId` mixes in both input *lengths* before the values, so
`('ab', 'c:d')` and `('ab:c', 'd')` cannot collide the way plain
`grantId + ':' + contactId` concatenation could. It also means two apps paired
to the same directory see two disjoint id spaces over the same people —
colluding consumers cannot join records on the contact id alone.

## 5. JSON shapes

### Pairing ack (plaintext of the ack's NIP-44 ciphertext)

```json
{
  "v": 2, "grantId": "<32 hex>", "railPubkey": "<64 hex>",
  "projectionTag": "<32 hex>", "proposalTag": "<32 hex>", "relay": "<wss://…>",
  "grantedCapabilities": ["signet.contacts.read:directory", "…"],
  "maxStalenessSeconds": 21600, "challenge": "<echoed verbatim>"
}
```

`grantedCapabilities` may be **narrower** than what the app requested — the
owner is free to tick fewer boxes — and is clamped to the known `CAPABILITIES`
list. `maxStalenessSeconds` is clamped to `[3600, 604800]` (falling back to the
default `21600` when absent or invalid) by `clampStaleness`.

### Projection (plaintext inside the vault envelope)

| Field | Type | Limit |
|---|---|---|
| `v` | `2` | — |
| `grantId` | 32-hex | — |
| `scopes` | `Capability[]` | ≤ 16 (`MAX_CAPABILITIES`), normalised order |
| `frontier.maxClock` | non-negative integer | — |
| `frontier.opCount` | non-negative integer | — |
| `frontier.publishedAt` | non-negative integer (unix seconds) | — |
| `frontier.deviceId` | 32-hex | — |
| `issuedAt` | non-negative integer | — |
| `expiresAt` | integer ≥ `issuedAt` | — |
| `contacts` | `ProjectedContact[]` | ≤ 2000 (`MAX_CONTACTS_PER_PROJECTION`); a parser that has to cut the list sets `truncated` itself |
| `revoked` | `true` or absent | — |
| `truncated` | `true` or absent | — |

`ProjectedContact`:

| Field | Type | Limit |
|---|---|---|
| `contactId` | 32-hex, grant-scoped opaque id | — |
| `type` (legacy) | `'person' \| 'organisation'` | no capability covers it: a projection carrying it is refused |
| `identities[].pubkey` | 64-hex | ≤ 16 per contact (`MAX_IDENTITIES_PER_CONTACT`) |
| `identities[].verification` (optional) | `'unverified' \| 'proven' \| 'mutual'` | — |
| `displayName` | sanitised string | ≤ 100 chars (`MAX_DISPLAY_NAME`) |
| `avatar.url` | `https://` only; no capability covers `avatar` yet, so a projection carrying it is refused | ≤ 512 chars (`MAX_URL_LEN`) |
| `avatar.hash` | 64-hex | — |
| `avatar.key` (optional) | 64-hex | — |
| `effectiveTier` (optional) | `'kin' \| 'kith' \| 'ken' \| 'none'` | — |
| `tierSource` (optional) | `'direct' \| 'guardian-vouched' \| 'guardian-limited'` | — |
| `roles` | `string[]`, sanitised | ≤ 8 items (`MAX_ROLES_PER_CONTACT`), ≤ 40 chars each (`MAX_ROLE_LEN`) |
| `contactMethods[].kind` | `'phone' \| 'email' \| 'website' \| 'postal-address' \| 'other'` | ≤ 16 per contact (`MAX_METHODS_PER_CONTACT`) |
| `contactMethods[].value` | sanitised string | ≤ 320 chars (`MAX_METHOD_VALUE`) |
| `contactMethods[].verification` (optional) | `'unverified' \| 'proven'` | — |
| `blocked` (optional) | boolean | — |
| `checks[]` (optional) | array of check records | ≤ 128 entries; a malformed entry is dropped |
| `checks[].pubkey` | 64-hex (producers list only keys already shared on this contact) | — |
| `checks[].method` | `'words' \| 'in-person' \| 'nip05' \| 'app-attested'` | — |
| `checks[].checkedAt` | non-negative safe integer, **Unix milliseconds** | — |
| `linkedPubkeys` (legacy) | `string[]` of 64-hex; no capability covers it: a projection carrying it is refused | ≤ 16 items (`MAX_LINKED_PUBKEYS`) |

There is **no owner pubkey on this wire** (R-31). A connected app learns the
grant's rail pubkey and a set of grant-scoped opaque contact ids, and nothing
else about whose directory it is reading: the owner's persona pubkey would have
been identical in every grant on that directory, so two colluding apps could
have joined their two projections on it in a single line — the very link
`scopedContactId` exists to break — and on a `dependant` directory it would
have been a minor's long-lived public identity handed to every paired app. A
producer that puts an `ownerPubkey` field on the body anyway is not rejected;
the field is simply not part of this wire, so the parser drops it and no
consumer ever sees it.

A projection is a **snapshot**: `frontier` carries publication metadata.
Newest wins by `(publishedAt, maxClock)` — **`publishedAt` is compared first**
and `maxClock` only breaks a tie between two devices that published in the same
second; an exact tie on both is not newer and is ignored. There is no
per-operation id list on the wire.

Producers may set `maxClock` and `opCount` to zero and use a grant-local opaque
32-hex token for `deviceId`, avoiding disclosure of hidden vault activity or a
cross-grant device identifier. Consumers must not treat these fields as a count
of visible contacts or as a stable owner identity.

The order is deliberately recency-first (R-30). When supplied, `maxClock` measures
how much of the contact log the publishing device has seen, not how recent its
snapshot is: a block entered on a second device that has not yet merged the
first device's recent operations carries a clock no higher than one the
consumer already holds, and a clock-first order would refuse that whole
projection — the block with it — until some unrelated later change happened to
be published. A consumer must not make safety state wait for the producer's own
log to converge.

A projection carrying `revoked: true` is exempt from this check entirely: a
revoking producer may not know the consumer's frontier, and losing a revocation
is far worse than applying one out of order.

### Proposal batch (plaintext of the proposal's NIP-44 ciphertext)

```json
{ "v": 1, "proposals": [ { "v": 1, "grantId": "<32 hex>", "operationId": "<32 hex>", "action": "add-ken", "value": { "pubkey": "<64 hex>", "displayName": "…" }, "createdAt": 0 } ] }
```

or, for `action: "rename-app-label"`:

```json
{ "value": { "contactId": "<32 hex>", "label": "…", "updatedAt": 0 } }
```

| Field | Type | Limit |
|---|---|---|
| batch `proposals` | array | ≤ 50 (`MAX_PROPOSALS_PER_BATCH`) |
| `operationId` | 32-hex, `randomHex(16)` | idempotency key |
| `add-ken.displayName` | sanitised string | ≤ 100 chars (`MAX_DISPLAY_NAME`) |
| `rename-app-label.label` | sanitised string | ≤ 100 chars (`MAX_APP_LABEL`) |
| `rename-app-label.updatedAt` | non-negative integer, ms epoch | last-writer-wins clock |

Only two actions exist in v2: `add-ken` and `rename-app-label`. `remove`,
`block` and `unblock` are deliberately absent and are not implied by either —
a later wire version may add them with their own capabilities. A
`rename-app-label` proposal carries the grant-scoped `contactId` the app saw
in its own projection; the producer maps it back by recomputing
`scopedContactId` over its own records, never by trusting an app-supplied
producer-side id.

A batch is one replaceable event per grant, so a second batch overwrites the
first before the producer necessarily read it (B2). This SDK's own consumer
client (`propose`) resends what is still waiting on every later call, keyed by
the SAME `operationId` it minted the first time — a producer must therefore
treat a repeated `operationId` as already handled, not as an error, exactly as
the idempotency-key rule in the table above already requires.

## 6. Capabilities

| Token | Description | Fields it unlocks |
|---|---|---|
| `signet.contacts.read:directory` | Read contact ids, display names and identity pubkeys only. | `contactId`, `displayName`, `identities[].pubkey` |
| `signet.contacts.read:method:phone` | Read shareable phone contact methods. | Phone `contactMethods` only |
| `signet.contacts.read:method:email` | Read shareable email contact methods. | Email `contactMethods` only |
| `signet.contacts.read:method:website` | Read shareable website contact methods. | Website `contactMethods` only |
| `signet.contacts.read:method:postal-address` | Read shareable postal-address contact methods. | Postal-address `contactMethods` only |
| `signet.contacts.read:method:other` | Read shareable other contact methods. | Other `contactMethods` only |
| `signet.contacts.read:tier` | Read Kin, Kith or Ken labels and whether a guardian set or limited them. | `effectiveTier`, `tierSource` |
| `signet.contacts.read:check-records` | Read check methods and dates for shared public keys. Private sources and evidence stay private. | `checks[]`: `pubkey`, `method`, `checkedAt` |
| `signet.contacts.read:checks` | Read verification status on the keys and contact methods already granted. | `identities[].verification`, `contactMethods[].verification` |
| `signet.contacts.read:roles` | Read the owner-assigned role labels on each contact. | `roles` |
| `signet.contacts.blocks.read` | Read blocked contacts, including their identity pubkeys, so the app can filter them. | `blocked`, `identities[].pubkey` |
| `signet.contacts.propose:add-ken` | Add contacts to your Ken list (recognised only, no access). Links to an existing contact under another identity need your confirmation. | `add-ken` proposals |
| `signet.contacts.propose:rename-app-label` | Propose a rename that applies only inside this grant’s own projection. | `rename-app-label` proposals |

Only `read:directory` is preselected on the grant screen. All other requested
capabilities require explicit consent. Method, role, tier and check permissions
also require `read:directory`; checks never grant a method value on their own.
Notes, private evidence and private identity links are never projected.

**Pre-release upgrade:** `read:methods` is retired, not expanded into the new
method capabilities. Unknown tokens are dropped; reconnect with explicit method
requests to restore access. Existing directory grants receive less data: tiers,
checks and block state are optional and require their named capabilities.
`type` and `linkedPubkeys` are no longer on this wire: no capability covers
them, so a projection carrying either is refused (§10). Old SDKs requiring tier/check fields may reject the smaller
snapshot; update the SDK before reconnecting. This is a change before the first
SDK release, not a compatibility promise for published consumers.

Each Signet grant covers one owning identity's contact list within its vault.
Other list memberships and vault-wide operation counts are never disclosed.
Legacy vault-wide grants require reconnection for fresh consent.

A valid `add-ken` can add a new key directly at Ken. If the key exists under
another identity, the link waits for owner confirmation. Even after approval,
the app receives only what it supplied, plus appropriately granted fields the
user subsequently adds under that identity. It cannot use proposals to read
existing names, methods, checks or tier from another list. Additions are capped
per grant. Proposal refusal, pending review and existence under another identity
are not returned as lookup results. Apps should treat their projection as the
only directory they can read, and tolerate delayed or absent additions.

Private links are not included, even in a blocks-only projection.

There is deliberately no *read-avatar* capability in v2 (ruling R-12): a
capability that grants a field the producer cannot yet fill is a promise the
wire does not keep, so it waits until signet-app has an avatar map to project.
The `ProjectedAvatar` shape and its parser already exist, but until that
capability does, a projection carrying `avatar` is refused (§10). Adding it
later is additive: a new capability, and a new pairing to consent to it.

### Field coverage

Which capabilities a projected-contact field needs is one table,
`FIELD_COVERAGE` in `src/wire/coverage.ts`, read by both the builder and the
parser. All listed capabilities are required:

| Field | Requires |
|---|---|
| the contact itself, `identities` (pubkeys) | `read:directory`; **or**, on a contact with `blocked: true`, `blocks.read` |
| `displayName`, `contactMethods` (the array) | `read:directory` |
| `contactMethods[]` of kind *k* | `read:directory` + `read:method:`*k* |
| `effectiveTier`, `tierSource` | `read:directory` + `read:tier` |
| `identities[].verification`, `contactMethods[].verification` | `read:directory` + `read:checks` |
| `checks` | `read:directory` + `read:check-records` |
| `roles` | `read:directory` + `read:roles` |
| `blocked` | `blocks.read` |
| `avatar`, `type`, `linkedPubkeys` | nothing covers them — always refused |

A field is judged by its presence on the wire, not by whether it would parse.
Keys that are not wire fields at all (private notes, secrets) are simply
dropped by the parser, as before.

## 7. Error-handling contract

- **Envelope-level failure → `null`.** `openVaultPayload` returns `null` for a
  malformed envelope, a wrong key, tampered ciphertext, or a backend that
  threw — never a thrown exception, and never a fallback to a bare NIP-44
  decrypt (this wire has no legacy v1 envelope format).
- **Item-level failure → drop the item, keep the rest.** One malformed contact
  inside an otherwise good `contacts` array is dropped by
  `parseProjectedContact`; the projection as a whole is not rejected for it.
  The same applies to one malformed proposal inside a batch.
- **Uncovered field → refuse the whole projection.** A contact carrying a
  field the projection's `scopes` do not cover (§6, Field coverage) is not a
  malformed item: it is a producer out of contract, so `parseProjection`
  returns `null` for the whole projection.
- **Builders throw.** `buildProjection` and `buildProposalBatch` are strict:
  they re-parse their own output and throw a `TypeError` if anything would be
  dropped, capped or rewritten in transit, if a contact carries a field the
  scopes do not cover, or if the sealed body would exceed
  `MAX_WIRE_BYTES`. A producer is expected to have fitted the body first
  (`projectionByteLength`); reaching the throw means it did not.

## 8. Hard limits

- **`MAX_WIRE_BYTES = 65532`** — the UTF-8 byte ceiling on a projection's
  canonical serialised body, enforced by `buildProjection` (throws above it),
  not merely documented. See §1 for why this number and not 65536 or 65535.
- **`truncated: true`** — set by the producer when it had to drop contacts to
  fit `MAX_WIRE_BYTES`. The drop order is deterministic and is the OPPOSITE way
  round from how it reads at a glance: contacts are **kept** most-recently-
  updated first (`contactId`, compared by code point, as the tiebreak), so it is
  the **least** recently updated that go. Two further rules sit above that
  ordering: a record created by a connected app (an applied `add-ken`) is
  dropped before any record the owner created (R-28c), so one app's volume can
  never evict the owner's real contacts from a DIFFERENT app's projection; and
  `MAX_CONTACTS_PER_PROJECTION` is applied in the same order, so ">2000
  contacts" is handled by this rule rather than by the parser's silent cap. The
  flag is never silent: a consumer should surface it as "this list may be
  incomplete".
- **`MAX_PROPOSALS_PER_BATCH = 50`** — the most proposals one signed batch may
  carry; `buildProposalBatch` throws above it.
- **`MAX_RELAY_LEN = 256`** — on the pairing URI's `relay` and the ack's
  `relay` alike. It matches signet-app's own storage bound: a longer relay URL
  is dropped from the owner's sealed grant backup, so a pairing accepted above
  this cap would work on the device that approved it and never reach a second
  one.
- **`CHALLENGE_HEX_CHARS = 32`** — the pairing challenge is exactly 32 hex
  characters.
- **`MAX_PAIRING_URI_CHARS = 2048`** — the raw pairing URI a parser will look
  at.
- **`ACK_CANDIDATE_LIMIT = 10`** — ack candidates a consumer considers per
  poll (§3).

### Producer-side limits a consumer meets in normal use

These are enforced by signet-app rather than by this package, and there is no
error reply on the wire for any of them — which is exactly why they are
normative here. An implementer who does not know them will build a UI that
waits for something that is never coming.

- **A proposal older than `MAX_STALENESS_SECONDS` (604800 — 7 days) is
  refused**, as is one stamped beyond a small future-skew window. `createdAt` is
  the producer's clock check, not a hint.
- **At most 16 app labels per grant** (`MAX_APP_LABELS_PER_GRANT`). A 17th
  `rename-app-label` is accepted onto the wire, queued, and never applied. It
  will sit in `pendingProposals()` until the seven-day drop.
- **At most 10 active grants per owner** (`CONTACT_GRANT_V2_CAP`). A consumer
  experiences the eleventh as `awaitPairingAck` returning `null`, the same as a
  timeout or a refusal — tell the person their Signet may be at its connected-
  app limit rather than only "timed out".

## 9. Vectors

Frozen, byte-exact test vectors live in `vectors/`, generated by
`src/wire/vectors.test.ts`:

- `vectors/pairing.v2.json` — a built pairing URI and its parse.
- `vectors/projection.v2.json` — a built projection body and its parse, plus
  `uncovered`: projections carrying a field their scopes do not cover, each of
  which a parser must refuse whole. Regenerated on 2026-09-16 to drop
  `ownerPubkey` (R-31), and on 2026-09-23 for the pre-release contract freeze
  (every case now carries only fields its scopes cover); its `regenerated`
  field records both reasons, and signet-app regenerates its own parity
  fixtures to match.
- `vectors/proposal.v1.json` — a built proposal batch and its parse.
- `vectors/sanitise.json` — the `sanitizeWireText` behaviour both this SDK and
  signet-app assert against (R-6 parity).
- `vectors/envelope.v2.json` — a sealed and opened v2 vault envelope, using
  real NIP-44 and AES-GCM under injected deterministic randomness.

Regenerate all of them with:

```bash
WRITE_VECTORS=1 npx vitest run src/wire/vectors.test.ts
```

then re-run `npx vitest run src/wire/vectors.test.ts` (or `npm run
vectors:check`) without the flag to confirm the new bytes are stable and to
catch an accidental drift on the next run.


### Check records (`checks`)

`checks` is optional and has at most 128 entries. Each entry contains a shared
contact `pubkey`, `method` (`words`, `in-person`, `nip05`, `app-attested`) and
`checkedAt` as Unix milliseconds. These are the user's records, not proof for a
relying app. The parser drops malformed entries and allowlists those three
fields. Sources, evidence, identity-list membership and exchange transcripts
remain private. Checks do not change relationship tier or inherit between lists.

`signet.contacts.read:check-records` requires explicit consent and directory
access. A `signet.contacts.read:checks` grant shares only the verification
summaries on identities and methods, never `checks`. Reaching `checks` from an
existing grant is broader sharing and needs a fresh pairing (§10); older
producers reject the unknown capability. The frozen vectors carry no `checks`.

## App introductions (v1, owner identities)

- `signet.contacts.invites:create`: Issue named contact invites for the paired identity; eligible single-use requests may be accepted automatically for five minutes.
- `signet.contacts.invites:receive`: Hand over a contact invite and send a request from the paired identity; no connection result is returned.

These capabilities do not imply directory access. Family policies and bot signer
routing must be implemented before producers offer them for those directories.
Use `createAppInviteClient({ signer, relay })` with `requestInvite(pairing)` or
`handOverInvite(pairing, invite)`. Keep one outstanding request per grant across
all client instances. The RelayIo contract authenticates signatures; the bundled
nostr-tools adapter uses its verifying relay pool.

Requests use kind 30078, app → rail NIP-44, with exactly one **readable** `d`
tag `signet:contacts:app-invite:<grantId>` (see §0 for what that exposes). JSON fields: v=1, grantId, requestId (32 hex),
createdAt (seconds), action (`create-invite` with mode `single-use`/`standing`, or
`receive-invite` with invite). Lifetime is 300 seconds; future clocks are rejected.
Replies use kind 30078, rail → app NIP-44, readable tag
`signet:contacts:app-invite:<grantId>:<requestId>`, and echo v/grantId/requestId.
They carry createdAt plus `issued` with invite or `queued` without invite.
No completion, other-contact existence, check, or private attribution is returned.
Parsers cap JSON at 8192 characters; producers and clients cap ciphertext at 16384.
App revocation disables its invitations. Automatic acceptance requires a current
explicit grant, its enabled per-app switch, the first single-use arrival, and the
five-minute window. Standing invites never auto-accept. Identity signer refusal
is retained for manual retry, not repeatedly prompted in the background.

## 10. Consent and grant changes

A grant is the owner's approval of one pairing ack: one `grantId`, one
directory, one `grantedCapabilities` set, one `maxStalenessSeconds`.

- **Ordinary updates keep the existing approval.** Republishing a projection as
  contacts are added, edited, blocked or removed; a keepalive republish; a
  projection whose `scopes` are narrower than the grant; an applied proposal;
  an app-label rename; a revocation. None of these asks the owner again.
- **Anything wider needs fresh consent — a new pairing, never an update.** A
  capability not in `grantedCapabilities`; a different or wider directory; a
  longer staleness window; a field class no granted capability unlocks (§6).
  A producer must not deliver any of these on an existing grant, and a
  consumer must not accept them as one.

What this package enforces:

- **field coverage, on both sides**: `buildProjection` throws on a contact
  carrying a field its `scopes` do not cover, and `parseProjection` refuses
  such a projection whole — one shared table (§6, Field coverage), so producer
  and consumer cannot disagree about what a capability unlocks;
- a projection whose `scopes` exceed the grant's `grantedCapabilities` is
  refused whole;
- a projection whose `expiresAt − issuedAt` exceeds the grant's
  `maxStalenessSeconds` is refused whole;
- an ack granting a capability the app did not request is refused, when the
  app passes `requestedCapabilities` to `awaitPairingAck`;
- `propose`, `requestInvite` and `handOverInvite` refuse locally unless the
  matching capability was granted.

What it cannot enforce, and the producer must: the directory. It is chosen at
pairing and is not carried on the ack or the projection. The producer's
projection builder is also still the allowlist that decides which contacts and
values a grant receives; the coverage check only guarantees it never ships a
field class the grant does not cover.
