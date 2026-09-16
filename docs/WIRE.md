# Contacts app-access wire — v2 specification

This is the language-neutral specification of the wire `@forgesworn/signet-contacts`
implements. It exists so an implementation in a language other than TypeScript
(a Dart mobile client, for instance) can be built without reading the SDK's own
source — everything here is normative for a byte-compatible implementation.

`v=2` (the pairing URI parameter and the `"v": 2` field on every JSON payload)
is the version marker. A `v=1` payload belongs to the older Kenspeckle
companion rail this wire extends and is a different, incompatible format.

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
never author-pinnable; see §6 of `SECURITY.md`).

Only the projection goes through the vault envelope of §1. The ack and the
proposal are ordinary NIP-44 payloads.

## 3. Pairing URI

Scheme: `signet-grant:`. An app builds one URI and renders it as a QR code;
Signet parses it, shows the owner a consent screen, and (on approval) publishes
the ack. Parameter order is **binding** — `vectors/pairing.v2.json` pins the
exact string byte-for-byte:

```
signet-grant://pair?v=2&app=<64-hex>&name=<sanitised, ≤64 chars>&caps=<comma-separated capability tokens>&dir=owner|dependant&relay=<wss://…>&t=<unix seconds>&challenge=<≥16 hex chars>
```

`v` must be the literal string `2` and is checked first: a parser that read a
`v=1` Kenspeckle URI as v2 would silently grant capabilities never asked for,
so a wrong or missing `v` is a hard rejection, not a default. `t` must be
within `PAIRING_FRESHNESS_SECONDS` (300s) of the reader's clock. `challenge` is
compared byte-for-byte, case preserved, on the way back in the ack — it is the
app's own anti-replay nonce.

## 4. Tag derivations

Every routing tag is a domain-separated SHA-256 digest truncated to 128 bits
(32 lowercase hex characters), so it is opaque on the relay: a scraper of kind
30078 sees a random-looking `d` tag, never `signet:contacts:…` in the clear.

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
| `contacts` | `ProjectedContact[]` | ≤ 2000 (`MAX_CONTACTS_PER_PROJECTION`) |
| `revoked` | `true` or absent | — |
| `truncated` | `true` or absent | — |

`ProjectedContact`:

| Field | Type | Limit |
|---|---|---|
| `contactId` | 32-hex, grant-scoped opaque id | — |
| `type` | `'person' \| 'organisation'` | — |
| `identities[].pubkey` | 64-hex | ≤ 16 per contact (`MAX_IDENTITIES_PER_CONTACT`) |
| `identities[].verification` | `'unverified' \| 'proven' \| 'mutual'` | — |
| `displayName` | sanitised string | ≤ 100 chars (`MAX_DISPLAY_NAME`) |
| `avatar.url` | `https://` only | ≤ 512 chars (`MAX_URL_LEN`) |
| `avatar.hash` | 64-hex | — |
| `effectiveTier` | `'kin' \| 'kith' \| 'ken' \| 'none'` | — |
| `tierSource` | `'direct' \| 'guardian-vouched' \| 'guardian-limited'` | — |
| `roles` | `string[]`, sanitised | ≤ 8 items (`MAX_ROLES_PER_CONTACT`), ≤ 40 chars each (`MAX_ROLE_LEN`) |
| `contactMethods[].kind` | `'phone' \| 'email' \| 'website' \| 'postal-address' \| 'other'` | ≤ 16 per contact (`MAX_METHODS_PER_CONTACT`) |
| `contactMethods[].value` | sanitised string | ≤ 320 chars (`MAX_METHOD_VALUE`) |
| `contactMethods[].verification` | `'unverified' \| 'proven'` | — |
| `blocked` | boolean | — |
| `linkedPubkeys` | `string[]` of 64-hex | ≤ 16 items (`MAX_LINKED_PUBKEYS`) |

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

A projection is a **snapshot**: `frontier` says who published it and when.
Newest wins by `(publishedAt, maxClock)` — **`publishedAt` is compared first**
and `maxClock` only breaks a tie between two devices that published in the same
second; an exact tie on both is not newer and is ignored. There is no
per-operation id list on the wire.

The order is deliberately recency-first (R-30). `maxClock` measures how much of
the owner's contact log the publishing DEVICE has seen, not how recent its
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

## 6. Capabilities

| Token | Description | Fields it unlocks |
|---|---|---|
| `signet.contacts.read:directory` | Read the directory: contact ids, type, display name, tier, tier source and identity pubkeys. | `contactId`, `type`, `displayName`, `effectiveTier`, `tierSource`, `identities` |
| `signet.contacts.read:methods` | Read contact methods whose sharingPolicy is grantable (phone, email, website, postal address). | `contactMethods` |
| `signet.contacts.read:roles` | Read the owner-assigned role labels on each contact. | `roles` |
| `signet.contacts.blocks.read` | Read blocked contacts, including their identity and linked pubkeys, so the app can filter them. | `blocked`, plus `identities`/`linkedPubkeys` on a blocked contact (S9 — identity keys come with it) |
| `signet.contacts.propose:add-ken` | Propose an add-ken operation: a pubkey and a display name the owner may accept as a Ken contact. | unlocks `client.propose` with an `add-ken` draft |
| `signet.contacts.propose:rename-app-label` | Propose a rename that applies only inside this grant’s own projection. | unlocks `client.propose` with a `rename-app-label` draft |

There is deliberately no *read-avatar* capability in v2 (ruling R-12): a
capability that grants a field the producer cannot yet fill is a promise the
wire does not keep, so it waits until signet-app has an avatar map to project.
The `ProjectedAvatar` shape and its parser already exist, so adding the
capability later is additive, not a breaking change.

## 7. Error-handling contract

- **Envelope-level failure → `null`.** `openVaultPayload` returns `null` for a
  malformed envelope, a wrong key, tampered ciphertext, or a backend that
  threw — never a thrown exception, and never a fallback to a bare NIP-44
  decrypt (this wire has no legacy v1 envelope format).
- **Item-level failure → drop the item, keep the rest.** One malformed contact
  inside an otherwise good `contacts` array is dropped by
  `parseProjectedContact`; the projection as a whole is not rejected for it.
  The same applies to one malformed proposal inside a batch.
- **Builders throw.** `buildProjection` and `buildProposalBatch` are strict:
  they re-parse their own output and throw a `TypeError` if anything would be
  dropped, capped or rewritten in transit, or if the sealed body would exceed
  `MAX_WIRE_BYTES`. A producer is expected to have fitted the body first
  (`projectionByteLength`); reaching the throw means it did not.

## 8. Hard limits

- **`MAX_WIRE_BYTES = 65532`** — the UTF-8 byte ceiling on a projection's
  canonical serialised body, enforced by `buildProjection` (throws above it),
  not merely documented. See §1 for why this number and not 65536 or 65535.
- **`truncated: true`** — set by the producer when it had to drop contacts to
  fit `MAX_WIRE_BYTES`. Contacts are dropped deterministically (most recently
  updated first, then `contactId`), and this flag is never silent: a consumer
  should surface it as "this list may be incomplete".
- **`MAX_PROPOSALS_PER_BATCH = 50`** — the most proposals one signed batch may
  carry; `buildProposalBatch` throws above it.

## 9. Vectors

Frozen, byte-exact test vectors live in `vectors/`, generated by
`src/wire/vectors.test.ts`:

- `vectors/pairing.v2.json` — a built pairing URI and its parse.
- `vectors/projection.v2.json` — a built projection body and its parse.
  Regenerated once, on 2026-09-16, to drop `ownerPubkey` (R-31); its
  `regenerated` field records the reason, and signet-app regenerates its own
  parity fixtures to match.
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
