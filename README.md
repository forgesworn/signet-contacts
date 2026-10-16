# @forgesworn/signet-contacts

The v2 wire for **application access to a Signet contact directory**: a
capability-scoped pairing, a per-grant encrypted projection the owner controls
what goes into, and a small proposal channel for an app to ask (never demand)
for a contact to be added or relabelled.

It is a *consumer* SDK. It does not run inside Signet — it runs inside the app
that wants a slice of somebody's contacts, once that person has granted it.

## Where this lives, and why

The exploration spec (§5.10) originally put the richer family-contact wire
inside `signet-protocol`. It does not live there. This package is its own
private repository instead — a deliberate departure from that spec, on record
as ruling R-1 — because `signet-protocol` is the shared, slow-moving surface
every Signet consumer depends on, and this wire is still finding its shape.
Shipping it as a separate package means it can version, break and fix things
on its own schedule without forcing a protocol bump on everyone else.

The **Kenspeckle** v1 companion rail remains the compatibility baseline this
wire builds on: the `signet-grant:` pairing scheme and the kind-21237 ack are
reused byte-for-byte from it (a `v=2` marker separates the two), so an app that
already speaks the v1 rail is most of the way to speaking this one.

## Install

The repository is **private**. Install it pinned to a commit, with a read
Personal Access Token (or SSH access) configured for `github.com`:

```bash
npm install git+https://github.com/forgesworn/signet-contacts.git#<sha>
```

`<sha>` should be a specific commit, not a branch — this package has no
published releases yet.

`nostr-tools` (`^2.23.9`) is an **optional peer dependency**, and the quick
start below uses it, so install it alongside:

```bash
npm install nostr-tools
```

What needs it, exactly: `createSimplePoolRelayIo` takes any object shaped like
a nostr-tools `SimplePool` and imports nothing itself, but a `SimplePool` is
the obvious thing to give it, and the local-key signer below uses
`nostr-tools/pure` and `nip44`. The `adapters/invite-nostr-tools` entry point
imports `nostr-tools` directly, so it cannot be used without it. An app with
its own relay client and signer can leave `nostr-tools` out entirely.

## Runtimes

The package is ESM only and runs in Node or a browser. `engines` says Node 22
or newer, which is the floor set by its `spoken-token` dependency, and CI runs
Node 22. It reads the global Web Crypto object (`crypto.subtle` and
`crypto.getRandomValues`), so the runtime must provide it as a global; Node 22
does, and Node 18 does not without `--experimental-global-webcrypto`. It opens
no socket and holds no key of its own: the signer, the relay and the storage are
all injected. The quick start's `localStorage` storage is
**browser-only**; on Node use a file or database store, such as the one in
"Storage, and the sticky Blocked set".

## Quick start

The signer, the relay and the storage are all injected. The signer is a
`ContactsSigner`, every method async:

```ts
interface ContactsSigner {
  pubkey: string;                                                        // 64 lowercase hex
  nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string>;
  nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
  signEvent(event: UnsignedNostrEvent): Promise<SignedNostrEvent>;
}
```

```ts
import { SimplePool } from 'nostr-tools/pool';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { nip44 } from 'nostr-tools';
import { createSignetContactsClient } from '@forgesworn/signet-contacts';
import type { ContactsSigner, StorageIo } from '@forgesworn/signet-contacts';
import { createSimplePoolRelayIo } from '@forgesworn/signet-contacts/adapters/nostr-tools';
import { randomHex } from '@forgesworn/signet-contacts/wire';

// A local-key signer. Your app's OWN signer works unchanged (NIP-46, NIP-07, a
// flock or stash signer): anything with the shape above, so no second key is
// needed. In a real app, persist this key: the pairing is addressed to its
// public key.
const secretKey = generateSecretKey();
const signer: ContactsSigner = {
  pubkey: getPublicKey(secretKey),
  async nip44Encrypt(peer, plaintext) {
    return nip44.v2.encrypt(plaintext, nip44.v2.utils.getConversationKey(secretKey, peer));
  },
  async nip44Decrypt(peer, ciphertext) {
    return nip44.v2.decrypt(ciphertext, nip44.v2.utils.getConversationKey(secretKey, peer));
  },
  async signEvent(event) {
    return finalizeEvent(event, secretKey);
  },
};
const relay = createSimplePoolRelayIo(new SimplePool());

// Storage is where the sticky Blocked set lives. The default is in-memory, so
// a client built without one forgets every block on restart — pass something
// that survives the process (see "Storage, and the sticky Blocked set").
// This one is BROWSER-ONLY; a Node example is in that section.
const storage: StorageIo = {
  async get(key) { return localStorage.getItem(key); },
  async set(key, value) { localStorage.setItem(key, value); },
};
const client = createSignetContactsClient({ signer, relay, storage });

const capabilities = [
  'signet.contacts.read:directory',
  'signet.contacts.blocks.read',
] as const;

const challenge = randomHex(16);  // exactly 32 hex characters, your own nonce

const uri = client.buildPairingUri({
  appName: 'My App',
  capabilities: [...capabilities],
  directory: 'owner',             // 'owner' or 'dependant'
  relay: 'wss://relay.example.com',
  nowSec: Math.floor(Date.now() / 1000),
  challenge,
});
renderQrCode(uri); // app-supplied: draw the QR code; the owner scans it in Signet

const pairing = await client.awaitPairingAck({
  challenge,
  relays: ['wss://relay.example.com'],
  // Narrowing only: an ack granting anything you did not ask for is refused.
  requestedCapabilities: [...capabilities],
});
if (pairing) {
  // Before you save it, have the person confirm the pairing verification code
  // in Signet (docs/INTEGRATION.md, step 1).
  await savePairing(pairing);                 // app-supplied: your own persistence, plain JSON
  await client.load(pairing.grantId);         // rehydrate state, Blocked set included
  const projection = await client.fetchProjection(pairing);
  const blocked = client.getBlockedSet();     // apply at ingress AND at display
  const waiting = client.pendingProposals();  // proposals sent, not yet applied

  // Register the revocation listener, then start reading the rail.
  const forget = client.onRevoked((grantId) => {
    // clear the directory from your UI; the Blocked set stays
  });
  const stopLive = client.start(pairing);     // live updates + poll fallback
  // later: stopLive() or client.stop() ends it; forget() removes the listener
}
```

`start` returns a plain function, `() => void`, that tears down that one
subscription; `client.stop()` does the same for whichever subscription is
current. `onRevoked` is a separate client method, not an option of `start`
(`start` takes `{ pollMs }` only). `renderQrCode` and `savePairing` are yours to
write; the package supplies neither.

On every later launch, persist and reload `pairing` yourself (it is a plain
object), then call `client.load(pairing.grantId)` **before**
`client.fetchProjection(pairing)` — `load` is what restores the Blocked set and
the frontier this client compares incoming projections against.

## Storage, and the sticky Blocked set

`storage` is optional and defaults to `createMemoryStorage()` — a `Map` inside
that one client. Everything still works, and nothing survives the process:

| | with a persistent `StorageIo` | with the in-memory default |
|---|---|---|
| Blocked set after a restart | kept (the point of "sticky") | **lost until the next projection arrives** |
| Pending proposals after a restart | kept | lost |
| Held frontier after a restart | kept, so a stale replay is still refused | the next projection is treated as this grant's first |

The contract is two methods, `get(key)` and `set(key, value)`, both async, both
free to fail — the client treats storage as a convenience and never throws out
of a read or a write. It writes two keys per grant
(`signet-contacts:state:<grantId>` and `signet-contacts:pending:<grantId>`), so
a shared store is fine. A stored row is re-validated on `load` exactly as a
wire value would be, and a corrupt one is dropped without taking the Blocked
set with it.

On Node there is no `localStorage`. A JSON file is enough for a single process
(writes are queued so two `set` calls cannot overwrite each other):

```ts
import { readFile, writeFile } from 'node:fs/promises';
import type { StorageIo } from '@forgesworn/signet-contacts';

function createFileStorage(path: string): StorageIo {
  let queue: Promise<unknown> = Promise.resolve();
  const read = async (): Promise<Record<string, string>> => {
    try { return JSON.parse(await readFile(path, 'utf8')) as Record<string, string>; }
    catch { return {}; }
  };
  return {
    get: async (key) => (await read())[key] ?? null,
    set: (key, value) => {
      const next = queue.then(async () => {
        await writeFile(path, JSON.stringify({ ...(await read()), [key]: value }));
      });
      queue = next.catch(() => undefined);
      return next;
    },
  };
}
```

## Options and their defaults

`createSignetContactsClient({ ... })`:

| Option | Default | What it is |
|---|---|---|
| `signer` | — | required; your app's own NIP-44 + signing backend |
| `relay` | — | required; a `RelayIo` (the bundled adapter, or your own) |
| `storage` | `createMemoryStorage()` | where state and pending proposals persist |
| `now` | `() => Math.floor(Date.now() / 1000)` | the seconds clock (freshness, `sentAt`) |
| `nowMs` | `() => Date.now()` | the ms clock a `rename-app-label` with no `updatedAt` is stamped from |
| `maxPendingStalenessSeconds` | `604800` (7 days) | when an unanswered proposal is given up on |

`client.awaitPairingAck({ ... })`:

| Option | Default | What it is |
|---|---|---|
| `challenge` | — | required; your own nonce, exactly 32 hex characters |
| `relays` | — | required; where the ack is expected |
| `timeoutMs` | `600000` (`2 * PAIRING_FRESHNESS_SECONDS * 1000`) | how long the QR stays worth showing before `null` |
| `pollMs` | `2000` | how often the relays are asked while waiting |
| `requestedCapabilities` | unset | your own request, so an over-granting ack is refused |
| `signal` | unset | an `AbortSignal`; aborting it cancels the wait and its listeners |

`client.start(pairing, { pollMs })` defaults `pollMs` to `60000`; `pollMs` is its
only option. Revocation is observed with the separate `client.onRevoked(cb)`
method, which returns a function that removes the listener.

`createSimplePoolRelayIo(pool, { timeoutMs })` defaults `timeoutMs` to `8000`,
which bounds every individual pool call.

### Pairing acknowledgement delivery

Pairing acknowledgements use ephemeral kind 21237, plus a STORED copy of the
same content as a replaceable kind-30078 event (`d` = `ackTag(challenge)`,
NIP-40-expired), so a consumer app that was backgrounded through the
ephemeral event's whole life can still find it by polling: see `docs/WIRE.md`
"Ack delivery". Supply `RelayIo.subscribe` (the bundled adapter does) so
`awaitPairingAck` listens throughout the approval window on both filters;
polling alone can miss an approval between queries. Pass an `AbortSignal` as
`signal` to cancel that listener when the pairing UI closes. One attempt opens
at most 32 distinct candidate ciphertexts, deduplicated by event ID; after
that it returns `null` and requires a new explicit attempt. A crowd of more
than `ACK_CANDIDATE_LIMIT` newer junk stored acks (a photographed QR lets
anyone publish these) is paged past with `until`, up to a few pages per poll,
so an older genuine ack behind the crowd is still reachable. Every poll runs
BEFORE the timeout/abort/cap check that can end the wait, so a resumed
(e.g. backgrounded) app still gets one more look at the relays even if real
time has already run past `timeoutMs` while it was suspended.

## Staying current — live, with polling as the fallback

`client.start(pairing)` subscribes to the grant's projection slot and polls
every `pollMs` (default 60 000 ms) as a fallback, so a new projection and a
revocation tombstone both arrive without the app asking; `client.stop()` ends
both. A transport with no `subscribe` runs on the poll alone. A listener registered
with `client.onRevoked(cb)` fires from whichever path sees the revocation first, once per revocation: a repeated
tombstone does not fire it twice, and a grant that is un-revoked by a newer
projection and then revoked again fires it again. It only fires while something
is reading the rail, which is what `start` is for. `start` returns a handle for
that subscription, a plain `() => void`. An old handle is inert once a later
`start` has replaced it, so a cleanup that runs late cannot tear down the
current one.

## Proposing a change

An app never writes to the directory. It asks, with `client.propose`, and
Signet decides. There are two actions, each behind its own capability that the
owner must have granted (`signet.contacts.propose:add-ken` and
`signet.contacts.propose:rename-app-label`):

```ts
// Ask for a key to be added at Ken (recognised only, no access).
const sent = await client.propose(pairing, [
  { action: 'add-ken', value: { pubkey, displayName: 'Ada' } },
]);

// Ask for a label that applies only inside this grant's own projection.
// `contactId` is the grant-scoped id the app saw in its projection.
await client.propose(pairing, [
  { action: 'rename-app-label', value: { contactId, label: 'Ada (work)' } },
]);

if (!sent) {
  // not sent: show "couldn't send", the same way whatever the reason
}
```

`propose(pairing, drafts)` takes a `readonly ContactProposalDraft[]` and returns
`Promise<boolean>`. `true` means the batch reached a relay; it does not mean
Signet has applied it, and there is no "declined" reply on this wire. It
returns `false`, without throwing, when `drafts` is empty, when any draft's
capability is not in `pairing.grantedCapabilities`, when a value would not
survive the wire's own validation (a `pubkey` that is not lowercase 64-hex, a
`contactId` that is not 32-hex, a name or label over 100 characters), or when
the encrypt, sign or publish step fails. A `rename-app-label` draft's
`updatedAt` is optional (milliseconds since the epoch; the client's `nowMs` clock
stamps it when absent).

Each call also resends anything still pending for the same grant that the new
drafts do not supersede, so an earlier proposal Signet never got to read is not
lost. Two drafts for the same pubkey or the same `contactId` in one call keep
only the last. A batch holds at most 50 proposals.

`client.pendingProposals()` lists what has been sent and not yet seen applied,
as `PendingProposal[]` (`grantId`, `operationId`, `action`, `value`, `sentAt` in
seconds). It is consumer-side state and nothing else, so render "asked, not
answered yet" from it. An entry clears when a projection shows its effect, and
is dropped after `maxPendingStalenessSeconds` (7 days by default). The step-by-step
version is in [`docs/INTEGRATION.md`](docs/INTEGRATION.md), step 5.

## The freshness rule

Keep the last projection until a newer one arrives. Use `client.isFresh()` to
tell the person their contact list may be stale — that is a display hint, not
a permission check. And never un-block anyone because a projection expired or
the grant was revoked: `client.getBlockedSet()` is sticky and ignores both.

## Two honesty boundaries

> **Revocation is not recall.** When a person disconnects your app, Signet
> stops publishing and sends a revocation. It cannot make your app forget a
> projection it has already decrypted. Honour the revocation: clear the
> directory, keep the Blocked set, and say so in your UI.

> **Kin means close circle, not family.** The three distances are Ken (a key
> you recognise), Kith (someone you have verified) and Kin (your close
> circle). Kin is not a claim about a family relationship and must not be
> presented as one.

## Capabilities and directory kinds

A pairing asks for capabilities by token. `CAPABILITIES` is the canonical list
(in its binding order) and `CAPABILITY_DESCRIPTIONS` has a one-line description
of each; the wire document has the field-by-field table in
[`docs/WIRE.md` §6](docs/WIRE.md) and the two introduction tokens under "App
introductions". A reader takes at most the first 16 tokens of a link (`MAX_CAPABILITIES`),
and the capabilities the owner grants may be narrower than what was asked.

| Token | Grants |
|---|---|
| `signet.contacts.read:directory` | contact ids, display names and identity pubkeys only; the only one preselected on the owner's consent screen |
| `signet.contacts.read:method:phone` | shareable phone contact methods |
| `signet.contacts.read:method:email` | shareable email contact methods |
| `signet.contacts.read:method:website` | shareable website contact methods |
| `signet.contacts.read:method:postal-address` | shareable postal-address contact methods |
| `signet.contacts.read:method:other` | shareable other contact methods |
| `signet.contacts.read:tier` | the Kin, Kith or Ken label, and whether a guardian set or limited it |
| `signet.contacts.read:checks` | verification status on the keys and methods already granted |
| `signet.contacts.read:check-records` | check methods and dates for shared public keys |
| `signet.contacts.read:roles` | the owner-assigned role labels on each contact |
| `signet.contacts.blocks.read` | blocked contacts and their identity pubkeys, so the app can filter them |
| `signet.contacts.propose:add-ken` | `propose` with an `add-ken` draft |
| `signet.contacts.propose:rename-app-label` | `propose` with a `rename-app-label` draft |
| `signet.contacts.invites:create` | `createAppInviteClient(...).requestInvite` (owner identities) |
| `signet.contacts.invites:receive` | `createAppInviteClient(...).handOverInvite` (owner identities) |

Method, tier, check and role capabilities also need `read:directory`. There is
no avatar capability in v2.

The `directory` option of `buildPairingUri` is a `DirectoryKind`: `'owner'` or
`'dependant'`. Any other value throws a `TypeError`
(`signet-contacts: invalid directory`). When parsing a link, an unrecognised
`dir` is read as `'owner'` with a `bad-directory` warning. The invitation
capabilities are for owner identities.

## Entry points

`package.json` exports these subpaths. Everything is ESM, with types.

| Import | What it provides |
|---|---|
| `@forgesworn/signet-contacts` | the client (`createSignetContactsClient`, `createMemoryStorage`, `createAppInviteClient`, `DEFAULT_LIVE_POLL_MS`), their types, and everything in `./wire` |
| `@forgesworn/signet-contacts/wire` | the wire layer alone: constants and `CAPABILITIES`, pairing URI and ack builders and parsers, the vault envelope, projection, proposal and invite parsers and builders, state reduction (`applyProjection`, `blockedSetOf`, `isFresh`, `visibleContacts`), `pairingCode`, `randomHex` and the wire types; no client |
| `@forgesworn/signet-contacts/adapters/nostr-tools` | `createSimplePoolRelayIo(pool, { timeoutMs })`, a `RelayIo` over a `SimplePool`-shaped object |
| `@forgesworn/signet-contacts/adapters/invite-nostr-tools` | the contact-invite mailbox helpers `wrapContactExchange`, `openContactMailboxWrap` and `openContactIdentityPacket`; imports `nostr-tools` |
| `@forgesworn/signet-contacts/vectors/*` | the frozen JSON test vectors for ports (`envelope.v2.json`, `pairing.v2.json`, `pairing-code.json`, `projection.v2.json`, `proposal.v1.json`, `sanitise.json`, `contact-invite-v1.json`, `contact-card-v1.json`, `contact-card-blur-v1.json`, `channel-check-v1.json`) |
| `@forgesworn/signet-contacts/package.json` | the manifest |

## API reference

`createSignetContactsClient(opts)` returns a `SignetContactsClient`. The
options are in "Options and their defaults".

```ts
interface SignetContactsClient {
  buildPairingUri(opts: Omit<PairingUriOptionsV2, 'appPubkey'>): string;       // throws TypeError on bad input
  parsePairingUri(input: string, opts?: { nowSec?: number; freshnessSeconds?: number }): PairingRequestV2Result;
  awaitPairingAck(opts: {
    challenge: string; relays: string[]; timeoutMs?: number; pollMs?: number;
    signal?: AbortSignal; requestedCapabilities?: readonly Capability[];
  }): Promise<PairingV2 | null>;                 // null: timed out, aborted or no valid ack
  load(grantId: string): Promise<ContactsState>; // call before fetchProjection on a later launch
  fetchProjection(pairing: PairingV2): Promise<ContactProjectionV2 | null>;
  getState(): ContactsState;
  getBlockedSet(): Set<string>;                  // lowercase 64-hex pubkeys
  isFresh(nowSec?: number): boolean;
  propose(pairing: PairingV2, drafts: readonly ContactProposalDraft[]): Promise<boolean>;
  pendingProposals(): PendingProposal[];         // a copy; mutating it changes nothing
  onRevoked(cb: (grantId: string) => void): () => void;   // returns "remove this listener"
  start(pairing: PairingV2, opts?: { pollMs?: number }): () => void;  // returns "stop this subscription"
  stop(): void;                                  // idempotent
}
```

Return values worth knowing:

- `fetchProjection` resolves `null` (it never throws) when there is no event,
  the event fails any check, or it is not strictly newer than the one held, so
  `null` is not necessarily an error.
- `getBlockedSet()` is a new `Set` of the identity pubkeys of every contact
  whose projection entry has `blocked: true`. It ignores expiry and revocation. Test membership with the sender's own
  lowercase pubkey.
- `isFresh()` is `true` only while a projection is held, the grant is not
  revoked and the clock is at or before its `expiresAt`. It is a display hint,
  not a permission check.
- `getState()` is the reduced `ContactsState`: `{ grantId, projection,
  receivedAt, blockedPubkeys, revoked }`.

The types they exchange, from `@forgesworn/signet-contacts`:

```ts
// What awaitPairingAck resolves and what you persist (plain JSON).
interface PairingV2 {
  grantId: string;                       // 32 hex
  railPubkey: string;                    // 64 hex; the key every projection is signed by
  projectionTag: string;
  proposalTag: string;
  relay: string;                         // wss:// URL
  grantedCapabilities: Capability[];     // may be narrower than requested
  maxStalenessSeconds: number;
  pairedAt: number;                      // local only, never on the wire
}

interface ContactProjectionV2 {
  v: 2; grantId: string; scopes: Capability[];
  frontier: ProjectionFrontier; issuedAt: number; expiresAt: number;
  contacts: ProjectedContact[]; revoked?: true; truncated?: true;
}                                        // field by field: docs/WIRE.md §5

type ContactProposalDraft =
  | { action: 'add-ken'; value: { pubkey: string; displayName: string } }
  | { action: 'rename-app-label'; value: { contactId: string; label: string; updatedAt?: number } };

interface PendingProposal {
  grantId: string; operationId: string;
  action: 'add-ken' | 'rename-app-label';
  value: AddKenValue | RenameAppLabelValue;
  sentAt: number;                        // seconds
}

interface RelayIo {
  fetchNewest(filter: NostrFilterLike, relays: string[], author?: string): Promise<SignedNostrEvent | null>;
  publish(event: SignedNostrEvent, relays: string[]): Promise<boolean>;
  fetchMany?(filter: NostrFilterLike, relays: string[], author?: string): Promise<SignedNostrEvent[]>;
  subscribe?(filter: NostrFilterLike, relays: string[], onEvent: (event: SignedNostrEvent) => void): () => void;
}

interface StorageIo {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
}
```

`fetchMany` and `subscribe` are optional on `RelayIo`. Without `fetchMany` the
client considers one pairing-ack candidate instead of several; without
`subscribe`, `start` runs on its poll fallback alone. `ContactsSigner` is
shown under "Quick start".

## Further reading

- [`docs/WIRE.md`](docs/WIRE.md) — the language-neutral wire specification: event
  kinds, tag derivations, JSON shapes, capability table, limits and vectors.
- [`docs/INTEGRATION.md`](docs/INTEGRATION.md) — a worked integration against a
  real consumer app.
- [`SECURITY.md`](SECURITY.md) — the threat model this wire was built against.
- [signet-contacts-conformance](https://github.com/forgesworn/signet-contacts-conformance)
  — these vectors plus generated edge cases, for ports to other languages; a
  change here that alters them opens a sync pull request there
  (`.github/workflows/conformance.yml`).
- [signet-contacts-kotlin](https://github.com/forgesworn/signet-contacts-kotlin)
  — the Kotlin port, tested against every conformance vector.
- [`CHANGELOG.md`](CHANGELOG.md) — dated wire changes, including which ones are
  not backwards compatible. There are no published releases yet, so pin a
  commit and read this before moving the pin.

## Licence

MIT.
