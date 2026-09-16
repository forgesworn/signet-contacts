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

## Quick start

```ts
import { SimplePool } from 'nostr-tools/pool';
import { createSignetContactsClient } from '@forgesworn/signet-contacts';
import type { StorageIo } from '@forgesworn/signet-contacts';
import { createSimplePoolRelayIo } from '@forgesworn/signet-contacts/adapters/nostr-tools';

// Your app's OWN signer — NIP-46, NIP-07, or a local key. No second key needed.
const signer = { pubkey, nip44Encrypt, nip44Decrypt, signEvent };
const relay = createSimplePoolRelayIo(new SimplePool());

// Storage is where the sticky Blocked set lives. The default is in-memory, so
// a client built without one forgets every block on restart — pass something
// that survives the process (see "Storage, and the sticky Blocked set").
const storage: StorageIo = {
  async get(key) { return localStorage.getItem(key); },
  async set(key, value) { localStorage.setItem(key, value); },
};
const client = createSignetContactsClient({ signer, relay, storage });

const capabilities = [
  'signet.contacts.read:directory',
  'signet.contacts.blocks.read',
] as const;

const challenge = crypto.getRandomValues(new Uint8Array(16))
  .reduce((s, b) => s + b.toString(16).padStart(2, '0'), '');

const uri = client.buildPairingUri({
  appName: 'My App',
  capabilities: [...capabilities],
  directory: 'owner',
  relay: 'wss://relay.example.com',
  nowSec: Math.floor(Date.now() / 1000),
  challenge,
});
renderQrCode(uri); // show this to the owner; they scan it in Signet

const pairing = await client.awaitPairingAck({
  challenge,
  relays: ['wss://relay.example.com'],
  // Narrowing only: an ack granting anything you did not ask for is refused.
  requestedCapabilities: [...capabilities],
});
if (pairing) {
  await savePairing(pairing);                 // your own persistence — plain JSON
  await client.load(pairing.grantId);         // rehydrate state, Blocked set included
  const projection = await client.fetchProjection(pairing);
  const blocked = client.getBlockedSet();     // apply at ingress AND at display
  const waiting = client.pendingProposals();  // proposals sent, not yet applied
  const stop = client.start(pairing);         // live updates + poll fallback
}
```

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
| `timeoutMs` | `120000` | how long the QR stays worth showing before `null` |
| `pollMs` | `2000` | how often the relays are asked while waiting |
| `requestedCapabilities` | unset | your own request, so an over-granting ack is refused |

`client.start(pairing, { pollMs })` defaults `pollMs` to `60000`.
`createSimplePoolRelayIo(pool, { timeoutMs })` defaults `timeoutMs` to `8000`,
which bounds every individual pool call.

## Staying current — live, with polling as the fallback

`client.start(pairing)` subscribes to the grant's projection slot and polls
every `pollMs` (default 60 000 ms) as a fallback, so a new projection and a
revocation tombstone both arrive without the app asking; `client.stop()` ends
both. A transport with no `subscribe` runs on the poll alone. `onRevoked` fires
from whichever path sees the revocation first, once per revocation: a repeated
tombstone does not fire it twice, and a grant that is un-revoked by a newer
projection and then revoked again fires it again. It only fires while something
is reading the rail, which is what `start` is for. `start` returns a handle for
that subscription — an old handle is inert once a later `start` has replaced
it, so a cleanup that runs late cannot tear down the current one.

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

## Further reading

- [`docs/WIRE.md`](docs/WIRE.md) — the language-neutral wire specification: event
  kinds, tag derivations, JSON shapes, capability table, limits and vectors.
- [`docs/INTEGRATION.md`](docs/INTEGRATION.md) — a worked integration against a
  real consumer app.
- [`SECURITY.md`](SECURITY.md) — the threat model this wire was built against.
- [`CHANGELOG.md`](CHANGELOG.md) — dated wire changes, including which ones are
  not backwards compatible. There are no published releases yet, so pin a
  commit and read this before moving the pin.

## Licence

MIT.
