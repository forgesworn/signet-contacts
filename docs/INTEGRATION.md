# Integration guide — worked example against flock

This walks the five steps a real consumer takes, against `forgesworn/flock`'s
actual shapes: `FlockSigner` (`{ readonly pubkey; signEvent; nip44Encrypt;
nip44Decrypt }`), `Circle.members?: string[]`, and `Profile { name?: string;
picture?: string }`. `FlockSigner` is structurally identical to
`ContactsSigner`, so a flock signer can be passed to
`createSignetContactsClient` unchanged — no adapter needed.

If your app is not flock, the shapes below are illustrative; the five SDK
calls (`buildPairingUri`/`awaitPairingAck`, `fetchProjection`, `getBlockedSet`,
`propose`, `onRevoked`) are what matters.

## Setup

```ts
import { SimplePool } from 'nostr-tools/pool';
import { createSignetContactsClient } from '@forgesworn/signet-contacts';
import type { StorageIo } from '@forgesworn/signet-contacts';
import { createSimplePoolRelayIo } from '@forgesworn/signet-contacts/adapters/nostr-tools';
import type { FlockSigner } from './signer';

function createContactsClient(signer: FlockSigner, storage: StorageIo) {
  const relay = createSimplePoolRelayIo(new SimplePool());
  return createSignetContactsClient({ signer, relay, storage });
}
```

`storage` is not decoration. Without it the client falls back to an in-memory
store and the sticky Blocked set — the one piece of state that must never decay
— is lost on every restart. Two async methods, `get(key)` and `set(key, value)`,
are the whole contract; see the README's "Storage, and the sticky Blocked set"
for what is kept and what is not. Every option and its default is in the
README's options table.

## Step 1 — Pair

Build the pairing URI, render it as a QR code, and wait for the ack once the
owner scans it and approves in Signet:

```ts
const challenge = randomHex(16); // your own CSPRNG helper
const relays = ['wss://relay.example.com'];

const uri = client.buildPairingUri({
  appName: 'Flock',
  capabilities: [
    'signet.contacts.read:directory',
    'signet.contacts.blocks.read',
    'signet.contacts.propose:add-ken',
  ],
  directory: 'owner',
  relay: relays[0],
  nowSec: Math.floor(Date.now() / 1000),
  challenge,
});
showQrCode(uri);

const pairing = await client.awaitPairingAck({
  challenge,
  relays,
  requestedCapabilities: [
    'signet.contacts.read:directory',
    'signet.contacts.blocks.read',
    'signet.contacts.propose:add-ken',
  ],
});
if (pairing === null) {
  // timed out, or the owner declined — show the QR again, do not retry silently
  return;
}
await savePairing(pairing); // your own persistence — plain JSON
```

`pairing.grantedCapabilities` may be **narrower** than what was requested —
always read it back rather than assuming the owner ticked every box.

## Step 2 — Fetch

Fetch on app start, and again whenever the app resumes from background — and
call `client.start(pairing)` (step 6) so later projections and a revocation
arrive live rather than only when you next ask. `isFresh()` drives a "last
updated" line rather than gating anything:

```ts
async function refreshContacts(client: SignetContactsClient, pairing: PairingV2) {
  await client.load(pairing.grantId);       // rehydrate persisted state first
  const projection = await client.fetchProjection(pairing);
  if (projection === null) {
    // no newer projection than what's already held — not necessarily an error
  }
  return {
    state: client.getState(),
    fresh: client.isFresh(),                // "Updated just now" vs "Last updated 3h ago"
  };
}
```

## Step 3 — Filter members by tier

Map `effectiveTier` onto who may see a circle's live location. `kin` is the
default threshold for the tightest circle — but **tier grants nothing by
itself**; it is flock, not the wire, that decides what a tier is allowed to
see:

```ts
import { visibleContacts } from '@forgesworn/signet-contacts';

const TIER_RANK = { kin: 3, kith: 2, ken: 1, none: 0 } as const;

function membersAllowedToSeeCircle(circle: Circle, state: ContactsState, minTier: 'kin' | 'kith' | 'ken' = 'kin') {
  const contacts = visibleContacts(state); // already excludes blocked contacts
  const allowedPubkeys = new Set(
    contacts
      .filter((c) => TIER_RANK[c.effectiveTier] >= TIER_RANK[minTier])
      .flatMap((c) => (c.identities ?? []).map((i) => i.pubkey)),
  );
  return (circle.members ?? []).filter((pubkey) => allowedPubkeys.has(pubkey));
}
```

A contact reaching `kin` says nothing about family, and nothing about what
flock should let them do — that mapping (here, "may see this circle's live
location") is a product decision flock owns, not a permission the wire hands
out.

## Step 4 — Apply the Blocked set at both ingress and display

`getBlockedSet()` must be checked in two places: before accepting an inbound
location update, and again before rendering a roster row. Both checks matter
independently — a pubkey could be blocked after an update was already queued,
or a stale UI could still be showing a row built before the block landed:

```ts
function onLocationUpdate(client: SignetContactsClient, senderPubkey: string, update: LocationUpdate) {
  if (client.getBlockedSet().has(senderPubkey)) return; // ingress gate
  applyLocationUpdate(update);
}

function renderRoster(client: SignetContactsClient, circle: Circle) {
  const blocked = client.getBlockedSet();
  return (circle.members ?? [])
    .filter((pubkey) => !blocked.has(pubkey))            // display gate
    .map((pubkey) => renderRosterRow(pubkey));
}
```

Blocked is **sticky**: it survives an expired projection and a revoked grant.
Never clear it on anything but a newer, non-revoked projection that itself
narrows it. `applyProjection` is what enforces that — it carries the previous
`blockedPubkeys` through a revocation and only replaces the set when a strictly
newer, non-revoked projection is accepted; `blockedSetOf` just hands you a copy
of whatever that left. Do not maintain a second copy of it yourself.

## Step 5 — Propose, and show what's outstanding

When the person adds a friend inside flock, propose it back to Signet rather
than writing it straight into the directory — Signet decides whether it
becomes a real Ken contact:

```ts
async function proposeNewFriend(client: SignetContactsClient, pairing: PairingV2, pubkey: string, displayName: string) {
  const ok = await client.propose(pairing, [
    { action: 'add-ken', value: { pubkey, displayName } },
  ]);
  if (!ok) {
    // not granted, or the send itself failed — same UI either way: "couldn't send"
  }
}
```

`pendingProposals()` is consumer-side state (R-9) — the SDK remembers what it
sent so you can render "asked, not answered yet" without a second store:

```ts
function renderOutstandingRequests(client: SignetContactsClient) {
  return client.pendingProposals().map((p) => ({
    ...p,
    waitingSince: p.sentAt, // your own copy: "Asked 2 days ago" — the wire has
                            // no "declined" reply, so write your own "still
                            // waiting" / "given up" language from this
  }));
}
```

An `add-ken` proposal clears itself out of `pendingProposals()` the moment a
later projection carries that pubkey, and a `rename-app-label` clears when the
named contact comes back showing that label — there is nothing to reconcile by
hand.

**The SDK also gives up on its own.** A pending row older than
`maxPendingStalenessSeconds` (default `604800` — seven days) is dropped during
the next reconcile, whether or not it was ever applied. This wire has no
"declined" reply by design, so an unanswered proposal is indistinguishable from
a refused one, and showing "asked 14 months ago" for ever would be its own kind
of lie. If your UI wants a different horizon, set the option; if it wants to
show older rows, keep your own copy at send time. Reconciliation happens when a
projection is accepted, so a client that never fetches never drops anything.

Finally, wire up revocation. It clears the directory, but **keeps** the
Blocked set, and should tell the person plainly which connection ended:

```ts
const forget = client.onRevoked((grantId) => {
  notifyUser('Your Signet contacts connection has ended. Your blocked list is unaffected.');
  // client.getState().projection is now { contacts: [] }; getBlockedSet() is untouched
});
```

`onRevoked` fires from whichever path sees the revocation first — a live push or
the next fetch — and exactly once either way. It does not fire on its own:
something has to be reading the rail, which is what `client.start()` below is
for. `onRevoked` returns a function that forgets the listener; it does not stop
the subscription.

## Step 6 — Stay current: live updates, with polling as the fallback

`client.start(pairing)` subscribes to the grant's projection slot and polls as a
fallback, so a new projection and a revocation tombstone both arrive without the
app asking. Call `stop()` from whatever teardown owns the client — it is
idempotent, and safe to call when `start` was never called:

```ts
useEffect(() => {
  const stop = client.start(pairing, { pollMs: 60_000 }); // 60_000 is the default
  return stop;                                            // same function as client.stop
}, [client, pairing]);
```

A transport with no `subscribe` (or one whose socket is down) leaves the poll
doing the whole job — that is a documented degraded mode, not a failure. One
subscription per client: calling `start` again replaces the previous one.

## Summary

| Step | SDK call |
|---|---|
| 1. Pair | `buildPairingUri`, `awaitPairingAck` |
| 2. Fetch | `fetchProjection`, `isFresh` |
| 3. Filter by tier | `visibleContacts`, `effectiveTier` (app-owned policy) |
| 4. Apply Blocked | `getBlockedSet` at ingress and at display |
| 5. Propose | `propose`, `pendingProposals`, `onRevoked` |
| 6. Stay current | `start` (live + poll fallback), `stop` |
