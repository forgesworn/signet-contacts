import { describe, it, expect, vi } from 'vitest';
import { createSignetContactsClient, createMemoryStorage } from './client.js';
import type { ContactsSigner, RelayIo } from './client.js';
import { buildPairingAckV2, ackEventTemplate } from './wire/ack.js';
import { MAX_ENVELOPE_CHARS, sealVaultPayload } from './wire/envelope.js';
import { buildProjection, projectionEventTemplate } from './wire/projection.js';
import { parseProposalBatch } from './wire/proposal.js';
import { projectionTag, proposalTag } from './wire/ids.js';
import { ACK_CANDIDATE_LIMIT, MAX_PROPOSALS_PER_BATCH, MAX_STALENESS_SECONDS, PAIRING_FRESHNESS_SECONDS } from './wire/constants.js';
import type { ContactProjectionV2, PairingV2, PendingProposal, SignedNostrEvent } from './wire/types.js';

const GRANT = 'f'.repeat(32);
const APP = 'a'.repeat(64);
const RAIL = 'b'.repeat(64);
const CHALLENGE = 'D'.repeat(32);
const RELAYS = ['wss://relay.example.com'];

/** Mirrors client.ts's own (unexported) `STATE_KEY_PREFIX`/`PENDING_KEY_PREFIX`
 *  — white-box, needed only by the `load()` row-validation tests, which seed
 *  a specific stored SHAPE directly rather than round-tripping through a full
 *  `propose`/`fetchProjection` cycle. */
const STATE_KEY = (grantId: string) => `signet-contacts:state:${grantId}`;
const PENDING_KEY = (grantId: string) => `signet-contacts:pending:${grantId}`;

/**
 * A fake signer: "encryption" is a reversible tagged wrapper, so a test can
 * assert who a payload was addressed to without a crypto dependency.
 *
 * Fix round 1 (the "sealed to a different app pubkey" test below): the check
 * is a STRICT `o.to === pubkey`, not the earlier `o.to === pubkey || o.to ===
 * peer`. The `peer` branch was pure leniency left over from convenience test
 * fixtures that never actually needed it (every fixture here already
 * addresses payloads "to APP", the same identity that decrypts them) — but it
 * made the fake open ANYTHING addressed to whatever `peer` argument the
 * caller happened to pass, including a wrong-recipient envelope sealed "to
 * the rail" by mistake, which is exactly the mistake the new test needs the
 * fake to catch rather than spuriously accept.
 */
function fakeSigner(pubkey = APP): ContactsSigner {
  return {
    pubkey,
    async nip44Encrypt(peer, plaintext) { return JSON.stringify({ to: peer, plaintext }); },
    async nip44Decrypt(_peer, ciphertext) {
      const o = JSON.parse(ciphertext) as { to: string; plaintext: string };
      if (o.to !== pubkey) throw new Error('wrong recipient');
      return o.plaintext;
    },
    async signEvent(event) { return { ...event, id: '0'.repeat(64), sig: '1'.repeat(128) }; },
  };
}

function signed(template: ReturnType<typeof projectionEventTemplate>): SignedNostrEvent {
  return { ...template, id: '2'.repeat(64), sig: '3'.repeat(128) };
}

/** Seal a projection the way the app really publishes one (ruling R-4): a v2
 *  vault envelope, content key wrapped to the APP's own pubkey (the only
 *  identity this SDK's fake signer will ever open for). */
async function sealProjection(signer: ContactsSigner, proj: ContactProjectionV2, recipient = APP): Promise<string> {
  const sealed = await sealVaultPayload(buildProjection(proj), signer, recipient);
  if (sealed === null) throw new Error('test setup: sealVaultPayload returned null');
  return sealed;
}

const PAIRING: PairingV2 = {
  grantId: GRANT, railPubkey: RAIL,
  projectionTag: projectionTag(GRANT), proposalTag: proposalTag(GRANT, APP),
  relay: RELAYS[0]!, grantedCapabilities: ['signet.contacts.read:directory'],
  maxStalenessSeconds: 21600, pairedAt: 1_700_000_000,
};

function projection(over: Partial<ContactProjectionV2> = {}): ContactProjectionV2 {
  return {
    v: 2, grantId: GRANT,
    scopes: ['signet.contacts.read:directory'],
    frontier: { maxClock: 5, opCount: 10, publishedAt: 1_700_000_000, deviceId: '2'.repeat(32) },
    issuedAt: 1_700_000_000, expiresAt: 1_700_021_600,
    contacts: [{
      // Only fields `read:directory` covers (WIRE.md §10).
      contactId: 'c'.repeat(32), displayName: 'Dee',
      identities: [{ pubkey: 'd'.repeat(64) }],
    }],
    ...over,
  };
}

describe('awaitPairingAck', () => {
  it('returns the pairing when the ack matches the challenge', async () => {
    const signer = fakeSigner();
    const ackPlain = buildPairingAckV2({
      v: 2, grantId: GRANT, railPubkey: RAIL,
      projectionTag: projectionTag(GRANT), proposalTag: proposalTag(GRANT, APP),
      relay: RELAYS[0]!, grantedCapabilities: ['signet.contacts.read:directory'],
      maxStalenessSeconds: 21600, challenge: CHALLENGE,
    });
    const content = await signer.nip44Encrypt(APP, ackPlain);
    const relay: RelayIo = {
      // createdAt matches the client's injected `now()` — fresh under
      // PAIRING_FRESHNESS_SECONDS (correction 1).
      fetchNewest: async () => ({ ...ackEventTemplate('9'.repeat(64), APP, 1_700_000_000, content), id: '4'.repeat(64), sig: '5'.repeat(128) }),
      publish: async () => true,
    };
    const client = createSignetContactsClient({ signer, relay, now: () => 1_700_000_000 });
    const pairing = await client.awaitPairingAck({ challenge: CHALLENGE, relays: RELAYS, timeoutMs: 50, pollMs: 5 });
    expect(pairing?.grantId).toBe(GRANT);
    expect(pairing?.pairedAt).toBe(1_700_000_000);
  });

  it('returns null and stops polling on timeout', async () => {
    const fetchNewest = vi.fn(async () => null);
    const client = createSignetContactsClient({
      signer: fakeSigner(), relay: { fetchNewest, publish: async () => true },
    });
    expect(await client.awaitPairingAck({ challenge: CHALLENGE, relays: RELAYS, timeoutMs: 30, pollMs: 10 })).toBeNull();
    expect(fetchNewest).toHaveBeenCalled();
  });

  it('ignores an ack carrying someone else’s challenge', async () => {
    const signer = fakeSigner();
    const content = await signer.nip44Encrypt(APP, buildPairingAckV2({
      v: 2, grantId: GRANT, railPubkey: RAIL, projectionTag: projectionTag(GRANT),
      proposalTag: proposalTag(GRANT, APP), relay: RELAYS[0]!,
      grantedCapabilities: ['signet.contacts.read:directory'], maxStalenessSeconds: 21600,
      challenge: 'E'.repeat(32),
    }));
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest: async () => ({ ...ackEventTemplate('9'.repeat(64), APP, 1_700_000_000, content), id: '4'.repeat(64), sig: '5'.repeat(128) }),
        publish: async () => true,
      },
      now: () => 1_700_000_000,
    });
    expect(await client.awaitPairingAck({ challenge: CHALLENGE, relays: RELAYS, timeoutMs: 30, pollMs: 10 })).toBeNull();
  });

  // Controller correction 1: narrowing-only + carrier-event freshness.
  it('rejects an ack that grants a capability the app never requested', async () => {
    const signer = fakeSigner();
    const content = await signer.nip44Encrypt(APP, buildPairingAckV2({
      v: 2, grantId: GRANT, railPubkey: RAIL, projectionTag: projectionTag(GRANT),
      proposalTag: proposalTag(GRANT, APP), relay: RELAYS[0]!,
      // Producer granted a proposal capability the app never asked for.
      grantedCapabilities: ['signet.contacts.read:directory', 'signet.contacts.propose:add-ken'],
      maxStalenessSeconds: 21600, challenge: CHALLENGE,
    }));
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest: async () => ({ ...ackEventTemplate('9'.repeat(64), APP, 1_700_000_000, content), id: '4'.repeat(64), sig: '5'.repeat(128) }),
        publish: async () => true,
      },
      now: () => 1_700_000_000,
    });
    const pairing = await client.awaitPairingAck({
      challenge: CHALLENGE, relays: RELAYS, timeoutMs: 30, pollMs: 10,
      requestedCapabilities: ['signet.contacts.read:directory'],
    });
    expect(pairing).toBeNull();
  });

  it('accepts an ack that grants a strict subset of the requested capabilities', async () => {
    const signer = fakeSigner();
    const content = await signer.nip44Encrypt(APP, buildPairingAckV2({
      v: 2, grantId: GRANT, railPubkey: RAIL, projectionTag: projectionTag(GRANT),
      proposalTag: proposalTag(GRANT, APP), relay: RELAYS[0]!,
      grantedCapabilities: ['signet.contacts.read:directory'],
      maxStalenessSeconds: 21600, challenge: CHALLENGE,
    }));
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest: async () => ({ ...ackEventTemplate('9'.repeat(64), APP, 1_700_000_000, content), id: '4'.repeat(64), sig: '5'.repeat(128) }),
        publish: async () => true,
      },
      now: () => 1_700_000_000,
    });
    const pairing = await client.awaitPairingAck({
      challenge: CHALLENGE, relays: RELAYS, timeoutMs: 30, pollMs: 10,
      requestedCapabilities: ['signet.contacts.read:directory', 'signet.contacts.propose:add-ken'],
    });
    expect(pairing?.grantId).toBe(GRANT);
  });

  it('ignores an ack whose carrier event is older than the freshness window', async () => {
    const signer = fakeSigner();
    const content = await signer.nip44Encrypt(APP, buildPairingAckV2({
      v: 2, grantId: GRANT, railPubkey: RAIL, projectionTag: projectionTag(GRANT),
      proposalTag: proposalTag(GRANT, APP), relay: RELAYS[0]!,
      grantedCapabilities: ['signet.contacts.read:directory'],
      maxStalenessSeconds: 21600, challenge: CHALLENGE,
    }));
    const staleCreatedAt = 1_700_000_000 - PAIRING_FRESHNESS_SECONDS - 1;
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest: async () => ({ ...ackEventTemplate('9'.repeat(64), APP, staleCreatedAt, content), id: '4'.repeat(64), sig: '5'.repeat(128) }),
        publish: async () => true,
      },
      now: () => 1_700_000_000,
    });
    const pairing = await client.awaitPairingAck({ challenge: CHALLENGE, relays: RELAYS, timeoutMs: 30, pollMs: 10 });
    expect(pairing).toBeNull();
  });

  // I3: both the app pubkey and the rendezvous relay are printed in the QR the
  // consumer shows on screen, so anyone who photographs it can park a junk
  // kind-21237 addressed to the app. A `limit: 1` fetch let one such event keep
  // the genuine ack out of the answer for the whole pairing window, while the
  // owner's device had already spent a grant slot on it.
  it('accepts the genuine ack from behind newer junk events (I3)', async () => {
    const signer = fakeSigner();
    const ackPlain = buildPairingAckV2({
      v: 2, grantId: GRANT, railPubkey: RAIL,
      projectionTag: projectionTag(GRANT), proposalTag: proposalTag(GRANT, APP),
      relay: RELAYS[0]!, grantedCapabilities: ['signet.contacts.read:directory'],
      maxStalenessSeconds: 21600, challenge: CHALLENGE,
    });
    const genuine = {
      ...ackEventTemplate('9'.repeat(64), APP, 1_700_000_000, await signer.nip44Encrypt(APP, ackPlain)),
      id: '4'.repeat(64), sig: '5'.repeat(128),
    };
    // Newest first: undecryptable junk, then an ack echoing someone else's
    // challenge, then the real one.
    const junkUndecryptable = {
      ...ackEventTemplate('8'.repeat(64), APP, 1_700_000_002, 'not even JSON'),
      id: '6'.repeat(64), sig: '5'.repeat(128),
    };
    const junkWrongChallenge = {
      ...ackEventTemplate('7'.repeat(64), APP, 1_700_000_001, await signer.nip44Encrypt(APP, buildPairingAckV2({
        v: 2, grantId: '0'.repeat(32), railPubkey: RAIL, projectionTag: projectionTag(GRANT),
        proposalTag: proposalTag(GRANT, APP), relay: RELAYS[0]!,
        grantedCapabilities: ['signet.contacts.read:directory'], maxStalenessSeconds: 21600,
        challenge: 'E'.repeat(32),
      }))),
      id: '7'.repeat(64), sig: '5'.repeat(128),
    };
    const fetchMany = vi.fn(async () => [junkUndecryptable, junkWrongChallenge, genuine]);
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest: async () => junkUndecryptable,
        fetchMany,
        publish: async () => true,
      },
      now: () => 1_700_000_000,
    });
    const pairing = await client.awaitPairingAck({ challenge: CHALLENGE, relays: RELAYS, timeoutMs: 50, pollMs: 5 });
    expect(pairing?.grantId).toBe(GRANT);
    expect(fetchMany).toHaveBeenCalled();
    // The filter asks for several, never one.
    expect((fetchMany.mock.calls[0]?.[0] as { limit: number }).limit).toBe(ACK_CANDIDATE_LIMIT);
  });

  it('falls back to the single newest when the transport has no fetchMany (I3)', async () => {
    const signer = fakeSigner();
    const content = await signer.nip44Encrypt(APP, buildPairingAckV2({
      v: 2, grantId: GRANT, railPubkey: RAIL, projectionTag: projectionTag(GRANT),
      proposalTag: proposalTag(GRANT, APP), relay: RELAYS[0]!,
      grantedCapabilities: ['signet.contacts.read:directory'], maxStalenessSeconds: 21600,
      challenge: CHALLENGE,
    }));
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest: async () => ({ ...ackEventTemplate('9'.repeat(64), APP, 1_700_000_000, content), id: '4'.repeat(64), sig: '5'.repeat(128) }),
        publish: async () => true,
      },
      now: () => 1_700_000_000,
    });
    expect((await client.awaitPairingAck({ challenge: CHALLENGE, relays: RELAYS, timeoutMs: 50, pollMs: 5 }))?.grantId).toBe(GRANT);
  });

  it('never decrypts an ack candidate whose content is over the envelope cap', async () => {
    const signer = fakeSigner();
    const decrypt = vi.spyOn(signer, 'nip44Decrypt');
    const oversized = {
      ...ackEventTemplate('9'.repeat(64), APP, 1_700_000_000, 'x'.repeat(MAX_ENVELOPE_CHARS + 1)),
      id: '4'.repeat(64), sig: '5'.repeat(128),
    };
    const client = createSignetContactsClient({
      signer,
      relay: { fetchNewest: async () => oversized, fetchMany: async () => [oversized], publish: async () => true },
      now: () => 1_700_000_000,
    });
    expect(await client.awaitPairingAck({ challenge: CHALLENGE, relays: RELAYS, timeoutMs: 30, pollMs: 10 })).toBeNull();
    expect(decrypt).not.toHaveBeenCalled();
  });

  // Fix round 1, M4.
  it('rejects an ack whose railPubkey is the app’s own pubkey', async () => {
    const signer = fakeSigner();
    const content = await signer.nip44Encrypt(APP, buildPairingAckV2({
      v: 2, grantId: GRANT, railPubkey: APP, projectionTag: projectionTag(GRANT),
      proposalTag: proposalTag(GRANT, APP), relay: RELAYS[0]!,
      grantedCapabilities: ['signet.contacts.read:directory'], maxStalenessSeconds: 21600,
      challenge: CHALLENGE,
    }));
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest: async () => ({ ...ackEventTemplate('9'.repeat(64), APP, 1_700_000_000, content), id: '4'.repeat(64), sig: '5'.repeat(128) }),
        publish: async () => true,
      },
      now: () => 1_700_000_000,
    });
    const pairing = await client.awaitPairingAck({ challenge: CHALLENGE, relays: RELAYS, timeoutMs: 30, pollMs: 10 });
    expect(pairing).toBeNull();
  });
});

describe('fetchProjection', () => {
  it('opens the sealed envelope, applies and exposes state', async () => {
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection());
    // Residuals fix #3: spy on the SAME object `createSignetContactsClient`
    // receives, so this proves the SDK really unwraps `k` with
    // `pairing.railPubkey`, not (say) `event.pubkey` — which happens to be
    // the same value in every other fixture here, so a wrong wiring would
    // pass every other test silently.
    const decryptSpy = vi.spyOn(signer, 'nip44Decrypt');
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1_700_000_000, content)),
        publish: async () => true,
      },
      now: () => 1_700_000_100,
    });
    const p = await client.fetchProjection(PAIRING);
    expect(p?.contacts).toHaveLength(1);
    expect(client.isFresh()).toBe(true);
    expect(client.getState().grantId).toBe(GRANT);
    expect(decryptSpy).toHaveBeenCalledWith(RAIL, expect.any(String));
  });

  it('pins the rail author: an event from another key is ignored', async () => {
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection());
    const imposter = { ...signed(projectionEventTemplate(RAIL, GRANT, 1, content)), pubkey: '7'.repeat(64) };
    const client = createSignetContactsClient({
      signer, relay: { fetchNewest: async () => imposter, publish: async () => true },
    });
    expect(await client.fetchProjection(PAIRING)).toBeNull();
  });

  it('ignores a projection whose grantId is not this pairing’s', async () => {
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection({ grantId: '0'.repeat(32) }));
    const client = createSignetContactsClient({
      signer,
      relay: { fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, content)), publish: async () => true },
    });
    expect(await client.fetchProjection(PAIRING)).toBeNull();
  });

  it('fires onRevoked once when a revocation lands', async () => {
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection({ contacts: [], revoked: true }));
    const onRevoked = vi.fn();
    const client = createSignetContactsClient({
      signer,
      relay: { fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, content)), publish: async () => true },
    });
    client.onRevoked(onRevoked);
    await client.fetchProjection(PAIRING);
    await client.fetchProjection(PAIRING);
    expect(onRevoked).toHaveBeenCalledTimes(1);
    expect(onRevoked).toHaveBeenCalledWith(GRANT);
  });

  it('persists and reloads state through injected storage', async () => {
    const storage = createMemoryStorage();
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection());
    const relay: RelayIo = {
      fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, content)),
      publish: async () => true,
    };
    const first = createSignetContactsClient({ signer, relay, storage });
    await first.fetchProjection(PAIRING);
    const second = createSignetContactsClient({ signer, relay, storage });
    const loaded = await second.load(GRANT);
    expect(loaded.projection?.contacts).toHaveLength(1);
    expect(second.getBlockedSet().size).toBe(0);
  });

  // Controller correction 2: the grant's clamped maxStalenessSeconds is an
  // independent ceiling, enforced by the client, not just whatever the
  // projection's own issuedAt/expiresAt happen to say.
  it('rejects a projection whose staleness window exceeds the grant’s clamp', async () => {
    const signer = fakeSigner();
    const tooWide = projection({ issuedAt: 1_700_000_000, expiresAt: 1_700_000_000 + PAIRING.maxStalenessSeconds + 1 });
    const content = await sealProjection(signer, tooWide);
    const client = createSignetContactsClient({
      signer,
      relay: { fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, content)), publish: async () => true },
    });
    expect(await client.fetchProjection(PAIRING)).toBeNull();
    expect(client.getState().grantId).toBeNull();
  });

  it('does not throw when the relay returns a malformed event', async () => {
    const client = createSignetContactsClient({
      signer: fakeSigner(),
      // Hostile/malformed data: pubkey is not even a string.
      relay: { fetchNewest: async () => ({ pubkey: 12345 } as unknown as SignedNostrEvent), publish: async () => true },
    });
    await expect(client.fetchProjection(PAIRING)).resolves.toBeNull();
  });

  // Fix round 1, C2 (ruling R-4).
  it('resolves null for a bare NIP-44 payload — the app never publishes one for this wire', async () => {
    const signer = fakeSigner();
    // The OLD (pre-fix) shape: no envelope, just `nip44Encrypt` directly.
    const bare = await signer.nip44Encrypt(APP, buildProjection(projection()));
    const client = createSignetContactsClient({
      signer,
      relay: { fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, bare)), publish: async () => true },
    });
    expect(await client.fetchProjection(PAIRING)).toBeNull();
  });

  it('resolves null for a projection sealed to a DIFFERENT app pubkey', async () => {
    const signer = fakeSigner();
    // Sealed to some other pubkey, not this client's own signer — a producer
    // (or relay) mistake, not this app's projection to open.
    const content = await sealProjection(signer, projection(), 'e'.repeat(64));
    const client = createSignetContactsClient({
      signer,
      relay: { fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, content)), publish: async () => true },
    });
    expect(await client.fetchProjection(PAIRING)).toBeNull();
  });

  it('resolves null for a tampered envelope', async () => {
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection());
    const envelope = JSON.parse(content) as { ct: string };
    const bytes = Uint8Array.from(atob(envelope.ct), (c) => c.charCodeAt(0));
    bytes[0] = (bytes[0] ?? 0) ^ 0x01;
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    const tampered = JSON.stringify({ ...envelope, ct: btoa(binary) });
    const client = createSignetContactsClient({
      signer,
      relay: { fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, tampered)), publish: async () => true },
    });
    expect(await client.fetchProjection(PAIRING)).toBeNull();
  });

  // Fix round 1, I1: the frontier rule in `applyProjection` rejects an older
  // or duplicate snapshot by returning the SAME state object back — the
  // caller must see that as "nothing new", not as a projection it can use.
  it('returns null for an older replay and leaves state untouched', async () => {
    const signer = fakeSigner();
    const newer = projection({ frontier: { maxClock: 5, opCount: 10, publishedAt: 1_700_000_000, deviceId: '2'.repeat(32) } });
    const older = projection({ frontier: { maxClock: 1, opCount: 1, publishedAt: 1_699_999_000, deviceId: '2'.repeat(32) } });
    let contentToServe = await sealProjection(signer, newer);
    const client = createSignetContactsClient({
      signer,
      relay: { fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, contentToServe)), publish: async () => true },
    });
    const first = await client.fetchProjection(PAIRING);
    expect(first?.frontier.maxClock).toBe(5);
    contentToServe = await sealProjection(signer, older);
    const replay = await client.fetchProjection(PAIRING);
    expect(replay).toBeNull();
    expect(client.getState().projection?.frontier.maxClock).toBe(5);
  });

  // Fix round 1, M3.
  it('resolves null for a projection whose scopes exceed the grant’s capabilities', async () => {
    const signer = fakeSigner();
    const overScoped = projection({
      scopes: ['signet.contacts.read:directory', 'signet.contacts.blocks.read'],
    });
    const content = await sealProjection(signer, overScoped);
    const client = createSignetContactsClient({
      signer,
      // PAIRING only grants `signet.contacts.read:directory`.
      relay: { fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, content)), publish: async () => true },
    });
    expect(await client.fetchProjection(PAIRING)).toBeNull();
    expect(client.getState().grantId).toBeNull();
  });
});

// R-32: live updates, with polling as the fallback. The SDK declared
// `RelayIo.subscribe`, the adapter implemented it, and the client never called
// it — so a consumer that wired `onRevoked` and waited learned nothing, ever.
describe('start / stop — live updates with a poll fallback (R-32)', () => {
  it('applies a projection pushed down the subscription, without any fetch', async () => {
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection());
    const fetchNewest = vi.fn(async () => null);
    let push: ((e: SignedNostrEvent) => void) | null = null;
    const close = vi.fn();
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest,
        publish: async () => true,
        subscribe: (_filter, _relays, onEvent) => { push = onEvent; return close; },
      },
      now: () => 1_700_000_100,
    });
    const stop = client.start(PAIRING, { pollMs: 60_000 });
    expect(push).not.toBeNull();
    push!(signed(projectionEventTemplate(RAIL, GRANT, 1_700_000_000, content)));
    await vi.waitFor(() => expect(client.getState().projection?.contacts).toHaveLength(1));
    stop();
    expect(close).toHaveBeenCalled();
  });

  it('fires onRevoked from the live path', async () => {
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection({ contacts: [], revoked: true }));
    let push: ((e: SignedNostrEvent) => void) | null = null;
    const onRevoked = vi.fn();
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest: async () => null,
        publish: async () => true,
        subscribe: (_f, _r, onEvent) => { push = onEvent; return () => {}; },
      },
    });
    client.onRevoked(onRevoked);
    client.start(PAIRING, { pollMs: 60_000 });
    push!(signed(projectionEventTemplate(RAIL, GRANT, 1, content)));
    await vi.waitFor(() => expect(onRevoked).toHaveBeenCalledWith(GRANT));
    client.stop();
    // Still exactly once when the same revocation then arrives by poll.
    expect(onRevoked).toHaveBeenCalledTimes(1);
  });

  it('polls when the transport cannot subscribe, and stops polling on stop()', async () => {
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection());
    const fetchNewest = vi.fn(async () => signed(projectionEventTemplate(RAIL, GRANT, 1_700_000_000, content)));
    const client = createSignetContactsClient({
      signer,
      // No `subscribe` at all — the documented degraded mode.
      relay: { fetchNewest, publish: async () => true },
      now: () => 1_700_000_100,
    });
    client.start(PAIRING, { pollMs: 10 });
    // Nothing is fetched synchronously: the first poll is one interval away.
    expect(fetchNewest).not.toHaveBeenCalled();
    await vi.waitFor(() => expect(client.getState().projection?.contacts).toHaveLength(1));
    client.stop();
    const afterStop = fetchNewest.mock.calls.length;
    await new Promise((resolve) => { setTimeout(resolve, 60); });
    expect(fetchNewest.mock.calls.length).toBe(afterStop);
  });

  // Round 2: `start` returned the ONE module-level teardown closure, so a
  // handle kept from an earlier `start` tore down whatever subscription was
  // current — the exact shape of a React effect whose cleanup runs after the
  // next effect has already re-subscribed.
  it('gives each start its own handle, so a stale one cannot tear down a later subscription', () => {
    const closes = [vi.fn(), vi.fn()];
    let index = 0;
    const client = createSignetContactsClient({
      signer: fakeSigner(),
      relay: {
        fetchNewest: async () => null,
        publish: async () => true,
        subscribe: () => closes[index++]!,
      },
    });
    const stopFirst = client.start(PAIRING, { pollMs: 60_000 });
    const stopSecond = client.start(PAIRING, { pollMs: 60_000 });
    expect(closes[0]).toHaveBeenCalledTimes(1);   // replaced by the second start
    // The stale handle must be inert, not a teardown of the live subscription.
    stopFirst();
    expect(closes[1]).not.toHaveBeenCalled();
    stopSecond();
    expect(closes[1]).toHaveBeenCalledTimes(1);
  });

  // Round 2: `revokedAnnounced` latched true for the life of the client, so a
  // grant that was revoked, un-revoked by a strictly newer projection (which
  // `applyProjection` allows) and revoked again told the app about the first
  // revocation only — while the state itself had changed under it.
  it('fires onRevoked on every revocation edge, and never twice for one', async () => {
    const signer = fakeSigner();
    const revocation = await sealProjection(signer, projection({
      contacts: [], revoked: true,
      frontier: { maxClock: 5, opCount: 10, publishedAt: 1_700_000_000, deviceId: '2'.repeat(32) },
    }));
    const unrevoke = await sealProjection(signer, projection({
      frontier: { maxClock: 6, opCount: 11, publishedAt: 1_700_000_010, deviceId: '2'.repeat(32) },
    }));
    const secondRevocation = await sealProjection(signer, projection({
      contacts: [], revoked: true,
      frontier: { maxClock: 7, opCount: 12, publishedAt: 1_700_000_020, deviceId: '2'.repeat(32) },
    }));
    let serve = revocation;
    const onRevoked = vi.fn();
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, serve)),
        publish: async () => true,
      },
      now: () => 1_700_000_100,
    });
    client.onRevoked(onRevoked);

    await client.fetchProjection(PAIRING);
    expect(onRevoked).toHaveBeenCalledTimes(1);
    // The same tombstone arriving again (a relay replay, or the poll racing
    // the live socket) is not a second revocation.
    await client.fetchProjection(PAIRING);
    expect(onRevoked).toHaveBeenCalledTimes(1);

    serve = unrevoke;
    await client.fetchProjection(PAIRING);
    expect(client.getState().revoked).toBe(false);
    expect(onRevoked).toHaveBeenCalledTimes(1);

    serve = secondRevocation;
    await client.fetchProjection(PAIRING);
    expect(client.getState().revoked).toBe(true);
    expect(onRevoked).toHaveBeenCalledTimes(2);
  });

  it('skips a poll tick that the live socket has already covered', async () => {
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection());
    const fetchNewest = vi.fn(async () => null);
    let push: ((e: SignedNostrEvent) => void) | null = null;
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest, publish: async () => true,
        subscribe: (_f, _r, onEvent) => { push = onEvent; return () => {}; },
      },
      now: () => 1_700_000_100,
    });
    client.start(PAIRING, { pollMs: 200 });
    // Deliver half an interval in, so the tick at 200ms sees a socket that
    // has plainly just worked.
    await new Promise((resolve) => { setTimeout(resolve, 100); });
    push!(signed(projectionEventTemplate(RAIL, GRANT, 1_700_000_000, content)));
    await vi.waitFor(() => expect(client.getState().projection?.contacts).toHaveLength(1));
    await new Promise((resolve) => { setTimeout(resolve, 180); });
    expect(fetchNewest).not.toHaveBeenCalled();
    // Once the socket goes quiet for a whole interval, the safety net resumes.
    await vi.waitFor(() => expect(fetchNewest).toHaveBeenCalled(), { timeout: 1500 });
    client.stop();
  });

  it('replaces the previous subscription when start is called again, and stop is idempotent', () => {
    const closes = [vi.fn(), vi.fn()];
    let index = 0;
    const client = createSignetContactsClient({
      signer: fakeSigner(),
      relay: {
        fetchNewest: async () => null,
        publish: async () => true,
        subscribe: () => closes[index++]!,
      },
    });
    client.start(PAIRING, { pollMs: 60_000 });
    client.start(PAIRING, { pollMs: 60_000 });
    expect(closes[0]).toHaveBeenCalledTimes(1);
    client.stop();
    client.stop();
    expect(closes[1]).toHaveBeenCalledTimes(1);
  });

  it('survives a transport whose subscribe throws, falling back to the poll alone', async () => {
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection());
    const fetchNewest = vi.fn(async () => signed(projectionEventTemplate(RAIL, GRANT, 1_700_000_000, content)));
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest, publish: async () => true,
        subscribe: () => { throw new Error('socket refused'); },
      },
      now: () => 1_700_000_100,
    });
    expect(() => client.start(PAIRING, { pollMs: 10 })).not.toThrow();
    await vi.waitFor(() => expect(client.getState().projection?.contacts).toHaveLength(1));
    client.stop();
  });

  it('ignores a pushed event that is not this grant’s rail, and never throws into the transport', async () => {
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection());
    let push: ((e: SignedNostrEvent) => void) | null = null;
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest: async () => null, publish: async () => true,
        subscribe: (_f, _r, onEvent) => { push = onEvent; return () => {}; },
      },
    });
    client.start(PAIRING, { pollMs: 60_000 });
    expect(() => push!({
      ...signed(projectionEventTemplate(RAIL, GRANT, 1, content)), pubkey: '7'.repeat(64),
    })).not.toThrow();
    await Promise.resolve();
    expect(client.getState().projection).toBeNull();
    client.stop();
  });
});

// Fix round 1, I2: a stored row is outside this client's control (shared with
// the rest of the app, editable by devtools, subject to partial writes) —
// `load()` must not trust it any further than a wire value.
describe('load — stored-row validation (I2)', () => {
  it('drops a malformed pending row rather than keeping it', async () => {
    const storage = createMemoryStorage();
    await storage.set(PENDING_KEY(GRANT), JSON.stringify([
      // Bad operationId (not 32-hex).
      { operationId: 'not-hex', action: 'add-ken', value: { pubkey: 'd'.repeat(64), displayName: 'Ada' }, sentAt: 1 },
      // Bad value shape for its action — would throw in `reconcilePending`'s
      // `.pubkey.toLowerCase()` on every future `fetchProjection` if kept.
      { operationId: 'a'.repeat(32), action: 'add-ken', value: { pubkey: 'not-hex', displayName: 'Ada' }, sentAt: 1 },
      // Unknown action.
      { operationId: 'c'.repeat(32), action: 'delete-everything', value: {}, sentAt: 1 },
      // Well-formed — the one row that should survive.
      { operationId: 'b'.repeat(32), action: 'add-ken', value: { pubkey: 'd'.repeat(64), displayName: 'Ada' }, sentAt: 1 },
    ]));
    const client = createSignetContactsClient({
      signer: fakeSigner(), relay: { fetchNewest: async () => null, publish: async () => true }, storage,
    });
    await client.load(GRANT);
    const pending = client.pendingProposals();
    expect(pending).toHaveLength(1);
    expect(pending[0]?.operationId).toBe('b'.repeat(32));
  });

  it('drops a corrupt stored projection without wedging a later fetchProjection, keeping blockedPubkeys', async () => {
    const storage = createMemoryStorage();
    await storage.set(STATE_KEY(GRANT), JSON.stringify({
      grantId: GRANT,
      // Missing frontier/scopes/contacts/etc — would throw inside
      // `applyProjection`'s frontier comparison on every future fetch if a
      // future `fetchProjection` ever compared against it directly.
      projection: { v: 2, grantId: GRANT },
      receivedAt: 1,
      blockedPubkeys: ['d'.repeat(64)],
      revoked: false,
    }));
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection());
    const client = createSignetContactsClient({
      signer,
      relay: { fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, content)), publish: async () => true },
      storage,
    });
    const loaded = await client.load(GRANT);
    expect(loaded.projection).toBeNull();
    // Sticky Blocked set survives even though the projection it came from did not.
    expect(client.getBlockedSet().has('d'.repeat(64))).toBe(true);
    // A corrupt stored projection must not wedge every later fetchProjection —
    // this grant's first REAL projection applies exactly as if it were new.
    const p = await client.fetchProjection(PAIRING);
    expect(p?.contacts).toHaveLength(1);
  });

  // Residuals fix #1.
  it('drops a stored projection whose grantId does not match the ARGUMENT grantId, pinning state to the argument', async () => {
    const OTHER_GRANT = '9'.repeat(32);
    const storage = createMemoryStorage();
    // A row stored under OTHER_GRANT's key but whose payload actually
    // belongs to GRANT (stale key reuse / a corrupted write) — `load` is
    // called with OTHER_GRANT, so `parsed.grantId` disagrees with the
    // argument.
    await storage.set(STATE_KEY(OTHER_GRANT), JSON.stringify({
      grantId: GRANT,
      projection: projection(),
      receivedAt: 1,
      blockedPubkeys: [],
      revoked: false,
    }));
    const signer = fakeSigner();
    const otherPairing: PairingV2 = { ...PAIRING, grantId: OTHER_GRANT };
    const content = await sealProjection(signer, projection({ grantId: OTHER_GRANT }));
    const client = createSignetContactsClient({
      signer, storage,
      relay: { fetchNewest: async () => signed(projectionEventTemplate(RAIL, OTHER_GRANT, 1, content)), publish: async () => true },
    });
    const loaded = await client.load(OTHER_GRANT);
    expect(loaded.grantId).toBe(OTHER_GRANT);
    expect(loaded.projection).toBeNull();

    // Not wedged: on the SAME client, a REAL projection for OTHER_GRANT
    // applies cleanly. If the mismatched (GRANT-shaped) projection had been
    // kept as `state.projection`, `applyProjection`'s frontier comparison
    // would run this incoming OTHER_GRANT projection against a held
    // projection that was never OTHER_GRANT's in the first place.
    const p = await client.fetchProjection(otherPairing);
    expect(p?.contacts).toHaveLength(1);
  });
});

describe('propose', () => {
  // NB: `PAIRING` only grants `signet.contacts.read:directory` (see the next
  // test, which relies on exactly that to prove an ungranted action is
  // refused) — an add-ken proposal needs a pairing that actually grants
  // `signet.contacts.propose:add-ken`.
  const ADD_KEN_PAIRING: PairingV2 = {
    ...PAIRING,
    grantedCapabilities: ['signet.contacts.read:directory', 'signet.contacts.propose:add-ken'],
  };

  it('encrypts to the rail, signs as the app and publishes under the proposal tag', async () => {
    let captured: SignedNostrEvent | null = null;
    const client = createSignetContactsClient({
      signer: fakeSigner(),
      relay: { fetchNewest: async () => null, publish: async (e) => { captured = e; return true; } },
      now: () => 1_700_000_500,
    });
    const ok = await client.propose(ADD_KEN_PAIRING, [
      { action: 'add-ken', value: { pubkey: 'c'.repeat(64), displayName: 'Ada' } },
    ]);
    expect(ok).toBe(true);
    expect(captured!.pubkey).toBe(APP);
    expect(captured!.tags).toEqual([['d', proposalTag(GRANT, APP)]]);
    const inner = JSON.parse(captured!.content) as { to: string; plaintext: string };
    expect(inner.to).toBe(RAIL);
    const batch = parseProposalBatch(inner.plaintext);
    expect(batch?.proposals[0]?.action).toBe('add-ken');
    expect(batch?.proposals[0]?.grantId).toBe(GRANT);
  });

  it('refuses a draft the grant does not cover, without touching the relay', async () => {
    const publish = vi.fn(async () => true);
    const client = createSignetContactsClient({
      signer: fakeSigner(), relay: { fetchNewest: async () => null, publish },
    });
    const ok = await client.propose(PAIRING, [
      { action: 'rename-app-label', value: { contactId: 'a'.repeat(32), label: 'Coach' } },
    ]);
    expect(ok).toBe(false);
    expect(publish).not.toHaveBeenCalled();
  });

  it('refuses an empty draft list', async () => {
    const client = createSignetContactsClient({
      signer: fakeSigner(), relay: { fetchNewest: async () => null, publish: async () => true },
    });
    expect(await client.propose(PAIRING, [])).toBe(false);
  });

  // Controller correction 3: a rename draft with no `updatedAt` is stamped
  // from the client's injected clock, not real wall time.
  it('stamps a rename-app-label draft’s updatedAt from the injected clock', async () => {
    let captured: SignedNostrEvent | null = null;
    const RENAME_PAIRING: PairingV2 = {
      ...PAIRING,
      grantedCapabilities: ['signet.contacts.read:directory', 'signet.contacts.propose:rename-app-label'],
    };
    const client = createSignetContactsClient({
      signer: fakeSigner(),
      relay: { fetchNewest: async () => null, publish: async (e) => { captured = e; return true; } },
      now: () => 1_700_000_500,
      nowMs: () => 1_700_000_500_123,
    });
    const ok = await client.propose(RENAME_PAIRING, [
      { action: 'rename-app-label', value: { contactId: 'a'.repeat(32), label: 'Coach' } },
    ]);
    expect(ok).toBe(true);
    const inner = JSON.parse(captured!.content) as { to: string; plaintext: string };
    const batch = parseProposalBatch(inner.plaintext);
    const value = batch?.proposals[0]?.value as { updatedAt: number };
    expect(value.updatedAt).toBe(1_700_000_500_123);
  });

  // Fix round 1, I3.
  it('resolves false, never throws, when the signer’s nip44Encrypt rejects', async () => {
    const signer = fakeSigner();
    const throwingSigner: ContactsSigner = { ...signer, nip44Encrypt: async () => { throw new Error('bunker offline'); } };
    const publish = vi.fn(async () => true);
    const client = createSignetContactsClient({
      signer: throwingSigner, relay: { fetchNewest: async () => null, publish },
    });
    const ADD_KEN = { ...PAIRING, grantedCapabilities: ['signet.contacts.read:directory', 'signet.contacts.propose:add-ken'] as const };
    await expect(client.propose(ADD_KEN, [
      { action: 'add-ken', value: { pubkey: 'c'.repeat(64), displayName: 'Ada' } },
    ])).resolves.toBe(false);
    expect(publish).not.toHaveBeenCalled();
    expect(client.pendingProposals()).toEqual([]);
  });

  it('resolves false, never throws, when signEvent rejects', async () => {
    const signer = fakeSigner();
    const throwingSigner: ContactsSigner = { ...signer, signEvent: async () => { throw new Error('user declined'); } };
    const client = createSignetContactsClient({
      signer: throwingSigner, relay: { fetchNewest: async () => null, publish: async () => true },
    });
    const ADD_KEN = { ...PAIRING, grantedCapabilities: ['signet.contacts.read:directory', 'signet.contacts.propose:add-ken'] as const };
    await expect(client.propose(ADD_KEN, [
      { action: 'add-ken', value: { pubkey: 'c'.repeat(64), displayName: 'Ada' } },
    ])).resolves.toBe(false);
    expect(client.pendingProposals()).toEqual([]);
  });

  it('resolves false, never throws, when the relay’s publish rejects', async () => {
    const client = createSignetContactsClient({
      signer: fakeSigner(),
      relay: { fetchNewest: async () => null, publish: async () => { throw new Error('socket closed'); } },
    });
    const ADD_KEN = { ...PAIRING, grantedCapabilities: ['signet.contacts.read:directory', 'signet.contacts.propose:add-ken'] as const };
    await expect(client.propose(ADD_KEN, [
      { action: 'add-ken', value: { pubkey: 'c'.repeat(64), displayName: 'Ada' } },
    ])).resolves.toBe(false);
    expect(client.pendingProposals()).toEqual([]);
  });
});

describe('propose — resend (B2)', () => {
  const ADD_KEN_PAIRING: PairingV2 = {
    ...PAIRING,
    grantedCapabilities: ['signet.contacts.read:directory', 'signet.contacts.propose:add-ken'],
  };

  function plaintextOf(event: SignedNostrEvent): string {
    return (JSON.parse(event.content) as { to: string; plaintext: string }).plaintext;
  }

  it('resends a still-pending proposal on the next call, byte-identical to the first send', async () => {
    let clock = 1_700_000_500;
    const captured: SignedNostrEvent[] = [];
    const client = createSignetContactsClient({
      signer: fakeSigner(),
      relay: { fetchNewest: async () => null, publish: async (e) => { captured.push(e); return true; } },
      now: () => clock,
    });
    await client.propose(ADD_KEN_PAIRING, [
      { action: 'add-ken', value: { pubkey: 'c'.repeat(64), displayName: 'Ada' } },
    ]);
    const firstProposal = parseProposalBatch(plaintextOf(captured[0]!))!.proposals[0]!;

    clock += 100; // a second call, later — the resent entry must keep the ORIGINAL createdAt
    await client.propose(ADD_KEN_PAIRING, [
      { action: 'add-ken', value: { pubkey: 'd'.repeat(64), displayName: 'Bo' } },
    ]);
    const secondBatch = parseProposalBatch(plaintextOf(captured[1]!))!;
    expect(secondBatch.proposals).toHaveLength(2);
    // New drafts come first.
    expect((secondBatch.proposals[0]!.value as { pubkey: string }).pubkey).toBe('d'.repeat(64));
    const resent = secondBatch.proposals[1]!;
    expect(resent.operationId).toBe(firstProposal.operationId);
    expect(resent.action).toBe(firstProposal.action);
    expect(resent.value).toEqual(firstProposal.value);
    expect(resent.createdAt).toBe(firstProposal.createdAt);
    expect(resent.createdAt).toBe(1_700_000_500); // not the later clock
  });

  it('caps at MAX_PROPOSALS_PER_BATCH, new drafts first, resends newest-sentAt-first', async () => {
    const storage = createMemoryStorage();
    const baseSentAt = 1_700_000_000;
    const rows: PendingProposal[] = [];
    for (let i = 0; i < 60; i++) {
      rows.push({
        operationId: i.toString(16).padStart(32, '0'),
        action: 'add-ken',
        value: { pubkey: i.toString(16).padStart(64, '9'), displayName: `P${i}` },
        sentAt: baseSentAt + i, // strictly increasing: row 59 is newest
      });
    }
    await storage.set(`signet-contacts:pending:${GRANT}`, JSON.stringify(rows));

    const captured: SignedNostrEvent[] = [];
    const client = createSignetContactsClient({
      signer: fakeSigner(), storage,
      relay: { fetchNewest: async () => null, publish: async (e) => { captured.push(e); return true; } },
      now: () => baseSentAt + 1000,
    });
    await client.load(GRANT);
    const newDrafts = Array.from({ length: 5 }, (_, k) => ({
      action: 'add-ken' as const,
      value: { pubkey: `f${k}`.padStart(64, 'f'), displayName: `New${k}` },
    }));
    expect(await client.propose(ADD_KEN_PAIRING, newDrafts)).toBe(true);

    const batch = parseProposalBatch(plaintextOf(captured[0]!))!;
    expect(batch.proposals).toHaveLength(MAX_PROPOSALS_PER_BATCH);
    const resent = batch.proposals.slice(newDrafts.length);
    expect(resent).toHaveLength(MAX_PROPOSALS_PER_BATCH - newDrafts.length); // 45
    const resentSentAts = resent.map((p) => p.createdAt);
    expect(resentSentAts[0]).toBe(baseSentAt + 59); // newest first
    expect(resentSentAts.at(-1)).toBe(baseSentAt + 15); // the 45 newest of 60, so 15..59
    expect(resentSentAts).toEqual([...resentSentAts].sort((a, b) => b - a));
    // The 15 oldest (rows 0..14) were pushed out of the batch, not dropped —
    // they stay pending for a later call or reconcilePending to deal with.
    expect(client.pendingProposals()).toHaveLength(65); // 60 original + 5 new
  });

  it('does not resend an add-ken superseded by a new draft for the same pubkey, and drops it only on success', async () => {
    const storage = createMemoryStorage();
    const pubkey = 'c'.repeat(64);
    const oldRow: PendingProposal = {
      operationId: '1'.repeat(32), action: 'add-ken', value: { pubkey, displayName: 'Old name' }, sentAt: 1_700_000_000,
    };
    await storage.set(`signet-contacts:pending:${GRANT}`, JSON.stringify([oldRow]));

    // A failed publish must leave the superseded row exactly where it was.
    const failing = createSignetContactsClient({
      signer: fakeSigner(), storage,
      relay: { fetchNewest: async () => null, publish: async () => false },
      now: () => 1_700_000_500,
    });
    await failing.load(GRANT);
    expect(await failing.propose(ADD_KEN_PAIRING, [{ action: 'add-ken', value: { pubkey, displayName: 'New name' } }]))
      .toBe(false);
    expect(failing.pendingProposals()).toEqual([oldRow]);

    // A successful publish drops it, and it must never have ridden along.
    const captured: SignedNostrEvent[] = [];
    const client = createSignetContactsClient({
      signer: fakeSigner(), storage,
      relay: { fetchNewest: async () => null, publish: async (e) => { captured.push(e); return true; } },
      now: () => 1_700_000_500,
    });
    await client.load(GRANT);
    expect(await client.propose(ADD_KEN_PAIRING, [{ action: 'add-ken', value: { pubkey, displayName: 'New name' } }]))
      .toBe(true);
    const batch = parseProposalBatch(plaintextOf(captured[0]!))!;
    expect(batch.proposals).toHaveLength(1); // the superseded row never rode along
    expect(client.pendingProposals().some((p) => p.operationId === oldRow.operationId)).toBe(false);
  });

  it('does not resend a rename-app-label superseded by a new draft for the same contactId', async () => {
    const storage = createMemoryStorage();
    const contactId = 'a'.repeat(32);
    const oldRow: PendingProposal = {
      operationId: '6'.repeat(32), action: 'rename-app-label',
      value: { contactId, label: 'Old label', updatedAt: 1_700_000_000_000 }, sentAt: 1_700_000_000,
    };
    await storage.set(`signet-contacts:pending:${GRANT}`, JSON.stringify([oldRow]));
    const RENAME_PAIRING: PairingV2 = {
      ...PAIRING, grantedCapabilities: ['signet.contacts.read:directory', 'signet.contacts.propose:rename-app-label'],
    };
    const captured: SignedNostrEvent[] = [];
    const client = createSignetContactsClient({
      signer: fakeSigner(), storage,
      relay: { fetchNewest: async () => null, publish: async (e) => { captured.push(e); return true; } },
      now: () => 1_700_000_500,
    });
    await client.load(GRANT);
    expect(await client.propose(RENAME_PAIRING, [
      { action: 'rename-app-label', value: { contactId, label: 'New label', updatedAt: 1_700_000_600_000 } },
    ])).toBe(true);
    const batch = parseProposalBatch(plaintextOf(captured[0]!))!;
    expect(batch.proposals).toHaveLength(1);
    expect(client.pendingProposals().some((p) => p.operationId === oldRow.operationId)).toBe(false);
  });

  it('does not resend a pending entry older than the wire’s staleness ceiling, even under a looser local window', async () => {
    const storage = createMemoryStorage();
    const staleRow: PendingProposal = {
      operationId: '2'.repeat(32), action: 'add-ken', value: { pubkey: 'c'.repeat(64), displayName: 'Stale' }, sentAt: 1_700_000_000,
    };
    await storage.set(`signet-contacts:pending:${GRANT}`, JSON.stringify([staleRow]));
    const nowSec = 1_700_000_000 + MAX_STALENESS_SECONDS + 1;
    const captured: SignedNostrEvent[] = [];
    const client = createSignetContactsClient({
      signer: fakeSigner(), storage,
      relay: { fetchNewest: async () => null, publish: async (e) => { captured.push(e); return true; } },
      now: () => nowSec,
      maxPendingStalenessSeconds: MAX_STALENESS_SECONDS * 10, // looser than the wire's own ceiling
    });
    await client.load(GRANT);
    expect(await client.propose(ADD_KEN_PAIRING, [{ action: 'add-ken', value: { pubkey: 'd'.repeat(64), displayName: 'New' } }]))
      .toBe(true);
    const batch = parseProposalBatch(plaintextOf(captured[0]!))!;
    expect(batch.proposals).toHaveLength(1); // the stale row is excluded from the batch
    // Not dropped either — only resend is refused; reconcilePending owns aging it out.
    expect(client.pendingProposals().some((p) => p.operationId === staleRow.operationId)).toBe(true);
  });

  it('does not resend a pending entry whose capability the grant no longer covers', async () => {
    const storage = createMemoryStorage();
    const renameRow: PendingProposal = {
      operationId: '3'.repeat(32), action: 'rename-app-label',
      value: { contactId: 'a'.repeat(32), label: 'Coach', updatedAt: 1_700_000_000_000 }, sentAt: 1_700_000_000,
    };
    await storage.set(`signet-contacts:pending:${GRANT}`, JSON.stringify([renameRow]));
    const captured: SignedNostrEvent[] = [];
    const client = createSignetContactsClient({
      signer: fakeSigner(), storage,
      relay: { fetchNewest: async () => null, publish: async (e) => { captured.push(e); return true; } },
      now: () => 1_700_000_500,
    });
    await client.load(GRANT);
    // ADD_KEN_PAIRING grants only add-ken; the rename row's capability is gone.
    expect(await client.propose(ADD_KEN_PAIRING, [{ action: 'add-ken', value: { pubkey: 'd'.repeat(64), displayName: 'New' } }]))
      .toBe(true);
    const batch = parseProposalBatch(plaintextOf(captured[0]!))!;
    expect(batch.proposals).toHaveLength(1);
    expect(client.pendingProposals().some((p) => p.operationId === renameRow.operationId)).toBe(true);
  });

  it('leaves pending fully unchanged, resend candidates included, when the publish fails', async () => {
    const storage = createMemoryStorage();
    const existingRow: PendingProposal = {
      operationId: '4'.repeat(32), action: 'add-ken', value: { pubkey: 'c'.repeat(64), displayName: 'Existing' }, sentAt: 1_700_000_000,
    };
    await storage.set(`signet-contacts:pending:${GRANT}`, JSON.stringify([existingRow]));
    const client = createSignetContactsClient({
      signer: fakeSigner(), storage,
      relay: { fetchNewest: async () => null, publish: async () => false },
      now: () => 1_700_000_500,
    });
    await client.load(GRANT);
    expect(await client.propose(ADD_KEN_PAIRING, [{ action: 'add-ken', value: { pubkey: 'd'.repeat(64), displayName: 'New' } }]))
      .toBe(false);
    expect(client.pendingProposals()).toEqual([existingRow]);
  });

  it('never resends an item reconcilePending already cleared via an accepted projection', async () => {
    const signer = fakeSigner();
    const pubkey = 'd'.repeat(64);
    const proj = projection({
      contacts: [{ contactId: 'c'.repeat(32), displayName: 'Ada', identities: [{ pubkey }] }],
    });
    const content = await sealProjection(signer, proj);
    const captured: SignedNostrEvent[] = [];
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, content)),
        publish: async (e) => { captured.push(e); return true; },
      },
      now: () => 1_700_000_500,
    });
    await client.propose(ADD_KEN_PAIRING, [{ action: 'add-ken', value: { pubkey, displayName: 'Ada' } }]);
    expect(client.pendingProposals()).toHaveLength(1);
    await client.fetchProjection(PAIRING);
    expect(client.pendingProposals()).toEqual([]); // reconciled away by the projection

    expect(await client.propose(ADD_KEN_PAIRING, [{ action: 'add-ken', value: { pubkey: 'e'.repeat(64), displayName: 'Bo' } }]))
      .toBe(true);
    const batch = parseProposalBatch(plaintextOf(captured[1]!))!;
    expect(batch.proposals).toHaveLength(1); // nothing resurrected
  });
});

describe('pendingProposals (R-9)', () => {
  const ADD_PAIRING: PairingV2 = {
    ...PAIRING,
    grantedCapabilities: ['signet.contacts.read:directory', 'signet.contacts.propose:add-ken'],
  };

  it('remembers what was sent, with the time it was sent', async () => {
    const client = createSignetContactsClient({
      signer: fakeSigner(),
      relay: { fetchNewest: async () => null, publish: async () => true },
      now: () => 1_700_000_500,
    });
    await client.propose(ADD_PAIRING, [{ action: 'add-ken', value: { pubkey: 'd'.repeat(64), displayName: 'Ada' } }]);
    const pending = client.pendingProposals();
    expect(pending).toHaveLength(1);
    expect(pending[0]?.action).toBe('add-ken');
    expect(pending[0]?.sentAt).toBe(1_700_000_500);
    expect(pending[0]?.operationId).toMatch(/^[0-9a-f]{32}$/);
  });

  it('remembers nothing for a proposal it refused to send', async () => {
    const client = createSignetContactsClient({
      signer: fakeSigner(), relay: { fetchNewest: async () => null, publish: async () => false },
    });
    await client.propose(PAIRING, [{ action: 'add-ken', value: { pubkey: 'd'.repeat(64), displayName: 'Ada' } }]);
    expect(client.pendingProposals()).toEqual([]);
  });

  it('clears an add-ken once a projection carries that pubkey', async () => {
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection());
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, content)),
        publish: async () => true,
      },
      now: () => 1_700_000_500,
    });
    await client.propose(ADD_PAIRING, [{ action: 'add-ken', value: { pubkey: 'd'.repeat(64), displayName: 'Ada' } }]);
    expect(client.pendingProposals()).toHaveLength(1);
    await client.fetchProjection(PAIRING);
    expect(client.pendingProposals()).toEqual([]);
  });

  it('gives up on a proposal older than the staleness window', async () => {
    let clock = 1_700_000_500;
    const signer = fakeSigner();
    const content = await sealProjection(signer, projection({ contacts: [] }));
    const client = createSignetContactsClient({
      signer,
      relay: {
        fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, content)),
        publish: async () => true,
      },
      now: () => clock,
      maxPendingStalenessSeconds: 100,
    });
    await client.propose(ADD_PAIRING, [{ action: 'add-ken', value: { pubkey: '9'.repeat(64), displayName: 'Bo' } }]);
    clock += 101;
    await client.fetchProjection(PAIRING);
    expect(client.pendingProposals()).toEqual([]);
  });

  // Fix round 1, M1: keyed off `pairing.grantId`, not `state.grantId` (which
  // stays null until the first successful `fetchProjection`).
  it('persists a proposal sent BEFORE any projection has ever been fetched', async () => {
    const storage = createMemoryStorage();
    const signer = fakeSigner();
    const first = createSignetContactsClient({
      signer, storage,
      relay: { fetchNewest: async () => null, publish: async () => true },
      now: () => 1_700_000_500,
    });
    // No fetchProjection call at all — `state.grantId` is still null here.
    const ok = await first.propose(ADD_PAIRING, [{ action: 'add-ken', value: { pubkey: 'd'.repeat(64), displayName: 'Ada' } }]);
    expect(ok).toBe(true);

    const second = createSignetContactsClient({
      signer, storage, relay: { fetchNewest: async () => null, publish: async () => true },
    });
    const loaded = await second.load(GRANT);
    expect(loaded).toBeDefined();
    expect(second.pendingProposals()).toHaveLength(1);
    expect(second.pendingProposals()[0]?.action).toBe('add-ken');
  });

  // Fix round 1, M2.
  it('returns a deep copy: mutating a returned entry cannot corrupt internal state', async () => {
    const client = createSignetContactsClient({
      signer: fakeSigner(),
      relay: { fetchNewest: async () => null, publish: async () => true },
      now: () => 1_700_000_500,
    });
    await client.propose(ADD_PAIRING, [{ action: 'add-ken', value: { pubkey: 'd'.repeat(64), displayName: 'Ada' } }]);
    const first = client.pendingProposals();
    (first[0]!.value as { displayName: string }).displayName = 'TAMPERED';
    (first[0] as { action: string }).action = 'rename-app-label';
    const second = client.pendingProposals();
    expect((second[0]!.value as { displayName: string }).displayName).toBe('Ada');
    expect(second[0]!.action).toBe('add-ken');
  });
});

describe('ephemeral pairing acknowledgements', () => {
  it('keeps a live listener between polling queries and removes it after approval', async () => {
    const signer = fakeSigner(), stopped = vi.fn();
    let receive!: (event: SignedNostrEvent) => void;
    const content = await signer.nip44Encrypt(APP, buildPairingAckV2({ v: 2, grantId: GRANT, railPubkey: RAIL,
      projectionTag: projectionTag(GRANT), proposalTag: proposalTag(GRANT, APP), relay: RELAYS[0],
      grantedCapabilities: ['signet.contacts.read:directory'], maxStalenessSeconds: 21600, challenge: CHALLENGE }));
    const client = createSignetContactsClient({ signer, now: () => 1700000000, relay: {
      fetchNewest: async () => null, publish: async () => true,
      subscribe: (_filter, _relays, callback) => { receive = callback; return stopped; },
    } });
    const waiting = client.awaitPairingAck({ challenge: CHALLENGE, relays: RELAYS, pollMs: 10000 });
    await Promise.resolve(); await Promise.resolve();
    receive({ ...ackEventTemplate('9'.repeat(64), APP, 1700000000, content), id: '4'.repeat(64), sig: '5'.repeat(128) });
    expect((await waiting)?.grantId).toBe(GRANT);
    expect(stopped).toHaveBeenCalledOnce();
  });
  it('cancels a waiting live listener without accepting a late acknowledgement', async () => {
    const controller = new AbortController(), stopped = vi.fn(), signer = fakeSigner();
    const client = createSignetContactsClient({ signer, relay: { fetchNewest: async () => null,
      publish: async () => true, subscribe: () => stopped } });
    const waiting = client.awaitPairingAck({ challenge: CHALLENGE, relays: RELAYS, signal: controller.signal });
    controller.abort();
    expect(await waiting).toBeNull(); expect(stopped).toHaveBeenCalledOnce();
  });
  it('limits identity decryption to 32 unique candidates for one pairing attempt', async () => {
    const signer = fakeSigner(); signer.nip44Decrypt = vi.fn(async () => { throw new Error('not our ack'); });
    let id = 0;
    const client = createSignetContactsClient({ signer, now: () => 1700000000, relay: {
      fetchNewest: async () => ({ ...ackEventTemplate('9'.repeat(64), APP, 1700000000, 'junk'),
        id: (++id).toString(16).padStart(64, '0'), sig: '5'.repeat(128) }), publish: async () => true,
    } });
    expect(await client.awaitPairingAck({ challenge: CHALLENGE, relays: RELAYS, pollMs: 0, timeoutMs: 5000 })).toBeNull();
    expect(signer.nip44Decrypt).toHaveBeenCalledTimes(32);
  });
});
