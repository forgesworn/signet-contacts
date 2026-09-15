import { describe, it, expect, vi } from 'vitest';
import { createSignetContactsClient, createMemoryStorage } from './client.js';
import type { ContactsSigner, RelayIo } from './client.js';
import { buildPairingAckV2, ackEventTemplate } from './wire/ack.js';
import { buildProjection, projectionEventTemplate } from './wire/projection.js';
import { parseProposalBatch } from './wire/proposal.js';
import { projectionTag, proposalTag } from './wire/ids.js';
import { PAIRING_FRESHNESS_SECONDS } from './wire/constants.js';
import type { ContactProjectionV2, PairingV2, SignedNostrEvent } from './wire/types.js';

const GRANT = 'f'.repeat(32);
const APP = 'a'.repeat(64);
const RAIL = 'b'.repeat(64);
const CHALLENGE = 'D'.repeat(32);
const RELAYS = ['wss://relay.example.com'];

/** A fake signer: "encryption" is a reversible tagged wrapper, so a test can
 *  assert who a payload was addressed to without a crypto dependency. */
function fakeSigner(pubkey = APP): ContactsSigner {
  return {
    pubkey,
    async nip44Encrypt(peer, plaintext) { return JSON.stringify({ to: peer, plaintext }); },
    async nip44Decrypt(peer, ciphertext) {
      const o = JSON.parse(ciphertext) as { to: string; plaintext: string };
      if (o.to !== pubkey && o.to !== peer) throw new Error('wrong recipient');
      return o.plaintext;
    },
    async signEvent(event) { return { ...event, id: '0'.repeat(64), sig: '1'.repeat(128) }; },
  };
}

function signed(template: ReturnType<typeof projectionEventTemplate>): SignedNostrEvent {
  return { ...template, id: '2'.repeat(64), sig: '3'.repeat(128) };
}

const PAIRING: PairingV2 = {
  grantId: GRANT, railPubkey: RAIL,
  projectionTag: projectionTag(GRANT), proposalTag: proposalTag(GRANT, APP),
  relay: RELAYS[0]!, grantedCapabilities: ['signet.contacts.read:directory'],
  maxStalenessSeconds: 21600, pairedAt: 1_700_000_000,
};

function projection(over: Partial<ContactProjectionV2> = {}): ContactProjectionV2 {
  return {
    v: 2, grantId: GRANT, ownerPubkey: '1'.repeat(64),
    scopes: ['signet.contacts.read:directory'],
    frontier: { maxClock: 5, opCount: 10, publishedAt: 1_700_000_000, deviceId: '2'.repeat(32) },
    issuedAt: 1_700_000_000, expiresAt: 1_700_021_600,
    contacts: [{
      contactId: 'c'.repeat(32), type: 'person', blocked: false,
      identities: [{ pubkey: 'd'.repeat(64), verification: 'proven' }],
      effectiveTier: 'kith', tierSource: 'direct',
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
});

describe('fetchProjection', () => {
  it('decrypts, applies and exposes state', async () => {
    const signer = fakeSigner();
    const content = await signer.nip44Encrypt(APP, buildProjection(projection()));
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
  });

  it('pins the rail author: an event from another key is ignored', async () => {
    const signer = fakeSigner();
    const content = await signer.nip44Encrypt(APP, buildProjection(projection()));
    const imposter = { ...signed(projectionEventTemplate(RAIL, GRANT, 1, content)), pubkey: '7'.repeat(64) };
    const client = createSignetContactsClient({
      signer, relay: { fetchNewest: async () => imposter, publish: async () => true },
    });
    expect(await client.fetchProjection(PAIRING)).toBeNull();
  });

  it('ignores a projection whose grantId is not this pairing’s', async () => {
    const signer = fakeSigner();
    const content = await signer.nip44Encrypt(APP, buildProjection(projection({ grantId: '0'.repeat(32) })));
    const client = createSignetContactsClient({
      signer,
      relay: { fetchNewest: async () => signed(projectionEventTemplate(RAIL, GRANT, 1, content)), publish: async () => true },
    });
    expect(await client.fetchProjection(PAIRING)).toBeNull();
  });

  it('fires onRevoked once when a revocation lands', async () => {
    const signer = fakeSigner();
    const content = await signer.nip44Encrypt(APP, buildProjection(projection({ contacts: [], revoked: true })));
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
    const content = await signer.nip44Encrypt(APP, buildProjection(projection()));
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
    const content = await signer.nip44Encrypt(APP, buildProjection(tooWide));
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
    const content = await signer.nip44Encrypt(APP, buildProjection(projection()));
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
    const content = await signer.nip44Encrypt(APP, buildProjection(projection({ contacts: [] })));
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
});
