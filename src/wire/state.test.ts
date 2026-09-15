import { describe, it, expect } from 'vitest';
import { emptyContactsState, applyProjection, isFresh, blockedSetOf, visibleContacts } from './state.js';
import type { ContactProjectionV2, ProjectedContact } from './types.js';

const GRANT = 'f'.repeat(32);
const DEVICE = '2'.repeat(32);
const ISSUED = 1_700_000_000;
const EXPIRES = ISSUED + 21600;

function contact(id: string, blocked: boolean, pubkey: string): ProjectedContact {
  return {
    contactId: id, type: 'person', blocked,
    identities: [{ pubkey, verification: 'proven' }],
    effectiveTier: blocked ? 'none' : 'kith', tierSource: 'direct',
  };
}
function projection(over: Partial<ContactProjectionV2> = {}): ContactProjectionV2 {
  return {
    v: 2, grantId: GRANT, ownerPubkey: '1'.repeat(64),
    scopes: ['signet.contacts.read:directory', 'signet.contacts.blocks.read'],
    frontier: { maxClock: 5, opCount: 10, publishedAt: ISSUED, deviceId: DEVICE }, issuedAt: ISSUED, expiresAt: EXPIRES,
    contacts: [contact('a'.repeat(32), false, 'b'.repeat(64)), contact('c'.repeat(32), true, 'd'.repeat(64))],
    ...over,
  };
}

describe('applyProjection', () => {
  it('accepts the first projection and binds the grant', () => {
    const state = applyProjection(emptyContactsState(), projection(), ISSUED + 1);
    expect(state.grantId).toBe(GRANT);
    expect(state.projection?.contacts).toHaveLength(2);
    expect(state.receivedAt).toBe(ISSUED + 1);
    expect(state.revoked).toBe(false);
  });

  it('ignores a projection for a different grant', () => {
    const first = applyProjection(emptyContactsState(), projection(), ISSUED + 1);
    const other = applyProjection(first, projection({ grantId: '0'.repeat(32) }), ISSUED + 2);
    expect(other).toBe(first);
  });

  it('ignores a projection whose frontier has gone backwards', () => {
    const first = applyProjection(emptyContactsState(), projection(), ISSUED + 1);
    const stale = applyProjection(first, projection({ frontier: { maxClock: 4, opCount: 9, publishedAt: ISSUED, deviceId: DEVICE } }), ISSUED + 2);
    expect(stale).toBe(first);
  });

  it('accepts an equal frontier with a newer issuedAt (a cover republish)', () => {
    const first = applyProjection(emptyContactsState(), projection(), ISSUED + 1);
    const again = applyProjection(first, projection({
      issuedAt: ISSUED + 10, expiresAt: EXPIRES + 10,
      frontier: { maxClock: 5, opCount: 10, publishedAt: ISSUED + 10, deviceId: DEVICE },
    }), ISSUED + 11);
    expect(again.projection?.expiresAt).toBe(EXPIRES + 10);
  });

  it('breaks an equal-clock tie by publishedAt, in both directions (C13)', () => {
    const first = applyProjection(emptyContactsState(), projection(), ISSUED + 1);
    const otherDeviceOlder = applyProjection(first, projection({
      frontier: { maxClock: 5, opCount: 10, publishedAt: ISSUED - 50, deviceId: '3'.repeat(32) },
      contacts: [],
    }), ISSUED + 2);
    expect(otherDeviceOlder).toBe(first);
    const otherDeviceNewer = applyProjection(first, projection({
      frontier: { maxClock: 5, opCount: 10, publishedAt: ISSUED + 50, deviceId: '3'.repeat(32) },
      contacts: [],
    }), ISSUED + 3);
    expect(otherDeviceNewer.projection?.contacts).toEqual([]);
  });

  it('replaces the blocked set when a newer projection un-blocks someone', () => {
    const first = applyProjection(emptyContactsState(), projection(), ISSUED + 1);
    expect(blockedSetOf(first)).toEqual(new Set(['d'.repeat(64)]));
    const unblocked = applyProjection(first, projection({
      frontier: { maxClock: 6, opCount: 11, publishedAt: ISSUED + 2, deviceId: DEVICE },
      contacts: [contact('a'.repeat(32), false, 'b'.repeat(64)), contact('c'.repeat(32), false, 'd'.repeat(64))],
    }), ISSUED + 2);
    expect(blockedSetOf(unblocked).size).toBe(0);
  });

  it('keeps the blocked set through revocation and empties the contacts', () => {
    const first = applyProjection(emptyContactsState(), projection(), ISSUED + 1);
    const revoked = applyProjection(first, projection({
      contacts: [], revoked: true, frontier: { maxClock: 6, opCount: 11, publishedAt: ISSUED + 2, deviceId: DEVICE },
    }), ISSUED + 2);
    expect(revoked.revoked).toBe(true);
    expect(revoked.projection?.contacts).toEqual([]);
    expect(blockedSetOf(revoked)).toEqual(new Set(['d'.repeat(64)]));
  });

  it('accepts a revocation even when its frontier went backwards', () => {
    const first = applyProjection(emptyContactsState(), projection(), ISSUED + 1);
    const revoked = applyProjection(first, projection({ contacts: [], revoked: true, frontier: { maxClock: 1, opCount: 1, publishedAt: ISSUED + 2, deviceId: DEVICE } }), ISSUED + 2);
    expect(revoked.revoked).toBe(true);
  });

  it('includes linked pubkeys in the blocked set', () => {
    const withLink = projection({
      contacts: [{ ...contact('c'.repeat(32), true, 'd'.repeat(64)), linkedPubkeys: ['e'.repeat(64)] }],
    });
    const state = applyProjection(emptyContactsState(), withLink, ISSUED + 1);
    expect(blockedSetOf(state)).toEqual(new Set(['d'.repeat(64), 'e'.repeat(64)]));
  });
});

describe('isFresh', () => {
  it('is true up to expiresAt, false after, false when revoked, false when empty', () => {
    const state = applyProjection(emptyContactsState(), projection(), ISSUED + 1);
    expect(isFresh(state, EXPIRES)).toBe(true);
    expect(isFresh(state, EXPIRES + 1)).toBe(false);
    expect(isFresh(emptyContactsState(), ISSUED)).toBe(false);
    const revoked = applyProjection(state, projection({ contacts: [], revoked: true }), ISSUED + 2);
    expect(isFresh(revoked, ISSUED + 3)).toBe(false);
  });
});

describe('blockedSetOf after expiry', () => {
  it('never un-blocks because the projection went stale', () => {
    const state = applyProjection(emptyContactsState(), projection(), ISSUED + 1);
    expect(isFresh(state, EXPIRES + 10_000)).toBe(false);
    expect(blockedSetOf(state)).toEqual(new Set(['d'.repeat(64)]));
  });
});

describe('visibleContacts', () => {
  it('excludes blocked contacts and returns nothing once revoked', () => {
    const state = applyProjection(emptyContactsState(), projection(), ISSUED + 1);
    expect(visibleContacts(state).map((c) => c.contactId)).toEqual(['a'.repeat(32)]);
    const revoked = applyProjection(state, projection({ contacts: [], revoked: true }), ISSUED + 2);
    expect(visibleContacts(revoked)).toEqual([]);
  });
});
