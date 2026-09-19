import { expect, it } from 'vitest';
import { lookupContactKey, CONTACT_CHECK_MENU } from './check-menu.js';
import { emptyContactsState } from './state.js';
import type { ContactsState, ContactProjectionV2 } from './types.js';
const key = 'a'.repeat(64), other = 'b'.repeat(64);
function state(): ContactsState {
  return { ...emptyContactsState(), projection: { scopes: ['signet.contacts.read:directory'], issuedAt: 10, expiresAt: 100,
    contacts: [{ contactId: 'c'.repeat(32), displayName: 'Ada', identities: [{ pubkey: key }] }] } as ContactProjectionV2 };
}
it('looks up keys and flags same-name different-key records without inferring verification', () => {
  expect(lookupContactKey(state(), key, { now: 20 }).status).toBe('known');
  expect(lookupContactKey(state(), other, { now: 20, displayName: ' ADA ' }).status).toBe('name-clash');
  expect(lookupContactKey(state(), other, { now: 20 }).status).toBe('not-in-contacts');
  expect(CONTACT_CHECK_MENU.map(item => item.method)).toEqual(['in-person', 'words', 'nip05', 'app-attested']);
});
it('withholds revoked/ungranted directories while keeping sticky blocks', () => {
  const revoked = { ...state(), revoked: true, blockedPubkeys: [key] };
  expect(lookupContactKey(revoked, key, { now: 20 })).toMatchObject({ status: 'unavailable', contacts: [], blocked: true });
  expect(lookupContactKey(emptyContactsState(), key, { now: 20 }).status).toBe('unavailable');
  expect(lookupContactKey(state(), key, { now: 101 })).toMatchObject({ status: 'known', fresh: false });
});
