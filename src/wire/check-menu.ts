import type { ContactsState, ProjectedContact } from './types.js';
import { isFresh } from './state.js';
import { sanitizeWireText } from './ids.js';
import { MAX_DISPLAY_NAME } from './constants.js';
/** A menu for developer-selected UI, never a ranking or automatic proof. */
export const CONTACT_CHECK_MENU = [
  { method: 'in-person', label: 'In person', guidance: 'Compare the person and their invite QR in person.' },
  { method: 'words', label: 'Words', guidance: 'Compare both directional codes after the signed commit-and-reveal exchange.' },
  { method: 'nip05', label: 'NIP-05', guidance: 'Fetch only after an explicit Check action; show the domain and date, not a trust tick.' },
  { method: 'app-attested', label: 'App attestation', guidance: 'Show the accountable issuer and independently validate its signed attestation.' },
] as const;
export interface ContactKeyLookup {
  status: 'known' | 'not-in-contacts' | 'name-clash' | 'unavailable';
  contacts: ProjectedContact[];
  fresh: boolean;
  blocked: boolean;
}
/** Uses only the granted local snapshot. It performs no name or network lookup. */
export function lookupContactKey(state: ContactsState, pubkey: string, options: { now: number; displayName?: string }): ContactKeyLookup {
  const key = pubkey.toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(key)) throw new Error('Invalid contact public key');
  const result: ContactKeyLookup = { status: 'unavailable', contacts: [], fresh: isFresh(state, options.now), blocked: state.blockedPubkeys.includes(key) };
  if (state.revoked || !state.projection?.scopes.includes('signet.contacts.read:directory')) return result;
  const contacts = state.projection.contacts;
  const known = contacts.filter(contact => contact.identities?.some(identity => identity.pubkey === key));
  if (known.length) return { ...result, status: 'known', contacts: known };
  const name = (value: string | undefined) => sanitizeWireText(value ?? '', MAX_DISPLAY_NAME).normalize('NFKC').toLowerCase().trim();
  const requested = name(options.displayName);
  const clashes = requested ? contacts.filter(contact => name(contact.displayName) === requested && contact.identities?.length) : [];
  return { ...result, status: clashes.length ? 'name-clash' : 'not-in-contacts', contacts: clashes };
}
