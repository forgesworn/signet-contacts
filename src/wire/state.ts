/**
 * Consumer-side state reduction. This is the half of the contract a consuming
 * app MUST get right, so it lives in the SDK rather than in each app.
 *
 * Three rules, in order of how easy they are to get wrong:
 *
 * 1. **Blocked is sticky.** A projection expiring, or the grant being revoked,
 *    never un-blocks anybody. Safety state that decays on a timer is worse than
 *    no safety state, because the app looks like it is filtering right up until
 *    the moment it stops. Only a newer, accepted, non-revoked projection may
 *    shrink the Blocked set (spec §7.9, exploration §5.6).
 * 2. **Monotonic frontier, ordered by `(maxClock, publishedAt)` (C13).** A
 *    projection strictly older than the one already held is ignored — a relay
 *    may legitimately answer with an older replaceable event, and applying it
 *    would roll the directory back. `maxClock` alone is not enough: two of the
 *    owner's devices can reach the same clock, and then each would reject the
 *    other for ever, so the tie is broken by which snapshot was published
 *    later. A REVOCATION is exempt from both: a revoking producer may not know
 *    the consumer's frontier, and losing a revocation is far worse than
 *    applying one out of order.
 * 3. **Freshness is advisory for reads, never for blocks.** `isFresh` tells an
 *    app its directory may be out of date; `blockedSetOf` is unconditional.
 */
import type { ContactProjectionV2, ContactsState, ProjectedContact } from './types.js';

export function emptyContactsState(): ContactsState {
  return { grantId: null, projection: null, receivedAt: 0, blockedPubkeys: [], revoked: false };
}

function blockedPubkeysOf(contacts: readonly ProjectedContact[]): string[] {
  const out = new Set<string>();
  for (const contact of contacts) {
    if (!contact.blocked) continue;
    for (const identity of contact.identities ?? []) out.add(identity.pubkey);
    for (const linked of contact.linkedPubkeys ?? []) out.add(linked);
  }
  return [...out];
}

export function applyProjection(
  state: ContactsState, projection: ContactProjectionV2, nowSec: number,
): ContactsState {
  if (state.grantId !== null && state.grantId !== projection.grantId) return state;

  if (projection.revoked === true) {
    return {
      grantId: projection.grantId,
      projection: { ...projection, contacts: [] },
      receivedAt: nowSec,
      blockedPubkeys: state.blockedPubkeys,   // sticky through revocation
      revoked: true,
    };
  }

  // C13: newest wins by `(maxClock, publishedAt)`. `maxClock` alone cannot
  // order two of the owner's devices publishing the same grant — they can
  // legitimately reach the same clock — so a tie is broken by which
  // snapshot was published later, and only a strictly older one is refused.
  if (state.projection !== null && !state.revoked) {
    const held = state.projection.frontier;
    const incoming = projection.frontier;
    const older = incoming.maxClock < held.maxClock
      || (incoming.maxClock === held.maxClock && incoming.publishedAt < held.publishedAt);
    if (older) return state;
  }

  return {
    grantId: projection.grantId,
    projection,
    receivedAt: nowSec,
    blockedPubkeys: blockedPubkeysOf(projection.contacts),
    revoked: false,
  };
}

/** True while the held projection is inside its issued staleness window. */
export function isFresh(state: ContactsState, nowSec: number): boolean {
  if (state.projection === null || state.revoked) return false;
  return nowSec <= state.projection.expiresAt;
}

/** Every pubkey the app must filter at ingress and at display time. Unaffected
 *  by expiry or revocation — see rule 1 in the module header. */
export function blockedSetOf(state: ContactsState): Set<string> {
  return new Set(state.blockedPubkeys);
}

/** Contacts an app may show. Blocked contacts are excluded here so a caller
 *  cannot forget; a revoked grant shows nothing at all. */
export function visibleContacts(state: ContactsState): ProjectedContact[] {
  if (state.projection === null || state.revoked) return [];
  return state.projection.contacts.filter((c) => !c.blocked);
}
