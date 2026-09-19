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
 * 2. **Monotonic frontier, ordered by `(publishedAt, maxClock)` (R-30,
 *    amending C13).** A projection whose frontier is not strictly newer than
 *    the one already held is ignored — a relay may legitimately answer with
 *    an older replaceable event, and applying it would roll the directory
 *    back; an exact tie is likewise ignored rather than re-applied.
 *
 *    `publishedAt` is compared FIRST, and `maxClock` only breaks a tie,
 *    because the Lamport clock measures how much of the owner's contacts log
 *    a DEVICE has seen, not how recent its snapshot is. A block entered on a
 *    second device that has not yet merged the first device's recent
 *    operations carries a `maxClock` no higher than the one the consumer
 *    already holds, so a clock-first order refused the whole projection —
 *    block included — until some unrelated later change happened to be
 *    published. Safety state must not wait for the contacts rail to
 *    converge, so recency decides; when two devices publish in the same
 *    second, the one that has seen more of the log wins.
 *
 *    This check still runs after a revocation — the held frontier then IS
 *    the revoking projection's frontier, so only a projection strictly newer
 *    than the one that revoked may un-revoke, and a stale relay replay
 *    standing behind the revocation can never resurrect the directory. A
 *    REVOCATION ITSELF is exempt: a revoking producer may not know the
 *    consumer's frontier, and losing a revocation is far worse than applying
 *    one out of order.
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
    // Apply even an out-of-order revocation, but never lower the replay floor.
    // Otherwise an old tombstone followed by an intermediate old live snapshot
    // could resurrect a grant that had already observed a newer frontier.
    const held = state.projection?.frontier;
    const incoming = projection.frontier;
    const frontier = held && (held.publishedAt > incoming.publishedAt
      || (held.publishedAt === incoming.publishedAt && held.maxClock > incoming.maxClock)) ? held : incoming;
    return {
      grantId: projection.grantId,
      projection: { ...projection, frontier: { ...frontier }, contacts: [] },
      receivedAt: nowSec,
      blockedPubkeys: state.blockedPubkeys,   // sticky through revocation
      revoked: true,
    };
  }

  // R-30: newest wins by `(publishedAt, maxClock)` — recency first, the
  // Lamport clock only as the tiebreak for two devices publishing in the
  // same second. An exact tie on both is not newer and is ignored. Runs
  // regardless of `state.revoked` — see rule 2 above.
  if (state.projection !== null) {
    const held = state.projection.frontier;
    const incoming = projection.frontier;
    const notNewer = incoming.publishedAt < held.publishedAt
      || (incoming.publishedAt === held.publishedAt && incoming.maxClock <= held.maxClock);
    if (notNewer) return state;
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
