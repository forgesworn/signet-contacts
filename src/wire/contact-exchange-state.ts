import { CONTACT_IDENTITY_DECRYPTS_PER_UNLOCK, contactCommitment, contactMessageHash,
  createContactAcceptance, createContactReveal, contactVerificationWords } from './invite.js';
import type { ContactRequest, ContactAcceptance, ContactReveal } from './invite.js';

/** Owner-private state. Persist before emitting the corresponding message. */
export interface ContactExchangeState {
  role: 'requester' | 'recipient';
  request: ContactRequest;
  nonce: string;
  acceptance?: ContactAcceptance;
  reveal?: ContactReveal;
  phase: 'requested' | 'accepted' | 'reveal-pending' | 'complete' | 'declined';
}
export function beginContactExchange(request: ContactRequest, nonce: string): ContactExchangeState {
  if (contactCommitment({ ...request, nonce }) !== request.commitment) throw new Error('Wrong request nonce');
  contactMessageHash(request);
  return { role: 'requester', request, nonce, phase: 'requested' };
}
export function acceptContactExchange(request: ContactRequest, nonce: string, now: number): ContactExchangeState {
  return { role: 'recipient', request, nonce, acceptance: createContactAcceptance(request, nonce, now), phase: 'accepted' };
}
/** The first acceptance is immutable. Otherwise an attacker could change nonceB
 * after learning nonceA and grind new words through repeated acceptances. */
export function receiveContactAcceptance(state: ContactExchangeState, acceptance: ContactAcceptance,
  now: number): ContactExchangeState {
  if (state.role !== 'requester' || state.phase === 'declined') throw new Error('Exchange cannot accept this message');
  if (state.acceptance) {
    if (contactMessageHash(state.acceptance) !== contactMessageHash(acceptance)) throw new Error('Acceptance already pinned');
    return state;
  }
  const reveal = createContactReveal(state.request, acceptance, state.nonce, now);
  return { ...state, acceptance, reveal, phase: 'reveal-pending' };
}
export function receiveContactReveal(state: ContactExchangeState, reveal: ContactReveal, now: number): ContactExchangeState {
  if (state.role !== 'recipient' || !state.acceptance || state.phase === 'declined'
    || !Number.isSafeInteger(now) || now < reveal.createdAt || now >= state.request.expiresAt) throw new Error('Exchange cannot accept this reveal');
  contactVerificationWords(state.request, state.acceptance, reveal, state.request.to);
  if (state.reveal) {
    if (contactMessageHash(state.reveal) !== contactMessageHash(reveal)) throw new Error('Reveal already pinned');
    return state;
  }
  return { ...state, reveal, phase: 'complete' };
}
export function confirmContactRevealSent(state: ContactExchangeState): ContactExchangeState {
  if (state.role !== 'requester' || state.phase !== 'reveal-pending' || !state.acceptance || !state.reveal) throw new Error('No reveal to confirm');
  contactVerificationWords(state.request, state.acceptance, state.reveal, state.request.from);
  return { ...state, phase: 'complete' };
}
/** Each attempted identity decrypt consumes budget, including malformed packets.
 * Keep one instance for the whole unlock, not one instance per invite or screen. */
export class ContactIdentityDecryptBudget {
  private spent = 0;
  private attempted = new Set<string>();
  get remaining(): number { return CONTACT_IDENTITY_DECRYPTS_PER_UNLOCK - this.spent; }
  consume(packetId?: string): boolean {
    if (this.remaining <= 0 || (packetId !== undefined && this.attempted.has(packetId))) return false;
    if (packetId !== undefined) this.attempted.add(packetId);
    this.spent++;
    return true;
  }
}
