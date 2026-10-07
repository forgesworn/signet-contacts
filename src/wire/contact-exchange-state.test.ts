import { expect, it } from 'vitest';
import { createContactRequest, createContactAcceptance, createContactReveal } from './invite.js';
import { beginContactExchange, acceptContactExchange, receiveContactAcceptance, receiveContactReveal,
  confirmContactRevealSent, ContactIdentityDecryptBudget } from './contact-exchange-state.js';
const nonce = '3'.repeat(64), now = 1700000000;
const request = createContactRequest({ id: '4'.repeat(32), from: '1'.repeat(64), to: '2'.repeat(64), nonce,
  reply: { secret: '5'.repeat(64), relays: ['wss://relay.example'] }, now });
it('pins acceptance before revealing and is idempotent on retransmission', () => {
  const sender = beginContactExchange(request, nonce);
  const receiver = acceptContactExchange(request, '6'.repeat(64), now + 1);
  const revealed = receiveContactAcceptance(sender, receiver.acceptance!, now + 2);
  expect(revealed.phase).toBe('reveal-pending');
  expect(receiveContactAcceptance(revealed, receiver.acceptance!, now + 3)).toBe(revealed);
  const replacement = createContactAcceptance(request, '7'.repeat(64), now + 3);
  expect(() => receiveContactAcceptance(revealed, replacement, now + 4)).toThrow('pinned');
  const completed = receiveContactReveal(receiver, revealed.reveal!, now + 3);
  expect(completed.phase).toBe('complete');
  expect(confirmContactRevealSent(revealed).phase).toBe('complete');
  expect(receiveContactReveal(completed, revealed.reveal!, now + 4)).toBe(completed);
  expect(() => receiveContactReveal(receiver, createContactReveal(request, receiver.acceptance!, nonce, now + 2), request.expiresAt)).toThrow();
});
it('caps identity decrypt attempts across invites for the whole unlock', () => {
  const budget = new ContactIdentityDecryptBudget();
  for (let n = 0; n < 32; n++) expect(budget.consume()).toBe(true);
  expect(budget.remaining).toBe(0);
  expect(budget.consume()).toBe(false);
});
it('keeps each side\'s card on its own message through the state machine', () => {
  const card = { name: 'Ada', photo: { key: '8'.repeat(64), server: 'https://blossom.example/', hash: '9'.repeat(64) } };
  const carded = createContactRequest({ id: '4'.repeat(32), from: '1'.repeat(64), to: '2'.repeat(64), nonce,
    reply: { secret: '5'.repeat(64), relays: ['wss://relay.example'] }, now, card });
  const sender = beginContactExchange(carded, nonce);
  expect(sender.request.card).toEqual(card);
  const receiver = acceptContactExchange(carded, '6'.repeat(64), now + 1, { name: 'Grace' });
  expect(receiver.request.card).toEqual(card);
  expect(receiver.acceptance?.card).toEqual({ name: 'Grace' });
  const revealed = receiveContactAcceptance(sender, receiver.acceptance!, now + 2);
  expect(revealed.acceptance?.card).toEqual({ name: 'Grace' });
  expect(revealed.reveal && 'card' in revealed.reveal).toBe(false);
  // Accepting with no card of your own does not echo the requester's.
  expect(acceptContactExchange(carded, '6'.repeat(64), now + 1).acceptance?.card).toBeUndefined();
  // A repeat of the pinned acceptance with a different card is still the same acceptance: the first is kept.
  const reCarded = { ...receiver.acceptance!, card: { name: 'Mallory' } };
  expect(receiveContactAcceptance(revealed, reCarded, now + 3).acceptance?.card).toEqual({ name: 'Grace' });
  expect(receiveContactReveal(receiver, revealed.reveal!, now + 3).phase).toBe('complete');
});
