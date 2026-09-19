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
