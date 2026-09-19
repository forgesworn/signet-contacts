import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { bytesToHex } from '@noble/hashes/utils.js';
import { parseContactInvite, encodeContactInvite, deriveContactMailboxSecret, contactCommitment,
  createContactRequest, createContactAcceptance, createContactReveal, contactVerificationWords,
  contactMessageHash, parseContactExchangeMessage, CONTACT_REQUEST_TTL } from './invite.js';
const from = '1'.repeat(64), to = '2'.repeat(64), nonce = '3'.repeat(64);
function exchange() {
  const request = createContactRequest({ id: '4'.repeat(32), from, to, nonce,
    reply: { secret: '5'.repeat(64), relays: ['wss://relay.example'] }, now: 1700000000 });
  const acceptance = createContactAcceptance(request, '6'.repeat(64), request.createdAt + 1);
  const reveal = createContactReveal(request, acceptance, nonce, request.createdAt + 2);
  return { request, acceptance, reveal };
}
it('round trips an allowlisted invite and rejects unsafe routing, expired and oversized inputs', () => {
  const invite = { v: 1 as const, recipient: to, secret: '7'.repeat(64), relays: ['wss://relay.example'], caption: 'Conference' };
  const encoded = encodeContactInvite({ ...invite, name: 'Private invite name' } as typeof invite);
  expect(encoded).not.toContain('Private invite');
  expect(parseContactInvite(encoded)).toMatchObject({ ...invite, relays: ['wss://relay.example/'] });
  for (const relay of ['https://relay.example', 'wss://user:secret@relay.example', 'wss://relay.example/#secret', 'ws://relay.example']) {
    expect(parseContactInvite(JSON.stringify({ ...invite, relays: [relay] }))).toBeNull();
  }
  expect(parseContactInvite(JSON.stringify({ ...invite, expiresAt: 100 }), 100)).toBeNull();
  expect(parseContactInvite('x'.repeat(8193))).toBeNull();
});
it('pins mailbox/commitment/transcript and directional word vectors', () => {
  const vector = JSON.parse(readFileSync(new URL('../../vectors/contact-invite-v1.json', import.meta.url), 'utf8'));
  const { request, acceptance, reveal } = exchange();
  const secret = deriveContactMailboxSecret(vector.inviteSecret);
  try { expect(bytesToHex(secret)).toBe(vector.mailboxPrivateKey); } finally { secret.fill(0); }
  expect(request.commitment).toBe(vector.commitment);
  expect(contactMessageHash(request)).toBe(vector.requestHash);
  expect(contactMessageHash(acceptance)).toBe(vector.acceptanceHash);
  expect(contactVerificationWords(request, acceptance, reveal, from)).toEqual(vector.requesterWords);
  expect(contactVerificationWords(request, acceptance, reveal, to)).toEqual({ youSay: vector.requesterWords.theySay, theySay: vector.requesterWords.youSay });
});
it('binds both keys and both random contributions; rejects substituted accept/reveal and expiry', () => {
  const { request, acceptance, reveal } = exchange();
  expect(contactCommitment({ ...request, nonce, to: '8'.repeat(64) })).not.toBe(request.commitment);
  expect(() => createContactReveal(request, acceptance, '9'.repeat(64), reveal.createdAt)).toThrow();
  expect(() => contactVerificationWords(request, { ...acceptance, nonce: '9'.repeat(64) }, reveal, from)).toThrow();
  expect(() => contactVerificationWords(request, acceptance, { ...reveal, from: to }, from)).toThrow();
  expect(() => createContactAcceptance(request, nonce, request.expiresAt)).toThrow();
  expect(parseContactExchangeMessage(JSON.stringify({ ...request, expiresAt: request.createdAt + CONTACT_REQUEST_TTL + 1 }))).toBeNull();
  expect(() => contactVerificationWords(request, acceptance, reveal, '8'.repeat(64))).toThrow();
});
it('uses canonical field order and gives no word-grinding freedom in reveal timestamps', () => {
  const { request, acceptance, reveal } = exchange();
  const reordered = Object.fromEntries(Object.entries(request).reverse());
  expect(contactMessageHash(reordered as typeof request)).toBe(contactMessageHash(request));
  const delayed = createContactReveal(request, acceptance, nonce, reveal.createdAt + 500);
  expect(contactVerificationWords(request, acceptance, delayed, from)).toEqual(contactVerificationWords(request, acceptance, reveal, from));
});
