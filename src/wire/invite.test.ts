import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { bytesToHex } from '@noble/hashes/utils.js';
import { parseContactInvite, encodeContactInvite, deriveContactMailboxSecret, contactCommitment,
  createContactRequest, createContactAcceptance, createContactReveal, contactVerificationWords,
  contactMessageHash, parseContactExchangeMessage, parseContactCard, CONTACT_REQUEST_TTL } from './invite.js';
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
const card = { name: 'Ada', photo: { key: '8'.repeat(64), server: 'https://blossom.example/', hash: '9'.repeat(64) } };
const reqArgs = { id: '4'.repeat(32), from, to, nonce, reply: { secret: '5'.repeat(64), relays: ['wss://relay.example'] }, now: 1700000000 };
it('carries an optional card on request and acceptance, normalised, and hashes identically without it', () => {
  const plain = createContactRequest(reqArgs);
  const request = createContactRequest({ ...reqArgs, card: { ...card, name: ' ‮Ada\u0000 ', photo: { ...card.photo, server: 'https://Blossom.Example' } } });
  expect(request.card).toEqual(card);
  expect(plain.card).toBeUndefined();
  expect('card' in plain).toBe(false);
  expect(contactMessageHash(request)).toBe(contactMessageHash(plain));
  expect(request.commitment).toBe(plain.commitment);
  expect(parseContactExchangeMessage(JSON.stringify(request))).toEqual(request);
  const acceptance = createContactAcceptance(request, '6'.repeat(64), request.createdAt + 1, { name: 'Grace' });
  const acceptancePlain = createContactAcceptance(plain, '6'.repeat(64), request.createdAt + 1);
  // The requester's card is never copied into the acceptance.
  expect(createContactAcceptance(request, '6'.repeat(64), request.createdAt + 1).card).toBeUndefined();
  expect(acceptance.card).toEqual({ name: 'Grace' });
  expect(contactMessageHash(acceptance)).toBe(contactMessageHash(acceptancePlain));
  expect(acceptance.requestHash).toBe(contactMessageHash(plain));
  const reveal = createContactReveal(request, acceptance, nonce, request.createdAt + 2);
  const plainReveal = createContactReveal(plain, acceptancePlain, nonce, request.createdAt + 2);
  expect(contactVerificationWords(request, acceptance, reveal, from)).toEqual(contactVerificationWords(plain, acceptancePlain, plainReveal, from));
  expect(contactMessageHash(reveal)).toBe(contactMessageHash(plainReveal));
  expect(() => createContactReveal(request, createContactAcceptance(plain, '6'.repeat(64), request.createdAt + 1), nonce, request.createdAt + 2)).not.toThrow();
});
it('never lets a card reach a reveal and never lets a bad card invalidate a message', () => {
  const { request, acceptance, reveal } = exchange();
  expect('card' in parseContactExchangeMessage(JSON.stringify({ ...reveal, card }))!).toBe(false);
  for (const bad of [{ name: 7 }, { photo: { key: 'x' } }, { name: 'Ada', pad: 'x'.repeat(2000) }, 'Ada', 7, null, [], {}]) {
    const parsed = parseContactExchangeMessage(JSON.stringify({ ...request, card: bad }));
    expect(parsed).not.toBeNull();
    expect(contactMessageHash(parsed!)).toBe(contactMessageHash(request));
    expect(parsed).toEqual(request);
    expect(parseContactExchangeMessage(JSON.stringify({ ...acceptance, card: bad }))).toEqual(acceptance);
  }
});
it('parses a card strictly: allowlist, name stripping and limits, photo validity', () => {
  expect(parseContactCard({ name: 'a'.repeat(100) })).toEqual({ name: 'a'.repeat(100) });
  expect(parseContactCard({ name: 'a'.repeat(101) })).toBeNull();
  expect(parseContactCard({ name: '‎‏؜⁦\u0085' })).toBeNull();
  expect(parseContactCard({ name: 'Ada', photo: { ...card.photo, key: 'A'.repeat(64) } })).toEqual({ name: 'Ada' });
  expect(parseContactCard({ photo: { ...card.photo, server: 'http://blossom.example/' } })).toBeNull();
  expect(parseContactCard({ photo: { ...card.photo, server: 'https://u@blossom.example/' } })).toBeNull();
  expect(parseContactCard({ photo: { ...card.photo, server: 'https://blossom.example/#a' } })).toBeNull();
  expect(parseContactCard({ photo: { ...card.photo, server: `https://b.example/${'a'.repeat(500)}` } })).toBeNull();
  expect(parseContactCard({ ...card, extra: 1, photo: { ...card.photo, extra: 1 } })).toEqual(card);
  expect(parseContactCard(parseContactCard(card))).toEqual(card);
  // 1024 bytes of JSON is the ceiling, counted as received.
  const pad = (n: number) => ({ name: 'Ada', pad: 'x'.repeat(n) });
  const slack = 1024 - JSON.stringify(pad(0)).length;
  expect(parseContactCard(pad(slack))).toEqual({ name: 'Ada' });
  expect(parseContactCard(pad(slack + 1))).toBeNull();
  expect(parseContactCard(undefined)).toBeNull();
});
it('throws on an invalid card at create time', () => {
  const request = createContactRequest(reqArgs);
  for (const bad of [{}, { name: '' }, { name: 'a'.repeat(101) }, { name: 'Ada', photo: { ...card.photo, key: 'nope' } },
    { photo: { ...card.photo, server: 'http://blossom.example/' } }, { name: 'Ada', pad: 'x'.repeat(2000) }] as unknown as Array<typeof card>) {
    expect(() => createContactRequest({ ...reqArgs, card: bad })).toThrow('Invalid contact card');
    expect(() => createContactAcceptance(request, '6'.repeat(64), request.createdAt + 1, bad)).toThrow('Invalid contact card');
  }
});
