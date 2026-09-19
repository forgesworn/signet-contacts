import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { CHANNEL_CHECK_TTL, createChannelCheckRequest, createChannelCheckAcceptance, createChannelCheckReveal,
  channelCheckHash, channelCheckCommitment, channelCheckWords, parseChannelCheckMessage,
  beginChannelCheck, acceptChannelCheck, receiveChannelCheckAcceptance, receiveChannelCheckReveal,
  confirmChannelCheckRevealSent } from './channel-check.js';
const args = { id: '1'.repeat(32), context: '2'.repeat(64), from: '3'.repeat(64), to: '4'.repeat(64), nonce: '5'.repeat(64), now: 1800000000 };
function exchange() {
  const request = createChannelCheckRequest(args);
  const acceptance = createChannelCheckAcceptance(request, '6'.repeat(64), args.now + 1);
  const reveal = createChannelCheckReveal(request, acceptance, args.nonce, args.now + 2);
  return { request, acceptance, reveal };
}
it('pins the separate channel profile and three-word directional vectors', () => {
  const vector = JSON.parse(readFileSync(new URL('../../vectors/channel-check-v1.json', import.meta.url), 'utf8'));
  const { request, acceptance, reveal } = exchange();
  expect({ request, acceptance, reveal, requestHash: channelCheckHash(request), acceptanceHash: channelCheckHash(acceptance),
    requesterWords: channelCheckWords(request, acceptance, reveal, args.from) }).toEqual(vector);
  const words = channelCheckWords(request, acceptance, reveal, args.from);
  expect(words.youSay.split(' ')).toHaveLength(3);
  expect(channelCheckWords(request, acceptance, reveal, args.to)).toEqual({ youSay: words.theySay, theySay: words.youSay });
});
it('binds the channel context, both participants, both nonces and every transcript message', () => {
  const { request, acceptance, reveal } = exchange();
  for (const patch of [{ context: '7'.repeat(64) }, { to: '7'.repeat(64) }, { from: '7'.repeat(64) }, { nonce: '7'.repeat(64) }]) {
    expect(channelCheckCommitment({ ...args, ...patch })).not.toBe(request.commitment);
  }
  for (const altered of [{ ...acceptance, context: '7'.repeat(64) }, { ...acceptance, requestHash: '7'.repeat(64) },
    { ...acceptance, from: args.from }, { ...acceptance, nonce: '7'.repeat(64) }]) {
    expect(() => channelCheckWords(request, altered, reveal, args.from)).toThrow();
  }
  expect(() => channelCheckWords(request, acceptance, { ...reveal, nonce: '7'.repeat(64) }, args.from)).toThrow();
  expect(() => channelCheckWords(request, acceptance, reveal, '7'.repeat(64))).toThrow();
});
it('pins the first acceptance before revealing, rejects substitution after restart and completes both sides', () => {
  const { request, acceptance, reveal } = exchange();
  const initial = beginChannelCheck(request, args.nonce);
  const pinned = receiveChannelCheckAcceptance(initial, acceptance, reveal.createdAt);
  const restored = JSON.parse(JSON.stringify(pinned));
  expect(receiveChannelCheckAcceptance(restored, acceptance, reveal.createdAt + 1)).toEqual(pinned);
  expect(() => receiveChannelCheckAcceptance(restored, { ...acceptance, nonce: '7'.repeat(64) }, reveal.createdAt + 1)).toThrow('pinned');
  expect(confirmChannelCheckRevealSent(restored).phase).toBe('complete');
  const recipient = acceptChannelCheck(request, acceptance.nonce, acceptance.createdAt);
  const complete = receiveChannelCheckReveal(recipient, reveal, reveal.createdAt);
  expect(complete.phase).toBe('complete');
  expect(receiveChannelCheckReveal(complete, reveal, reveal.createdAt)).toEqual(complete);
  expect(() => receiveChannelCheckReveal(complete, { ...reveal, createdAt: reveal.createdAt + 1 }, reveal.createdAt + 1)).toThrow('pinned');
  expect(() => receiveChannelCheckAcceptance({ ...initial, phase: 'declined' }, acceptance, reveal.createdAt)).toThrow();
});
it('bounds input, lifetime and clocks while retaining already-completed words after expiry', () => {
  const { request, acceptance, reveal } = exchange();
  for (const raw of ['null', '[]', 'x'.repeat(2049), JSON.stringify({ ...request, expiresAt: request.createdAt + CHANNEL_CHECK_TTL + 1 }),
    JSON.stringify({ ...request, context: '' }), JSON.stringify({ ...request, from: request.to })]) expect(parseChannelCheckMessage(raw)).toBeNull();
  expect(() => createChannelCheckAcceptance(request, acceptance.nonce, request.expiresAt)).toThrow();
  expect(() => createChannelCheckReveal(request, acceptance, args.nonce, args.now)).toThrow();
  expect(() => receiveChannelCheckReveal(acceptChannelCheck(request, acceptance.nonce, acceptance.createdAt), reveal, request.expiresAt)).toThrow();
  expect(channelCheckWords(request, acceptance, reveal, args.from).youSay).toBeTruthy();
});
it('canonicalises field order and excludes reveal timestamps from the words', () => {
  const { request, acceptance, reveal } = exchange();
  expect(channelCheckHash(Object.fromEntries(Object.entries(request).reverse()) as typeof request)).toBe(channelCheckHash(request));
  expect(parseChannelCheckMessage(JSON.stringify({ ...request, reply: { secret: 'secret' } }))).toEqual(request);
  const delayed = createChannelCheckReveal(request, acceptance, args.nonce, reveal.createdAt + 100);
  expect(channelCheckWords(request, acceptance, delayed, args.from)).toEqual(channelCheckWords(request, acceptance, reveal, args.from));
});
