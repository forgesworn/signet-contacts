import { expect, it, vi } from 'vitest';
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure';
import { nip44 } from 'nostr-tools';
import { hexToBytes } from '@noble/hashes/utils.js';
import { createContactRequest } from '../wire/invite.js';
import { wrapContactExchange, openContactMailboxWrap, openContactIdentityPacket } from './invite-nostr-tools.js';
const a = hexToBytes('01'.repeat(32)), b = hexToBytes('02'.repeat(32)), c = hexToBytes('03'.repeat(32));
function signer(key: Uint8Array) {
  return { publicKey: getPublicKey(key), signEvent: vi.fn(async (event: Parameters<typeof finalizeEvent>[0]) => finalizeEvent(event, key)),
    decrypt: vi.fn(async (pubkey: string, ciphertext: string) => {
      const shared = nip44.v2.utils.getConversationKey(key, pubkey);
      try { return nip44.v2.decrypt(ciphertext, shared); } finally { shared.fill(0); }
    }) };
}
it('hides both identity keys from the relay and sender identity from another invite holder', async () => {
  const sender = signer(a), receiver = signer(b), stranger = signer(c), secret = '04'.repeat(32);
  const request = createContactRequest({ id: '05'.repeat(16), from: sender.publicKey, to: receiver.publicKey,
    nonce: '06'.repeat(32), reply: { secret: '07'.repeat(32), relays: ['wss://relay.example'] }, now: 1700000000 });
  const wrap = await wrapContactExchange(request, secret, sender);
  expect(sender.signEvent).toHaveBeenCalledTimes(1);
  const publicRouting = JSON.stringify({ pubkey: wrap.pubkey, tags: wrap.tags });
  expect(publicRouting).not.toContain(sender.publicKey);
  expect(publicRouting).not.toContain(receiver.publicKey);
  const opaque = openContactMailboxWrap(wrap, secret);
  expect(opaque).not.toBeNull();
  expect(JSON.stringify(opaque)).not.toContain(sender.publicKey);
  expect(receiver.decrypt).not.toHaveBeenCalled();
  await expect(openContactIdentityPacket(opaque!, stranger)).rejects.toThrow();
  expect(await openContactIdentityPacket(opaque!, receiver)).toEqual(request);
  expect(receiver.decrypt).toHaveBeenCalledTimes(1);
  expect(openContactMailboxWrap(wrap, '08'.repeat(32))).toBeNull();
  expect(openContactMailboxWrap({ ...wrap, content: wrap.content + 'x' }, secret)).toBeNull();
});
it('rejects malformed packets without asking the identity to decrypt', async () => {
  const receiver = signer(b);
  expect(await openContactIdentityPacket({ v: 1, key: 'invalid', ciphertext: 'x' }, receiver)).toBeNull();
  expect(receiver.decrypt).not.toHaveBeenCalled();
});
