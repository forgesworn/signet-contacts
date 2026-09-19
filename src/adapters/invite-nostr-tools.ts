/** Two recipient layers: the mailbox holder sees no identity-signed seal until
 * the intended identity decrypts it. A conventional NIP-59 mailbox wrap would
 * expose the sender seal's pubkey to everyone holding a standing invite. */
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { nip44 } from 'nostr-tools';
import { deriveContactMailboxSecret, parseContactExchangeMessage, CONTACT_MESSAGE_MAX_BYTES } from '../wire/invite.js';
import type { ContactExchangeMessage } from '../wire/invite.js';
import type { SignedNostrEvent, UnsignedNostrEvent } from '../wire/types.js';
export interface ContactIdentitySigner {
  publicKey: string;
  signEvent(event: UnsignedNostrEvent): Promise<SignedNostrEvent>;
  decrypt(senderPubkey: string, ciphertext: string): Promise<string>;
}
export interface SealedContactPacket { v: 1; key: string; ciphertext: string }
const MAX_PACKET = 20000, MAX_WRAP = 32000;
const hex = /^[0-9a-f]{64}$/;
function randomTime(now: number): number {
  const value = new Uint32Array(1); globalThis.crypto.getRandomValues(value);
  return Math.max(0, now - value[0]! % 172800);
}
function encrypt(key: Uint8Array, pubkey: string, plaintext: string): string {
  const shared = nip44.v2.utils.getConversationKey(key, pubkey);
  try { return nip44.v2.encrypt(plaintext, shared); } finally { shared.fill(0); }
}
function decrypt(key: Uint8Array, pubkey: string, ciphertext: string): string {
  const shared = nip44.v2.utils.getConversationKey(key, pubkey);
  try { return nip44.v2.decrypt(ciphertext, shared); } finally { shared.fill(0); }
}
function packet(raw: unknown): SealedContactPacket | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const p = raw as Record<string, unknown>;
  return p.v === 1 && typeof p.key === 'string' && hex.test(p.key)
    && typeof p.ciphertext === 'string' && p.ciphertext.length <= MAX_PACKET
    ? { v: 1, key: p.key, ciphertext: p.ciphertext } : null;
}
export async function wrapContactExchange(message: ContactExchangeMessage, mailboxSecret: string,
  signer: Pick<ContactIdentitySigner, 'publicKey' | 'signEvent'>): Promise<SignedNostrEvent> {
  const parsed = parseContactExchangeMessage(JSON.stringify(message));
  if (!parsed || parsed.from !== signer.publicKey) throw new Error('Contact exchange signer mismatch');
  const seal = await signer.signEvent({ kind: 13, pubkey: signer.publicKey, tags: [],
    created_at: randomTime(parsed.createdAt), content: JSON.stringify(parsed) });
  if (!verifyEvent(seal) || seal.pubkey !== signer.publicKey || seal.kind !== 13
    || seal.tags.length !== 0 || seal.content !== JSON.stringify(parsed)) throw new Error('Invalid identity seal');
  const innerKey = generateSecretKey(), outerKey = generateSecretKey();
  const mailboxKey = deriveContactMailboxSecret(mailboxSecret);
  try {
    const sealed: SealedContactPacket = { v: 1, key: getPublicKey(innerKey),
      ciphertext: encrypt(innerKey, parsed.to, JSON.stringify(seal)) };
    const mailboxPubkey = getPublicKey(mailboxKey);
    return finalizeEvent({ kind: 1059, created_at: randomTime(parsed.createdAt), tags: [['p', mailboxPubkey]],
      content: encrypt(outerKey, mailboxPubkey, JSON.stringify(sealed)) }, outerKey);
  } finally { innerKey.fill(0); outerKey.fill(0); mailboxKey.fill(0); }
}
/** Cheap local-only arrival check; never touches the recipient identity signer. */
export function openContactMailboxWrap(event: SignedNostrEvent, mailboxSecret: string): SealedContactPacket | null {
  let key: Uint8Array | undefined;
  try {
    if (event.kind !== 1059 || typeof event.content !== 'string' || event.content.length > MAX_WRAP || !verifyEvent(event)) return null;
    key = deriveContactMailboxSecret(mailboxSecret);
    const pubkey = getPublicKey(key);
    if (event.tags.length !== 1 || event.tags[0]?.length !== 2 || event.tags[0][0] !== 'p' || event.tags[0][1] !== pubkey) return null;
    const raw = decrypt(key, event.pubkey, event.content);
    if (raw.length > MAX_PACKET) return null;
    return packet(JSON.parse(raw));
  } catch { return null; }
  finally { key?.fill(0); }
}
/** Call only when the user opens the inbox, after decrementing an unlock budget. */
export async function openContactIdentityPacket(sealed: SealedContactPacket,
  signer: Pick<ContactIdentitySigner, 'publicKey' | 'decrypt'>): Promise<ContactExchangeMessage | null> {
  const p = packet(sealed);
  if (!p) return null;
  // Signer refusal/offline is retryable, not a malformed packet to discard.
  const raw = await signer.decrypt(p.key, p.ciphertext);
  try {
    if (raw.length > CONTACT_MESSAGE_MAX_BYTES + 2048) return null;
    const seal = JSON.parse(raw) as SignedNostrEvent;
    if (seal.kind !== 13 || seal.tags.length !== 0 || !verifyEvent(seal)) return null;
    const message = parseContactExchangeMessage(seal.content);
    if (!message || message.from !== seal.pubkey || message.to !== signer.publicKey) return null;
    return message;
  } catch { return null; }
}
