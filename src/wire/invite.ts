/** Unreleased contact exchange v1. Review the accompanying vectors before release. */
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { deriveDirectionalPair } from 'spoken-token';

export const CONTACT_REQUEST_TTL = 30 * 24 * 60 * 60;
export const CONTACT_MESSAGE_MAX_BYTES = 8192;
export const CONTACT_IDENTITY_DECRYPTS_PER_UNLOCK = 32;
export const CONTACT_INVITE_PENDING_LIMIT = 128;
export const CONTACT_SENDER_PENDING_LIMIT = 8;
export const CONTACT_AUTO_ACCEPT_SECONDS = 300;
export const CONTACT_WORDS_NAMESPACE = 'signet-contacts:exchange:v1';
const MAILBOX_NAMESPACE = 'signet-contacts:mailbox:v1';
const HEX32 = /^[0-9a-f]{64}$/;
const ID = /^[0-9a-f]{32}$/;
const SCALAR_ORDER = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';

type ObjectValue = Record<string, unknown>;
export interface ContactMailbox { secret: string; relays: string[] }
/** Names, intended recipients and standing/single-use policy remain owner-private. */
export interface ContactInvite extends ContactMailbox {
  v: 1; recipient: string; expiresAt?: number; caption?: string;
}
export interface ContactRequest {
  v: 1; type: 'signet-contact-request'; id: string; from: string; to: string;
  createdAt: number; expiresAt: number; commitment: string; reply: ContactMailbox;
}
export interface ContactAcceptance {
  v: 1; type: 'signet-contact-accept'; id: string; from: string; to: string;
  createdAt: number; requestHash: string; nonce: string;
}
export interface ContactReveal {
  v: 1; type: 'signet-contact-reveal'; id: string; from: string; to: string;
  createdAt: number; requestHash: string; acceptanceHash: string; nonce: string;
}
export type ContactExchangeMessage = ContactRequest | ContactAcceptance | ContactReveal;
const object = (v: unknown): v is ObjectValue => !!v && typeof v === 'object' && !Array.isArray(v);
const hex = (v: unknown): v is string => typeof v === 'string' && HEX32.test(v);
const time = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0;
function relays(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length < 1 || value.length > 8) return null;
  const out: string[] = [];
  for (const raw of value) {
    if (typeof raw !== 'string' || raw.length > 512) return null;
    try {
      const url = new URL(raw);
      if (url.protocol !== 'wss:' || url.username || url.password || url.hash) return null;
      out.push(url.href);
    } catch { return null; }
  }
  return [...new Set(out)];
}
function mailbox(value: unknown): ContactMailbox | null {
  if (!object(value) || !hex(value.secret)) return null;
  const urls = relays(value.relays);
  return urls ? { secret: value.secret, relays: urls } : null;
}
function decode(raw: string): unknown {
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).length > CONTACT_MESSAGE_MAX_BYTES) return null;
  try { return JSON.parse(raw); } catch { return null; }
}
export function parseContactInvite(raw: string, now?: number): ContactInvite | null {
  const value = decode(raw);
  if (!object(value) || value.v !== 1 || !hex(value.recipient)) return null;
  const box = mailbox(value);
  if (!box) return null;
  const invite: ContactInvite = { v: 1, recipient: value.recipient, ...box };
  if (value.expiresAt !== undefined) {
    if (!time(value.expiresAt) || (now !== undefined && value.expiresAt <= now)) return null;
    invite.expiresAt = value.expiresAt;
  }
  if (value.caption !== undefined) {
    if (typeof value.caption !== 'string' || value.caption.length > 200 || /[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/u.test(value.caption)) return null;
    invite.caption = value.caption;
  }
  return invite;
}
export function encodeContactInvite(value: ContactInvite): string {
  const parsed = parseContactInvite(JSON.stringify(value));
  if (!parsed) throw new Error('Invalid contact invite');
  return JSON.stringify(parsed);
}
/** Caller zeroises this key. A vanishingly rare invalid scalar rejects the invite;
 * the issuer must generate a new invite secret, never reduce modulo the order. */
export function deriveContactMailboxSecret(secret: string): Uint8Array {
  if (!hex(secret)) throw new Error('Invalid mailbox secret');
  const input = hexToBytes(secret);
  try {
    const key = hkdf(sha256, input, utf8ToBytes(MAILBOX_NAMESPACE), new Uint8Array(), 32);
    const encoded = bytesToHex(key);
    if (/^0+$/.test(encoded) || encoded >= SCALAR_ORDER) { key.fill(0); throw new Error('Invalid mailbox scalar'); }
    return key;
  } finally { input.fill(0); }
}
function digest(namespace: string, fields: unknown[]): string {
  return bytesToHex(sha256(utf8ToBytes(JSON.stringify([namespace, ...fields]))));
}
export function contactCommitment(args: { id: string; from: string; to: string; nonce: string }): string {
  if (!ID.test(args.id) || !hex(args.from) || !hex(args.to) || args.from === args.to || !hex(args.nonce)) throw new Error('Invalid commitment input');
  return digest('signet-contacts:commit:v1', [args.id, args.from, args.to, args.nonce]);
}
/** Authenticate the seal signer against `from` before using this parsed body. */
export function parseContactExchangeMessage(raw: string): ContactExchangeMessage | null {
  const v = decode(raw);
  if (!object(v) || v.v !== 1 || typeof v.id !== 'string' || !ID.test(v.id)
    || !hex(v.from) || !hex(v.to) || v.from === v.to || !time(v.createdAt)) return null;
  const base = { v: 1 as const, id: v.id, from: v.from, to: v.to, createdAt: v.createdAt };
  if (v.type === 'signet-contact-request') {
    const reply = mailbox(v.reply);
    if (!reply || !hex(v.commitment) || !time(v.expiresAt) || v.expiresAt <= v.createdAt
      || v.expiresAt - v.createdAt > CONTACT_REQUEST_TTL) return null;
    return { ...base, type: v.type, expiresAt: v.expiresAt, commitment: v.commitment, reply };
  }
  if (!hex(v.requestHash) || !hex(v.nonce)) return null;
  if (v.type === 'signet-contact-accept') return { ...base, type: v.type, requestHash: v.requestHash, nonce: v.nonce };
  if (v.type === 'signet-contact-reveal' && hex(v.acceptanceHash)) {
    return { ...base, type: v.type, requestHash: v.requestHash, acceptanceHash: v.acceptanceHash, nonce: v.nonce };
  }
  return null;
}
export function contactMessageHash(message: ContactExchangeMessage): string {
  const parsed = parseContactExchangeMessage(JSON.stringify(message));
  if (!parsed) throw new Error('Invalid contact exchange message');
  // Parser constructs allowlisted fields in a fixed order, independent of input ordering.
  return digest('signet-contacts:message:v1', [parsed]);
}
export function createContactRequest(args: { id: string; from: string; to: string; nonce: string;
  reply: ContactMailbox; now: number; expiresAt?: number }): ContactRequest {
  const value = parseContactExchangeMessage(JSON.stringify({ v: 1, type: 'signet-contact-request',
    id: args.id, from: args.from, to: args.to, createdAt: args.now,
    expiresAt: args.expiresAt ?? args.now + CONTACT_REQUEST_TTL, reply: args.reply,
    commitment: contactCommitment(args) }));
  if (!value || value.type !== 'signet-contact-request') throw new Error('Invalid contact request');
  return value;
}
function validRequest(request: ContactRequest, now: number): ContactRequest {
  const parsed = parseContactExchangeMessage(JSON.stringify(request));
  if (!parsed || parsed.type !== 'signet-contact-request' || !time(now)
    || now < parsed.createdAt || now >= parsed.expiresAt) throw new Error('Contact request expired or not yet valid');
  return parsed;
}
export function createContactAcceptance(request: ContactRequest, nonce: string, now: number): ContactAcceptance {
  const parsed = validRequest(request, now);
  if (!hex(nonce)) throw new Error('Invalid acceptance nonce');
  return { v: 1, type: 'signet-contact-accept', id: parsed.id, from: parsed.to, to: parsed.from,
    createdAt: now, requestHash: contactMessageHash(parsed), nonce };
}
function validAcceptance(request: ContactRequest, acceptance: ContactAcceptance): void {
  const parsed = parseContactExchangeMessage(JSON.stringify(acceptance));
  if (!parsed || parsed.type !== 'signet-contact-accept' || parsed.id !== request.id
    || parsed.from !== request.to || parsed.to !== request.from || parsed.requestHash !== contactMessageHash(request)
    || parsed.createdAt < request.createdAt || parsed.createdAt >= request.expiresAt) throw new Error('Acceptance does not match request');
}
export function createContactReveal(request: ContactRequest, acceptance: ContactAcceptance,
  nonce: string, now: number): ContactReveal {
  validRequest(request, now); validAcceptance(request, acceptance);
  if (now < acceptance.createdAt || contactCommitment({ ...request, nonce }) !== request.commitment) throw new Error('Reveal does not match commitment');
  return { v: 1, type: 'signet-contact-reveal', id: request.id, from: request.from, to: request.to,
    createdAt: now, requestHash: contactMessageHash(request), acceptanceHash: contactMessageHash(acceptance), nonce };
}
/** Words only after all signed messages have been authenticated by the caller. */
export function contactVerificationWords(request: ContactRequest, acceptance: ContactAcceptance,
  reveal: ContactReveal, localPubkey: string): { youSay: string; theySay: string } {
  const r = validRequest(request, reveal.createdAt);
  validAcceptance(r, acceptance);
  const expected = createContactReveal(r, acceptance, reveal.nonce, reveal.createdAt);
  if (contactMessageHash(expected) !== contactMessageHash(reveal)) throw new Error('Invalid reveal transcript');
  const roles = [r.from, r.to].sort() as [string, string];
  if (!roles.includes(localPubkey)) throw new Error('Identity is not part of this exchange');
  const material = hexToBytes(digest('signet-contacts:words-material:v1',
    [contactMessageHash(r), contactMessageHash(acceptance), reveal.nonce]));
  try {
    const pair = deriveDirectionalPair(material, CONTACT_WORDS_NAMESPACE, roles, 0, { format: 'words', count: 3 });
    const other = localPubkey === roles[0] ? roles[1] : roles[0];
    return { youSay: pair[localPubkey]!, theySay: pair[other]! };
  } finally { material.fill(0); }
}
