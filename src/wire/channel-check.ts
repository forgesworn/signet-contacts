/** Unreleased authenticated-channel profile. No mailbox or identity decrypt is
 * required. The transport MUST authenticate `from` before accepting a message.
 * Persist every transition before sending its output, especially acceptance
 * pinning before revealing the requester's nonce. */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { deriveDirectionalPair } from 'spoken-token';

export const CHANNEL_CHECK_TTL = 600;
export const CHANNEL_CHECK_MAX_BYTES = 2048;
export const CHANNEL_CHECK_WORDS_NAMESPACE = 'signet-contacts:channel-check:v1';
const HEX = /^[0-9a-f]{64}$/;
const ID = /^[0-9a-f]{32}$/;
type Base = { v: 1; id: string; context: string; from: string; to: string; createdAt: number };
export type ChannelCheckRequest = Base & { type: 'channel-check-request'; expiresAt: number; commitment: string };
export type ChannelCheckAcceptance = Base & { type: 'channel-check-accept'; requestHash: string; nonce: string };
export type ChannelCheckReveal = Base & { type: 'channel-check-reveal'; requestHash: string; acceptanceHash: string; nonce: string };
export type ChannelCheckMessage = ChannelCheckRequest | ChannelCheckAcceptance | ChannelCheckReveal;
export interface ChannelCheckState {
  role: 'requester' | 'recipient'; request: ChannelCheckRequest; nonce: string;
  acceptance?: ChannelCheckAcceptance; reveal?: ChannelCheckReveal;
  phase: 'requested' | 'accepted' | 'reveal-pending' | 'complete' | 'declined';
}
const hex = (v: unknown): v is string => typeof v === 'string' && HEX.test(v);
const time = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0;
const digest = (domain: string, fields: unknown[]): string => bytesToHex(sha256(utf8ToBytes(JSON.stringify([domain, ...fields]))));
export function parseChannelCheckMessage(raw: string): ChannelCheckMessage | null {
  if (typeof raw !== 'string' || utf8ToBytes(raw).length > CHANNEL_CHECK_MAX_BYTES) return null;
  let v: Record<string, unknown>;
  try { v = JSON.parse(raw); } catch { return null; }
  if (!v || typeof v !== 'object' || Array.isArray(v) || v.v !== 1 || typeof v.id !== 'string' || !ID.test(v.id)
    || !hex(v.context) || !hex(v.from) || !hex(v.to) || v.from === v.to || !time(v.createdAt)) return null;
  const base = { v: 1 as const, id: v.id, context: v.context, from: v.from, to: v.to, createdAt: v.createdAt };
  if (v.type === 'channel-check-request' && time(v.expiresAt) && v.expiresAt > v.createdAt
    && v.expiresAt - v.createdAt <= CHANNEL_CHECK_TTL && hex(v.commitment)) {
    return { ...base, type: v.type, expiresAt: v.expiresAt, commitment: v.commitment };
  }
  if (!hex(v.requestHash) || !hex(v.nonce)) return null;
  if (v.type === 'channel-check-accept') return { ...base, type: v.type, requestHash: v.requestHash, nonce: v.nonce };
  if (v.type === 'channel-check-reveal' && hex(v.acceptanceHash)) {
    return { ...base, type: v.type, requestHash: v.requestHash, acceptanceHash: v.acceptanceHash, nonce: v.nonce };
  }
  return null;
}
export function channelCheckHash(message: ChannelCheckMessage): string {
  const parsed = parseChannelCheckMessage(JSON.stringify(message));
  if (!parsed) throw new Error('Invalid channel check');
  return digest('signet-contacts:channel-message:v1', [parsed]);
}
export function channelCheckCommitment(args: { id: string; context: string; from: string; to: string; nonce: string }): string {
  if (!ID.test(args.id) || !hex(args.context) || !hex(args.from) || !hex(args.to) || args.from === args.to || !hex(args.nonce)) throw new Error('Invalid channel commitment');
  return digest('signet-contacts:channel-commit:v1', [args.id, args.context, args.from, args.to, args.nonce]);
}
export function createChannelCheckRequest(args: { id: string; context: string; from: string; to: string; nonce: string; now: number }): ChannelCheckRequest {
  const parsed = parseChannelCheckMessage(JSON.stringify({ v: 1, type: 'channel-check-request',
    id: args.id, context: args.context, from: args.from, to: args.to, createdAt: args.now,
    expiresAt: args.now + CHANNEL_CHECK_TTL, commitment: channelCheckCommitment(args) }));
  if (!parsed || parsed.type !== 'channel-check-request') throw new Error('Invalid channel check request');
  return parsed;
}
function validRequest(request: ChannelCheckRequest, now: number): ChannelCheckRequest {
  const parsed = parseChannelCheckMessage(JSON.stringify(request));
  if (!parsed || parsed.type !== 'channel-check-request' || !time(now) || now < parsed.createdAt || now >= parsed.expiresAt) throw new Error('Channel check expired or not yet valid');
  return parsed;
}
export function createChannelCheckAcceptance(request: ChannelCheckRequest, nonce: string, now: number): ChannelCheckAcceptance {
  const r = validRequest(request, now);
  if (!hex(nonce)) throw new Error('Invalid channel nonce');
  return { v: 1, type: 'channel-check-accept', id: r.id, context: r.context, from: r.to, to: r.from,
    createdAt: now, requestHash: channelCheckHash(r), nonce };
}
function validAcceptance(request: ChannelCheckRequest, acceptance: ChannelCheckAcceptance): void {
  const a = parseChannelCheckMessage(JSON.stringify(acceptance));
  if (!a || a.type !== 'channel-check-accept' || a.id !== request.id || a.context !== request.context
    || a.from !== request.to || a.to !== request.from || a.requestHash !== channelCheckHash(request)
    || a.createdAt < request.createdAt || a.createdAt >= request.expiresAt) throw new Error('Acceptance does not match channel request');
}
export function createChannelCheckReveal(request: ChannelCheckRequest, acceptance: ChannelCheckAcceptance, nonce: string, now: number): ChannelCheckReveal {
  const r = validRequest(request, now); validAcceptance(r, acceptance);
  if (now < acceptance.createdAt || channelCheckCommitment({ ...r, nonce }) !== r.commitment) throw new Error('Reveal does not match channel commitment');
  return { v: 1, type: 'channel-check-reveal', id: r.id, context: r.context, from: r.from, to: r.to,
    createdAt: now, requestHash: channelCheckHash(r), acceptanceHash: channelCheckHash(acceptance), nonce };
}
export function channelCheckWords(request: ChannelCheckRequest, acceptance: ChannelCheckAcceptance, reveal: ChannelCheckReveal,
  local: string): { youSay: string; theySay: string } {
  const expected = createChannelCheckReveal(request, acceptance, reveal.nonce, reveal.createdAt);
  if (channelCheckHash(expected) !== channelCheckHash(reveal) || (local !== request.from && local !== request.to)) throw new Error('Invalid channel transcript');
  // Reveal timestamps never enter word material: once nonceA is known neither
  // side may grind a different set of words by delaying its reveal.
  const material = hexToBytes(digest('signet-contacts:channel-words-material:v1',
    [channelCheckHash(request), channelCheckHash(acceptance), reveal.nonce]));
  try {
    const roles = [request.from, request.to].sort() as [string, string];
    const pair = deriveDirectionalPair(material, CHANNEL_CHECK_WORDS_NAMESPACE, roles, 0, { format: 'words', count: 3 });
    return { youSay: pair[local]!, theySay: pair[local === request.from ? request.to : request.from]! };
  } finally { material.fill(0); }
}
export function beginChannelCheck(request: ChannelCheckRequest, nonce: string): ChannelCheckState {
  channelCheckHash(request);
  if (channelCheckCommitment({ ...request, nonce }) !== request.commitment) throw new Error('Wrong channel request nonce');
  return { role: 'requester', request, nonce, phase: 'requested' };
}
export function acceptChannelCheck(request: ChannelCheckRequest, nonce: string, now: number): ChannelCheckState {
  return { role: 'recipient', request, nonce, acceptance: createChannelCheckAcceptance(request, nonce, now), phase: 'accepted' };
}
export function receiveChannelCheckAcceptance(state: ChannelCheckState, acceptance: ChannelCheckAcceptance, now: number): ChannelCheckState {
  if (state.role !== 'requester' || state.phase === 'declined') throw new Error('Channel check cannot accept');
  if (state.acceptance) {
    if (channelCheckHash(state.acceptance) !== channelCheckHash(acceptance)) throw new Error('Channel acceptance already pinned');
    return state;
  }
  const reveal = createChannelCheckReveal(state.request, acceptance, state.nonce, now);
  return { ...state, acceptance, reveal, phase: 'reveal-pending' };
}
export function receiveChannelCheckReveal(state: ChannelCheckState, reveal: ChannelCheckReveal, now: number): ChannelCheckState {
  if (state.role !== 'recipient' || !state.acceptance || state.phase === 'declined'
    || !time(now) || now < reveal.createdAt || now >= state.request.expiresAt) throw new Error('Channel check cannot reveal');
  channelCheckWords(state.request, state.acceptance, reveal, state.request.to);
  if (state.reveal) {
    if (channelCheckHash(state.reveal) !== channelCheckHash(reveal)) throw new Error('Channel reveal already pinned');
    return state;
  }
  return { ...state, reveal, phase: 'complete' };
}
export function confirmChannelCheckRevealSent(state: ChannelCheckState): ChannelCheckState {
  if (state.role !== 'requester' || state.phase !== 'reveal-pending' || !state.acceptance || !state.reveal) throw new Error('No channel reveal to confirm');
  channelCheckWords(state.request, state.acceptance, state.reveal, state.request.from);
  return { ...state, phase: 'complete' };
}
