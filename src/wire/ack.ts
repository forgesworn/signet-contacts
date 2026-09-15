/**
 * Pairing ack v2 — the kind-21237 reply Signet publishes after the owner
 * approves a grant. The plaintext here is what gets NIP-44-encrypted to the
 * app pubkey; the event carrying it is signed by a throwaway ephemeral key, so
 * the app learns the grant's rail pubkey and nothing about the owner's keys.
 *
 * `grantedCapabilities` may be NARROWER than the request: the owner is free to
 * tick fewer boxes. A consumer must read this field rather than assuming it got
 * what it asked for, which is why the parser drops unknown tokens instead of
 * passing them through — an app that trusted an unknown token would build a UI
 * around data that will never arrive.
 */
import { ACK_KIND, clampStaleness, isCapability, normaliseCapabilities } from './constants.js';
import type { Capability } from './constants.js';
import type { PairingAckV2, PairingV2, UnsignedNostrEvent } from './types.js';
import { isHex } from './ids.js';
import { isValidContactsRelayUrl } from './pairing.js';

export function buildPairingAckV2(ack: PairingAckV2): string {
  return JSON.stringify({
    v: 2,
    grantId: ack.grantId,
    railPubkey: ack.railPubkey,
    projectionTag: ack.projectionTag,
    proposalTag: ack.proposalTag,
    relay: ack.relay,
    grantedCapabilities: ack.grantedCapabilities,
    maxStalenessSeconds: ack.maxStalenessSeconds,
    challenge: ack.challenge,
  });
}

export function parsePairingAckV2(plaintext: string, expectedChallenge: string): PairingAckV2 | null {
  let raw: unknown;
  try {
    raw = JSON.parse(plaintext);
  } catch {
    return null;
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;

  if (o.v !== 2) return null;
  // Byte-for-byte: the challenge is the app's own anti-replay nonce and a
  // case-folded comparison would accept an ack minted for a different request.
  if (typeof o.challenge !== 'string' || o.challenge !== expectedChallenge) return null;
  if (!isHex(o.grantId, 32)) return null;
  if (!isHex(o.railPubkey, 64)) return null;
  if (!isHex(o.projectionTag, 32)) return null;
  if (!isHex(o.proposalTag, 32)) return null;
  if (typeof o.relay !== 'string' || !isValidContactsRelayUrl(o.relay)) return null;
  if (!Array.isArray(o.grantedCapabilities)) return null;

  const granted = normaliseCapabilities(
    o.grantedCapabilities.filter((c): c is Capability => isCapability(c)),
  );
  if (granted.length === 0) return null;

  return {
    v: 2,
    grantId: o.grantId,
    railPubkey: o.railPubkey,
    projectionTag: o.projectionTag,
    proposalTag: o.proposalTag,
    relay: o.relay,
    grantedCapabilities: granted,
    maxStalenessSeconds: clampStaleness(typeof o.maxStalenessSeconds === 'number' ? o.maxStalenessSeconds : undefined),
    challenge: o.challenge,
  };
}

/** The ephemeral kind-21237 carrier. `ephemeralPubkey` is a throwaway key —
 *  never the owner's persona, never the rail. */
export function ackEventTemplate(
  ephemeralPubkey: string, appPubkey: string, createdAt: number, content: string,
): UnsignedNostrEvent {
  return { kind: ACK_KIND, pubkey: ephemeralPubkey, created_at: createdAt, tags: [['p', appPubkey]], content };
}

/** Reduce a validated ack to the shape a consumer persists. */
export function pairingFromAck(ack: PairingAckV2, pairedAt: number): PairingV2 {
  const { v: _v, challenge: _challenge, ...rest } = ack;
  return { ...rest, pairedAt };
}
