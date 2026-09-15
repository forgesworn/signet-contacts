/**
 * Pairing v2 — the `signet-grant:` URI a consuming app shows as a QR code.
 *
 * The scheme is shared with the shipped v1 companion rail on purpose, so
 * signet-app's existing QR route extends rather than forks. `v=2` is the FIRST
 * parameter and is mandatory: a parser that reads a v1 URI as v2 would silently
 * grant an app a capability set it never asked for, so an absent or wrong `v`
 * is a hard rejection, not a default.
 *
 * Parameter order is binding — vectors pin the exact string.
 */
import {
  MAX_APP_NAME, MAX_CAPABILITIES, PAIRING_FRESHNESS_SECONDS,
  PAIRING_SCHEME, PAIRING_VERSION, isCapability, normaliseCapabilities,
} from './constants.js';
import type { Capability } from './constants.js';
import type { DirectoryKind, PairingRequestV2, PairingRequestV2Result, PairingUriOptionsV2 } from './types.js';
import { sanitizeWireText } from './ids.js';

const HEX64 = /^[0-9a-f]{64}$/;
const CHALLENGE_HEX = /^[0-9a-f]{16,}$/i;
const DIRECTORIES: readonly DirectoryKind[] = ['owner', 'dependant'];

/** Production relays require TLS; plaintext is reserved for loopback development. */
export function isValidContactsRelayUrl(value: string): boolean {
  return /^wss:\/\//i.test(value) || /^ws:\/\/(localhost|127\.0\.0\.1)([:/]|$)/i.test(value);
}

export function buildPairingUriV2(opts: PairingUriOptionsV2): string {
  if (!HEX64.test(opts.appPubkey)) throw new TypeError('signet-contacts: app pubkey must be lowercase 64-hex');
  if (!isValidContactsRelayUrl(opts.relay)) throw new TypeError('signet-contacts: invalid relay URL');
  if (!Number.isInteger(opts.nowSec) || opts.nowSec < 0) throw new TypeError('signet-contacts: invalid timestamp');
  if (!CHALLENGE_HEX.test(opts.challenge)) throw new TypeError('signet-contacts: invalid challenge');
  const caps = normaliseCapabilities(opts.capabilities.filter(isCapability));
  if (caps.length === 0) throw new TypeError('signet-contacts: at least one capability is required');
  if (!DIRECTORIES.includes(opts.directory)) throw new TypeError('signet-contacts: invalid directory');

  const params = new URLSearchParams();
  params.set('v', String(PAIRING_VERSION));
  params.set('app', opts.appPubkey);
  params.set('name', opts.appName);
  params.set('caps', caps.join(','));
  params.set('dir', opts.directory);
  params.set('relay', opts.relay);
  params.set('t', String(opts.nowSec));
  params.set('challenge', opts.challenge);
  return `${PAIRING_SCHEME}//pair?${params.toString()}`;
}

export function parsePairingRequestV2(
  input: string,
  opts: { nowSec?: number; freshnessSeconds?: number } = {},
): PairingRequestV2Result {
  const warnings: string[] = [];
  let params: URLSearchParams;
  try {
    const qIndex = input.indexOf('?');
    params = new URLSearchParams(qIndex >= 0 ? input.slice(qIndex + 1) : input);
  } catch {
    return { request: null, warnings: ['malformed'] };
  }

  if (params.get('v') !== String(PAIRING_VERSION)) return { request: null, warnings: ['bad-version'] };

  const appPubkey = (params.get('app') ?? '').toLowerCase();
  if (!HEX64.test(appPubkey)) return { request: null, warnings: ['bad-app-pubkey'] };

  const rendezvousRelay = params.get('relay') ?? '';
  if (!isValidContactsRelayUrl(rendezvousRelay)) return { request: null, warnings: ['bad-relay'] };

  const t = Number(params.get('t'));
  if (!Number.isInteger(t) || t < 0) return { request: null, warnings: ['bad-timestamp'] };
  const nowSec = opts.nowSec ?? Math.floor(Date.now() / 1000);
  const freshnessSeconds = opts.freshnessSeconds ?? PAIRING_FRESHNESS_SECONDS;
  if (Math.abs(nowSec - t) > freshnessSeconds) return { request: null, warnings: ['stale-timestamp'] };

  // Validate case-insensitively but preserve verbatim: the ack echoes this
  // challenge byte-for-byte, including uppercase hex from another consumer.
  const challenge = params.get('challenge') ?? '';
  if (!CHALLENGE_HEX.test(challenge)) return { request: null, warnings: ['bad-challenge'] };

  const rawCaps = (params.get('caps') ?? '').split(',').map((c) => c.trim()).filter(Boolean).slice(0, MAX_CAPABILITIES);
  const known = rawCaps.filter((c): c is Capability => isCapability(c));
  if (rawCaps.some((c) => !isCapability(c))) warnings.push('caps-unknown-token');
  if (known.length === 0) {
    warnings.push('caps-empty');
    return { request: null, warnings };
  }
  const capabilities = normaliseCapabilities(known);

  const rawDir = params.get('dir') ?? '';
  let directory: DirectoryKind = 'owner';
  if (DIRECTORIES.includes(rawDir as DirectoryKind)) {
    directory = rawDir as DirectoryKind;
  } else {
    warnings.push('bad-directory');
  }

  const rawName = params.get('name') ?? '';
  const appName = sanitizeWireText(rawName, MAX_APP_NAME);
  if (appName.length === 0) return { request: null, warnings: [...warnings, 'bad-app-name'] };
  if (sanitizeWireText(rawName, MAX_APP_NAME + 1).length > MAX_APP_NAME) warnings.push('name-truncated');

  return {
    request: { v: 2, appPubkey, appName, capabilities, directory, rendezvousRelay, t, challenge },
    warnings,
  };
}
