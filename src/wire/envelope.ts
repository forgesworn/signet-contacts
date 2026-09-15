/**
 * Vault envelope v2 — SDK-side open/seal.
 *
 * FORMAT-MIRRORED, byte-for-byte, from signet-app's `src/lib/vault-envelope.ts`
 * (ruling R-4). The app publishes every private-state rail — including the
 * grant's rail-key projection this SDK consumes — as a v2 envelope rather than
 * a bare NIP-44 payload: nostr-tools' NIP-44 v2 implementation rejects
 * plaintext over 65535 bytes, so the bulk of the payload goes through
 * AES-256-GCM under a fresh random 32-byte content key, and only that 32-byte
 * key is NIP-44-wrapped. A consumer that skipped this layer and called
 * `nip44Decrypt` directly on `event.content` would try to NIP-44-decrypt JSON
 * `{v:2,k,iv,ct,b}` and fail on every real projection.
 *
 * WIRE. `content` is the JSON string `{ v: 2, k, iv, ct, b }`: `k` is the
 * NIP-44 ciphertext of the base64 content key (wrapped to the app's own
 * pubkey — the recipient of the grant's projection), `iv` the base64
 * AES-GCM IV, `ct` the base64 AES ciphertext, `b` the bucket the plaintext
 * was padded to.
 *
 * PADDING. The AES plaintext is a 4-byte big-endian length prefix, the UTF-8
 * body, then zero fill to the smallest bucket in `BUCKETS` that fits.
 *
 * NO LEGACY FALLBACK, unlike the app's five older rails: the contacts wire
 * never had a v1 (bare-NIP-44) format, so `openVaultPayload` here requires a
 * well-formed v2 envelope and returns null for anything else — never a bare
 * `nip44Decrypt` attempt on a malformed `content` (that would be a free
 * signer round-trip a hostile relay could buy per event, S5 in the app's
 * module).
 *
 * KEY MATERIAL. The raw content key and the padded body are `fill(0)`ed in a
 * `finally` on both legs, same acceptance the app documents: `b64(rawKey)`
 * still mints an immutable string holding the 256-bit key that cannot itself
 * be zeroized, but the `Uint8Array`s are wiped.
 */

// `webcrypto.CryptoKey` (Node's Web Crypto types live inside `node:crypto`'s
// `webcrypto` namespace, not as a bare global identifier) — a type-only
// import, so it costs nothing at runtime and every consumer's own bundler
// resolution is unaffected.
import type { webcrypto } from 'node:crypto';

export const BUCKETS: readonly number[] = [4096, 8192, 16384, 32768, 65536];
export const TOP_BUCKET: number = BUCKETS[BUCKETS.length - 1]!;
export const LENGTH_PREFIX_BYTES = 4;

/**
 * Hard cap on the `content` string this SDK will even attempt to parse. The
 * top bucket base64-expands to ~88 kB plus the JSON frame; 100_000 mirrors
 * the app's cap and bounds the work a hostile relay can impose.
 */
export const MAX_ENVELOPE_CHARS = 100_000;

/** AES-GCM IV length in bytes (mirrors the app's `aes-crypto.ts` `IV_LENGTH`). */
const IV_LENGTH = 12;

/** The JSON shape of a sealed `content`. */
export interface VaultEnvelope {
  v: 2;
  /** NIP-44 ciphertext of the base64 content key. */
  k: string;
  /** Base64 AES-GCM IV. */
  iv: string;
  /** Base64 AES-GCM ciphertext of the padded body. */
  ct: string;
  /** Padding bucket the plaintext was padded to. */
  b: number;
}

/** What `sealVaultPayload` needs from a signer. */
export interface SealEnvelopeBackend {
  nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string>;
}

/** What `openVaultPayload` needs from a signer. */
export interface OpenEnvelopeBackend {
  nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
}

export interface SealVaultOptions {
  /** Caller-supplied ceiling below the top bucket. */
  maxBucket?: number;
  /**
   * Injectable randomness. Production callers omit this and get real entropy
   * from the platform `crypto`; Task 12's frozen vector, and this module's own
   * zeroisation tests, need a deterministic (or observable) content key and IV.
   * Called once for the 32-byte content key and once for the 12-byte IV.
   */
  random?: (bytes: number) => Uint8Array;
}

/**
 * Length-prefix `plaintext` and zero-pad it to the smallest bucket that fits.
 * Returns null when it does not fit `maxBucket` — the caller chunks or
 * refuses, and never truncates.
 */
export function padToBucket(
  plaintext: string,
  maxBucket: number = TOP_BUCKET,
): Uint8Array<ArrayBuffer> | null {
  const body = new TextEncoder().encode(plaintext);
  const needed = LENGTH_PREFIX_BYTES + body.length;
  const bucket = BUCKETS.find((b) => b >= needed && b <= maxBucket);
  if (bucket === undefined) return null;
  const out = new Uint8Array(bucket);
  new DataView(out.buffer).setUint32(0, body.length, false);
  out.set(body, LENGTH_PREFIX_BYTES);
  return out;
}

/** Reverse `padToBucket`. Returns null for a malformed or truncated buffer. */
export function unpad(padded: Uint8Array): string | null {
  if (padded.length < LENGTH_PREFIX_BYTES) return null;
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  const length = view.getUint32(0, false);
  if (length > padded.length - LENGTH_PREFIX_BYTES) return null;
  return new TextDecoder().decode(padded.subarray(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + length));
}

/**
 * Shape-check a `content` string as a v2 envelope. Returns null for anything
 * else. The size cap is checked BEFORE `JSON.parse` — a hostile relay must
 * not be able to buy a large parse with an oversized `content` string.
 */
export function parseVaultEnvelope(content: string): VaultEnvelope | null {
  if (typeof content !== 'string' || content.length > MAX_ENVELOPE_CHARS) return null;
  let obj: unknown;
  try {
    obj = JSON.parse(content);
  } catch {
    return null;
  }
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) return null;
  const e = obj as Record<string, unknown>;
  if (e.v !== 2) return null;
  if (typeof e.k !== 'string' || typeof e.iv !== 'string' || typeof e.ct !== 'string') return null;
  if (typeof e.b !== 'number' || !BUCKETS.includes(e.b)) return null;
  return { v: 2, k: e.k, iv: e.iv, ct: e.ct, b: e.b };
}

/**
 * Import 32 raw bytes as a non-extractable AES-256-GCM key. Mirrors the app's
 * `aes-crypto.ts` `importAesKeyRaw` byte-for-byte, including the defensive
 * copy (SubtleCrypto needs a plain-`ArrayBuffer`-backed view, not whatever the
 * caller's `raw` happens to be a view over) and its zeroisation.
 */
async function importAesKeyRaw(raw: Uint8Array): Promise<webcrypto.CryptoKey> {
  if (raw.length !== 32) throw new Error('signet-contacts: invalid AES key length');
  const buf = Uint8Array.from(raw);
  try {
    // `await`, not a bare `return`: without it the `finally` would wipe the
    // copy before SubtleCrypto has read it.
    return await crypto.subtle.importKey('raw', buf, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } finally {
    buf.fill(0);
  }
}

// Chunked: `String.fromCharCode(...u)` over a 64 KiB payload would spread tens
// of thousands of arguments and blow the call-stack argument limit.
const B64_CHUNK = 8192;
function b64(u: Uint8Array): string {
  let s = '';
  for (let i = 0; i < u.length; i += B64_CHUNK) {
    s += String.fromCharCode(...u.subarray(i, i + B64_CHUNK));
  }
  return btoa(s);
}
function unb64(s: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

/** Strict lowercase 64-hex, same pattern as `isHex(x, 64)` in `ids.ts` (kept
 *  local, and to this exact literal, so this file's crypto boundary reads no
 *  differently from the app's own `LOWERCASE_HEX_64` guard it mirrors). */
const LOWERCASE_HEX_64 = /^[0-9a-f]{64}$/;

/**
 * Seal `plaintext` into a v2 envelope string, or null when it exceeds the top
 * bucket (or `opts.maxBucket`), or on any failure. The content key is wrapped
 * to `recipientPubkey` via `backend.nip44Encrypt` — for this SDK that is
 * always the APP's own pubkey (an app opens its own projections), but the
 * parameter is explicit rather than read off a connected backend, since the
 * SDK holds no notion of "our own pubkey" independent of the caller's signer.
 *
 * Residuals fix: `recipientPubkey` is checked as strict lowercase 64-hex
 * BEFORE anything else — matching the app's own guard (Task 23,
 * `vault-envelope.ts`'s `activePublicKeyHex` check). Wrapping a content key
 * to `''`, an npub, or mixed-case hex would either throw out of a publish
 * path whose contract is a `false`/`null` return, or silently address the
 * envelope to a pubkey nothing can ever open — neither of which the caller
 * should learn about only after paying for the padding and AES-GCM work.
 */
export async function sealVaultPayload(
  plaintext: string,
  backend: SealEnvelopeBackend,
  recipientPubkey: string,
  opts: SealVaultOptions = {},
): Promise<string | null> {
  if (!LOWERCASE_HEX_64.test(recipientPubkey)) return null;
  const padded = padToBucket(plaintext, opts.maxBucket ?? TOP_BUCKET);
  if (padded === null) return null;
  const random = opts.random ?? ((n: number) => crypto.getRandomValues(new Uint8Array(n)));
  const rawKey = random(32);
  try {
    if (rawKey.length !== 32) return null;
    const key = await importAesKeyRaw(rawKey);
    const iv = random(IV_LENGTH);
    if (iv.length !== IV_LENGTH) return null;
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, padded));
    const wrapped = await backend.nip44Encrypt(recipientPubkey, b64(rawKey));
    const envelope: VaultEnvelope = { v: 2, k: wrapped, iv: b64(iv), ct: b64(ciphertext), b: padded.length };
    return JSON.stringify(envelope);
  } catch {
    return null;
  } finally {
    rawKey.fill(0);
    padded.fill(0);
  }
}

/**
 * Open a v2 envelope. Returns null on ANY failure — tampered ciphertext,
 * wrong key, malformed padding, a backend that threw or returned rubbish, or
 * a `content` that is not a v2 envelope at all. There is deliberately no
 * legacy fallback (see the module header): a consumer of this wire has never
 * seen a v1 payload, so a non-envelope `content` is simply not this grant's
 * projection.
 */
export async function openVaultPayload(
  content: string,
  backend: OpenEnvelopeBackend,
  senderPubkey: string,
): Promise<string | null> {
  const envelope = parseVaultEnvelope(content);
  if (!envelope) return null;

  let rawKey: Uint8Array | null = null;
  // The decrypted body is the whole plaintext in the clear — wiped in the
  // `finally` alongside the key, exactly as the seal leg wipes its own copy.
  let padded: Uint8Array | null = null;
  try {
    const wrappedKeyPlaintext = await backend.nip44Decrypt(senderPubkey, envelope.k);
    // `nip44Decrypt` may be a remote round-trip (a NIP-46 signer); its result
    // is type-checked, not trusted — an object escaping here would read as a
    // non-null "plaintext" downstream.
    if (typeof wrappedKeyPlaintext !== 'string') return null;
    rawKey = unb64(wrappedKeyPlaintext);
    if (rawKey.length !== 32) return null;
    const key = await importAesKeyRaw(rawKey);
    padded = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: unb64(envelope.iv) },
      key,
      unb64(envelope.ct),
    ));
    // The declared bucket must match what actually came out — a mismatch
    // means the envelope was relabelled, which is a rewrite, not a read.
    if (padded.length !== envelope.b) return null;
    return unpad(padded);
  } catch {
    return null;
  } finally {
    rawKey?.fill(0);
    padded?.fill(0);
  }
}
