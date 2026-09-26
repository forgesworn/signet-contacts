/**
 * Pairing verification code (B1).
 *
 * The `signet-grant:` QR a consuming app shows on screen carries `appPubkey`,
 * `challenge`, `relay` and `capabilities` — and nothing on that QR stops
 * whoever photographs it from publishing their OWN kind-21237 ack, encrypted
 * to the app and echoing the app's own challenge, before the owner's real ack
 * lands. `awaitPairingAck` accepts the first valid candidate it sees, so a
 * fast forged ack wins and the real one is ignored. The app is then paired to
 * the ATTACKER's rail: it reads a projection the attacker writes, sends its
 * proposals to the attacker's channel, and never sees the owner's directory
 * or blocks — with nothing on screen to say so. This is a takeover, not a
 * denial of service.
 *
 * The fix is a short code both screens can show and a person can compare by
 * eye. It is built from `grantId` and `railPubkey` — a random 32-hex id and a
 * fresh rail key that exist only inside the REAL ack, minted the moment
 * Signet approves the grant — never inside the photographed QR. A code built
 * only from `appPubkey` and `challenge` would prove nothing: the attacker has
 * both of those too, straight off the same QR. Because `awaitPairingAck`
 * accepts the first ack that decrypts and echoes the challenge, the attacker
 * gets exactly one attempt at guessing the owner's code, so this matches by
 * chance with probability 1 in 1,000,000. See `docs/WIRE.md` §3 for the
 * consumer/producer rules this function exists to support.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { CHALLENGE_HEX_CHARS } from './constants.js';
import { isHex } from './ids.js';

/** Same shape as `pairing.ts`'s own (unexported) `CHALLENGE_HEX` — a
 *  challenge may arrive uppercase and is validated case-insensitively. */
const CHALLENGE_HEX = new RegExp(`^[0-9a-f]{${CHALLENGE_HEX_CHARS}}$`, 'i');
const PAIRING_CODE_MODULUS = 1_000_000;
const PAIRING_CODE_DIGITS = 6;

export interface PairingCodeInput {
  appPubkey: string;   // 64 hex
  challenge: string;   // CHALLENGE_HEX_CHARS hex, case-insensitive on the way in
  grantId: string;     // 32 hex
  railPubkey: string;  // 64 hex
}

/**
 * Deterministic 6-digit code, e.g. `"042917"`. Both screens compute this from
 * the same four values, so a mismatch means one side has a different
 * `grantId`/`railPubkey` — i.e. a different pairing — from the other.
 */
export function pairingCode(input: PairingCodeInput): string {
  if (
    !isHex(input.appPubkey, 64) || !isHex(input.grantId, 32) || !isHex(input.railPubkey, 64)
    || typeof input.challenge !== 'string' || !CHALLENGE_HEX.test(input.challenge)
  ) {
    throw new TypeError('signet-contacts: invalid pairing-code input');
  }
  // Lowercased before hashing: only the challenge may actually arrive
  // uppercase (isHex already requires the other three to be lowercase to
  // pass), but hashing all four the same way keeps the digest independent of
  // case by construction rather than by which fields happen to allow it.
  const appPubkey = input.appPubkey.toLowerCase();
  const challenge = input.challenge.toLowerCase();
  const grantId = input.grantId.toLowerCase();
  const railPubkey = input.railPubkey.toLowerCase();

  const payload = `signet-contacts:pairing-code:v1\n${appPubkey}\n${challenge}\n${grantId}\n${railPubkey}`;
  const digest = sha256(new TextEncoder().encode(payload));
  const n = ((digest[0]! << 24) | (digest[1]! << 16) | (digest[2]! << 8) | digest[3]!) >>> 0;
  return String(n % PAIRING_CODE_MODULUS).padStart(PAIRING_CODE_DIGITS, '0');
}

/** Display grouping only, e.g. `"042 917"` — the value to compare against is
 *  the bare 6 digits `pairingCode` returns. */
export function formatPairingCode(code: string): string {
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}
