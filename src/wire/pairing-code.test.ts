import { describe, it, expect } from 'vitest';
import { pairingCode, formatPairingCode } from './pairing-code.js';

const APP = 'a'.repeat(64);
const RAIL = 'b'.repeat(64);
const GRANT = 'f'.repeat(32);
const CHALLENGE = 'd'.repeat(32);

describe('pairingCode', () => {
  it('is deterministic: the same four inputs always produce the same code', () => {
    const code = pairingCode({ appPubkey: APP, challenge: CHALLENGE, grantId: GRANT, railPubkey: RAIL });
    expect(code).toMatch(/^[0-9]{6}$/);
    expect(pairingCode({ appPubkey: APP, challenge: CHALLENGE, grantId: GRANT, railPubkey: RAIL })).toBe(code);
  });

  it('does not depend on the challenge’s case: it is echoed verbatim but hashed lowercase', () => {
    const lower = pairingCode({ appPubkey: APP, challenge: CHALLENGE, grantId: GRANT, railPubkey: RAIL });
    const upper = pairingCode({ appPubkey: APP, challenge: CHALLENGE.toUpperCase(), grantId: GRANT, railPubkey: RAIL });
    expect(upper).toBe(lower);
  });

  it('differs when grantId or railPubkey differs, even with appPubkey/challenge unchanged', () => {
    const a = pairingCode({ appPubkey: APP, challenge: CHALLENGE, grantId: GRANT, railPubkey: RAIL });
    expect(pairingCode({ appPubkey: APP, challenge: CHALLENGE, grantId: '0'.repeat(32), railPubkey: RAIL })).not.toBe(a);
    expect(pairingCode({ appPubkey: APP, challenge: CHALLENGE, grantId: GRANT, railPubkey: '0'.repeat(64) })).not.toBe(a);
  });

  // A code built only from what the photographed QR carries (appPubkey,
  // challenge) would be useless — the attacker has both. grantId and
  // railPubkey exist only inside the real ack, which is why they are inputs.
  it('is unaffected by appPubkey/challenge alone once grantId and railPubkey are fixed', () => {
    const a = pairingCode({ appPubkey: APP, challenge: CHALLENGE, grantId: GRANT, railPubkey: RAIL });
    const b = pairingCode({ appPubkey: 'c'.repeat(64), challenge: '1'.repeat(32), grantId: GRANT, railPubkey: RAIL });
    expect(a).not.toBe(b); // appPubkey/challenge are still mixed in — a full-code comparison still binds them
  });

  it('rejects a malformed appPubkey', () => {
    expect(() => pairingCode({ appPubkey: 'AB', challenge: CHALLENGE, grantId: GRANT, railPubkey: RAIL }))
      .toThrow(TypeError);
    expect(() => pairingCode({ appPubkey: APP.toUpperCase(), challenge: CHALLENGE, grantId: GRANT, railPubkey: RAIL }))
      .toThrow(TypeError);
  });

  it('rejects a malformed grantId', () => {
    expect(() => pairingCode({ appPubkey: APP, challenge: CHALLENGE, grantId: 'short', railPubkey: RAIL }))
      .toThrow(TypeError);
  });

  it('rejects a malformed railPubkey', () => {
    expect(() => pairingCode({ appPubkey: APP, challenge: CHALLENGE, grantId: GRANT, railPubkey: 'short' }))
      .toThrow(TypeError);
  });

  it('rejects a challenge of the wrong length or shape', () => {
    expect(() => pairingCode({ appPubkey: APP, challenge: CHALLENGE.slice(1), grantId: GRANT, railPubkey: RAIL }))
      .toThrow(TypeError);
    expect(() => pairingCode({ appPubkey: APP, challenge: 'z'.repeat(32), grantId: GRANT, railPubkey: RAIL }))
      .toThrow(TypeError);
  });

  it('rejects a non-string challenge', () => {
    expect(() => pairingCode({
      appPubkey: APP, challenge: undefined as unknown as string, grantId: GRANT, railPubkey: RAIL,
    })).toThrow(TypeError);
  });

  it('throws the exact message a caller can match on', () => {
    expect(() => pairingCode({ appPubkey: 'short', challenge: CHALLENGE, grantId: GRANT, railPubkey: RAIL }))
      .toThrow('signet-contacts: invalid pairing-code input');
  });
});

describe('formatPairingCode', () => {
  it('groups the six digits as "NNN NNN"', () => {
    expect(formatPairingCode('042917')).toBe('042 917');
    expect(formatPairingCode('000000')).toBe('000 000');
  });
});
