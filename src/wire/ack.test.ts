import { describe, it, expect } from 'vitest';
import { buildPairingAckV2, parsePairingAckV2, ackEventTemplate, pairingFromAck } from './ack.js';
import { projectionTag, proposalTag } from './ids.js';
import { ACK_KIND } from './constants.js';
import type { PairingAckV2 } from './types.js';

const GRANT = 'f'.repeat(32);
const APP = 'a'.repeat(64);
const CHALLENGE = 'D'.repeat(32);

const ACK: PairingAckV2 = {
  v: 2,
  grantId: GRANT,
  railPubkey: 'b'.repeat(64),
  projectionTag: projectionTag(GRANT),
  proposalTag: proposalTag(GRANT, APP),
  relay: 'wss://relay.example.com',
  grantedCapabilities: ['signet.contacts.read:directory'],
  maxStalenessSeconds: 21600,
  challenge: CHALLENGE,
};

describe('buildPairingAckV2 / parsePairingAckV2', () => {
  it('round-trips', () => {
    expect(parsePairingAckV2(buildPairingAckV2(ACK), CHALLENGE)).toEqual(ACK);
  });

  it('rejects a challenge that does not match byte-for-byte', () => {
    expect(parsePairingAckV2(buildPairingAckV2(ACK), 'E'.repeat(32))).toBeNull();
    expect(parsePairingAckV2(buildPairingAckV2(ACK), CHALLENGE.toLowerCase())).toBeNull();
  });

  it('rejects v1, a short rail pubkey, a bad tag and a bad relay', () => {
    expect(parsePairingAckV2(buildPairingAckV2(ACK).replace('"v":2', '"v":1'), CHALLENGE)).toBeNull();
    expect(parsePairingAckV2(buildPairingAckV2({ ...ACK, railPubkey: 'short' }), CHALLENGE)).toBeNull();
    expect(parsePairingAckV2(buildPairingAckV2({ ...ACK, projectionTag: 'nope' }), CHALLENGE)).toBeNull();
    expect(parsePairingAckV2(buildPairingAckV2({ ...ACK, relay: 'http://x.example' }), CHALLENGE)).toBeNull();
    // C-I7: the same 256-character cap the pairing URI enforces. An ack is the
    // one place a relay URL enters a consumer's own storage.
    expect(parsePairingAckV2(
      buildPairingAckV2({ ...ACK, relay: `wss://${'a'.repeat(300)}.example` }), CHALLENGE,
    )).toBeNull();
  });

  it('rejects non-JSON and a JSON array', () => {
    expect(parsePairingAckV2('{', CHALLENGE)).toBeNull();
    expect(parsePairingAckV2('[]', CHALLENGE)).toBeNull();
  });

  it('drops unknown granted capabilities rather than trusting them', () => {
    const tampered = buildPairingAckV2(ACK).replace(
      '"signet.contacts.read:directory"',
      '"signet.contacts.read:directory","signet.contacts.read:everything"',
    );
    expect(parsePairingAckV2(tampered, CHALLENGE)?.grantedCapabilities)
      .toEqual(['signet.contacts.read:directory']);
  });

  it('clamps an out-of-band staleness window', () => {
    expect(parsePairingAckV2(buildPairingAckV2({ ...ACK, maxStalenessSeconds: 1 }), CHALLENGE)?.maxStalenessSeconds)
      .toBe(3600);
    expect(parsePairingAckV2(buildPairingAckV2({ ...ACK, maxStalenessSeconds: 99_999_999 }), CHALLENGE)?.maxStalenessSeconds)
      .toBe(604800);
  });
});

describe('ackEventTemplate', () => {
  it('is kind 21237 addressed to the app with no other tag', () => {
    const tmpl = ackEventTemplate('c'.repeat(64), APP, 1_700_000_000, 'ciphertext');
    expect(tmpl.kind).toBe(ACK_KIND);
    expect(tmpl.tags).toEqual([['p', APP]]);
    expect(tmpl.pubkey).toBe('c'.repeat(64));
  });
});

describe('pairingFromAck', () => {
  it('drops the version and challenge and stamps pairedAt', () => {
    const pairing = pairingFromAck(ACK, 1_700_000_005);
    expect(pairing.pairedAt).toBe(1_700_000_005);
    expect('challenge' in pairing).toBe(false);
    expect('v' in pairing).toBe(false);
    expect(pairing.railPubkey).toBe(ACK.railPubkey);
  });
});
