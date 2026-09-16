import { describe, it, expect } from 'vitest';
import {
  CAPABILITIES, CAPABILITY_DESCRIPTIONS, PAIRING_SCHEME, PAIRING_VERSION, ACK_KIND,
  PROJECTION_KIND, PROPOSAL_KIND, DEFAULT_STALENESS_SECONDS, MIN_STALENESS_SECONDS,
  MAX_STALENESS_SECONDS, MAX_WIRE_BYTES, MAX_PROPOSALS_PER_BATCH, isCapability, clampStaleness,
} from './constants.js';

// R-28(d): the description of a capability must say what the producer DOES,
// not what a reviewer might wish it did. `propose:add-ken` is auto-applied by
// signet-app the moment the batch validates — there is no queue, no prompt and
// no owner decision — so describing it as a request the owner answers made the
// approval screen's consent false. A1(M1): `linkedPubkeys` rides every
// projected contact, so `read:directory` names it too.
describe('capability descriptions say what happens (R-28d)', () => {
  it('describes add-ken as adding contacts, never as asking', () => {
    const addKen = CAPABILITY_DESCRIPTIONS['signet.contacts.propose:add-ken'];
    expect(addKen).toContain('Add contacts to your Ken list (recognised only, no access)');
    expect(addKen).not.toMatch(/ask/i);
    expect(addKen).not.toMatch(/may accept|approve|propose/i);
  });

  it('names linked keys wherever they are actually carried', () => {
    expect(CAPABILITY_DESCRIPTIONS['signet.contacts.read:directory']).toMatch(/linked/i);
    expect(CAPABILITY_DESCRIPTIONS['signet.contacts.blocks.read']).toMatch(/linked/i);
  });
});

describe('capability list', () => {
  it('is the six v2 capabilities, in a frozen order', () => {
    expect(CAPABILITIES).toEqual([
      'signet.contacts.read:directory',
      'signet.contacts.read:methods',
      'signet.contacts.read:roles',
      'signet.contacts.blocks.read',
      'signet.contacts.propose:add-ken',
      'signet.contacts.propose:rename-app-label',
    ]);
  });

  it('does not ship a capability nothing can grant', () => {
    // R-12: read:avatar is out until the producer has an avatar map to fill.
    expect(CAPABILITIES).not.toContain('signet.contacts.read:avatar');
    expect(isCapability('signet.contacts.read:avatar')).toBe(false);
  });

  it('describes every capability for consumer documentation', () => {
    for (const cap of CAPABILITIES) {
      expect(CAPABILITY_DESCRIPTIONS[cap].length).toBeGreaterThan(10);
    }
  });

  it('recognises only known capability tokens', () => {
    expect(isCapability('signet.contacts.read:directory')).toBe(true);
    expect(isCapability('signet.contacts.read:everything')).toBe(false);
    expect(isCapability(42)).toBe(false);
  });
});

describe('wire constants', () => {
  it('reuses the v1 pairing scheme and ack kind, at version 2', () => {
    expect(PAIRING_SCHEME).toBe('signet-grant:');
    expect(PAIRING_VERSION).toBe(2);
    expect(ACK_KIND).toBe(21237);
    expect(PROJECTION_KIND).toBe(30078);
    expect(PROPOSAL_KIND).toBe(30078);
  });

  it('caps a payload at the vault envelope’s top padding bucket', () => {
    // R-5: 65536 (TOP_BUCKET) minus the envelope's 4-byte length prefix. Also
    // under nostr-tools' 65535-byte NIP-44 v2 plaintext limit, so both hold.
    expect(MAX_WIRE_BYTES).toBe(65532);
    expect(MAX_PROPOSALS_PER_BATCH).toBe(50);
  });
});

describe('clampStaleness', () => {
  it('defaults, floors and ceilings', () => {
    expect(clampStaleness(undefined)).toBe(DEFAULT_STALENESS_SECONDS);
    expect(clampStaleness(10)).toBe(MIN_STALENESS_SECONDS);
    expect(clampStaleness(99_999_999)).toBe(MAX_STALENESS_SECONDS);
    expect(clampStaleness(21600)).toBe(21600);
    expect(clampStaleness(Number.NaN)).toBe(DEFAULT_STALENESS_SECONDS);
  });
});
