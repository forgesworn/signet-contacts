import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { CAPABILITIES, CAPABILITY_DESCRIPTIONS, MAX_PROPOSALS_PER_BATCH, MAX_WIRE_BYTES } from './wire/constants.js';

const wire = readFileSync('docs/WIRE.md', 'utf8');
const readme = readFileSync('README.md', 'utf8');
const integration = readFileSync('docs/INTEGRATION.md', 'utf8');
const security = readFileSync('SECURITY.md', 'utf8');

describe('docs/WIRE.md', () => {
  it('documents every capability token and its description', () => {
    for (const cap of CAPABILITIES) {
      expect(wire).toContain(cap);
      expect(wire).toContain(CAPABILITY_DESCRIPTIONS[cap]);
    }
  });

  it('does not document a capability this version does not ship', () => {
    expect(wire).not.toContain('signet.contacts.read:avatar');
  });

  it('states every event kind and the encryption direction of each payload', () => {
    for (const needle of ['21237', '30078', 'rail → app', 'app → rail', 'NIP-44']) {
      expect(wire).toContain(needle);
    }
  });

  it('states the hard limits', () => {
    expect(wire).toContain(String(MAX_WIRE_BYTES));
    expect(wire).toContain(String(MAX_PROPOSALS_PER_BATCH));
  });

  it('points at the generated vectors', () => {
    expect(wire).toContain('vectors/pairing.v2.json');
    expect(wire).toContain('vectors/projection.v2.json');
    expect(wire).toContain('vectors/proposal.v1.json');
    expect(wire).toContain('vectors/sanitise.json');
  });

  it('documents the envelope the projection is sealed in (R-4)', () => {
    for (const needle of ['padding', 'bucket', 'recipient']) {
      expect(wire.toLowerCase()).toContain(needle);
    }
  });
});

describe('README.md', () => {
  it('shows the install, an injected signer and the pending-proposal accessor', () => {
    expect(readme).toContain('git+https://github.com/forgesworn/signet-contacts.git');
    expect(readme).toContain('nip44Decrypt');
    expect(readme).toContain('createSignetContactsClient');
    expect(readme).toContain('pendingProposals');
  });

  it('says where the wire lives and why it is not in signet-protocol (R-1)', () => {
    expect(readme).toMatch(/signet-protocol/);
  });

  it('states the freshness rule and the two honesty boundaries', () => {
    expect(readme).toMatch(/never un-block/i);
    expect(readme).toMatch(/cannot recall|already downloaded|already decrypted/i);
    expect(readme).toMatch(/close circle/i);
  });
});

describe('docs/INTEGRATION.md and SECURITY.md', () => {
  it('walks the five flock steps and shows pending proposals', () => {
    for (const needle of ['awaitPairingAck', 'fetchProjection', 'getBlockedSet', 'propose', 'onRevoked', 'pendingProposals']) {
      expect(integration).toContain(needle);
    }
  });

  it('keeps the threat model to roughly a dozen lines', () => {
    const bullets = security.split('\n').filter((l) => l.trim().startsWith('-'));
    expect(bullets.length).toBeGreaterThanOrEqual(10);
    expect(bullets.length).toBeLessThanOrEqual(14);
  });

  it('states the author-pin reasoning and the timing trade-off (S7, S8)', () => {
    expect(security).toMatch(/event\.pubkey/);
    expect(security).toMatch(/timing/i);
    expect(security).toMatch(/rail (private )?key|rail nsec/i);
  });
});
