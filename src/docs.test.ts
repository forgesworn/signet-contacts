import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  ACK_CANDIDATE_LIMIT, CAPABILITIES, CAPABILITY_DESCRIPTIONS, CHALLENGE_HEX_CHARS,
  MAX_PAIRING_URI_CHARS, MAX_PROPOSALS_PER_BATCH, MAX_RELAY_LEN, MAX_WIRE_BYTES,
} from './wire/constants.js';
import { DEFAULT_LIVE_POLL_MS } from './client.js';

const wire = readFileSync('docs/WIRE.md', 'utf8');
const readme = readFileSync('README.md', 'utf8');
const integration = readFileSync('docs/INTEGRATION.md', 'utf8');
const security = readFileSync('SECURITY.md', 'utf8');
const changelog = readFileSync('CHANGELOG.md', 'utf8');

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
    // C-I7: the two fields that used to have no upper bound, and the raw-input
    // cap. A number documented nowhere is a number an independent
    // implementation will not enforce.
    expect(wire).toContain(`MAX_RELAY_LEN = ${MAX_RELAY_LEN}`);
    expect(wire).toContain(`CHALLENGE_HEX_CHARS = ${CHALLENGE_HEX_CHARS}`);
    expect(wire).toContain(`MAX_PAIRING_URI_CHARS = ${MAX_PAIRING_URI_CHARS}`);
    expect(wire).toContain(`ACK_CANDIDATE_LIMIT = ${ACK_CANDIDATE_LIMIT}`);
  });

  // R-31: the owner's persona pubkey is not on this wire, and no document may
  // describe it as if it were — a doc that still listed the field would send
  // an independent implementer straight back into the join it was removed to
  // prevent.
  it('never documents an owner pubkey field on the projection body (R-31)', () => {
    for (const doc of [readme, integration, security]) {
      expect(doc).not.toContain('ownerPubkey');
    }
    // WIRE.md names it exactly once, in the paragraph that says it is gone.
    expect(wire).toContain('no owner pubkey on this wire');
    const vector = JSON.parse(readFileSync('vectors/projection.v2.json', 'utf8')) as {
      regenerated: string; full: { plaintext: string; parsed: Record<string, unknown> };
    };
    expect(vector.regenerated).toContain('R-31');
    expect(vector.full.plaintext).not.toContain('ownerPubkey');
    expect('ownerPubkey' in vector.full.parsed).toBe(false);
  });

  // R-30: the ordering rule is the one thing an independent implementer can
  // get backwards while every vector still passes, so the doc must state the
  // order the code actually applies.
  it('states the frontier order as publishedAt first, maxClock as the tiebreak (R-30)', () => {
    expect(wire).toContain('`(publishedAt, maxClock)`');
    expect(wire).not.toContain('`(maxClock, publishedAt)`');
    expect(wire).toMatch(/revoked[^\n]*exempt|exempt[^\n]*revocation/i);
  });

  // I3: an implementer who reads "newest ack wins" builds the crowd-out back
  // in, so the candidate count is documented as a number and pinned here.
  it('states how many ack candidates a consumer considers (I3)', () => {
    expect(wire).toContain(String(ACK_CANDIDATE_LIMIT));
    expect(wire).toContain('ACK_CANDIDATE_LIMIT');
    expect(wire).toMatch(/newest first/i);
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

describe('README.md — storage, options and the persistence contract (C-I1, C-I3, C-M3)', () => {
  it('quick start loads persisted state and passes its own requested capabilities', () => {
    const quickStart = readme.slice(readme.indexOf('## Quick start'), readme.indexOf('## Storage'));
    expect(quickStart).toContain('client.load(');
    expect(quickStart).toContain('requestedCapabilities');
    expect(quickStart).toContain('storage');
  });

  it('says the default storage is in-memory and what that costs', () => {
    expect(readme).toMatch(/in-memory/i);
    expect(readme).toMatch(/Blocked set[^\n]*restart|restart[^\n]*Blocked/i);
  });

  it('documents every client and adapter option with its default', () => {
    for (const option of [
      'storage', 'now', 'nowMs', 'maxPendingStalenessSeconds',
      'timeoutMs', 'pollMs', 'requestedCapabilities',
    ]) {
      expect(readme).toContain(option);
    }
    for (const dflt of ['604800', '120000', '2000', '60000', '8000']) {
      expect(readme).toContain(dflt);
    }
  });
});

describe('docs/INTEGRATION.md — pending proposals and the Blocked set (C-I4, C-M1, C-M2)', () => {
  it('documents the seven-day pending drop and names the option', () => {
    expect(integration).toContain('maxPendingStalenessSeconds');
    expect(integration).toContain('604800');
    expect(integration).toMatch(/seven days/i);
  });

  it('credits applyProjection, not blockedSetOf, with enforcing stickiness', () => {
    const para = integration.slice(integration.indexOf('Blocked is **sticky**'));
    expect(para.slice(0, 600)).toContain('applyProjection');
  });

  it('imports every type its own setup block uses', () => {
    expect(integration).toContain("import type { StorageIo }");
  });
});

describe('docs/WIRE.md — truncation order and producer limits (C-I5, C-I6)', () => {
  it('states the drop order the producer actually applies', () => {
    const limits = wire.slice(wire.indexOf('## 8. Hard limits'));
    expect(limits).toMatch(/kept\*?\*? most-recently-/i);
    expect(limits).toMatch(/least\*?\*? recently updated/i);
    // R-28(c): app-created records go first, whatever their recency.
    expect(limits).toContain('R-28c');
  });

  it('names the three producer-side limits with their numbers', () => {
    const limits = wire.slice(wire.indexOf('## 8. Hard limits'));
    expect(limits).toContain('MAX_APP_LABELS_PER_GRANT');
    expect(limits).toContain('16');
    expect(limits).toContain('CONTACT_GRANT_V2_CAP');
    expect(limits).toContain('10');
    expect(limits).toContain('604800');
  });
});

describe('README.md and docs/INTEGRATION.md — live updates (R-32)', () => {
  it('describe start/stop as live with a poll fallback, and the default cadence', () => {
    for (const doc of [readme, integration]) {
      expect(doc).toContain('client.start(');
      expect(doc).toMatch(/poll(ing)? (as the )?fallback/i);
    }
    // Written for a reader ("60 000 ms"), pinned against the constant so a
    // change to the default cadence cannot leave the README saying the old one.
    const digits = String(DEFAULT_LIVE_POLL_MS).split('').join('[\\s_,]?');
    expect(readme).toMatch(new RegExp(digits));
    expect(integration).toContain('client.stop');
  });
});

describe('CHANGELOG.md', () => {
  it('records the one authorised projection-vector regeneration and its reason', () => {
    expect(changelog).toContain('R-31');
    expect(changelog).toContain('vectors/projection.v2.json');
    expect(readme).toContain('CHANGELOG.md');
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
