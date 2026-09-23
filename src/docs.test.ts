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

describe('docs/WIRE.md — carriers (M10)', () => {
  it('documents the web and App Link carriers, not only the custom scheme', () => {
    expect(wire).toContain('signet-grant://pair?');
    expect(wire).toContain('pair=1');
    expect(wire).toMatch(/App Link/);
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
    // Short enough to read in one sitting is the actual requirement; the
    // upper bound moved from 14 to 18 when S4, S5 and S9 were named rather
    // than left implicit.
    expect(bullets.length).toBeGreaterThanOrEqual(10);
    expect(bullets.length).toBeLessThanOrEqual(18);
  });

  // C-C1: SECURITY.md claimed the rail key is all an app sees while the
  // projection carried the owner's persona pubkey. R-31 made the claim true;
  // this pins both halves together.
  it('states what an app never receives, including the owner persona pubkey', () => {
    expect(security).toMatch(/persona pubkey/i);
    expect(security).toContain('R-31');
    expect(security).toMatch(/rail key, and only the rail key/);
  });

  it('names the advisory-freshness, revocation-reach and rendezvous-relay acceptances (S4, S5, S9)', () => {
    expect(security).toContain('**S4');
    expect(security).toContain('**S5');
    expect(security).toContain('**S9');
    expect(security).toMatch(/advisory/i);
    expect(security).toContain('MAX_STALENESS_SECONDS');
    expect(security).toMatch(/rendezvous relay is chosen by the app/i);
  });

  it('cross-references SECURITY.md by its S-labels, never by a section number', () => {
    expect(wire).not.toMatch(/§\s*\d+\s*of `SECURITY\.md`/);
    expect(wire).toContain('S7 in `SECURITY.md`');
  });

  it('states the author-pin reasoning and the timing trade-off (S7, S8)', () => {
    expect(security).toMatch(/event\.pubkey/);
    expect(security).toMatch(/timing/i);
    expect(security).toMatch(/rail (private )?key|rail nsec/i);
  });
});

// The co-maintainer's contract ruling: separate message versions are fine,
// but the wire spec must say which kind carries which `v`, which routing tags
// are readable, and which older readers are unsupported. These pin the table
// to what the code actually builds, so the two cannot drift apart again.
describe('docs/WIRE.md message-version contract', () => {
  const invite = readFileSync('docs/contact-invite-v1.md', 'utf8');
  const tableRow = (label: string): string => {
    const row = wire.split('\n').find((line) => line.startsWith(`| ${label} |`));
    expect(row, `no version-table row for ${label}`).toBeDefined();
    return row as string;
  };

  it('no longer claims a single version or universally hashed tags', () => {
    expect(wire).not.toMatch(/"v": 2` field on every JSON payload/);
    expect(wire).not.toContain('Every routing tag is a domain-separated');
  });

  it('gives each message kind the version its code builds', async () => {
    const { WIRE_VERSION, PAIRING_VERSION, buildProposalBatch, appInviteTag } = await import('./wire/index.js');
    expect(tableRow('Pairing URI')).toContain(`\`v=${PAIRING_VERSION}\``);
    expect(tableRow('Pairing ack')).toContain(`| \`${WIRE_VERSION}\` |`);
    expect(tableRow('Projection body')).toContain(`| \`${WIRE_VERSION}\` |`);
    const batch = JSON.parse(buildProposalBatch([{
      v: 1, grantId: 'a'.repeat(32), operationId: 'b'.repeat(32), action: 'add-ken',
      value: { pubkey: 'c'.repeat(64), displayName: 'Ada' }, createdAt: 1,
    }])) as { v: number };
    expect(tableRow('Proposal batch, and each proposal in it')).toContain(`| \`${batch.v}\` |`);
    const appRow = tableRow('App-introduction request');
    expect(appRow).toContain('| `1` |');
    expect(appRow).toContain('**readable**');
    expect(appInviteTag('a'.repeat(32))).toBe(`signet:contacts:app-invite:${'a'.repeat(32)}`);
    expect(tableRow('Projection body')).toContain('**hashed**');
    expect(tableRow('Contact invite')).toContain('| `1` |');
  });

  it('states the unsupported readers, the checks shape and the consent rule', () => {
    expect(wire).toContain('### Unsupported readers');
    expect(wire).toContain('`checks[].checkedAt`');
    expect(wire).toContain('## 10. Consent and grant changes');
    expect(wire).toMatch(/Ordinary updates keep the existing approval/);
    expect(wire).toMatch(/fresh consent/);
  });

  it('marks invitations final, not draft', () => {
    expect(invite).not.toMatch(/draft/i);
    expect(wire).not.toMatch(/App introductions \(draft/);
  });
});
