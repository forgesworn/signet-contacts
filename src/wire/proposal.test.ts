import { describe, it, expect } from 'vitest';
import {
  buildProposalBatch, parseProposalBatch, proposalEventTemplate, proposalFilter, draftToProposal,
} from './proposal.js';
import { proposalTag } from './ids.js';
import { PROPOSAL_KIND, MAX_PROPOSALS_PER_BATCH } from './constants.js';
import type { ContactProposalV1 } from './types.js';

const GRANT = 'f'.repeat(32);
const APP = 'a'.repeat(64);

function addKen(over: Partial<ContactProposalV1> = {}): ContactProposalV1 {
  return {
    v: 1, grantId: GRANT, operationId: '9'.repeat(32), action: 'add-ken',
    value: { pubkey: 'c'.repeat(64), displayName: 'Ada' }, createdAt: 1_700_000_000, ...over,
  };
}
function rename(over: Partial<ContactProposalV1> = {}): ContactProposalV1 {
  return {
    v: 1, grantId: GRANT, operationId: '8'.repeat(32), action: 'rename-app-label',
    value: { contactId: 'a'.repeat(32), label: 'Coach', updatedAt: 1_700_000_000_000 }, createdAt: 1_700_000_000, ...over,
  };
}

describe('buildProposalBatch / parseProposalBatch', () => {
  it('round-trips both actions', () => {
    const batch = parseProposalBatch(buildProposalBatch([addKen(), rename()]));
    expect(batch?.proposals).toEqual([addKen(), rename()]);
  });

  it('throws on an over-cap batch rather than truncating silently', () => {
    const many = Array.from({ length: MAX_PROPOSALS_PER_BATCH + 1 }, (_, i) =>
      addKen({ operationId: i.toString(16).padStart(32, '0') }));
    expect(() => buildProposalBatch(many)).toThrow(/50/);
  });

  it('throws on an empty batch', () => {
    expect(() => buildProposalBatch([])).toThrow();
  });

  it('throws when a proposal would be rewritten in transit', () => {
    expect(() => buildProposalBatch([addKen({ value: { pubkey: 'nope', displayName: 'Ada' } })])).toThrow();
    expect(() => buildProposalBatch([addKen({ operationId: 'short' })])).toThrow();
    expect(() => buildProposalBatch([rename({ value: { contactId: 'a'.repeat(32), label: 'x'.repeat(200), updatedAt: 1_700_000_000_000 } })])).toThrow();
    expect(() => buildProposalBatch([addKen({ value: { pubkey: 'c'.repeat(64), displayName: '   ' } })])).toThrow();
  });

  it('drops an individually invalid proposal on parse and keeps the rest', () => {
    const json = JSON.stringify({ v: 1, proposals: [addKen(), { v: 1, action: 'nonsense' }] });
    expect(parseProposalBatch(json)?.proposals).toHaveLength(1);
  });

  it('drops a rename-app-label with a missing or malformed updatedAt (R-7) and keeps the rest', () => {
    const missing = { v: 1, grantId: GRANT, operationId: '7'.repeat(32), action: 'rename-app-label', value: { contactId: 'a'.repeat(32), label: 'Coach' }, createdAt: 1_700_000_000 };
    const negative = rename({ operationId: '6'.repeat(32), value: { contactId: 'a'.repeat(32), label: 'Coach', updatedAt: -1 } });
    const nonInteger = rename({ operationId: '5'.repeat(32), value: { contactId: 'a'.repeat(32), label: 'Coach', updatedAt: 1.5 } });
    const nonNumeric = { v: 1, grantId: GRANT, operationId: '4'.repeat(32), action: 'rename-app-label', value: { contactId: 'a'.repeat(32), label: 'Coach', updatedAt: '1700000000000' }, createdAt: 1_700_000_000 };
    const json = JSON.stringify({ v: 1, proposals: [addKen(), missing, negative, nonInteger, nonNumeric] });
    expect(parseProposalBatch(json)?.proposals).toEqual([addKen()]);
  });

  it('caps the parsed batch at 50', () => {
    const many = Array.from({ length: 80 }, (_, i) => addKen({ operationId: i.toString(16).padStart(32, '0') }));
    expect(parseProposalBatch(JSON.stringify({ v: 1, proposals: many }))?.proposals).toHaveLength(50);
  });

  it('returns null on a broken envelope', () => {
    expect(parseProposalBatch('{')).toBeNull();
    expect(parseProposalBatch('[]')).toBeNull();
    expect(parseProposalBatch(JSON.stringify({ v: 2, proposals: [] }))).toBeNull();
    expect(parseProposalBatch(JSON.stringify({ v: 1 }))).toBeNull();
  });
});

describe('draftToProposal', () => {
  it('mints a 32-hex operation id and stamps the grant', () => {
    const p = draftToProposal({ action: 'add-ken', value: { pubkey: 'c'.repeat(64), displayName: 'Ada' } }, GRANT, 1_700_000_000);
    expect(p.operationId).toMatch(/^[0-9a-f]{32}$/);
    expect(p.grantId).toBe(GRANT);
    expect(p.createdAt).toBe(1_700_000_000);
  });

  it('R-7: stamps a rename draft\'s updatedAt from the draft when given', () => {
    const p = draftToProposal(
      { action: 'rename-app-label', value: { contactId: 'a'.repeat(32), label: 'Coach', updatedAt: 1_700_000_000_000 } },
      GRANT, 1_700_000_000,
    );
    expect(p.value).toEqual({ contactId: 'a'.repeat(32), label: 'Coach', updatedAt: 1_700_000_000_000 });
  });

  it('R-7: defaults a rename draft\'s updatedAt to Date.now() when omitted', () => {
    const before = Date.now();
    const p = draftToProposal(
      { action: 'rename-app-label', value: { contactId: 'a'.repeat(32), label: 'Coach' } },
      GRANT, 1_700_000_000,
    );
    const after = Date.now();
    const value = p.value as { updatedAt: number };
    expect(value.updatedAt).toBeGreaterThanOrEqual(before);
    expect(value.updatedAt).toBeLessThanOrEqual(after);
  });
});

describe('proposalEventTemplate and proposalFilter', () => {
  it('is a replaceable kind-30078 under the app-bound proposal tag', () => {
    const tmpl = proposalEventTemplate(APP, GRANT, 1_700_000_000, 'ciphertext');
    expect(tmpl.kind).toBe(PROPOSAL_KIND);
    expect(tmpl.pubkey).toBe(APP);
    expect(tmpl.tags).toEqual([['d', proposalTag(GRANT, APP)]]);
  });

  it('builds the matching producer-side filter pinned to the app author', () => {
    expect(proposalFilter(APP, GRANT)).toEqual({
      kinds: [PROPOSAL_KIND], authors: [APP], '#d': [proposalTag(GRANT, APP)], limit: 1,
    });
  });
});
