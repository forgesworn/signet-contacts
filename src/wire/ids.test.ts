import { describe, it, expect } from 'vitest';
import { projectionTag, proposalTag, scopedContactId, isHex, randomHex, sanitizeWireText } from './ids.js';

const GRANT = 'f'.repeat(32);
const APP = 'a'.repeat(64);

describe('routing tags', () => {
  it('are 32 lowercase hex and deterministic', () => {
    const tag = projectionTag(GRANT);
    expect(tag).toMatch(/^[0-9a-f]{32}$/);
    expect(projectionTag(GRANT)).toBe(tag);
  });

  it('are domain-separated: a projection tag is never a proposal tag', () => {
    expect(projectionTag(GRANT)).not.toBe(proposalTag(GRANT, APP));
  });

  it('bind a proposal tag to one app pubkey', () => {
    expect(proposalTag(GRANT, APP)).not.toBe(proposalTag(GRANT, 'b'.repeat(64)));
  });

  it('pins the exact frozen digests', () => {
    // sha256('signet:contacts:proj:' + GRANT).slice(0,32) — regenerate ONLY with
    // an accompanying wire major bump; consumers key their storage off these.
    expect(projectionTag(GRANT)).toBe('5d65155161ef7e713af3bf7bc7b213d0');
    expect(proposalTag(GRANT, APP)).toBe('2713fc461de3b92ac3da773f33926f3d');
  });
});

describe('scopedContactId', () => {
  it('is stable per (grant, contact) and differs across grants', () => {
    const a = scopedContactId(GRANT, 'contact-1');
    expect(a).toMatch(/^[0-9a-f]{32}$/);
    expect(scopedContactId(GRANT, 'contact-1')).toBe(a);
    expect(scopedContactId('0'.repeat(32), 'contact-1')).not.toBe(a);
  });

  it('does not collide on a separator ambiguity', () => {
    expect(scopedContactId('ab', 'c:d')).not.toBe(scopedContactId('ab:c', 'd'));
  });
});

describe('isHex', () => {
  it('accepts lowercase hex of the requested length only', () => {
    expect(isHex('ab12', 4)).toBe(true);
    expect(isHex('AB12', 4)).toBe(false);
    expect(isHex('ab12', 6)).toBe(false);
    expect(isHex('zz', 2)).toBe(false);
    expect(isHex(12 as unknown, 2)).toBe(false);
    expect(isHex('abcd')).toBe(true);
  });
});

describe('randomHex', () => {
  it('returns 2 chars per byte and differs between calls', () => {
    expect(randomHex(16)).toHaveLength(32);
    expect(randomHex(16)).not.toBe(randomHex(16));
  });
});

describe('sanitizeWireText', () => {
  it('strips control and bidi characters, trims, then caps', () => {
    expect(sanitizeWireText('  Sam‮  ', 100)).toBe('Sam');
    expect(sanitizeWireText('abcdef', 3)).toBe('abc');
    expect(sanitizeWireText(undefined, 10)).toBe('');
    expect(sanitizeWireText(7, 10)).toBe('');
  });
});
