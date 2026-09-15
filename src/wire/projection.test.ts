import { describe, it, expect } from 'vitest';
import {
  buildProjection, parseProjection, projectionByteLength, projectionEventTemplate, projectionFilter,
} from './projection.js';
import { projectionTag } from './ids.js';
import { MAX_WIRE_BYTES, PROJECTION_KIND } from './constants.js';
import type { ContactProjectionV2, ProjectedContact } from './types.js';

const GRANT = 'f'.repeat(32);
const DEVICE = '2'.repeat(32);

function contact(over: Partial<ProjectedContact> = {}): ProjectedContact {
  return {
    contactId: 'a'.repeat(32),
    type: 'person',
    identities: [{ pubkey: 'b'.repeat(64), verification: 'proven' }],
    displayName: 'Sam',
    effectiveTier: 'kith',
    tierSource: 'direct',
    blocked: false,
    ...over,
  };
}

function projection(over: Partial<ContactProjectionV2> = {}): ContactProjectionV2 {
  return {
    v: 2, grantId: GRANT, ownerPubkey: '1'.repeat(64),
    scopes: ['signet.contacts.read:directory'],
    frontier: { maxClock: 7, opCount: 12, publishedAt: 1_700_000_000, deviceId: DEVICE },
    issuedAt: 1_700_000_000, expiresAt: 1_700_021_600,
    contacts: [contact()],
    ...over,
  };
}

describe('buildProjection / parseProjection', () => {
  it('round-trips a full projection byte-identically', () => {
    const p = projection({
      contacts: [contact({
        avatar: { url: 'https://blossom.example/a', hash: 'c'.repeat(64), key: 'd'.repeat(64) },
        roles: ['coach'],
        contactMethods: [{ kind: 'email', value: 'sam@example.com', verification: 'unverified' }],
        linkedPubkeys: ['e'.repeat(64)],
      })],
      scopes: ['signet.contacts.read:directory', 'signet.contacts.read:roles'],
    });
    expect(parseProjection(buildProjection(p))).toEqual(p);
  });

  it('round-trips a revocation with no contacts', () => {
    const p = projection({ contacts: [], revoked: true });
    const parsed = parseProjection(buildProjection(p));
    expect(parsed?.revoked).toBe(true);
    expect(parsed?.contacts).toEqual([]);
  });

  it('round-trips the truncated marker', () => {
    const p = projection({ truncated: true });
    expect(parseProjection(buildProjection(p))?.truncated).toBe(true);
    expect(parseProjection(buildProjection(projection()))?.truncated).toBeUndefined();
  });

  it('rejects a frontier with no publisher or no moment', () => {
    const json = buildProjection(projection());
    expect(parseProjection(json.replace(`"deviceId":"${DEVICE}"`, '"deviceId":"nope"'))).toBeNull();
    expect(parseProjection(json.replace('"publishedAt":1700000000', '"publishedAt":"soon"'))).toBeNull();
  });

  it('measures and refuses a body over the wire cap', () => {
    const small = projection();
    expect(projectionByteLength(small)).toBeLessThan(MAX_WIRE_BYTES);
    // ~400 bytes each, so 400 contacts is comfortably over 65532.
    const many = Array.from({ length: 400 }, (_, i) => contact({
      contactId: i.toString(16).padStart(32, '0'),
      displayName: 'N'.repeat(100),
      roles: ['r'.repeat(40), 's'.repeat(40)],
      linkedPubkeys: ['e'.repeat(64), 'f'.repeat(64)],
    }));
    const big = projection({ contacts: many });
    expect(projectionByteLength(big)).toBeGreaterThan(MAX_WIRE_BYTES);
    expect(() => buildProjection(big)).toThrow(/65532/);
  });

  it('omits absent optional fields rather than emitting undefined', () => {
    expect(buildProjection(projection())).not.toContain('"roles"');
    expect(buildProjection(projection())).not.toContain('"avatar"');
  });

  it('throws when an input contact would not survive its own parser', () => {
    expect(() => buildProjection(projection({ contacts: [contact({ contactId: 'not-hex' })] }))).toThrow();
    expect(() => buildProjection(projection({ contacts: [contact({ displayName: 'x'.repeat(200) })] }))).toThrow();
    expect(() => buildProjection(projection({ contacts: [contact({ roles: Array(20).fill('r') })] }))).toThrow();
  });

  it('throws on a grant id, owner pubkey or expiry that is not well formed', () => {
    expect(() => buildProjection(projection({ grantId: 'short' }))).toThrow();
    expect(() => buildProjection(projection({ ownerPubkey: 'nope' }))).toThrow();
    expect(() => buildProjection(projection({ expiresAt: 1_600_000_000 }))).toThrow();
  });

  it('drops an individually invalid contact and keeps the rest', () => {
    const good = buildProjection(projection({ contacts: [contact(), contact({ contactId: '9'.repeat(32) })] }));
    const tampered = good.replace('"' + '9'.repeat(32) + '"', '"bad"');
    const parsed = parseProjection(tampered);
    expect(parsed?.contacts).toHaveLength(1);
    expect(parsed?.contacts[0]?.contactId).toBe('a'.repeat(32));
  });

  it('returns null on a structurally broken envelope', () => {
    expect(parseProjection('{')).toBeNull();
    expect(parseProjection('[]')).toBeNull();
    expect(parseProjection(buildProjection(projection()).replace('"v":2', '"v":1'))).toBeNull();
    expect(parseProjection('{"v":2,"grantId":"' + GRANT + '"}')).toBeNull();
  });

  it('caps the contacts list', () => {
    const many = Array.from({ length: 2100 }, (_, i) =>
      contact({ contactId: i.toString(16).padStart(32, '0') }));
    const json = JSON.stringify({ ...projection(), contacts: many });
    expect(parseProjection(json)?.contacts).toHaveLength(2000);
  });

  it('rejects an avatar url that is not https and a key that is not hex', () => {
    const withBadUrl = JSON.stringify({
      ...projection(),
      contacts: [{ ...contact(), avatar: { url: 'javascript:alert(1)', hash: 'c'.repeat(64) } }],
    });
    expect(parseProjection(withBadUrl)?.contacts[0]?.avatar).toBeUndefined();
    const withBadKey = JSON.stringify({
      ...projection(),
      contacts: [{ ...contact(), avatar: { url: 'https://x.example/a', hash: 'c'.repeat(64), key: 'nope' } }],
    });
    expect(parseProjection(withBadKey)?.contacts[0]?.avatar?.key).toBeUndefined();
  });
});

describe('projectionEventTemplate and projectionFilter', () => {
  it('addresses the replaceable projection by opaque d tag with no p tag', () => {
    const tmpl = projectionEventTemplate('b'.repeat(64), GRANT, 1_700_000_000, 'ciphertext');
    expect(tmpl.kind).toBe(PROJECTION_KIND);
    expect(tmpl.tags).toEqual([['d', projectionTag(GRANT)]]);
    expect(JSON.stringify(tmpl.tags)).not.toContain('"p"');
  });

  it('builds the matching consumer filter', () => {
    expect(projectionFilter('b'.repeat(64), GRANT)).toEqual({
      kinds: [PROJECTION_KIND],
      authors: ['b'.repeat(64)],
      '#d': [projectionTag(GRANT)],
      limit: 1,
    });
  });
});
