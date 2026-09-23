import { describe, it, expect } from 'vitest';
import {
  parseProjectedContact, buildProjection, parseProjection, projectionByteLength, projectionEventTemplate, projectionFilter,
} from './projection.js';
import { projectionTag } from './ids.js';
import {
  MAX_CAPABILITIES, MAX_CONTACTS_PER_PROJECTION, MAX_IDENTITIES_PER_CONTACT,
  MAX_METHODS_PER_CONTACT, MAX_WIRE_BYTES, PROJECTION_KIND,
} from './constants.js';
import type { ContactProjectionV2, ProjectedContact } from './types.js';

const GRANT = 'f'.repeat(32);
const DEVICE = '2'.repeat(32);
/** Every read capability, so a fixture carrying any covered field is in contract. */
const FULL_SCOPES: ContactProjectionV2['scopes'] = [
  'signet.contacts.read:directory', 'signet.contacts.read:method:phone', 'signet.contacts.read:method:email',
  'signet.contacts.read:method:website', 'signet.contacts.read:method:postal-address', 'signet.contacts.read:method:other',
  'signet.contacts.read:tier', 'signet.contacts.read:checks', 'signet.contacts.read:check-records',
  'signet.contacts.read:roles', 'signet.contacts.blocks.read',
];

function contact(over: Partial<ProjectedContact> = {}): ProjectedContact {
  return {
    contactId: 'a'.repeat(32),
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
    v: 2, grantId: GRANT,
    scopes: FULL_SCOPES,
    frontier: { maxClock: 7, opCount: 12, publishedAt: 1_700_000_000, deviceId: DEVICE },
    issuedAt: 1_700_000_000, expiresAt: 1_700_021_600,
    contacts: [contact()],
    ...over,
  };
}

describe('buildProjection / parseProjection', () => {
  it('round-trips a full projection', () => {
    const p = projection({
      contacts: [contact({
        roles: ['coach'],
        contactMethods: [{ kind: 'email', value: 'sam@example.com', verification: 'unverified' }],
        checks: [{ pubkey: 'b'.repeat(64), method: 'words', checkedAt: 1000 }],
      })],
    });
    expect(parseProjection(buildProjection(p))).toEqual(p);
  });

  it('produces byte-identical JSON regardless of caller key insertion order (I1)', () => {
    const base = contact({
      roles: ['coach'],
      contactMethods: [{ kind: 'email', value: 'sam@example.com', verification: 'unverified' }],
    });
    // Same values, deliberately different key insertion order.
    const reordered: ProjectedContact = {
      blocked: base.blocked,
      contactMethods: base.contactMethods,
      tierSource: base.tierSource,
      roles: base.roles,
      effectiveTier: base.effectiveTier,
      displayName: base.displayName,
      identities: base.identities,
      contactId: base.contactId,
    };
    const a = buildProjection(projection({ contacts: [base] }));
    const b = buildProjection(projection({ contacts: [reordered] }));
    expect(a).toBe(b);
  });

  it('does not throw when an optional contact field is explicitly undefined (I2)', () => {
    const withUndefined = contact({ roles: undefined, avatar: undefined });
    expect(() => buildProjection(projection({ contacts: [withUndefined] }))).not.toThrow();
    const parsed = parseProjection(buildProjection(projection({ contacts: [withUndefined] })));
    expect(parsed?.contacts[0]?.roles).toBeUndefined();
    expect(parsed?.contacts[0]?.avatar).toBeUndefined();
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
      contactMethods: [{ kind: 'email', value: 'e'.repeat(64) + '@example.com' }, { kind: 'other', value: 'f'.repeat(64) }],
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

  it('throws on a grant id or expiry that is not well formed', () => {
    expect(() => buildProjection(projection({ grantId: 'short' }))).toThrow();
    expect(() => buildProjection(projection({ expiresAt: 1_600_000_000 }))).toThrow();
  });

  // R-31: the directory owner's persona pubkey is NOT on this wire. It was
  // stable across every grant on a directory, so two colluding apps could
  // join on it in one line — the exact join `scopedContactId`'s opacity
  // exists to frustrate — and for a dependant directory it was a minor's
  // long-lived public identity handed to every paired app. The SDK never
  // read it: nothing in `client.ts`, `state.ts` or `projection.ts` compared,
  // checked or used it for anything.
  // M8: the parser's own cap used to be silent, so a consumer handed a
  // 2500-contact projection kept 2000 of them and believed the list complete —
  // `truncated` was producer-set only. A cut the READER makes is exactly as
  // much a truncation as one the producer made.
  it('sets truncated when it caps the contacts list itself', () => {
    const many = Array.from({ length: MAX_CONTACTS_PER_PROJECTION + 3 }, (_, i) => contact({
      contactId: i.toString(16).padStart(32, '0'),
    }));
    const overSent = JSON.stringify({
      v: 2, grantId: GRANT, scopes: FULL_SCOPES,
      frontier: { maxClock: 1, opCount: 1, publishedAt: 1, deviceId: DEVICE },
      issuedAt: 1, expiresAt: 2, contacts: many,
    });
    const parsed = parseProjection(overSent);
    expect(parsed?.contacts).toHaveLength(MAX_CONTACTS_PER_PROJECTION);
    expect(parsed?.truncated).toBe(true);
  });

  it('leaves truncated unset when nothing was cut', () => {
    expect(parseProjection(buildProjection(projection()))?.truncated).toBeUndefined();
  });

  it('does not carry an owner pubkey, and drops one a producer tries to smuggle in', () => {
    const body = buildProjection(projection());
    expect(body).not.toContain('ownerPubkey');

    const smuggled = JSON.stringify({
      ...(JSON.parse(body) as Record<string, unknown>),
      ownerPubkey: '1'.repeat(64),
    });
    const parsed = parseProjection(smuggled);
    expect(parsed).not.toBeNull();
    expect('ownerPubkey' in (parsed as object)).toBe(false);
  });

  it('parses a projection that never had an owner pubkey at all', () => {
    const body = JSON.parse(buildProjection(projection())) as Record<string, unknown>;
    expect(body.ownerPubkey).toBeUndefined();
    expect(parseProjection(JSON.stringify(body))?.grantId).toBe(GRANT);
  });

  it('throws when a scope would be silently narrowed in transit', () => {
    // 'signet.contacts.read:bogus' is not a real capability — the parser
    // drops it, which would ship a grant promising less than the caller
    // asked for unless the builder catches it.
    expect(() => buildProjection(projection({
      scopes: ['signet.contacts.read:directory', 'signet.contacts.read:bogus'] as unknown as ContactProjectionV2['scopes'],
    }))).toThrow();
  });

  it('does not throw when the same scope set is given in a different order', () => {
    const a = buildProjection(projection({ scopes: FULL_SCOPES }));
    const b = buildProjection(projection({ scopes: [...FULL_SCOPES].reverse() }));
    expect(a).toBe(b);
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

  it('refuses a projection carrying an avatar, type or linked pubkeys: no capability covers them', () => {
    for (const extra of [
      { avatar: { url: 'https://x.example/a', hash: 'c'.repeat(64) } },
      { type: 'person' },
      { linkedPubkeys: ['e'.repeat(64)] },
    ]) {
      const json = JSON.stringify({ ...projection(), contacts: [{ ...contact(), ...extra }] });
      expect(parseProjection(json)).toBeNull();
      expect(() => buildProjection(projection({ contacts: [{ ...contact(), ...extra } as ProjectedContact] })))
        .toThrow(/do not cover/);
    }
  });

  it('still refuses a non-https avatar url and a non-hex key on a bare contact parse', () => {
    expect(parseProjectedContact({ ...contact(), avatar: { url: 'javascript:alert(1)', hash: 'c'.repeat(64) } })?.avatar)
      .toBeUndefined();
    expect(parseProjectedContact({ ...contact(), avatar: { url: 'https://x.example/a', hash: 'c'.repeat(64), key: 'nope' } })?.avatar?.key)
      .toBeUndefined();
  });

  it('strips fields outside the allowlist from a wire contact', () => {
    const json = JSON.stringify({
      ...projection(),
      contacts: [{
        ...contact(),
        sharedSecret: 'topsecret',
        notes: 'private notes',
        itemId: 'internal-id',
        actorPubkey: 'z'.repeat(64),
        reason: 'because',
      }],
    });
    const parsed = parseProjection(json);
    expect(parsed?.contacts).toHaveLength(1);
    const keys = Object.keys(parsed!.contacts[0] as object);
    expect(keys).not.toContain('sharedSecret');
    expect(keys).not.toContain('notes');
    expect(keys).not.toContain('itemId');
    expect(keys).not.toContain('actorPubkey');
    expect(keys).not.toContain('reason');
  });

  it('caps identities and contact methods per contact on parse', () => {
    const tooMany = {
      ...contact(),
      identities: Array.from({ length: MAX_IDENTITIES_PER_CONTACT + 4 }, (_, i) => (
        { pubkey: i.toString(16).padStart(64, '0'), verification: 'proven' }
      )),
      contactMethods: Array.from({ length: MAX_METHODS_PER_CONTACT + 4 }, (_, i) => (
        { kind: 'email', value: `a${i}@example.com`, verification: 'unverified' }
      )),
    };
    const json = JSON.stringify({ ...projection(), contacts: [tooMany] });
    const parsed = parseProjection(json);
    expect(parsed?.contacts[0]?.identities).toHaveLength(MAX_IDENTITIES_PER_CONTACT);
    expect(parsed?.contacts[0]?.contactMethods).toHaveLength(MAX_METHODS_PER_CONTACT);
  });

  it('sanitises control/bidi characters in displayName and method values on parse', () => {
    const poisoned = {
      ...contact(),
      displayName: 'Sam​‮ evil',
      contactMethods: [{ kind: 'email', value: 'sam​@example.com', verification: 'unverified' }],
    };
    const json = JSON.stringify({ ...projection(), contacts: [poisoned] });
    const parsed = parseProjection(json);
    expect(parsed?.contacts[0]?.displayName).toBe('Sam evil');
    expect(parsed?.contacts[0]?.contactMethods?.[0]?.value).toBe('sam@example.com');
  });

  it('drops a later duplicate contactId, keeping the first (M5)', () => {
    const json = JSON.stringify({
      ...projection(),
      contacts: [contact({ displayName: 'First' }), contact({ displayName: 'Second' })],
    });
    const parsed = parseProjection(json);
    expect(parsed?.contacts).toHaveLength(1);
    expect(parsed?.contacts[0]?.displayName).toBe('First');
  });

  it('caps scopes before filtering (M3)', () => {
    const scopes = Array.from({ length: MAX_CAPABILITIES + 10 }, (_, i) => (
      i === MAX_CAPABILITIES + 5 ? 'signet.contacts.read:directory' : 'bogus'
    ));
    const json = JSON.stringify({ ...projection(), scopes, contacts: [] });
    expect(parseProjection(json)?.scopes).toEqual([]);
  });

  it('filters unknown scope strings', () => {
    const json = JSON.stringify({
      ...projection(),
      scopes: ['signet.contacts.read:directory', 'signet.contacts.read:bogus', 'not-a-capability'],
      contacts: [{ contactId: 'a'.repeat(32), displayName: 'Sam' }],
    });
    expect(parseProjection(json)?.scopes).toEqual(['signet.contacts.read:directory']);
  });

  it('never throws on hostile contact nesting', () => {
    const json = JSON.stringify({ ...projection(), contacts: [null, 1, 'x', { weird: true }] });
    expect(() => parseProjection(json)).not.toThrow();
    expect(parseProjection(json)?.contacts).toEqual([]);
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


it('round-trips name and public key without inventing a tier, block state or checks', () => {
  const minimal = { contactId: 'a'.repeat(32), displayName: 'Ada', identities: [{ pubkey: 'b'.repeat(64) }] };
  const read = parseProjection(buildProjection(projection({ contacts: [minimal] })))!;
  expect(read.contacts).toEqual([minimal]);
  expect(read.contacts[0]?.effectiveTier).toBeUndefined();
  expect(read.contacts[0]?.blocked).toBeUndefined();
  expect(read.contacts[0]?.identities?.[0]?.verification).toBeUndefined();
});

it('round-trips a method value without requiring a verification disclosure', () => {
  const minimal = { contactId: 'a'.repeat(32), contactMethods: [{ kind: 'email' as const, value: 'ada@example.com' }] };
  expect(parseProjection(buildProjection(projection({
    scopes: ['signet.contacts.read:directory', 'signet.contacts.read:method:email'], contacts: [minimal],
  })))?.contacts).toEqual([minimal]);
});

it('allowlists check summaries and strips private sources and evidence', () => {
  const parsed = parseProjectedContact({ contactId: 'a'.repeat(32), checks: [
    { pubkey: 'b'.repeat(64), method: 'words', checkedAt: 1000, source: 'website', evidence: 'private link', ownerIdentityPubkey: 'c'.repeat(64) },
    { pubkey: 'b'.repeat(64), method: 'invented', checkedAt: 1000 },
  ] });
  expect(parsed?.checks).toEqual([{ pubkey: 'b'.repeat(64), method: 'words', checkedAt: 1000 }]);
});

// Consent (WIRE.md §10): a field the projection's scopes do not cover is
// broader sharing than the owner approved. The builder throws, the parser
// refuses the whole projection — both from the one FIELD_COVERAGE table.
describe('field coverage', () => {
  const DIR = 'signet.contacts.read:directory' as const;
  const cases: Array<[string, ContactProjectionV2['scopes'], Record<string, unknown>]> = [
    ['tier without read:tier', [DIR], { effectiveTier: 'kith' }],
    ['tier source without read:tier', [DIR], { tierSource: 'direct' }],
    ['roles without read:roles', [DIR], { roles: ['coach'] }],
    ['identity verification without read:checks', [DIR], { identities: [{ pubkey: 'b'.repeat(64), verification: 'proven' }] }],
    ['a phone method under an email grant', [DIR, 'signet.contacts.read:method:email'], { contactMethods: [{ kind: 'phone', value: '+441234' }] }],
    ['method verification without read:checks', [DIR, 'signet.contacts.read:method:email'], { contactMethods: [{ kind: 'email', value: 'a@b.example', verification: 'proven' }] }],
    ['check records under read:checks only', [DIR, 'signet.contacts.read:checks'], { checks: [{ pubkey: 'b'.repeat(64), method: 'words', checkedAt: 1 }] }],
    ['block state without blocks.read', [DIR], { blocked: false }],
    ['tier with read:tier but no directory', ['signet.contacts.read:tier', 'signet.contacts.blocks.read'], { blocked: true, effectiveTier: 'kin' }],
    ['an unblocked contact under blocks.read only', ['signet.contacts.blocks.read'], { blocked: false }],
    ['a display name under blocks.read only', ['signet.contacts.blocks.read'], { blocked: true, displayName: 'Mallory' }],
  ];
  for (const [label, scopes, fields] of cases) {
    it(`refuses ${label}`, () => {
      const c = { contactId: 'a'.repeat(32), ...fields };
      expect(() => buildProjection(projection({ scopes, contacts: [c as ProjectedContact] }))).toThrow(/do not cover/);
      const json = JSON.stringify({ ...projection(), scopes, contacts: [c] });
      expect(parseProjection(json)).toBeNull();
      expect(parseProjectedContact(c, scopes)).toBeNull();
    });
  }

  it('accepts a blocked contact and its identity pubkeys under blocks.read alone', () => {
    const c: ProjectedContact = { contactId: 'a'.repeat(32), identities: [{ pubkey: 'b'.repeat(64) }], blocked: true };
    const p = projection({ scopes: ['signet.contacts.blocks.read'], contacts: [c] });
    expect(parseProjection(buildProjection(p))).toEqual(p);
  });

  it('accepts each method kind under its own capability', () => {
    const c: ProjectedContact = { contactId: 'a'.repeat(32), contactMethods: [{ kind: 'postal-address', value: '1 High St' }] };
    const p = projection({ scopes: [DIR, 'signet.contacts.read:method:postal-address'], contacts: [c] });
    expect(parseProjection(buildProjection(p))).toEqual(p);
  });

  it('refuses the whole projection, not just the offending contact', () => {
    const json = JSON.stringify({ ...projection(), scopes: [DIR], contacts: [
      { contactId: 'a'.repeat(32), displayName: 'Fine' },
      { contactId: 'b'.repeat(32), effectiveTier: 'kin' },
    ] });
    expect(parseProjection(json)).toBeNull();
  });
});
