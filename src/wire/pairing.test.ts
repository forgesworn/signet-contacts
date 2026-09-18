import { describe, it, expect } from 'vitest';
import { buildPairingUriV2, parsePairingRequestV2, isValidContactsRelayUrl } from './pairing.js';
import {
  CAPABILITIES, CHALLENGE_HEX_CHARS, MAX_APP_NAME, MAX_PAIRING_URI_CHARS, MAX_RELAY_LEN,
} from './constants.js';

const NOW = 1_700_000_000;
const BASE = {
  appPubkey: 'a'.repeat(64),
  appName: 'Flock',
  capabilities: ['signet.contacts.read:directory', 'signet.contacts.blocks.read'] as const,
  directory: 'owner' as const,
  relay: 'wss://relay.example.com',
  nowSec: NOW,
  challenge: 'D'.repeat(32),
};

describe('buildPairingUriV2', () => {
  it('emits v=2 first and the binding parameter order', () => {
    const uri = buildPairingUriV2(BASE);
    expect(uri.startsWith('signet-grant://pair?v=2&app=')).toBe(true);
    expect(uri).toContain('&caps=signet.contacts.read%3Adirectory%2Csignet.contacts.blocks.read');
    expect(uri).toContain('&dir=owner');
    expect(uri.indexOf('&relay=')).toBeLessThan(uri.indexOf('&t='));
    expect(uri.indexOf('&t=')).toBeLessThan(uri.indexOf('&challenge='));
  });

  it('refuses a bad pubkey, relay, timestamp or challenge', () => {
    expect(() => buildPairingUriV2({ ...BASE, appPubkey: 'nope' })).toThrow(TypeError);
    expect(() => buildPairingUriV2({ ...BASE, relay: 'http://relay.example.com' })).toThrow(TypeError);
    expect(() => buildPairingUriV2({ ...BASE, nowSec: -1 })).toThrow(TypeError);
    expect(() => buildPairingUriV2({ ...BASE, challenge: 'short' })).toThrow(TypeError);
  });

  it('refuses an empty capability list', () => {
    expect(() => buildPairingUriV2({ ...BASE, capabilities: [] })).toThrow(TypeError);
  });

  it('rejects a non-lowercase app pubkey — asymmetric with the parser, intentionally', () => {
    // The builder fully controls its own output, so it never needs to normalise
    // anything it emits; an upper-case (or mixed-case) pubkey is refused outright
    // rather than silently lowercased. Contrast with parsePairingRequestV2 below,
    // which accepts and lowercases an upper-case pubkey on read.
    expect(() => buildPairingUriV2({ ...BASE, appPubkey: BASE.appPubkey.toUpperCase() })).toThrow(TypeError);
  });
});

// C-I7: `relay` and `challenge` were the two fields on this wire with no upper
// bound, and signet-app's own grants rail caps a relay at 256 characters — so
// a pairing this parser accepted could mint a grant that worked on one device
// and silently failed to reach the owner's second one. Over-bound is a parse
// failure, never a truncation: a truncated relay URL is a different relay.
// `sanitizeWireText` truncates by CODE POINT, so the check for "was this name
// truncated?" has to count the same way. Counting UTF-16 units made every
// astral character (an emoji, a sigil) look like two characters, so a name
// well inside the cap was reported truncated — and a consumer reading
// `warnings` would tell the owner their app name had been cut when it had not.
describe('name-truncated is decided by code point, like the truncation itself', () => {
  const astralName = '\u{1F702}'.repeat(MAX_APP_NAME);   // MAX_APP_NAME code points, twice that in UTF-16 units

  it('does not report truncation for a name that exactly fills the cap in code points', () => {
    expect(Array.from(astralName)).toHaveLength(MAX_APP_NAME);
    expect(astralName.length).toBe(MAX_APP_NAME * 2);
    const { request, warnings } = parsePairingRequestV2(
      buildPairingUriV2({ ...BASE, appName: astralName }), { nowSec: NOW },
    );
    expect(warnings).not.toContain('name-truncated');
    expect(Array.from(request?.appName ?? '')).toHaveLength(MAX_APP_NAME);
  });

  it('still reports truncation when a code point really was dropped', () => {
    const overLong = `${astralName}\u{1F703}`;
    const { request, warnings } = parsePairingRequestV2(
      buildPairingUriV2({ ...BASE, appName: overLong }), { nowSec: NOW },
    );
    expect(warnings).toContain('name-truncated');
    expect(Array.from(request?.appName ?? '')).toHaveLength(MAX_APP_NAME);
    // Never a split surrogate pair: the truncation itself is code-point safe.
    const withoutPairs = (request?.appName ?? '').replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, '');
    expect(/[\uD800-\uDFFF]/.test(withoutPairs)).toBe(false);
  });
});

describe('parser bounds on relay, challenge and raw input (C-I7)', () => {
  it('refuses a relay URL longer than MAX_RELAY_LEN, on the way out and the way in', () => {
    const longRelay = `wss://${'a'.repeat(MAX_RELAY_LEN)}.example`;
    expect(longRelay.length).toBeGreaterThan(MAX_RELAY_LEN);
    expect(isValidContactsRelayUrl(longRelay)).toBe(false);
    expect(() => buildPairingUriV2({ ...BASE, relay: longRelay })).toThrow(TypeError);
    const uri = buildPairingUriV2(BASE).replace(
      encodeURIComponent(BASE.relay), encodeURIComponent(longRelay),
    );
    expect(parsePairingRequestV2(uri, { nowSec: NOW }).warnings).toContain('bad-relay');
    expect(parsePairingRequestV2(uri, { nowSec: NOW }).request).toBeNull();
  });

  it('accepts a relay exactly at the cap', () => {
    const prefix = 'wss://';
    const exact = prefix + 'a'.repeat(MAX_RELAY_LEN - prefix.length);
    expect(exact).toHaveLength(MAX_RELAY_LEN);
    expect(isValidContactsRelayUrl(exact)).toBe(true);
  });

  it('requires a challenge of exactly CHALLENGE_HEX_CHARS hex characters', () => {
    expect(() => buildPairingUriV2({ ...BASE, challenge: 'a'.repeat(16) })).toThrow(TypeError);
    expect(() => buildPairingUriV2({ ...BASE, challenge: 'a'.repeat(64) })).toThrow(TypeError);
    expect(() => buildPairingUriV2({ ...BASE, challenge: 'z'.repeat(CHALLENGE_HEX_CHARS) })).toThrow(TypeError);
    expect(() => buildPairingUriV2({ ...BASE, challenge: 'A'.repeat(CHALLENGE_HEX_CHARS) })).not.toThrow();
    const short = buildPairingUriV2(BASE).replace(BASE.challenge, 'a'.repeat(16));
    expect(parsePairingRequestV2(short, { nowSec: NOW })).toEqual({ request: null, warnings: ['bad-challenge'] });
    const long = buildPairingUriV2(BASE).replace(BASE.challenge, 'a'.repeat(64));
    expect(parsePairingRequestV2(long, { nowSec: NOW })).toEqual({ request: null, warnings: ['bad-challenge'] });
  });

  it('refuses an input longer than MAX_PAIRING_URI_CHARS without parsing it', () => {
    const padded = `${buildPairingUriV2(BASE)}&pad=${'x'.repeat(MAX_PAIRING_URI_CHARS)}`;
    expect(parsePairingRequestV2(padded, { nowSec: NOW })).toEqual({ request: null, warnings: ['too-long'] });
  });
});

describe('parsePairingRequestV2', () => {
  it('round-trips a built URI', () => {
    const { request, warnings } = parsePairingRequestV2(buildPairingUriV2(BASE), { nowSec: NOW });
    expect(warnings).toEqual([]);
    expect(request).toEqual({
      v: 2,
      appPubkey: BASE.appPubkey,
      appName: 'Flock',
      capabilities: ['signet.contacts.read:directory', 'signet.contacts.blocks.read'],
      directory: 'owner',
      rendezvousRelay: BASE.relay,
      t: NOW,
      challenge: BASE.challenge,
    });
  });

  it('parses a bare query and an https carrier URL identically', () => {
    const uri = buildPairingUriV2(BASE);
    const query = uri.slice(uri.indexOf('?') + 1);
    const carrier = `https://mysignet.app/pair?${query}`;
    expect(parsePairingRequestV2(query, { nowSec: NOW }).request)
      .toEqual(parsePairingRequestV2(carrier, { nowSec: NOW }).request);
  });

  it('rejects a v1 request rather than reading it as v2', () => {
    const v1 = 'signet-grant://pair?app=' + 'a'.repeat(64) +
      '&name=Fledgling&scope=kin&relay=wss%3A%2F%2Frelay.example.com&t=' + NOW +
      '&challenge=' + 'D'.repeat(32);
    const { request, warnings } = parsePairingRequestV2(v1, { nowSec: NOW });
    expect(request).toBeNull();
    expect(warnings).toEqual(['bad-version']);
  });

  it('drops unknown capability tokens and warns', () => {
    const uri = buildPairingUriV2(BASE).replace('&caps=', '&caps=signet.contacts.read%3Aeverything%2C');
    const { request, warnings } = parsePairingRequestV2(uri, { nowSec: NOW });
    expect(warnings).toContain('caps-unknown-token');
    expect(request?.capabilities).toEqual(['signet.contacts.read:directory', 'signet.contacts.blocks.read']);
  });

  it('refuses a request with no recognised capability', () => {
    const uri = buildPairingUriV2(BASE).replace(
      '&caps=signet.contacts.read%3Adirectory%2Csignet.contacts.blocks.read',
      '&caps=nonsense',
    );
    const { request, warnings } = parsePairingRequestV2(uri, { nowSec: NOW });
    expect(request).toBeNull();
    expect(warnings).toContain('caps-empty');
  });

  it('rejects a stale timestamp on either side of now', () => {
    const uri = buildPairingUriV2(BASE);
    expect(parsePairingRequestV2(uri, { nowSec: NOW + 301 }).warnings).toEqual(['stale-timestamp']);
    expect(parsePairingRequestV2(uri, { nowSec: NOW - 301 }).warnings).toEqual(['stale-timestamp']);
  });

  it('sanitises and caps the app name, and warns when it truncated', () => {
    const uri = buildPairingUriV2({ ...BASE, appName: 'F'.repeat(120) + '‮' });
    const { request, warnings } = parsePairingRequestV2(uri, { nowSec: NOW });
    expect(request?.appName).toHaveLength(64);
    expect(request?.appName).not.toContain('‮');
    expect(warnings).toContain('name-truncated');
  });

  it('defaults an absent or unknown dir to owner and warns', () => {
    const uri = buildPairingUriV2(BASE).replace('&dir=owner', '&dir=cousin');
    const { request, warnings } = parsePairingRequestV2(uri, { nowSec: NOW });
    expect(request?.directory).toBe('owner');
    expect(warnings).toContain('bad-directory');
  });

  it('rejects a malformed input outright', () => {
    expect(parsePairingRequestV2('', { nowSec: NOW }).request).toBeNull();
    expect(parsePairingRequestV2('not a uri at all', { nowSec: NOW }).request).toBeNull();
  });

  it('lowercases an upper-case app pubkey — asymmetric with the builder, intentionally', () => {
    // The parser reads URIs it did not produce (a QR scan, a paste), so it is
    // lenient and lowercases on read; the builder above stays strict since it
    // fully controls its own output.
    const uri = buildPairingUriV2(BASE).replace(BASE.appPubkey, BASE.appPubkey.toUpperCase());
    const { request, warnings } = parsePairingRequestV2(uri, { nowSec: NOW });
    expect(request?.appPubkey).toBe(BASE.appPubkey);
    expect(warnings).toEqual([]);
  });

  it('warns and truncates when the capability list exceeds MAX_CAPABILITIES', () => {
    // Only 6 valid capability tokens exist (CAPABILITIES), so a boundary test
    // with 17 DISTINCT VALID tokens is not constructible. Per the fix-round
    // instruction this instead uses 16 raw tokens (cycling the 6 valid
    // capabilities so every one of them appears) plus a 17th, unknown, trailing
    // token, and asserts: the 17th token is sliced away by MAX_CAPABILITIES
    // before the unknown-token check runs (so 'caps-unknown-token' never
    // fires), 'caps-truncated' does fire, and the full known set survives.
    const cycled = Array.from({ length: 16 }, (_, i) => CAPABILITIES[i % CAPABILITIES.length]);
    const rawCaps = [...cycled, 'signet.contacts.read:everything'].join(',');
    const uri = buildPairingUriV2(BASE).replace(
      '&caps=signet.contacts.read%3Adirectory%2Csignet.contacts.blocks.read',
      `&caps=${encodeURIComponent(rawCaps)}`,
    );
    const { request, warnings } = parsePairingRequestV2(uri, { nowSec: NOW });
    expect(warnings).toContain('caps-truncated');
    expect(warnings).not.toContain('caps-unknown-token');
    expect(request?.capabilities).toEqual([...CAPABILITIES]);
  });
});

describe('isValidContactsRelayUrl', () => {
  it('requires wss, allowing ws only on loopback', () => {
    expect(isValidContactsRelayUrl('wss://relay.example.com')).toBe(true);
    expect(isValidContactsRelayUrl('ws://localhost:7777')).toBe(true);
    expect(isValidContactsRelayUrl('ws://127.0.0.1')).toBe(true);
    expect(isValidContactsRelayUrl('ws://evil.example.com')).toBe(false);
    expect(isValidContactsRelayUrl('https://relay.example.com')).toBe(false);
  });
});


it('drops legacy broad method access instead of converting it into new grants', () => {
  const uri = buildPairingUriV2({ ...BASE, capabilities: ['signet.contacts.read:directory', 'signet.contacts.read:method:email'] });
  const old = uri.replace('read%3Amethod%3Aemail', 'read%3Amethods');
  expect(parsePairingRequestV2(old, { nowSec: NOW }).request?.capabilities)
    .toEqual(['signet.contacts.read:directory']);
  expect(parsePairingRequestV2(uri, { nowSec: NOW }).request?.capabilities)
    .toEqual(['signet.contacts.read:directory', 'signet.contacts.read:method:email']);
});
