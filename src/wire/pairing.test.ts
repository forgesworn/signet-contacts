import { describe, it, expect } from 'vitest';
import { buildPairingUriV2, parsePairingRequestV2, isValidContactsRelayUrl } from './pairing.js';

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
