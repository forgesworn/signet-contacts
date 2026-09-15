import { describe, it, expect } from 'vitest';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { buildPairingUriV2, parsePairingRequestV2 } from './pairing.js';
import { buildPairingAckV2, parsePairingAckV2 } from './ack.js';
import { buildProjection, parseProjection } from './projection.js';
import { buildProposalBatch, parseProposalBatch } from './proposal.js';
import { projectionTag, proposalTag, scopedContactId, sanitizeWireText } from './ids.js';
import { MAX_DISPLAY_NAME } from './constants.js';
import type { ContactProjectionV2, ContactProposalV1, PairingAckV2 } from './types.js';
import { sealVaultPayload, openVaultPayload } from './envelope.js';
import type { SealEnvelopeBackend, OpenEnvelopeBackend } from './envelope.js';
import { getPublicKey } from 'nostr-tools/pure';
import { getConversationKey, v2 as nip44v2 } from 'nostr-tools/nip44';
import { hexToBytes } from '@noble/hashes/utils.js';

const NOW = 1_700_000_000;
const GRANT = 'f'.repeat(32);
const APP = 'a'.repeat(64);
const RAIL = 'b'.repeat(64);
const OWNER = '1'.repeat(64);
const DEVICE = '2'.repeat(32);
const CHALLENGE = 'D'.repeat(32);
const WRITE = process.env.WRITE_VECTORS === '1';

function frozen(path: string, actual: unknown): void {
  mkdirSync('vectors', { recursive: true });
  const json = `${JSON.stringify(actual, null, 2)}\n`;
  if (WRITE || !existsSync(path)) {
    writeFileSync(path, json, 'utf8');
    return;
  }
  expect(readFileSync(path, 'utf8')).toBe(json);
}

describe('vectors', () => {
  it('freezes the pairing request and ack', () => {
    const uri = buildPairingUriV2({
      appPubkey: APP, appName: 'Flock',
      capabilities: ['signet.contacts.read:directory', 'signet.contacts.blocks.read', 'signet.contacts.propose:add-ken'],
      directory: 'owner', relay: 'wss://relay.example.com', nowSec: NOW, challenge: CHALLENGE,
    });
    const ack: PairingAckV2 = {
      v: 2, grantId: GRANT, railPubkey: RAIL,
      projectionTag: projectionTag(GRANT), proposalTag: proposalTag(GRANT, APP),
      relay: 'wss://relay.example.com',
      grantedCapabilities: ['signet.contacts.read:directory', 'signet.contacts.blocks.read'],
      maxStalenessSeconds: 21600, challenge: CHALLENGE,
    };
    const ackPlaintext = buildPairingAckV2(ack);
    expect(parsePairingRequestV2(uri, { nowSec: NOW }).request).not.toBeNull();
    expect(parsePairingAckV2(ackPlaintext, CHALLENGE)).toEqual(ack);

    frozen('vectors/pairing.v2.json', {
      description: 'Capability-scoped v2 pairing request, and the Signet ack that narrows it',
      nowSec: NOW,
      request: { uri, parsed: parsePairingRequestV2(uri, { nowSec: NOW }).request },
      ack: {
        plaintext: ackPlaintext,
        parsed: ack,
        v1Plaintext: '{"v":1,"railPubkey":"' + RAIL + '","dTag":"signet:companion-rail","snapshotRelay":"wss://relay.example.com","grantedScope":{"tiers":["kin"],"personas":"all"},"challenge":"' + CHALLENGE + '"}',
        wrongChallenge: 'E'.repeat(32),
      },
      tags: { projectionTag: projectionTag(GRANT), proposalTag: proposalTag(GRANT, APP) },
    });
  });

  it('freezes a full projection, a blocks-only projection and a revocation', () => {
    const full: ContactProjectionV2 = {
      v: 2, grantId: GRANT, ownerPubkey: OWNER,
      scopes: ['signet.contacts.read:directory', 'signet.contacts.read:roles', 'signet.contacts.blocks.read'],
      frontier: { maxClock: 42, opCount: 137, publishedAt: NOW, deviceId: DEVICE }, issuedAt: NOW, expiresAt: NOW + 21600,
      contacts: [
        {
          contactId: scopedContactId(GRANT, 'contact-ada'), type: 'person',
          identities: [{ pubkey: 'c'.repeat(64), verification: 'proven' }],
          displayName: 'Ada', effectiveTier: 'kith', tierSource: 'direct',
          roles: ['coach'], blocked: false,
        },
        {
          contactId: scopedContactId(GRANT, 'contact-mallory'), type: 'person',
          identities: [{ pubkey: 'd'.repeat(64), verification: 'proven' }],
          effectiveTier: 'none', tierSource: 'guardian-limited',
          blocked: true, linkedPubkeys: ['e'.repeat(64)],
        },
      ],
    };
    const blocksOnly: ContactProjectionV2 = {
      ...full,
      scopes: ['signet.contacts.blocks.read'],
      contacts: [full.contacts[1]!],
    };
    const revocation: ContactProjectionV2 = { ...full, contacts: [], revoked: true };
    // R-5: a producer that had to drop contacts to fit says so on the wire.
    const truncated: ContactProjectionV2 = { ...full, contacts: [full.contacts[0]!], truncated: true };

    for (const p of [full, blocksOnly, revocation, truncated]) {
      expect(parseProjection(buildProjection(p))).toEqual(p);
    }

    frozen('vectors/projection.v2.json', {
      description: 'ContactProjectionV2 at full scope, at blocks-only scope, truncated, and as a revocation',
      full: { plaintext: buildProjection(full), parsed: full },
      blocksOnly: { plaintext: buildProjection(blocksOnly), parsed: blocksOnly },
      revocation: { plaintext: buildProjection(revocation), parsed: revocation },
      truncated: { plaintext: buildProjection(truncated), parsed: truncated },
      malformed: [
        '{"v":1,"grantId":"' + GRANT + '"}',
        '{"v":2,"grantId":"short","ownerPubkey":"' + OWNER + '","scopes":[],"frontier":{"maxClock":1,"opCount":1,"publishedAt":1,"deviceId":"' + DEVICE + '"},"issuedAt":1,"expiresAt":2,"contacts":[]}',
        '[]',
      ],
    });
  });

  it('freezes a proposal batch', () => {
    const proposals: ContactProposalV1[] = [
      {
        v: 1, grantId: GRANT, operationId: '9'.repeat(32), action: 'add-ken',
        value: { pubkey: 'c'.repeat(64), displayName: 'Ada' }, createdAt: NOW,
      },
      {
        // R-7 (post-dates this brief's original draft — see task-8):
        // `RenameAppLabelValue.updatedAt` is required (ms epoch), so a value
        // literal without it does not typecheck and would be silently
        // rewritten in transit; NOW is a seconds epoch elsewhere on this
        // wire, so the ms equivalent is `NOW * 1000`.
        v: 1, grantId: GRANT, operationId: '8'.repeat(32), action: 'rename-app-label',
        value: { contactId: scopedContactId(GRANT, 'contact-ada'), label: 'Coach', updatedAt: NOW * 1000 }, createdAt: NOW,
      },
    ];
    const plaintext = buildProposalBatch(proposals);
    expect(parseProposalBatch(plaintext)?.proposals).toEqual(proposals);

    frozen('vectors/proposal.v1.json', {
      description: 'Proposal batch carrying one add-ken and one rename-app-label',
      batch: { plaintext, parsed: { v: 1, proposals } },
      malformed: [
        '{"v":2,"proposals":[]}',
        '{"v":1}',
        '{"v":1,"proposals":[{"v":1,"grantId":"' + GRANT + '","operationId":"short","action":"add-ken","value":{"pubkey":"' + 'c'.repeat(64) + '","displayName":"Ada"},"createdAt":' + NOW + '}]}',
      ],
    });
  });

  it('freezes the sanitiser, which BOTH repositories must agree on', () => {
    // R-6. The producer (signet-app's projection builder) and the parser (this
    // package) run the SAME function, so this file is what proves a future
    // edit to either side did not quietly change the class. signet-app asserts
    // against this exact file in `contacts-sdk-smoke.test.ts`.
    const cases = [
      '  Sam  ',
      'Ada‮eda',
      'Ada​Bo',
      'line\nbreak',
      'tab\tted',
      ' ',
      '⁦isolate⁩',
      'x'.repeat(MAX_DISPLAY_NAME + 20),
      '',
      '   ',
      '🜂 sigil',
    ];
    const pairs = cases.map((input) => ({ input, output: sanitizeWireText(input, MAX_DISPLAY_NAME) }));
    // A spot-check, so a regenerated file that is wrong still fails here.
    expect(pairs[0]?.output).toBe('Sam');
    expect(pairs[1]?.output).toBe('Adaeda');
    expect(pairs[7]?.output).toHaveLength(MAX_DISPLAY_NAME);
    expect(pairs[9]?.output).toBe('');

    frozen('vectors/sanitise.json', {
      description: 'sanitizeWireText: the one sanitiser on this wire. Producer and parser must agree byte for byte.',
      maxLen: MAX_DISPLAY_NAME,
      pairs,
    });
  });

  it('freezes a sealed vault envelope, opened by the SDK\'s own openVaultPayload with real NIP-44', async () => {
    // R-4 addition (controller ruling). Everything above this line exercises
    // this package's own JSON framing; this vector proves the SDK can open a
    // vault envelope end to end with the REAL cryptographic primitives
    // (`nostr-tools/nip44` `v2.encrypt`/`v2.decrypt` + `getConversationKey`),
    // not the fake reversible backend `envelope.test.ts` uses to isolate the
    // padding/framing logic from the crypto.
    //
    // TEST KEYS ONLY. Generated once with `nostr-tools`'s `generateSecretKey()`
    // and hardcoded here so the vector is reproducible byte-for-byte on every
    // run — they are not derived from anything real and must never be reused
    // for anything but this frozen fixture.
    const ENVELOPE_RAIL_SK_HEX = 'ca40240ab6c15508af98172ea2d3a31d510889672cc9e87a73d489374fcd66a6';
    const ENVELOPE_APP_SK_HEX = '8d31dddf1d96f947489c7ec3ee1a042fc7a1a0b5014c1c78ea50699388643216';
    const railSecretKey = hexToBytes(ENVELOPE_RAIL_SK_HEX);
    const appSecretKey = hexToBytes(ENVELOPE_APP_SK_HEX);
    const railPubkey = getPublicKey(railSecretKey);
    const appPubkey = getPublicKey(appSecretKey);

    // Fixed 32-byte NIP-44 nonce. `v2.encrypt` otherwise draws a fresh random
    // nonce per call (correct for production, but this vector must reproduce
    // byte-for-byte on every regeneration) — TEST-ONLY, never reused outside
    // this fixture.
    const NIP44_TEST_NONCE = hexToBytes('11'.repeat(32));

    function realSealBackend(mySecretKey: Uint8Array): SealEnvelopeBackend {
      return {
        async nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string> {
          const conversationKey = getConversationKey(mySecretKey, peerPubkey);
          return nip44v2.encrypt(plaintext, conversationKey, NIP44_TEST_NONCE);
        },
      };
    }
    function realOpenBackend(mySecretKey: Uint8Array): OpenEnvelopeBackend {
      return {
        async nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string> {
          const conversationKey = getConversationKey(mySecretKey, peerPubkey);
          return nip44v2.decrypt(ciphertext, conversationKey);
        },
      };
    }

    // Deterministic injected randomness for `sealVaultPayload`'s content key
    // and IV (`opts.random`) — a fresh xorshift32 stream from a fixed seed,
    // so two independent seal calls with a freshly constructed generator
    // produce byte-identical output.
    function makeDeterministicRandom(seed: number): (bytes: number) => Uint8Array {
      let state = seed >>> 0;
      return (n: number) => {
        const out = new Uint8Array(n);
        for (let i = 0; i < n; i++) {
          state ^= state << 13; state >>>= 0;
          state ^= state >>> 17; state >>>= 0;
          state ^= state << 5; state >>>= 0;
          out[i] = state & 0xff;
        }
        return out;
      };
    }
    const SEED = 0x5e17ed42;

    const plaintext = JSON.stringify({ hello: 'signet-contacts vector', grantId: GRANT });

    const sealed = await sealVaultPayload(
      plaintext,
      realSealBackend(railSecretKey),
      appPubkey,
      { random: makeDeterministicRandom(SEED) },
    );
    expect(sealed).not.toBeNull();
    const parsed = JSON.parse(sealed!);

    // The SDK's own openVaultPayload, exercised with real NIP-44, must
    // recover the exact plaintext.
    const opened = await openVaultPayload(sealed!, realOpenBackend(appSecretKey), railPubkey);
    expect(opened).toBe(plaintext);

    // Re-sealing with a fresh instance of the same deterministic randomness
    // reproduces `sealed` byte-for-byte.
    const resealed = await sealVaultPayload(
      plaintext,
      realSealBackend(railSecretKey),
      appPubkey,
      { random: makeDeterministicRandom(SEED) },
    );
    expect(resealed).toBe(sealed);

    frozen('vectors/envelope.v2.json', {
      description: 'A v2 vault envelope sealed and opened with real NIP-44 (nostr-tools v2.encrypt/decrypt + getConversationKey), under injected deterministic randomness for the content key/IV and a fixed inner NIP-44 nonce, so the fixture is byte-identical on every regeneration.',
      note: 'railSecretKey and appSecretKey are TEST KEYS ONLY, generated once and hardcoded for reproducibility. Never reuse them for anything real.',
      railSecretKey: ENVELOPE_RAIL_SK_HEX,
      appSecretKey: ENVELOPE_APP_SK_HEX,
      railPubkey,
      appPubkey,
      plaintext,
      sealed,
      parsed,
    });
  });
});
