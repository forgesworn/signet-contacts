import { describe, it, expect } from 'vitest';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { buildPairingUriV2, parsePairingRequestV2 } from './pairing.js';
import { buildPairingAckV2, parsePairingAckV2 } from './ack.js';
import { buildProjection, parseProjection } from './projection.js';
import { buildProposalBatch, parseProposalBatch } from './proposal.js';
import { projectionTag, proposalTag, scopedContactId, sanitizeWireText } from './ids.js';
import { pairingCode } from './pairing-code.js';
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
const DEVICE = '2'.repeat(32);
const CHALLENGE = 'D'.repeat(32);
const WRITE = process.env.WRITE_VECTORS === '1';

/** Fix round 1: `JSON.stringify` does not escape non-ASCII -- a literal bidi
 *  override, zero-width character, or emoji embedded in a fixture (the whole
 *  point of `sanitise.json`) would otherwise land in the frozen file as raw
 *  UTF-8 bytes: invisible in an editor, easy to corrupt via copy-paste, and
 *  indistinguishable at a glance from a byte a reviewer actually meant to
 *  approve. This rewrites every character outside printable ASCII
 *  (U+0020-U+007E) to a backslash-u escape, one per UTF-16 code unit -- so an
 *  astral character (outside the BMP, e.g. an emoji) comes out as its
 *  surrogate pair's two escapes, which is the only way JSON can spell it.
 *
 *  Tab/newline/CR are exempted: any occurrence of one of those INSIDE a JSON
 *  string value has already been escaped textually by JSON.stringify (a
 *  literal newline in a string becomes the two ASCII characters backslash
 *  and "n"); the only raw tab/newline/CR bytes left in the stringified
 *  output are JSON.stringify's own pretty-print indentation, which must stay
 *  literal or the file stops being valid, readable JSON. Every other
 *  character JSON.stringify already escapes textually (a quote, a NUL, ...)
 *  is untouched here for the same reason -- its escaped form is already
 *  plain ASCII. */
function escapeNonAscii(json: string): string {
  let out = '';
  for (let i = 0; i < json.length; i++) {
    const code = json.charCodeAt(i);
    const literal = (code >= 0x20 && code <= 0x7e) || code === 0x09 || code === 0x0a || code === 0x0d;
    out += literal ? json[i] : `\\u${code.toString(16).padStart(4, '0')}`;
  }
  return out;
}

function frozen(path: string, actual: unknown): void {
  mkdirSync('vectors', { recursive: true });
  const json = `${escapeNonAscii(JSON.stringify(actual, null, 2))}\n`;
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
    // Every case carries ONLY fields its own scopes cover (WIRE.md §10): the
    // builder throws otherwise and the parser refuses the projection.
    const full: ContactProjectionV2 = {
      v: 2, grantId: GRANT,
      scopes: [
        'signet.contacts.read:directory', 'signet.contacts.read:method:email', 'signet.contacts.read:tier',
        'signet.contacts.read:checks', 'signet.contacts.read:check-records', 'signet.contacts.read:roles',
        'signet.contacts.blocks.read',
      ],
      frontier: { maxClock: 42, opCount: 137, publishedAt: NOW, deviceId: DEVICE }, issuedAt: NOW, expiresAt: NOW + 21600,
      contacts: [
        {
          contactId: scopedContactId(GRANT, 'contact-ada'),
          identities: [{ pubkey: 'c'.repeat(64), verification: 'proven' }],
          displayName: 'Ada', effectiveTier: 'kith', tierSource: 'direct',
          roles: ['coach'],
          contactMethods: [{ kind: 'email', value: 'ada@example.com', verification: 'proven' }],
          blocked: false,
          checks: [{ pubkey: 'c'.repeat(64), method: 'words', checkedAt: NOW * 1000 }],
        },
        {
          contactId: scopedContactId(GRANT, 'contact-mallory'),
          identities: [{ pubkey: 'd'.repeat(64), verification: 'proven' }],
          effectiveTier: 'none', tierSource: 'guardian-limited',
          blocked: true,
        },
      ],
    };
    // A blocks-only grant is a filter list: a blocked contact and its
    // identity pubkeys, nothing else.
    const blocksOnly: ContactProjectionV2 = {
      ...full,
      scopes: ['signet.contacts.blocks.read'],
      contacts: [{ contactId: scopedContactId(GRANT, 'contact-mallory'), identities: [{ pubkey: 'd'.repeat(64) }], blocked: true }],
    };
    const revocation: ContactProjectionV2 = { ...full, contacts: [], revoked: true };
    // R-5: a producer that had to drop contacts to fit says so on the wire.
    const truncated: ContactProjectionV2 = { ...full, contacts: [full.contacts[0]!], truncated: true };

    for (const p of [full, blocksOnly, revocation, truncated]) {
      expect(parseProjection(buildProjection(p))).toEqual(p);
    }

    // Each is a well-formed projection that carries one field its scopes do
    // not cover. A parser must refuse the WHOLE projection, not drop the field.
    const body = (scopes: string[], contact: Record<string, unknown>): string => JSON.stringify({
      v: 2, grantId: GRANT, scopes,
      frontier: { maxClock: 1, opCount: 1, publishedAt: 1, deviceId: DEVICE }, issuedAt: 1, expiresAt: 2,
      contacts: [{ contactId: scopedContactId(GRANT, 'contact-ada'), ...contact }],
    });
    const uncovered = [
      { reason: 'effectiveTier without signet.contacts.read:tier',
        plaintext: body(['signet.contacts.read:directory'], { displayName: 'Ada', effectiveTier: 'kith' }) },
      { reason: 'identity verification without signet.contacts.read:checks',
        plaintext: body(['signet.contacts.read:directory'], { identities: [{ pubkey: 'c'.repeat(64), verification: 'proven' }] }) },
      { reason: 'a phone method under an email-only grant',
        plaintext: body(['signet.contacts.read:directory', 'signet.contacts.read:method:email'], { contactMethods: [{ kind: 'phone', value: '+441234567890' }] }) },
      { reason: 'checks under signet.contacts.read:checks, not read:check-records',
        plaintext: body(['signet.contacts.read:directory', 'signet.contacts.read:checks'], { checks: [{ pubkey: 'c'.repeat(64), method: 'words', checkedAt: 1 }] }) },
      { reason: 'an unblocked contact under signet.contacts.blocks.read alone',
        plaintext: body(['signet.contacts.blocks.read'], { blocked: false }) },
      { reason: 'an avatar, which no capability covers',
        plaintext: body(['signet.contacts.read:directory'], { avatar: { url: 'https://x.example/a', hash: 'c'.repeat(64) } }) },
    ];
    for (const u of uncovered) expect(parseProjection(u.plaintext), u.reason).toBeNull();

    frozen('vectors/projection.v2.json', {
      description: 'ContactProjectionV2 at full scope, at blocks-only scope, truncated, and as a revocation; plus projections carrying a field their scopes do not cover, which a parser must refuse whole',
      regenerated: '2026-09-23: pre-release contract freeze (WIRE.md §10). Every case now carries only fields its scopes cover, because both the builder and the parser now enforce field coverage; the full case gains the scopes it needs and drops type and linkedPubkeys, which no capability covers; the uncovered cases are new. Earlier: 2026-09-16, ownerPubkey removed (R-31). The package has never been published; signet-app regenerates its own parity fixtures to match.',
      full: { plaintext: buildProjection(full), parsed: full },
      blocksOnly: { plaintext: buildProjection(blocksOnly), parsed: blocksOnly },
      revocation: { plaintext: buildProjection(revocation), parsed: revocation },
      truncated: { plaintext: buildProjection(truncated), parsed: truncated },
      malformed: [
        '{"v":1,"grantId":"' + GRANT + '"}',
        '{"v":2,"grantId":"short","scopes":[],"frontier":{"maxClock":1,"opCount":1,"publishedAt":1,"deviceId":"' + DEVICE + '"},"issuedAt":1,"expiresAt":2,"contacts":[]}',
        // R-31: an `ownerPubkey` a producer tries to smuggle back on is not
        // fatal — it is simply not a field of this wire, so the parser drops
        // it and the value never reaches a consumer.
        '{"v":2,"grantId":"' + GRANT + '","ownerPubkey":"' + '1'.repeat(64) + '","scopes":[],"frontier":{"maxClock":1,"opCount":1,"publishedAt":1,"deviceId":"' + DEVICE + '"},"issuedAt":1,"expiresAt":2,"contacts":[]}',
        '[]',
      ],
      uncovered,
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
    // Fix round 1: SURROGATE_BOUNDARY is 99 ASCII characters followed by
    // one astral emoji (one code point, two UTF-16 units) then more filler --
    // built so a CODE-POINT-safe cap at MAX_DISPLAY_NAME (100) keeps the 99
    // characters plus the whole emoji (its 100th code point) and drops
    // everything after, whereas a UTF-16-unit cap of the same number would
    // slice straight through the emoji's surrogate pair, leaving a lone
    // surrogate on the wire.
    const SURROGATE_BOUNDARY = `${'x'.repeat(MAX_DISPLAY_NAME - 1)}🜂yyyyy`;
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
      SURROGATE_BOUNDARY,
    ];
    const pairs = cases.map((input) => ({ input, output: sanitizeWireText(input, MAX_DISPLAY_NAME) }));
    // A spot-check, so a regenerated file that is wrong still fails here.
    expect(pairs[0]?.output).toBe('Sam');
    expect(pairs[1]?.output).toBe('Adaeda');
    expect(pairs[7]?.output).toHaveLength(MAX_DISPLAY_NAME);
    expect(pairs[9]?.output).toBe('');
    // R-ruling (fix round 1): the cap lands exactly on the surrogate-pair
    // boundary -- the whole emoji survives, the pair is never split, and
    // nothing after it (the 'yyyyy' filler) makes it through.
    const boundaryOutput = pairs[11]?.output ?? '';
    expect(boundaryOutput).toBe(`${'x'.repeat(MAX_DISPLAY_NAME - 1)}🜂`);
    expect(Array.from(boundaryOutput)).toHaveLength(MAX_DISPLAY_NAME);
    expect(/[\uD800-\uDFFF]/.test(boundaryOutput.replace(/[\uD800-\uDBFF][\uDC00-\uDFFF]/g, ''))).toBe(false);

    frozen('vectors/sanitise.json', {
      description: 'sanitizeWireText: the one sanitiser on this wire. Producer and parser must agree byte for byte.',
      maxLen: MAX_DISPLAY_NAME,
      pairs,
    });
  });

  it('freezes the pairing verification code (B1)', () => {
    // Deliberately lowercase, unlike the file-level CHALLENGE — so the next
    // case's `.toUpperCase()` actually differs from this one on the wire.
    const LOWER_CHALLENGE = CHALLENGE.toLowerCase();
    // Base case, and the SAME inputs with an uppercase challenge — the QR's
    // challenge may arrive either case, and a producer/consumer that hashed
    // it as received rather than lowercased would show two different codes
    // for what is really one pairing.
    const base = { appPubkey: APP, challenge: LOWER_CHALLENGE, grantId: GRANT, railPubkey: RAIL };
    const upperChallenge = { ...base, challenge: LOWER_CHALLENGE.toUpperCase() };
    // Found by search: a grantId that happens to produce a code with a
    // leading zero, so a regression that dropped `padStart` is caught here
    // rather than only on an unlucky run.
    const leadingZero = { ...base, grantId: 'c0000001099999999999999999999999' };
    const distinct = {
      appPubkey: '3'.repeat(64), challenge: '9'.repeat(32), grantId: '5'.repeat(32), railPubkey: '7'.repeat(64),
    };
    const cases = [
      { description: 'base case', input: base, code: pairingCode(base) },
      { description: 'same pairing, uppercase challenge — same code', input: upperChallenge, code: pairingCode(upperChallenge) },
      { description: 'a grantId chosen to produce a leading zero', input: leadingZero, code: pairingCode(leadingZero) },
      { description: 'a fully distinct pairing', input: distinct, code: pairingCode(distinct) },
    ];
    expect(cases[0]?.code).toBe(cases[1]?.code);
    expect(cases[2]?.code.startsWith('0')).toBe(true);
    for (const c of cases) expect(c.code).toMatch(/^[0-9]{6}$/);

    frozen('vectors/pairing-code.json', {
      description: 'pairingCode: a 6-digit code built from appPubkey, challenge, grantId and railPubkey (B1). Producer and consumer must agree byte for byte.',
      cases,
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

  // Fix round 1. Runs after every `frozen()` call above has written its file
  // for this test run (vitest runs `it`s within one `describe` in declaration
  // order), and reads the files back as raw BYTES rather than a decoded
  // string, so an escaping regression cannot hide behind a lenient decoder.
  it('never puts a raw non-ASCII byte or an unescaped control character in a frozen vector file', () => {
    const files = [
      'vectors/pairing.v2.json',
      'vectors/projection.v2.json',
      'vectors/proposal.v1.json',
      'vectors/sanitise.json',
      'vectors/envelope.v2.json',
      'vectors/pairing-code.json',
    ];
    for (const path of files) {
      const bytes = readFileSync(path);
      for (let i = 0; i < bytes.length; i++) {
        const byte = bytes[i]!;
        // Structural pretty-print whitespace only: tab, LF, CR.
        const isStructuralWhitespace = byte === 0x09 || byte === 0x0a || byte === 0x0d;
        expect(byte, `${path} byte ${i} (0x${byte.toString(16)}) must be < 0x80`).toBeLessThan(0x80);
        if (byte < 0x20) {
          expect(isStructuralWhitespace, `${path} byte ${i} (0x${byte.toString(16)}) is a raw control character`).toBe(true);
        }
        expect(byte, `${path} byte ${i} must not be DEL (0x7f)`).not.toBe(0x7f);
      }
    }
  });
});
