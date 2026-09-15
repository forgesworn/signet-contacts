import { describe, it, expect, vi } from 'vitest';
import {
  BUCKETS, TOP_BUCKET, LENGTH_PREFIX_BYTES, MAX_ENVELOPE_CHARS,
  padToBucket, unpad, parseVaultEnvelope, sealVaultPayload, openVaultPayload,
} from './envelope.js';
import type { SealEnvelopeBackend, OpenEnvelopeBackend, VaultEnvelope } from './envelope.js';

const SENDER = 'a'.repeat(64);
const RECIPIENT = 'b'.repeat(64);

/**
 * A fake, reversible NIP-44: the envelope treats `k`'s ciphertext as opaque
 * and never itself checks who a peer argument names (that policing — pinning
 * `senderPubkey`/`recipientPubkey` to a real key — is the CALLER's job,
 * exercised at the client level in `client.test.ts`, not here). This file
 * tests the envelope format itself: padding, parsing, AES-GCM, tamper
 * rejection and zeroisation, all of which are exercised the same way
 * regardless of which peer argument a call carries.
 */
function fakeBackend(overrides: Partial<SealEnvelopeBackend & OpenEnvelopeBackend> = {}) {
  return {
    nip44Encrypt: vi.fn(async (_peer: string, plaintext: string) => btoa(plaintext)),
    nip44Decrypt: vi.fn(async (_peer: string, ciphertext: string) => atob(ciphertext)),
    ...overrides,
  };
}

const ascii = (n: number) => 'x'.repeat(n);

function flipBase64Byte(b64: string): string {
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  bytes[0] = (bytes[0] ?? 0) ^ 0x01;
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

describe('BUCKETS', () => {
  it('is the power-of-two ladder from 4 KiB to 64 KiB', () => {
    expect([...BUCKETS]).toEqual([4096, 8192, 16384, 32768, 65536]);
    expect(TOP_BUCKET).toBe(65536);
    expect(LENGTH_PREFIX_BYTES).toBe(4);
    expect(MAX_ENVELOPE_CHARS).toBe(100_000);
  });
});

describe('padToBucket / unpad', () => {
  it('round-trips every bucket, including the top', () => {
    for (const bucket of BUCKETS) {
      const body = ascii(bucket - LENGTH_PREFIX_BYTES);
      const padded = padToBucket(body)!;
      expect(padded.length).toBe(bucket);
      expect(unpad(padded)).toBe(body);
    }
  });

  it('returns null above the top bucket rather than truncating', () => {
    expect(padToBucket(ascii(TOP_BUCKET - LENGTH_PREFIX_BYTES))).not.toBeNull();
    expect(padToBucket(ascii(TOP_BUCKET - LENGTH_PREFIX_BYTES + 1))).toBeNull();
  });

  it('rejects a truncated buffer and a length prefix past the end', () => {
    expect(unpad(new Uint8Array(3))).toBeNull();
    const bad = new Uint8Array(16);
    new DataView(bad.buffer).setUint32(0, 999, false);
    expect(unpad(bad)).toBeNull();
  });
});

describe('parseVaultEnvelope', () => {
  it('accepts a well-formed envelope', () => {
    const raw = { v: 2, k: 'a', iv: 'b', ct: 'c', b: 4096 };
    expect(parseVaultEnvelope(JSON.stringify(raw))).toEqual(raw);
  });

  it('rejects malformed shapes', () => {
    expect(parseVaultEnvelope('not json')).toBeNull();
    expect(parseVaultEnvelope('[]')).toBeNull();
    expect(parseVaultEnvelope(JSON.stringify({ v: 1, k: 'a', iv: 'b', ct: 'c', b: 4096 }))).toBeNull();
    expect(parseVaultEnvelope(JSON.stringify({ v: 2, k: 1, iv: 'b', ct: 'c', b: 4096 }))).toBeNull();
    expect(parseVaultEnvelope(JSON.stringify({ v: 2, k: 'a', iv: 'b', ct: 'c', b: 5000 }))).toBeNull();
  });

  // C1: the cap is checked BEFORE JSON.parse — a hostile relay must not be
  // able to buy a large parse with an oversized `content` string.
  it('refuses an oversized content string before parsing it', () => {
    const huge = `{"v":2,"k":"${'a'.repeat(MAX_ENVELOPE_CHARS)}","iv":"b","ct":"c","b":4096}`;
    expect(huge.length).toBeGreaterThan(MAX_ENVELOPE_CHARS);
    expect(parseVaultEnvelope(huge)).toBeNull();
  });
});

describe('sealVaultPayload / openVaultPayload', () => {
  it('round-trips a small payload and wraps only the 32-byte key', async () => {
    const backend = fakeBackend();
    const sealed = (await sealVaultPayload('{"hello":"world"}', backend, RECIPIENT))!;
    expect(sealed).not.toBeNull();
    const envelope = parseVaultEnvelope(sealed)!;
    expect(envelope.v).toBe(2);
    expect(envelope.b).toBe(4096);
    const wrappedArg = backend.nip44Encrypt.mock.calls[0]![1] as string;
    expect(atob(wrappedArg).length).toBe(32);
    expect(backend.nip44Encrypt.mock.calls[0]![0]).toBe(RECIPIENT);
    expect(await openVaultPayload(sealed, backend, SENDER)).toBe('{"hello":"world"}');
  });

  it('round-trips at every bucket boundary, including the top', async () => {
    const backend = fakeBackend();
    for (const bucket of BUCKETS) {
      const body = 'y'.repeat(bucket - LENGTH_PREFIX_BYTES);
      const sealed = (await sealVaultPayload(body, backend, RECIPIENT))!;
      expect(parseVaultEnvelope(sealed)!.b).toBe(bucket);
      expect(await openVaultPayload(sealed, backend, SENDER)).toBe(body);
    }
  });

  it('returns null above the top bucket rather than truncating, without touching the backend', async () => {
    const backend = fakeBackend();
    expect(await sealVaultPayload('z'.repeat(TOP_BUCKET), backend, RECIPIENT)).toBeNull();
    expect(backend.nip44Encrypt).not.toHaveBeenCalled();
  });

  it('honours an explicit lower ceiling', async () => {
    const backend = fakeBackend();
    expect(await sealVaultPayload('z'.repeat(5000), backend, RECIPIENT, { maxBucket: 4096 })).toBeNull();
    expect(await sealVaultPayload('z'.repeat(100), backend, RECIPIENT, { maxBucket: 4096 })).not.toBeNull();
  });

  // Residuals fix #4, matching the app's Task 23 `activePublicKeyHex` guard.
  it('refuses a recipientPubkey that is not strict lowercase 64-hex, without touching the backend', async () => {
    for (const bad of ['', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'z'.repeat(64), 'nostr:npub1x']) {
      const backend = fakeBackend();
      expect(await sealVaultPayload('refuse me', backend, bad)).toBeNull();
      expect(backend.nip44Encrypt).not.toHaveBeenCalled();
    }
  });

  it('uses fresh content key material and IV per seal', async () => {
    const backend = fakeBackend();
    const first = parseVaultEnvelope((await sealVaultPayload('same', backend, RECIPIENT))!)!;
    const second = parseVaultEnvelope((await sealVaultPayload('same', backend, RECIPIENT))!)!;
    expect(first.k).not.toBe(second.k);
    expect(first.iv).not.toBe(second.iv);
    expect(first.ct).not.toBe(second.ct);
  });

  it('accepts injected randomness for a deterministic seal (vector generation)', async () => {
    const backend = fakeBackend();
    const fixed = (n: number) => new Uint8Array(n).fill(7);
    const a = await sealVaultPayload('deterministic', backend, RECIPIENT, { random: fixed });
    const b = await sealVaultPayload('deterministic', backend, RECIPIENT, { random: fixed });
    expect(a).toBe(b);
  });

  // C2 / no-throw-on-garbage.
  it('never throws on garbage content, returning null instead', async () => {
    const backend = fakeBackend();
    for (const garbage of ['', 'not json', '{}', '[]', 'null', '"x"', '12345', '{"v":2}']) {
      await expect(openVaultPayload(garbage, backend, SENDER)).resolves.toBeNull();
    }
  });

  it('refuses an oversized content string before ever calling the backend', async () => {
    const backend = fakeBackend();
    const huge = 'z'.repeat(MAX_ENVELOPE_CHARS + 1);
    expect(await openVaultPayload(huge, backend, SENDER)).toBeNull();
    expect(backend.nip44Decrypt).not.toHaveBeenCalled();
  });

  describe('tamper rejection', () => {
    async function sealedEnvelope(backend: ReturnType<typeof fakeBackend>): Promise<VaultEnvelope> {
      return parseVaultEnvelope((await sealVaultPayload('tamper target', backend, RECIPIENT))!)!;
    }

    it('rejects a flipped ciphertext byte', async () => {
      const backend = fakeBackend();
      const e = await sealedEnvelope(backend);
      const tampered = JSON.stringify({ ...e, ct: flipBase64Byte(e.ct) });
      expect(await openVaultPayload(tampered, backend, SENDER)).toBeNull();
    });

    it('rejects a flipped IV byte', async () => {
      const backend = fakeBackend();
      const e = await sealedEnvelope(backend);
      const tampered = JSON.stringify({ ...e, iv: flipBase64Byte(e.iv) });
      expect(await openVaultPayload(tampered, backend, SENDER)).toBeNull();
    });

    it('rejects a swapped wrapped key (k) from a different envelope', async () => {
      const backend = fakeBackend();
      const mine = await sealedEnvelope(backend);
      const theirsSealed = (await sealVaultPayload('theirs', backend, RECIPIENT))!;
      const theirs = parseVaultEnvelope(theirsSealed)!;
      const tampered = JSON.stringify({ ...mine, k: theirs.k });
      expect(await openVaultPayload(tampered, backend, SENDER)).toBeNull();
    });

    it('rejects a version bump', async () => {
      const backend = fakeBackend();
      const e = await sealedEnvelope(backend);
      const tampered = JSON.stringify({ ...e, v: 3 });
      expect(await openVaultPayload(tampered, backend, SENDER)).toBeNull();
    });

    it('rejects a relabelled bucket (b), even though it is a legal ladder value', async () => {
      const backend = fakeBackend();
      const e = await sealedEnvelope(backend);
      const otherLadderBucket = BUCKETS.find((b) => b !== e.b)!;
      const tampered = JSON.stringify({ ...e, b: otherLadderBucket });
      expect(await openVaultPayload(tampered, backend, SENDER)).toBeNull();
    });

    it('rejects a wrong-length content key', async () => {
      const sealed = (await sealVaultPayload('anything', fakeBackend(), RECIPIENT))!;
      const liar = fakeBackend({ nip44Decrypt: vi.fn(async () => btoa('short')) });
      expect(await openVaultPayload(sealed, liar, SENDER)).toBeNull();
    });

    it('returns null, never throws, when the backend hands back non-string rubbish', async () => {
      const sealed = (await sealVaultPayload('anything', fakeBackend(), RECIPIENT))!;
      for (const rubbish of [{}, [], 42, null, undefined, true]) {
        const backend = fakeBackend({ nip44Decrypt: vi.fn(async () => rubbish as never) });
        expect(await openVaultPayload(sealed, backend, SENDER)).toBeNull();
      }
    });

    it('returns null when the backend throws', async () => {
      const sealed = (await sealVaultPayload('anything', fakeBackend(), RECIPIENT))!;
      const thrower = fakeBackend({ nip44Decrypt: vi.fn(async () => { throw new Error('nope'); }) });
      expect(await openVaultPayload(sealed, thrower, SENDER)).toBeNull();
    });
  });

  describe('key-material hygiene', () => {
    it('wipes the content key and the padded body after a seal', async () => {
      let capturedKey: Uint8Array | null = null;
      const random = (n: number) => {
        const arr = crypto.getRandomValues(new Uint8Array(n));
        if (n === 32) capturedKey = arr;
        return arr;
      };
      const encryptSpy = vi.spyOn(crypto.subtle, 'encrypt');
      const backend = fakeBackend();
      let paddedArg: Uint8Array;
      try {
        expect(await sealVaultPayload('wipe me', backend, RECIPIENT, { random })).not.toBeNull();
        // Captured BEFORE `mockRestore()`: restoring a spy also resets its
        // recorded `.mock.calls`/`.mock.results`, same as `mockReset()`.
        paddedArg = encryptSpy.mock.calls[0]![2] as Uint8Array;
      } finally {
        encryptSpy.mockRestore();
      }
      expect(capturedKey).not.toBeNull();
      expect(capturedKey!.every((b) => b === 0)).toBe(true);
      expect(paddedArg.length).toBe(4096);
      expect(paddedArg.every((b) => b === 0)).toBe(true);
    });

    it('wipes the unwrapped content key and the decrypted body after an open', async () => {
      const backend = fakeBackend();
      const sealed = (await sealVaultPayload('wipe me too', backend, RECIPIENT))!;
      const fromSpy = vi.spyOn(Uint8Array, 'from');
      const decryptSpy = vi.spyOn(crypto.subtle, 'decrypt');
      let decryptedBuffer: ArrayBuffer;
      let keyLength32Results: Uint8Array[];
      try {
        const opened = await openVaultPayload(sealed, backend, SENDER);
        expect(opened).toBe('wipe me too');
        // All captured BEFORE `mockRestore()` below — see the note in the
        // previous test.
        decryptedBuffer = await (decryptSpy.mock.results[0]!.value as Promise<ArrayBuffer>);
        // Every 32-byte `Uint8Array.from` result along the open path — the
        // unwrapped content key, and `importAesKeyRaw`'s own defensive copy —
        // must have been zeroed by the time the call has returned.
        keyLength32Results = fromSpy.mock.results
          .map((r) => r.value as Uint8Array)
          .filter((v) => v.length === 32);
      } finally {
        fromSpy.mockRestore();
        decryptSpy.mockRestore();
      }
      expect(keyLength32Results.length).toBeGreaterThan(0);
      for (const key of keyLength32Results) {
        expect(key.every((b) => b === 0)).toBe(true);
      }
      expect(new Uint8Array(decryptedBuffer).every((b) => b === 0)).toBe(true);
    });
  });
});
