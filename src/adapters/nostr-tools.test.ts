import { describe, it, expect, vi } from 'vitest';
import { createSimplePoolRelayIo } from './nostr-tools.js';
import type { SimplePoolLike } from './nostr-tools.js';
import type { SignedNostrEvent } from '../wire/types.js';

const EVENT: SignedNostrEvent = {
  id: '0'.repeat(64), pubkey: 'b'.repeat(64), created_at: 1, kind: 30078,
  tags: [['d', 'a'.repeat(32)]], content: 'ciphertext', sig: '1'.repeat(128),
};

describe('createSimplePoolRelayIo', () => {
  it('maps fetchNewest onto pool.get and pins the author', async () => {
    const get = vi.fn(async () => EVENT);
    const io = createSimplePoolRelayIo({ get, publish: () => [], subscribeMany: () => ({ close() {} }) });
    expect(await io.fetchNewest({ kinds: [30078] }, ['wss://r.example'], EVENT.pubkey)).toEqual(EVENT);
    expect(get).toHaveBeenCalledWith(['wss://r.example'], { kinds: [30078] });
    expect(await io.fetchNewest({ kinds: [30078] }, ['wss://r.example'], 'c'.repeat(64))).toBeNull();
  });

  it('returns null when the pool throws or answers with a non-event', async () => {
    const throwing = createSimplePoolRelayIo({
      get: async () => { throw new Error('offline'); }, publish: () => [], subscribeMany: () => ({ close() {} }),
    });
    expect(await throwing.fetchNewest({ kinds: [30078] }, ['wss://r.example'])).toBeNull();
    const junk = createSimplePoolRelayIo({
      get: async () => ({ not: 'an event' }), publish: () => [], subscribeMany: () => ({ close() {} }),
    });
    expect(await junk.fetchNewest({ kinds: [30078] }, ['wss://r.example'])).toBeNull();
  });

  it('resolves publish true when at least one relay accepts', async () => {
    const io = createSimplePoolRelayIo({
      get: async () => null,
      publish: () => [Promise.reject(new Error('rejected')), Promise.resolve('ok')],
      subscribeMany: () => ({ close() {} }),
    });
    expect(await io.publish(EVENT, ['wss://a.example', 'wss://b.example'])).toBe(true);
  });

  it('resolves publish false when every relay rejects', async () => {
    const io = createSimplePoolRelayIo({
      get: async () => null,
      publish: () => [Promise.reject(new Error('no'))],
      subscribeMany: () => ({ close() {} }),
    });
    expect(await io.publish(EVENT, ['wss://a.example'])).toBe(false);
  });

  it('forwards only well-formed events to a subscriber and closes cleanly', () => {
    const close = vi.fn();
    let emit: ((e: unknown) => void) | null = null;
    const io = createSimplePoolRelayIo({
      get: async () => null, publish: () => [],
      subscribeMany: (_relays, _filter, params) => { emit = params.onevent; return { close }; },
    });
    const seen: SignedNostrEvent[] = [];
    const stop = io.subscribe!({ kinds: [30078] }, ['wss://r.example'], (e) => seen.push(e));
    emit!({ junk: true });
    emit!(EVENT);
    expect(seen).toEqual([EVENT]);
    stop();
    expect(close).toHaveBeenCalledTimes(1);
  });

  it('picks the newest event across relays when they disagree', async () => {
    const older: SignedNostrEvent = { ...EVENT, id: '1'.repeat(64), created_at: 3 };
    const newer: SignedNostrEvent = { ...EVENT, id: '2'.repeat(64), created_at: 5 };
    const get = vi.fn(async (relays: string[]) => (relays[0] === 'wss://a.example' ? older : newer));
    const io = createSimplePoolRelayIo({ get, publish: () => [], subscribeMany: () => ({ close() {} }) });
    const result = await io.fetchNewest(
      { kinds: [30078] }, ['wss://a.example', 'wss://b.example'], EVENT.pubkey,
    );
    expect(result).toEqual(newer);
    expect(get).toHaveBeenNthCalledWith(1, ['wss://a.example'], { kinds: [30078] });
    expect(get).toHaveBeenNthCalledWith(2, ['wss://b.example'], { kinds: [30078] });
  });

  it('breaks a same-created_at tie by the lowest id', async () => {
    const highId: SignedNostrEvent = { ...EVENT, id: 'f'.repeat(64), created_at: 5 };
    const lowId: SignedNostrEvent = { ...EVENT, id: '0'.repeat(64), created_at: 5 };
    const get = vi.fn(async (relays: string[]) => (relays[0] === 'wss://a.example' ? highId : lowId));
    const io = createSimplePoolRelayIo({ get, publish: () => [], subscribeMany: () => ({ close() {} }) });
    const result = await io.fetchNewest(
      { kinds: [30078] }, ['wss://a.example', 'wss://b.example'], EVENT.pubkey,
    );
    expect(result).toEqual(lowId);
  });

  it('bounds fetchNewest to timeoutMs and resolves null on a stalling relay, clearing the timer', async () => {
    vi.useFakeTimers();
    try {
      const get = vi.fn(() => new Promise<never>(() => {}));
      const io = createSimplePoolRelayIo(
        { get, publish: () => [], subscribeMany: () => ({ close() {} }) }, { timeoutMs: 5000 },
      );
      const pending = io.fetchNewest({ kinds: [30078] }, ['wss://r.example']);
      await vi.advanceTimersByTimeAsync(5000);
      expect(await pending).toBeNull();
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('clears the timer immediately when a relay answers before the timeout', async () => {
    vi.useFakeTimers();
    try {
      const get = vi.fn(async () => EVENT);
      const io = createSimplePoolRelayIo(
        { get, publish: () => [], subscribeMany: () => ({ close() {} }) }, { timeoutMs: 5000 },
      );
      const result = await io.fetchNewest({ kinds: [30078] }, ['wss://r.example'], EVENT.pubkey);
      expect(result).toEqual(EVENT);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('bounds publish to timeoutMs and resolves false when every relay stalls, clearing the timer', async () => {
    vi.useFakeTimers();
    try {
      const io = createSimplePoolRelayIo(
        {
          get: async () => null,
          publish: () => [new Promise<never>(() => {})],
          subscribeMany: () => ({ close() {} }),
        },
        { timeoutMs: 4000 },
      );
      const pending = io.publish(EVENT, ['wss://a.example']);
      await vi.advanceTimersByTimeAsync(4000);
      expect(await pending).toBe(false);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('resolves publish true when one relay answers before the timeout and another stalls', async () => {
    vi.useFakeTimers();
    try {
      const io = createSimplePoolRelayIo(
        {
          get: async () => null,
          publish: () => [new Promise<never>(() => {}), Promise.resolve('ok')],
          subscribeMany: () => ({ close() {} }),
        },
        { timeoutMs: 4000 },
      );
      const pending = io.publish(EVENT, ['wss://a.example', 'wss://b.example']);
      await vi.advanceTimersByTimeAsync(4000);
      expect(await pending).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it('throws synchronously for a relay URL that is neither wss:// nor loopback ws://', () => {
    const io = createSimplePoolRelayIo({
      get: async () => null, publish: () => [], subscribeMany: () => ({ close() {} }),
    });
    expect(() => io.fetchNewest({ kinds: [30078] }, ['http://evil.example'])).toThrow(TypeError);
    expect(() => io.publish(EVENT, ['ws://evil.example'])).toThrow(TypeError);
    expect(() => io.subscribe!({ kinds: [30078] }, ['ws://192.168.1.1'], () => {})).toThrow(TypeError);
  });

  it('accepts wss:// and loopback ws:// relays', async () => {
    const get = vi.fn(async () => null);
    const io = createSimplePoolRelayIo({ get, publish: () => [], subscribeMany: () => ({ close() {} }) });
    await expect(io.fetchNewest({ kinds: [30078] }, ['ws://localhost:4869'])).resolves.toBeNull();
    await expect(io.fetchNewest({ kinds: [30078] }, ['ws://127.0.0.1:4869'])).resolves.toBeNull();
    await expect(io.fetchNewest({ kinds: [30078] }, ['wss://relay.example'])).resolves.toBeNull();
  });

  // Residuals fix #2: `SimplePoolLike` is structurally typed precisely so a
  // caller isn't forced to import nostr-tools — a pool that satisfies the
  // shape but resolves SYNCHRONOUSLY (a plain non-thenable return, not a
  // real `Promise`) must not make `raceTimeout` reject or leak its timer.
  it('never rejects, and clears the timer, when the pool returns a synchronous non-promise value', async () => {
    vi.useFakeTimers();
    try {
      const syncPool: SimplePoolLike = {
        // Cast is deliberate: this is exactly the "satisfies the shape but
        // lies about being async" case the fix is for.
        get: (() => EVENT) as unknown as SimplePoolLike['get'],
        publish: (() => [EVENT.id]) as unknown as SimplePoolLike['publish'],
        subscribeMany: () => ({ close() {} }),
      };
      const io = createSimplePoolRelayIo(syncPool, { timeoutMs: 5000 });
      await expect(io.fetchNewest({ kinds: [30078] }, ['wss://r.example'], EVENT.pubkey))
        .resolves.toEqual(EVENT);
      expect(vi.getTimerCount()).toBe(0);
      await expect(io.publish(EVENT, ['wss://r.example'])).resolves.toBe(true);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});
