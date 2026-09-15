import { describe, it, expect, vi } from 'vitest';
import { createSimplePoolRelayIo } from './nostr-tools.js';
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
});
