/**
 * `RelayIo` over a nostr-tools `SimplePool`.
 *
 * Deliberately structurally typed rather than importing `SimplePool`: the
 * adapter then works across nostr-tools minor versions and, more importantly,
 * a consumer on a different client library can satisfy the same three methods
 * without pulling nostr-tools in at all. `nostr-tools` stays an OPTIONAL peer
 * dependency of this package for exactly that reason.
 */
import type { NostrFilterLike, SignedNostrEvent } from '../wire/types.js';
import type { RelayIo } from '../client.js';

export interface SimplePoolLike {
  get(relays: string[], filter: object): Promise<unknown>;
  publish(relays: string[], event: object): Promise<string>[];
  subscribeMany(relays: string[], filter: object, params: { onevent: (e: unknown) => void }): { close(): void };
}

function asSignedEvent(raw: unknown): SignedNostrEvent | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const o = raw as Record<string, unknown>;
  if (typeof o.id !== 'string' || typeof o.pubkey !== 'string' || typeof o.sig !== 'string') return null;
  if (typeof o.kind !== 'number' || typeof o.created_at !== 'number' || typeof o.content !== 'string') return null;
  if (!Array.isArray(o.tags)) return null;
  return {
    id: o.id, pubkey: o.pubkey, sig: o.sig, kind: o.kind,
    created_at: o.created_at, content: o.content, tags: o.tags as string[][],
  };
}

export function createSimplePoolRelayIo(pool: SimplePoolLike): RelayIo {
  return {
    async fetchNewest(filter: NostrFilterLike, relays: string[], author?: string) {
      let raw: unknown;
      try {
        raw = await pool.get(relays, filter as object);
      } catch {
        return null;
      }
      const event = asSignedEvent(raw);
      if (!event) return null;
      // Author pin, applied here as well as in the client: a relay is free to
      // answer with a stranger's event, and a failed decrypt downstream reads
      // as "nothing found", which is exactly what suppresses the real record.
      if (author && event.pubkey.toLowerCase() !== author.toLowerCase()) return null;
      return event;
    },

    async publish(event: SignedNostrEvent, relays: string[]) {
      const results = await Promise.allSettled(pool.publish(relays, event));
      return results.some((r) => r.status === 'fulfilled');
    },

    subscribe(filter: NostrFilterLike, relays: string[], onEvent: (event: SignedNostrEvent) => void) {
      const sub = pool.subscribeMany(relays, filter as object, {
        onevent: (raw) => {
          const event = asSignedEvent(raw);
          if (event) onEvent(event);
        },
      });
      return () => { try { sub.close(); } catch { /* already closed */ } };
    },
  };
}
