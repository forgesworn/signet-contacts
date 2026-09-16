/**
 * `RelayIo` over a nostr-tools `SimplePool`.
 *
 * Deliberately structurally typed rather than importing `SimplePool`: the
 * adapter then works across nostr-tools minor versions and, more importantly,
 * a consumer on a different client library can satisfy the same three methods
 * without pulling nostr-tools in at all. `nostr-tools` stays an OPTIONAL peer
 * dependency of this package for exactly that reason.
 *
 * Bounded calls. `client.ts` only bounds its OWN polling loop
 * (`awaitPairingAck`'s `timeoutMs`) — a single `pool.get`/`pool.publish` call
 * has no bound of its own, so a relay that simply never answers hangs
 * `fetchProjection` forever. Every pool call here is now raced against
 * `timeoutMs` (default `DEFAULT_RELAY_TIMEOUT_MS`), and a stalled call reads
 * as "no answer from that relay" — the same as a rejection or a malformed
 * reply — never as a hang and never as a throw.
 */
import { isValidContactsRelayUrl } from '../wire/pairing.js';
import type { NostrFilterLike, SignedNostrEvent } from '../wire/types.js';
import type { RelayIo } from '../client.js';

export interface SimplePoolLike {
  get(relays: string[], filter: object): Promise<unknown>;
  publish(relays: string[], event: object): Promise<string>[];
  subscribeMany(relays: string[], filter: object, params: { onevent: (e: unknown) => void }): { close(): void };
  /** Optional on purpose: nostr-tools' own `SimplePool` has it, but this
   *  interface is structural so a consumer on another client library can
   *  satisfy the rest without it. Missing, `fetchMany` degrades to one `get`
   *  per relay (I3). */
  querySync?(relays: string[], filter: object): Promise<unknown[]>;
}

export interface SimplePoolRelayIoOptions {
  /** Bounds every individual `pool.get` / `pool.publish` call. Default 8s. */
  timeoutMs?: number;
}

const DEFAULT_RELAY_TIMEOUT_MS = 8000;

/** `fetchMany` with no `limit` on the filter, and the ceiling on any `limit`
 *  a caller does name — a relay's answer is never trusted to be small. */
const DEFAULT_FETCH_MANY_LIMIT = 10;
const MAX_FETCH_MANY_LIMIT = 100;

/** Distinguishes "the timeout fired" from any real value a pool call could
 *  resolve to (including `undefined`/`null`), so a raced call never confuses
 *  the two. */
const TIMEOUT = Symbol('signet-contacts:relay-timeout');

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

/**
 * Defence in depth: the app-level pairing/projection flow already refuses a
 * non-`wss://` (or loopback `ws://`) relay before it ever reaches this
 * adapter (`wire/pairing.ts`'s `isValidContactsRelayUrl`, enforced in
 * `buildPairingUri`/`parsePairingUri`), but this adapter is also usable
 * directly by anyone satisfying `RelayIo`, so it enforces the same rule at
 * its own boundary rather than trusting every caller to have done so
 * upstream. A bad relay list is a caller bug, not a transient relay failure,
 * so it is thrown SYNCHRONOUSLY (before any pool call, and before an `await`
 * is even reachable) rather than resolved away as `null`/`false` — the two
 * failure modes should not look the same to the caller.
 */
function assertValidRelays(relays: string[]): void {
  for (const relay of relays) {
    if (!isValidContactsRelayUrl(relay)) {
      throw new TypeError(`signet-contacts: relay must be wss:// or ws://localhost|127.0.0.1, got "${relay}"`);
    }
  }
}

/** Races `factory()` (called synchronously, so a factory that throws
 *  synchronously is treated the same as one that rejects) against `ms`.
 *  Never rejects: resolves the settled value, or `TIMEOUT`. The timer is
 *  always cleared as soon as the race is decided, on every path. */
function raceTimeout<T>(factory: () => Promise<T>, ms: number): Promise<T | typeof TIMEOUT> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(TIMEOUT), ms);
    try {
      // `Promise.resolve(...)`, not a bare `.then` on
      // whatever `factory()` returned. `factory`'s TYPE says `Promise<T>`,
      // but a `SimplePoolLike` is structurally typed precisely so a caller
      // can hand in anything satisfying the shape — including a pool whose
      // `get`/publish entry resolves synchronously and returns a plain,
      // non-thenable value. Calling `.then` directly on that would throw
      // ("x.then is not a function"), and that throw happens OUTSIDE this
      // `try` in the previous version, so it escaped as a rejection AND left
      // `timer` running forever. `Promise.resolve` coerces any value —
      // thenable or not — into a real promise first, so `.then` is always
      // safe, and the whole thing stays inside this `try` as a second line
      // of defence.
      Promise.resolve(factory()).then(
        (value) => { clearTimeout(timer); resolve(value); },
        () => { clearTimeout(timer); resolve(TIMEOUT); },
      );
    } catch {
      clearTimeout(timer);
      resolve(TIMEOUT);
    }
  });
}

export function createSimplePoolRelayIo(pool: SimplePoolLike, opts: SimplePoolRelayIoOptions = {}): RelayIo {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_RELAY_TIMEOUT_MS;

  async function doFetchNewest(
    filter: NostrFilterLike, relays: string[], author?: string,
  ): Promise<SignedNostrEvent | null> {
    // One `get` per relay, not one `get` given the whole relay set: a single
    // combined call would trust whichever answer the pool's own internal
    // merge happened to prefer. Querying per relay lets THIS adapter pick the
    // newest across them deterministically, rather than trusting the pool.
    const raws = await Promise.all(
      relays.map((relay) => raceTimeout(() => pool.get([relay], filter as object), timeoutMs)),
    );
    let best: SignedNostrEvent | null = null;
    for (const raw of raws) {
      if (raw === TIMEOUT) continue;
      const event = asSignedEvent(raw);
      if (!event) continue;
      // Author pin, applied here as well as in the client: a relay is free to
      // answer with a stranger's event, and a failed decrypt downstream reads
      // as "nothing found", which is exactly what suppresses the real record.
      if (author && event.pubkey.toLowerCase() !== author.toLowerCase()) continue;
      // Newest by created_at; a same-second tie breaks on the LOWEST id so
      // every reader picks the same winner from the same relay answers
      // without needing a second signal to agree on.
      if (
        best === null
        || event.created_at > best.created_at
        || (event.created_at === best.created_at && event.id < best.id)
      ) {
        best = event;
      }
    }
    return best;
  }

  /**
   * I3: several candidates for one filter, newest first. Uses the pool's own
   * `querySync` when it has one, and otherwise degrades to one `get` per relay
   * — which still beats a single combined `get`, because each relay
   * contributes its own newest candidate.
   *
   * Bounded on every axis a relay controls: each pool call is raced against
   * `timeoutMs`, results are deduped by event id, the author pin is applied
   * here as well as in the client, and the list is cut to `filter.limit` (or
   * `DEFAULT_FETCH_MANY_LIMIT` when the filter names none) before it is
   * returned — so a relay answering with ten thousand events costs the caller
   * at most `limit` decrypt attempts.
   */
  async function doFetchMany(
    filter: NostrFilterLike, relays: string[], author?: string,
  ): Promise<SignedNostrEvent[]> {
    const limit = typeof filter.limit === 'number' && Number.isInteger(filter.limit) && filter.limit > 0
      ? Math.min(filter.limit, MAX_FETCH_MANY_LIMIT)
      : DEFAULT_FETCH_MANY_LIMIT;
    const raws: unknown[] = [];
    if (typeof pool.querySync === 'function') {
      const querySync = pool.querySync.bind(pool);
      const answers = await Promise.all(
        relays.map((r) => raceTimeout(() => Promise.resolve(querySync([r], filter as object)), timeoutMs)),
      );
      for (const answer of answers) {
        if (answer === TIMEOUT || !Array.isArray(answer)) continue;
        for (const raw of answer.slice(0, MAX_FETCH_MANY_LIMIT)) raws.push(raw);
      }
    } else {
      const answers = await Promise.all(
        relays.map((r) => raceTimeout(() => pool.get([r], filter as object), timeoutMs)),
      );
      for (const answer of answers) {
        if (answer === TIMEOUT) continue;
        raws.push(answer);
      }
    }

    const byId = new Map<string, SignedNostrEvent>();
    for (const raw of raws) {
      const event = asSignedEvent(raw);
      if (!event) continue;
      if (author && event.pubkey.toLowerCase() !== author.toLowerCase()) continue;
      if (!byId.has(event.id)) byId.set(event.id, event);
    }
    // Newest first; a same-second tie breaks on the LOWEST id, the same rule
    // `doFetchNewest` uses, so both paths agree on an ordering.
    return [...byId.values()]
      .sort((a, b) => (b.created_at - a.created_at) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      .slice(0, limit);
  }

  async function doPublish(event: SignedNostrEvent, relays: string[]): Promise<boolean> {
    let publishing: Promise<string>[];
    try {
      publishing = pool.publish(relays, event);
    } catch {
      return false;
    }
    const settled = await Promise.all(publishing.map((p) => raceTimeout(() => p, timeoutMs)));
    // Any ONE relay accepting is enough: the event only needs to reach the
    // network once for a reader on any relay in the pool to eventually see
    // it, so requiring unanimity would let a single flaky relay block every
    // publish outright.
    return settled.some((r) => r !== TIMEOUT);
  }

  return {
    fetchNewest(filter: NostrFilterLike, relays: string[], author?: string) {
      assertValidRelays(relays);
      return doFetchNewest(filter, relays, author);
    },

    fetchMany(filter: NostrFilterLike, relays: string[], author?: string) {
      assertValidRelays(relays);
      return doFetchMany(filter, relays, author);
    },

    publish(event: SignedNostrEvent, relays: string[]) {
      assertValidRelays(relays);
      return doPublish(event, relays);
    },

    subscribe(filter: NostrFilterLike, relays: string[], onEvent: (event: SignedNostrEvent) => void) {
      assertValidRelays(relays);
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
