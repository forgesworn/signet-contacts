/**
 * Consumer client.
 *
 * Signing, encryption, relay I/O and storage are ALL injected. The SDK opens no
 * socket and holds no key: a consumer already has a signer (flock's
 * `FlockSigner`, stash's `StashSigner`, a NIP-46 bunker, a NIP-07 extension) and
 * a relay pool, and requiring a second one would be the single biggest barrier
 * to adoption. `./adapters/nostr-tools` supplies a `RelayIo` for apps that just
 * want the obvious one.
 *
 * The client owns exactly one thing of its own: the reduced `ContactsState`,
 * including the sticky Blocked set, persisted through `StorageIo` so an app
 * restart does not silently un-block anybody.
 *
 * S7: the pairing ack is carried by an EPHEMERAL, throwaway key the app has
 * never seen before — there is nothing to author-pin it against. The real gate
 * on an ack is that it decrypts under NIP-44 to something the app's own signer
 * can read, addressed with the app's own anti-replay challenge. A projection,
 * by contrast, is signed by a KNOWN key (the grant's rail, learned from the
 * ack) and is always author-pinned before its ciphertext is even opened.
 */
import {
  ACK_KIND, PAIRING_FRESHNESS_SECONDS, isCapability,
} from './wire/constants.js';
import type { Capability } from './wire/constants.js';
import { parsePairingAckV2, pairingFromAck } from './wire/ack.js';
import { openVaultPayload } from './wire/envelope.js';
import { isHex } from './wire/ids.js';
import { buildPairingUriV2, parsePairingRequestV2 } from './wire/pairing.js';
import { parseProjection, projectionFilter } from './wire/projection.js';
import { buildProposalBatch, draftToProposal, proposalEventTemplate } from './wire/proposal.js';
import { applyProjection, blockedSetOf, emptyContactsState, isFresh } from './wire/state.js';
import type {
  AddKenValue, ContactProjectionV2, ContactProposalDraft, ContactProposalV1, ContactsState,
  NostrFilterLike, PairingRequestV2Result, PairingUriOptionsV2, PairingV2, PendingProposal,
  RenameAppLabelValue, SignedNostrEvent, UnsignedNostrEvent,
} from './wire/types.js';

export interface ContactsSigner {
  pubkey: string;
  nip44Encrypt(peerPubkey: string, plaintext: string): Promise<string>;
  nip44Decrypt(peerPubkey: string, ciphertext: string): Promise<string>;
  signEvent(event: UnsignedNostrEvent): Promise<SignedNostrEvent>;
}

export interface RelayIo {
  fetchNewest(filter: NostrFilterLike, relays: string[], author?: string): Promise<SignedNostrEvent | null>;
  publish(event: SignedNostrEvent, relays: string[]): Promise<boolean>;
  subscribe?(filter: NostrFilterLike, relays: string[], onEvent: (event: SignedNostrEvent) => void): () => void;
}

export interface StorageIo {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
}

export interface SignetContactsClient {
  buildPairingUri(opts: Omit<PairingUriOptionsV2, 'appPubkey'>): string;
  parsePairingUri(input: string, opts?: { nowSec?: number; freshnessSeconds?: number }): PairingRequestV2Result;
  awaitPairingAck(opts: {
    challenge: string; relays: string[]; timeoutMs?: number; pollMs?: number;
    /** Controller correction 1: the app's OWN request, so a producer cannot
     *  grant a capability nobody asked for. Omitted only by a caller that
     *  chose not to enforce narrowing itself. */
    requestedCapabilities?: readonly Capability[];
  }): Promise<PairingV2 | null>;
  fetchProjection(pairing: PairingV2): Promise<ContactProjectionV2 | null>;
  getState(): ContactsState;
  getBlockedSet(): Set<string>;
  isFresh(nowSec?: number): boolean;
  propose(pairing: PairingV2, drafts: readonly ContactProposalDraft[]): Promise<boolean>;
  /**
   * R-9: proposals this client has sent that it has not yet seen applied.
   * Consumer-side state and nothing else — the producer never stores it, and
   * no byte of it is on the wire. An app renders "asked, not answered yet"
   * from `sentAt`; the SDK does not decide when that becomes "gave up".
   */
  pendingProposals(): PendingProposal[];
  onRevoked(cb: (grantId: string) => void): () => void;
  load(grantId: string): Promise<ContactsState>;
}

/** Default storage: in-memory, per client. An app that wants state to survive a
 *  restart — and every app should, because of the sticky Blocked set — passes
 *  its own. */
export function createMemoryStorage(): StorageIo {
  const map = new Map<string, string>();
  return {
    async get(key) { return map.get(key) ?? null; },
    async set(key, value) { map.set(key, value); },
  };
}

const STATE_KEY_PREFIX = 'signet-contacts:state:';
const PENDING_KEY_PREFIX = 'signet-contacts:pending:';

/** R-9 default: a week. A proposal the producer never applied is dropped
 *  rather than shown for ever — the owner may simply have said no, and there
 *  is no "declined" message on this wire by design. */
const DEFAULT_PENDING_STALENESS_SECONDS = 604_800;

const CAPABILITY_FOR_ACTION: Record<ContactProposalDraft['action'], Capability> = {
  'add-ken': 'signet.contacts.propose:add-ken',
  'rename-app-label': 'signet.contacts.propose:rename-app-label',
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => { setTimeout(resolve, ms); });
}

/**
 * Fix round 1, I2: a stored pending row is trusted no further than a wire
 * value would be — `operationId` is checked as the 32-hex id it always is
 * (`randomHex(16)`), and `value`'s shape is checked against the SAME two
 * value types the wire itself allows, per `action`.
 */
function isValidPendingProposal(candidate: unknown): candidate is PendingProposal {
  if (typeof candidate !== 'object' || candidate === null) return false;
  const o = candidate as Record<string, unknown>;
  if (!isHex(o.operationId, 32)) return false;
  if (typeof o.sentAt !== 'number' || !Number.isFinite(o.sentAt)) return false;
  if (typeof o.value !== 'object' || o.value === null) return false;
  const v = o.value as Record<string, unknown>;
  if (o.action === 'add-ken') {
    return isHex(v.pubkey, 64) && typeof v.displayName === 'string';
  }
  if (o.action === 'rename-app-label') {
    return isHex(v.contactId, 32) && typeof v.label === 'string'
      && typeof v.updatedAt === 'number' && Number.isFinite(v.updatedAt);
  }
  return false;
}

export function createSignetContactsClient(opts: {
  signer: ContactsSigner; relay: RelayIo; storage?: StorageIo; now?: () => number;
  maxPendingStalenessSeconds?: number;
  /** Controller correction 3: the clock a `rename-app-label` draft with no
   *  `updatedAt` is stamped from. Defaults to `Date.now` (ms epoch, matching
   *  `RenameAppLabelValue.updatedAt`'s documented unit) — inject it in a test
   *  so the LWW field is deterministic rather than depending on wall time. */
  nowMs?: () => number;
}): SignetContactsClient {
  const { signer, relay } = opts;
  const storage = opts.storage ?? createMemoryStorage();
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  const nowMs = opts.nowMs ?? (() => Date.now());
  const maxPendingStaleness = opts.maxPendingStalenessSeconds ?? DEFAULT_PENDING_STALENESS_SECONDS;

  let state: ContactsState = emptyContactsState();
  let pending: PendingProposal[] = [];
  const revokedListeners = new Set<(grantId: string) => void>();
  let revokedAnnounced = false;

  async function persistState(): Promise<void> {
    if (state.grantId === null) return;
    try {
      await storage.set(`${STATE_KEY_PREFIX}${state.grantId}`, JSON.stringify(state));
    } catch {
      // Storage is a convenience, not a correctness requirement — an app with a
      // full or unavailable store keeps working on in-memory state this session.
    }
  }

  /**
   * Controller correction M1: keyed off the CALLER's `grantId` (known the
   * moment a pairing exists), never `state.grantId` — which stays null until
   * the first successful `fetchProjection`. A proposal sent before that first
   * fetch is exactly the "asked, not answered yet" case R-9 exists for, and it
   * must survive a restart just as much as a proposal sent afterwards.
   */
  async function persistPending(grantId: string): Promise<void> {
    try {
      await storage.set(`${PENDING_KEY_PREFIX}${grantId}`, JSON.stringify(pending));
    } catch {
      // See persistState — storage is a convenience, not a correctness input.
    }
  }

  /**
   * R-9: an `add-ken` clears when a projection carries that pubkey; a
   * `rename-app-label` clears when the named contact is showing that label.
   * Anything older than the staleness window is given up on — the owner may
   * have declined it, and this wire has no "declined" reply by design.
   */
  function reconcilePending(projection: ContactProjectionV2, nowSec: number): void {
    const pubkeys = new Set<string>();
    const labels = new Map<string, string>();
    for (const contact of projection.contacts) {
      for (const identity of contact.identities ?? []) pubkeys.add(identity.pubkey.toLowerCase());
      if (contact.displayName !== undefined) labels.set(contact.contactId, contact.displayName);
    }
    pending = pending.filter((p) => {
      if (nowSec - p.sentAt > maxPendingStaleness) return false;
      if (p.action === 'add-ken') {
        return !pubkeys.has((p.value as AddKenValue).pubkey.toLowerCase());
      }
      const rename = p.value as RenameAppLabelValue;
      return labels.get(rename.contactId) !== rename.label;
    });
  }

  return {
    buildPairingUri(uriOpts) {
      return buildPairingUriV2({ ...uriOpts, appPubkey: signer.pubkey });
    },

    parsePairingUri(input, parseOpts) {
      return parsePairingRequestV2(input, parseOpts);
    },

    async awaitPairingAck({ challenge, relays, timeoutMs = 120_000, pollMs = 2000, requestedCapabilities }) {
      const deadline = Date.now() + timeoutMs;
      const filter: NostrFilterLike = { kinds: [ACK_KIND], '#p': [signer.pubkey], limit: 1 };
      const allowed = requestedCapabilities ? new Set<Capability>(requestedCapabilities) : null;

      while (Date.now() < deadline) {
        // Hostile or merely broken relay data must never escape this loop as a
        // thrown exception — a bad event is exactly as "no ack yet" as no event.
        try {
          const event = await relay.fetchNewest(filter, relays);
          if (event && typeof event.pubkey === 'string' && typeof event.content === 'string') {
            // Controller correction 1: the ack payload carries no timestamp of
            // its own, so freshness is judged on the carrier EVENT's
            // `created_at` — an old ack replayed by a relay must not resurrect
            // a pairing the app has long since given up polling for.
            const createdAt = event.created_at;
            const fresh = typeof createdAt === 'number' && Number.isFinite(createdAt)
              && Math.abs(now() - createdAt) <= PAIRING_FRESHNESS_SECONDS;
            if (fresh) {
              try {
                const plaintext = await signer.nip44Decrypt(event.pubkey, event.content);
                const ack = parsePairingAckV2(plaintext, challenge);
                if (ack) {
                  // Controller correction 1: narrowing only. A producer that
                  // grants a capability the app never requested is either a bug
                  // or an attempt to smuggle scope past the app's own consent
                  // screen — either way this is not a valid ack for this request.
                  const overGranted = allowed !== null
                    && ack.grantedCapabilities.some((c) => !allowed.has(c));
                  // Fix round 1, M4: a rail that is the app's OWN pubkey is
                  // nonsensical for this wire (the app cannot be its own
                  // signing rail) and would make the projection's later
                  // author-pin check trivially satisfiable by anything the
                  // app itself ever publishes — reject rather than pair.
                  const selfRail = ack.railPubkey.toLowerCase() === signer.pubkey.toLowerCase();
                  if (!overGranted && !selfRail) return pairingFromAck(ack, now());
                }
              } catch {
                // Not our ack, or not decryptable by us — keep waiting rather
                // than failing the whole pairing on one stray event addressed
                // to us. (S7: NIP-44 is the real authentication gate here.)
              }
            }
          }
        } catch {
          // A transport that throws is treated the same as one that answered
          // "nothing yet" — see the module-header note on hostile relay data.
        }
        const remaining = deadline - Date.now();
        if (remaining <= 0) break;
        await sleep(Math.min(pollMs, remaining));
      }
      return null;
    },

    async fetchProjection(pairing) {
      try {
        const event = await relay.fetchNewest(
          projectionFilter(pairing.railPubkey, pairing.grantId), [pairing.relay], pairing.railPubkey,
        );
        if (!event) return null;
        // Author pin. A relay may answer with anything; a projection signed by
        // a key that is not this grant's rail is not this grant's projection.
        if (typeof event.pubkey !== 'string' || event.pubkey.toLowerCase() !== pairing.railPubkey.toLowerCase()) {
          return null;
        }
        if (typeof event.content !== 'string') return null;

        // Fix round 1, C2 (ruling R-4): the app publishes every private-state
        // rail — this grant's projection included — as a v2 VAULT ENVELOPE
        // (`{v:2,k,iv,ct,b}`: a random AES-256-GCM content key, itself
        // NIP-44-wrapped), never a bare NIP-44 payload. A bare
        // `signer.nip44Decrypt` here would try to NIP-44-decrypt that JSON
        // and fail on every real projection.
        const plaintext = await openVaultPayload(event.content, signer, pairing.railPubkey);
        if (plaintext === null) return null;

        const projection = parseProjection(plaintext);
        if (!projection || projection.grantId !== pairing.grantId) return null;

        // Fix round 1, M3: the grant's own `grantedCapabilities` is a ceiling
        // on what this projection may claim to carry — a producer (or a
        // relay replaying an old event from before a narrowing) cannot hand
        // out MORE scopes than the app was actually granted.
        const grantedSet = new Set(pairing.grantedCapabilities);
        if (projection.scopes.some((s) => !grantedSet.has(s))) return null;

        // Controller correction 2: the grant's own clamped ceiling on how
        // stale a projection may be, enforced independently of whatever the
        // projection itself claims — a producer (or a relay replaying an old
        // event) cannot hand out a wider staleness window than the owner
        // actually granted. Treated as malformed: reject, do not apply.
        if (projection.expiresAt - projection.issuedAt > pairing.maxStalenessSeconds) return null;

        const nowSec = now();
        const next = applyProjection(state, projection, nowSec);
        // Fix round 1, I1: `next === state` means the frontier rule REJECTED
        // this projection (an older or duplicate replay) — the caller must
        // not be handed a projection that was never actually applied.
        if (next === state) return null;
        state = next;
        reconcilePending(projection, nowSec);
        await persistState();
        await persistPending(pairing.grantId);
        if (state.revoked && !revokedAnnounced) {
          revokedAnnounced = true;
          for (const cb of revokedListeners) cb(state.grantId ?? projection.grantId);
        }
        return projection;
      } catch {
        // Hostile or malformed relay data must never throw out of `fetch` —
        // see the module-header note.
        return null;
      }
    },

    getState() { return state; },
    getBlockedSet() { return blockedSetOf(state); },
    isFresh(nowSec) { return isFresh(state, nowSec ?? now()); },

    async propose(pairing, drafts) {
      if (drafts.length === 0) return false;
      const granted = new Set<Capability>(pairing.grantedCapabilities.filter(isCapability));
      // Refuse locally rather than publishing something the producer will bin:
      // a silently-dropped proposal looks identical to a slow one.
      if (drafts.some((d) => !granted.has(CAPABILITY_FOR_ACTION[d.action]))) return false;

      const createdAt = now();
      let plaintext: string;
      let proposals: ContactProposalV1[];
      try {
        // Controller correction 3: a rename draft with no `updatedAt` is
        // stamped from the client's OWN injected clock, not `draftToProposal`'s
        // internal `Date.now()` fallback — so a caller that injected `nowMs`
        // for determinism gets a deterministic LWW field, not real wall time.
        const stamped = drafts.map((d) => (
          d.action === 'rename-app-label' && d.value.updatedAt === undefined
            ? { ...d, value: { ...d.value, updatedAt: nowMs() } }
            : d
        ));
        proposals = stamped.map((d) => draftToProposal(d, pairing.grantId, createdAt));
        plaintext = buildProposalBatch(proposals);
      } catch {
        return false;
      }
      // Fix round 1, I3: none of the encrypt/sign/publish leg is allowed to
      // throw out of `propose` — a signer or relay that rejects (a bunker
      // round-trip failing, a relay socket dropping) is exactly the same
      // "did not send" outcome as `publish` returning `false`.
      let ok: boolean;
      try {
        const content = await signer.nip44Encrypt(pairing.railPubkey, plaintext);
        const template = proposalEventTemplate(signer.pubkey, pairing.grantId, createdAt, content);
        const event = await signer.signEvent(template);
        ok = await relay.publish(event, [pairing.relay]);
      } catch {
        return false;
      }
      // R-9: only a proposal that actually reached a relay is pending. One that
      // never got out is not "waiting for the owner", it is "not sent".
      if (ok) {
        for (const proposal of proposals) {
          pending.push({
            operationId: proposal.operationId, action: proposal.action,
            value: proposal.value, sentAt: createdAt,
          });
        }
        // Fix round 1, M1: keyed off `pairing.grantId`, not `state.grantId` —
        // see `persistPending`'s own note.
        await persistPending(pairing.grantId);
      }
      return ok;
    },

    // Fix round 1, M2: a deep copy. `pendingProposals()` is documented
    // read-only; a shallow `[...pending]` still hands out the SAME `value`
    // object each entry wraps, so a caller mutating `pending[0].value.label`
    // (say) would corrupt this client's own internal state.
    pendingProposals() {
      return pending.map((p) => ({ ...p, value: { ...p.value } }));
    },

    onRevoked(cb) {
      revokedListeners.add(cb);
      return () => { revokedListeners.delete(cb); };
    },

    async load(grantId) {
      try {
        const rawPending = await storage.get(`${PENDING_KEY_PREFIX}${grantId}`);
        if (rawPending) {
          const parsed = JSON.parse(rawPending) as unknown;
          // Fix round 1, I2: a per-row shape check, not just "has the two
          // fields every row happens to share" — a row this client wrote is
          // always well-formed, but the STORE is outside this client's
          // control (shared with the rest of the app, editable by devtools,
          // subject to partial writes), and `reconcilePending` later does
          // `(p.value as AddKenValue).pubkey.toLowerCase()` unconditionally —
          // a malformed row would throw there on every future
          // `fetchProjection`, not just at load time.
          if (Array.isArray(parsed)) pending = parsed.filter(isValidPendingProposal);
        }
      } catch {
        // Unreadable pending state: start with none. It is a UI convenience,
        // never a correctness input — unlike the sticky Blocked set below.
      }
      try {
        const raw = await storage.get(`${STATE_KEY_PREFIX}${grantId}`);
        if (raw) {
          const parsed = JSON.parse(raw) as Partial<ContactsState>;
          if (typeof parsed === 'object' && parsed !== null && Array.isArray(parsed.blockedPubkeys)) {
            // Fix round 1, I2: re-validate the stored projection through the
            // same guards a fresh wire projection gets, rather than trusting
            // whatever JSON happens to be sitting in the store. `state.
            // projection` feeds `applyProjection`'s frontier comparison on
            // every later `fetchProjection` — a corrupt row here would throw
            // there FOREVER (caught by that call's own try/catch, but always
            // returning null), wedging the grant shut. Dropping just the
            // projection (never `blockedPubkeys`, the one thing that must
            // stay sticky) recovers cleanly: the next real fetch is treated
            // like this grant's first.
            const projection = parsed.projection === null || parsed.projection === undefined
              ? null
              : parseProjection(JSON.stringify(parsed.projection));
            state = {
              grantId: typeof parsed.grantId === 'string' ? parsed.grantId : grantId,
              projection,
              receivedAt: typeof parsed.receivedAt === 'number' ? parsed.receivedAt : 0,
              blockedPubkeys: parsed.blockedPubkeys.filter((p): p is string => typeof p === 'string'),
              revoked: parsed.revoked === true,
            };
            revokedAnnounced = state.revoked;
          }
        }
      } catch {
        // Unreadable stored state: start empty rather than throwing at an app's
        // startup path. The next fetch repopulates everything except the sticky
        // Blocked set, which is why an app should not lose this store lightly.
      }
      return state;
    },
  };
}
