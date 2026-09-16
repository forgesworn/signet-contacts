/**
 * Contacts app-access wire v2 — type surface.
 *
 * Every shape here is a WIRE shape: what is serialised, encrypted and published.
 * Nothing local to a producer or a consumer belongs in this file, with one
 * documented exception (`PairingV2.pairedAt`, which a consumer persists beside
 * the ack and which is never transmitted).
 *
 * The minimal `UnsignedNostrEvent` / `SignedNostrEvent` / `NostrFilterLike`
 * shapes exist so `src/wire/` can build and match events without depending on
 * nostr-tools. They are structurally compatible with nostr-tools' `Event` and
 * `Filter`, so a consumer can pass its own objects straight through.
 */
import type { Capability } from './constants.js';
export type { Capability };

export type DirectoryKind = 'owner' | 'dependant';
export type ProjectedTier = 'kin' | 'kith' | 'ken' | 'none';
export type ProjectedTierSource = 'direct' | 'guardian-vouched' | 'guardian-limited';
export type ProjectedType = 'person' | 'organisation';
export type ProjectedVerification = 'unverified' | 'proven' | 'mutual';
export type ProjectedMethodKind = 'phone' | 'email' | 'website' | 'postal-address' | 'other';

/** Minimal Nostr shapes so the wire layer never imports nostr-tools. */
export interface UnsignedNostrEvent { kind: number; pubkey: string; created_at: number; tags: string[][]; content: string }
export interface SignedNostrEvent extends UnsignedNostrEvent { id: string; sig: string }
export interface NostrFilterLike { kinds?: number[]; authors?: string[]; limit?: number; [tagQuery: string]: unknown }

export interface PairingUriOptionsV2 {
  appPubkey: string; appName: string; capabilities: readonly Capability[];
  directory: DirectoryKind; relay: string; nowSec: number; challenge: string;
}
export interface PairingRequestV2 {
  v: 2; appPubkey: string; appName: string; capabilities: Capability[];
  directory: DirectoryKind; rendezvousRelay: string; t: number; challenge: string;
}
export interface PairingRequestV2Result { request: PairingRequestV2 | null; warnings: string[] }

export interface PairingAckV2 {
  v: 2; grantId: string; railPubkey: string; projectionTag: string; proposalTag: string;
  relay: string; grantedCapabilities: Capability[]; maxStalenessSeconds: number; challenge: string;
}
/** Consumer-side persisted pairing. `pairedAt` is local metadata, never wire. */
export interface PairingV2 extends Omit<PairingAckV2, 'v' | 'challenge'> { pairedAt: number }

export interface ProjectedIdentity { pubkey: string; verification: ProjectedVerification }
export interface ProjectedMethod { kind: ProjectedMethodKind; value: string; verification: 'unverified' | 'proven' }
export interface ProjectedAvatar { url: string; hash: string; key?: string }
export interface ProjectedContact {
  contactId: string;                 // grant-scoped opaque, 32 lowercase hex
  type: ProjectedType;
  identities?: ProjectedIdentity[];
  displayName?: string;
  avatar?: ProjectedAvatar;
  effectiveTier: ProjectedTier;
  tierSource: ProjectedTierSource;
  roles?: string[];
  contactMethods?: ProjectedMethod[];
  blocked: boolean;
  linkedPubkeys?: string[];
}
/** C13: a projection is a SNAPSHOT, so the frontier says who published it and
 *  when. R-30: newest wins by `(publishedAt, maxClock)` — recency first, the
 *  Lamport clock only as a same-second tiebreak, so a block published from a
 *  device whose log is behind still applies. There are no `opIds`. */
export interface ProjectionFrontier {
  maxClock: number; opCount: number; publishedAt: number; deviceId: string;  // 32 hex
}
/**
 * R-31: there is deliberately NO `ownerPubkey` on this wire. A connected app
 * learns the grant's rail pubkey and a set of grant-scoped opaque contact ids,
 * and nothing else about whose directory it is reading. The owner's persona
 * pubkey would have been stable across every grant on a directory, so two
 * colluding apps could have joined their projections on it in one line — the
 * very link `scopedContactId` exists to break — and on a `dependant`
 * directory it would have been a minor's long-lived public identity, handed
 * to every paired app. Nothing in this SDK ever read it.
 */
export interface ContactProjectionV2 {
  v: 2; grantId: string; scopes: Capability[];
  frontier: ProjectionFrontier; issuedAt: number; expiresAt: number;
  contacts: ProjectedContact[]; revoked?: true;
  /** R-5: set when the producer dropped contacts to fit `MAX_WIRE_BYTES`. */
  truncated?: true;
}

export interface AddKenValue { pubkey: string; displayName: string }
/** R-7: `updatedAt` (ms epoch, integer >= 0) is the last-writer-wins clock the
 *  app compares a rename against — without it a replayed stale rename could
 *  re-apply an old label over a newer one (S6). */
export interface RenameAppLabelValue { contactId: string; label: string; updatedAt: number }
export interface ContactProposalV1 {
  v: 1; grantId: string; operationId: string;
  action: 'add-ken' | 'rename-app-label';
  value: AddKenValue | RenameAppLabelValue;
  createdAt: number;
}
export interface ProposalBatch { v: 1; proposals: ContactProposalV1[] }
/** What a consumer passes to `client.propose` — `operationId` is minted for it.
 *  A rename draft's `updatedAt` is optional: `draftToProposal` stamps it from
 *  the draft when given, else from `Date.now()` (R-7). */
export type ContactProposalDraft =
  | { action: 'add-ken'; value: AddKenValue }
  | { action: 'rename-app-label'; value: Omit<RenameAppLabelValue, 'updatedAt'> & { updatedAt?: number } };

export interface ContactsState {
  grantId: string | null;
  projection: ContactProjectionV2 | null;
  receivedAt: number;
  blockedPubkeys: string[];   // sticky: survives expiry AND revocation
  revoked: boolean;
}

/** R-9: consumer-side only. The SDK remembers what it proposed so an app can
 *  show "sent, not applied yet"; nothing about this is ever on the wire, and
 *  the producer never stores it. */
export interface PendingProposal {
  operationId: string;
  action: 'add-ken' | 'rename-app-label';
  value: AddKenValue | RenameAppLabelValue;
  sentAt: number;
}
