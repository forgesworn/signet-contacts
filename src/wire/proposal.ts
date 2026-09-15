/**
 * App → Signet proposals.
 *
 * A proposal is NOT a write. It is a signed request, addressed to the grant's
 * rail, that Signet validates against the grant before converting it into a
 * canonical contact operation (exploration §5.2, §5.10). The app signs it as
 * itself, so the producer can pin the author and know exactly which grant is
 * speaking; the replaceable `d` tag is bound to the app pubkey so two apps on
 * one grant cannot overwrite each other.
 *
 * Only two actions exist in v2: `add-ken` and `rename-app-label`. `remove`,
 * `block` and `unblock` are deliberately absent and are not implied by either
 * of these — a later wire version may add them with their own capabilities.
 *
 * `rename-app-label` carries the GRANT-SCOPED contact id the app saw in its
 * projection, because that is the only id the app has ever been told. The
 * producer maps it back by recomputing `scopedContactId` over its own records.
 */
import { MAX_APP_LABEL, MAX_DISPLAY_NAME, MAX_PROPOSALS_PER_BATCH, PROPOSAL_KIND } from './constants.js';
import type {
  AddKenValue, ContactProposalDraft, ContactProposalV1, NostrFilterLike,
  ProposalBatch, RenameAppLabelValue, UnsignedNostrEvent,
} from './types.js';
import { isHex, proposalTag, randomHex, sanitizeWireText } from './ids.js';

export function parseProposal(raw: unknown): ContactProposalV1 | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  if (o.v !== 1) return null;
  if (!isHex(o.grantId, 32)) return null;
  if (!isHex(o.operationId, 32)) return null;
  if (typeof o.createdAt !== 'number' || !Number.isInteger(o.createdAt) || o.createdAt < 0) return null;
  if (typeof o.value !== 'object' || o.value === null) return null;
  const value = o.value as Record<string, unknown>;

  if (o.action === 'add-ken') {
    if (!isHex(value.pubkey, 64)) return null;
    const displayName = sanitizeWireText(value.displayName, MAX_DISPLAY_NAME);
    if (displayName.length === 0) return null;
    const v: AddKenValue = { pubkey: value.pubkey, displayName };
    return { v: 1, grantId: o.grantId, operationId: o.operationId, action: 'add-ken', value: v, createdAt: o.createdAt };
  }
  if (o.action === 'rename-app-label') {
    if (!isHex(value.contactId, 32)) return null;
    const label = sanitizeWireText(value.label, MAX_APP_LABEL);
    if (label.length === 0) return null;
    // R-7: last-writer-wins clock. Missing or malformed drops the whole
    // proposal — a rename with no comparable timestamp cannot be applied
    // safely, and a replayed stale rename must not be able to re-apply an
    // old label over a newer one (S6).
    if (typeof value.updatedAt !== 'number' || !Number.isInteger(value.updatedAt) || value.updatedAt < 0) return null;
    const v: RenameAppLabelValue = { contactId: value.contactId, label, updatedAt: value.updatedAt };
    return { v: 1, grantId: o.grantId, operationId: o.operationId, action: 'rename-app-label', value: v, createdAt: o.createdAt };
  }
  return null;
}

export function parseProposalBatch(json: string): ProposalBatch | null {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return null;
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  if (o.v !== 1) return null;
  if (!Array.isArray(o.proposals)) return null;
  const proposals = o.proposals
    .slice(0, MAX_PROPOSALS_PER_BATCH)
    .map(parseProposal)
    .filter((p): p is ContactProposalV1 => p !== null);
  return { v: 1, proposals };
}

/** Round-trip-validating builder: a cap breach or a field that would be
 *  rewritten is a hard error here, not a silent loss discovered after transit. */
export function buildProposalBatch(proposals: readonly ContactProposalV1[]): string {
  if (proposals.length === 0) throw new TypeError('signet-contacts: a proposal batch must not be empty');
  if (proposals.length > MAX_PROPOSALS_PER_BATCH) {
    throw new TypeError(`signet-contacts: at most ${MAX_PROPOSALS_PER_BATCH} proposals per batch`);
  }
  const json = JSON.stringify({ v: 1, proposals });
  const reparsed = parseProposalBatch(json);
  if (reparsed === null) throw new TypeError('signet-contacts: proposal batch is not parseable');
  if (JSON.stringify(reparsed.proposals) !== JSON.stringify(proposals)) {
    throw new TypeError('signet-contacts: proposal batch would be rewritten in transit');
  }
  return json;
}

/** Mint a wire proposal from a consumer draft. `operationId` is the idempotency
 *  key: a producer that has already applied it does nothing on a retry.
 *
 *  R-7: a `rename-app-label` draft's `updatedAt` is stamped from the draft
 *  when the consumer supplied one (e.g. an app replaying its own local edit
 *  timestamp), else from `Date.now()` at mint time — ms epoch either way. */
export function draftToProposal(draft: ContactProposalDraft, grantId: string, createdAt: number): ContactProposalV1 {
  if (draft.action === 'rename-app-label') {
    const value: RenameAppLabelValue = { ...draft.value, updatedAt: draft.value.updatedAt ?? Date.now() };
    return { v: 1, grantId, operationId: randomHex(16), action: 'rename-app-label', value, createdAt };
  }
  return { v: 1, grantId, operationId: randomHex(16), action: 'add-ken', value: draft.value, createdAt };
}

export function proposalEventTemplate(
  appPubkey: string, grantId: string, createdAt: number, content: string,
): UnsignedNostrEvent {
  return {
    kind: PROPOSAL_KIND,
    pubkey: appPubkey,
    created_at: createdAt,
    tags: [['d', proposalTag(grantId, appPubkey)]],
    content,
  };
}

export function proposalFilter(appPubkey: string, grantId: string): NostrFilterLike {
  return { kinds: [PROPOSAL_KIND], authors: [appPubkey], '#d': [proposalTag(grantId, appPubkey)], limit: 1 };
}
