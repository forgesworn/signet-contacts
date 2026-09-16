/**
 * ContactProjectionV2 — the per-grant encrypted view a consuming app reads.
 *
 * Signed by the grant's random rail key, NIP-44-encrypted to the app pubkey,
 * published as a replaceable kind-30078 under an opaque `d` tag. No `p` tag:
 * the recipient stays off the wire (kenspeckle v1 precedent, exploration §7).
 *
 * The builder is deliberately strict and the parser deliberately forgiving.
 * A producer that silently dropped a field would ship a projection that looks
 * fine and is missing exactly the data the grant exists to carry — so
 * `buildProjection` re-parses its own output and throws unless everything
 * survived. A consumer, by contrast, must keep going: one malformed contact in
 * an otherwise good projection drops that contact, not the whole directory.
 *
 * Nothing here can be widened without a `v` bump. Adding a field to
 * `ProjectedContact` means a new capability and a new pairing.
 */
import {
  MAX_CAPABILITIES, MAX_CONTACTS_PER_PROJECTION, MAX_DISPLAY_NAME, MAX_IDENTITIES_PER_CONTACT,
  MAX_LINKED_PUBKEYS, MAX_METHODS_PER_CONTACT, MAX_METHOD_VALUE, MAX_ROLES_PER_CONTACT,
  MAX_ROLE_LEN, MAX_URL_LEN, MAX_WIRE_BYTES, PROJECTION_KIND, isCapability, normaliseCapabilities,
} from './constants.js';
import type { Capability } from './constants.js';
import type {
  ContactProjectionV2, NostrFilterLike, ProjectedAvatar, ProjectedContact,
  ProjectedIdentity, ProjectedMethod, ProjectedMethodKind, ProjectedTier,
  ProjectedTierSource, ProjectedType, ProjectedVerification, UnsignedNostrEvent,
} from './types.js';
import { isHex, projectionTag, sanitizeWireText } from './ids.js';

const TIERS: readonly ProjectedTier[] = ['kin', 'kith', 'ken', 'none'];
const TIER_SOURCES: readonly ProjectedTierSource[] = ['direct', 'guardian-vouched', 'guardian-limited'];
const TYPES: readonly ProjectedType[] = ['person', 'organisation'];
const VERIFICATIONS: readonly ProjectedVerification[] = ['unverified', 'proven', 'mutual'];
const METHOD_KINDS: readonly ProjectedMethodKind[] = ['phone', 'email', 'website', 'postal-address', 'other'];

/** https only. A projected avatar or website URL is fetched by the consumer, so
 *  any other scheme is a code-execution or exfiltration primitive, not a link. */
function safeHttpsUrl(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_URL_LEN) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' ? value : null;
  } catch {
    return null;
  }
}

function parseIdentity(raw: unknown): ProjectedIdentity | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const o = raw as Record<string, unknown>;
  if (!isHex(o.pubkey, 64)) return null;
  const verification = o.verification;
  if (typeof verification !== 'string' || !VERIFICATIONS.includes(verification as ProjectedVerification)) return null;
  return { pubkey: o.pubkey, verification: verification as ProjectedVerification };
}

function parseMethod(raw: unknown): ProjectedMethod | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const o = raw as Record<string, unknown>;
  const kind = o.kind;
  if (typeof kind !== 'string' || !METHOD_KINDS.includes(kind as ProjectedMethodKind)) return null;
  const value = sanitizeWireText(o.value, MAX_METHOD_VALUE);
  if (value.length === 0) return null;
  if (o.verification !== 'unverified' && o.verification !== 'proven') return null;
  return { kind: kind as ProjectedMethodKind, value, verification: o.verification };
}

function parseAvatar(raw: unknown): ProjectedAvatar | undefined {
  if (typeof raw !== 'object' || raw === null) return undefined;
  const o = raw as Record<string, unknown>;
  const url = safeHttpsUrl(o.url);
  if (url === null || !isHex(o.hash, 64)) return undefined;
  const avatar: ProjectedAvatar = { url, hash: o.hash };
  if (isHex(o.key, 64)) avatar.key = o.key;
  return avatar;
}

/** Parse one contact. Returns null when the contact cannot be trusted at all;
 *  an individually unparseable OPTIONAL field is dropped, not fatal. */
export function parseProjectedContact(raw: unknown): ProjectedContact | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const o = raw as Record<string, unknown>;
  if (!isHex(o.contactId, 32)) return null;
  if (typeof o.type !== 'string' || !TYPES.includes(o.type as ProjectedType)) return null;
  if (typeof o.effectiveTier !== 'string' || !TIERS.includes(o.effectiveTier as ProjectedTier)) return null;
  if (typeof o.tierSource !== 'string' || !TIER_SOURCES.includes(o.tierSource as ProjectedTierSource)) return null;
  if (typeof o.blocked !== 'boolean') return null;

  const contact: ProjectedContact = {
    contactId: o.contactId,
    type: o.type as ProjectedType,
    effectiveTier: o.effectiveTier as ProjectedTier,
    tierSource: o.tierSource as ProjectedTierSource,
    blocked: o.blocked,
  };

  if (Array.isArray(o.identities)) {
    const identities = o.identities
      .slice(0, MAX_IDENTITIES_PER_CONTACT)
      .map(parseIdentity)
      .filter((i): i is ProjectedIdentity => i !== null);
    if (identities.length > 0) contact.identities = identities;
  }
  if (typeof o.displayName === 'string') {
    const displayName = sanitizeWireText(o.displayName, MAX_DISPLAY_NAME);
    if (displayName.length > 0) contact.displayName = displayName;
  }
  const avatar = parseAvatar(o.avatar);
  if (avatar) contact.avatar = avatar;
  if (Array.isArray(o.roles)) {
    const roles = o.roles
      .slice(0, MAX_ROLES_PER_CONTACT)
      .map((r) => sanitizeWireText(r, MAX_ROLE_LEN))
      .filter((r) => r.length > 0);
    if (roles.length > 0) contact.roles = roles;
  }
  if (Array.isArray(o.contactMethods)) {
    const methods = o.contactMethods
      .slice(0, MAX_METHODS_PER_CONTACT)
      .map(parseMethod)
      .filter((m): m is ProjectedMethod => m !== null);
    if (methods.length > 0) contact.contactMethods = methods;
  }
  if (Array.isArray(o.linkedPubkeys)) {
    const linked = o.linkedPubkeys
      .slice(0, MAX_LINKED_PUBKEYS)
      .filter((p): p is string => isHex(p, 64));
    if (linked.length > 0) contact.linkedPubkeys = linked;
  }
  return contact;
}

export function parseProjection(json: string): ContactProjectionV2 | null {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch {
    return null;
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;

  if (o.v !== 2) return null;
  if (!isHex(o.grantId, 32)) return null;
  if (!Array.isArray(o.scopes)) return null;
  if (typeof o.issuedAt !== 'number' || !Number.isInteger(o.issuedAt) || o.issuedAt < 0) return null;
  if (typeof o.expiresAt !== 'number' || !Number.isInteger(o.expiresAt) || o.expiresAt < o.issuedAt) return null;
  if (typeof o.frontier !== 'object' || o.frontier === null) return null;
  const frontier = o.frontier as Record<string, unknown>;
  if (typeof frontier.maxClock !== 'number' || !Number.isInteger(frontier.maxClock) || frontier.maxClock < 0) return null;
  if (typeof frontier.opCount !== 'number' || !Number.isInteger(frontier.opCount) || frontier.opCount < 0) return null;
  // C13: a snapshot names its publisher and its moment. Both are required —
  // `maxClock` alone cannot order two devices publishing the same grant.
  if (typeof frontier.publishedAt !== 'number' || !Number.isInteger(frontier.publishedAt) || frontier.publishedAt < 0) return null;
  if (!isHex(frontier.deviceId, 32)) return null;
  if (!Array.isArray(o.contacts)) return null;

  // Cap before filtering, same discipline as every other array on this wire.
  const scopes = normaliseCapabilities(
    o.scopes.slice(0, MAX_CAPABILITIES).filter((c): c is Capability => isCapability(c)),
  );
  // A later duplicate `contactId` is dropped, keeping the first — two
  // contacts sharing an id is malformed input, and silently keeping both
  // would let a hostile relay smuggle a second, different record under an
  // id the consumer already trusts.
  const seenContactIds = new Set<string>();
  // M8: a cut the READER makes is as much a truncation as one the producer
  // made. Without this a consumer handed an over-sent projection kept the
  // first 2000 contacts and had nothing to tell it the list was short.
  const parserCapped = o.contacts.length > MAX_CONTACTS_PER_PROJECTION;
  const contacts = o.contacts
    .slice(0, MAX_CONTACTS_PER_PROJECTION)
    .map(parseProjectedContact)
    .filter((c): c is ProjectedContact => c !== null)
    .filter((c) => {
      if (seenContactIds.has(c.contactId)) return false;
      seenContactIds.add(c.contactId);
      return true;
    });

  const projection: ContactProjectionV2 = {
    v: 2,
    grantId: o.grantId,
    scopes,
    frontier: {
      maxClock: frontier.maxClock, opCount: frontier.opCount,
      publishedAt: frontier.publishedAt, deviceId: frontier.deviceId,
    },
    issuedAt: o.issuedAt,
    expiresAt: o.expiresAt,
    contacts,
  };
  if (o.revoked === true) projection.revoked = true;
  if (o.truncated === true || parserCapped) projection.truncated = true;
  return projection;
}

/**
 * Structural equality over JSON-shaped values, indifferent to object key
 * insertion order. `buildProjection`'s round-trip check exists to catch
 * VALUE-level divergence (a field dropped, capped or rewritten by the
 * parser) — not to enforce that a caller's object literal happens to declare
 * its keys in the same order `parseProjectedContact` reconstructs them in.
 * A plain `JSON.stringify` comparison is order-sensitive and would throw on
 * a perfectly faithful round-trip whenever the two constructions order their
 * keys differently, which defeats the check's actual purpose.
 */
function deepEqualJson(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => deepEqualJson(v, b[i]));
  }
  if (typeof a === 'object' && a !== null && typeof b === 'object' && b !== null) {
    const aKeys = Object.keys(a as Record<string, unknown>);
    const bKeys = Object.keys(b as Record<string, unknown>);
    if (aKeys.length !== bKeys.length) return false;
    return aKeys.every((k) => (
      Object.prototype.hasOwnProperty.call(b, k)
      && deepEqualJson((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k])
    ));
  }
  return false;
}

/** Field-by-field body shape shared by the draft (pre-validation) and
 *  canonical (post-validation) serialisations below — kept as one function so
 *  the two can never drift into emitting a different field set. */
function bodyOf(p: ContactProjectionV2, scopes: readonly Capability[], contacts: readonly ProjectedContact[]): Record<string, unknown> {
  const body: Record<string, unknown> = {
    v: 2,
    grantId: p.grantId,
    scopes,
    frontier: {
      maxClock: p.frontier.maxClock, opCount: p.frontier.opCount,
      publishedAt: p.frontier.publishedAt, deviceId: p.frontier.deviceId,
    },
    issuedAt: p.issuedAt,
    expiresAt: p.expiresAt,
    contacts,
  };
  if (p.revoked === true) body.revoked = true;
  if (p.truncated === true) body.truncated = true;
  return body;
}

/**
 * Serialise an EXPLICIT projection of the input, then prove it survives its
 * own parser, then serialise AGAIN from the reparsed (canonical-order,
 * undefined-free, deduped, capped) values — see the module header.
 *
 * The wire body is built from the REPARSED contacts, never the caller's
 * raw objects. Passing `projection.contacts` straight to `JSON.stringify`
 * would make the output depend on the caller's object-literal key insertion
 * order — two logically identical projections built from differently
 * ordered literals would then produce different bytes, which breaks
 * byte-identical hashing/dedupe and Task 12's frozen vectors. Rebuilding
 * from `reparsed.contacts` (each contact reconstructed field-by-field by
 * `parseProjectedContact`) gives one canonical order regardless of caller
 * order, and closes any extra-field pass-through by construction — the
 * reparsed object can only ever contain fields the parser itself put there.
 */
export function buildProjection(projection: ContactProjectionV2): string {
  const draftJson = JSON.stringify(bodyOf(projection, projection.scopes, projection.contacts));

  const reparsed = parseProjection(draftJson);
  if (reparsed === null) throw new TypeError('signet-contacts: projection is not parseable');
  if (reparsed.contacts.length !== projection.contacts.length) {
    throw new TypeError('signet-contacts: projection would drop contacts in transit');
  }
  // Compare against the JSON-round-tripped form of the caller's own
  // contacts, not the caller's raw objects. `JSON.stringify` already drops
  // an explicitly-`undefined` optional field (e.g. a producer writing
  // `{ roles: hasRoles ? roles : undefined }`), and comparing the reparsed
  // form against the raw object would see an extra `roles` key on the raw
  // side that never made it onto the wire at all — an entirely faithful
  // build would then throw forever, with nothing logged to explain why (the
  // exact silent-rail hazard R-6 exists to prevent).
  const draftContacts = (JSON.parse(draftJson) as { contacts: unknown }).contacts;
  if (!deepEqualJson(reparsed.contacts, draftContacts)) {
    throw new TypeError('signet-contacts: projection would rewrite contact fields in transit');
  }
  // A scope the parser drops (an unknown capability string, or one past the
  // `MAX_CAPABILITIES` cap) is exactly the same silent-narrowing hazard as a
  // dropped contact — the grant would ship promising less than the caller
  // asked for, with nothing to say so. Compared against the caller's RAW
  // scopes (cast to `string[]` — a caller can smuggle a non-`Capability`
  // string past the type system, and that is precisely the case this check
  // exists to catch), never against `normaliseCapabilities(projection.scopes)`:
  // that function itself only ever keeps values already in the known
  // `CAPABILITIES` list, so it would silently agree with the parser and never
  // reveal that anything was dropped. Order-insensitive set comparison.
  const rawScopeSet = new Set(projection.scopes as readonly string[]);
  const reparsedScopeSet = new Set(reparsed.scopes as readonly string[]);
  const sameScopeSet = rawScopeSet.size === reparsedScopeSet.size
    && [...rawScopeSet].every((s) => reparsedScopeSet.has(s));
  if (!sameScopeSet) {
    throw new TypeError('signet-contacts: projection would narrow scopes in transit');
  }

  const json = JSON.stringify(bodyOf(reparsed, reparsed.scopes, reparsed.contacts));
  // R-5: fail closed on an over-cap body. The producer is expected to have
  // fitted it already (signet-app's own projection builder); reaching here
  // means it did not, and sealing would throw somewhere nobody is looking.
  const bytes = new TextEncoder().encode(json).length;
  if (bytes > MAX_WIRE_BYTES) {
    throw new TypeError(`signet-contacts: projection is ${bytes} bytes, over the ${MAX_WIRE_BYTES} cap`);
  }
  return json;
}

/** UTF-8 byte length of the CANONICAL serialised body, so a producer can fit
 *  a projection BEFORE it builds one (R-5). Goes through the same
 *  draft-then-reparse canonicalisation as `buildProjection` (I1) — measured
 *  the same way the builder measures it, so "it fits" here means "it builds"
 *  there, byte for byte. Falls back to measuring the draft when the input
 *  cannot even parse — the producer gets the actual error from
 *  `buildProjection`, this function only ever needs to answer "how big". */
export function projectionByteLength(projection: ContactProjectionV2): number {
  const draftJson = JSON.stringify(bodyOf(projection, projection.scopes, projection.contacts));
  const reparsed = parseProjection(draftJson);
  if (reparsed === null) return new TextEncoder().encode(draftJson).length;
  return new TextEncoder().encode(JSON.stringify(bodyOf(reparsed, reparsed.scopes, reparsed.contacts))).length;
}

export function projectionEventTemplate(
  railPubkey: string, grantId: string, createdAt: number, content: string,
): UnsignedNostrEvent {
  return {
    kind: PROJECTION_KIND,
    pubkey: railPubkey,
    created_at: createdAt,
    tags: [['d', projectionTag(grantId)]],
    content,
  };
}

export function projectionFilter(railPubkey: string, grantId: string): NostrFilterLike {
  return { kinds: [PROJECTION_KIND], authors: [railPubkey], '#d': [projectionTag(grantId)], limit: 1 };
}
