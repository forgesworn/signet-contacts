/**
 * Field coverage — the ONE table that says which capability unlocks which
 * projected-contact field (docs/WIRE.md §6 and §10).
 *
 * Both sides read it: `buildProjection` refuses to build a projection carrying
 * a field its `scopes` do not cover, and `parseProjection` rejects one. A
 * field a grant does not cover is broader sharing than the owner approved, so
 * it is never an item-level drop — it is a producer violating consent, and the
 * whole projection is refused.
 *
 * `requires` is an all-of list. `orIfBlocked`, where present, is an
 * alternative all-of list that applies only to a contact carrying
 * `blocked: true` — a blocks-only grant is a filter list, so it may see a
 * blocked contact and its identity pubkeys, and nothing else.
 *
 * A field with no entry here that `ProjectedContact` still declares (`avatar`,
 * `type`, `linkedPubkeys`) is covered by no capability, so carrying it is
 * always refused. Adding one later means a new capability and a new pairing.
 */
import type { Capability, ProjectedMethodKind } from './types.js';

export interface FieldCoverageRule {
  /** Every one of these capabilities must be in the projection's scopes. */
  readonly requires: readonly Capability[];
  /** Alternative, for a contact carrying `blocked: true` only. */
  readonly orIfBlocked?: readonly Capability[];
}

const DIRECTORY = 'signet.contacts.read:directory' as const;
const BLOCKS = 'signet.contacts.blocks.read' as const;

/** Keyed by field path. `contactMethods[kind=<k>]` is one entry per method kind. */
export const FIELD_COVERAGE: Readonly<Record<string, FieldCoverageRule>> = {
  // The contact's presence at all: a directory grant, or a blocks grant for a
  // blocked contact. A blocks-only grant never sees an unblocked contact.
  'contact': { requires: [DIRECTORY], orIfBlocked: [BLOCKS] },
  'identities': { requires: [DIRECTORY], orIfBlocked: [BLOCKS] },
  'identities[].verification': { requires: [DIRECTORY, 'signet.contacts.read:checks'] },
  'displayName': { requires: [DIRECTORY] },
  'effectiveTier': { requires: [DIRECTORY, 'signet.contacts.read:tier'] },
  'tierSource': { requires: [DIRECTORY, 'signet.contacts.read:tier'] },
  'roles': { requires: [DIRECTORY, 'signet.contacts.read:roles'] },
  'contactMethods': { requires: [DIRECTORY] },
  'contactMethods[kind=phone]': { requires: [DIRECTORY, 'signet.contacts.read:method:phone'] },
  'contactMethods[kind=email]': { requires: [DIRECTORY, 'signet.contacts.read:method:email'] },
  'contactMethods[kind=website]': { requires: [DIRECTORY, 'signet.contacts.read:method:website'] },
  'contactMethods[kind=postal-address]': { requires: [DIRECTORY, 'signet.contacts.read:method:postal-address'] },
  'contactMethods[kind=other]': { requires: [DIRECTORY, 'signet.contacts.read:method:other'] },
  'contactMethods[].verification': { requires: [DIRECTORY, 'signet.contacts.read:checks'] },
  'checks': { requires: [DIRECTORY, 'signet.contacts.read:check-records'] },
  'blocked': { requires: [BLOCKS] },
};

/** Contact-level keys that no capability covers. */
const NEVER_COVERED = ['avatar', 'type', 'linkedPubkeys'] as const;

function covered(path: string, scopes: ReadonlySet<string>, blocked: boolean): boolean {
  const rule = FIELD_COVERAGE[path];
  if (!rule) return false;
  if (rule.requires.every((c) => scopes.has(c))) return true;
  return blocked && rule.orIfBlocked !== undefined && rule.orIfBlocked.every((c) => scopes.has(c));
}

/**
 * Field paths a raw (unparsed) contact carries that `scopes` do not cover.
 * Empty means the contact is within the grant. Reads the RAW object, so a
 * field is judged by its presence on the wire, not by whether it would have
 * survived parsing. Keys that are not wire fields at all are ignored here —
 * the parser drops them.
 */
export function uncoveredContactFields(raw: unknown, scopes: Iterable<string>): string[] {
  if (typeof raw !== 'object' || raw === null) return [];
  const o = raw as Record<string, unknown>;
  const set = new Set(scopes);
  const blocked = o.blocked === true;
  const out: string[] = [];
  const has = (k: string): boolean => o[k] !== undefined;

  if (!covered('contact', set, blocked)) out.push('contact');
  for (const key of ['identities', 'displayName', 'effectiveTier', 'tierSource', 'roles', 'contactMethods', 'checks', 'blocked']) {
    if (has(key) && !covered(key, set, blocked)) out.push(key);
  }
  for (const key of NEVER_COVERED) if (has(key)) out.push(key);

  if (Array.isArray(o.identities)) {
    const verified = o.identities.some((i) => typeof i === 'object' && i !== null
      && (i as Record<string, unknown>).verification !== undefined);
    if (verified && !covered('identities[].verification', set, blocked)) out.push('identities[].verification');
  }
  if (Array.isArray(o.contactMethods)) {
    for (const m of o.contactMethods) {
      if (typeof m !== 'object' || m === null) continue;
      const method = m as Record<string, unknown>;
      const path = `contactMethods[kind=${String(method.kind as ProjectedMethodKind)}]`;
      if (!covered(path, set, blocked) && !out.includes(path)) out.push(path);
      if (method.verification !== undefined && !covered('contactMethods[].verification', set, blocked)
        && !out.includes('contactMethods[].verification')) out.push('contactMethods[].verification');
    }
  }
  return out;
}
