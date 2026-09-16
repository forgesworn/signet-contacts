/**
 * Identifiers and routing tags.
 *
 * Every tag is a domain-separated SHA-256 truncated to 128 bits (32 hex). The
 * prefixes are what stop one grant's tag being computable as another's, and
 * what stops a projection tag ever equalling a proposal tag for the same grant.
 *
 * Tags are OPAQUE on the relay by design (exploration §7): a scraper of kind
 * 30078 sees a random-looking `d` tag, not `signet:contacts:<something>`, so
 * knowing the rail npub is a prerequisite to reading anything at all.
 *
 * `scopedContactId` also hides the producer's real contact id from the app: two
 * apps paired to the same directory see two disjoint id spaces over the same
 * people, so colluding consumers cannot join on the identifier alone.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

const PROJECTION_PREFIX = 'signet:contacts:proj:';
const PROPOSAL_PREFIX = 'signet:contacts:prop:';
const SCOPED_PREFIX = 'signet:contacts:cid:';
const TAG_HEX_CHARS = 32;

/**
 * R-6: byte-identical to signet-app's own `sanitizeDisplayName` character
 * class, written with ESCAPES rather than the literal
 * invisible characters — the literal spelling cannot be reviewed by reading
 * and does not survive a copy-paste, and this class is the one thing that has
 * to agree across two repositories. Strip, trim, slice, in that order.
 *
 * U+0000-001F C0 controls; U+007F-009F DEL + C1 controls; U+200B-200F
 * zero-width + LRM/RLM; U+2028-202E separators + bidi embedding/override;
 * U+2066-2069 bidi isolates. `vectors/sanitise.json` (Task 12) freezes the
 * behaviour and BOTH repositories assert against it.
 */
// eslint-disable-next-line no-control-regex
const CONTROL_BIDI = /[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2066-\u2069]/g;

function digestHex(input: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(input)));
}

/** Replaceable `d` tag of a grant's projection event. */
export function projectionTag(grantId: string): string {
  return digestHex(`${PROJECTION_PREFIX}${grantId}`).slice(0, TAG_HEX_CHARS);
}

/** Replaceable `d` tag of one app's proposal event for a grant. Bound to the
 *  app pubkey so a second app on the same grant cannot overwrite the first's
 *  replaceable event. */
export function proposalTag(grantId: string, appPubkey: string): string {
  return digestHex(`${PROPOSAL_PREFIX}${grantId}:${appPubkey}`).slice(0, TAG_HEX_CHARS);
}

/**
 * Grant-scoped opaque contact id.
 *
 * The lengths of both inputs are mixed in before the values, so
 * `('ab','c:d')` and `('ab:c','d')` cannot produce the same digest — a plain
 * `grantId + ':' + contactId` concatenation is ambiguous whenever either side
 * may contain the separator.
 */
export function scopedContactId(grantId: string, contactId: string): string {
  const payload = `${SCOPED_PREFIX}${grantId.length}:${grantId}:${contactId.length}:${contactId}`;
  return digestHex(payload).slice(0, TAG_HEX_CHARS);
}

/** Lowercase-hex guard. With `length`, the string must be exactly that long. */
export function isHex(value: unknown, length?: number): value is string {
  if (typeof value !== 'string') return false;
  if (typeof length === 'number' && value.length !== length) return false;
  if (value.length === 0 || value.length % 2 !== 0) return false;
  return /^[0-9a-f]+$/.test(value);
}

/** Cryptographically random lowercase hex. Uses the platform `crypto`. */
export function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(buf);
  return bytesToHex(buf);
}

/** Strip control + bidi/invisible characters, trim, then cap. Non-strings
 *  become the empty string rather than `String(value)` — a wire field that is
 *  not a string is missing data, not data that needs coercing.
 *
 *  `maxLen` counts CODE POINTS, not UTF-16 code units: the cap is applied via
 *  `Array.from(string)`, which iterates by code point, so a cap can never
 *  land inside a surrogate pair. A plain `.slice(0, maxLen)` operates on
 *  UTF-16 units and can split a pair in two, leaving a lone surrogate on the
 *  wire — a malformed string a receiver's `JSON.parse`/display layer may
 *  choke on or render as a replacement character.
 *
 *  R-6: this is the ONLY sanitiser on this wire. signet-app's projection
 *  builder imports THIS function rather than using its own
 *  `sanitizeDisplayName`, so a producer can never emit a string its own parser
 *  would rewrite — which would make `buildProjection` throw on every rebuild
 *  and kill that grant's rail permanently and silently. (signet-app's own display-layer
 *  sanitiser still slices by UTF-16 unit — a separate, pre-existing gap in
 *  that repo, not fixed here.) */
export function sanitizeWireText(raw: unknown, maxLen: number): string {
  if (typeof raw !== 'string') return '';
  const stripped = raw.replace(CONTROL_BIDI, '').trim();
  return Array.from(stripped).slice(0, maxLen).join('');
}
