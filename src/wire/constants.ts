/**
 * Frozen constants for the contacts app-access wire v2.
 *
 * The pairing scheme and the 21237 ack kind are REUSED from the shipped v1
 * companion rail so signet-app's existing QR route extends rather than forks.
 * The version marker `v=2` in the URI and `"v": 2` in every payload is what
 * separates the two; a v1 consumer's bytes are unchanged.
 */

export const PAIRING_SCHEME = 'signet-grant:';
export const PAIRING_VERSION = 2;
export const ACK_KIND = 21237;
export const PROJECTION_KIND = 30078;
export const PROPOSAL_KIND = 30078;
export const PAIRING_FRESHNESS_SECONDS = 300;

/**
 * How many kind-21237 candidates a consumer considers when waiting for its
 * pairing ack (I3).
 *
 * Both the app pubkey and the rendezvous relay are printed in the QR code the
 * consumer shows on screen, and the ack is carried by a throwaway ephemeral
 * key, so anyone who photographs that QR can publish a junk event addressed to
 * the app. Asking a relay for the single newest match let one such event keep
 * the genuine ack out of the answer for the whole pairing window, and the
 * owner's device has by then already minted, saved and spent a grant slot on a
 * pairing that can never complete. The consumer therefore takes up to this many
 * candidates, newest first, and accepts the first that decrypts to its own key
 * AND echoes its own challenge — junk costs one failed decrypt each, and ten is
 * far more than a pairing window ever legitimately contains.
 */
export const ACK_CANDIDATE_LIMIT = 10;

/**
 * R-12: there is no `signet.contacts.read:avatar` in v2. A capability that
 * grants a field the producer cannot fill is a promise the wire does not keep,
 * so it waits until signet-app has an avatar map to project. `ProjectedAvatar`
 * and its parser stay, so adding the capability later is additive.
 */
export type Capability =
  | 'signet.contacts.read:directory'
  | 'signet.contacts.read:methods'
  | 'signet.contacts.read:roles'
  | 'signet.contacts.blocks.read'
  | 'signet.contacts.propose:add-ken'
  | 'signet.contacts.propose:rename-app-label';

/** Order is binding: it is the order a grant screen lists them in, and the
 *  order `scopes` is normalised to before hashing. */
export const CAPABILITIES = [
  'signet.contacts.read:directory',
  'signet.contacts.read:methods',
  'signet.contacts.read:roles',
  'signet.contacts.blocks.read',
  'signet.contacts.propose:add-ken',
  'signet.contacts.propose:rename-app-label',
] as const satisfies readonly Capability[];

const CAPABILITY_SET: ReadonlySet<string> = new Set<string>(CAPABILITIES);

export function isCapability(value: unknown): value is Capability {
  return typeof value === 'string' && CAPABILITY_SET.has(value);
}

/** Sort an arbitrary capability list into CAPABILITIES order, deduped. */
export function normaliseCapabilities(input: readonly Capability[]): Capability[] {
  const present = new Set<Capability>(input);
  return CAPABILITIES.filter((cap) => present.has(cap));
}

/**
 * One machine-readable line per capability, for `docs/WIRE.md` and a consumer's
 * own documentation. C10: this is NOT the copy a person approves against —
 * that lives in signet-app's `contacts-v2-copy.ts`, inside the repo's
 * vocabulary guard, where every other word the owner reads lives. Shipping
 * user-facing copy from `node_modules` would put it outside both the
 * forbidden-vocabulary scan and the no-console scan, and the words a consumer's
 * README promises are not automatically the words the owner should be shown.
 */
export const CAPABILITY_DESCRIPTIONS: Record<Capability, string> = {
  'signet.contacts.read:directory':
    'Read the directory: contact ids, type, display name, tier, tier source, identity pubkeys and linked pubkeys.',
  'signet.contacts.read:methods':
    'Read contact methods whose sharingPolicy is grantable (phone, email, website, postal address).',
  'signet.contacts.read:roles':
    'Read the owner-assigned role labels on each contact.',
  'signet.contacts.blocks.read':
    'Read blocked contacts, including their identity and linked pubkeys, so the app can filter them.',
  // R-28(d): signet-app applies an add-ken as soon as the batch validates —
  // there is no queue, no prompt, no owner decision. Describing it as a
  // request the owner answers made the consent false, so it says what happens:
  // the app adds the contact, at the weakest distance the model has.
  'signet.contacts.propose:add-ken':
    'Add contacts to your Ken list (recognised only, no access).',
  'signet.contacts.propose:rename-app-label':
    'Propose a rename that applies only inside this grant’s own projection.',
};

export const DEFAULT_STALENESS_SECONDS = 21600;  // 6 h — exploration §5.1 example grant
export const MIN_STALENESS_SECONDS = 3600;       // 1 h
export const MAX_STALENESS_SECONDS = 604800;     // 7 d

/**
 * Hard plaintext ceiling for anything this wire seals (R-5).
 *
 * Two limits meet here and the tighter one wins: nostr-tools' NIP-44 v2
 * implementation rejects plaintext over 65535 bytes (exploration §7 review
 * note), and signet-app's vault envelope pads into buckets topping out at
 * `TOP_BUCKET` = 65536 with a 4-byte length prefix — so 65532 bytes is the
 * most a projection body can be and still seal.
 *
 * This is ENFORCED, not documented: `buildProjection` throws above it, and the
 * producer fits the body first (`projectionByteLength`, and signet-app's
 * `buildContactProjection`, which drops the least recently updated contacts
 * and sets `truncated: true`). A projection that cannot fit fails loudly at
 * build time rather than failing to encrypt in a catch nobody reads.
 */
export const MAX_WIRE_BYTES = 65532;

export const MAX_APP_NAME = 64;
export const MAX_CAPABILITIES = 16;
export const MAX_CONTACTS_PER_PROJECTION = 2000;
export const MAX_IDENTITIES_PER_CONTACT = 16;
export const MAX_METHODS_PER_CONTACT = 16;
export const MAX_ROLES_PER_CONTACT = 8;
export const MAX_LINKED_PUBKEYS = 16;
export const MAX_DISPLAY_NAME = 100;
export const MAX_APP_LABEL = 100;
export const MAX_ROLE_LEN = 40;
export const MAX_METHOD_VALUE = 320;
export const MAX_URL_LEN = 512;
export const MAX_PROPOSALS_PER_BATCH = 50;

/**
 * C-I7: `relay` and `challenge` were the only two fields on this wire with no
 * upper bound, and both cross into somebody's storage.
 *
 * 256 is signet-app's own `MAX_RELAY_LEN` on the grants rail. A pairing whose
 * relay is longer than that is accepted by a lenient parser and then DROPPED
 * from the owner's sealed grant backup, so the grant works on the device that
 * approved it and silently never reaches a second one. Matching the producer's
 * cap is what stops the two sides disagreeing about which pairings exist.
 *
 * A challenge is exactly 32 hex characters — 128 bits, the same width as every
 * other random identifier here (`randomHex(16)`), which is what both this SDK
 * and signet-app emit. It is the consumer's own anti-replay nonce and is
 * echoed byte-for-byte, so accepting an arbitrary-length one bought nothing
 * and let a caller mint a 4-character "nonce" or a megabyte of hex.
 *
 * Both are HARD failures, never truncations: a truncated relay URL is a
 * different relay, and a truncated nonce is a weaker one.
 */
export const MAX_RELAY_LEN = 256;
export const CHALLENGE_HEX_CHARS = 32;

/** Ceiling on the raw pairing URI a parser will even look at. Every field
 *  inside it is capped, so a well-formed v2 URI is comfortably under 1 kB;
 *  anything past this is not a pairing request, and is refused before the
 *  query string is parsed at all. */
export const MAX_PAIRING_URI_CHARS = 2048;

/** Clamp a requested staleness window into the permitted band. Anything that
 *  is not a finite positive integer resolves to the default rather than 0 —
 *  a zero window would expire every projection the instant it was issued. */
export function clampStaleness(seconds: number | undefined): number {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds <= 0) {
    return DEFAULT_STALENESS_SECONDS;
  }
  const whole = Math.floor(seconds);
  if (whole < MIN_STALENESS_SECONDS) return MIN_STALENESS_SECONDS;
  if (whole > MAX_STALENESS_SECONDS) return MAX_STALENESS_SECONDS;
  return whole;
}
