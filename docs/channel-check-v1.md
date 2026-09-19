# Authenticated-channel words, draft v1

This additive profile lets KithMoot carry a commit/reveal check over its existing
credential-authenticated room channel. It does not create a Signet contact or
claim a human has compared the words. The mailbox invite profile and its frozen
vectors remain unchanged. Maintainer review is required before release.

The transport must authenticate the exact `from` participant, bind it to the
current room/channel, and verify `to` is the local participant. Possession of a
shared room encryption key is insufficient: use the room's device credential and
signed message verification. KithMoot uses the room ID for `context`; other apps
must specify their own stable, 32-byte context binding. Context is public, never
a secret or a private key. Channel messages must not cross rooms.

A requester explicitly starts a check with a random 16-byte ID and random
32-byte nonce A. The recipient explicitly accepts with independent random
32-byte nonce B. The requester durably pins the first acceptance before sending
nonce A. A different acceptance for the same request is always rejected, even
after restart. The recipient validates the commitment and acceptance hash before
showing words. The requester shows words after its reveal was sent. A complete
transcript remains usable for later human comparison. Transport completion alone
never marks a contact verified.

Messages have a ten-minute handshake lifetime and a 2048-byte cap. Canonical
hashes use the parser's allowlisted field order, JSON UTF-8 and SHA-256. The
commitment binds ID, context, both participant keys and nonce A. Message hashes
bind the complete canonical request and acceptance. Word material binds those
two hashes and nonce A; reveal time is deliberately excluded to prevent grinding
words after the nonce is known. The three-word directional derivation uses
`spoken-token` 2.1.0 with sorted participant roles and the namespace exported as
`CHANNEL_CHECK_WORDS_NAMESPACE`. Exact bytes and words are recorded in
`vectors/channel-check-v1.json`.

Persist private state before emitting every new message. Retries resend the same
persisted message, not new nonces or timestamps. Pin terminal/declined state so a
replay cannot restart a check. Bound active requests and retained transcripts;
rate-limit unsolicited input. A failed storage write must prevent publication or
word display. Serialise read/modify/write operations across tabs. On sign-out or
room change, cancel pending work. Never silently fall back to old room-key words
when the peer does not support this profile.
