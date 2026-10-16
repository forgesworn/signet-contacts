# AGENTS.md

`@forgesworn/signet-contacts` is the TypeScript reference for the Signet contacts app-access wire (v2): pairing, encrypted projections, proposals and contact invites. `docs/WIRE.md` is the language-neutral specification; `vectors/` holds the frozen test vectors that ports (Kotlin and others) are checked against.

## Commands

Run these from the repository root. CI runs them in this order on Node 22.

```bash
npm ci
npm run typecheck      # tsc --noEmit
npm run build          # tsc, emits dist/
npm run no-console     # fails if shipped (non-test) source calls console.*
npm run vectors:check  # re-runs the vector tests with WRITE_VECTORS unset
npm test               # vitest run
```

On a loaded machine, `npx vitest run --maxWorkers=2 --testTimeout=60000` is steadier.

## Layout

- `src/wire/`: the wire layer (constants, pairing, ack, envelope, projection, proposal, state, invite). No I/O.
- `src/client.ts`: the consumer client. Signer, relay and storage are injected.
- `src/app-invite-client.ts`: the app introduction client.
- `src/adapters/`: `RelayIo` over a nostr-tools `SimplePool`, and the invite mailbox helpers.
- `src/*.test.ts` and `src/**/*.test.ts`: tests sit beside the code. `src/docs.test.ts` pins parts of `README.md`, `docs/WIRE.md`, `docs/INTEGRATION.md`, `SECURITY.md` and `CHANGELOG.md`, so run the tests after any doc edit.
- `vectors/`: generated vectors, asserted byte for byte. Regenerate only deliberately, with `WRITE_VECTORS=1` on the test files listed in `scripts/check-vectors.mjs`, and record the reason in `CHANGELOG.md`.

## Rules

- Never unblock anyone on expiry or revocation. The Blocked set is sticky: only a strictly newer, accepted, non-revoked projection may shrink it (`applyProjection` in `src/wire/state.ts`). `isFresh` is advisory and gates nothing.
- Never put an owner persona pubkey on the wire (R-31). A connected app learns the grant's rail pubkey and grant-scoped opaque contact ids, nothing more.
- No `console.*` in shipped source. Storage and relay failures are swallowed, not thrown, by `load`, `fetchProjection`, `propose` and `awaitPairingAck`.
- A wire change that alters a vector also changes the conformance repository and every port. Say so in `CHANGELOG.md`.
- `nostr-tools` is an optional peer dependency. `src/wire/` and `src/client.ts` must not import it; only the adapters may.
- British English in prose. Conventional commits (`type: description`).
