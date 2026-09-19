import { expect, it, vi } from 'vitest';
import { createAppInviteClient } from './app-invite-client.js';
import type { ContactsSigner, RelayIo } from './client.js';
import type { PairingV2, SignedNostrEvent } from './wire/types.js';
import { appInviteTag } from './wire/app-invite.js';
const pairing: PairingV2 = { grantId: 'a'.repeat(32), railPubkey: 'b'.repeat(64), relay: 'wss://app.example',
  grantedCapabilities: ['signet.contacts.invites:create', 'signet.contacts.invites:receive'], maxStalenessSeconds: 3600, pairedAt: 100 };
const invite = { v: 1 as const, recipient: 'c'.repeat(64), secret: 'd'.repeat(64), relays: ['wss://contact.example/'] };
function fixture() {
  let posted: SignedNostrEvent;
  const signer: ContactsSigner = { pubkey: 'e'.repeat(64), nip44Encrypt: vi.fn(async (_key, text) => text),
    nip44Decrypt: vi.fn(async (_key, text) => text), signEvent: vi.fn(async event => ({ ...event, id: 'f'.repeat(64), sig: '0'.repeat(128) })) };
  const relay: RelayIo = { publish: vi.fn(async event => { posted = event; return true; }), fetchNewest: vi.fn(async () => {
    const request = JSON.parse(posted.content);
    return { kind: 30078, pubkey: pairing.railPubkey, created_at: 100, id: '1'.repeat(64), sig: '2'.repeat(128),
      tags: [['d', appInviteTag(pairing.grantId, request.requestId)]],
      content: JSON.stringify({ v: 1, grantId: pairing.grantId, requestId: request.requestId, createdAt: 100,
        ...(request.action === 'create-invite' ? { status: 'issued', invite } : { status: 'queued' }) }) };
  }) };
  return { signer, relay, client: createAppInviteClient({ signer, relay, now: () => 100 }) };
}
it('requests an invite and hands one over without requiring directory access', async () => {
  const { client, relay } = fixture();
  expect((await client.requestInvite(pairing, 'single-use', { timeoutMs: 0 }))?.invite).toEqual(invite);
  expect(await client.handOverInvite(pairing, invite, { timeoutMs: 0 })).toMatchObject({ status: 'queued' });
  expect(relay.publish).toHaveBeenCalledTimes(2);
});
it('rejects missing consent locally and refuses a reply from another author before decrypting', async () => {
  const { client, signer, relay } = fixture();
  expect(await client.requestInvite({ ...pairing, grantedCapabilities: [] })).toBeNull();
  expect(signer.signEvent).not.toHaveBeenCalled();
  vi.mocked(relay.fetchNewest).mockResolvedValue({ kind: 30078, pubkey: '9'.repeat(64), created_at: 100,
    tags: [], content: 'forged', id: '8'.repeat(64), sig: '7'.repeat(128) });
  expect(await client.requestInvite(pairing, 'single-use', { timeoutMs: 0 })).toBeNull();
  expect(signer.nip44Decrypt).not.toHaveBeenCalled();
});
