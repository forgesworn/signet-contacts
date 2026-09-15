import { describe, it, expect } from 'vitest';
import type {
  ContactProjectionV2, ProjectedContact, ContactProposalV1, ProposalBatch,
  PairingRequestV2, PairingAckV2, PairingV2, ContactsState, PendingProposal, SignedNostrEvent,
} from './types.js';

describe('wire types', () => {
  it('constructs a full projection with every documented field', () => {
    const contact: ProjectedContact = {
      contactId: 'a'.repeat(32),
      type: 'person',
      identities: [{ pubkey: 'b'.repeat(64), verification: 'proven' }],
      displayName: 'Sam',
      avatar: { url: 'https://blossom.example/abc', hash: 'c'.repeat(64), key: 'd'.repeat(64) },
      effectiveTier: 'kith',
      tierSource: 'direct',
      roles: ['coach'],
      contactMethods: [{ kind: 'email', value: 'sam@example.com', verification: 'unverified' }],
      blocked: false,
      linkedPubkeys: ['e'.repeat(64)],
    };
    const projection: ContactProjectionV2 = {
      v: 2,
      grantId: 'f'.repeat(32),
      ownerPubkey: '1'.repeat(64),
      scopes: ['signet.contacts.read:directory'],
      frontier: { maxClock: 7, opCount: 12, publishedAt: 1_700_000_000, deviceId: '2'.repeat(32) },
      issuedAt: 1_700_000_000,
      expiresAt: 1_700_021_600,
      contacts: [contact],
      truncated: true,
    };
    expect(projection.contacts[0]?.effectiveTier).toBe('kith');
    expect(projection.expiresAt - projection.issuedAt).toBe(21600);
    // C13: a snapshot says who published it and when — no opIds.
    expect(projection.frontier.deviceId).toHaveLength(32);
    expect('opIds' in projection.frontier).toBe(false);
  });

  it('constructs a pairing request, ack, persisted pairing and proposal batch', () => {
    const request: PairingRequestV2 = {
      v: 2, appPubkey: 'a'.repeat(64), appName: 'Flock',
      capabilities: ['signet.contacts.read:directory', 'signet.contacts.blocks.read'],
      directory: 'owner', rendezvousRelay: 'wss://relay.example.com',
      t: 1_700_000_000, challenge: 'D'.repeat(32),
    };
    const ack: PairingAckV2 = {
      v: 2, grantId: 'f'.repeat(32), railPubkey: 'b'.repeat(64),
      projectionTag: '0'.repeat(32), proposalTag: '1'.repeat(32),
      relay: 'wss://relay.example.com',
      grantedCapabilities: ['signet.contacts.read:directory'],
      maxStalenessSeconds: 21600, challenge: request.challenge,
    };
    const pairing: PairingV2 = { ...ack, pairedAt: 1_700_000_001 } as PairingV2;
    const batch: ProposalBatch = {
      v: 1,
      proposals: [{
        v: 1, grantId: ack.grantId, operationId: '9'.repeat(32),
        action: 'add-ken', value: { pubkey: 'c'.repeat(64), displayName: 'Ada' },
        createdAt: 1_700_000_002,
      } satisfies ContactProposalV1],
    };
    expect(pairing.grantId).toBe(ack.grantId);
    expect(batch.proposals).toHaveLength(1);
  });

  it('starts consumer state empty and keeps a sticky blocked list', () => {
    const state: ContactsState = {
      grantId: null, projection: null, receivedAt: 0,
      blockedPubkeys: ['a'.repeat(64)], revoked: false,
    };
    expect(state.blockedPubkeys).toHaveLength(1);
  });

  it('types a pending proposal as consumer-side state only', () => {
    const pending: PendingProposal = {
      operationId: '9'.repeat(32), action: 'add-ken',
      value: { pubkey: 'c'.repeat(64), displayName: 'Ada' }, sentAt: 1_700_000_000,
    };
    // R-9: `sentAt` is the only timing the SDK offers — the consumer writes
    // its own "still waiting" copy against it.
    expect(pending.sentAt).toBe(1_700_000_000);
    expect(pending.operationId).toHaveLength(32);
  });

  it('describes a signed event without importing nostr-tools', () => {
    const event: SignedNostrEvent = {
      id: '0'.repeat(64), pubkey: '1'.repeat(64), created_at: 1, kind: 30078,
      tags: [['d', '2'.repeat(32)]], content: 'ciphertext', sig: '3'.repeat(128),
    };
    expect(event.tags[0]?.[0]).toBe('d');
  });
});
