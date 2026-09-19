import type { ContactsSigner, RelayIo } from './client.js';
import type { PairingV2 } from './wire/types.js';
import type { ContactInvite } from './wire/invite.js';
import { randomHex } from './wire/ids.js';
import { appInviteTag, APP_INVITE_RECEIVE_CAPABILITY, APP_INVITE_REQUEST_CAPABILITY,
  parseAppInviteRequest, parseAppInviteReply, type AppInviteRequest, type AppInviteReply } from './wire/app-invite.js';

/** One request at a time per grant. RelayIo must authenticate event signatures
 * (the nostr-tools adapter does). A response never reveals whether peers connected. */
export function createAppInviteClient(options: { signer: ContactsSigner; relay: RelayIo; now?: () => number }) {
  const active = new Set<string>();
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  async function send(pairing: PairingV2, value: Pick<AppInviteRequest, 'action' | 'mode' | 'invite'>,
    wait: { timeoutMs?: number; signal?: AbortSignal } = {}): Promise<AppInviteReply | null> {
    const capability = value.action === 'create-invite' ? APP_INVITE_REQUEST_CAPABILITY : APP_INVITE_RECEIVE_CAPABILITY;
    if (!pairing.grantedCapabilities.some(cap => (cap as string) === capability) || active.has(pairing.grantId) || wait.signal?.aborted) return null;
    active.add(pairing.grantId);
    try {
      const request = parseAppInviteRequest(JSON.stringify({ v: 1, grantId: pairing.grantId,
        requestId: randomHex(16), createdAt: now(), ...value }), now());
      if (!request) return null;
      const content = await options.signer.nip44Encrypt(pairing.railPubkey, JSON.stringify(request));
      const event = await options.signer.signEvent({ kind: 30078, pubkey: options.signer.pubkey,
        created_at: request.createdAt, tags: [['d', appInviteTag(pairing.grantId)]], content });
      if (wait.signal?.aborted || !await options.relay.publish(event, [pairing.relay])) return null;
      const tag = appInviteTag(pairing.grantId, request.requestId);
      const deadline = Date.now() + Math.min(300_000, Math.max(0, wait.timeoutMs ?? 120_000));
      do {
        if (wait.signal?.aborted) return null;
        const reply = await options.relay.fetchNewest({ kinds: [30078], authors: [pairing.railPubkey], '#d': [tag], limit: 1 }, [pairing.relay], pairing.railPubkey);
        if (reply && reply.kind === 30078 && reply.pubkey === pairing.railPubkey && reply.content.length <= 16384
          && reply.tags.filter(t => t[0] === 'd').length === 1 && reply.tags.some(t => t[0] === 'd' && t[1] === tag)) {
          const plaintext = await options.signer.nip44Decrypt(pairing.railPubkey, reply.content);
          const result = parseAppInviteReply(plaintext, request, now());
          if (result && result.createdAt === reply.created_at) return result;
        }
        if (Date.now() >= deadline) return null;
        await new Promise(resolve => setTimeout(resolve, Math.min(1000, deadline - Date.now())));
      } while (Date.now() <= deadline);
      return null;
    } catch { return null; }
    finally { active.delete(pairing.grantId); }
  }
  return {
    requestInvite: (pairing: PairingV2, mode: 'single-use' | 'standing' = 'single-use', wait?: { timeoutMs?: number; signal?: AbortSignal }) =>
      send(pairing, { action: 'create-invite', mode }, wait),
    handOverInvite: (pairing: PairingV2, invite: ContactInvite, wait?: { timeoutMs?: number; signal?: AbortSignal }) =>
      send(pairing, { action: 'receive-invite', invite }, wait),
  };
}
