/** Draft app-introduction transport. Each grant has one outstanding request slot.
 * Payloads are NIP-44 encrypted between the app key and its random grant rail.
 * Replies acknowledge issuance/queueing only, never connection completion. */
import { isHex } from './ids.js';
import { parseContactInvite, type ContactInvite } from './invite.js';
export const APP_INVITE_REQUEST_SECONDS = 300;
export const APP_INVITE_REQUEST_CAPABILITY = 'signet.contacts.invites:create' as const;
export const APP_INVITE_RECEIVE_CAPABILITY = 'signet.contacts.invites:receive' as const;
export interface AppInviteRequest {
  v: 1; grantId: string; requestId: string; createdAt: number;
  action: 'create-invite' | 'receive-invite';
  mode?: 'single-use' | 'standing'; invite?: ContactInvite;
}
export interface AppInviteReply {
  v: 1; grantId: string; requestId: string; createdAt: number;
  status: 'issued' | 'queued'; invite?: ContactInvite;
}
const stamp = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
function base(value: unknown): value is { v: 1; grantId: string; requestId: string; createdAt: number } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const v = value as AppInviteRequest;
  return v.v === 1 && isHex(v.grantId, 32) && isHex(v.requestId, 32) && stamp(v.createdAt);
}
export function parseAppInviteRequest(json: string, now: number): AppInviteRequest | null {
  if (json.length > 8192 || !stamp(now)) return null;
  try {
    const raw: unknown = JSON.parse(json);
    if (!base(raw) || raw.createdAt > now || raw.createdAt + APP_INVITE_REQUEST_SECONDS <= now) return null;
    const v = raw as AppInviteRequest;
    const common = { v: 1 as const, grantId: v.grantId, requestId: v.requestId, createdAt: v.createdAt };
    if (v.action === 'create-invite' && (v.mode === 'single-use' || v.mode === 'standing') && v.invite === undefined)
      return { ...common, action: v.action, mode: v.mode };
    if (v.action === 'receive-invite' && v.mode === undefined) {
      const invite = parseContactInvite(JSON.stringify(v.invite), now);
      if (invite) return { ...common, action: v.action, invite };
    }
    return null;
  } catch { return null; }
}
export function parseAppInviteReply(json: string, request: AppInviteRequest, now: number): AppInviteReply | null {
  if (json.length > 8192 || !stamp(now)) return null;
  try {
    const raw: unknown = JSON.parse(json);
    if (!base(raw) || raw.grantId !== request.grantId || raw.requestId !== request.requestId
      || raw.createdAt < request.createdAt || raw.createdAt > now || now >= request.createdAt + APP_INVITE_REQUEST_SECONDS) return null;
    const v = raw as AppInviteReply;
    const common = { v: 1 as const, grantId: v.grantId, requestId: v.requestId, createdAt: v.createdAt };
    if (request.action === 'receive-invite' && v.status === 'queued' && v.invite === undefined) return { ...common, status: 'queued' };
    if (request.action === 'create-invite' && v.status === 'issued') {
      const invite = parseContactInvite(JSON.stringify(v.invite), now);
      if (invite) return { ...common, status: 'issued', invite };
    }
    return null;
  } catch { return null; }
}
export function appInviteTag(grantId: string, replyId?: string): string {
  if (!isHex(grantId, 32) || (replyId !== undefined && !isHex(replyId, 32))) throw new Error('Invalid app invite id');
  return `signet:contacts:app-invite:${grantId}${replyId ? ':' + replyId : ''}`;
}
