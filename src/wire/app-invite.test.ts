import { expect, it } from 'vitest';
import { parseAppInviteRequest, parseAppInviteReply, appInviteTag } from './app-invite.js';
const request = { v: 1 as const, grantId: 'a'.repeat(32), requestId: 'b'.repeat(32), createdAt: 100, action: 'create-invite' as const, mode: 'single-use' as const };
const invite = { v: 1, recipient: 'c'.repeat(64), secret: 'd'.repeat(64), relays: ['wss://relay.example/'] };
it('bounds request lifetime and rejects ambiguous actions', () => {
  expect(parseAppInviteRequest(JSON.stringify(request), 100)).toEqual(request);
  expect(parseAppInviteRequest(JSON.stringify(request), 400)).toBeNull();
  expect(parseAppInviteRequest(JSON.stringify(request), 99)).toBeNull();
  expect(parseAppInviteRequest(JSON.stringify({ ...request, invite }), 100)).toBeNull();
});
it('pins replies to request, action and freshness without revealing completion', () => {
  const reply = { v: 1, grantId: request.grantId, requestId: request.requestId, createdAt: 101, status: 'issued', invite };
  expect(parseAppInviteReply(JSON.stringify(reply), request, 101)?.invite).toEqual(invite);
  expect(parseAppInviteReply(JSON.stringify({ ...reply, requestId: 'e'.repeat(32) }), request, 101)).toBeNull();
  expect(parseAppInviteReply(JSON.stringify(reply), request, 400)).toBeNull();
  expect(parseAppInviteReply(JSON.stringify({ ...reply, status: 'complete' }), request, 101)).toBeNull();
  expect(appInviteTag(request.grantId)).not.toBe(appInviteTag(request.grantId, request.requestId));
});
