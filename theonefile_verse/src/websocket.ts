import * as redis from "./redis";
import * as oidc from "./oidc";
import * as db from "./database";
import * as auth from "./auth";
import {
  roomConnections, roomUsers, roomMeta, roomUsedNames, roomChatHistory,
  loadRoom, saveRoom, deleteRoomData, scheduleDestruction, resetDestructionTimer,
  scheduleEmptyDestruction, cancelEmptyDestruction, scheduleIdleCleanup, cancelIdleCleanup,
  EMPTY_DESTRUCT_OWNERLESS_GRACE_MS,
  persistTopology, isRoomViewOnly, noteForeignPersist, presence, currentTopology,
  validateTopology, sanitizeTopologyStrings, storedRoomBytes, storageQuotaAllows, STORAGE_QUOTA_ERROR,
  type Room, type RoomMeta
} from "./rooms";
import { validateWsSessionToken } from "./tokens";
import { mergeChangedOntoStored, validChangedKeys } from "./state-merge";
import { isSafeId, remapUnsafeId } from "./topology-shape";
import { checkWsRateLimit, wsRateLimitRetryAfterMs } from "./rate-limit";
import { getSettings, isValidUUID, getMaxRoomSizeBytes, getMaxGuestRoomSizeBytes, REDIS_FANOUT } from "./config";

export interface WsData {
  roomId?: string;
  connectionId?: string;
  userId?: string;
  verifiedUserId?: string;
  sessionUserId?: string;
  authenticated?: boolean;
  attached?: boolean;
  joined?: boolean;
  role?: RoomRole;
  identityCheckedAt?: number;
}


export const WS_IDLE_TIMEOUT_SECONDS = Math.min(255, Math.max(90,
  parseInt(process.env.WS_IDLE_TIMEOUT || '', 10) || 120));

export const WS_PING_INTERVAL_MS = Math.max(15000, Math.floor((WS_IDLE_TIMEOUT_SECONDS * 1000) / 2));

export const MAX_ROSTER_SNAPSHOT = 256;

export const MAX_CONNECTIONS_PER_ROOM = (() => {
  const raw = parseInt(process.env.MAX_ROOM_CONNECTIONS || '', 10);
  if (Number.isFinite(raw) && raw >= 0) return raw;
  return 64;
})();


export type RoomRole = 'owner' | 'admin' | 'editor' | 'viewer' | 'guest';

export function resolveRoomRole(room: Room | null, verifiedUserId: string | undefined): RoomRole {
  if (!verifiedUserId) return 'guest';
  let user: any = null;
  try { user = db.getUserById(verifiedUserId); } catch { user = null; }
  if (user && user.isActive === false) return 'guest';
  if (room?.ownerUserId && verifiedUserId === room.ownerUserId) return 'owner';
  if (!user) return 'guest';
  if (user.role === 'admin') return 'admin';
  return 'editor';
}

export function remapChangedKey(key: string): string {
  const parts = key.split("\u001f");
  if (parts.length !== 3 || parts[0] === "__top" || parts[0] === "__tabs") return key;
  if (!isSafeId(parts[1])) parts[1] = remapUnsafeId(parts[1]);
  return parts.join("\u001f");
}

export const IDENTITY_RECHECK_MS = 15000;

function socketIdentity(data: WsData | undefined): string | undefined {
  return data?.verifiedUserId || data?.sessionUserId;
}

function sendPermissions(ws: any, roomId: string): void {
  const data = ws.data as WsData;
  const viewOnly = isRoomViewOnly(roomId);
  try {
    ws.send(JSON.stringify({
      type: 'permissions',
      role: data.role || 'guest',
      canWrite: canWrite(data.role, viewOnly),
      viewOnly,
      pingIntervalMs: WS_PING_INTERVAL_MS
    }));
  } catch {  }
}

function closeForIdentity(ws: any, code: number, reason: string, message: string, errCode: string): void {
  try { ws.send(JSON.stringify({ type: 'error', code: errCode, error: message })); } catch {  }
  try { ws.close(code, reason); } catch {  }
}

export function revalidateSocketIdentity(ws: any, force = false): boolean {
  const data = ws.data as WsData | undefined;
  if (!data?.roomId) return false;
  const userId = socketIdentity(data);
  if (!userId) return true;
  const now = Date.now();
  if (!force && data.identityCheckedAt && now - data.identityCheckedAt < IDENTITY_RECHECK_MS) return true;
  data.identityCheckedAt = now;
  let user: any = null;
  try { user = db.getUserById(userId); } catch { user = null; }
  const room = loadRoom(data.roomId);
  const isOwner = !!(room?.ownerUserId && room.ownerUserId === userId);
  if (!user && !isOwner) {
    if (!data.role || data.role === 'guest') return true;
    closeForIdentity(ws, 4003, 'Account disabled', 'Your account is no longer active. Sign in again to continue.', 'account-disabled');
    return false;
  }
  if (user && user.isActive === false) {
    closeForIdentity(ws, 4003, 'Account disabled', 'Your account is no longer active. Sign in again to continue.', 'account-disabled');
    return false;
  }
  const next = resolveRoomRole(room, userId);
  if (next !== data.role) {
    data.role = next;
    if (data.joined) sendPermissions(ws, data.roomId);
  }
  return true;
}

export function refreshUserSockets(userId: string): number {
  let touched = 0;
  for (const [, connections] of roomConnections) {
    for (const ws of [...connections]) {
      if (socketIdentity(ws.data as WsData) !== userId) continue;
      touched++;
      revalidateSocketIdentity(ws, true);
    }
  }
  return touched;
}

export function disconnectRoomGuestsAfterPasswordChange(roomId: string): number {
  const connections = roomConnections.get(roomId);
  if (!connections) return 0;
  let closed = 0;
  for (const ws of [...connections]) {
    const role = (ws.data as WsData | undefined)?.role;
    if (role === 'owner' || role === 'admin') continue;
    closeForIdentity(ws, 4004, 'Room password changed', 'The room password was changed. Enter the new password to rejoin.', 'room-password-changed');
    closed++;
  }
  return closed;
}

export function canWrite(role: RoomRole | undefined, viewOnly: boolean): boolean {
  if (role === 'owner' || role === 'admin') return true;
  if (role === 'viewer') return false;
  if (viewOnly) return false;
  return true;
}

export function isWriteAction(msg: any): boolean {
  if (!msg || typeof msg !== 'object') return false;
  if (msg.type === 'state') return true;
  if (msg.type === 'cursor' && msg.furnOp) return true;
  return false;
}

export function wsRateBucketFor(msg: any): string {
  if (msg && msg.type === 'cursor' && msg.d3 && msg.furnOp) return 'furnOp';
  return msg?.type;
}

export interface FanoutTransport {
  enabled(): boolean;
  publish(roomId: string, message: any): Promise<boolean>;
  subscribe(roomId: string, handler: (message: any) => void): Promise<() => Promise<void>>;
}

export const fanout: FanoutTransport = {
  enabled: () => REDIS_FANOUT,
  publish: (roomId, message) => redis.publishToRoom(roomId, message),
  subscribe: (roomId, handler) => redis.subscribeToRoom(roomId, handler)
};

interface FanoutSub { gen: number; unsub?: () => Promise<void>; pending: boolean }
const roomFanoutSubs = new Map<string, FanoutSub>();

export function fanoutSubscriptionCount(): number { return roomFanoutSubs.size; }

function deliverLocal(roomId: string, payload: string, exclude?: any): void {
  const connections = roomConnections.get(roomId);
  if (!connections) return;
  for (const client of connections) {
    if (client === exclude) continue;
    if (client.readyState !== 1) continue;
    try { client.send(payload); } catch {  }
  }
}

const STATE_PREFIX = '{"type":"state","state":';

export function applyFanoutMessage(roomId: string, payload: unknown): void {
  if (typeof payload !== 'string') return;
  deliverLocal(roomId, payload);
  if (payload.startsWith(STATE_PREFIX) && payload.endsWith('}')) {
    const json = payload.slice(STATE_PREFIX.length, -1);
    try { noteForeignPersist(roomId, json); } catch {  }
  }
}

function fanoutPublish(roomId: string, payload: string): void {
  if (!fanout.enabled()) return;
  void fanout.publish(roomId, payload).catch(() => {  });
}

function broadcastRoom(ws: any, roomId: string, payload: string): void {
  ws.publish(roomId, payload);
  fanoutPublish(roomId, payload);
}

function ensureFanoutSubscription(roomId: string): void {
  if (!fanout.enabled()) return;
  const existing = roomFanoutSubs.get(roomId);
  if (existing) return;
  const entry: FanoutSub = { gen: 1, pending: true };
  roomFanoutSubs.set(roomId, entry);
  const gen = entry.gen;
  void fanout.subscribe(roomId, (message) => applyFanoutMessage(roomId, message))
    .then(unsub => {
      entry.pending = false;
      if (roomFanoutSubs.get(roomId) !== entry || entry.gen !== gen) {
        void unsub().catch(() => {});
        return;
      }
      entry.unsub = unsub;
    })
    .catch(err => {
      if (roomFanoutSubs.get(roomId) === entry) roomFanoutSubs.delete(roomId);
      console.error('[Fanout] subscribe failed:', err?.message);
    });
}

function releaseFanoutSubscription(roomId: string): void {
  const entry = roomFanoutSubs.get(roomId);
  if (!entry) return;
  roomFanoutSubs.delete(roomId);
  entry.gen++;
  if (entry.unsub) void entry.unsub().catch(() => {});
}

export function pushRoomReset(roomId: string, topology: any): number {
  const connections = roomConnections.get(roomId);
  if (!connections || connections.size === 0) return 0;
  const payload = JSON.stringify({ type: 'initial-state', state: sanitizeTopologyStrings(topology) });
  let sent = 0;
  for (const client of connections) {
    if (client.readyState !== 1 || !(client.data as WsData | undefined)?.joined) continue;
    try { client.send(payload); sent++; } catch {}
  }
  return sent;
}

export function broadcastRoomPermissions(roomId: string): number {
  const connections = roomConnections.get(roomId);
  if (!connections || connections.size === 0) return 0;
  const viewOnly = isRoomViewOnly(roomId);
  let sent = 0;
  for (const client of connections) {
    if (client.readyState !== 1) continue;
    const data = client.data as WsData | undefined;
    if (!data?.joined) continue;
    const role = data.role || 'guest';
    try {
      client.send(JSON.stringify({
        type: 'permissions',
        role,
        canWrite: canWrite(role, viewOnly),
        viewOnly,
        pingIntervalMs: WS_PING_INTERVAL_MS
      }));
      sent++;
    } catch {  }
  }
  return sent;
}

function denyWrite(ws: any, msg: any) {
  ws.send(JSON.stringify({
    type: 'error',
    error: 'This room is view only, your change was not saved.',
    code: 'forbidden',
    messageType: msg?.type
  }));
}

function attachToRoom(ws: any): boolean {
  const data = ws.data as WsData;
  const roomId = data?.roomId;
  if (!roomId) return false;
  if (data.attached) return true;
  if (!roomConnections.has(roomId)) roomConnections.set(roomId, new Set());
  const connections = roomConnections.get(roomId)!;
  if (MAX_CONNECTIONS_PER_ROOM > 0 && connections.size >= MAX_CONNECTIONS_PER_ROOM) {
    try {
      ws.send(JSON.stringify({ type: 'error', code: 'room-full', error: 'This room has reached its connection limit. Try again shortly.' }));
    } catch {  }
    ws.close(4008, 'Room full');
    return false;
  }
  data.attached = true;
  const wasEmpty = connections.size === 0;
  connections.add(ws);
  if (wasEmpty) ensureFanoutSubscription(roomId);
  if (!roomUsers.has(roomId)) roomUsers.set(roomId, new Map());
  ws.subscribe(roomId);
  const meta = roomMeta.get(roomId) || { connectedUsers: 0 };
  meta.connectedUsers++;
  meta.ownerWasLast = false;
  if (meta.destructTimer) { clearTimeout(meta.destructTimer); meta.destructTimer = undefined; }
  roomMeta.set(roomId, meta);
  cancelEmptyDestruction(roomId);
  cancelIdleCleanup(roomId);
  return true;
}

function stampIdentity(ws: any, roomId: string, msg: any): void {
  const wsUserId = (ws.data as WsData)?.userId;
  msg.userId = wsUserId;
  const user = roomUsers.get(roomId)?.get(wsUserId!);
  msg.userName = user?.name || '';
  if (user?.color) msg.color = user.color; else delete msg.color;
}

export const websocketHandlers = {
  open(ws: any) {
    const data = ws.data as WsData;
    if (!data?.roomId) return;
    data.connectionId = crypto.randomUUID();
    if (data.authenticated) {
      data.role = resolveRoomRole(loadRoom(data.roomId), data.sessionUserId);
      data.identityCheckedAt = Date.now();
      attachToRoom(ws);
    }
  },

  async message(ws: any, message: any) {
    const roomId = (ws.data as WsData)?.roomId;
    const connectionId = (ws.data as WsData)?.connectionId;
    if (!roomId || !connectionId) return;
    const rawLen = typeof message === 'string'
      ? Buffer.byteLength(message, 'utf8')
      : ((message && message.byteLength) || 0);
    if (rawLen > getMaxRoomSizeBytes() + 64 * 1024) return;
    let msg;
    try { msg = JSON.parse(message.toString()); } catch { return; }

    if (msg.type === 'auth') {
      if ((ws.data as WsData).authenticated) {
        ws.send(JSON.stringify({ type: 'auth-ok', pingIntervalMs: WS_PING_INTERVAL_MS }));
        return;
      }
      const token = msg.token;
      if (!token || typeof token !== 'string') {
        ws.send(JSON.stringify({ type: 'auth-error', error: 'Token required' }));
        ws.close(4001, 'Authentication failed');
        return;
      }
      const tokenValidation = await validateWsSessionToken(token, roomId);
      if (!tokenValidation.valid) {
        ws.send(JSON.stringify({ type: 'auth-error', error: 'Invalid or expired token' }));
        ws.close(4001, 'Authentication failed');
        return;
      }
      (ws.data as WsData).authenticated = true;
      (ws.data as WsData).verifiedUserId = tokenValidation.collabUserId;
      (ws.data as WsData).role = resolveRoomRole(loadRoom(roomId), tokenValidation.collabUserId);
      (ws.data as WsData).identityCheckedAt = Date.now();
      if (!attachToRoom(ws)) return;
      ws.send(JSON.stringify({ type: 'auth-ok', pingIntervalMs: WS_PING_INTERVAL_MS }));
      return;
    }

    if (!(ws.data as WsData).authenticated) {
      ws.send(JSON.stringify({ type: 'auth-error', error: 'Authenticate first' }));
      ws.close(4001, 'Not authenticated');
      return;
    }

    const validTypes = ['join', 'leave', 'presence', 'state', 'chat', 'cursor', 'typing', 'ping'];
    if (!msg.type || !validTypes.includes(msg.type)) return;

    const rateBucket = wsRateBucketFor(msg);
    const wsUserKey = (ws.data as WsData)?.verifiedUserId ? 'u:' + (ws.data as WsData).verifiedUserId : null;
    if (!checkWsRateLimit(connectionId, rateBucket) || (wsUserKey && !checkWsRateLimit(wsUserKey, rateBucket))) {
      if (rateBucket === 'furnOp') {
        let echoOp: any = msg.furnOp;
        try {
          if ((JSON.stringify(echoOp) ?? '').length > 1024) echoOp = null;
        } catch { echoOp = null; }
        ws.send(JSON.stringify({
          type: 'error', code: 'rate-limited', channel: 'furnOp',
          error: 'Too many 3D scene updates, resend.',
          op: echoOp, retryAfterMs: wsRateLimitRetryAfterMs('furnOp')
        }));
      } else {
        ws.send(JSON.stringify({ type: 'rate-limited', messageType: msg.type }));
      }
      return;
    }

    if (msg.type === 'ping') {
      const pingUserId = (ws.data as WsData)?.userId;
      if (pingUserId && presence.enabled()) {
        void presence.touch(roomId, pingUserId).catch(() => {  });
      }
      ws.send(JSON.stringify({ type: 'pong' }));
      return;
    }

    if (msg.type !== 'join' && !(ws.data as WsData).joined) {
      ws.send(JSON.stringify({ type: 'error', code: 'join-required', error: 'Join the room before sending messages' }));
      return;
    }

    const messageStr = message.toString();
    const maxSize = (msg.type === 'state' && msg.state) ? getMaxRoomSizeBytes() + 64 * 1024 : 1024;
    if (Buffer.byteLength(messageStr, 'utf8') > maxSize) return;

    if (isWriteAction(msg)) {
      if (!revalidateSocketIdentity(ws)) return;
      const role = (ws.data as WsData).role;
      if (!canWrite(role, isRoomViewOnly(roomId))) {
        denyWrite(ws, msg);
        return;
      }
    }

    if (msg.type === 'chat' && !getSettings().chatEnabled) {
      ws.send(JSON.stringify({ type: 'error', code: 'chat-disabled', error: 'Chat is disabled on this instance' }));
      return;
    }
    if (msg.type === 'cursor' && !msg.furnOp && !getSettings().cursorSharingEnabled) return;
    if (msg.type === 'typing' && !getSettings().chatEnabled) return;

    if (msg.type === 'chat') {
      if (!msg.text || typeof msg.text !== 'string') return;
      if (msg.text.length > 500) msg.text = msg.text.substring(0, 500);
      msg.text = msg.text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
      stampIdentity(ws, roomId, msg);
      if (!roomChatHistory.has(roomId)) roomChatHistory.set(roomId, []);
      const history = roomChatHistory.get(roomId)!;
      history.push({ ...msg, timestamp: Date.now() });
      if (history.length > 100) history.splice(0, history.length - 100);
      broadcastRoom(ws, roomId, JSON.stringify(msg));
      resetDestructionTimer(roomId);
      return;
    }

    if (msg.type === 'join' && msg.user) {
      const userId = msg.user.id;
      if (!userId || !isValidUUID(userId)) return;

      const verifiedUserId = (ws.data as WsData)?.verifiedUserId;
      if (verifiedUserId) {
        if (userId !== verifiedUserId) {
          ws.send(JSON.stringify({ type: 'error', error: 'User ID mismatch with session token' }));
          return;
        }
      }

      let rawName = msg.user.name;
      if (rawName && typeof rawName === 'string') {
        rawName = rawName.substring(0, 30).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;').trim();
      }
      msg.user = { id: userId, name: rawName || '', color: msg.user.color || '' };
      const userName = rawName?.toLowerCase().trim();
      const users = roomUsers.get(roomId)!;

      if (!roomUsedNames.has(roomId)) roomUsedNames.set(roomId, new Map());
      const usedNames = roomUsedNames.get(roomId)!;

      let clusterPresence: Map<string, any> | null = null;
      if (presence.enabled()) {
        try { clusterPresence = await presence.list(roomId); } catch { clusterPresence = null; }
        if (ws.readyState !== 1 || !(ws.data as WsData).attached) return;
      }

      const existingUser = users.get(userId);
      const isNameChange = existingUser && existingUser.name?.toLowerCase().trim() !== userName;
      const isNewUser = !existingUser;

      if (isNameChange && !getSettings().nameChangeEnabled) {
        ws.send(JSON.stringify({ type: 'name-rejected', reason: 'Name changes are disabled on this instance' }));
        return;
      }
      if (userName && (isNewUser || isNameChange)) {
        const nameOwner = usedNames.get(userName);
        if (nameOwner && nameOwner !== userId) {
          ws.send(JSON.stringify({ type: 'name-rejected', reason: 'Name already taken in this room' }));
          return;
        }
        if (clusterPresence) {
          for (const [otherId, other] of clusterPresence) {
            if (otherId === userId) continue;
            const otherName = typeof other?.name === 'string' ? other.name.toLowerCase().trim() : '';
            if (otherName && otherName === userName) {
              ws.send(JSON.stringify({ type: 'name-rejected', reason: 'Name already taken in this room' }));
              return;
            }
          }
        }
        if (isNameChange && existingUser?.name) {
          usedNames.delete(existingUser.name.toLowerCase().trim());
        }
        usedNames.set(userName, userId);
      }

      (ws.data as WsData).userId = userId;
      (ws.data as WsData).joined = true;
      users.delete(userId);
      users.set(userId, msg.user);
      const existingUsers = Array.from(users.values()).filter(u => u.id !== userId);
      if (clusterPresence) {
        const seen = new Set<string>(existingUsers.map(u => u.id));
        seen.add(userId);
        for (const [otherId, other] of clusterPresence) {
          if (seen.has(otherId) || !other || typeof other !== 'object') continue;
          if (!isValidUUID(otherId)) continue;
          seen.add(otherId);
          existingUsers.push({
            id: otherId,
            name: typeof other.name === 'string' ? other.name.slice(0, 30) : '',
            color: typeof other.color === 'string' ? other.color.slice(0, 32) : ''
          });
          if (existingUsers.length >= MAX_ROSTER_SNAPSHOT) break;
        }
      }
      if (existingUsers.length > 0) ws.send(JSON.stringify({ type: 'users', users: existingUsers }));

      if (isNewUser) {
        const room = loadRoom(roomId);
        const topo = room ? currentTopology(roomId) : null;
        if (room && topo) {
          ws.send(JSON.stringify({ type: 'initial-state', state: sanitizeTopologyStrings(topo) }));
        } else {
          ws.send(JSON.stringify({ type: 'initial-state', state: null }));
        }
        const chatHistory = roomChatHistory.get(roomId);
        if (chatHistory && chatHistory.length > 0) {
          ws.send(JSON.stringify({ type: 'chat-history', messages: chatHistory }));
        }
        db.addActivityLog({ timestamp: new Date().toISOString(), roomId, userId, userName: rawName, eventType: "join" });
      }

      void presence.set(roomId, userId, msg.user).catch(() => {  });

      ws.send(JSON.stringify({
        type: 'permissions',
        role: (ws.data as WsData).role || 'guest',
        canWrite: canWrite((ws.data as WsData).role, isRoomViewOnly(roomId)),
        viewOnly: isRoomViewOnly(roomId),
        pingIntervalMs: WS_PING_INTERVAL_MS
      }));

      const joinMsg = JSON.stringify(msg);
      const connections = roomConnections.get(roomId);
      if (connections) {
        connections.forEach(client => { if (client !== ws && client.readyState === 1) client.send(joinMsg); });
      }
      fanoutPublish(roomId, joinMsg);
    } else if (msg.type === 'presence') {
      const wsUserId = (ws.data as WsData)?.userId;
      if (!wsUserId) return;
      stampIdentity(ws, roomId, msg);
      const users = roomUsers.get(roomId);
      if (users) {
        const user = users.get(wsUserId);
        if (user) {
          if (Array.isArray(msg.selectedNodes)) {
            user.selectedNodes = msg.selectedNodes.filter((id: unknown) => typeof id === 'string' && /^[\w-]+$/.test(id)).slice(0, 50);
            msg.selectedNodes = user.selectedNodes;
          }
          if (typeof msg.editingNode === 'string' && /^[\w-]+$/.test(msg.editingNode)) {
            user.editingNode = msg.editingNode;
          } else if (msg.editingNode === null) {
            user.editingNode = null;
          }
        }
      }
      broadcastRoom(ws, roomId, JSON.stringify(msg));
    } else if (msg.type === 'state') {
      if (msg.state) {
        const topologyValidation = validateTopology(msg.state);
        if (!topologyValidation.valid) {
          ws.send(JSON.stringify({ type: 'error', error: topologyValidation.error || 'Invalid state data' }));
          return;
        }
        let next = topologyValidation.sanitized;
        let corrected = false;
        const rawChanged = msg.changed !== undefined ? validChangedKeys(msg.changed) : null;
        const changed = rawChanged ? rawChanged.map(remapChangedKey) : null;
        if (changed) {
          const merged = mergeChangedOntoStored(currentTopology(roomId), next, changed);
          if (merged) {
            const mv = validateTopology(merged);
            if (mv.valid) {
              corrected = JSON.stringify(mv.sanitized) !== JSON.stringify(next);
              next = mv.sanitized;
            }
          }
        }
        const json = JSON.stringify(next);
        const previousBytes = storedRoomBytes(roomId);
        if ((ws.data as WsData).role === 'guest' && json.length > getMaxGuestRoomSizeBytes() && json.length > previousBytes) {
          ws.send(JSON.stringify({ type: 'error', code: 'room-too-large', error: 'This room is larger than guests may save. Sign in to keep editing, or remove large images and recordings.' }));
          return;
        }
        if (!storageQuotaAllows(json.length, previousBytes)) {
          ws.send(JSON.stringify({ type: 'error', code: 'storage-full', error: STORAGE_QUOTA_ERROR }));
          return;
        }
        broadcastRoom(ws, roomId, STATE_PREFIX + json + '}');
        if (corrected && ws.readyState === 1) ws.send(STATE_PREFIX + json + '}');
        persistTopology(roomId, next, json, new Date().toISOString());
      } else {
        return;
      }
    } else if (msg.type !== 'join') {
      stampIdentity(ws, roomId, msg);
      broadcastRoom(ws, roomId, JSON.stringify(msg));
    }
    resetDestructionTimer(roomId);
  },

  close(ws: any) {
    const roomId = (ws.data as WsData)?.roomId;
    const userId = (ws.data as WsData)?.userId;
    const verifiedUserId = (ws.data as WsData)?.verifiedUserId;
    if (!roomId || !(ws.data as WsData)?.attached) return;
    (ws.data as WsData).attached = false;
    const connections = roomConnections.get(roomId);
    if (connections) {
      connections.delete(ws);
      if (connections.size === 0) {
        roomConnections.delete(roomId);
        releaseFanoutSubscription(roomId);
      }
    }
    if (userId) {
      const users = roomUsers.get(roomId);
      if (users) {
        const user = users.get(userId);
        users.delete(userId);
        const leaveMsg = JSON.stringify({ type: 'leave', userId });
        if (connections && connections.size > 0) {
          connections.forEach(client => { if (client.readyState === 1) client.send(leaveMsg); });
        }
        fanoutPublish(roomId, leaveMsg);
        if (users.size === 0) roomUsers.delete(roomId);
        db.addActivityLog({ timestamp: new Date().toISOString(), roomId, userId, userName: user?.name, eventType: "leave" });
        void presence.remove(roomId, userId).catch(() => {  });
      }
      const usedNames = roomUsedNames.get(roomId);
      if (usedNames) {
        for (const [name, owner] of usedNames) {
          if (owner === userId) usedNames.delete(name);
        }
        if (usedNames.size === 0) roomUsedNames.delete(roomId);
      }
    }
    ws.unsubscribe(roomId);
    const meta = roomMeta.get(roomId);
    if (meta) {
      meta.connectedUsers = Math.max(0, meta.connectedUsers - 1);
      if (meta.connectedUsers === 0) {
        const room = loadRoom(roomId);
        const identity = verifiedUserId || (ws.data as WsData)?.sessionUserId;
        meta.ownerWasLast = !!(room?.ownerUserId && identity === room.ownerUserId);
        meta.lastLeaverWasUser = !!identity && ((ws.data as WsData)?.role || 'guest') !== 'guest';
        if (room) {
          if (room.destruct.mode === "empty") {
            scheduleEmptyDestruction(roomId, room.ownerUserId ? undefined : EMPTY_DESTRUCT_OWNERLESS_GRACE_MS);
          } else if (room.destruct.mode === "time") {
            scheduleDestruction(roomId, room.destruct.value);
          }
        }
        scheduleIdleCleanup(roomId);
      }
    }
  }
};
