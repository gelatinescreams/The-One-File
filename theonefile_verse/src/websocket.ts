import * as redis from "./redis";
import * as oidc from "./oidc";
import * as db from "./database";
import * as auth from "./auth";
import { roomConnections, roomUsers, roomMeta, roomUsedNames, roomChatHistory, loadRoom, saveRoom, deleteRoomData, scheduleDestruction, resetDestructionTimer, validateTopology, sanitizeTopologyStrings, type Room, type RoomMeta } from "./rooms";
import { validateWsSessionToken } from "./tokens";
import { checkWsRateLimit } from "./rate-limit";
import { getSettings, isValidUUID } from "./config";

export interface WsData {
  roomId?: string;
  connectionId?: string;
  userId?: string;
  verifiedUserId?: string;
  authenticated?: boolean;
}

export const websocketHandlers = {
  open(ws: any) {
    const roomId = (ws.data as WsData)?.roomId;
    if (!roomId) return;
    const connectionId = crypto.randomUUID();
    (ws.data as WsData).connectionId = connectionId;
    if (!roomConnections.has(roomId)) roomConnections.set(roomId, new Set());
    roomConnections.get(roomId)!.add(ws);
    if (!roomUsers.has(roomId)) roomUsers.set(roomId, new Map());
    ws.subscribe(roomId);
    const meta = roomMeta.get(roomId) || { connectedUsers: 0 };
    meta.connectedUsers++;
    if (meta.destructTimer) { clearTimeout(meta.destructTimer); meta.destructTimer = undefined; }
    roomMeta.set(roomId, meta);
  },

  async message(ws: any, message: any) {
    const roomId = (ws.data as WsData)?.roomId;
    const connectionId = (ws.data as WsData)?.connectionId;
    if (!roomId || !connectionId) return;
    let msg;
    try { msg = JSON.parse(message.toString()); } catch { return; }

    if (msg.type === 'auth') {
      if ((ws.data as WsData).authenticated) {
        ws.send(JSON.stringify({ type: 'auth-ok' }));
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
      ws.send(JSON.stringify({ type: 'auth-ok' }));
      return;
    }

    if (!(ws.data as WsData).authenticated) {
      ws.send(JSON.stringify({ type: 'auth-error', error: 'Authenticate first' }));
      ws.close(4001, 'Not authenticated');
      return;
    }

    const validTypes = ['join', 'leave', 'presence', 'state', 'patch', 'chat', 'cursor', 'typing'];
    if (!msg.type || !validTypes.includes(msg.type)) return;

    if (!checkWsRateLimit(connectionId, msg.type)) {
      ws.send(JSON.stringify({ type: 'rate-limited', messageType: msg.type }));
      return;
    }

    const messageStr = message.toString();
    const maxSize = msg.type === 'state' ? 5 * 1024 * 1024 : 1024;
    if (messageStr.length > maxSize) return;

    if (msg.type === 'chat') {
      if (!msg.text || typeof msg.text !== 'string') return;
      if (msg.text.length > 500) msg.text = msg.text.substring(0, 500);
      msg.text = msg.text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
      if (!roomChatHistory.has(roomId)) roomChatHistory.set(roomId, []);
      const history = roomChatHistory.get(roomId)!;
      history.push({ ...msg, timestamp: Date.now() });
      if (history.length > 100) history.splice(0, history.length - 100);
      ws.publish(roomId, JSON.stringify(msg));
      resetDestructionTimer(roomId);
      return;
    }

    if (msg.type === 'join' && msg.user) {
      let userId = msg.user.id;
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

      const existingUser = users.get(userId);
      const isNameChange = existingUser && existingUser.name?.toLowerCase().trim() !== userName;
      const isNewUser = !existingUser;

      if (userName && (isNewUser || isNameChange)) {
        const nameOwner = usedNames.get(userName);
        if (nameOwner && nameOwner !== userId) {
          ws.send(JSON.stringify({ type: 'name-rejected', reason: 'Name already taken in this room' }));
          return;
        }
        if (isNameChange && existingUser?.name) {
          usedNames.delete(existingUser.name.toLowerCase().trim());
        }
        usedNames.set(userName, userId);
      }

      (ws.data as WsData).userId = userId;
      users.delete(userId);
      users.set(userId, msg.user);
      const existingUsers = Array.from(users.values()).filter(u => u.id !== userId);
      if (existingUsers.length > 0) ws.send(JSON.stringify({ type: 'users', users: existingUsers }));

      if (isNewUser) {
        const room = loadRoom(roomId);
        if (room && room.topology) {
          ws.send(JSON.stringify({ type: 'initial-state', state: sanitizeTopologyStrings(room.topology) }));
        } else {
          ws.send(JSON.stringify({ type: 'initial-state', state: null }));
        }
        const chatHistory = roomChatHistory.get(roomId);
        if (chatHistory && chatHistory.length > 0) {
          ws.send(JSON.stringify({ type: 'chat-history', messages: chatHistory }));
        }
        db.addActivityLog({ timestamp: new Date().toISOString(), roomId, userId, userName: rawName, eventType: "join" });
        if (redis.isRedisConnected()) {
          redis.setUserPresence(roomId, userId, msg.user, 300);
        }
      }

      const connections = roomConnections.get(roomId);
      if (connections) {
        const joinMsg = JSON.stringify(msg);
        connections.forEach(client => { if (client !== ws && client.readyState === 1) client.send(joinMsg); });
      }
    } else if (msg.type === 'presence') {
      const wsUserId = (ws.data as WsData)?.userId;
      if (!wsUserId) return;
      msg.userId = wsUserId;
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
      ws.publish(roomId, JSON.stringify(msg));
    } else if (msg.type === 'state') {
      if (msg.state) {
        const topologyValidation = validateTopology(msg.state);
        if (!topologyValidation.valid) {
          ws.send(JSON.stringify({ type: 'error', error: topologyValidation.error || 'Invalid state data' }));
          return;
        }
        ws.publish(roomId, JSON.stringify({ type: 'state', state: topologyValidation.sanitized }));
        const room = loadRoom(roomId);
        if (room) { room.topology = topologyValidation.sanitized; room.lastActivity = new Date().toISOString(); saveRoom(room); }
      } else {
        ws.publish(roomId, message);
      }
    } else if (msg.type === 'patch') {
      if (msg.patch) {
        msg.patch = sanitizeTopologyStrings(msg.patch);
      }
      ws.publish(roomId, JSON.stringify(msg));
    } else {
      const wsUserId = (ws.data as WsData)?.userId;
      if (wsUserId && msg.userId) msg.userId = wsUserId;
      ws.publish(roomId, JSON.stringify(msg));
    }
    resetDestructionTimer(roomId);
  },

  close(ws: any) {
    const roomId = (ws.data as WsData)?.roomId;
    const userId = (ws.data as WsData)?.userId;
    if (!roomId) return;
    const connections = roomConnections.get(roomId);
    if (connections) {
      connections.delete(ws);
      if (connections.size === 0) roomConnections.delete(roomId);
    }
    if (userId) {
      const users = roomUsers.get(roomId);
      if (users) {
        const user = users.get(userId);
        users.delete(userId);
        if (connections && connections.size > 0) {
          const leaveMsg = JSON.stringify({ type: 'leave', userId });
          connections.forEach(client => { if (client.readyState === 1) client.send(leaveMsg); });
        }
        if (users.size === 0) roomUsers.delete(roomId);
        db.addActivityLog({ timestamp: new Date().toISOString(), roomId, userId, userName: user?.name, eventType: "leave" });
        if (redis.isRedisConnected()) {
          redis.removeUserPresence(roomId, userId);
        }
      }
    }
    ws.unsubscribe(roomId);
    const meta = roomMeta.get(roomId);
    if (meta) {
      meta.connectedUsers = Math.max(0, meta.connectedUsers - 1);
      if (meta.connectedUsers === 0) {
        const room = loadRoom(roomId);
        if (room) {
          if (room.destruct.mode === "empty") { deleteRoomData(roomId); }
          else if (room.destruct.mode === "time") { scheduleDestruction(roomId, room.destruct.value); }
        }
      }
    }
  }
};
