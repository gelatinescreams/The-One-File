import { createClient, RedisClientType } from "redis";

const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";

let client: RedisClientType | null = null;
let subscriber: RedisClientType | null = null;
let isConnected = false;

const messageHandlers = new Map<string, Set<(message: string, channel: string) => void>>();

export async function connectRedis(): Promise<boolean> {
  if (!process.env.REDIS_URL) {
    return false;
  }
  try {
    client = createClient({ url: REDIS_URL, socket: { reconnectStrategy: (retries) => Math.min(1000 + retries * 500, 15000) } });
    subscriber = client.duplicate();

    let errorLogged = false;
    client.on("error", (err) => {
      isConnected = false;
      if (!errorLogged) {
        console.error("[Redis] Client error:", err.message);
        errorLogged = true;
      }
    });
    client.on("ready", () => { errorLogged = false; isConnected = true; });

    subscriber.on("error", () => {});

    await client.connect();
    await subscriber.connect();

    isConnected = true;
    console.log("[Redis] Connected to", REDIS_URL);


    return true;
  } catch (err: any) {
    console.error("[Redis] Connection failed:", err.message);
    isConnected = false;
    return false;
  }
}

export function isRedisConnected(): boolean {
  return isConnected && client !== null;
}

const RATE_LIMIT_LUA = `
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return c
`;

export async function checkRateLimitRedis(
  key: string,
  maxAttempts: number,
  windowSeconds: number
): Promise<boolean> {
  if (!client || !isConnected) return false;

  try {
    const redisKey = `ratelimit:${key}`;
    const current = await client.eval(RATE_LIMIT_LUA, { keys: [redisKey], arguments: [String(windowSeconds)] }) as number;
    return current <= maxAttempts;
  } catch (err: any) {
    console.error("[Redis] Rate limit check failed, denying request (fail-closed):", err.message);
    return false;
  }
}

export async function setSessionToken(
  token: string,
  data: { type: string; createdAt: number } | Record<string, any>,
  ttlSeconds: number = 604800
): Promise<boolean> {
  if (!client || !isConnected) return false;

  try {
    await client.setEx(`session:${token}`, ttlSeconds, JSON.stringify(data));
    return true;
  } catch (err: any) {
    console.error("[Redis] Set session token failed:", err.message);
    return false;
  }
}

export async function getSessionToken(token: string): Promise<{ type: string; createdAt: number } | null> {
  if (!client || !isConnected) return null;

  try {
    const data = await client.get(`session:${token}`);
    return data ? JSON.parse(data) : null;
  } catch (err: any) {
    console.error("[Redis] Get session token failed:", err.message);
    return null;
  }
}

export async function consumeSessionToken(token: string): Promise<any | null> {
  if (!client || !isConnected) return null;
  try {
    const data = await client.getDel(`session:${token}`);
    return data ? JSON.parse(data) : null;
  } catch (err: any) {
    console.error("[Redis] Consume session token failed:", err.message);
    return null;
  }
}

export async function deleteSessionToken(token: string): Promise<boolean> {
  if (!client || !isConnected) return false;

  try {
    await client.del(`session:${token}`);
    return true;
  } catch (err: any) {
    console.error("[Redis] Delete session token failed:", err.message);
    return false;
  }
}

const presenceIndexKey = (roomId: string) => `presence:idx:${roomId}`;

const presenceIndexTtl = (ttlSeconds: number) => ttlSeconds * 2;

function escapeGlob(s: string): string {
  return s.replace(/[\\*?[\]]/g, (c) => `\\${c}`);
}

export async function setUserPresence(
  roomId: string,
  userId: string,
  userData: any,
  ttlSeconds: number = 300
): Promise<boolean> {
  if (!client || !isConnected) return false;

  try {
    const userKey = `presence:${roomId}:${userId}`;
    const idxKey = presenceIndexKey(roomId);
    await client.multi()
      .setEx(userKey, ttlSeconds, JSON.stringify(userData))
      .sAdd(idxKey, userId)
      .expire(idxKey, presenceIndexTtl(ttlSeconds))
      .exec();
    return true;
  } catch (err: any) {
    console.error("[Redis] Set user presence failed:", err.message);
    return false;
  }
}

export async function getUserPresence(roomId: string, userId: string): Promise<any | null> {
  if (!client || !isConnected) return null;

  try {
    const data = await client.get(`presence:${roomId}:${userId}`);
    return data ? JSON.parse(data) : null;
  } catch (err: any) {
    console.error("[Redis] Get user presence failed:", err.message);
    return null;
  }
}

async function scanPresenceKeys(roomId: string): Promise<string[]> {
  const pattern = `presence:${escapeGlob(roomId)}:*`;
  let cursor = 0;
  const keys: string[] = [];
  do {
    const reply = await client!.scan(cursor, { MATCH: pattern, COUNT: 200 });
    cursor = reply.cursor;
    keys.push(...reply.keys);
  } while (cursor !== 0);
  return keys;
}

async function presenceKeysFor(roomId: string): Promise<string[]> {
  const members = await client!.sMembers(presenceIndexKey(roomId));
  if (members.length === 0) return await scanPresenceKeys(roomId);
  return members.map((u) => `presence:${roomId}:${u}`);
}

function reapPresenceIndex(roomId: string, staleUserIds: string[]): void {
  if (staleUserIds.length === 0) return;
  client!.sRem(presenceIndexKey(roomId), staleUserIds)
    .catch((e: any) => console.error("[Redis] Presence index reap failed:", e?.message));
}

export async function getAllUserPresence(roomId: string): Promise<Map<string, any>> {
  const result = new Map<string, any>();
  if (!client || !isConnected) return result;

  try {
    const keys = await presenceKeysFor(roomId);
    if (keys.length === 0) return result;
    const values = await client.mGet(keys);
    const stale: string[] = [];
    for (let i = 0; i < keys.length; i++) {
      const userId = keys[i].split(':').slice(2).join(':');
      if (values[i]) {
        try { result.set(userId, JSON.parse(values[i])); } catch (e: any) { console.error("[Redis] Presence JSON parse failed:", e.message); }
      } else {
        stale.push(userId);
      }
    }
    reapPresenceIndex(roomId, stale);
  } catch (err: any) {
    console.error("[Redis] Get all user presence failed:", err.message);
  }

  return result;
}

export async function refreshUserPresence(
  roomId: string,
  userId: string,
  ttlSeconds: number = 300
): Promise<boolean> {
  if (!client || !isConnected) return false;
  try {
    const alive = !!(await client.expire(`presence:${roomId}:${userId}`, ttlSeconds));
    if (alive) {
      client.expire(presenceIndexKey(roomId), presenceIndexTtl(ttlSeconds))
        .catch((e: any) => console.error("[Redis] Presence index touch failed:", e?.message));
    }
    return alive;
  } catch (err: any) {
    console.error("[Redis] Refresh user presence failed:", err.message);
    return false;
  }
}

export async function getRoomPresenceCount(roomId: string): Promise<number | null> {
  if (!client || !isConnected) return null;
  try {
    const keys = await presenceKeysFor(roomId);
    if (keys.length === 0) return 0;
    const values = await client.mGet(keys);
    let count = 0;
    const stale: string[] = [];
    for (let i = 0; i < keys.length; i++) {
      if (values[i]) count++;
      else stale.push(keys[i].split(':').slice(2).join(':'));
    }
    reapPresenceIndex(roomId, stale);
    return count;
  } catch (err: any) {
    console.error("[Redis] Room presence count failed:", err.message);
    return null;
  }
}

export async function removeUserPresence(roomId: string, userId: string): Promise<boolean> {
  if (!client || !isConnected) return false;

  try {
    await client.multi()
      .del(`presence:${roomId}:${userId}`)
      .sRem(presenceIndexKey(roomId), userId)
      .exec();
    return true;
  } catch (err: any) {
    console.error("[Redis] Remove user presence failed:", err.message);
    return false;
  }
}

export async function setRoomStateCache(roomId: string, state: any, ttlSeconds: number = 3600): Promise<boolean> {
  if (!client || !isConnected) return false;

  try {
    await client.setEx(`roomstate:${roomId}`, ttlSeconds, JSON.stringify(state));
    return true;
  } catch (err: any) {
    console.error("[Redis] Set room state cache failed:", err.message);
    return false;
  }
}

export async function getRoomStateCache(roomId: string): Promise<any | null> {
  if (!client || !isConnected) return null;

  try {
    const data = await client.get(`roomstate:${roomId}`);
    return data ? JSON.parse(data) : null;
  } catch (err: any) {
    console.error("[Redis] Get room state cache failed:", err.message);
    return null;
  }
}

export async function deleteRoomStateCache(roomId: string): Promise<boolean> {
  if (!client || !isConnected) return false;

  try {
    await client.del(`roomstate:${roomId}`);
    return true;
  } catch (err: any) {
    console.error("[Redis] Delete room state cache failed:", err.message);
    return false;
  }
}

export async function publishMessage(channel: string, message: string): Promise<boolean> {
  if (!client || !isConnected) return false;

  try {
    await client.publish(channel, message);
    return true;
  } catch (err: any) {
    console.error("[Redis] Publish message failed:", err.message);
    return false;
  }
}

export async function subscribeToChannel(
  channel: string,
  handler: (message: string, channel: string) => void
): Promise<void> {
  if (!subscriber || !isConnected) return;

  try {
    if (!messageHandlers.has(channel)) {
      messageHandlers.set(channel, new Set());
      await subscriber.subscribe(channel, (message, ch) => {
        const handlers = messageHandlers.get(ch);
        if (handlers) {
          handlers.forEach((h) => h(message, ch));
        }
      });
    }
    messageHandlers.get(channel)!.add(handler);
  } catch (err: any) {
    console.error("[Redis] Subscribe to channel failed:", err.message);
  }
}

export async function unsubscribeFromChannel(
  channel: string,
  handler?: (message: string, channel: string) => void
): Promise<void> {
  if (!subscriber || !isConnected) return;

  try {
    if (handler) {
      const handlers = messageHandlers.get(channel);
      if (handlers) {
        handlers.delete(handler);
        if (handlers.size === 0) {
          messageHandlers.delete(channel);
          await subscriber.unsubscribe(channel);
        }
      }
    } else {
      messageHandlers.delete(channel);
      await subscriber.unsubscribe(channel);
    }
  } catch (err: any) {
    console.error("[Redis] Unsubscribe from channel failed:", err.message);
  }
}

export const INSTANCE_ID = `${process.pid}-${Math.random().toString(36).slice(2, 10)}`;

export async function publishToRoom(roomId: string, message: any): Promise<boolean> {
  if (!client || !isConnected) return false;
  try {
    return await publishMessage(`room:${roomId}`, JSON.stringify({ __from: INSTANCE_ID, payload: message }));
  } catch (err: any) {
    console.error("[Redis] publishToRoom failed:", err.message);
    return false;
  }
}

export async function subscribeToRoom(
  roomId: string,
  handler: (message: any) => void
): Promise<() => Promise<void>> {
  const wrappedHandler = (msg: string) => {
    try {
      const envelope = JSON.parse(msg);
      if (envelope && typeof envelope === "object" && "__from" in envelope) {
        if (envelope.__from === INSTANCE_ID) return;
        handler(envelope.payload);
      } else {
        handler(envelope);
      }
    } catch (err: any) {
      console.error("[Redis] Room message parse failed:", err.message);
    }
  };

  await subscribeToChannel(`room:${roomId}`, wrappedHandler);

  return async () => {
    await unsubscribeFromChannel(`room:${roomId}`, wrappedHandler);
  };
}

export async function incrementCounter(key: string): Promise<number> {
  if (!client || !isConnected) return 0;

  try {
    return await client.incr(`counter:${key}`);
  } catch (err: any) {
    console.error("[Redis] Increment counter failed:", err.message);
    return 0;
  }
}

export async function getCounter(key: string): Promise<number> {
  if (!client || !isConnected) return 0;

  try {
    const value = await client.get(`counter:${key}`);
    return value ? parseInt(value, 10) : 0;
  } catch (err: any) {
    console.error("[Redis] Get counter failed:", err.message);
    return 0;
  }
}

export async function setWithExpiry(key: string, value: string, ttlSeconds: number): Promise<boolean> {
  if (!client || !isConnected) return false;

  try {
    await client.setEx(key, ttlSeconds, value);
    return true;
  } catch (err: any) {
    console.error("[Redis] Set with expiry failed:", err.message);
    return false;
  }
}

export async function getValue(key: string): Promise<string | null> {
  if (!client || !isConnected) return null;

  try {
    return await client.get(key);
  } catch (err: any) {
    console.error("[Redis] Get value failed:", err.message);
    return null;
  }
}

export async function deleteKey(key: string): Promise<boolean> {
  if (!client || !isConnected) return false;

  try {
    await client.del(key);
    return true;
  } catch (err: any) {
    console.error("[Redis] Delete key failed:", err.message);
    return false;
  }
}

export async function ping(): Promise<boolean> {
  if (!client || !isConnected) return false;
  try {
    const result = await client.ping();
    return result === "PONG";
  } catch {
    return false;
  }
}

export async function disconnectRedis(): Promise<void> {
  try {
    if (subscriber) {
      await subscriber.quit();
      subscriber = null;
    }
    if (client) {
      await client.quit();
      client = null;
    }
    isConnected = false;
    console.log("[Redis] Disconnected");
  } catch (err: any) {
    console.error("[Redis] Disconnect failed:", err.message);
  }
}

export function getRedisClient(): RedisClientType | null {
  return client;
}
