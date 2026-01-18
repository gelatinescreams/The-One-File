import { createClient, RedisClientType } from "redis";

const REDIS_URL = process.env.REDIS_URL || "redis://localhost:6379";

let client: RedisClientType | null = null;
let subscriber: RedisClientType | null = null;
let isConnected = false;

const messageHandlers = new Map<string, Set<(message: string, channel: string) => void>>();

export async function connectRedis(): Promise<boolean> {
  try {
    client = createClient({ url: REDIS_URL });
    subscriber = client.duplicate();

    client.on("error", (err) => {
      console.error("[Redis] Client error:", err.message);
      isConnected = false;
    });

    subscriber.on("error", (err) => {
      console.error("[Redis] Subscriber error:", err.message);
    });

    await client.connect();
    await subscriber.connect();

    isConnected = true;
    console.log("[Redis] Connected to", REDIS_URL);

    subscriber.on("message", (channel, message) => {
      const handlers = messageHandlers.get(channel);
      if (handlers) {
        handlers.forEach((handler) => handler(message, channel));
      }
    });

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

export async function checkRateLimitRedis(
  key: string,
  maxAttempts: number,
  windowSeconds: number
): Promise<boolean> {
  if (!client || !isConnected) return true;

  try {
    const redisKey = `ratelimit:${key}`;
    const current = await client.incr(redisKey);

    if (current === 1) {
      await client.expire(redisKey, windowSeconds);
    }

    return current <= maxAttempts;
  } catch {
    return true;
  }
}

export async function setSessionToken(
  token: string,
  data: { type: string; createdAt: number },
  ttlSeconds: number = 604800
): Promise<void> {
  if (!client || !isConnected) return;

  try {
    await client.setEx(`session:${token}`, ttlSeconds, JSON.stringify(data));
  } catch {}
}

export async function getSessionToken(token: string): Promise<{ type: string; createdAt: number } | null> {
  if (!client || !isConnected) return null;

  try {
    const data = await client.get(`session:${token}`);
    return data ? JSON.parse(data) : null;
  } catch {
    return null;
  }
}

export async function deleteSessionToken(token: string): Promise<void> {
  if (!client || !isConnected) return;

  try {
    await client.del(`session:${token}`);
  } catch {}
}

export async function setUserPresence(
  roomId: string,
  userId: string,
  userData: any,
  ttlSeconds: number = 300
): Promise<void> {
  if (!client || !isConnected) return;

  try {
    await client.hSet(`presence:${roomId}`, userId, JSON.stringify(userData));
    await client.expire(`presence:${roomId}`, ttlSeconds);
  } catch {}
}

export async function getUserPresence(roomId: string, userId: string): Promise<any | null> {
  if (!client || !isConnected) return null;

  try {
    const data = await client.hGet(`presence:${roomId}`, userId);
    return data ? JSON.parse(data) : null;
  } catch {
    return null;
  }
}

export async function getAllUserPresence(roomId: string): Promise<Map<string, any>> {
  const result = new Map<string, any>();
  if (!client || !isConnected) return result;

  try {
    const data = await client.hGetAll(`presence:${roomId}`);
    for (const [userId, userData] of Object.entries(data)) {
      result.set(userId, JSON.parse(userData));
    }
  } catch {}

  return result;
}

export async function removeUserPresence(roomId: string, userId: string): Promise<void> {
  if (!client || !isConnected) return;

  try {
    await client.hDel(`presence:${roomId}`, userId);
  } catch {}
}

export async function setRoomStateCache(roomId: string, state: any, ttlSeconds: number = 3600): Promise<void> {
  if (!client || !isConnected) return;

  try {
    await client.setEx(`roomstate:${roomId}`, ttlSeconds, JSON.stringify(state));
  } catch {}
}

export async function getRoomStateCache(roomId: string): Promise<any | null> {
  if (!client || !isConnected) return null;

  try {
    const data = await client.get(`roomstate:${roomId}`);
    return data ? JSON.parse(data) : null;
  } catch {
    return null;
  }
}

export async function deleteRoomStateCache(roomId: string): Promise<void> {
  if (!client || !isConnected) return;

  try {
    await client.del(`roomstate:${roomId}`);
  } catch {}
}

export async function publishMessage(channel: string, message: string): Promise<void> {
  if (!client || !isConnected) return;

  try {
    await client.publish(channel, message);
  } catch {}
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
  } catch {}
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
  } catch {}
}

export async function publishToRoom(roomId: string, message: any): Promise<void> {
  await publishMessage(`room:${roomId}`, JSON.stringify(message));
}

export async function subscribeToRoom(
  roomId: string,
  handler: (message: any) => void
): Promise<() => Promise<void>> {
  const wrappedHandler = (msg: string) => {
    try {
      handler(JSON.parse(msg));
    } catch {}
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
  } catch {
    return 0;
  }
}

export async function getCounter(key: string): Promise<number> {
  if (!client || !isConnected) return 0;

  try {
    const value = await client.get(`counter:${key}`);
    return value ? parseInt(value, 10) : 0;
  } catch {
    return 0;
  }
}

export async function setWithExpiry(key: string, value: string, ttlSeconds: number): Promise<void> {
  if (!client || !isConnected) return;

  try {
    await client.setEx(key, ttlSeconds, value);
  } catch {}
}

export async function getValue(key: string): Promise<string | null> {
  if (!client || !isConnected) return null;

  try {
    return await client.get(key);
  } catch {
    return null;
  }
}

export async function deleteKey(key: string): Promise<void> {
  if (!client || !isConnected) return;

  try {
    await client.del(key);
  } catch {}
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
  } catch {}
}

export function getRedisClient(): RedisClientType | null {
  return client;
}
