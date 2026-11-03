import * as redis from "./redis";
import * as oidc from "./oidc";
import * as db from "./database";

const INSTANCE_TOKENS = new Map<string, number>();
const TOKEN_EXPIRY = 7 * 24 * 60 * 60 * 1000;

const ROOM_ACCESS_TOKENS = new Map<string, { roomId: string; expiresAt: number }>();
const ROOM_ACCESS_EXPIRY = 24 * 60 * 60 * 1000;

interface WsSessionToken {
  roomId: string;
  collabUserId: string;
  createdAt: number;
  expiresAt: number;
}

const WS_SESSION_TOKENS = new Map<string, WsSessionToken>();
export const WS_TOKEN_EXPIRY = 5 * 60 * 1000;

export async function generateWsSessionToken(roomId: string, collabUserId: string): Promise<string> {
  const token = oidc.generateSecureToken(32);
  const now = Date.now();
  const tokenData: WsSessionToken = {
    roomId,
    collabUserId,
    createdAt: now,
    expiresAt: now + WS_TOKEN_EXPIRY
  };
  if (redis.isRedisConnected()) {
    await redis.setSessionToken(`ws:${token}`, tokenData, Math.ceil(WS_TOKEN_EXPIRY / 1000));
  } else {
    WS_SESSION_TOKENS.set(token, tokenData);
  }
  return token;
}

export async function validateWsSessionToken(token: string, roomId: string): Promise<{ valid: boolean; collabUserId?: string }> {
  if (!token) return { valid: false };
  let tokenData: WsSessionToken | null = null;
  if (redis.isRedisConnected()) {
    tokenData = await redis.consumeSessionToken(`ws:${token}`) as WsSessionToken | null;
  } else {
    tokenData = WS_SESSION_TOKENS.get(token) || null;
    if (tokenData) {
      WS_SESSION_TOKENS.delete(token);
    }
  }
  if (!tokenData) return { valid: false };
  if (Date.now() > tokenData.expiresAt) return { valid: false };
  if (tokenData.roomId !== roomId) return { valid: false };
  return { valid: true, collabUserId: tokenData.collabUserId };
}

const MAX_WS_SESSION_TOKENS = 50000;

const ROOM_REDIS_PREFIX = "roomaccess:";
const INSTANCE_REDIS_PREFIX = "instance:";

function redisOn(): boolean {
  try { return redis.isRedisConnected(); } catch { return false; }
}

function mirror(p: Promise<unknown>): void {
  p.catch((e: any) => console.error("[Tokens] Redis mirror failed:", e?.message));
}

export function generateRoomAccessToken(roomId: string): string {
  const token = oidc.generateSecureToken(32);
  const key = oidc.hashTokenSync(token);
  const expiresAt = Date.now() + ROOM_ACCESS_EXPIRY;
  ROOM_ACCESS_TOKENS.set(key, { roomId, expiresAt });
  if (ROOM_ACCESS_TOKENS.size > 10000) {
    const now = Date.now();
    for (const [k, v] of ROOM_ACCESS_TOKENS) {
      if (now > v.expiresAt) ROOM_ACCESS_TOKENS.delete(k);
    }
  }
  if (redisOn()) {
    mirror(redis.setSessionToken(`${ROOM_REDIS_PREFIX}${key}`, { roomId, expiresAt }, Math.ceil(ROOM_ACCESS_EXPIRY / 1000)));
  }
  return token;
}

export function validateRoomAccessToken(token: string, roomId: string): boolean {
  if (!token) return false;
  const key = oidc.hashTokenSync(token);
  const data = ROOM_ACCESS_TOKENS.get(key);
  if (!data) return false;
  if (Date.now() > data.expiresAt) { ROOM_ACCESS_TOKENS.delete(key); return false; }
  return data.roomId === roomId;
}

export async function validateRoomAccessTokenAsync(token: string, roomId: string): Promise<boolean> {
  if (!token) return false;
  if (validateRoomAccessToken(token, roomId)) return true;
  if (!redisOn()) return false;
  const key = oidc.hashTokenSync(token);
  const data = await redis.getSessionToken(`${ROOM_REDIS_PREFIX}${key}`) as unknown as { roomId: string; expiresAt: number } | null;
  if (!data || typeof data.expiresAt !== "number") return false;
  if (Date.now() > data.expiresAt) {
    mirror(redis.deleteSessionToken(`${ROOM_REDIS_PREFIX}${key}`));
    return false;
  }
  if (data.roomId !== roomId) return false;
  ROOM_ACCESS_TOKENS.set(key, { roomId: data.roomId, expiresAt: data.expiresAt });
  return true;
}

export function generateInstanceToken(): string {
  const token = oidc.generateSecureToken(32);
  storeInstanceToken(token);
  return token;
}

export function validateInstanceToken(token: string): boolean {
  if (!token) return false;
  const key = oidc.hashTokenSync(token);
  const createdAt = INSTANCE_TOKENS.get(key);
  if (!createdAt) return false;
  if (Date.now() - createdAt > TOKEN_EXPIRY) {
    INSTANCE_TOKENS.delete(key);
    return false;
  }
  return true;
}

export async function validateInstanceTokenAsync(token: string): Promise<boolean> {
  if (!token) return false;
  if (validateInstanceToken(token)) return true;
  if (!redisOn()) return false;
  const key = oidc.hashTokenSync(token);
  const data = await redis.getSessionToken(`${INSTANCE_REDIS_PREFIX}${key}`) as unknown as { createdAt: number } | null;
  if (!data || typeof data.createdAt !== "number") return false;
  if (Date.now() - data.createdAt > TOKEN_EXPIRY) {
    mirror(redis.deleteSessionToken(`${INSTANCE_REDIS_PREFIX}${key}`));
    return false;
  }
  INSTANCE_TOKENS.set(key, data.createdAt);
  return true;
}

export function storeInstanceToken(token: string): void {
  const key = oidc.hashTokenSync(token);
  const createdAt = Date.now();
  INSTANCE_TOKENS.set(key, createdAt);
  if (redisOn()) {
    mirror(redis.setSessionToken(`${INSTANCE_REDIS_PREFIX}${key}`, { createdAt }, Math.ceil(TOKEN_EXPIRY / 1000)));
  }
}

export function removeInstanceToken(token: string): void {
  const key = oidc.hashTokenSync(token);
  INSTANCE_TOKENS.delete(key);
  if (redisOn()) mirror(redis.deleteSessionToken(`${INSTANCE_REDIS_PREFIX}${key}`));
}

export function removeRoomAccessToken(token: string): void {
  const key = oidc.hashTokenSync(token);
  ROOM_ACCESS_TOKENS.delete(key);
  if (redisOn()) mirror(redis.deleteSessionToken(`${ROOM_REDIS_PREFIX}${key}`));
}

export async function hashApiKey(key: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Buffer.from(hash).toString("hex");
}

export async function validateApiKey(key: string): Promise<db.ApiKey | null> {
  const hash = await hashApiKey(key);
  const apiKey = db.getApiKeyByHash(hash);
  if (!apiKey) return null;
  if (apiKey.expiresAt && new Date(apiKey.expiresAt) < new Date()) return null;
  db.updateApiKeyLastUsed(apiKey.id);
  return apiKey;
}

let wsTokenSweepTimer: ReturnType<typeof setInterval> | null = null;
let instanceTokenSweepTimer: ReturnType<typeof setInterval> | null = null;

function unrefTimer(t: any): void {
  if (t && typeof t.unref === 'function') t.unref();
}

export function startTokenCleanupIntervals(): void {
  if (wsTokenSweepTimer || instanceTokenSweepTimer) return;
  wsTokenSweepTimer = setInterval(() => {
    const now = Date.now();
    for (const [token, data] of WS_SESSION_TOKENS.entries()) {
      if (now > data.expiresAt) {
        WS_SESSION_TOKENS.delete(token);
      }
    }
    if (WS_SESSION_TOKENS.size > MAX_WS_SESSION_TOKENS) {
      const entries = [...WS_SESSION_TOKENS.entries()].sort((a, b) => a[1].createdAt - b[1].createdAt);
      const toRemove = entries.length - Math.floor(MAX_WS_SESSION_TOKENS * 0.75);
      for (let i = 0; i < toRemove; i++) WS_SESSION_TOKENS.delete(entries[i][0]);
    }
  }, 60 * 1000);
  unrefTimer(wsTokenSweepTimer);

  instanceTokenSweepTimer = setInterval(() => {
    const now = Date.now();
    for (const [token, createdAt] of INSTANCE_TOKENS.entries()) {
      if (now - createdAt > TOKEN_EXPIRY) INSTANCE_TOKENS.delete(token);
    }
    if (INSTANCE_TOKENS.size > 1000) {
      const sorted = [...INSTANCE_TOKENS.entries()].sort((a, b) => a[1] - b[1]);
      for (let i = 0; i < sorted.length - 500; i++) INSTANCE_TOKENS.delete(sorted[i][0]);
    }
  }, 10 * 60 * 1000);
  unrefTimer(instanceTokenSweepTimer);
}

export function stopTokenCleanupIntervals(): void {
  if (wsTokenSweepTimer) { clearInterval(wsTokenSweepTimer); wsTokenSweepTimer = null; }
  if (instanceTokenSweepTimer) { clearInterval(instanceTokenSweepTimer); instanceTokenSweepTimer = null; }
}

export function tokenCleanupIntervalCount(): number {
  return (wsTokenSweepTimer ? 1 : 0) + (instanceTokenSweepTimer ? 1 : 0);
}

export function cleanupExpiredRoomTokens(): void {
  const now = Date.now();
  for (const [k, v] of ROOM_ACCESS_TOKENS) {
    if (now > v.expiresAt) ROOM_ACCESS_TOKENS.delete(k);
  }
}
