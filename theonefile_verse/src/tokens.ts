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
    tokenData = await redis.getSessionToken(`ws:${token}`) as unknown as WsSessionToken | null;
    if (tokenData) {
      await redis.deleteSessionToken(`ws:${token}`);
    }
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

export function generateRoomAccessToken(roomId: string): string {
  const token = oidc.generateSecureToken(32);
  ROOM_ACCESS_TOKENS.set(oidc.hashTokenSync(token), { roomId, expiresAt: Date.now() + ROOM_ACCESS_EXPIRY });
  if (ROOM_ACCESS_TOKENS.size > 10000) {
    const now = Date.now();
    for (const [k, v] of ROOM_ACCESS_TOKENS) {
      if (now > v.expiresAt) ROOM_ACCESS_TOKENS.delete(k);
    }
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

export function generateInstanceToken(): string {
  const token = oidc.generateSecureToken(32);
  INSTANCE_TOKENS.set(oidc.hashTokenSync(token), Date.now());
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

export function storeInstanceToken(token: string): void {
  INSTANCE_TOKENS.set(oidc.hashTokenSync(token), Date.now());
}

export function removeInstanceToken(token: string): void {
  INSTANCE_TOKENS.delete(oidc.hashTokenSync(token));
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

export function startTokenCleanupIntervals(): void {
  setInterval(() => {
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

  setInterval(() => {
    const now = Date.now();
    for (const [token, createdAt] of INSTANCE_TOKENS.entries()) {
      if (now - createdAt > TOKEN_EXPIRY) INSTANCE_TOKENS.delete(token);
    }
    if (INSTANCE_TOKENS.size > 1000) {
      const sorted = [...INSTANCE_TOKENS.entries()].sort((a, b) => a[1] - b[1]);
      for (let i = 0; i < sorted.length - 500; i++) INSTANCE_TOKENS.delete(sorted[i][0]);
    }
  }, 10 * 60 * 1000);
}

export function cleanupExpiredRoomTokens(): void {
  const now = Date.now();
  for (const [k, v] of ROOM_ACCESS_TOKENS) {
    if (now > v.expiresAt) ROOM_ACCESS_TOKENS.delete(k);
  }
}
