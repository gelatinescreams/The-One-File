import * as redis from "./redis";
import * as db from "./database";
import * as oidc from "./oidc";
import { type InstanceSettings } from "./config";

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const MAX_RATE_LIMIT_ENTRIES = 10000;
const rateLimitStore = new Map<string, RateLimitEntry>();

interface WsTokenBucket {
  tokens: number;
  lastRefill: number;
}

const WS_RATE_LIMITS = {
  state: { bucketSize: 10, refillRate: 2 },
  chat: { bucketSize: 5, refillRate: 1 },
  cursor: { bucketSize: 30, refillRate: 15 },
  typing: { bucketSize: 5, refillRate: 1 },
  presence: { bucketSize: 20, refillRate: 5 },
  default: { bucketSize: 20, refillRate: 5 }
};

const MAX_WS_RATE_LIMIT_BUCKETS = 50000;
const wsRateLimitBuckets = new Map<string, WsTokenBucket>();

export function checkWsRateLimit(connectionId: string, messageType: string): boolean {
  const limits = WS_RATE_LIMITS[messageType as keyof typeof WS_RATE_LIMITS] || WS_RATE_LIMITS.default;
  const key = `${connectionId}:${messageType}`;
  const now = Date.now();
  let bucket = wsRateLimitBuckets.get(key);
  if (!bucket) {
    bucket = { tokens: limits.bucketSize, lastRefill: now };
    wsRateLimitBuckets.set(key, bucket);
  }
  const elapsed = (now - bucket.lastRefill) / 1000;
  bucket.tokens = Math.min(limits.bucketSize, bucket.tokens + elapsed * limits.refillRate);
  bucket.lastRefill = now;
  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    return true;
  }
  return false;
}

export async function checkRateLimit(ip: string, endpoint: string, settings: InstanceSettings, maxOverride?: number, windowOverride?: number): Promise<boolean> {
  if (!settings.rateLimitEnabled) return true;
  const key = `${ip}:${endpoint}`;
  const maxAttempts = maxOverride ?? settings.rateLimitMaxAttempts;
  const windowSeconds = windowOverride ?? settings.rateLimitWindow;
  if (redis.isRedisConnected()) {
    return await redis.checkRateLimitRedis(key, maxAttempts, windowSeconds);
  }
  if (rateLimitStore.size > MAX_RATE_LIMIT_ENTRIES) {
    const now = Date.now();
    for (const [k, v] of rateLimitStore.entries()) {
      if (now > v.resetAt) rateLimitStore.delete(k);
    }
    if (rateLimitStore.size > MAX_RATE_LIMIT_ENTRIES) {
      const entries = [...rateLimitStore.entries()].sort((a, b) => a[1].resetAt - b[1].resetAt);
      const toRemove = entries.length - Math.floor(MAX_RATE_LIMIT_ENTRIES * 0.75);
      for (let i = 0; i < toRemove; i++) rateLimitStore.delete(entries[i][0]);
    }
  }
  const now = Date.now();
  const entry = rateLimitStore.get(key);
  const window = windowSeconds * 1000;
  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(key, { count: 1, resetAt: now + window });
    return true;
  }
  if (entry.count >= maxAttempts) {
    return false;
  }
  entry.count++;
  return true;
}

export async function checkEmailRateLimit(email: string, action: string, settings: InstanceSettings): Promise<boolean> {
  if (!settings.rateLimitEnabled) return true;
  const authSettings = oidc.getAuthSettings();
  const windowSeconds = authSettings.emailRateLimitWindowSeconds;
  const maxAttempts = authSettings.emailRateLimitMaxAttempts;
  const normalizedEmail = email.toLowerCase().trim();
  if (redis.isRedisConnected()) {
    const key = `email:${normalizedEmail}:${action}`;
    return await redis.checkRateLimitRedis(key, maxAttempts, windowSeconds);
  }
  const currentCount = db.countEmailRateLimitAttempts(normalizedEmail, action, windowSeconds);
  if (currentCount >= maxAttempts) {
    return false;
  }
  db.recordEmailRateLimit(normalizedEmail, action);
  return true;
}

const wsConnectionCounts = new Map<string, { count: number; resetAt: number }>();
const MAX_WS_CONNECTIONS_PER_IP = 50;
const WS_CONNECTION_WINDOW = 3600 * 1000;

export function checkWsConnectionLimit(clientIp: string): boolean {
  const now = Date.now();
  const wsEntry = wsConnectionCounts.get(clientIp);
  if (wsEntry && now < wsEntry.resetAt && wsEntry.count >= MAX_WS_CONNECTIONS_PER_IP) {
    return false;
  }
  if (!wsEntry || now > wsEntry.resetAt) {
    wsConnectionCounts.set(clientIp, { count: 1, resetAt: now + WS_CONNECTION_WINDOW });
  } else {
    wsEntry.count++;
  }
  return true;
}

export function startRateLimitCleanupIntervals(): void {
  setInterval(() => {
    const now = Date.now();
    const staleThreshold = 60 * 1000;
    for (const [key, bucket] of wsRateLimitBuckets.entries()) {
      if (now - bucket.lastRefill > staleThreshold) {
        wsRateLimitBuckets.delete(key);
      }
    }
    if (wsRateLimitBuckets.size > MAX_WS_RATE_LIMIT_BUCKETS) {
      const entries = [...wsRateLimitBuckets.entries()].sort((a, b) => a[1].lastRefill - b[1].lastRefill);
      const toRemove = entries.length - Math.floor(MAX_WS_RATE_LIMIT_BUCKETS * 0.75);
      for (let i = 0; i < toRemove; i++) wsRateLimitBuckets.delete(entries[i][0]);
    }
  }, 30 * 1000);

  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of rateLimitStore.entries()) {
      if (now > entry.resetAt) {
        rateLimitStore.delete(key);
      }
    }
    db.cleanupEmailRateLimits(3600);
  }, 60 * 1000);

  setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of wsConnectionCounts.entries()) {
      if (now > entry.resetAt) wsConnectionCounts.delete(ip);
    }
  }, 5 * 60 * 1000);
}
