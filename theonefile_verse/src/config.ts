import { readFileSync, existsSync } from "fs";
import { join } from "path";
import * as db from "./database";
import * as auth from "./auth";
import pkg from "../package.json";

export const APP_VERSION = pkg.version || "unknown";
export const PORT = parseInt(process.env.PORT || "10101");
export const DATA_DIR = process.env.DATA_DIR || "./data";
export const ROOMS_DIR = join(DATA_DIR, "rooms");
export const ADMIN_CONFIG_PATH = join(DATA_DIR, "admin.json");
export const SETTINGS_PATH = join(DATA_DIR, "settings.json");

export const ENV_UPDATE_INTERVAL = parseInt(process.env.UPDATE_INTERVAL || "0");
export const ENV_SKIP_UPDATE = process.env.SKIP_UPDATE === "true";
export const ENV_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
export const ENV_TRUSTED_PROXY_COUNT = process.env.TRUSTED_PROXY_COUNT ? parseInt(process.env.TRUSTED_PROXY_COUNT) : null;
export const ENV_PUBLIC_URL = process.env.PUBLIC_URL || "";
export const ENV_TRUSTED_PROXIES = process.env.TRUSTED_PROXIES ? process.env.TRUSTED_PROXIES.split(",").map(s => s.trim()).filter(Boolean) : null;

export const REDIS_FANOUT = process.env.REDIS_FANOUT === "true" && !!process.env.REDIS_URL;

export const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isValidUUID(id: string): boolean {
  return UUID_REGEX.test(id);
}

export interface AdminConfig {
  passwordHash: string;
  createdAt: string;
}

export interface InstanceSettings {
  instancePasswordEnabled: boolean;
  instancePasswordHash: string | null;
  updateIntervalHours: number;
  skipUpdates: boolean;
  allowPublicRoomCreation: boolean;
  maxRoomsPerInstance: number;
  maxRoomSizeMB: number;
  defaultDestructMode: "time" | "empty" | "never";
  defaultDestructHours: number;
  forcedTheme: "user" | "dark" | "light";
  rateLimitEnabled: boolean;
  rateLimitWindow: number;
  rateLimitMaxAttempts: number;
  chatEnabled: boolean;
  cursorSharingEnabled: boolean;
  nameChangeEnabled: boolean;
  webhookUrl: string | null;
  webhookEnabled: boolean;
  backupEnabled: boolean;
  backupIntervalHours: number;
  backupRetentionCount: number;
  adminPath: string;
  showAdminLink: boolean;
  trustedProxyCount: number;
  trustedProxies: string[];
  defaultRoomTheme: string;
  forceWelcomeModal: boolean;
  probeEnabled: boolean;
  discoveryEnabled: boolean;
  discoveryAdminOnly: boolean;
  discoveryAllowPublicRanges: boolean;
  discoveryMaxPrefix: number;
  publicUrl: string;
  enable3d: boolean;
  maxAssetsPerRoomMB: number;
  maxAssetsTotalGB: number;
}

export const defaultSettings: InstanceSettings = {
  instancePasswordEnabled: false,
  instancePasswordHash: null,
  updateIntervalHours: 0,
  skipUpdates: false,
  allowPublicRoomCreation: true,
  maxRoomsPerInstance: 0,
  maxRoomSizeMB: 50,
  defaultDestructMode: "time",
  defaultDestructHours: 24,
  forcedTheme: "user",
  rateLimitEnabled: true,
  rateLimitWindow: 60,
  rateLimitMaxAttempts: 10,
  chatEnabled: true,
  cursorSharingEnabled: true,
  nameChangeEnabled: true,
  webhookUrl: null,
  webhookEnabled: false,
  backupEnabled: false,
  backupIntervalHours: 24,
  backupRetentionCount: 7,
  adminPath: "admin",
  showAdminLink: true,
  trustedProxyCount: 0,
  trustedProxies: [],
  defaultRoomTheme: "",
  forceWelcomeModal: false,
  probeEnabled: true,
  discoveryEnabled: true,
  discoveryAdminOnly: true,
  discoveryAllowPublicRanges: false,
  discoveryMaxPrefix: 20,
  publicUrl: "",
  enable3d: true,
  maxAssetsPerRoomMB: 200,
  maxAssetsTotalGB: 5
};

export function loadSettings(): InstanceSettings {
  const allSettings = db.getAllSettings();
  if (Object.keys(allSettings).length === 0) {
    if (existsSync(SETTINGS_PATH)) {
      try {
        const saved = JSON.parse(readFileSync(SETTINGS_PATH, "utf-8"));
        return { ...defaultSettings, ...saved };
      } catch (e: any) { console.error("[Settings]", e.message); return { ...defaultSettings }; }
    }
    return { ...defaultSettings };
  }
  const result = { ...defaultSettings };
  for (const [key, value] of Object.entries(allSettings)) {
    try {
      (result as any)[key] = JSON.parse(value);
    } catch {
      (result as any)[key] = value;
    }
  }
  return result;
}

export function saveSettings(settings: InstanceSettings): void {
  for (const [key, value] of Object.entries(settings)) {
    db.setSetting(key, JSON.stringify(value));
  }
}

let instanceSettings = loadSettings();

if (ENV_SKIP_UPDATE) instanceSettings.skipUpdates = true;
if (ENV_UPDATE_INTERVAL > 0) instanceSettings.updateIntervalHours = ENV_UPDATE_INTERVAL;
if (ENV_TRUSTED_PROXY_COUNT !== null) instanceSettings.trustedProxyCount = ENV_TRUSTED_PROXY_COUNT;
if (ENV_TRUSTED_PROXIES !== null) instanceSettings.trustedProxies = ENV_TRUSTED_PROXIES;
if (ENV_PUBLIC_URL) instanceSettings.publicUrl = ENV_PUBLIC_URL;

export function getSettings(): InstanceSettings { return instanceSettings; }
export function updateSettings(s: InstanceSettings): void { instanceSettings = s; }

export const MAX_ROOM_SIZE_MB_CEILING = 64;

export function getMaxRoomSizeBytes(): number {
  const mb = getSettings().maxRoomSizeMB;
  const clamped = Math.max(1, Math.min(MAX_ROOM_SIZE_MB_CEILING, typeof mb === "number" && mb > 0 ? mb : 50));
  return clamped * 1024 * 1024;
}
export function getMaxAssetsPerRoomBytes(): number {
  const mb = getSettings().maxAssetsPerRoomMB;
  if (typeof mb !== "number" || !(mb > 0)) return 0;
  return Math.floor(mb) * 1024 * 1024;
}

export function getMaxAssetsTotalBytes(): number {
  const gb = getSettings().maxAssetsTotalGB;
  if (typeof gb !== "number" || !(gb > 0)) return 0;
  return Math.floor(gb * 1024) * 1024 * 1024;
}

export function reloadSettings(): void {
  instanceSettings = loadSettings();
  if (ENV_SKIP_UPDATE) instanceSettings.skipUpdates = true;
  if (ENV_TRUSTED_PROXY_COUNT !== null) instanceSettings.trustedProxyCount = ENV_TRUSTED_PROXY_COUNT;
  if (ENV_TRUSTED_PROXIES !== null) instanceSettings.trustedProxies = ENV_TRUSTED_PROXIES;
  if (ENV_PUBLIC_URL) instanceSettings.publicUrl = ENV_PUBLIC_URL;
}

export function loadAdminConfig(): AdminConfig | null {
  const hash = db.getSetting("admin_password_hash");
  const createdAt = db.getSetting("admin_created_at");
  if (!hash) {
    if (existsSync(ADMIN_CONFIG_PATH)) {
      try { return JSON.parse(readFileSync(ADMIN_CONFIG_PATH, "utf-8")); } catch (e: any) { console.error("[Config]", e.message); return null; }
    }
    return null;
  }
  return { passwordHash: hash, createdAt: createdAt || new Date().toISOString() };
}

export function saveAdminConfig(config: AdminConfig): void {
  db.setSetting("admin_password_hash", config.passwordHash);
  db.setSetting("admin_created_at", config.createdAt);
}

export function isAdminConfigured(): boolean {
  return !!ENV_ADMIN_PASSWORD || hasAdminUser() || getOldAdminPasswordHash() !== null;
}

export function needsAdminMigration(): boolean {
  return !hasAdminUser() && getOldAdminPasswordHash() !== null;
}

export function hasAdminUser(): boolean {
  return db.countUsersByRole('admin') > 0;
}

export function getOldAdminPasswordHash(): string | null {
  return db.getSetting('admin_password_hash');
}

export async function verifyAdminPassword(password: string): Promise<boolean> {
  if (ENV_ADMIN_PASSWORD) {
    const maxLen = Math.max(password.length, ENV_ADMIN_PASSWORD.length) + 4;
    const padded = Buffer.alloc(maxLen, 0);
    const expected = Buffer.alloc(maxLen, 0);
    const lenBuf1 = Buffer.alloc(4);
    const lenBuf2 = Buffer.alloc(4);
    lenBuf1.writeUInt32BE(password.length);
    lenBuf2.writeUInt32BE(ENV_ADMIN_PASSWORD.length);
    Buffer.from(password).copy(padded);
    lenBuf1.copy(padded, maxLen - 4);
    Buffer.from(ENV_ADMIN_PASSWORD).copy(expected);
    lenBuf2.copy(expected, maxLen - 4);
    return crypto.timingSafeEqual(padded, expected);
  }
  const config = loadAdminConfig();
  if (!config) return false;
  return await auth.verifyPassword(password, config.passwordHash);
}

export async function verifyInstancePassword(password: string): Promise<boolean> {
  if (!instanceSettings.instancePasswordEnabled || !instanceSettings.instancePasswordHash) return true;
  return await auth.verifyPassword(password, instanceSettings.instancePasswordHash);
}

export function isInstanceLocked(): boolean {
  return instanceSettings.instancePasswordEnabled && !!instanceSettings.instancePasswordHash;
}

export function getAdminPath(): string {
  const path = instanceSettings.adminPath || "admin";
  const sanitized = path.replace(/[^a-zA-Z0-9_-]/g, '');
  return sanitized || "admin";
}

export function isCustomAdminPath(path: string): boolean {
  const adminPath = getAdminPath();
  return path === `/${adminPath}` || path.startsWith(`/${adminPath}/`);
}

export function validateAdminPath(newPath: string): { valid: boolean; error?: string } {
  if (!newPath || newPath.length < 2) {
    return { valid: false, error: "Admin path must be at least 2 characters" };
  }
  if (newPath.length > 50) {
    return { valid: false, error: "Admin path must be less than 50 characters" };
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(newPath)) {
    return { valid: false, error: "Admin path can only contain letters, numbers, hyphens, and underscores" };
  }
  const reserved = ["api", "s", "ws", "auth", "public", "static", "assets"];
  if (reserved.includes(newPath.toLowerCase())) {
    return { valid: false, error: "This path is reserved" };
  }
  return { valid: true };
}

export function isAdminRoute(path: string): boolean {
  return path === "/" || path === "/index.html" || path.startsWith("/s/") ||
         path.startsWith("/ws/") || path.startsWith("/api/room") ||
         path === "/api/setup";
}

export function hasTrustedProxy(): boolean {
  const s = getSettings();
  return (s.trustedProxies?.length || 0) > 0 || (s.trustedProxyCount || 0) > 0;
}

const HOST_RE = /^[A-Za-z0-9.-]+(?::\d{1,5})?$|^\[[0-9A-Fa-f:.]+\](?::\d{1,5})?$/;

export function normalizeOrigin(value: string): string | null {
  try {
    const u = new URL(value.trim());
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.origin;
  } catch { return null; }
}

let warnedBadPublicUrl = "";
export function getConfiguredOrigin(): string | null {
  const raw = getSettings().publicUrl;
  if (!raw) return null;
  const origin = normalizeOrigin(raw);
  if (!origin && warnedBadPublicUrl !== raw) {
    warnedBadPublicUrl = raw;
    console.error(
      `[Config] publicUrl ${JSON.stringify(raw)} is not a valid http(s) origin and is being IGNORED. ` +
      `Expected e.g. "https://verse.example.com" (scheme required, no path). ` +
      `Email links and the same-origin CSRF check are falling back to the request URL.`
    );
  }
  return origin;
}

export function getExternalOrigin(req: Request): string {
  const configured = getConfiguredOrigin();
  if (configured) return configured;
  if (hasTrustedProxy()) {
    const fwdProto = req.headers.get("x-forwarded-proto");
    const fwdHost = req.headers.get("x-forwarded-host") || req.headers.get("host");
    if (fwdProto && fwdHost) {
      const proto = fwdProto.split(",")[0].trim().toLowerCase();
      const host = fwdHost.split(",")[0].trim();
      if ((proto === "http" || proto === "https") && HOST_RE.test(host)) {
        return `${proto}://${host}`;
      }
    }
  }
  try { return new URL(req.url).origin; } catch { return "http://localhost"; }
}

export function isHttpsRequest(req: Request): boolean {
  return getExternalOrigin(req).startsWith("https:");
}
