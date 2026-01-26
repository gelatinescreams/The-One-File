import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync, readdirSync } from "fs";
import { join } from "path";
import * as db from "./database";
import * as redis from "./redis";
import * as auth from "./auth";
import * as oidc from "./oidc";
import * as mailer from "./mailer";

const PORT = parseInt(process.env.PORT || "10101");
const DATA_DIR = process.env.DATA_DIR || "./data";
const ROOMS_DIR = join(DATA_DIR, "rooms");
const ADMIN_CONFIG_PATH = join(DATA_DIR, "admin.json");
const SETTINGS_PATH = join(DATA_DIR, "settings.json");

const ENV_UPDATE_INTERVAL = parseInt(process.env.UPDATE_INTERVAL || "0");
const ENV_SKIP_UPDATE = process.env.SKIP_UPDATE === "true";
const ENV_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function isValidUUID(id: string): boolean {
  return UUID_REGEX.test(id);
}

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const rateLimitStore = new Map<string, RateLimitEntry>();

interface WsTokenBucket {
  tokens: number;
  lastRefill: number;
}

const WS_RATE_LIMITS = {
  state: { bucketSize: 10, refillRate: 2 },
  chat: { bucketSize: 5, refillRate: 1 },
  cursor: { bucketSize: 30, refillRate: 15 },
  presence: { bucketSize: 20, refillRate: 5 },
  default: { bucketSize: 20, refillRate: 5 }
};

const wsRateLimitBuckets = new Map<string, WsTokenBucket>();

function checkWsRateLimit(connectionId: string, messageType: string): boolean {
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

setInterval(() => {
  const now = Date.now();
  const staleThreshold = 60 * 1000;
  for (const [key, bucket] of wsRateLimitBuckets.entries()) {
    if (now - bucket.lastRefill > staleThreshold) {
      wsRateLimitBuckets.delete(key);
    }
  }
}, 30 * 1000);

async function checkRateLimit(ip: string, endpoint: string, settings: InstanceSettings): Promise<boolean> {
  if (!settings.rateLimitEnabled) return true;

  const key = `${ip}:${endpoint}`;

  if (redis.isRedisConnected()) {
    return await redis.checkRateLimitRedis(key, settings.rateLimitMaxAttempts, settings.rateLimitWindow);
  }

  const now = Date.now();
  const entry = rateLimitStore.get(key);
  const window = settings.rateLimitWindow * 1000;
  const maxAttempts = settings.rateLimitMaxAttempts;

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

async function checkEmailRateLimit(email: string, action: string, settings: InstanceSettings): Promise<boolean> {
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

function getClientIP(req: Request): string {
  const xForwardedFor = req.headers.get("x-forwarded-for");

  if (xForwardedFor) {
    const ips = xForwardedFor.split(",").map(ip => ip.trim());

    if (instanceSettings.trustedProxies.length > 0) {
      for (let i = ips.length - 1; i >= 0; i--) {
        if (!instanceSettings.trustedProxies.includes(ips[i])) {
          return ips[i];
        }
      }
    }

    if (instanceSettings.trustedProxyCount > 0) {
      const index = Math.max(0, ips.length - instanceSettings.trustedProxyCount);
      return ips[index] || ips[0];
    }

    return ips[0];
  }

  return req.headers.get("x-real-ip") || "unknown";
}

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore.entries()) {
    if (now > entry.resetAt) {
      rateLimitStore.delete(key);
    }
  }
  db.cleanupEmailRateLimits(3600);
}, 60 * 1000);

function getSecurityHeaders(isAdminPage: boolean = false): Record<string, string> {
  const authSettings = oidc.getAuthSettings();
  const headers: Record<string, string> = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin"
  };

  if (authSettings.productionMode) {
    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload";
  }

  if (isAdminPage) {
    headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";
  }

  return headers;
}

const securityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
  "Referrer-Policy": "strict-origin-when-cross-origin"
};

interface AdminConfig {
  passwordHash: string;
  createdAt: string;
}

interface InstanceSettings {
  instancePasswordEnabled: boolean;
  instancePasswordHash: string | null;
  updateIntervalHours: number;
  skipUpdates: boolean;
  allowPublicRoomCreation: boolean;
  maxRoomsPerInstance: number;
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
  trustedProxyCount: number;
  trustedProxies: string[];
}

const defaultSettings: InstanceSettings = {
  instancePasswordEnabled: false,
  instancePasswordHash: null,
  updateIntervalHours: 0,
  skipUpdates: false,
  allowPublicRoomCreation: true,
  maxRoomsPerInstance: 0,
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
  trustedProxyCount: 1,
  trustedProxies: []
};

function loadSettings(): InstanceSettings {
  const allSettings = db.getAllSettings();
  if (Object.keys(allSettings).length === 0) {
    if (existsSync(SETTINGS_PATH)) {
      try {
        const saved = JSON.parse(readFileSync(SETTINGS_PATH, "utf-8"));
        return { ...defaultSettings, ...saved };
      } catch { return { ...defaultSettings }; }
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

function saveSettings(settings: InstanceSettings): void {
  for (const [key, value] of Object.entries(settings)) {
    db.setSetting(key, JSON.stringify(value));
  }
}

let instanceSettings = loadSettings();

if (ENV_SKIP_UPDATE) instanceSettings.skipUpdates = true;
if (ENV_UPDATE_INTERVAL > 0) instanceSettings.updateIntervalHours = ENV_UPDATE_INTERVAL;

function loadAdminConfig(): AdminConfig | null {
  const hash = db.getSetting("admin_password_hash");
  const createdAt = db.getSetting("admin_created_at");
  if (!hash) {
    if (existsSync(ADMIN_CONFIG_PATH)) {
      try { return JSON.parse(readFileSync(ADMIN_CONFIG_PATH, "utf-8")); } catch { return null; }
    }
    return null;
  }
  return { passwordHash: hash, createdAt: createdAt || new Date().toISOString() };
}

function saveAdminConfig(config: AdminConfig): void {
  db.setSetting("admin_password_hash", config.passwordHash);
  db.setSetting("admin_created_at", config.createdAt);
}

function isAdminConfigured(): boolean {
  return !!ENV_ADMIN_PASSWORD || hasAdminUser() || getOldAdminPasswordHash() !== null;
}

function needsAdminMigration(): boolean {
  return !hasAdminUser() && getOldAdminPasswordHash() !== null;
}

async function verifyAdminPassword(password: string): Promise<boolean> {
  if (ENV_ADMIN_PASSWORD) {
    if (password.length !== ENV_ADMIN_PASSWORD.length) return false;
    let result = 0;
    for (let i = 0; i < password.length; i++) {
      result |= password.charCodeAt(i) ^ ENV_ADMIN_PASSWORD.charCodeAt(i);
    }
    return result === 0;
  }
  const config = loadAdminConfig();
  if (!config) return false;
  return await verifyPassword(password, config.passwordHash);
}

async function verifyInstancePassword(password: string): Promise<boolean> {
  if (!instanceSettings.instancePasswordEnabled || !instanceSettings.instancePasswordHash) return true;
  return await verifyPassword(password, instanceSettings.instancePasswordHash);
}

function isInstanceLocked(): boolean {
  return instanceSettings.instancePasswordEnabled && !!instanceSettings.instancePasswordHash;
}

interface TokenEntry {
  token: string;
  createdAt: number;
}

const ADMIN_TOKENS = new Map<string, TokenEntry>();
const INSTANCE_TOKENS = new Set<string>();
const TOKEN_EXPIRY = 7 * 24 * 60 * 60 * 1000;

interface WsSessionToken {
  roomId: string;
  collabUserId: string;
  createdAt: number;
  expiresAt: number;
}

const WS_SESSION_TOKENS = new Map<string, WsSessionToken>();
const WS_TOKEN_EXPIRY = 5 * 60 * 1000;

async function generateWsSessionToken(roomId: string, collabUserId: string): Promise<string> {
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

async function validateWsSessionToken(token: string, roomId: string): Promise<{ valid: boolean; collabUserId?: string }> {
  if (!token) return { valid: false };

  let tokenData: WsSessionToken | null = null;

  if (redis.isRedisConnected()) {
    tokenData = await redis.getSessionToken(`ws:${token}`) as WsSessionToken | null;
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

setInterval(() => {
  const now = Date.now();
  for (const [token, data] of WS_SESSION_TOKENS.entries()) {
    if (now > data.expiresAt) {
      WS_SESSION_TOKENS.delete(token);
    }
  }
}, 60 * 1000);

async function generateAdminToken(): Promise<string> {
  const token = oidc.generateSecureToken(32);
  const data = { type: "admin", createdAt: Date.now() };
  if (redis.isRedisConnected()) {
    await redis.setSessionToken(token, data, 604800);
  } else {
    ADMIN_TOKENS.set(token, { token, createdAt: Date.now() });
  }
  return token;
}

async function validateAdminToken(token: string): Promise<boolean> {
  if (redis.isRedisConnected()) {
    const data = await redis.getSessionToken(token);
    if (!data || data.type !== "admin") return false;
    if (Date.now() - data.createdAt > TOKEN_EXPIRY) {
      await redis.deleteSessionToken(token);
      return false;
    }
    return true;
  }
  const entry = ADMIN_TOKENS.get(token);
  if (!entry) return false;
  if (Date.now() - entry.createdAt > TOKEN_EXPIRY) {
    ADMIN_TOKENS.delete(token);
    return false;
  }
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [token, entry] of ADMIN_TOKENS.entries()) {
    if (now - entry.createdAt > TOKEN_EXPIRY) {
      ADMIN_TOKENS.delete(token);
    }
  }
}, 60 * 60 * 1000);

function getTokenFromRequest(req: Request): string | null {
  const cookie = req.headers.get("cookie") || "";
  const match = cookie.match(/collab_token=([^;]+)/);
  if (match) return match[1];
  const auth = req.headers.get("authorization") || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

function getUserTokenFromRequest(req: Request): string | null {
  const cookie = req.headers.get("cookie") || "";
  const hostMatch = cookie.match(/__Host-user_token=([^;]+)/);
  if (hostMatch) return hostMatch[1];
  const match = cookie.match(/user_token=([^;]+)/);
  if (match) return match[1];
  const auth = req.headers.get("authorization") || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

async function validateAdminUser(req: Request): Promise<db.User | null> {
  const token = getUserTokenFromRequest(req);
  if (!token) return null;
  const user = await oidc.validateUserSessionToken(token);
  if (!user || user.role !== 'admin') return null;
  return user;
}

function hasAdminUser(): boolean {
  return db.countUsersByRole('admin') > 0;
}

function getOldAdminPasswordHash(): string | null {
  return db.getSetting('admin_password_hash');
}

function isAdminRoute(path: string): boolean {
  return path === "/" || path === "/index.html" || path.startsWith("/s/") ||
         path.startsWith("/ws/") || path.startsWith("/api/room");
}

function getAdminPath(): string {
  const path = instanceSettings.adminPath || "admin";
  const sanitized = path.replace(/[^a-zA-Z0-9_-]/g, '');
  return sanitized || "admin";
}

function isCustomAdminPath(path: string): boolean {
  const adminPath = getAdminPath();
  return path === `/${adminPath}` || path.startsWith(`/${adminPath}/`);
}

function validateAdminPath(newPath: string): { valid: boolean; error?: string } {
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

async function sendWebhook(event: string, data: any): Promise<void> {
  if (!instanceSettings.webhookEnabled || !instanceSettings.webhookUrl) return;
  try {
    await fetch(instanceSettings.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event, timestamp: new Date().toISOString(), data })
    });
  } catch (e: any) {
    console.error('[Webhook] Failed to send webhook:', e.message);
  }
}

const BACKUPS_DIR = join(DATA_DIR, "backups");
if (!existsSync(BACKUPS_DIR)) mkdirSync(BACKUPS_DIR, { recursive: true });

async function createBackup(autoGenerated: boolean = false): Promise<{ id: string; filename: string; size: number } | null> {
  try {
    const id = crypto.randomUUID();
    const timestamp = new Date().toISOString().replace(/[:.]/g, "").slice(0, 15);
    const filename = `backup_${timestamp}_${id.slice(0, 8)}.json`;
    const rooms = db.listRooms();
    const settings = db.getAllSettings();
    const backupData = { version: 1, timestamp: new Date().toISOString(), rooms, settings };
    const content = JSON.stringify(backupData, null, 2);
    writeFileSync(join(BACKUPS_DIR, filename), content);
    const size = content.length;
    db.createBackupRecord({ id, filename, createdAt: new Date().toISOString(), sizeBytes: size, roomCount: rooms.length, autoGenerated });
    if (autoGenerated && instanceSettings.backupRetentionCount > 0) {
      const oldBackups = db.getOldAutoBackups(instanceSettings.backupRetentionCount);
      for (const backup of oldBackups) {
        const backupPath = join(BACKUPS_DIR, backup.filename);
        if (existsSync(backupPath)) unlinkSync(backupPath);
        db.deleteBackupRecord(backup.id);
      }
    }
    return { id, filename, size };
  } catch { return null; }
}

async function restoreBackup(backupId: string): Promise<{ success: boolean; error?: string; roomsRestored?: number }> {
  const backups = db.listBackups();
  const backup = backups.find(b => b.id === backupId);
  if (!backup) return { success: false, error: "Backup not found" };
  const backupPath = join(BACKUPS_DIR, backup.filename);
  if (!existsSync(backupPath)) return { success: false, error: "Backup file missing" };
  try {
    const content = readFileSync(backupPath, "utf-8");
    const data = JSON.parse(content);
    if (!data.rooms || !Array.isArray(data.rooms)) return { success: false, error: "Invalid backup format" };
    let roomsRestored = 0;
    for (const room of data.rooms) {
      const existing = db.getRoom(room.id);
      if (!existing) {
        db.createRoom(room);
        roomsRestored++;
      }
    }
    return { success: true, roomsRestored };
  } catch { return { success: false, error: "Failed to parse backup" }; }
}

let backupTimer: Timer | null = null;

function restartBackupTimer(): void {
  if (backupTimer) clearInterval(backupTimer);
  backupTimer = null;
  if (instanceSettings.backupEnabled && instanceSettings.backupIntervalHours > 0) {
    backupTimer = setInterval(() => { createBackup(true); }, instanceSettings.backupIntervalHours * 60 * 60 * 1000);
    console.log(`[Backup] Auto backup every ${instanceSettings.backupIntervalHours} hours`);
  }
}

async function hashApiKey(key: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Buffer.from(hash).toString("hex");
}

async function validateApiKey(key: string): Promise<db.ApiKey | null> {
  const hash = await hashApiKey(key);
  const apiKey = db.getApiKeyByHash(hash);
  if (!apiKey) return null;
  if (apiKey.expiresAt && new Date(apiKey.expiresAt) < new Date()) return null;
  db.updateApiKeyLastUsed(apiKey.id);
  return apiKey;
}

const setupPageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Setup - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .setup-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:450px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    .subtitle{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    .info{background:rgba(201,162,39,0.1);border:1px solid rgba(201,162,39,0.3);border-radius:8px;padding:12px;margin-bottom:24px;font-size:13px;color:#c9a227}
    label{display:block;font-size:14px;color:var(--text-soft);margin-bottom:6px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
    button:hover{background:var(--accent-hover)}
    button:disabled{background:var(--border);cursor:not-allowed}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    .oidc-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:var(--bg);border:1px solid var(--border);margin-bottom:12px}
    .oidc-btn:hover{background:var(--bg-alt)}
    .divider{display:flex;align-items:center;gap:12px;margin:24px 0;color:var(--text-soft);font-size:12px}
    .divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}
  </style>
</head>
<body>
  <div class="setup-box">
    <h1>Welcome to The One File Collab</h1>
    <p class="subtitle">Create your admin account to get started</p>
    <div class="info">The first user created becomes the administrator.</div>
    <div class="error" id="error"></div>
    <div id="oidc-buttons"></div>
    <div class="divider" id="divider" style="display:none">or continue with email</div>
    <form id="setup-form">
      <label for="email">Email</label>
      <input type="email" id="email" placeholder="admin@example.com" autocomplete="email" autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" placeholder="At least 8 characters" autocomplete="new-password">
      <label for="confirm">Confirm Password</label>
      <input type="password" id="confirm" placeholder="Confirm your password" autocomplete="new-password">
      <button type="submit" id="submit-btn">Create Admin Account</button>
    </form>
  </div>
  <script>
    (function(){document.documentElement.setAttribute('data-theme',localStorage.getItem('theme')||'dark')})();
    const email=document.getElementById('email'),pwd=document.getElementById('password'),confirm=document.getElementById('confirm'),btn=document.getElementById('submit-btn'),error=document.getElementById('error');
    fetch('/api/auth/providers').then(r=>r.json()).then(providers=>{
      if(providers.length>0){
        document.getElementById('divider').style.display='flex';
        const container=document.getElementById('oidc-buttons');
        providers.forEach(p=>{
          const btn=document.createElement('button');
          btn.type='button';
          btn.className='oidc-btn';
          btn.innerHTML=(p.iconUrl?'<img src="'+p.iconUrl+'" width="20" height="20">':'')+' Continue with '+p.name;
          btn.onclick=()=>window.location.href='/api/auth/oidc/'+p.id+'/login';
          container.appendChild(btn);
        });
      }
    }).catch(()=>{});
    document.getElementById('setup-form').addEventListener('submit',async(e)=>{
      e.preventDefault();error.classList.remove('active');
      if(!email.value||!email.value.includes('@')){error.textContent='Please enter a valid email';error.classList.add('active');return}
      if(pwd.value.length<8){error.textContent='Password must be at least 8 characters';error.classList.add('active');return}
      if(pwd.value!==confirm.value){error.textContent='Passwords do not match';error.classList.add('active');return}
      try{
        const res=await fetch('/api/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email.value,password:pwd.value})});
        const d=await res.json();
        if(res.ok&&d.success){window.location.href='/admin'}
        else{error.textContent=d.error||'Setup failed';error.classList.add('active')}
      }catch{error.textContent='Connection error';error.classList.add('active')}
    });
  </script>
</body>
</html>`;

const migrationPageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Migrate Admin - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .setup-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:450px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    .subtitle{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    .info{background:rgba(201,162,39,0.1);border:1px solid rgba(201,162,39,0.3);border-radius:8px;padding:12px;margin-bottom:24px;font-size:13px;color:#c9a227}
    label{display:block;font-size:14px;color:var(--text-soft);margin-bottom:6px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
  </style>
</head>
<body>
  <div class="setup-box">
    <h1>Migrate to User Account</h1>
    <p class="subtitle">Convert your admin password to a user account</p>
    <div class="info">Enter your current admin password and a new email to create your admin user account. This is a one time migration.</div>
    <div class="error" id="error"></div>
    <form id="migrate-form">
      <label for="old-password">Current Admin Password</label>
      <input type="password" id="old-password" placeholder="Your existing admin password" autofocus>
      <label for="email">Email for Admin Account</label>
      <input type="email" id="email" placeholder="admin@example.com" autocomplete="email">
      <label for="new-password">New Password (optional)</label>
      <input type="password" id="new-password" placeholder="Leave blank to keep current password">
      <button type="submit">Migrate Account</button>
    </form>
  </div>
  <script>
    (function(){document.documentElement.setAttribute('data-theme',localStorage.getItem('theme')||'dark')})();
    const oldPwd=document.getElementById('old-password'),email=document.getElementById('email'),newPwd=document.getElementById('new-password'),error=document.getElementById('error');
    document.getElementById('migrate-form').addEventListener('submit',async(e)=>{
      e.preventDefault();error.classList.remove('active');
      if(!oldPwd.value){error.textContent='Please enter your current admin password';error.classList.add('active');return}
      if(!email.value||!email.value.includes('@')){error.textContent='Please enter a valid email';error.classList.add('active');return}
      try{
        const res=await fetch('/api/admin/migrate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({oldPassword:oldPwd.value,email:email.value,newPassword:newPwd.value||null})});
        const d=await res.json();
        if(res.ok&&d.success){window.location.href='/admin'}
        else{error.textContent=d.error||'Migration failed';error.classList.add('active')}
      }catch{error.textContent='Connection error';error.classList.add('active')}
    });
  </script>
</body>
</html>`;

const loginPageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
  </style>
</head>
<body>
  <div class="login-box">
    <h1>The One File Collab</h1>
    <p>This instance requires a password</p>
    <div class="error" id="error">Invalid password</div>
    <form id="login-form">
      <input type="password" id="password" placeholder="Enter password" autofocus>
      <button type="submit">Login</button>
    </form>
  </div>
  <script>
    (function(){let f=null;function g(){if(f&&f!=='user')return f;return localStorage.getItem('theme')||'dark'}function s(t){document.documentElement.setAttribute('data-theme',t)}s(g());fetch('/api/theme').then(r=>r.json()).then(d=>{if(d.forcedTheme&&d.forcedTheme!=='user'){f=d.forcedTheme;s(f)}}).catch(()=>{})})();
    document.getElementById('login-form').addEventListener('submit',async(e)=>{
      e.preventDefault();
      const password=document.getElementById('password').value;
      try{
        const res=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});
        if(res.ok)window.location.reload();
        else{document.getElementById('error').classList.add('active');document.getElementById('password').value=''}
      }catch{document.getElementById('error').textContent='Connection error';document.getElementById('error').classList.add('active')}
    });
  </script>
</body>
</html>`;

const instanceLoginPageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
  </style>
</head>
<body>
  <div class="login-box">
    <h1>The One File Collab</h1>
    <p>This instance requires a password to access</p>
    <div class="error" id="error">Invalid password</div>
    <form id="login-form">
      <input type="password" id="password" placeholder="Enter password" autofocus>
      <button type="submit">Access</button>
    </form>
  </div>
  <script>
    (function(){let f=null;function g(){if(f&&f!=='user')return f;return localStorage.getItem('theme')||'dark'}function s(t){document.documentElement.setAttribute('data-theme',t)}s(g());fetch('/api/theme').then(r=>r.json()).then(d=>{if(d.forcedTheme&&d.forcedTheme!=='user'){f=d.forcedTheme;s(f)}}).catch(()=>{})})();
    document.getElementById('login-form').addEventListener('submit',async(e)=>{
      e.preventDefault();
      try{
        const res=await fetch('/api/instance-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('password').value})});
        if(res.ok)window.location.reload();
        else{document.getElementById('error').classList.add('active');document.getElementById('password').value=''}
      }catch{document.getElementById('error').textContent='Connection error';document.getElementById('error').classList.add('active')}
    });
  </script>
</body>
</html>`;

const userLoginHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    label{display:block;font-size:14px;color:var(--text-soft);margin-bottom:6px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    .success{color:#22c55e;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .success.active{display:block}
    .links{text-align:center;margin-top:20px;font-size:14px}
    .links a{color:var(--accent);text-decoration:none}
    .links a:hover{text-decoration:underline}
    .oidc-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:var(--bg);border:1px solid var(--border);margin-bottom:12px}
    .oidc-btn:hover{background:var(--bg-alt)}
    .divider{display:flex;align-items:center;gap:12px;margin:24px 0;color:var(--text-soft);font-size:12px}
    .divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}
  </style>
</head>
<body>
  <div class="login-box">
    <h1>Welcome Back</h1>
    <p>Sign in to your account</p>
    <div class="error" id="error"></div>
    <div id="oidc-buttons"></div>
    <div class="divider" id="divider" style="display:none">or continue with email</div>
    <form id="login-form">
      <label for="email">Email</label>
      <input type="email" id="email" placeholder="you@example.com" autocomplete="email" autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" placeholder="Your password" autocomplete="current-password">
      <button type="submit">Sign In</button>
    </form>
    <div class="links">
      <a href="/auth/forgot-password">Forgot password?</a>
      <span style="margin:0 8px;color:var(--text-soft)">|</span>
      <a href="/auth/register">Create account</a>
    </div>
  </div>
  <script>
    (function(){let f=null;function g(){if(f&&f!=='user')return f;return localStorage.getItem('theme')||'dark'}function s(t){document.documentElement.setAttribute('data-theme',t)}s(g());fetch('/api/theme').then(r=>r.json()).then(d=>{if(d.forcedTheme&&d.forcedTheme!=='user'){f=d.forcedTheme;s(f)}}).catch(()=>{})})();
    let csrfToken='';
    fetch('/api/auth/csrf').then(r=>r.json()).then(d=>{csrfToken=d.token}).catch(()=>{});
    fetch('/api/auth/providers').then(r=>r.json()).then(providers=>{
      if(providers.length>0){
        document.getElementById('divider').style.display='flex';
        const container=document.getElementById('oidc-buttons');
        providers.forEach(p=>{
          const btn=document.createElement('button');
          btn.type='button';
          btn.className='oidc-btn';
          btn.innerHTML=(p.iconUrl?'<img src="'+p.iconUrl+'" width="20" height="20">':'')+' Continue with '+p.name;
          btn.onclick=()=>window.location.href='/api/auth/oidc/'+p.id+'/login';
          container.appendChild(btn);
        });
      }
    }).catch(()=>{});
    document.getElementById('login-form').addEventListener('submit',async(e)=>{
      e.preventDefault();
      const error=document.getElementById('error');
      error.classList.remove('active');
      const email=document.getElementById('email').value;
      const password=document.getElementById('password').value;
      if(!email||!email.includes('@')){error.textContent='Please enter a valid email';error.classList.add('active');return}
      if(!password){error.textContent='Please enter your password';error.classList.add('active');return}
      try{
        const res=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password,csrfToken})});
        const d=await res.json();
        if(res.ok&&d.success){const redirect=new URLSearchParams(window.location.search).get('redirect')||'/';window.location.href=redirect}
        else{error.textContent=d.error||'Invalid credentials';error.classList.add('active');document.getElementById('password').value='';fetch('/api/auth/csrf').then(r=>r.json()).then(c=>{csrfToken=c.token}).catch(()=>{})}
      }catch{error.textContent='Connection error';error.classList.add('active')}
    });
  </script>
</body>
</html>`;

const userRegisterHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    label{display:block;font-size:14px;color:var(--text-soft);margin-bottom:6px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    .success{color:#22c55e;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .success.active{display:block}
    .links{text-align:center;margin-top:20px;font-size:14px}
    .links a{color:var(--accent);text-decoration:none}
    .links a:hover{text-decoration:underline}
    .oidc-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:var(--bg);border:1px solid var(--border);margin-bottom:12px}
    .oidc-btn:hover{background:var(--bg-alt)}
    .divider{display:flex;align-items:center;gap:12px;margin:24px 0;color:var(--text-soft);font-size:12px}
    .divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}
    .password-hint{font-size:12px;color:var(--text-soft);margin-top:-12px;margin-bottom:16px}
    .password-strength{height:4px;border-radius:2px;margin-top:-12px;margin-bottom:8px;background:var(--border);overflow:hidden}
    .password-strength-bar{height:100%;transition:all 0.3s;width:0%}
    .password-strength-bar.weak{width:33%;background:#ef4444}
    .password-strength-bar.medium{width:66%;background:#f59e0b}
    .password-strength-bar.strong{width:100%;background:#22c55e}
    .password-strength-text{font-size:11px;margin-top:-4px;margin-bottom:12px;transition:color 0.3s}
    .password-strength-text.weak{color:#ef4444}
    .password-strength-text.medium{color:#f59e0b}
    .password-strength-text.strong{color:#22c55e}
  </style>
</head>
<body>
  <div class="login-box">
    <h1>Create Account</h1>
    <p>Join The One File Collab</p>
    <div class="error" id="error"></div>
    <div class="success" id="success"></div>
    <div id="oidc-buttons"></div>
    <div class="divider" id="divider" style="display:none">or register with email</div>
    <form id="register-form">
      <label for="email">Email</label>
      <input type="email" id="email" placeholder="you@example.com" autocomplete="email" autofocus>
      <label for="displayName">Display Name</label>
      <input type="text" id="displayName" placeholder="Your name" autocomplete="name">
      <label for="password">Password</label>
      <input type="password" id="password" placeholder="Create a password" autocomplete="new-password">
      <div class="password-strength"><div class="password-strength-bar" id="strength-bar"></div></div>
      <div class="password-strength-text" id="strength-text"></div>
      <label for="confirmPassword">Confirm Password</label>
      <input type="password" id="confirmPassword" placeholder="Confirm your password" autocomplete="new-password">
      <button type="submit">Create Account</button>
    </form>
    <div class="links">
      Already have an account? <a href="/auth/login">Sign in</a>
    </div>
  </div>
  <script>
    (function(){let f=null;function g(){if(f&&f!=='user')return f;return localStorage.getItem('theme')||'dark'}function s(t){document.documentElement.setAttribute('data-theme',t)}s(g());fetch('/api/theme').then(r=>r.json()).then(d=>{if(d.forcedTheme&&d.forcedTheme!=='user'){f=d.forcedTheme;s(f)}}).catch(()=>{})})();
    let csrfToken='';
    fetch('/api/auth/csrf').then(r=>r.json()).then(d=>{csrfToken=d.token}).catch(()=>{});
    fetch('/api/auth/providers').then(r=>r.json()).then(providers=>{
      if(providers.length>0){
        document.getElementById('divider').style.display='flex';
        const container=document.getElementById('oidc-buttons');
        providers.forEach(p=>{
          const btn=document.createElement('button');
          btn.type='button';
          btn.className='oidc-btn';
          btn.innerHTML=(p.iconUrl?'<img src="'+p.iconUrl+'" width="20" height="20">':'')+' Continue with '+p.name;
          btn.onclick=()=>window.location.href='/api/auth/oidc/'+p.id+'/login';
          container.appendChild(btn);
        });
      }
    }).catch(()=>{});
    function checkPasswordStrength(pwd){
      if(!pwd)return{strength:'',text:''};
      let score=0;
      if(pwd.length>=8)score++;
      if(pwd.length>=12)score++;
      if(/[a-z]/.test(pwd)&&/[A-Z]/.test(pwd))score++;
      if(/[0-9]/.test(pwd))score++;
      if(/[^a-zA-Z0-9]/.test(pwd))score++;
      if(score<=2)return{strength:'weak',text:'Weak - Add more characters, numbers, or symbols'};
      if(score<=3)return{strength:'medium',text:'Medium - Getting better, add more variety'};
      return{strength:'strong',text:'Strong password'};
    }
    document.getElementById('password').addEventListener('input',(e)=>{
      const{strength,text}=checkPasswordStrength(e.target.value);
      const bar=document.getElementById('strength-bar');
      const txt=document.getElementById('strength-text');
      bar.className='password-strength-bar'+( strength?' '+strength:'');
      txt.className='password-strength-text'+(strength?' '+strength:'');
      txt.textContent=text;
    });
    document.getElementById('register-form').addEventListener('submit',async(e)=>{
      e.preventDefault();
      const error=document.getElementById('error');
      const success=document.getElementById('success');
      error.classList.remove('active');success.classList.remove('active');
      const email=document.getElementById('email').value;
      const displayName=document.getElementById('displayName').value;
      const password=document.getElementById('password').value;
      const confirmPassword=document.getElementById('confirmPassword').value;
      if(!email||!email.includes('@')){error.textContent='Please enter a valid email';error.classList.add('active');return}
      if(!password){error.textContent='Please enter a password';error.classList.add('active');return}
      if(password!==confirmPassword){error.textContent='Passwords do not match';error.classList.add('active');return}
      try{
        const res=await fetch('/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password,displayName:displayName||null,csrfToken})});
        const d=await res.json();
        if(res.ok){
          if(d.requiresVerification){success.textContent='Account created! Please check your email to verify your account.';success.classList.add('active');document.getElementById('register-form').reset()}
          else{window.location.href='/'}
        }else{error.textContent=d.error||'Registration failed';error.classList.add('active');fetch('/api/auth/csrf').then(r=>r.json()).then(c=>{csrfToken=c.token}).catch(()=>{})}
      }catch{error.textContent='Connection error';error.classList.add('active')}
    });
  </script>
</body>
</html>`;

const userForgotPasswordHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Forgot Password - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    label{display:block;font-size:14px;color:var(--text-soft);margin-bottom:6px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    .success{color:#22c55e;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .success.active{display:block}
    .links{text-align:center;margin-top:20px;font-size:14px}
    .links a{color:var(--accent);text-decoration:none}
    .links a:hover{text-decoration:underline}
  </style>
</head>
<body>
  <div class="login-box">
    <h1>Reset Password</h1>
    <p>Enter your email to receive a reset link</p>
    <div class="error" id="error"></div>
    <div class="success" id="success"></div>
    <form id="forgot-form">
      <label for="email">Email</label>
      <input type="email" id="email" placeholder="you@example.com" autocomplete="email" autofocus>
      <button type="submit">Send Reset Link</button>
    </form>
    <div class="links">
      <a href="/auth/login">Back to login</a>
    </div>
  </div>
  <script>
    (function(){let f=null;function g(){if(f&&f!=='user')return f;return localStorage.getItem('theme')||'dark'}function s(t){document.documentElement.setAttribute('data-theme',t)}s(g());fetch('/api/theme').then(r=>r.json()).then(d=>{if(d.forcedTheme&&d.forcedTheme!=='user'){f=d.forcedTheme;s(f)}}).catch(()=>{})})();
    document.getElementById('forgot-form').addEventListener('submit',async(e)=>{
      e.preventDefault();
      const error=document.getElementById('error');
      const success=document.getElementById('success');
      error.classList.remove('active');success.classList.remove('active');
      const email=document.getElementById('email').value;
      if(!email||!email.includes('@')){error.textContent='Please enter a valid email';error.classList.add('active');return}
      try{
        const res=await fetch('/api/auth/forgot-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email})});
        const d=await res.json();
        if(res.ok){success.textContent='If an account exists with this email, a reset link has been sent.';success.classList.add('active');document.getElementById('email').value=''}
        else{error.textContent=d.error||'Failed to send reset email';error.classList.add('active')}
      }catch{error.textContent='Connection error';error.classList.add('active')}
    });
  </script>
</body>
</html>`;

const adminDashboardHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{
      --bg:#0d0d0d;
      --bg-alt:#1a1a1a;
      --surface:#242424;
      --border:#333;
      --text:#e8e8e8;
      --text-soft:#999;
      --accent:#c9a227;
      --accent-hover:#d4b23a;
      --accent-bg:rgba(201,162,39,0.1);
      --accent-bg-hover:rgba(201,162,39,0.15);
    }
    [data-theme="light"]{
      --bg:#f5f3ef;
      --bg-alt:#eae7e0;
      --surface:#fff;
      --border:#d4d0c8;
      --text:#1a1a1a;
      --text-soft:#666;
      --accent:#996b1f;
      --accent-hover:#7a5518;
      --accent-bg:rgba(153,107,31,0.1);
      --accent-bg-hover:rgba(153,107,31,0.15);
    }
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:20px;padding-bottom:80px}
    .container{max-width:1200px;margin:0 auto}
    header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:12px}
    h1{font-size:24px;display:flex;align-items:center;gap:12px}
    .header-actions{display:flex;gap:8px;flex-wrap:wrap}
    .theme-toggle{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;cursor:pointer;font-size:14px}
    .theme-toggle:hover{background:var(--bg-alt)}
    .btn{padding:10px 20px;border-radius:8px;font-size:14px;font-weight:500;cursor:pointer;border:none;transition:all 0.15s;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:6px}
    .btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{background:var(--accent-hover)}
    .btn-secondary{background:var(--surface);color:var(--text);border:1px solid var(--border)}.btn-secondary:hover{background:var(--bg-alt)}
    .btn-danger{background:#dc2626;color:white}.btn-danger:hover{background:#b91c1c}
    .btn-success{background:#22c55e;color:white}.btn-success:hover{background:#16a34a}
    .btn-sm{padding:6px 12px;font-size:12px}
    .btn:disabled{opacity:0.5;cursor:not-allowed}
    .tabs{display:flex;gap:4px;margin-bottom:24px;border-bottom:1px solid var(--border);padding-bottom:0}
    .tab{padding:12px 20px;background:transparent;border:none;color:var(--text-soft);font-size:14px;font-weight:500;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px}
    .tab:hover{color:var(--text)}
    .tab.active{color:var(--accent);border-bottom-color:var(--accent)}
    .tab-content{display:none}
    .tab-content.active{display:block}
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}
    .stat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px}
    .stat-value{font-size:28px;font-weight:700;color:var(--accent)}
    .stat-label{font-size:13px;color:var(--text-soft);margin-top:4px}
    .section-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:12px}
    .section-title{font-size:18px;font-weight:600;display:flex;align-items:center;gap:8px}
    .bulk-actions{display:none;gap:8px;align-items:center;flex-wrap:wrap}
    .bulk-actions.active{display:flex}
    .selected-count{font-size:13px;color:var(--text-soft);padding:6px 12px;background:var(--surface);border-radius:6px}
    .room-list{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden}
    .room-header{display:grid;grid-template-columns:40px 1fr 100px 100px 80px 140px;padding:12px 16px;background:var(--bg-alt);font-size:12px;font-weight:600;color:var(--text-soft);text-transform:uppercase;gap:8px;align-items:center}
    .room-row{display:grid;grid-template-columns:40px 1fr 100px 100px 80px 140px;padding:12px 16px;border-bottom:1px solid var(--border);align-items:center;gap:8px;transition:background 0.15s}
    .room-row:last-child{border-bottom:none}
    .room-row:hover{background:var(--accent-bg)}
    .room-row.selected{background:var(--accent-bg-hover)}
    .room-checkbox{width:20px;height:20px;cursor:pointer;accent-color:var(--accent)}
    .room-id{font-family:monospace;font-size:11px;color:var(--text-soft);word-break:break-all}
    .room-name{font-weight:500;font-size:14px}
    .badge{display:inline-block;padding:4px 8px;border-radius:12px;font-size:11px;font-weight:500}
    .badge-green{background:rgba(34,197,94,0.15);color:#22c55e}
    .badge-yellow{background:rgba(201,162,39,0.15);color:#c9a227}
    .badge-gray{background:rgba(100,116,139,0.15);color:#94a3b8}
    .room-actions{display:flex;gap:6px;flex-wrap:wrap}
    #user-list .room-header,#user-list .room-row{grid-template-columns:1fr 100px 120px 100px 140px}
    .empty-state{text-align:center;padding:60px 20px;color:var(--text-soft)}
    .empty-state h3{font-size:18px;margin-bottom:8px;color:var(--text)}
    .settings-section{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:16px}
    .settings-section h3{font-size:16px;font-weight:600;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--border)}
    .setting-row{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:12px}
    .setting-row:last-child{border-bottom:none}
    .setting-info{flex:1;min-width:200px}
    .setting-label{font-size:14px;font-weight:500;margin-bottom:4px}
    .setting-desc{font-size:12px;color:var(--text-soft)}
    .setting-control{display:flex;align-items:center;gap:8px}
    .toggle{position:relative;width:48px;height:26px;background:var(--border);border-radius:13px;cursor:pointer;transition:background 0.2s}
    .toggle.active{background:var(--accent)}
    .toggle::after{content:'';position:absolute;top:3px;left:3px;width:20px;height:20px;background:var(--text);border-radius:50%;transition:transform 0.2s}
    .toggle.active::after{transform:translateX(22px)}
    input[type="text"],input[type="password"],input[type="number"],input[type="email"],select{padding:10px 12px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px;min-width:120px}
    input:focus,select:focus{outline:none;border-color:var(--accent)}
    .modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:1000;align-items:center;justify-content:center;padding:20px}
    .modal-overlay.active{display:flex}
    .modal{background:var(--surface);border:1px solid var(--border);border-radius:16px;width:100%;max-width:500px}
    .modal-header{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid var(--border)}
    .modal-header h3{font-size:18px}
    .modal-close{background:none;border:none;color:var(--text-soft);font-size:24px;cursor:pointer;padding:4px}
    .modal-body{padding:20px}
    .info-row{display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:8px}
    .info-row:last-child{border-bottom:none}
    .info-label{color:var(--text-soft);font-size:14px}
    .info-value{font-weight:500;font-size:14px;word-break:break-all}
    .status-msg{padding:12px;border-radius:8px;margin-bottom:16px;font-size:14px}
    .status-msg.success{background:rgba(34,197,94,0.15);color:#22c55e}
    .status-msg.error{background:rgba(239,68,68,0.15);color:#ef4444}
    @media(max-width:900px){.room-header,.room-row{grid-template-columns:32px 1fr 80px 100px}.room-header>*:nth-child(4),.room-header>*:nth-child(5),.room-row>*:nth-child(4),.room-row>*:nth-child(5){display:none}#user-list .room-header,#user-list .room-row{grid-template-columns:1fr 80px 100px}#user-list .room-header>*:nth-child(3),#user-list .room-header>*:nth-child(4),#user-list .room-row>*:nth-child(3),#user-list .room-row>*:nth-child(4){display:none}}
    @media(max-width:600px){body{padding:12px;padding-bottom:80px}header{flex-direction:column;align-items:flex-start}h1{font-size:20px}.stats{grid-template-columns:repeat(2,1fr);gap:8px}.stat-card{padding:12px}.stat-value{font-size:22px}.stat-label{font-size:11px}.room-header,.room-row{grid-template-columns:32px 1fr 90px}.room-header>*:nth-child(3),.room-header>*:nth-child(4),.room-header>*:nth-child(5),.room-row>*:nth-child(3),.room-row>*:nth-child(4),.room-row>*:nth-child(5){display:none}#user-list .room-header,#user-list .room-row{grid-template-columns:1fr 90px}#user-list .room-header>*:nth-child(2),#user-list .room-header>*:nth-child(3),#user-list .room-header>*:nth-child(4),#user-list .room-row>*:nth-child(2),#user-list .room-row>*:nth-child(3),#user-list .room-row>*:nth-child(4){display:none}.room-actions{justify-content:flex-end}.btn{padding:8px 12px;font-size:12px}.btn-sm{padding:6px 10px;font-size:11px}.section-header{flex-direction:column;align-items:flex-start}.bulk-actions{width:100%;justify-content:flex-start}.tabs{overflow-x:auto}.setting-row{flex-direction:column;align-items:flex-start}.setting-control{width:100%}}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Admin Dashboard</h1>
      <div class="header-actions">
        <button class="theme-toggle" id="theme-toggle" onclick="toggleTheme()"><span id="theme-icon"></span></button>
        <a href="/" class="btn btn-secondary">Back to App</a>
        <button class="btn btn-secondary" onclick="logout()">Logout</button>
      </div>
    </header>
    <div class="tabs">
      <button class="tab active" onclick="showTab('rooms')">Rooms</button>
      <button class="tab" onclick="showTab('users')">Users</button>
      <button class="tab" onclick="showTab('auth')">Authentication</button>
      <button class="tab" onclick="showTab('settings')">Settings</button>
      <button class="tab" onclick="showTab('logs')">Logs</button>
      <button class="tab" onclick="showTab('backups')">Backups</button>
      <button class="tab" onclick="showTab('apikeys')">API Keys</button>
    </div>
    <div id="tab-rooms" class="tab-content active">
      <div class="stats" id="stats"></div>
      <div class="section-header">
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          <h2 class="section-title">All Rooms</h2>
          <input type="text" id="room-search" placeholder="Search rooms..." style="padding:8px 12px;width:200px" onkeyup="searchRooms(this.value)">
        </div>
        <div class="bulk-actions" id="bulk-actions">
          <span class="selected-count" id="selected-count">0 selected</span>
          <button class="btn btn-danger btn-sm" onclick="deleteSelected()">Delete Selected</button>
          <button class="btn btn-secondary btn-sm" onclick="clearSelection()">Clear</button>
        </div>
      </div>
      <div class="room-list" id="room-list"></div>
    </div>
    <div id="tab-users" class="tab-content">
      <div class="section-header">
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          <h2 class="section-title">User Management</h2>
          <input type="text" id="user-search" placeholder="Search users..." style="padding:8px 12px;width:200px" onkeyup="searchUsers(this.value)">
        </div>
        <button class="btn btn-primary" onclick="showCreateUser()">Create User</button>
      </div>
      <div class="room-list" id="user-list"></div>
    </div>
    <div id="tab-auth" class="tab-content">
      <div id="auth-status"></div>
      <div class="settings-section">
        <h3>Authentication Mode</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Default Auth Mode</div><div class="setting-desc">How users can access the system</div></div>
          <div class="setting-control">
            <select id="auth-mode" onchange="saveAuthSettings()">
              <option value="open">Open (Anyone can register)</option>
              <option value="registration">Registration Required</option>
              <option value="oidc_only">OIDC Only</option>
              <option value="invite_only">Invite Only</option>
              <option value="closed">Closed (No new users)</option>
            </select>
          </div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Require Email Verification</div><div class="setting-desc">Users must verify email before accessing</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-require-email-verify" onclick="toggleAuthSetting('requireEmailVerification')"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Allow Magic Link Login</div><div class="setting-desc">Users can login via email link</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-magic-link" onclick="toggleAuthSetting('allowMagicLinkLogin')"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Match OIDC Emails</div><div class="setting-desc">Auto link OIDC accounts with matching email. <span style="color:#f59e0b">Only enable with trusted providers</span></div></div>
          <div class="setting-control"><div class="toggle" id="toggle-oidc-email-match" onclick="toggleAuthSetting('oidcEmailMatching')"></div></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Security</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Production Mode</div><div class="setting-desc">Enable HTTPS secure cookies. <span style="color:#ef4444">Required for production</span></div></div>
          <div class="setting-control"><div class="toggle" id="toggle-production-mode" onclick="toggleAuthSetting('productionMode')"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">ID Token Max Age (hours)</div><div class="setting-desc">Maximum age for OIDC ID tokens before they are considered too old</div></div>
          <div class="setting-control"><input type="number" id="input-id-token-max-age" min="1" max="168" style="width:80px;padding:8px;border:1px solid #374151;border-radius:4px;background:#1f2937;color:#fff" onchange="updateAuthNumber('idTokenMaxAgeHours',this.value)"></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Email Rate Limit Window (seconds)</div><div class="setting-desc">Time window for email rate limiting</div></div>
          <div class="setting-control"><input type="number" id="input-email-rate-window" min="60" max="3600" style="width:80px;padding:8px;border:1px solid #374151;border-radius:4px;background:#1f2937;color:#fff" onchange="updateAuthNumber('emailRateLimitWindowSeconds',this.value)"></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Email Rate Limit Max Attempts</div><div class="setting-desc">Maximum email requests per address within window</div></div>
          <div class="setting-control"><input type="number" id="input-email-rate-max" min="1" max="20" style="width:80px;padding:8px;border:1px solid #374151;border-radius:4px;background:#1f2937;color:#fff" onchange="updateAuthNumber('emailRateLimitMaxAttempts',this.value)"></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Guest Access</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Allow Guest Room Creation</div><div class="setting-desc">Unregistered users can create rooms</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-guest-room-create" onclick="toggleAuthSetting('allowGuestRoomCreation')"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Allow Guest Room Join</div><div class="setting-desc">Unregistered users can join rooms</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-guest-room-join" onclick="toggleAuthSetting('allowGuestRoomJoin')"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Room Creator Guest Setting</div><div class="setting-desc">Let room creators choose guest access per room</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-room-creator-guest" onclick="toggleAuthSetting('allowRoomCreatorGuestSetting')"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Share Button</div><div class="setting-desc">Show share button in rooms</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-share-button" onclick="toggleAuthSetting('shareButtonEnabled')"></div></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>OIDC Providers</h3>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <p style="color:var(--text-soft);font-size:13px">Configure OpenID Connect providers for SSO</p>
          <button class="btn btn-primary btn-sm" onclick="showAddOidcProvider()">Add Provider</button>
        </div>
        <div id="oidc-provider-list"></div>
      </div>
      <div class="settings-section">
        <h3>SMTP Configuration</h3>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <p style="color:var(--text-soft);font-size:13px">Configure email delivery for verification and notifications</p>
          <button class="btn btn-primary btn-sm" onclick="showAddSmtpConfig()">Add SMTP</button>
        </div>
        <div id="smtp-config-list"></div>
      </div>
      <div class="settings-section">
        <h3>Email Templates</h3>
        <div id="email-template-list"></div>
      </div>
      <div class="settings-section">
        <h3>Email Logs</h3>
        <div style="margin-bottom:12px;display:flex;gap:12px;align-items:center"><input type="text" id="email-log-search" placeholder="Filter by email..." style="width:250px" onkeyup="loadEmailLogs()"><button class="btn btn-sm btn-secondary" onclick="clearEmailLogs()">Clear All</button></div>
        <div id="email-log-list" style="max-height:300px;overflow-y:auto"></div>
      </div>
    </div>
    <div id="tab-settings" class="tab-content">
      <div id="settings-status"></div>
      <div class="settings-section">
        <h3>Instance Access</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Password Lock</div><div class="setting-desc">Require password to access the entire instance</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-instance-lock" onclick="toggleSetting('instancePasswordEnabled')"></div></div>
        </div>
        <div class="setting-row" id="instance-pwd-row" style="display:none">
          <div class="setting-info"><div class="setting-label">Instance Password</div><div class="setting-desc" id="instance-pwd-status">Set a password for instance access</div></div>
          <div class="setting-control"><input type="password" id="instance-password" placeholder="New password"><button class="btn btn-sm btn-primary" onclick="setInstancePassword()">Set</button></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Admin Panel Path</div><div class="setting-desc">Custom URL path for the admin panel (default: admin)</div></div>
          <div class="setting-control"><span style="color:#8892a0;font-size:12px">/</span><input type="text" id="admin-path" placeholder="admin" style="width:150px" pattern="[a-zA-Z0-9_-]+"><button class="btn btn-sm btn-primary" onclick="saveAdminPath()">Save</button></div>
        </div>
        <div class="setting-row" id="admin-path-info" style="display:none">
          <div class="setting-info"><div class="setting-label"></div><div class="setting-desc" id="admin-path-current" style="color:#4ade80">Current path: /admin</div></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>TheOneFile Source</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Source Mode</div><div class="setting-desc">Choose where to load TheOneFile from</div></div>
          <div class="setting-control">
            <select id="source-mode" onchange="changeSourceMode()"><option value="github">GitHub (Auto-Update)</option><option value="local">Local (Manual Upload)</option></select>
          </div>
        </div>
        <div class="setting-row" id="github-settings">
          <div class="setting-info"><div class="setting-label">Update Interval</div><div class="setting-desc">Hours between auto updates (0 = manual only)</div></div>
          <div class="setting-control"><input type="number" id="update-interval" min="0" max="168" style="width:80px"><button class="btn btn-sm btn-primary" onclick="saveUpdateInterval()">Save</button></div>
        </div>
        <div class="setting-row" id="github-update-row">
          <div class="setting-info"><div class="setting-label">Fetch from GitHub</div><div class="setting-desc">Download latest version now</div></div>
          <div class="setting-control"><button class="btn btn-sm btn-success" id="update-btn" onclick="triggerUpdate()">Update Now</button></div>
        </div>
        <div class="setting-row" id="upload-row" style="display:none">
          <div class="setting-info"><div class="setting-label">Upload Local File</div><div class="setting-desc" id="upload-status">Upload your own TheOneFile HTML</div></div>
          <div class="setting-control">
            <input type="file" id="upload-file" accept=".html" style="display:none" onchange="uploadFile()">
            <button class="btn btn-sm btn-primary" onclick="document.getElementById('upload-file').click()">Choose File</button>
          </div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Current File</div><div class="setting-desc" id="current-file-info">Loading...</div></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Appearance</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Theme</div><div class="setting-desc">Force a theme for all users or let them choose</div></div>
          <div class="setting-control">
            <select id="forced-theme" onchange="saveForcedTheme()"><option value="user">User Choice</option><option value="dark">Force Dark</option><option value="light">Force Light</option></select>
          </div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Room Defaults</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Default Self Destruct</div><div class="setting-desc">Default expiration for new rooms</div></div>
          <div class="setting-control">
            <select id="default-destruct-mode"><option value="time">After time</option><option value="empty">When empty</option><option value="never">Never</option></select>
            <input type="number" id="default-destruct-hours" min="1" max="720" style="width:70px">
            <span style="color:#8892a0;font-size:12px">hours</span>
          </div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Max Rooms</div><div class="setting-desc">Maximum rooms allowed (0 = unlimited)</div></div>
          <div class="setting-control"><input type="number" id="max-rooms" min="0" max="1000" style="width:80px"></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Public Room Creation</div><div class="setting-desc">Allow anyone to create rooms</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-public-rooms" onclick="toggleSetting('allowPublicRoomCreation')"></div></div>
        </div>
        <div style="margin-top:16px"><button class="btn btn-primary" onclick="saveRoomDefaults()">Save Room Settings</button></div>
      </div>
      <div class="settings-section">
        <h3>Rate Limiting</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Enable Rate Limiting</div><div class="setting-desc">Protect against brute force attacks</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-rate-limit" onclick="toggleSetting('rateLimitEnabled')"></div></div>
        </div>
        <div class="setting-row" id="rate-limit-options">
          <div class="setting-info"><div class="setting-label">Limit Settings</div><div class="setting-desc">Max attempts per time window</div></div>
          <div class="setting-control">
            <input type="number" id="rate-limit-attempts" min="1" max="100" style="width:60px">
            <span style="color:#8892a0;font-size:12px">attempts per</span>
            <input type="number" id="rate-limit-window" min="10" max="3600" style="width:70px">
            <span style="color:#8892a0;font-size:12px">seconds</span>
          </div>
        </div>
        <div style="margin-top:16px"><button class="btn btn-primary" onclick="saveRateLimitSettings()">Save Rate Limit Settings</button></div>
      </div>
      <div class="settings-section">
        <h3>Collaboration Features</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Chat</div><div class="setting-desc">Enable chat in rooms</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-chat" onclick="toggleSetting('chatEnabled')"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Cursor Sharing</div><div class="setting-desc">Show other users cursors</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-cursor" onclick="toggleSetting('cursorSharingEnabled')"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Name Changes</div><div class="setting-desc">Allow users to change name after joining</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-namechange" onclick="toggleSetting('nameChangeEnabled')"></div></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Webhooks</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Enable Webhooks</div><div class="setting-desc">Send notifications for events</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-webhook" onclick="toggleSetting('webhookEnabled')"></div></div>
        </div>
        <div class="setting-row" id="webhook-url-row">
          <div class="setting-info"><div class="setting-label">Webhook URL</div><div class="setting-desc">POST endpoint for notifications</div></div>
          <div class="setting-control"><input type="text" id="webhook-url" placeholder="https://..." style="width:250px"><button class="btn btn-sm btn-primary" onclick="saveWebhookUrl()">Save</button></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Automatic Backups</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Enable Auto Backup</div><div class="setting-desc">Automatically backup data</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-backup" onclick="toggleSetting('backupEnabled')"></div></div>
        </div>
        <div class="setting-row" id="backup-options">
          <div class="setting-info"><div class="setting-label">Backup Settings</div><div class="setting-desc">Interval and retention</div></div>
          <div class="setting-control">
            <span style="color:#8892a0;font-size:12px">Every</span>
            <input type="number" id="backup-interval" min="1" max="168" style="width:60px">
            <span style="color:#8892a0;font-size:12px">hours, keep</span>
            <input type="number" id="backup-retention" min="1" max="100" style="width:60px">
            <span style="color:#8892a0;font-size:12px">backups</span>
          </div>
        </div>
        <div style="margin-top:16px"><button class="btn btn-primary" onclick="saveBackupSettings()">Save Backup Settings</button></div>
      </div>
    </div>
    <div id="tab-logs" class="tab-content">
      <div class="settings-section">
        <h3>Activity Log</h3>
        <div style="margin-bottom:12px;display:flex;gap:12px;align-items:center"><input type="text" id="activity-search" placeholder="Filter by room ID..." style="width:250px" onkeyup="loadActivityLogs()"><button class="btn btn-sm btn-secondary" onclick="clearActivityLogs()">Clear All</button></div>
        <div id="activity-log-list" style="max-height:400px;overflow-y:auto"></div>
      </div>
      <div class="settings-section">
        <h3>Audit Log</h3>
        <div style="margin-bottom:12px;display:flex;gap:12px;align-items:center"><input type="text" id="audit-search" placeholder="Search..." style="width:250px" onkeyup="loadAuditLogs()"><button class="btn btn-sm btn-secondary" onclick="clearAuditLogs()">Clear All</button></div>
        <div id="audit-log-list" style="max-height:400px;overflow-y:auto"></div>
      </div>
    </div>
    <div id="tab-backups" class="tab-content">
      <div class="settings-section">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <h3 style="margin:0;border:none;padding:0">Backups</h3>
          <div style="display:flex;gap:8px">
            <button class="btn btn-primary btn-sm" onclick="createBackup()">Create Backup</button>
            <button class="btn btn-secondary btn-sm" onclick="exportAll()">Export All</button>
          </div>
        </div>
        <div id="backup-list"></div>
      </div>
    </div>
    <div id="tab-apikeys" class="tab-content">
      <div class="settings-section">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <h3 style="margin:0;border:none;padding:0">API Keys</h3>
          <button class="btn btn-primary btn-sm" onclick="showCreateApiKey()">Create API Key</button>
        </div>
        <div id="apikey-list"></div>
        <div id="new-key-display" style="display:none;margin-top:16px;padding:16px;background:var(--bg);border-radius:8px">
          <p style="margin-bottom:8px;font-weight:500">New API Key Created</p>
          <p style="font-size:12px;color:var(--text-soft);margin-bottom:8px">Copy this key now. It will not be shown again.</p>
          <code id="new-key-value" style="display:block;padding:12px;background:var(--surface);border-radius:4px;word-break:break-all;font-size:12px"></code>
        </div>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="room-modal">
    <div class="modal">
      <div class="modal-header"><h3 id="modal-title">Room Details</h3><button class="modal-close" onclick="closeModal()">&times;</button></div>
      <div class="modal-body" id="modal-body"></div>
    </div>
  </div>
  <div class="modal-overlay" id="apikey-modal">
    <div class="modal">
      <div class="modal-header"><h3>Create API Key</h3><button class="modal-close" onclick="closeApiKeyModal()">&times;</button></div>
      <div class="modal-body">
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Name</label><input type="text" id="apikey-name" placeholder="My API Key" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Expires In (days, 0=never)</label><input type="number" id="apikey-expires" value="0" min="0" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Permissions</label>
          <label style="display:flex;align-items:center;gap:8px;margin:8px 0"><input type="checkbox" id="perm-read" checked> Read rooms</label>
          <label style="display:flex;align-items:center;gap:8px;margin:8px 0"><input type="checkbox" id="perm-write"> Write rooms</label>
          <label style="display:flex;align-items:center;gap:8px;margin:8px 0"><input type="checkbox" id="perm-admin"> Admin access</label>
        </div>
        <button class="btn btn-primary" onclick="createApiKey()" style="width:100%">Create Key</button>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="user-modal">
    <div class="modal">
      <div class="modal-header"><h3>Create User</h3><button class="modal-close" onclick="closeUserModal()">&times;</button></div>
      <div class="modal-body">
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Email</label><input type="email" id="user-email" placeholder="user@example.com" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Display Name</label><input type="text" id="user-displayname" placeholder="John Doe" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Password (leave blank for invite email)</label><input type="password" id="user-password" placeholder="Optional" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Role</label>
          <select id="user-role" style="width:100%"><option value="user">User</option><option value="admin">Admin</option></select>
        </div>
        <button class="btn btn-primary" onclick="createUser()" style="width:100%">Create User</button>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="edit-user-modal">
    <div class="modal">
      <div class="modal-header"><h3>Edit User</h3><button class="modal-close" onclick="closeEditUserModal()">&times;</button></div>
      <div class="modal-body">
        <input type="hidden" id="edit-user-id">
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Email</label><input type="email" id="edit-user-email" style="width:100%;background:var(--bg-alt)" readonly></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Display Name</label><input type="text" id="edit-user-displayname" placeholder="Display Name" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">New Password (leave blank to keep current)</label><input type="password" id="edit-user-password" placeholder="Optional" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Role</label>
          <select id="edit-user-role" style="width:100%"><option value="user">User</option><option value="admin">Admin</option></select>
        </div>
        <div style="margin-bottom:16px">
          <label style="display:flex;align-items:center;gap:8px"><input type="checkbox" id="edit-user-active"> Active</label>
          <label style="display:flex;align-items:center;gap:8px;margin-top:8px"><input type="checkbox" id="edit-user-verified"> Email Verified</label>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-secondary" onclick="resetUserPassword()" style="flex:1">Send Password Reset</button>
          <button class="btn btn-primary" onclick="saveUserEdit()" style="flex:1">Save</button>
        </div>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="oidc-modal">
    <div class="modal" style="max-width:550px">
      <div class="modal-header"><h3 id="oidc-modal-title">Add OIDC Provider</h3><button class="modal-close" onclick="closeOidcModal()">&times;</button></div>
      <div class="modal-body">
        <input type="hidden" id="oidc-edit-id">
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Name</label><input type="text" id="oidc-name" placeholder="My Provider" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Provider Type</label>
          <select id="oidc-type" style="width:100%"><option value="generic">Generic OIDC</option><option value="authentik">Authentik</option><option value="keycloak">Keycloak</option><option value="auth0">Auth0</option><option value="okta">Okta</option></select>
        </div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Client ID</label><input type="text" id="oidc-client-id" placeholder="client-id" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Client Secret</label><input type="password" id="oidc-client-secret" placeholder="client-secret" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Issuer URL</label><input type="text" id="oidc-issuer" placeholder="https://auth.example.com" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Authorization URL</label><input type="text" id="oidc-auth-url" placeholder="https://auth.example.com/authorize" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Token URL</label><input type="text" id="oidc-token-url" placeholder="https://auth.example.com/token" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Userinfo URL</label><input type="text" id="oidc-userinfo-url" placeholder="https://auth.example.com/userinfo" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Scopes</label><input type="text" id="oidc-scopes" value="openid email profile" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:flex;align-items:center;gap:8px"><input type="checkbox" id="oidc-active" checked> Active</label></div>
        <button class="btn btn-primary" onclick="saveOidcProvider()" style="width:100%">Save Provider</button>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="smtp-modal">
    <div class="modal" style="max-width:550px">
      <div class="modal-header"><h3 id="smtp-modal-title">Add SMTP Configuration</h3><button class="modal-close" onclick="closeSmtpModal()">&times;</button></div>
      <div class="modal-body">
        <input type="hidden" id="smtp-edit-id">
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Name</label><input type="text" id="smtp-name" placeholder="Primary SMTP" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Host</label><input type="text" id="smtp-host" placeholder="smtp.example.com" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Port</label><input type="number" id="smtp-port" value="587" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Security Mode</label>
          <select id="smtp-secure-mode" style="width:100%"><option value="starttls">STARTTLS (587)</option><option value="tls">TLS/SSL (465)</option><option value="none">None (25)</option></select>
        </div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Username</label><input type="text" id="smtp-username" placeholder="user@example.com" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Password</label><input type="password" id="smtp-password" placeholder="password" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">From Email</label><input type="email" id="smtp-from-email" placeholder="noreply@example.com" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">From Name</label><input type="text" id="smtp-from-name" placeholder="TheOneFile_Verse" style="width:100%"></div>
        <div style="margin-bottom:16px">
          <label style="display:flex;align-items:center;gap:8px"><input type="checkbox" id="smtp-default"> Set as default</label>
          <label style="display:flex;align-items:center;gap:8px;margin-top:8px"><input type="checkbox" id="smtp-active" checked> Active</label>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-secondary" onclick="testSmtpConfig()" style="flex:1">Test</button>
          <button class="btn btn-primary" onclick="saveSmtpConfig()" style="flex:1">Save</button>
        </div>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="template-modal">
    <div class="modal" style="max-width:900px;max-height:90vh;display:flex;flex-direction:column">
      <div class="modal-header"><h3 id="template-modal-title">Edit Email Template</h3><button class="modal-close" onclick="closeTemplateModal()">&times;</button></div>
      <div class="modal-body" style="flex:1;overflow:auto;display:flex;flex-direction:column">
        <input type="hidden" id="template-edit-id">
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Template Name</label><input type="text" id="template-name" readonly style="width:100%;background:var(--bg-alt)"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Subject</label><input type="text" id="template-subject" placeholder="Email subject with {{variables}}" style="width:100%"></div>
        <div style="margin-bottom:8px;display:flex;justify-content:space-between;align-items:center">
          <label style="font-size:14px">HTML Body</label>
          <div style="display:flex;gap:4px">
            <button class="btn btn-sm btn-secondary" onclick="insertTemplateVar('displayName')">{{displayName}}</button>
            <button class="btn btn-sm btn-secondary" onclick="insertTemplateVar('actionUrl')">{{actionUrl}}</button>
            <button class="btn btn-sm btn-secondary" onclick="insertTemplateVar('appName')">{{appName}}</button>
            <button class="btn btn-sm btn-secondary" onclick="toggleTemplateView()">Toggle HTML/Preview</button>
          </div>
        </div>
        <div style="flex:1;min-height:300px;position:relative">
          <div id="template-editor-toolbar" style="background:var(--bg-alt);border:1px solid var(--border);border-bottom:none;border-radius:8px 8px 0 0;padding:8px;display:flex;gap:4px;flex-wrap:wrap">
            <button type="button" class="btn btn-sm btn-secondary" onclick="execCmd('bold')" title="Bold"><b>B</b></button>
            <button type="button" class="btn btn-sm btn-secondary" onclick="execCmd('italic')" title="Italic"><i>I</i></button>
            <button type="button" class="btn btn-sm btn-secondary" onclick="execCmd('underline')" title="Underline"><u>U</u></button>
            <span style="border-left:1px solid var(--border);margin:0 4px"></span>
            <button type="button" class="btn btn-sm btn-secondary" onclick="execCmd('justifyLeft')" title="Align Left">&#8676;</button>
            <button type="button" class="btn btn-sm btn-secondary" onclick="execCmd('justifyCenter')" title="Center">&#8596;</button>
            <button type="button" class="btn btn-sm btn-secondary" onclick="execCmd('justifyRight')" title="Align Right">&#8677;</button>
            <span style="border-left:1px solid var(--border);margin:0 4px"></span>
            <button type="button" class="btn btn-sm btn-secondary" onclick="execCmd('insertUnorderedList')" title="Bullet List">&#8226;</button>
            <button type="button" class="btn btn-sm btn-secondary" onclick="execCmd('insertOrderedList')" title="Numbered List">1.</button>
            <span style="border-left:1px solid var(--border);margin:0 4px"></span>
            <select onchange="execCmdArg('formatBlock',this.value);this.selectedIndex=0" style="padding:4px 8px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px">
              <option value="">Heading</option>
              <option value="h1">Heading 1</option>
              <option value="h2">Heading 2</option>
              <option value="h3">Heading 3</option>
              <option value="p">Paragraph</option>
            </select>
            <select onchange="execCmdArg('fontSize',this.value);this.selectedIndex=0" style="padding:4px 8px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px">
              <option value="">Size</option>
              <option value="1">Small</option>
              <option value="3">Normal</option>
              <option value="5">Large</option>
              <option value="7">Huge</option>
            </select>
            <input type="color" id="template-color" onchange="execCmdArg('foreColor',this.value)" title="Text Color" style="width:30px;height:26px;padding:0;border:1px solid var(--border);border-radius:4px;cursor:pointer">
            <span style="border-left:1px solid var(--border);margin:0 4px"></span>
            <button type="button" class="btn btn-sm btn-secondary" onclick="insertLink()" title="Insert Link">&#128279;</button>
            <button type="button" class="btn btn-sm btn-secondary" onclick="insertImage()" title="Insert Image">&#128247;</button>
            <button type="button" class="btn btn-sm btn-secondary" onclick="insertButton()" title="Insert Button">&#9634; Btn</button>
          </div>
          <div id="template-editor" contenteditable="true" style="flex:1;min-height:250px;background:var(--surface);border:1px solid var(--border);border-radius:0 0 8px 8px;padding:16px;overflow-y:auto;font-family:system-ui;line-height:1.6"></div>
          <textarea id="template-html-source" style="display:none;width:100%;min-height:300px;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;font-family:monospace;font-size:13px;color:var(--text);resize:vertical"></textarea>
        </div>
        <div style="margin-top:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Plain Text Body (fallback)</label><textarea id="template-text" placeholder="Plain text version for email clients that don't support HTML" style="width:100%;height:100px;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;font-family:monospace;font-size:13px;color:var(--text);resize:vertical"></textarea></div>
        <div style="margin-top:16px;display:flex;gap:8px;justify-content:flex-end">
          <button class="btn btn-secondary" onclick="previewTemplate()">Preview</button>
          <button class="btn btn-primary" onclick="saveTemplate()">Save Template</button>
        </div>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="template-preview-modal">
    <div class="modal" style="max-width:700px;max-height:80vh">
      <div class="modal-header"><h3>Email Preview</h3><button class="modal-close" onclick="closeTemplatePreview()">&times;</button></div>
      <div class="modal-body" style="padding:0">
        <div style="padding:12px 16px;background:var(--bg-alt);border-bottom:1px solid var(--border)">
          <div style="font-size:12px;color:var(--text-soft)">Subject:</div>
          <div id="preview-subject" style="font-weight:500"></div>
        </div>
        <iframe id="preview-frame" style="width:100%;height:400px;border:none;background:#fff"></iframe>
      </div>
    </div>
  </div>
  <script>
    let forcedTheme=null;
    function getTheme(){if(forcedTheme&&forcedTheme!=='user')return forcedTheme;return localStorage.getItem('theme')||'dark'}
    function setTheme(theme){if(!forcedTheme||forcedTheme==='user')localStorage.setItem('theme',theme);document.documentElement.setAttribute('data-theme',theme);document.getElementById('theme-icon').textContent=theme==='dark'?'\\u2600':'\\u263E'}
    function toggleTheme(){if(forcedTheme&&forcedTheme!=='user')return;setTheme(getTheme()==='dark'?'light':'dark')}
    function updateThemeToggleVisibility(){const btn=document.getElementById('theme-toggle');if(forcedTheme&&forcedTheme!=='user')btn.style.display='none';else btn.style.display='block'}
    setTheme(getTheme());
    fetch('/api/theme').then(r=>r.json()).then(data=>{if(data.forcedTheme&&data.forcedTheme!=='user'){forcedTheme=data.forcedTheme;setTheme(forcedTheme)}updateThemeToggleVisibility()}).catch(()=>updateThemeToggleVisibility());
    let rooms=[],selected=new Set(),settings={},totalRooms=0,searchTimeout=null,users=[],authSettings={},oidcProviders=[],smtpConfigs=[],emailLogs=[];
    function showTab(name){document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));document.querySelector('.tab-content#tab-'+name).classList.add('active');document.querySelector('.tab[onclick*="'+name+'"]').classList.add('active');if(name==='settings')loadSettings();if(name==='logs'){loadActivityLogs();loadAuditLogs()}if(name==='backups')loadBackups();if(name==='apikeys')loadApiKeys();if(name==='users')loadUsers();if(name==='auth'){loadAuthSettings();loadOidcProviders();loadSmtpConfigs();loadEmailTemplates();loadEmailLogs()}}
    async function loadData(query=''){try{const url=query?'/api/admin/rooms?q='+encodeURIComponent(query):'/api/admin/rooms';const res=await fetch(url);if(!res.ok){if(res.status===401)window.location.href='/admin/login';return}const data=await res.json();rooms=data.rooms||data;totalRooms=data.total||rooms.length;renderStats();renderRooms();updateBulkUI()}catch(e){console.error(e)}}
    function searchRooms(q){if(searchTimeout)clearTimeout(searchTimeout);searchTimeout=setTimeout(()=>loadData(q),300)}
    async function loadSettings(){try{const res=await fetch('/api/admin/settings');if(!res.ok)return;settings=await res.json();renderSettings()}catch(e){console.error(e)}}
    function renderSettings(){
      document.getElementById('toggle-instance-lock').classList.toggle('active',settings.instancePasswordEnabled);
      document.getElementById('toggle-public-rooms').classList.toggle('active',settings.allowPublicRoomCreation);
      document.getElementById('toggle-rate-limit').classList.toggle('active',settings.rateLimitEnabled!==false);
      document.getElementById('update-interval').value=settings.updateIntervalHours||0;
      document.getElementById('default-destruct-mode').value=settings.defaultDestructMode||'time';
      document.getElementById('default-destruct-hours').value=settings.defaultDestructHours||24;
      document.getElementById('max-rooms').value=settings.maxRoomsPerInstance||0;
      document.getElementById('forced-theme').value=settings.forcedTheme||'user';
      document.getElementById('rate-limit-attempts').value=settings.rateLimitMaxAttempts||10;
      document.getElementById('rate-limit-window').value=settings.rateLimitWindow||60;
      document.getElementById('rate-limit-options').style.display=settings.rateLimitEnabled!==false?'flex':'none';
      document.getElementById('instance-pwd-row').style.display=settings.instancePasswordEnabled?'flex':'none';
      document.getElementById('instance-pwd-status').textContent=settings.instancePasswordSet?'Password is set':'No password set';
      if(settings.envAdminPasswordSet){document.getElementById('toggle-instance-lock').style.opacity='0.5';document.getElementById('toggle-instance-lock').onclick=null}
      document.getElementById('toggle-chat').classList.toggle('active',settings.chatEnabled!==false);
      document.getElementById('toggle-cursor').classList.toggle('active',settings.cursorSharingEnabled!==false);
      document.getElementById('toggle-namechange').classList.toggle('active',settings.nameChangeEnabled!==false);
      document.getElementById('toggle-webhook').classList.toggle('active',settings.webhookEnabled);
      document.getElementById('webhook-url').value=settings.webhookUrl||'';
      document.getElementById('webhook-url-row').style.display=settings.webhookEnabled?'flex':'none';
      document.getElementById('toggle-backup').classList.toggle('active',settings.backupEnabled);
      document.getElementById('backup-interval').value=settings.backupIntervalHours||24;
      document.getElementById('backup-retention').value=settings.backupRetentionCount||7;
      document.getElementById('backup-options').style.display=settings.backupEnabled?'flex':'none';
      document.getElementById('admin-path').value=settings.adminPath||'admin';
      document.getElementById('admin-path-info').style.display='flex';
      document.getElementById('admin-path-current').textContent='Current path: /'+(settings.adminPath||'admin');
      updateSourceUI();
    }
    async function saveAdminPath(){
      const newPath=document.getElementById('admin-path').value.trim();
      if(!newPath){showStatus('Admin path cannot be empty','error');return}
      if(!/^[a-zA-Z0-9_-]+$/.test(newPath)){showStatus('Admin path can only contain letters, numbers, hyphens, and underscores','error');return}
      if(newPath.length<2){showStatus('Admin path must be at least 2 characters','error');return}
      const reserved=['api','s','ws','auth','public','static','assets'];
      if(reserved.includes(newPath.toLowerCase())){showStatus('This path is reserved','error');return}
      try{
        const res=await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({adminPath:newPath})});
        const data=await res.json();
        if(!res.ok){showStatus(data.error||'Failed to save','error');return}
        document.getElementById('admin-path-current').textContent='Current path: /'+newPath;
        showStatus('Admin path saved! Redirecting to new path...','success');
        setTimeout(()=>{window.location.href='/'+newPath},1500);
      }catch(e){showStatus('Error saving admin path','error')}
    }
    async function saveRateLimitSettings(){
      const attempts=parseInt(document.getElementById('rate-limit-attempts').value)||10;
      const window=parseInt(document.getElementById('rate-limit-window').value)||60;
      await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({rateLimitMaxAttempts:attempts,rateLimitWindow:window})});
      showStatus('Rate limit settings saved','success');
    }
    async function saveForcedTheme(){
      const val=document.getElementById('forced-theme').value;
      await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({forcedTheme:val})});
      showStatus('Theme setting saved','success');
    }
    async function toggleSetting(key){
      if(key==='instancePasswordEnabled'&&settings.envAdminPasswordSet)return;
      settings[key]=!settings[key];
      renderSettings();
      await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({[key]:settings[key]})});
      showStatus('Setting updated','success');
    }
    async function setInstancePassword(){
      const pwd=document.getElementById('instance-password').value;
      if(pwd.length<10){showStatus('Password must be at least 10 characters','error');return}
      await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({instancePassword:pwd})});
      document.getElementById('instance-password').value='';
      showStatus('Password updated','success');
      loadSettings();
    }
    async function saveUpdateInterval(){
      const val=parseInt(document.getElementById('update-interval').value)||0;
      await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({updateIntervalHours:val})});
      showStatus('Update interval saved','success');
    }
    async function triggerUpdate(){
      const btn=document.getElementById('update-btn');btn.disabled=true;btn.textContent='Updating...';
      try{const res=await fetch('/api/admin/update',{method:'POST'});const data=await res.json();
        if(data.success){showStatus('Updated successfully ('+Math.round(data.size/1024)+'KB)','success');loadSettings()}
        else showStatus(data.error||'Update failed','error');
      }catch{showStatus('Update failed','error')}
      btn.disabled=false;btn.textContent='Update Now';
    }
    async function changeSourceMode(){
      const mode=document.getElementById('source-mode').value;
      try{
        const res=await fetch('/api/admin/source-mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode})});
        const data=await res.json();
        if(data.success){
          showStatus('Source mode changed to '+mode,'success');
          loadSettings();
        }else{showStatus(data.error||'Failed to change mode','error')}
      }catch{showStatus('Failed to change mode','error')}
    }
    async function uploadFile(){
      const input=document.getElementById('upload-file');
      if(!input.files||!input.files[0])return;
      const file=input.files[0];
      const formData=new FormData();
      formData.append('file',file);
      try{
        const res=await fetch('/api/admin/upload-html',{method:'POST',body:formData});
        const data=await res.json();
        if(data.success){
          showStatus('Uploaded successfully ('+Math.round(data.size/1024)+'KB), '+data.edition+' edition','success');
          loadSettings();
        }else{showStatus(data.error||'Upload failed','error')}
      }catch{showStatus('Upload failed','error')}
      input.value='';
    }
    function updateSourceUI(){
      const isLocal=settings.skipUpdates;
      document.getElementById('source-mode').value=isLocal?'local':'github';
      document.getElementById('github-settings').style.display=isLocal?'none':'flex';
      document.getElementById('github-update-row').style.display=isLocal?'none':'flex';
      document.getElementById('upload-row').style.display=isLocal?'flex':'none';
      const sizeKB=settings.currentFileSize?Math.round(settings.currentFileSize/1024):0;
      const edition=settings.currentFileEdition||'unknown';
      const source=isLocal?'Local upload':'GitHub';
      document.getElementById('current-file-info').textContent=sizeKB+'KB, '+edition+' edition ('+source+')';
    }
    async function saveRoomDefaults(){
      await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
        defaultDestructMode:document.getElementById('default-destruct-mode').value,
        defaultDestructHours:parseInt(document.getElementById('default-destruct-hours').value)||24,
        maxRoomsPerInstance:parseInt(document.getElementById('max-rooms').value)||0
      })});
      showStatus('Room defaults saved','success');
    }
    function showStatus(msg,type){
      const el=document.getElementById('settings-status');
      el.innerHTML='<div class="status-msg '+type+'">'+msg+'</div>';
      setTimeout(()=>el.innerHTML='',3000);
    }
    function renderStats(){const active=rooms.filter(r=>r.connectedUsers>0).length;const withPwd=rooms.filter(r=>r.hasPassword).length;document.getElementById('stats').innerHTML='<div class="stat-card"><div class="stat-value">'+rooms.length+'</div><div class="stat-label">Total Rooms</div></div><div class="stat-card"><div class="stat-value">'+active+'</div><div class="stat-label">Active</div></div><div class="stat-card"><div class="stat-value">'+withPwd+'</div><div class="stat-label">Protected</div></div><div class="stat-card"><div class="stat-value">'+rooms.reduce((a,r)=>a+r.connectedUsers,0)+'</div><div class="stat-label">Users Online</div></div>'}
    function renderRooms(){if(rooms.length===0){document.getElementById('room-list').innerHTML='<div class="empty-state"><h3>No rooms yet</h3><p>Rooms will appear here when created</p></div>';return}let html='<div class="room-header"><input type="checkbox" class="room-checkbox" onchange="toggleAll(this.checked)" '+(selected.size===rooms.length&&rooms.length>0?'checked':'')+'><span>Room</span><span>Users</span><span>Created</span><span>Password</span><span>Actions</span></div>';rooms.forEach(r=>{const created=new Date(r.created).toLocaleDateString();const users=r.connectedUsers>0?'<span class="badge badge-green">'+r.connectedUsers+'</span>':'<span class="badge badge-gray">0</span>';const pwd=r.hasPassword?'<span class="badge badge-yellow">Yes</span>':'<span class="badge badge-gray">No</span>';const isSelected=selected.has(r.id);html+='<div class="room-row'+(isSelected?' selected':'')+'"><input type="checkbox" class="room-checkbox" '+(isSelected?'checked':'')+' onchange="toggleSelect(\\''+r.id+'\\',this.checked)"><div><div class="room-name">Room</div><div class="room-id">'+r.id+'</div></div><div>'+users+'</div><div>'+created+'</div><div>'+pwd+'</div><div class="room-actions"><button class="btn btn-secondary btn-sm" onclick="viewRoom(\\''+r.id+'\\')">View</button><button class="btn btn-primary btn-sm" onclick="joinRoom(\\''+r.id+'\\')">Join</button><button class="btn btn-danger btn-sm" onclick="deleteRoom(\\''+r.id+'\\')">Del</button></div></div>'});document.getElementById('room-list').innerHTML=html}
    function toggleSelect(id,checked){if(checked)selected.add(id);else selected.delete(id);updateBulkUI();renderRooms()}
    function toggleAll(checked){if(checked)rooms.forEach(r=>selected.add(r.id));else selected.clear();updateBulkUI();renderRooms()}
    function clearSelection(){selected.clear();updateBulkUI();renderRooms()}
    function updateBulkUI(){const bulk=document.getElementById('bulk-actions');const count=document.getElementById('selected-count');if(selected.size>0){bulk.classList.add('active');count.textContent=selected.size+' selected'}else{bulk.classList.remove('active')}}
    async function deleteSelected(){if(selected.size===0)return;if(!confirm('Delete '+selected.size+' room(s) permanently?'))return;for(const id of selected){try{await fetch('/api/admin/rooms/'+id,{method:'DELETE'})}catch{}}selected.clear();loadData()}
    function viewRoom(id){const room=rooms.find(r=>r.id===id);if(!room)return;let destruct='Never';if(room.destruct.mode==='time'){const h=room.destruct.value/3600000;destruct=h<1?Math.round(h*60)+' min':h<24?h+' hours':Math.round(h/24)+' days'}else if(room.destruct.mode==='empty')destruct='When empty';document.getElementById('modal-title').textContent='Room Details';document.getElementById('modal-body').innerHTML='<div class="info-row"><span class="info-label">Room ID</span><span class="info-value" style="font-family:monospace;font-size:12px">'+room.id+'</span></div><div class="info-row"><span class="info-label">Created</span><span class="info-value">'+new Date(room.created).toLocaleString()+'</span></div><div class="info-row"><span class="info-label">Last Activity</span><span class="info-value">'+new Date(room.lastActivity).toLocaleString()+'</span></div><div class="info-row"><span class="info-label">Connected Users</span><span class="info-value">'+room.connectedUsers+'</span></div><div class="info-row"><span class="info-label">Password Protected</span><span class="info-value">'+(room.hasPassword?'Yes':'No')+'</span></div><div class="info-row"><span class="info-label">Self-Destruct</span><span class="info-value">'+destruct+'</span></div><div style="margin-top:20px;display:flex;gap:12px;flex-wrap:wrap"><button class="btn btn-primary" onclick="joinRoom(\\''+room.id+'\\');closeModal()">Join Room</button><button class="btn btn-danger" onclick="deleteRoom(\\''+room.id+'\\');closeModal()">Delete Room</button></div>';document.getElementById('room-modal').classList.add('active')}
    function closeModal(){document.getElementById('room-modal').classList.remove('active')}
    function joinRoom(id){window.open('/s/'+id,'_blank')}
    async function deleteRoom(id){if(!confirm('Delete this room permanently?'))return;try{const res=await fetch('/api/admin/rooms/'+id,{method:'DELETE'});if(res.ok){selected.delete(id);loadData()}else alert('Failed to delete room')}catch{alert('Error deleting room')}}
    async function logout(){await fetch('/api/logout',{method:'POST',credentials:'include'});window.location.href='/'}
    document.getElementById('room-modal').addEventListener('click',e=>{if(e.target.id==='room-modal')closeModal()});
    document.getElementById('apikey-modal').addEventListener('click',e=>{if(e.target.id==='apikey-modal')closeApiKeyModal()});
    async function saveWebhookUrl(){const url=document.getElementById('webhook-url').value;await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({webhookUrl:url})});showStatus('Webhook URL saved','success')}
    async function saveBackupSettings(){const interval=parseInt(document.getElementById('backup-interval').value)||24;const retention=parseInt(document.getElementById('backup-retention').value)||7;await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({backupIntervalHours:interval,backupRetentionCount:retention})});showStatus('Backup settings saved','success')}
    async function loadActivityLogs(){try{const room=document.getElementById('activity-search').value;const url=room?'/api/admin/activity-logs?room='+encodeURIComponent(room):'/api/admin/activity-logs';const res=await fetch(url);if(!res.ok)return;const data=await res.json();renderActivityLogs(data.logs)}catch{}}
    async function loadAuditLogs(){try{const q=document.getElementById('audit-search').value;const url=q?'/api/admin/audit-logs?q='+encodeURIComponent(q):'/api/admin/audit-logs';const res=await fetch(url);if(!res.ok)return;const data=await res.json();renderAuditLogs(data.logs)}catch{}}
    function renderActivityLogs(logs){const el=document.getElementById('activity-log-list');if(!logs||logs.length===0){el.innerHTML='<p style="color:var(--text-soft);padding:12px">No activity logs</p>';return}el.innerHTML=logs.map(l=>'<div style="padding:8px 0;border-bottom:1px solid var(--border);font-size:13px"><span style="color:var(--text-soft)">'+new Date(l.timestamp).toLocaleString()+'</span> <span class="badge badge-'+(l.eventType==='join'?'green':'gray')+'">'+l.eventType+'</span> '+(l.userName||'Unknown')+' <span style="color:var(--text-soft);font-size:11px">'+l.roomId.slice(0,8)+'</span></div>').join('')}
    function renderAuditLogs(logs){const el=document.getElementById('audit-log-list');if(!logs||logs.length===0){el.innerHTML='<p style="color:var(--text-soft);padding:12px">No audit logs</p>';return}el.innerHTML=logs.map(l=>'<div style="padding:8px 0;border-bottom:1px solid var(--border);font-size:13px"><span style="color:var(--text-soft)">'+new Date(l.timestamp).toLocaleString()+'</span> <span class="badge badge-yellow">'+l.action+'</span> '+(l.actor||'system')+(l.targetId?' <span style="color:var(--text-soft);font-size:11px">'+l.targetId.slice(0,8)+'</span>':'')+'</div>').join('')}
    async function loadBackups(){try{const res=await fetch('/api/admin/backups');if(!res.ok)return;const data=await res.json();renderBackups(data.backups)}catch{}}
    function renderBackups(backups){const el=document.getElementById('backup-list');if(!backups||backups.length===0){el.innerHTML='<p style="color:var(--text-soft);padding:12px">No backups</p>';return}el.innerHTML=backups.map(b=>'<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)"><div><div style="font-weight:500">'+b.filename+'</div><div style="font-size:12px;color:var(--text-soft)">'+new Date(b.createdAt).toLocaleString()+' | '+Math.round(b.sizeBytes/1024)+'KB | '+b.roomCount+' rooms'+(b.autoGenerated?' | Auto':'')+'</div></div><div style="display:flex;gap:6px"><button class="btn btn-sm btn-secondary" onclick="downloadBackup(\\''+b.id+'\\')">Download</button><button class="btn btn-sm btn-success" onclick="restoreBackup(\\''+b.id+'\\')">Restore</button><button class="btn btn-sm btn-danger" onclick="deleteBackup(\\''+b.id+'\\')">Delete</button></div></div>').join('')}
    async function createBackup(){try{const res=await fetch('/api/admin/backups',{method:'POST'});const data=await res.json();if(data.success){showStatus('Backup created','success');loadBackups()}else showStatus(data.error||'Failed','error')}catch{showStatus('Failed to create backup','error')}}
    async function downloadBackup(id){window.open('/api/admin/backups/'+id+'/download','_blank')}
    async function restoreBackup(id){if(!confirm('Restore this backup? This will add missing rooms.'))return;try{const res=await fetch('/api/admin/backups/'+id+'/restore',{method:'POST'});const data=await res.json();if(data.success){showStatus('Restored '+data.roomsRestored+' rooms','success');loadData()}else showStatus(data.error||'Failed','error')}catch{showStatus('Failed to restore','error')}}
    async function deleteBackup(id){if(!confirm('Delete this backup?'))return;try{await fetch('/api/admin/backups/'+id,{method:'DELETE'});loadBackups()}catch{}}
    async function exportAll(){window.open('/api/admin/export','_blank')}
    async function loadApiKeys(){try{const res=await fetch('/api/admin/api-keys');if(!res.ok)return;const data=await res.json();renderApiKeys(data.keys)}catch{}}
    function renderApiKeys(keys){const el=document.getElementById('apikey-list');if(!keys||keys.length===0){el.innerHTML='<p style="color:var(--text-soft);padding:12px">No API keys</p>';return}el.innerHTML=keys.map(k=>'<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)"><div><div style="font-weight:500">'+k.name+'</div><div style="font-size:12px;color:var(--text-soft)">'+k.permissions.join(', ')+' | Created: '+new Date(k.createdAt).toLocaleDateString()+(k.lastUsed?' | Last used: '+new Date(k.lastUsed).toLocaleDateString():'')+(k.expiresAt?' | Expires: '+new Date(k.expiresAt).toLocaleDateString():'')+'</div></div><button class="btn btn-sm btn-danger" onclick="revokeApiKey(\\''+k.id+'\\')">Revoke</button></div>').join('')}
    function showCreateApiKey(){document.getElementById('apikey-modal').classList.add('active');document.getElementById('new-key-display').style.display='none'}
    function closeApiKeyModal(){document.getElementById('apikey-modal').classList.remove('active')}
    async function createApiKey(){const name=document.getElementById('apikey-name').value;if(!name){alert('Name required');return}const perms=[];if(document.getElementById('perm-read').checked)perms.push('read');if(document.getElementById('perm-write').checked)perms.push('write');if(document.getElementById('perm-admin').checked)perms.push('admin');const expires=parseInt(document.getElementById('apikey-expires').value)||0;try{const res=await fetch('/api/admin/api-keys',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,permissions:perms,expiresInDays:expires||null})});const data=await res.json();if(data.key){closeApiKeyModal();document.getElementById('new-key-display').style.display='block';document.getElementById('new-key-value').textContent=data.key;loadApiKeys()}else alert(data.error||'Failed')}catch{alert('Failed to create key')}}
    async function revokeApiKey(id){if(!confirm('Revoke this API key?'))return;try{await fetch('/api/admin/api-keys/'+id,{method:'DELETE'});loadApiKeys()}catch{}}
    async function loadUsers(q=''){try{const url=q?'/api/admin/users?q='+encodeURIComponent(q):'/api/admin/users';const res=await fetch(url);if(!res.ok)return;const data=await res.json();users=data.users||[];renderUsers()}catch{}}
    function searchUsers(q){if(searchTimeout)clearTimeout(searchTimeout);searchTimeout=setTimeout(()=>loadUsers(q),300)}
    function renderUsers(){const el=document.getElementById('user-list');if(!users||users.length===0){el.innerHTML='<div class="empty-state"><h3>No users yet</h3><p>Users will appear here when registered</p></div>';return}
    let html='<div class="room-header"><span>User</span><span>Role</span><span>Status</span><span>Created</span><span>Actions</span></div>';
    users.forEach(u=>{const role=u.role==='admin'?'<span class="badge badge-yellow">Admin</span>':'<span class="badge badge-gray">User</span>';const status=u.isActive?'<span class="badge badge-green">Active</span>':'<span class="badge badge-gray">Inactive</span>';const verified=u.emailVerified?'':'<span class="badge badge-yellow">Unverified</span>';
    html+='<div class="room-row"><div><div class="room-name">'+(u.displayName||'No name')+'</div><div class="room-id">'+u.email+'</div></div><div>'+role+'</div><div>'+status+verified+'</div><div>'+new Date(u.createdAt).toLocaleDateString()+'</div><div class="room-actions"><button class="btn btn-secondary btn-sm" onclick="editUser(\\''+u.id+'\\')">Edit</button><button class="btn btn-danger btn-sm" onclick="deleteUser(\\''+u.id+'\\')">Del</button></div></div>'});
    el.innerHTML=html}
    function showCreateUser(){document.getElementById('user-modal').classList.add('active')}
    function closeUserModal(){document.getElementById('user-modal').classList.remove('active');document.getElementById('user-email').value='';document.getElementById('user-displayname').value='';document.getElementById('user-password').value='';document.getElementById('user-role').value='user'}
    async function createUser(){const email=document.getElementById('user-email').value;const displayName=document.getElementById('user-displayname').value;const password=document.getElementById('user-password').value||null;const role=document.getElementById('user-role').value;if(!email){alert('Email required');return}try{const res=await fetch('/api/admin/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,displayName,password,role})});const data=await res.json();if(data.success){closeUserModal();loadUsers();showAuthStatus('User created','success')}else{alert(data.error||'Failed')}}catch{alert('Failed to create user')}}
    async function deleteUser(id){if(!confirm('Delete this user permanently?'))return;try{await fetch('/api/admin/users/'+id,{method:'DELETE'});loadUsers()}catch{alert('Error deleting user')}}
    function editUser(id){const u=users.find(x=>x.id===id);if(!u)return;document.getElementById('edit-user-id').value=id;document.getElementById('edit-user-email').value=u.email;document.getElementById('edit-user-displayname').value=u.displayName||'';document.getElementById('edit-user-password').value='';document.getElementById('edit-user-role').value=u.role||'user';document.getElementById('edit-user-active').checked=u.isActive!==false;document.getElementById('edit-user-verified').checked=u.emailVerified===true;document.getElementById('edit-user-modal').classList.add('active')}
    function closeEditUserModal(){document.getElementById('edit-user-modal').classList.remove('active')}
    async function saveUserEdit(){const id=document.getElementById('edit-user-id').value;const data={displayName:document.getElementById('edit-user-displayname').value,role:document.getElementById('edit-user-role').value,isActive:document.getElementById('edit-user-active').checked,emailVerified:document.getElementById('edit-user-verified').checked};const password=document.getElementById('edit-user-password').value;if(password)data.password=password;try{const res=await fetch('/api/admin/users/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const result=await res.json();if(result.success){closeEditUserModal();loadUsers();showAuthStatus('User updated','success')}else{alert(result.error||'Failed to update user')}}catch{alert('Failed to update user')}}
    async function resetUserPassword(){const id=document.getElementById('edit-user-id').value;const email=document.getElementById('edit-user-email').value;if(!confirm('Send password reset email to '+email+'?'))return;try{const res=await fetch('/api/admin/users/'+id+'/reset-password',{method:'POST'});const result=await res.json();if(result.success){alert('Password reset email sent!')}else{alert(result.error||'Failed to send reset email')}}catch{alert('Failed to send reset email')}}
    document.getElementById('user-modal').addEventListener('click',e=>{if(e.target.id==='user-modal')closeUserModal()});
    document.getElementById('edit-user-modal').addEventListener('click',e=>{if(e.target.id==='edit-user-modal')closeEditUserModal()});
    async function loadAuthSettings(){try{const res=await fetch('/api/admin/auth-settings');if(!res.ok)return;authSettings=await res.json();renderAuthSettings()}catch{}}
    function renderAuthSettings(){document.getElementById('auth-mode').value=authSettings.authMode||'open';document.getElementById('toggle-require-email-verify').classList.toggle('active',authSettings.requireEmailVerification);document.getElementById('toggle-magic-link').classList.toggle('active',authSettings.allowMagicLinkLogin);document.getElementById('toggle-oidc-email-match').classList.toggle('active',authSettings.oidcEmailMatching);document.getElementById('toggle-production-mode').classList.toggle('active',authSettings.productionMode);document.getElementById('toggle-guest-room-create').classList.toggle('active',authSettings.allowGuestRoomCreation!==false);document.getElementById('toggle-guest-room-join').classList.toggle('active',authSettings.allowGuestRoomJoin!==false);document.getElementById('toggle-room-creator-guest').classList.toggle('active',authSettings.allowRoomCreatorGuestSetting!==false);document.getElementById('toggle-share-button').classList.toggle('active',authSettings.shareButtonEnabled!==false);document.getElementById('input-id-token-max-age').value=authSettings.idTokenMaxAgeHours||2;document.getElementById('input-email-rate-window').value=authSettings.emailRateLimitWindowSeconds||300;document.getElementById('input-email-rate-max').value=authSettings.emailRateLimitMaxAttempts||3}
    async function saveAuthSettings(){const mode=document.getElementById('auth-mode').value;await fetch('/api/admin/auth-settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({authMode:mode})});showAuthStatus('Auth mode saved','success')}
    async function toggleAuthSetting(key){authSettings[key]=!authSettings[key];renderAuthSettings();await fetch('/api/admin/auth-settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({[key]:authSettings[key]})});showAuthStatus('Setting updated','success')}
    async function updateAuthNumber(key,value){const num=parseInt(value);if(isNaN(num))return;authSettings[key]=num;await fetch('/api/admin/auth-settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({[key]:num})});showAuthStatus('Setting updated','success')}
    function showAuthStatus(msg,type){const el=document.getElementById('auth-status');el.innerHTML='<div class="status-msg '+type+'">'+msg+'</div>';setTimeout(()=>el.innerHTML='',3000)}
    async function loadOidcProviders(){try{const res=await fetch('/api/admin/oidc-providers');if(!res.ok)return;const data=await res.json();oidcProviders=data.providers||[];renderOidcProviders()}catch{}}
    function renderOidcProviders(){const el=document.getElementById('oidc-provider-list');if(!oidcProviders||oidcProviders.length===0){el.innerHTML='<p style="color:var(--text-soft);padding:12px">No OIDC providers configured</p>';return}
    el.innerHTML=oidcProviders.map(p=>'<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)"><div><div style="font-weight:500">'+p.name+'</div><div style="font-size:12px;color:var(--text-soft)">'+p.providerType+' | '+(p.isActive?'<span style="color:#22c55e">Active</span>':'<span style="color:#94a3b8">Inactive</span>')+'</div></div><div style="display:flex;gap:6px"><button class="btn btn-sm btn-secondary" onclick="editOidcProvider(\\''+p.id+'\\')">Edit</button><button class="btn btn-sm btn-danger" onclick="deleteOidcProvider(\\''+p.id+'\\')">Delete</button></div></div>').join('')}
    function showAddOidcProvider(){document.getElementById('oidc-modal-title').textContent='Add OIDC Provider';document.getElementById('oidc-edit-id').value='';document.getElementById('oidc-name').value='';document.getElementById('oidc-type').value='generic';document.getElementById('oidc-client-id').value='';document.getElementById('oidc-client-secret').value='';document.getElementById('oidc-issuer').value='';document.getElementById('oidc-auth-url').value='';document.getElementById('oidc-token-url').value='';document.getElementById('oidc-userinfo-url').value='';document.getElementById('oidc-scopes').value='openid email profile';document.getElementById('oidc-active').checked=true;document.getElementById('oidc-modal').classList.add('active')}
    function editOidcProvider(id){const p=oidcProviders.find(x=>x.id===id);if(!p)return;document.getElementById('oidc-modal-title').textContent='Edit OIDC Provider';document.getElementById('oidc-edit-id').value=id;document.getElementById('oidc-name').value=p.name;document.getElementById('oidc-type').value=p.providerType;document.getElementById('oidc-client-id').value=p.clientId;document.getElementById('oidc-client-secret').value='';document.getElementById('oidc-issuer').value=p.issuerUrl||'';document.getElementById('oidc-auth-url').value=p.authorizationUrl||'';document.getElementById('oidc-token-url').value=p.tokenUrl||'';document.getElementById('oidc-userinfo-url').value=p.userinfoUrl||'';document.getElementById('oidc-scopes').value=p.scopes||'openid email profile';document.getElementById('oidc-active').checked=p.isActive;document.getElementById('oidc-modal').classList.add('active')}
    function closeOidcModal(){document.getElementById('oidc-modal').classList.remove('active')}
    async function saveOidcProvider(){const id=document.getElementById('oidc-edit-id').value;const data={name:document.getElementById('oidc-name').value,providerType:document.getElementById('oidc-type').value,clientId:document.getElementById('oidc-client-id').value,clientSecret:document.getElementById('oidc-client-secret').value||undefined,issuerUrl:document.getElementById('oidc-issuer').value,authorizationUrl:document.getElementById('oidc-auth-url').value,tokenUrl:document.getElementById('oidc-token-url').value,userinfoUrl:document.getElementById('oidc-userinfo-url').value,scopes:document.getElementById('oidc-scopes').value,isActive:document.getElementById('oidc-active').checked};if(!data.name||!data.clientId){alert('Name and Client ID required');return}try{const url=id?'/api/admin/oidc-providers/'+id:'/api/admin/oidc-providers';const method=id?'PUT':'POST';const res=await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const result=await res.json();if(result.success){closeOidcModal();loadOidcProviders();showAuthStatus('Provider saved','success')}else{alert(result.error||'Failed')}}catch{alert('Failed to save provider')}}
    async function deleteOidcProvider(id){if(!confirm('Delete this OIDC provider?'))return;try{await fetch('/api/admin/oidc-providers/'+id,{method:'DELETE'});loadOidcProviders()}catch{}}
    document.getElementById('oidc-modal').addEventListener('click',e=>{if(e.target.id==='oidc-modal')closeOidcModal()});
    async function loadSmtpConfigs(){try{const res=await fetch('/api/admin/smtp-configs');if(!res.ok)return;const data=await res.json();smtpConfigs=data.configs||[];renderSmtpConfigs()}catch{}}
    function renderSmtpConfigs(){const el=document.getElementById('smtp-config-list');if(!smtpConfigs||smtpConfigs.length===0){el.innerHTML='<p style="color:var(--text-soft);padding:12px">No SMTP configurations</p>';return}
    el.innerHTML=smtpConfigs.map(s=>'<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)"><div><div style="font-weight:500">'+s.name+(s.isDefault?' <span class="badge badge-green">Default</span>':'')+'</div><div style="font-size:12px;color:var(--text-soft)">'+s.host+':'+s.port+' ('+s.secureMode+') | '+(s.isActive?'<span style="color:#22c55e">Active</span>':'<span style="color:#94a3b8">Inactive</span>')+'</div></div><div style="display:flex;gap:6px"><button class="btn btn-sm btn-secondary" onclick="editSmtpConfig(\\''+s.id+'\\')">Edit</button><button class="btn btn-sm btn-danger" onclick="deleteSmtpConfig(\\''+s.id+'\\')">Delete</button></div></div>').join('')}
    function showAddSmtpConfig(){document.getElementById('smtp-modal-title').textContent='Add SMTP Configuration';document.getElementById('smtp-edit-id').value='';document.getElementById('smtp-name').value='';document.getElementById('smtp-host').value='';document.getElementById('smtp-port').value='587';document.getElementById('smtp-secure-mode').value='starttls';document.getElementById('smtp-username').value='';document.getElementById('smtp-password').value='';document.getElementById('smtp-from-email').value='';document.getElementById('smtp-from-name').value='';document.getElementById('smtp-default').checked=false;document.getElementById('smtp-active').checked=true;document.getElementById('smtp-modal').classList.add('active')}
    function editSmtpConfig(id){const s=smtpConfigs.find(x=>x.id===id);if(!s)return;document.getElementById('smtp-modal-title').textContent='Edit SMTP Configuration';document.getElementById('smtp-edit-id').value=id;document.getElementById('smtp-name').value=s.name;document.getElementById('smtp-host').value=s.host||'';document.getElementById('smtp-port').value=s.port||587;document.getElementById('smtp-secure-mode').value=s.secureMode||'starttls';document.getElementById('smtp-username').value=s.username||'';document.getElementById('smtp-password').value='';document.getElementById('smtp-from-email').value=s.fromEmail||'';document.getElementById('smtp-from-name').value=s.fromName||'';document.getElementById('smtp-default').checked=s.isDefault;document.getElementById('smtp-active').checked=s.isActive;document.getElementById('smtp-modal').classList.add('active')}
    function closeSmtpModal(){document.getElementById('smtp-modal').classList.remove('active')}
    async function saveSmtpConfig(){const id=document.getElementById('smtp-edit-id').value;const data={name:document.getElementById('smtp-name').value,host:document.getElementById('smtp-host').value,port:parseInt(document.getElementById('smtp-port').value),secureMode:document.getElementById('smtp-secure-mode').value,username:document.getElementById('smtp-username').value,password:document.getElementById('smtp-password').value||undefined,fromEmail:document.getElementById('smtp-from-email').value,fromName:document.getElementById('smtp-from-name').value,isDefault:document.getElementById('smtp-default').checked,isActive:document.getElementById('smtp-active').checked};if(!data.name||!data.host){alert('Name and Host required');return}try{const url=id?'/api/admin/smtp-configs/'+id:'/api/admin/smtp-configs';const method=id?'PUT':'POST';const res=await fetch(url,{method,headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const result=await res.json();if(result.success){closeSmtpModal();loadSmtpConfigs();showAuthStatus('SMTP config saved','success')}else{alert(result.error||'Failed')}}catch{alert('Failed to save config')}}
    async function testSmtpConfig(){const data={name:document.getElementById('smtp-name').value,host:document.getElementById('smtp-host').value,port:parseInt(document.getElementById('smtp-port').value),secureMode:document.getElementById('smtp-secure-mode').value,username:document.getElementById('smtp-username').value,password:document.getElementById('smtp-password').value,fromEmail:document.getElementById('smtp-from-email').value,fromName:document.getElementById('smtp-from-name').value};try{const res=await fetch('/api/admin/smtp-configs/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const result=await res.json();if(result.success){alert('Test email sent successfully!')}else{alert('Test failed: '+(result.error||'Unknown error'))}}catch{alert('Test failed')}}
    async function deleteSmtpConfig(id){if(!confirm('Delete this SMTP configuration?'))return;try{await fetch('/api/admin/smtp-configs/'+id,{method:'DELETE'});loadSmtpConfigs()}catch{}}
    document.getElementById('smtp-modal').addEventListener('click',e=>{if(e.target.id==='smtp-modal')closeSmtpModal()});
    let emailTemplates=[],currentEditTemplate=null,isHtmlSourceView=false;
    async function loadEmailTemplates(){try{const res=await fetch('/api/admin/email-templates');if(!res.ok)return;const data=await res.json();emailTemplates=data.templates||[];renderEmailTemplates(emailTemplates)}catch{}}
    function renderEmailTemplates(templates){const el=document.getElementById('email-template-list');if(!templates||templates.length===0){el.innerHTML='<p style="color:var(--text-soft);padding:12px">No email templates. Default templates will be used.</p>';return}
    el.innerHTML=templates.map(t=>'<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)"><div><div style="font-weight:500">'+t.name+'</div><div style="font-size:12px;color:var(--text-soft)">Subject: '+t.subject+'</div></div><button class="btn btn-sm btn-secondary" onclick="editTemplate(\\''+t.id+'\\')">Edit</button></div>').join('')}
    function editTemplate(id){const t=emailTemplates.find(x=>x.id===id);if(!t)return;currentEditTemplate=t;document.getElementById('template-edit-id').value=id;document.getElementById('template-name').value=t.name;document.getElementById('template-subject').value=t.subject||'';document.getElementById('template-editor').innerHTML=t.bodyHtml||'';document.getElementById('template-html-source').value=t.bodyHtml||'';document.getElementById('template-text').value=t.bodyText||'';isHtmlSourceView=false;showWysiwygView();document.getElementById('template-modal').classList.add('active')}
    function closeTemplateModal(){document.getElementById('template-modal').classList.remove('active');currentEditTemplate=null}
    function showWysiwygView(){document.getElementById('template-editor').style.display='block';document.getElementById('template-editor-toolbar').style.display='flex';document.getElementById('template-html-source').style.display='none'}
    function showHtmlSourceView(){document.getElementById('template-html-source').value=document.getElementById('template-editor').innerHTML;document.getElementById('template-editor').style.display='none';document.getElementById('template-editor-toolbar').style.display='none';document.getElementById('template-html-source').style.display='block'}
    function toggleTemplateView(){if(isHtmlSourceView){document.getElementById('template-editor').innerHTML=document.getElementById('template-html-source').value;showWysiwygView()}else{showHtmlSourceView()}isHtmlSourceView=!isHtmlSourceView}
    function execCmd(cmd){document.execCommand(cmd,false,null);document.getElementById('template-editor').focus()}
    function execCmdArg(cmd,arg){if(!arg)return;document.execCommand(cmd,false,arg);document.getElementById('template-editor').focus()}
    function insertTemplateVar(varName){const editor=document.getElementById('template-editor');editor.focus();document.execCommand('insertText',false,'{{'+varName+'}}')}
    function insertLink(){const url=prompt('Enter URL:');if(url){document.execCommand('createLink',false,url)}}
    function insertImage(){const url=prompt('Enter image URL:');if(url){document.execCommand('insertImage',false,url)}}
    function insertButton(){const url=prompt('Enter button URL:');const text=prompt('Enter button text:','Click Here');if(url&&text){const btn='<a href="'+url+'" style="display:inline-block;padding:12px 24px;background:#c9a227;color:#fff;text-decoration:none;border-radius:6px;font-weight:600">'+text+'</a>';document.execCommand('insertHTML',false,btn)}}
    async function saveTemplate(){const id=document.getElementById('template-edit-id').value;if(!id){alert('No template selected');return}const html=isHtmlSourceView?document.getElementById('template-html-source').value:document.getElementById('template-editor').innerHTML;const data={subject:document.getElementById('template-subject').value,bodyHtml:html,bodyText:document.getElementById('template-text').value};try{const res=await fetch('/api/admin/email-templates/'+id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const result=await res.json();if(result.success){closeTemplateModal();loadEmailTemplates();showAuthStatus('Template saved','success')}else{alert(result.error||'Failed to save')}}catch{alert('Failed to save template')}}
    function previewTemplate(){const subject=document.getElementById('template-subject').value.replace(/\\{\\{displayName\\}\\}/g,'John Doe').replace(/\\{\\{actionUrl\\}\\}/g,'https://example.com/action').replace(/\\{\\{appName\\}\\}/g,'TheOneFile_Verse');const html=(isHtmlSourceView?document.getElementById('template-html-source').value:document.getElementById('template-editor').innerHTML).replace(/\\{\\{displayName\\}\\}/g,'John Doe').replace(/\\{\\{actionUrl\\}\\}/g,'https://example.com/action').replace(/\\{\\{appName\\}\\}/g,'TheOneFile_Verse');document.getElementById('preview-subject').textContent=subject;const frame=document.getElementById('preview-frame');frame.srcdoc='<!DOCTYPE html><html><head><style>body{font-family:system-ui,sans-serif;padding:20px;line-height:1.6;color:#333}</style></head><body>'+html+'</body></html>';document.getElementById('template-preview-modal').classList.add('active')}
    function closeTemplatePreview(){document.getElementById('template-preview-modal').classList.remove('active')}
    document.getElementById('template-modal').addEventListener('click',e=>{if(e.target.id==='template-modal')closeTemplateModal()});
    document.getElementById('template-preview-modal').addEventListener('click',e=>{if(e.target.id==='template-preview-modal')closeTemplatePreview()});
    async function loadEmailLogs(){try{const email=document.getElementById('email-log-search').value;const url=email?'/api/admin/email-logs?email='+encodeURIComponent(email):'/api/admin/email-logs';const res=await fetch(url);if(!res.ok)return;const data=await res.json();emailLogs=data.logs||[];renderEmailLogs()}catch{}}
    function renderEmailLogs(){const el=document.getElementById('email-log-list');if(!emailLogs||emailLogs.length===0){el.innerHTML='<p style="color:var(--text-soft);padding:12px">No email logs</p>';return}
    el.innerHTML=emailLogs.map(l=>'<div style="padding:8px 0;border-bottom:1px solid var(--border);font-size:13px"><span style="color:var(--text-soft)">'+new Date(l.sentAt).toLocaleString()+'</span> <span class="badge badge-'+(l.status==='sent'?'green':'gray')+'">'+l.status+'</span> '+l.toEmail+' <span style="color:var(--text-soft)">'+l.subject+'</span>'+(l.errorMessage?' <span style="color:#ef4444">'+l.errorMessage+'</span>':'')+'</div>').join('')}
    async function clearEmailLogs(){if(!confirm('Clear all email logs? This cannot be undone.'))return;try{const res=await fetch('/api/admin/email-logs',{method:'DELETE'});if(res.ok){loadEmailLogs();showAuthStatus('Email logs cleared','success')}}catch{}}
    async function clearActivityLogs(){if(!confirm('Clear all activity logs? This cannot be undone.'))return;try{const res=await fetch('/api/admin/activity-logs',{method:'DELETE'});if(res.ok){loadActivityLogs();showAuthStatus('Activity logs cleared','success')}}catch{}}
    async function clearAuditLogs(){if(!confirm('Clear all audit logs? This cannot be undone.'))return;try{const res=await fetch('/api/admin/audit-logs',{method:'DELETE'});if(res.ok){loadAuditLogs();showAuthStatus('Audit logs cleared','success')}}catch{}}
    loadData();setInterval(loadData,10000);
  </script>
</body>
</html>`;

const adminLoginHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    label{display:block;font-size:14px;color:var(--text-soft);margin-bottom:6px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    .back-link{text-align:center;margin-top:20px}
    .back-link a{color:var(--accent);text-decoration:none;font-size:14px}
    .oidc-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:var(--bg);border:1px solid var(--border);margin-bottom:12px}
    .oidc-btn:hover{background:var(--bg-alt)}
    .divider{display:flex;align-items:center;gap:12px;margin:24px 0;color:var(--text-soft);font-size:12px}
    .divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}
  </style>
</head>
<body>
  <div class="login-box">
    <h1>Admin Login</h1>
    <p>Sign in with your admin account</p>
    <div class="error" id="error"></div>
    <div id="oidc-buttons"></div>
    <div class="divider" id="divider" style="display:none">or continue with email</div>
    <form id="login-form">
      <label for="email">Email</label>
      <input type="email" id="email" placeholder="admin@example.com" autocomplete="email" autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" placeholder="Your password" autocomplete="current-password">
      <button type="submit">Login</button>
    </form>
    <div class="back-link"><a href="/">Back to App</a></div>
  </div>
  <script>
    (function(){let f=null;function g(){if(f&&f!=='user')return f;return localStorage.getItem('theme')||'dark'}function s(t){document.documentElement.setAttribute('data-theme',t)}s(g());fetch('/api/theme').then(r=>r.json()).then(d=>{if(d.forcedTheme&&d.forcedTheme!=='user'){f=d.forcedTheme;s(f)}}).catch(()=>{})})();
    fetch('/api/auth/providers').then(r=>r.json()).then(providers=>{
      if(providers.length>0){
        document.getElementById('divider').style.display='flex';
        const container=document.getElementById('oidc-buttons');
        providers.forEach(p=>{
          const btn=document.createElement('button');
          btn.type='button';
          btn.className='oidc-btn';
          btn.innerHTML=(p.iconUrl?'<img src="'+p.iconUrl+'" width="20" height="20">':'')+' Continue with '+p.name;
          btn.onclick=()=>window.location.href='/api/auth/oidc/'+p.id+'/login?redirect=/admin';
          container.appendChild(btn);
        });
      }
    }).catch(()=>{});
    document.getElementById('login-form').addEventListener('submit',async(e)=>{
      e.preventDefault();
      const error=document.getElementById('error');
      error.classList.remove('active');
      const email=document.getElementById('email').value;
      const password=document.getElementById('password').value;
      if(!email||!email.includes('@')){error.textContent='Please enter a valid email';error.classList.add('active');return}
      if(!password){error.textContent='Please enter your password';error.classList.add('active');return}
      try{
        const res=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});
        const d=await res.json();
        if(res.ok&&d.success){window.location.href='/admin'}
        else{error.textContent=d.error||'Invalid credentials';error.classList.add('active');document.getElementById('password').value=''}
      }catch{error.textContent='Connection error';error.classList.add('active')}
    });
  </script>
</body>
</html>`;

function getPasswordResetHtml(token: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Password - TheOneFile_Verse</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0d0d0d;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    .success{color:#22c55e;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .success.active{display:block}
  </style>
</head>
<body>
  <div class="box">
    <h1>Reset Password</h1>
    <p>Enter your new password</p>
    <div class="error" id="error"></div>
    <div class="success" id="success">Password reset successfully! <a href="/" style="color:var(--accent)">Go to home</a></div>
    <form id="form">
      <input type="password" id="password" placeholder="New password (min 8 characters)" minlength="8" required>
      <input type="password" id="confirm" placeholder="Confirm password" required>
      <button type="submit">Reset Password</button>
    </form>
  </div>
  <script>
    document.getElementById('form').addEventListener('submit',async(e)=>{
      e.preventDefault();
      const pw=document.getElementById('password').value;
      const confirm=document.getElementById('confirm').value;
      const err=document.getElementById('error');
      err.classList.remove('active');
      if(pw!==confirm){err.textContent='Passwords do not match';err.classList.add('active');return}
      if(pw.length<8){err.textContent='Password must be at least 8 characters';err.classList.add('active');return}
      try{
        const res=await fetch('/api/auth/reset-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:'${token}',password:pw})});
        const data=await res.json();
        if(data.success){document.getElementById('form').style.display='none';document.getElementById('success').classList.add('active')}
        else{err.textContent=data.error||'Failed to reset password';err.classList.add('active')}
      }catch{err.textContent='Connection error';err.classList.add('active')}
    });
  </script>
</body>
</html>`;
}

if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
if (!existsSync(ROOMS_DIR)) mkdirSync(ROOMS_DIR, { recursive: true });

interface Room {
  id: string;
  created: string;
  lastActivity: string;
  creatorId: string;
  passwordHash: string | null;
  destruct: { mode: "time" | "empty" | "never"; value: number };
  topology: any;
  ownerUserId: string | null;
  allowGuests: boolean;
}

interface RoomMeta {
  connectedUsers: number;
  destructTimer?: Timer;
}

const roomMeta: Map<string, RoomMeta> = new Map();
const roomConnections: Map<string, Set<any>> = new Map();
const roomUsers: Map<string, Map<string, any>> = new Map();
const roomUsedNames: Map<string, Map<string, string>> = new Map();

async function hashPassword(password: string): Promise<string> {
  return await Bun.password.hash(password, {
    algorithm: "argon2id",
    memoryCost: 65536,
    timeCost: 2
  });
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  if (hash.startsWith('$argon2')) {
    return await Bun.password.verify(password, hash);
  }
  const encoder = new TextEncoder();
  const data = encoder.encode(password + "theonefile-collab-salt-v1");
  const legacyHash = await crypto.subtle.digest("SHA-256", data);
  return Buffer.from(legacyHash).toString("hex") === hash;
}

function loadRoom(id: string): Room | null {
  if (!isValidUUID(id)) return null;
  return db.getRoom(id);
}

function saveRoom(room: Room): void {
  if (!isValidUUID(room.id)) return;
  const existing = db.getRoom(room.id);
  if (existing) {
    db.updateRoom(room.id, room.lastActivity, room.topology);
  } else {
    db.createRoom(room);
  }
  if (redis.isRedisConnected() && room.topology) {
    redis.setRoomStateCache(room.id, room.topology, 3600);
  }
}

function deleteRoomData(id: string): boolean {
  const result = db.deleteRoom(id);
  if (result) {
    roomMeta.delete(id);
    roomUsedNames.delete(id);
    if (redis.isRedisConnected()) {
      redis.deleteRoomStateCache(id);
    }
  }
  return result;
}

function scheduleDestruction(roomId: string, delayMs: number): void {
  const meta = roomMeta.get(roomId) || { connectedUsers: 0 };
  if (meta.destructTimer) clearTimeout(meta.destructTimer);
  meta.destructTimer = setTimeout(() => {
    const room = loadRoom(roomId);
    if (room && room.destruct.mode === "time") {
      console.log(`[Room] ${roomId} self-destructed`);
      deleteRoomData(roomId);
    }
  }, delayMs);
  roomMeta.set(roomId, meta);
}

function resetDestructionTimer(roomId: string): void {
  const room = loadRoom(roomId);
  if (room && room.destruct.mode === "time") {
    scheduleDestruction(roomId, room.destruct.value);
  }
}

let theOneFileHtml = "";
const theOneFilePath = join(process.cwd(), "public", "theonefile.html");
const GITHUB_RAW_URL = "https://raw.githubusercontent.com/gelatinescreams/The-One-File/main/theonefile-networkening.html";

interface ValidationResult {
  valid: boolean;
  error?: string;
  edition?: string;
}

interface TopologyValidationResult {
  valid: boolean;
  error?: string;
  sanitized?: any;
}

const TOPOLOGY_LIMITS = {
  maxSizeBytes: 5 * 1024 * 1024,
  maxDepth: 20,
  maxArrayLength: 10000,
  maxObjectKeys: 10000,
  maxStringLength: 1 * 1024 * 1024
};

function checkJsonDepthAndSize(obj: any, currentDepth: number = 0): { valid: boolean; error?: string } {
  if (currentDepth > TOPOLOGY_LIMITS.maxDepth) {
    return { valid: false, error: `Topology exceeds maximum nesting depth of ${TOPOLOGY_LIMITS.maxDepth}` };
  }

  if (obj === null || obj === undefined) {
    return { valid: true };
  }

  if (typeof obj === 'string') {
    if (obj.length > TOPOLOGY_LIMITS.maxStringLength) {
      return { valid: false, error: `String value exceeds maximum length of ${TOPOLOGY_LIMITS.maxStringLength / 1024}KB` };
    }
    return { valid: true };
  }

  if (Array.isArray(obj)) {
    if (obj.length > TOPOLOGY_LIMITS.maxArrayLength) {
      return { valid: false, error: `Array exceeds maximum length of ${TOPOLOGY_LIMITS.maxArrayLength}` };
    }
    for (const item of obj) {
      const result = checkJsonDepthAndSize(item, currentDepth + 1);
      if (!result.valid) return result;
    }
    return { valid: true };
  }

  if (typeof obj === 'object') {
    const keys = Object.keys(obj);
    if (keys.length > TOPOLOGY_LIMITS.maxObjectKeys) {
      return { valid: false, error: `Object exceeds maximum keys of ${TOPOLOGY_LIMITS.maxObjectKeys}` };
    }
    for (const key of keys) {
      const result = checkJsonDepthAndSize(obj[key], currentDepth + 1);
      if (!result.valid) return result;
    }
    return { valid: true };
  }

  return { valid: true };
}

function validateTopology(topology: any): TopologyValidationResult {
  if (topology === null || topology === undefined) {
    return { valid: true, sanitized: null };
  }

  let jsonStr: string;
  try {
    jsonStr = JSON.stringify(topology);
  } catch {
    return { valid: false, error: "Topology is not valid JSON" };
  }

  if (jsonStr.length > TOPOLOGY_LIMITS.maxSizeBytes) {
    return { valid: false, error: `Topology exceeds maximum size of ${TOPOLOGY_LIMITS.maxSizeBytes / (1024 * 1024)}MB` };
  }

  const depthCheck = checkJsonDepthAndSize(topology);
  if (!depthCheck.valid) {
    return { valid: false, error: depthCheck.error };
  }

  if (typeof topology !== 'object' || Array.isArray(topology)) {
    return { valid: false, error: "Topology must be an object" };
  }

  const typeChecks: Array<{ key: string; expectedType: string; isArray?: boolean }> = [
    { key: 'nodeData', expectedType: 'object' },
    { key: 'edgeData', expectedType: 'object' },
    { key: 'nodePositions', expectedType: 'object' },
    { key: 'nodeSizes', expectedType: 'object' },
    { key: 'nodeStyles', expectedType: 'object' },
    { key: 'rectData', expectedType: 'object' },
    { key: 'textData', expectedType: 'object' },
    { key: 'imageData', expectedType: 'object' },
    { key: 'documentTabs', expectedType: 'object', isArray: true },
    { key: 'edgeLegend', expectedType: 'object' },
    { key: 'zoneLegend', expectedType: 'object' },
    { key: 'currentTabIndex', expectedType: 'number' },
  ];

  for (const check of typeChecks) {
    if (topology[check.key] !== undefined && topology[check.key] !== null) {
      const actualType = typeof topology[check.key];
      const isArray = Array.isArray(topology[check.key]);

      if (check.isArray) {
        if (!isArray) {
          return { valid: false, error: `Topology field '${check.key}' must be an array` };
        }
      } else if (check.expectedType === 'object') {
        if (actualType !== 'object' || isArray) {
          return { valid: false, error: `Topology field '${check.key}' must be an object` };
        }
      } else if (actualType !== check.expectedType) {
        return { valid: false, error: `Topology field '${check.key}' must be a ${check.expectedType}` };
      }
    }
  }

  return { valid: true, sanitized: topology };
}

function validateTheOneFileHtml(html: string): ValidationResult {
  if (!html || html.length < 1000) {
    return { valid: false, error: "File too small to be valid" };
  }
  if (!html.trim().startsWith("<!DOCTYPE html>") && !html.trim().startsWith("<html")) {
    return { valid: false, error: "Not a valid HTML file" };
  }
  const hasHeaderComment = html.includes("The One File") && html.includes("There can be only one");
  if (!hasHeaderComment) {
    return { valid: false, error: "Missing The One File header comment" };
  }
  const hasLangJson = html.includes('id="lang-json"');
  if (!hasLangJson) {
    return { valid: false, error: "Missing language system (lang json)" };
  }
  const hasTopologyState = html.includes('id="topology-state"');
  if (!hasTopologyState) {
    return { valid: false, error: "Missing topology state element" };
  }
  let edition = "core";
  if (html.includes("The Networkening") || html.includes("networkening")) {
    edition = "networkening";
  }
  const hasCoreVars = html.includes("NODE_DATA") && html.includes("EDGE_DATA") && html.includes("savedPositions");
  if (!hasCoreVars) {
    return { valid: false, error: "Missing core topology variables" };
  }
  return { valid: true, edition };
}

async function computeSha256Hash(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

function getExpectedTheOneFileHash(): string | null {
  return db.getSetting("theOneFileHash");
}

function setExpectedTheOneFileHash(hash: string): void {
  db.setSetting("theOneFileHash", hash);
}

async function fetchLatestFromGitHub(): Promise<boolean> {
  try {
    console.log("[Update] Fetching from GitHub...");
    const res = await fetch(GITHUB_RAW_URL);
    if (!res.ok) return false;
    const html = await res.text();

    const downloadedHash = await computeSha256Hash(html);
    const expectedHash = getExpectedTheOneFileHash();

    if (expectedHash) {
      if (downloadedHash !== expectedHash) {
        console.error(`[Update] INTEGRITY CHECK FAILED!`);
        console.error(`[Update] Expected: ${expectedHash}`);
        console.error(`[Update] Got:      ${downloadedHash}`);
        console.error(`[Update] File rejected - possible tampering or update. Admin must update the expected hash.`);
        return false;
      }
      console.log(`[Update] Integrity verified (SHA-256: ${downloadedHash.substring(0, 16)}...)`);
    } else {
      console.log(`[Update] No integrity hash set. Current file hash: ${downloadedHash}`);
      console.log(`[Update] Admin can set this hash in settings to enable integrity checking.`);
    }

    writeFileSync(theOneFilePath, html);
    theOneFileHtml = html;
    console.log(`[Update] Downloaded (${(html.length / 1024).toFixed(1)}KB)`);
    return true;
  } catch { return false; }
}

let updateTimer: Timer | null = null;

function restartUpdateTimer(): void {
  if (updateTimer) clearInterval(updateTimer);
  updateTimer = null;
  if (instanceSettings.updateIntervalHours > 0 && !instanceSettings.skipUpdates) {
    updateTimer = setInterval(() => { fetchLatestFromGitHub(); }, instanceSettings.updateIntervalHours * 60 * 60 * 1000);
    console.log(`[Update] Auto-update every ${instanceSettings.updateIntervalHours} hours`);
  }
}

if (instanceSettings.skipUpdates) {
  if (existsSync(theOneFilePath)) {
    theOneFileHtml = readFileSync(theOneFilePath, "utf-8");
    console.log("[Update] Using local file (updates disabled)");
  }
} else {
  await fetchLatestFromGitHub();
  if (!theOneFileHtml && existsSync(theOneFilePath)) {
    theOneFileHtml = readFileSync(theOneFilePath, "utf-8");
    console.log("[Update] Using cached file");
  }
}

restartUpdateTimer();

const server = Bun.serve({
  port: PORT,
  async fetch(req, server) {
    const url = new URL(req.url);
    const path = url.pathname;
    
    if (path.match(/^\/ws\/[\w-]+$/)) {
      const roomId = path.split("/")[2];
      if (!isValidUUID(roomId)) {
        return new Response("Invalid room ID", { status: 400 });
      }
      const room = loadRoom(roomId);
      if (!room) return new Response("Room not found", { status: 404 });

      if (ENV_ADMIN_PASSWORD || isInstanceLocked()) {
        const token = getTokenFromRequest(req);
        if (!token || !INSTANCE_TOKENS.has(token)) return new Response("Unauthorized", { status: 401 });
      }

      const wsToken = url.searchParams.get("token");
      let verifiedUserId: string | undefined;

      const authSettings = oidc.getAuthSettings();
      const requireWsToken = authSettings.productionMode || process.env.REQUIRE_WS_TOKEN === 'true';

      if (wsToken) {
        const tokenValidation = await validateWsSessionToken(wsToken, roomId);
        if (!tokenValidation.valid) {
          return new Response("Invalid or expired WebSocket token", { status: 401 });
        }
        verifiedUserId = tokenValidation.collabUserId;
      } else if (requireWsToken) {
        return new Response("WebSocket token required", { status: 401 });
      }

      const upgraded = server.upgrade(req, { data: { roomId, verifiedUserId } });
      if (upgraded) return undefined;
      return new Response("WebSocket upgrade failed", { status: 400 });
    }
    
    const requestOrigin = req.headers.get("origin") || new URL(req.url).origin;
    const configuredOrigins = process.env.CORS_ORIGIN?.split(",").map(o => o.trim()).filter(Boolean);

    let allowedOrigin: string;
    if (configuredOrigins && configuredOrigins.length > 0) {
      allowedOrigin = configuredOrigins.includes(requestOrigin) ? requestOrigin : configuredOrigins[0];
    } else {
      allowedOrigin = new URL(req.url).origin;
    }

    const corsHeaders = {
      "Access-Control-Allow-Origin": allowedOrigin,
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Credentials": "true",
      ...securityHeaders
    };
    
    if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

        if (!isAdminConfigured() && (path === "/" || path === "/index.html")) {
      return new Response(setupPageHtml, { headers: { "Content-Type": "text/html", ...securityHeaders } });
    }

    if (path === "/api/setup" && req.method === "POST") {
      if (hasAdminUser()) {
        return Response.json({ error: "Admin already configured" }, { status: 400, headers: corsHeaders });
      }
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "setup", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        if (!body.email || !body.email.includes('@')) {
          return Response.json({ error: "Valid email required" }, { status: 400, headers: corsHeaders });
        }
        if (!body.password || body.password.length < 8) {
          return Response.json({ error: "Password must be at least 8 characters" }, { status: 400, headers: corsHeaders });
        }
        const emailValidation = auth.validateEmail(body.email);
        if (!emailValidation.valid) {
          return Response.json({ error: emailValidation.error }, { status: 400, headers: corsHeaders });
        }
        const passwordValidation = auth.validatePassword(body.password);
        if (!passwordValidation.valid) {
          return Response.json({ error: passwordValidation.error }, { status: 400, headers: corsHeaders });
        }
        const baseUrl = new URL(req.url).origin;
        const result = await auth.registerUser(body.email, body.password, body.email.split('@')[0], baseUrl);
        if (!result.success) {
          return Response.json({ error: result.error || "Registration failed" }, { status: 400, headers: corsHeaders });
        }
        const clientIP = getClientIP(req);
        const loginResult = await auth.loginWithPassword(body.email, body.password, clientIP, req.headers.get("user-agent") || "");
        if (!loginResult.success || !loginResult.sessionToken) {
          return Response.json({ error: "Account created but login failed" }, { status: 400, headers: corsHeaders });
        }
        return Response.json({ success: true, sessionToken: loginResult.sessionToken }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    const adminPath = getAdminPath();

    if (path === `/${adminPath}`) {
      if (needsAdminMigration()) {
        const migrationWithPath = migrationPageHtml.replace(/\/admin/g, `/${adminPath}`);
        return new Response(migrationWithPath, { headers: { "Content-Type": "text/html", ...securityHeaders } });
      }
      if (!hasAdminUser()) {
        return Response.redirect(new URL("/", req.url).toString(), 302);
      }
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.redirect(new URL(`/${adminPath}/login`, req.url).toString(), 302);
      }
      const dashboardWithPath = adminDashboardHtml
        .replace(/\/admin\/login/g, `/${adminPath}/login`)
        .replace(/\/admin/g, `/${adminPath}`);
      return new Response(dashboardWithPath, { headers: { "Content-Type": "text/html", ...securityHeaders } });
    }

    if (path === `/${adminPath}/login`) {
      if (needsAdminMigration()) {
        return Response.redirect(new URL(`/${adminPath}`, req.url).toString(), 302);
      }
      if (!hasAdminUser()) {
        return Response.redirect(new URL("/", req.url).toString(), 302);
      }
      const loginWithPath = adminLoginHtml.replace(/\/admin/g, `/${adminPath}`);
      return new Response(loginWithPath, { headers: { "Content-Type": "text/html", ...securityHeaders } });
    }

    if (path === "/api/admin/login" && req.method === "POST") {
      if (!hasAdminUser()) {
        return Response.json({ error: "No admin user configured" }, { status: 400, headers: corsHeaders });
      }
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "admin-login", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        if (!body.email || !body.password) {
          return Response.json({ error: "Email and password required" }, { status: 400, headers: corsHeaders });
        }
        const result = await auth.loginWithPassword(body.email, body.password, clientIP, req.headers.get("user-agent") || "");
        if (!result.success || !result.sessionToken) {
          return Response.json({ error: result.error || "Invalid credentials" }, { status: 403, headers: corsHeaders });
        }
        const user = db.getUserByEmail(body.email);
        if (!user || user.role !== 'admin') {
          return Response.json({ error: "Not authorized as admin" }, { status: 403, headers: corsHeaders });
        }
        return new Response(JSON.stringify({ success: true }), {
          headers: { ...corsHeaders, "Content-Type": "application/json",
            "Set-Cookie": oidc.getSessionCookie("user_token", result.sessionToken) }
        });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/api/admin/migrate" && req.method === "POST") {
      if (!needsAdminMigration()) {
        return Response.json({ error: "Migration not needed" }, { status: 400, headers: corsHeaders });
      }
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "admin-migrate", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        if (!body.oldPassword || !body.email) {
          return Response.json({ error: "Current password and email required" }, { status: 400, headers: corsHeaders });
        }
        if (!(await verifyAdminPassword(body.oldPassword))) {
          return Response.json({ error: "Invalid current password" }, { status: 403, headers: corsHeaders });
        }
        const emailValidation = auth.validateEmail(body.email);
        if (!emailValidation.valid) {
          return Response.json({ error: emailValidation.error }, { status: 400, headers: corsHeaders });
        }
        const newPassword = body.newPassword || body.oldPassword;
        const passwordValidation = auth.validatePassword(newPassword);
        if (!passwordValidation.valid) {
          return Response.json({ error: passwordValidation.error }, { status: 400, headers: corsHeaders });
        }
        const baseUrl = new URL(req.url).origin;
        const result = await auth.registerUser(body.email, newPassword, body.email.split('@')[0], baseUrl);
        if (!result.success) {
          return Response.json({ error: result.error || "Migration failed" }, { status: 400, headers: corsHeaders });
        }
        db.deleteSetting('admin_password_hash');
        db.deleteSetting('admin_created_at');
        const loginResult = await auth.loginWithPassword(body.email, newPassword, clientIP, req.headers.get("user-agent") || "");
        if (!loginResult.success || !loginResult.sessionToken) {
          return Response.json({ error: "Migration succeeded but login failed" }, { status: 400, headers: corsHeaders });
        }
        return new Response(JSON.stringify({ success: true }), {
          headers: { ...corsHeaders, "Content-Type": "application/json",
            "Set-Cookie": oidc.getSessionCookie("user_token", loginResult.sessionToken) }
        });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/api/admin/rooms" && req.method === "GET") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const searchQuery = url.searchParams.get("q") || "";
      const limit = parseInt(url.searchParams.get("limit") || "100");
      const offset = parseInt(url.searchParams.get("offset") || "0");
      const dbRooms = searchQuery ? db.searchRooms(searchQuery, limit, offset) : db.listRooms();
      const rooms = dbRooms.map(room => {
        const meta = roomMeta.get(room.id);
        return {
          id: room.id,
          created: room.created,
          lastActivity: room.lastActivity,
          hasPassword: !!room.passwordHash,
          destruct: room.destruct,
          connectedUsers: meta?.connectedUsers || 0
        };
      });
      return Response.json({ rooms, total: db.countRooms() }, { headers: corsHeaders });
    }

    if (path.match(/^\/api\/admin\/rooms\/[\w-]+$/) && req.method === "DELETE") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const id = path.split("/")[4];
      if (!isValidUUID(id)) {
        return Response.json({ error: "Invalid room ID" }, { status: 400, headers: corsHeaders });
      }
      if (deleteRoomData(id)) {
        db.addAuditLog({ timestamp: new Date().toISOString(), action: "room_deleted", actor: adminUser.id, actorIp: getClientIP(req), targetType: "room", targetId: id });
        return Response.json({ deleted: true }, { headers: corsHeaders });
      }
      return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });
    }

    if (path === "/api/logout" && req.method === "POST") {
      const collabToken = getTokenFromRequest(req);
      if (collabToken) {
        ADMIN_TOKENS.delete(collabToken);
        INSTANCE_TOKENS.delete(collabToken);
        if (redis.isRedisConnected()) await redis.deleteSessionToken(collabToken);
      }

      const userToken = getUserTokenFromRequest(req);
      if (userToken) {
        await auth.logout(userToken);
        if (redis.isRedisConnected()) await redis.deleteSessionToken(userToken);
      }

      const clearCookies = [
        oidc.getClearCookie("collab_token"),
        oidc.getClearCookie("user_token")
      ].join(", ");

      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json", "Set-Cookie": clearCookies }
      });
    }


    if (path === "/api/auth/settings" && req.method === "GET") {
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "auth-settings", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      const authSettings = oidc.getAuthSettings();
      const providers = oidc.getActiveProviders();
      return Response.json({ settings: authSettings, providers }, { headers: corsHeaders });
    }

    if (path === "/api/auth/providers" && req.method === "GET") {
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "auth-providers", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      const providers = oidc.getActiveProviders();
      return Response.json(providers, { headers: corsHeaders });
    }

    if (path === "/api/auth/csrf" && req.method === "GET") {
      const csrfToken = oidc.generateCsrfToken();
      return new Response(JSON.stringify({ token: csrfToken }), {
        headers: { ...corsHeaders, "Content-Type": "application/json", "Set-Cookie": oidc.getCsrfCookie(csrfToken) }
      });
    }

    if (path === "/api/auth/register" && req.method === "POST") {
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "register", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        const csrfToken = body.csrfToken || req.headers.get("x-csrf-token");
        if (!oidc.validateCsrfToken(csrfToken)) {
          return Response.json({ error: "Invalid security token. Please refresh and try again." }, { status: 403, headers: corsHeaders });
        }
        if (body.email && !(await checkEmailRateLimit(body.email, "register", instanceSettings))) {
          return Response.json({ error: "Too many registration attempts for this email. Try again later." }, { status: 429, headers: corsHeaders });
        }
        const baseUrl = new URL(req.url).origin;
        const result = await auth.registerUser(body.email, body.password, body.displayName, baseUrl);
        if (!result.success) {
          return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
        }
        if (result.requiresVerification) {
          return Response.json({ success: true, requiresVerification: true }, { headers: corsHeaders });
        }
        const loginResult = await auth.loginWithPassword(body.email, body.password, clientIP, req.headers.get("user-agent") || "");
        if (loginResult.success) {
          return new Response(JSON.stringify({ success: true, userId: loginResult.userId }), {
            headers: { ...corsHeaders, "Content-Type": "application/json",
              "Set-Cookie": oidc.getSessionCookie("user_token", loginResult.sessionToken!) }
          });
        }
        return Response.json({ success: true, userId: result.userId }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/api/auth/login" && req.method === "POST") {
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "user-login", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        const csrfToken = body.csrfToken || req.headers.get("x-csrf-token");
        if (!oidc.validateCsrfToken(csrfToken)) {
          return Response.json({ error: "Invalid security token. Please refresh and try again." }, { status: 403, headers: corsHeaders });
        }
        const result = await auth.loginWithPassword(body.email, body.password, clientIP, req.headers.get("user-agent") || "");
        if (!result.success) {
          return Response.json({ error: result.error }, { status: 401, headers: corsHeaders });
        }
        return new Response(JSON.stringify({ success: true, userId: result.userId }), {
          headers: { ...corsHeaders, "Content-Type": "application/json",
            "Set-Cookie": oidc.getSessionCookie("user_token", result.sessionToken!) }
        });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/api/auth/me" && req.method === "GET") {
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "auth-me", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      const token = getUserTokenFromRequest(req);
      if (!token) {
        return Response.json({ user: null }, { headers: corsHeaders });
      }
      const user = await oidc.validateUserSessionToken(token);
      if (!user) {
        return Response.json({ user: null }, { headers: corsHeaders });
      }
      const { passwordHash, ...safeUser } = user;
      return Response.json({ user: safeUser }, { headers: corsHeaders });
    }

    if (path === "/api/auth/logout" && req.method === "POST") {
      const token = getUserTokenFromRequest(req);
      if (token) {
        await auth.logout(token);
        if (redis.isRedisConnected()) await redis.deleteSessionToken(token);
      }
      const clearCookies = [
        oidc.getClearCookie("collab_token"),
        oidc.getClearCookie("user_token")
      ].join(", ");
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json", "Set-Cookie": clearCookies }
      });
    }

    if (path.match(/^\/api\/auth\/oidc\/[\w-]+\/login$/) && req.method === "GET") {
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "oidc-init", instanceSettings))) {
        return Response.redirect(new URL("/?auth_error=rate_limited", req.url).toString(), 302);
      }
      const providerId = path.split("/")[4];
      const baseUrl = new URL(req.url).origin;
      const redirectParam = url.searchParams.get("redirect");
      const validatedRedirect = oidc.validateRedirectUrl(redirectParam, baseUrl);

      const result = await oidc.generateAuthorizationUrl(providerId, baseUrl);
      if (!result) {
        return Response.redirect(new URL("/?auth_error=provider_unavailable", req.url).toString(), 302);
      }
      return Response.redirect(result.url, 302);
    }

    if (path.match(/^\/api\/auth\/oidc\/[\w-]+$/) && req.method === "GET") {
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "oidc-init", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      const providerId = path.split("/")[4];
      const baseUrl = new URL(req.url).origin;
      let linkUserId: string | undefined = undefined;
      const linkParam = url.searchParams.get("link");
      if (linkParam) {
        const token = getUserTokenFromRequest(req);
        if (!token) {
          return Response.json({ error: "Authentication required for account linking" }, { status: 401, headers: corsHeaders });
        }
        const user = await oidc.validateUserSessionToken(token);
        if (!user) {
          return Response.json({ error: "Authentication required for account linking" }, { status: 401, headers: corsHeaders });
        }
        if (user.id !== linkParam) {
          return Response.json({ error: "Cannot link to another user's account" }, { status: 403, headers: corsHeaders });
        }
        linkUserId = linkParam;
      }
      const result = await oidc.generateAuthorizationUrl(providerId, baseUrl, linkUserId);
      if (!result) {
        return Response.json({ error: "Provider not available" }, { status: 400, headers: corsHeaders });
      }
      return Response.json({ url: result.url, state: result.state }, { headers: corsHeaders });
    }

    if (path.match(/^\/auth\/callback\/[\w-]+$/) && req.method === "GET") {
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "oidc-callback", instanceSettings))) {
        return Response.redirect(new URL("/?auth_error=rate_limited", req.url).toString(), 302);
      }
      const providerId = path.split("/")[3];
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const error = url.searchParams.get("error");

      if (error) {
        return Response.redirect(new URL(`/?auth_error=${encodeURIComponent(error)}`, req.url).toString(), 302);
      }

      if (!code || !state) {
        return Response.redirect(new URL("/?auth_error=missing_params", req.url).toString(), 302);
      }

      const result = await oidc.processOidcCallback(providerId, code, state, clientIP, req.headers.get("user-agent") || "");

      if (!result.success) {
        return Response.redirect(new URL(`/?auth_error=${encodeURIComponent(result.error || "unknown")}`, req.url).toString(), 302);
      }

      return new Response(null, {
        status: 302,
        headers: {
          "Location": result.isNewUser ? "/?welcome=true" : "/",
          "Set-Cookie": oidc.getSessionCookie("user_token", result.sessionToken!),
          "X-Content-Type-Options": "nosniff",
          "Cache-Control": "no-store"
        }
      });
    }

    if (path === "/auth/login" && req.method === "GET") {
      return new Response(userLoginHtml, { headers: { "Content-Type": "text/html", ...securityHeaders } });
    }

    if (path === "/auth/register" && req.method === "GET") {
      return new Response(userRegisterHtml, { headers: { "Content-Type": "text/html", ...securityHeaders } });
    }

    if (path === "/auth/forgot-password" && req.method === "GET") {
      return new Response(userForgotPasswordHtml, { headers: { "Content-Type": "text/html", ...securityHeaders } });
    }

    if (path === "/auth/verify" && req.method === "GET") {
      const token = url.searchParams.get("token");
      if (!token) {
        return Response.redirect(new URL("/?verify_error=missing_token", req.url).toString(), 302);
      }
      const result = await auth.verifyEmail(token);
      if (!result.success) {
        return Response.redirect(new URL(`/?verify_error=${encodeURIComponent(result.error || "unknown")}`, req.url).toString(), 302);
      }
      return Response.redirect(new URL("/?verified=true", req.url).toString(), 302);
    }

    if (path === "/api/auth/forgot-password" && req.method === "POST") {
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "forgot-password", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        if (body.email && !(await checkEmailRateLimit(body.email, "password-reset", instanceSettings))) {
          return Response.json({ success: true }, { headers: corsHeaders });
        }
        const baseUrl = new URL(req.url).origin;
        await auth.requestPasswordReset(body.email, baseUrl);
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/auth/reset-password" && req.method === "GET") {
      const token = url.searchParams.get("token");
      if (!token) {
        return Response.redirect(new URL("/?reset_error=missing_token", req.url).toString(), 302);
      }
      return new Response(getPasswordResetHtml(token), { headers: { "Content-Type": "text/html", ...securityHeaders } });
    }

    if (path === "/api/auth/reset-password" && req.method === "POST") {
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "reset-password", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        const result = await auth.resetPassword(body.token, body.password);
        if (!result.success) {
          return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
        }
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/api/auth/magic-link" && req.method === "POST") {
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "magic-link", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        if (body.email && !(await checkEmailRateLimit(body.email, "magic-link", instanceSettings))) {
          return Response.json({ success: true }, { headers: corsHeaders });
        }
        const baseUrl = new URL(req.url).origin;
        await auth.requestMagicLink(body.email, baseUrl);
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/auth/magic-link" && req.method === "GET") {
      const token = url.searchParams.get("token");
      if (!token) {
        return Response.redirect(new URL("/?magic_error=missing_token", req.url).toString(), 302);
      }
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "magic-link-verify", instanceSettings))) {
        return Response.redirect(new URL("/?magic_error=rate_limited", req.url).toString(), 302);
      }
      const result = await auth.loginWithMagicLink(token, clientIP, req.headers.get("user-agent") || "");
      if (!result.success) {
        return Response.redirect(new URL(`/?magic_error=${encodeURIComponent(result.error || "unknown")}`, req.url).toString(), 302);
      }
      return new Response(null, {
        status: 302,
        headers: {
          "Location": "/",
          "Set-Cookie": oidc.getSessionCookie("user_token", result.sessionToken!),
          "X-Content-Type-Options": "nosniff",
          "Cache-Control": "no-store"
        }
      });
    }

    if (path === "/api/auth/profile" && req.method === "PUT") {
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "profile-update", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      const token = getUserTokenFromRequest(req);
      if (!token) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const user = await oidc.validateUserSessionToken(token);
      if (!user) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        const result = auth.updateProfile(user.id, body);
        if (!result.success) {
          return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
        }
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/api/auth/change-password" && req.method === "POST") {
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "change-password", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      const token = getUserTokenFromRequest(req);
      if (!token) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const user = await oidc.validateUserSessionToken(token);
      if (!user) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        const result = await auth.changePassword(user.id, body.currentPassword, body.newPassword);
        if (!result.success) {
          return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
        }
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/api/auth/sessions" && req.method === "GET") {
      const token = getUserTokenFromRequest(req);
      if (!token) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const user = await oidc.validateUserSessionToken(token);
      if (!user) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const sessions = auth.getUserSessions(user.id);
      return Response.json({ sessions }, { headers: corsHeaders });
    }

    if (path === "/api/auth/sessions" && req.method === "DELETE") {
      const token = getUserTokenFromRequest(req);
      if (!token) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const user = await oidc.validateUserSessionToken(token);
      if (!user) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const count = auth.logoutAll(user.id);
      return Response.json({ success: true, loggedOut: count }, { headers: corsHeaders });
    }

    if (path === "/api/auth/oidc-links" && req.method === "GET") {
      const token = getUserTokenFromRequest(req);
      if (!token) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const user = await oidc.validateUserSessionToken(token);
      if (!user) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const links = auth.getUserOidcLinks(user.id).map(l => ({
        id: l.id,
        provider: l.provider,
        providerEmail: l.providerEmail,
        createdAt: l.createdAt
      }));
      return Response.json({ links }, { headers: corsHeaders });
    }

    if (path.match(/^\/api\/auth\/oidc-links\/[\w-]+$/) && req.method === "DELETE") {
      const linkId = path.split("/")[4];
      const token = getUserTokenFromRequest(req);
      if (!token) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const user = await oidc.validateUserSessionToken(token);
      if (!user) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const result = auth.unlinkOidcProvider(user.id, linkId);
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
      }
      return Response.json({ success: true }, { headers: corsHeaders });
    }


    if (path === "/api/admin/users" && req.method === "GET") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const searchQuery = url.searchParams.get("q") || "";
      const limit = parseInt(url.searchParams.get("limit") || "100");
      const offset = parseInt(url.searchParams.get("offset") || "0");
      const users = searchQuery ? db.searchUsers(searchQuery, limit, offset) : db.listUsers(limit, offset);
      const safeUsers = users.map(u => {
        const { passwordHash, ...safe } = u;
        return safe;
      });
      return Response.json({ users: safeUsers, total: db.countUsers() }, { headers: corsHeaders });
    }

    if (path === "/api/admin/users" && req.method === "POST") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        const result = await auth.adminCreateUser(body.email, body.password, body.displayName, body.role || 'user');
        if (!result.success) {
          return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
        }
        db.addAuditLog({ timestamp: new Date().toISOString(), action: "user_created", actor: adminUser.id, actorIp: getClientIP(req), targetType: "user", targetId: result.userId });
        return Response.json({ success: true, userId: result.userId }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path.match(/^\/api\/admin\/users\/[\w-]+$/) && req.method === "PUT") {
      const userId = path.split("/")[4];
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        const result = auth.adminUpdateUser(userId, body);
        if (!result.success) {
          return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
        }
        db.addAuditLog({ timestamp: new Date().toISOString(), action: "user_updated", actor: adminUser.id, actorIp: getClientIP(req), targetType: "user", targetId: userId, details: body });
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path.match(/^\/api\/admin\/users\/[\w-]+\/reset-password$/) && req.method === "POST") {
      const userId = path.split("/")[4];
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const user = db.getUserById(userId);
        if (!user) {
          return Response.json({ error: "User not found" }, { status: 404, headers: corsHeaders });
        }
        if (!user.email) {
          return Response.json({ error: "User has no email address" }, { status: 400, headers: corsHeaders });
        }
        const baseUrl = new URL(req.url).origin;
        await auth.requestPasswordReset(user.email, baseUrl);
        db.addAuditLog({ timestamp: new Date().toISOString(), action: "user_password_reset_sent", actor: adminUser.id, actorIp: getClientIP(req), targetType: "user", targetId: userId });
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Failed to send reset email" }, { status: 500, headers: corsHeaders }); }
    }

    if (path.match(/^\/api\/admin\/users\/[\w-]+\/set-password$/) && req.method === "POST") {
      const userId = path.split("/")[4];
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        if (!body.password || typeof body.password !== 'string') {
          return Response.json({ error: "Password is required" }, { status: 400, headers: corsHeaders });
        }
        const result = await auth.adminResetPassword(userId, body.password);
        if (!result.success) {
          return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
        }
        db.addAuditLog({ timestamp: new Date().toISOString(), action: "user_password_set", actor: adminUser.id, actorIp: getClientIP(req), targetType: "user", targetId: userId });
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path.match(/^\/api\/admin\/users\/[\w-]+$/) && req.method === "DELETE") {
      const userId = path.split("/")[4];
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const result = auth.adminDeleteUser(userId);
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
      }
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "user_deleted", actor: adminUser.id, actorIp: getClientIP(req), targetType: "user", targetId: userId });
      return Response.json({ success: true }, { headers: corsHeaders });
    }


    if (path === "/api/admin/auth-settings" && req.method === "GET") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      return Response.json(oidc.getAuthSettings(), { headers: corsHeaders });
    }

    if (path === "/api/admin/auth-settings" && req.method === "POST") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        oidc.saveAuthSettings(body);
        db.addAuditLog({ timestamp: new Date().toISOString(), action: "auth_settings_changed", actor: adminUser.id, actorIp: getClientIP(req), details: body });
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }


    if (path === "/api/admin/oidc-providers" && req.method === "GET") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const providers = db.listOidcProviders().map(p => ({
        id: p.id, name: p.name, providerType: p.providerType, clientId: p.clientId,
        issuerUrl: p.issuerUrl, authorizationUrl: p.authorizationUrl, tokenUrl: p.tokenUrl,
        userinfoUrl: p.userinfoUrl, scopes: p.scopes, isActive: p.isActive, displayOrder: p.displayOrder,
        iconUrl: p.iconUrl, createdAt: p.createdAt
      }));
      return Response.json({ providers }, { headers: corsHeaders });
    }

    if (path === "/api/admin/oidc-providers" && req.method === "POST") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        if (!body.name || !body.clientId || !body.clientSecret) {
          return Response.json({ error: "Name, client ID, and client secret are required" }, { status: 400, headers: corsHeaders });
        }
        const encryptedSecret = await oidc.encryptSecret(body.clientSecret);
        const now = new Date().toISOString();
        const provider: db.OidcProvider = {
          id: crypto.randomUUID(),
          name: body.name,
          providerType: body.providerType || 'generic',
          clientId: body.clientId,
          clientSecretEncrypted: encryptedSecret,
          issuerUrl: body.issuerUrl || null,
          authorizationUrl: body.authorizationUrl || null,
          tokenUrl: body.tokenUrl || null,
          userinfoUrl: body.userinfoUrl || null,
          jwksUri: body.jwksUri || null,
          scopes: body.scopes || 'openid email profile',
          isActive: body.isActive !== false,
          displayOrder: body.displayOrder || 0,
          iconUrl: body.iconUrl || null,
          createdAt: now,
          updatedAt: now
        };
        db.createOidcProvider(provider);
        db.addAuditLog({ timestamp: now, action: "oidc_provider_created", actor: adminUser.id, actorIp: getClientIP(req), targetType: "oidc_provider", targetId: provider.id, details: { name: provider.name } });
        return Response.json({ success: true, id: provider.id }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path.match(/^\/api\/admin\/oidc-providers\/[\w-]+$/) && req.method === "PUT") {
      const providerId = path.split("/")[4];
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        const existing = db.getOidcProvider(providerId);
        if (!existing) {
          return Response.json({ error: "Provider not found" }, { status: 404, headers: corsHeaders });
        }
        const now = new Date().toISOString();
        const updated: db.OidcProvider = {
          ...existing,
          name: body.name ?? existing.name,
          providerType: body.providerType ?? existing.providerType,
          clientId: body.clientId ?? existing.clientId,
          clientSecretEncrypted: body.clientSecret ? await oidc.encryptSecret(body.clientSecret) : existing.clientSecretEncrypted,
          issuerUrl: body.issuerUrl !== undefined ? body.issuerUrl : existing.issuerUrl,
          authorizationUrl: body.authorizationUrl !== undefined ? body.authorizationUrl : existing.authorizationUrl,
          tokenUrl: body.tokenUrl !== undefined ? body.tokenUrl : existing.tokenUrl,
          userinfoUrl: body.userinfoUrl !== undefined ? body.userinfoUrl : existing.userinfoUrl,
          jwksUri: body.jwksUri !== undefined ? body.jwksUri : existing.jwksUri,
          scopes: body.scopes ?? existing.scopes,
          isActive: body.isActive ?? existing.isActive,
          displayOrder: body.displayOrder ?? existing.displayOrder,
          iconUrl: body.iconUrl !== undefined ? body.iconUrl : existing.iconUrl,
          updatedAt: now
        };
        db.updateOidcProvider(updated);
        db.addAuditLog({ timestamp: now, action: "oidc_provider_updated", actor: adminUser.id, actorIp: getClientIP(req), targetType: "oidc_provider", targetId: providerId });
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path.match(/^\/api\/admin\/oidc-providers\/[\w-]+$/) && req.method === "DELETE") {
      const providerId = path.split("/")[4];
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      if (db.deleteOidcProvider(providerId)) {
        db.addAuditLog({ timestamp: new Date().toISOString(), action: "oidc_provider_deleted", actor: adminUser.id, actorIp: getClientIP(req), targetType: "oidc_provider", targetId: providerId });
        return Response.json({ success: true }, { headers: corsHeaders });
      }
      return Response.json({ error: "Provider not found" }, { status: 404, headers: corsHeaders });
    }


    if (path === "/api/admin/smtp-configs" && req.method === "GET") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const configs = db.listSmtpConfigs().map(c => ({
        id: c.id, name: c.name, providerType: c.providerType, host: c.host, port: c.port,
        secureMode: c.secureMode, username: c.username, fromEmail: c.fromEmail, fromName: c.fromName,
        isDefault: c.isDefault, isActive: c.isActive, createdAt: c.createdAt
      }));
      return Response.json({ configs }, { headers: corsHeaders });
    }

    if (path === "/api/admin/smtp-configs" && req.method === "POST") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        if (!body.name || !body.fromEmail) {
          return Response.json({ error: "Name and from email are required" }, { status: 400, headers: corsHeaders });
        }
        const encryptedPassword = body.password ? await oidc.encryptSecret(body.password) : null;
        const now = new Date().toISOString();
        const config: db.SmtpConfig = {
          id: crypto.randomUUID(),
          name: body.name,
          providerType: body.providerType || 'smtp',
          host: body.host || null,
          port: body.port || null,
          secureMode: body.secureMode || 'tls',
          username: body.username || null,
          passwordEncrypted: encryptedPassword,
          apiKeyEncrypted: null,
          fromEmail: body.fromEmail,
          fromName: body.fromName || null,
          isDefault: body.isDefault || false,
          isActive: body.isActive !== false,
          createdAt: now,
          updatedAt: now
        };
        db.createSmtpConfig(config);
        db.addAuditLog({ timestamp: now, action: "smtp_config_created", actor: adminUser.id, actorIp: getClientIP(req), targetType: "smtp_config", targetId: config.id, details: { name: config.name } });
        return Response.json({ success: true, id: config.id }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path.match(/^\/api\/admin\/smtp-configs\/[\w-]+$/) && req.method === "PUT") {
      const configId = path.split("/")[4];
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        const existing = db.getSmtpConfig(configId);
        if (!existing) {
          return Response.json({ error: "Config not found" }, { status: 404, headers: corsHeaders });
        }
        const now = new Date().toISOString();
        const updated: db.SmtpConfig = {
          ...existing,
          name: body.name ?? existing.name,
          providerType: body.providerType ?? existing.providerType,
          host: body.host !== undefined ? body.host : existing.host,
          port: body.port !== undefined ? body.port : existing.port,
          secureMode: body.secureMode ?? existing.secureMode,
          username: body.username !== undefined ? body.username : existing.username,
          passwordEncrypted: body.password ? await oidc.encryptSecret(body.password) : existing.passwordEncrypted,
          fromEmail: body.fromEmail ?? existing.fromEmail,
          fromName: body.fromName !== undefined ? body.fromName : existing.fromName,
          isDefault: body.isDefault ?? existing.isDefault,
          isActive: body.isActive ?? existing.isActive,
          updatedAt: now
        };
        db.updateSmtpConfig(updated);
        db.addAuditLog({ timestamp: now, action: "smtp_config_updated", actor: adminUser.id, actorIp: getClientIP(req), targetType: "smtp_config", targetId: configId });
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/api/admin/smtp-configs/test" && req.method === "POST") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        const now = new Date().toISOString();
        let passwordEncrypted: string | null = null;
        if (body.password) {
          passwordEncrypted = await oidc.encryptSecret(body.password);
        }
        const testConfig: db.SmtpConfig = {
          id: "test-" + crypto.randomUUID(),
          name: body.name || "Test",
          providerType: "smtp",
          host: body.host,
          port: body.port || 587,
          secureMode: body.secureMode || "starttls",
          username: body.username || null,
          passwordEncrypted,
          apiKeyEncrypted: null,
          fromEmail: body.fromEmail,
          fromName: body.fromName || null,
          isDefault: false,
          isActive: true,
          createdAt: now,
          updatedAt: now
        };
        const result = await mailer.testSmtpConfig(testConfig);
        return Response.json(result, { headers: corsHeaders });
      } catch (e: any) {
        return Response.json({ success: false, error: e.message || "Test failed" }, { headers: corsHeaders });
      }
    }

    if (path.match(/^\/api\/admin\/smtp-configs\/[\w-]+\/test$/) && req.method === "POST") {
      const configId = path.split("/")[4];
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const config = db.getSmtpConfig(configId);
      if (!config) {
        return Response.json({ error: "Config not found" }, { status: 404, headers: corsHeaders });
      }
      const result = await mailer.testSmtpConfig(config);
      return Response.json(result, { headers: corsHeaders });
    }

    if (path.match(/^\/api\/admin\/smtp-configs\/[\w-]+$/) && req.method === "DELETE") {
      const configId = path.split("/")[4];
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      if (db.deleteSmtpConfig(configId)) {
        db.addAuditLog({ timestamp: new Date().toISOString(), action: "smtp_config_deleted", actor: adminUser.id, actorIp: getClientIP(req), targetType: "smtp_config", targetId: configId });
        return Response.json({ success: true }, { headers: corsHeaders });
      }
      return Response.json({ error: "Config not found" }, { status: 404, headers: corsHeaders });
    }

    if (path === "/api/admin/email-logs" && req.method === "GET") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const limit = parseInt(url.searchParams.get("limit") || "100");
      const offset = parseInt(url.searchParams.get("offset") || "0");
      const logs = db.listEmailLogs(limit, offset);
      const stats = mailer.getEmailStats();
      return Response.json({ logs, stats }, { headers: corsHeaders });
    }

    if (path === "/api/admin/email-logs" && req.method === "DELETE") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      db.clearEmailLogs();
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "email_logs_cleared", actor: adminUser.email || "admin", actorIp: getClientIP(req) });
      return Response.json({ success: true }, { headers: corsHeaders });
    }

    if (path === "/api/admin/email-templates" && req.method === "GET") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      return Response.json({ templates: db.listEmailTemplates() }, { headers: corsHeaders });
    }

    if (path.match(/^\/api\/admin\/email-templates\/[\w-]+$/) && req.method === "PUT") {
      const templateId = path.split("/")[4];
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        const existing = db.getEmailTemplate(templateId);
        if (!existing) {
          return Response.json({ error: "Template not found" }, { status: 404, headers: corsHeaders });
        }
        const updated: db.EmailTemplate = {
          ...existing,
          subject: body.subject ?? existing.subject,
          bodyHtml: body.bodyHtml ?? existing.bodyHtml,
          bodyText: body.bodyText ?? existing.bodyText,
          updatedAt: new Date().toISOString()
        };
        db.updateEmailTemplate(updated);
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if ((ENV_ADMIN_PASSWORD || isInstanceLocked()) && isAdminRoute(path)) {
      const token = getTokenFromRequest(req);
      const adminUser = await validateAdminUser(req);
      const hasInstanceAccess = (token && INSTANCE_TOKENS.has(token)) || adminUser;
      if (!hasInstanceAccess) {
        if (path === "/" || path === "/index.html" || path.startsWith("/s/")) {
          return new Response(instanceLoginPageHtml, { headers: { "Content-Type": "text/html", ...securityHeaders } });
        }
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
    }

    if (path === "/api/instance-login" && req.method === "POST") {
      if (!ENV_ADMIN_PASSWORD && !isInstanceLocked()) {
        return Response.json({ error: "Instance not locked" }, { status: 400, headers: corsHeaders });
      }
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "instance-login", instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        let valid = false;
        if (ENV_ADMIN_PASSWORD) {
          valid = body.password === ENV_ADMIN_PASSWORD;
        } else {
          valid = await verifyInstancePassword(body.password);
        }
        if (valid) {
          const token = crypto.randomUUID();
          INSTANCE_TOKENS.add(token);
          return new Response(JSON.stringify({ success: true }), {
            headers: { ...corsHeaders, "Content-Type": "application/json",
              "Set-Cookie": oidc.getSessionCookie("collab_token", token, 604800) }
          });
        }
        return Response.json({ error: "Invalid password" }, { status: 403, headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/api/admin/settings" && req.method === "GET") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const { instancePasswordHash, ...safeSettings } = instanceSettings;
      const fileValidation = validateTheOneFileHtml(theOneFileHtml);
      const currentFileHash = theOneFileHtml ? await computeSha256Hash(theOneFileHtml) : null;
      const expectedFileHash = getExpectedTheOneFileHash();
      return Response.json({
        ...safeSettings,
        instancePasswordSet: !!instancePasswordHash,
        envAdminPasswordSet: !!ENV_ADMIN_PASSWORD,
        currentFileSize: theOneFileHtml.length,
        currentFileEdition: fileValidation.valid ? fileValidation.edition : "invalid",
        currentFileHash,
        expectedFileHash,
        integrityCheckEnabled: !!expectedFileHash,
        integrityCheckPassed: expectedFileHash ? currentFileHash === expectedFileHash : null
      }, { headers: corsHeaders });
    }

    if (path === "/api/admin/settings" && req.method === "POST") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();

        if (typeof body.instancePasswordEnabled === "boolean") {
          instanceSettings.instancePasswordEnabled = body.instancePasswordEnabled;
        }
        if (body.instancePassword !== undefined) {
          if (body.instancePassword === "") {
            instanceSettings.instancePasswordHash = null;
          } else if (body.instancePassword.length >= 10) {
            instanceSettings.instancePasswordHash = await hashPassword(body.instancePassword);
          } else {
            return Response.json({ error: "Password must be at least 10 characters" }, { status: 400, headers: corsHeaders });
          }
        }
        if (typeof body.updateIntervalHours === "number") {
          instanceSettings.updateIntervalHours = Math.max(0, body.updateIntervalHours);
          restartUpdateTimer();
        }
        if (typeof body.skipUpdates === "boolean") {
          instanceSettings.skipUpdates = body.skipUpdates;
        }
        if (typeof body.allowPublicRoomCreation === "boolean") {
          instanceSettings.allowPublicRoomCreation = body.allowPublicRoomCreation;
        }
        if (typeof body.maxRoomsPerInstance === "number") {
          instanceSettings.maxRoomsPerInstance = Math.max(0, body.maxRoomsPerInstance);
        }
        if (body.defaultDestructMode && ["time", "empty", "never"].includes(body.defaultDestructMode)) {
          instanceSettings.defaultDestructMode = body.defaultDestructMode;
        }
        if (typeof body.defaultDestructHours === "number") {
          instanceSettings.defaultDestructHours = Math.max(1, body.defaultDestructHours);
        }
        if (body.forcedTheme && ["user", "dark", "light"].includes(body.forcedTheme)) {
          instanceSettings.forcedTheme = body.forcedTheme;
        }
        if (typeof body.rateLimitEnabled === "boolean") {
          instanceSettings.rateLimitEnabled = body.rateLimitEnabled;
        }
        if (typeof body.rateLimitWindow === "number") {
          instanceSettings.rateLimitWindow = Math.max(10, Math.min(3600, body.rateLimitWindow));
        }
        if (typeof body.rateLimitMaxAttempts === "number") {
          instanceSettings.rateLimitMaxAttempts = Math.max(1, Math.min(100, body.rateLimitMaxAttempts));
        }
        if (typeof body.chatEnabled === "boolean") {
          instanceSettings.chatEnabled = body.chatEnabled;
        }
        if (typeof body.cursorSharingEnabled === "boolean") {
          instanceSettings.cursorSharingEnabled = body.cursorSharingEnabled;
        }
        if (typeof body.nameChangeEnabled === "boolean") {
          instanceSettings.nameChangeEnabled = body.nameChangeEnabled;
        }
        if (typeof body.webhookEnabled === "boolean") {
          instanceSettings.webhookEnabled = body.webhookEnabled;
        }
        if (body.webhookUrl !== undefined) {
          instanceSettings.webhookUrl = body.webhookUrl || null;
        }
        if (typeof body.backupEnabled === "boolean") {
          instanceSettings.backupEnabled = body.backupEnabled;
          restartBackupTimer();
        }
        if (typeof body.backupIntervalHours === "number") {
          instanceSettings.backupIntervalHours = Math.max(1, Math.min(168, body.backupIntervalHours));
          restartBackupTimer();
        }
        if (typeof body.backupRetentionCount === "number") {
          instanceSettings.backupRetentionCount = Math.max(1, Math.min(100, body.backupRetentionCount));
        }
        if (body.adminPath !== undefined) {
          const validation = validateAdminPath(body.adminPath);
          if (!validation.valid) {
            return Response.json({ error: validation.error }, { status: 400, headers: corsHeaders });
          }
          instanceSettings.adminPath = body.adminPath;
        }

        if (body.theOneFileHash !== undefined) {
          if (body.theOneFileHash === "" || body.theOneFileHash === null) {
            db.deleteSetting("theOneFileHash");
            console.log("[Security] TheOneFile integrity checking disabled by admin");
          } else if (typeof body.theOneFileHash === "string" && /^[a-f0-9]{64}$/i.test(body.theOneFileHash)) {
            setExpectedTheOneFileHash(body.theOneFileHash.toLowerCase());
            console.log(`[Security] TheOneFile integrity hash set: ${body.theOneFileHash.substring(0, 16)}...`);
          } else if (body.theOneFileHash === "current") {
            if (theOneFileHtml) {
              const currentHash = await computeSha256Hash(theOneFileHtml);
              setExpectedTheOneFileHash(currentHash);
              console.log(`[Security] TheOneFile integrity hash set to current file: ${currentHash.substring(0, 16)}...`);
            }
          } else {
            return Response.json({ error: "Invalid hash format. Must be 64 hex characters, 'current', or empty to disable." }, { status: 400, headers: corsHeaders });
          }
        }

        saveSettings(instanceSettings);
        db.addAuditLog({ timestamp: new Date().toISOString(), action: "settings_changed", actor: adminUser.id, actorIp: getClientIP(req), details: body });
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/api/admin/update" && req.method === "POST") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      if (instanceSettings.skipUpdates) {
        return Response.json({ error: "Updates disabled" }, { status: 400, headers: corsHeaders });
      }
      const success = await fetchLatestFromGitHub();
      return Response.json({ success, size: theOneFileHtml.length }, { headers: corsHeaders });
    }

    if (path === "/api/admin/upload-html" && req.method === "POST") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const formData = await req.formData();
        const file = formData.get("file") as File | null;
        if (!file) {
          return Response.json({ error: "No file provided" }, { status: 400, headers: corsHeaders });
        }
        const html = await file.text();
        const validationResult = validateTheOneFileHtml(html);
        if (!validationResult.valid) {
          return Response.json({ error: validationResult.error }, { status: 400, headers: corsHeaders });
        }
        writeFileSync(theOneFilePath, html);
        theOneFileHtml = html;
        instanceSettings.skipUpdates = true;
        saveSettings(instanceSettings);
        if (updateTimer) { clearInterval(updateTimer); updateTimer = null; }
        console.log(`[Upload] Admin uploaded local file (${(html.length / 1024).toFixed(1)}KB) - ${validationResult.edition}`);
        return Response.json({ success: true, size: html.length, edition: validationResult.edition }, { headers: corsHeaders });
      } catch (e) {
        return Response.json({ error: "Failed to process upload" }, { status: 500, headers: corsHeaders });
      }
    }

    if (path === "/api/admin/source-mode" && req.method === "POST") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        if (body.mode === "github") {
          instanceSettings.skipUpdates = false;
          saveSettings(instanceSettings);
          await fetchLatestFromGitHub();
          restartUpdateTimer();
          return Response.json({ success: true, mode: "github", size: theOneFileHtml.length }, { headers: corsHeaders });
        } else if (body.mode === "local") {
          instanceSettings.skipUpdates = true;
          saveSettings(instanceSettings);
          if (updateTimer) { clearInterval(updateTimer); updateTimer = null; }
          return Response.json({ success: true, mode: "local" }, { headers: corsHeaders });
        }
        return Response.json({ error: "Invalid mode" }, { status: 400, headers: corsHeaders });
      } catch {
        return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders });
      }
    }

    if (path === "/api/admin/audit-logs" && req.method === "GET") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const query = url.searchParams.get("q") || "";
      const limit = parseInt(url.searchParams.get("limit") || "100");
      const offset = parseInt(url.searchParams.get("offset") || "0");
      const logs = query ? db.searchAuditLogs(query, limit, offset) : db.getAuditLogs(limit, offset);
      return Response.json({ logs }, { headers: corsHeaders });
    }

    if (path === "/api/admin/audit-logs" && req.method === "DELETE") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      db.clearAuditLogs();
      return Response.json({ success: true }, { headers: corsHeaders });
    }

    if (path === "/api/admin/activity-logs" && req.method === "GET") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const roomId = url.searchParams.get("room") || "";
      const limit = parseInt(url.searchParams.get("limit") || "100");
      const offset = parseInt(url.searchParams.get("offset") || "0");
      const logs = roomId ? db.getActivityLogs(roomId, limit, offset) : db.getAllActivityLogs(limit, offset);
      return Response.json({ logs }, { headers: corsHeaders });
    }

    if (path === "/api/admin/activity-logs" && req.method === "DELETE") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      db.clearActivityLogs();
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "activity_logs_cleared", actor: adminUser.email || "admin", actorIp: getClientIP(req) });
      return Response.json({ success: true }, { headers: corsHeaders });
    }

    if (path === "/api/admin/backups" && req.method === "GET") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const backups = db.listBackups();
      return Response.json({ backups }, { headers: corsHeaders });
    }

    if (path === "/api/admin/backups" && req.method === "POST") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const result = await createBackup(false);
      if (result) {
        db.addAuditLog({ timestamp: new Date().toISOString(), action: "backup_created", actor: adminUser.id, actorIp: getClientIP(req), targetType: "backup", targetId: result.id });
        return Response.json({ success: true, backup: result }, { headers: corsHeaders });
      }
      return Response.json({ error: "Failed to create backup" }, { status: 500, headers: corsHeaders });
    }

    if (path.match(/^\/api\/admin\/backups\/[\w-]+\/restore$/) && req.method === "POST") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const backupId = path.split("/")[4];
      const result = await restoreBackup(backupId);
      if (result.success) {
        db.addAuditLog({ timestamp: new Date().toISOString(), action: "backup_restored", actor: adminUser.id, actorIp: getClientIP(req), targetType: "backup", targetId: backupId, details: { roomsRestored: result.roomsRestored } });
      }
      return Response.json(result, { headers: corsHeaders });
    }

    if (path.match(/^\/api\/admin\/backups\/[\w-]+\/download$/) && req.method === "GET") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const backupId = path.split("/")[4];
      const backups = db.listBackups();
      const backup = backups.find(b => b.id === backupId);
      if (!backup) return Response.json({ error: "Backup not found" }, { status: 404, headers: corsHeaders });
      const backupPath = join(BACKUPS_DIR, backup.filename);
      if (!existsSync(backupPath)) return Response.json({ error: "Backup file missing" }, { status: 404, headers: corsHeaders });
      const content = readFileSync(backupPath, "utf-8");
      return new Response(content, { headers: { "Content-Type": "application/json", "Content-Disposition": `attachment; filename="${backup.filename}"`, ...securityHeaders } });
    }

    if (path.match(/^\/api\/admin\/backups\/[\w-]+$/) && req.method === "DELETE") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const backupId = path.split("/")[4];
      const backups = db.listBackups();
      const backup = backups.find(b => b.id === backupId);
      if (!backup) return Response.json({ error: "Backup not found" }, { status: 404, headers: corsHeaders });
      const backupPath = join(BACKUPS_DIR, backup.filename);
      if (existsSync(backupPath)) unlinkSync(backupPath);
      db.deleteBackupRecord(backupId);
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "backup_deleted", actor: adminUser.id, actorIp: getClientIP(req), targetType: "backup", targetId: backupId });
      return Response.json({ deleted: true }, { headers: corsHeaders });
    }

    if (path === "/api/admin/api-keys" && req.method === "GET") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const keys = db.listApiKeys();
      return Response.json({ keys }, { headers: corsHeaders });
    }

    if (path === "/api/admin/api-keys" && req.method === "POST") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        if (!body.name) return Response.json({ error: "Name required" }, { status: 400, headers: corsHeaders });
        const id = crypto.randomUUID();
        const rawKey = `tof_${crypto.randomUUID().replace(/-/g, "")}`;
        const keyHash = await hashApiKey(rawKey);
        const permissions = body.permissions || ["read"];
        const expiresAt = body.expiresInDays ? new Date(Date.now() + body.expiresInDays * 24 * 60 * 60 * 1000).toISOString() : null;
        db.createApiKey({ id, name: body.name, keyHash, permissions, createdAt: new Date().toISOString(), expiresAt, active: true });
        db.addAuditLog({ timestamp: new Date().toISOString(), action: "api_key_created", actor: adminUser.id, actorIp: getClientIP(req), targetType: "api_key", targetId: id, details: { name: body.name } });
        return Response.json({ id, key: rawKey, name: body.name, permissions, expiresAt }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path.match(/^\/api\/admin\/api-keys\/[\w-]+$/) && req.method === "DELETE") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const keyId = path.split("/")[4];
      if (db.deactivateApiKey(keyId)) {
        db.addAuditLog({ timestamp: new Date().toISOString(), action: "api_key_revoked", actor: adminUser.id, actorIp: getClientIP(req), targetType: "api_key", targetId: keyId });
        return Response.json({ revoked: true }, { headers: corsHeaders });
      }
      return Response.json({ error: "API key not found" }, { status: 404, headers: corsHeaders });
    }

    if (path === "/api/admin/export" && req.method === "GET") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const rooms = db.listRooms();
      const settings = db.getAllSettings();
      const exportData = { version: 1, exportedAt: new Date().toISOString(), rooms, settings };
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "data_exported", actor: adminUser.id, actorIp: getClientIP(req), details: { roomCount: rooms.length } });
      return new Response(JSON.stringify(exportData, null, 2), { headers: { "Content-Type": "application/json", "Content-Disposition": `attachment; filename="theonefile_export_${new Date().toISOString().slice(0, 10)}.json"`, ...securityHeaders } });
    }

    if (path === "/api/theme" && req.method === "GET") {
      const authSettings = oidc.getAuthSettings();
      return Response.json({
        forcedTheme: instanceSettings.forcedTheme,
        chatEnabled: instanceSettings.chatEnabled,
        cursorSharingEnabled: instanceSettings.cursorSharingEnabled,
        nameChangeEnabled: instanceSettings.nameChangeEnabled,
        shareButtonEnabled: authSettings.shareButtonEnabled
      }, { headers: corsHeaders });
    }

    if (path === "/api/room" && req.method === "POST") {
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "room-create", instanceSettings))) {
        return Response.json({ error: "Too many rooms created. Try again later." }, { status: 429, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        const creatorId = body.creatorId && isValidUUID(body.creatorId) ? body.creatorId : crypto.randomUUID();
        const validDestructModes = ["time", "empty", "never"];
        const destructMode = validDestructModes.includes(body.destructMode) ? body.destructMode : "time";
        const maxDestructValue = 30 * 24 * 60 * 60 * 1000;
        const destructValue = typeof body.destructValue === "number"
          ? Math.min(Math.max(0, body.destructValue), maxDestructValue)
          : 86400000;
        const passwordHash = body.password && body.password.length >= 4
          ? await hashPassword(body.password)
          : null;

        const id = crypto.randomUUID();

        const userToken = getUserTokenFromRequest(req);
        let ownerUserId: string | null = null;
        if (userToken) {
          const user = await oidc.validateUserSessionToken(userToken);
          if (user) ownerUserId = user.id;
        }

        const authSettings = oidc.getAuthSettings();
        if (!authSettings.allowGuestRoomCreation && !ownerUserId) {
          return Response.json({ error: "Please sign in to create a room" }, { status: 401, headers: corsHeaders });
        }

        const allowGuests = body.allowGuests !== false && authSettings.allowGuestRoomJoin;

        let validatedTopology = null;
        if (body.topology) {
          const topologyValidation = validateTopology(body.topology);
          if (!topologyValidation.valid) {
            return Response.json({ error: topologyValidation.error || "Invalid topology data" }, { status: 400, headers: corsHeaders });
          }
          validatedTopology = topologyValidation.sanitized;
        }

        const room: Room = {
          id,
          created: new Date().toISOString(),
          lastActivity: new Date().toISOString(),
          creatorId,
          passwordHash,
          destruct: { mode: destructMode, value: destructValue },
          topology: validatedTopology,
          ownerUserId,
          allowGuests
        };
        saveRoom(room);
        if (room.destruct.mode === "time") scheduleDestruction(id, room.destruct.value);
        sendWebhook("room_created", { roomId: id, hasPassword: !!room.passwordHash, destructMode, creatorId });
        return Response.json({ id, url: `/s/${id}`, hasPassword: !!room.passwordHash, allowGuests: room.allowGuests }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }
    
    if (path.match(/^\/api\/room\/[\w-]+\/verify$/) && req.method === "POST") {
      const id = path.split("/")[3];
      if (!isValidUUID(id)) {
        return Response.json({ error: "Invalid room ID" }, { status: 400, headers: corsHeaders });
      }
      const room = loadRoom(id);
      if (!room) return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });
      if (!room.passwordHash) return Response.json({ valid: true }, { headers: corsHeaders });
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, `room-verify-${id}`, instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        return Response.json({ valid: await verifyPassword(body.password || "", room.passwordHash) }, { headers: corsHeaders });
      } catch { return Response.json({ valid: false }, { headers: corsHeaders }); }
    }
    
    if (path.match(/^\/api\/room\/[\w-]+$/) && req.method === "DELETE") {
      const id = path.split("/")[3];
      if (!isValidUUID(id)) {
        return Response.json({ error: "Invalid room ID" }, { status: 400, headers: corsHeaders });
      }
      const room = loadRoom(id);
      if (!room) return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });
      try {
        const body = await req.json();
        if (body.creatorId && isValidUUID(body.creatorId) && body.creatorId === room.creatorId) {
          deleteRoomData(id);
          return Response.json({ deleted: true }, { headers: corsHeaders });
        }
        return Response.json({ error: "Only room creator can delete" }, { status: 403, headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }
    
    if (path.match(/^\/api\/room\/[\w-]+\/exists$/) && req.method === "GET") {
      const id = path.split("/")[3];
      if (!isValidUUID(id)) {
        return Response.json({ exists: false }, { headers: corsHeaders });
      }
      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, "room-exists", instanceSettings))) {
        return Response.json({ error: "Too many requests. Try again later." }, { status: 429, headers: corsHeaders });
      }
      const room = loadRoom(id);
      if (!room) return Response.json({ exists: false }, { headers: corsHeaders });
      return Response.json({
        exists: true, hasPassword: !!room.passwordHash, created: room.created, destruct: room.destruct
      }, { headers: corsHeaders });
    }

    if (path.match(/^\/api\/room\/[\w-]+\/ws-token$/) && req.method === "POST") {
      const id = path.split("/")[3];
      if (!isValidUUID(id)) {
        return Response.json({ error: "Invalid room ID" }, { status: 400, headers: corsHeaders });
      }
      const room = loadRoom(id);
      if (!room) return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });

      const clientIP = getClientIP(req);
      if (!(await checkRateLimit(clientIP, `ws-token-${id}`, instanceSettings))) {
        return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
      }

      try {
        const body = await req.json();
        const collabUserId = body.collabUserId && isValidUUID(body.collabUserId) ? body.collabUserId : crypto.randomUUID();

        const wsToken = await generateWsSessionToken(id, collabUserId);

        return Response.json({ wsToken, expiresIn: WS_TOKEN_EXPIRY / 1000 }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }
    
    if (path === "/api/refresh" && req.method === "POST") {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      if (instanceSettings.skipUpdates) return Response.json({ error: "Updates disabled" }, { status: 400, headers: corsHeaders });
      const success = await fetchLatestFromGitHub();
      return Response.json({ success, size: theOneFileHtml.length }, { headers: corsHeaders });
    }
    
    if (path.match(/^\/s\/[\w-]+$/)) {
      const id = path.split("/")[2];
      if (!isValidUUID(id)) {
        return new Response("Invalid room ID", { status: 400, headers: securityHeaders });
      }
      const room = loadRoom(id);
      if (!room) return new Response("Room not found", { status: 404, headers: securityHeaders });
      if (!theOneFileHtml) return new Response("TheOneFile not loaded", { status: 500, headers: securityHeaders });

      const autosaveBlockerScript = `<script>
(function(){
  window.COLLAB_MODE = true;

  var origGetItem = localStorage.getItem.bind(localStorage);
  var origSetItem = localStorage.setItem.bind(localStorage);
  var origRemoveItem = localStorage.removeItem.bind(localStorage);
  var blockedKeys = ['topology', 'autosave', 'savedState', 'nodeData', 'edgeData', 'canvasState', 'lastState', 'PAGE_STATE', 'theonefile'];

  function isBlockedKey(key) {
    if (!key) return false;
    var lk = key.toLowerCase();
    for (var i = 0; i < blockedKeys.length; i++) {
      if (lk.indexOf(blockedKeys[i].toLowerCase()) !== -1) return true;
    }
    return false;
  }

  localStorage.getItem = function(key) {
    if (window.COLLAB_MODE && isBlockedKey(key)) {
      return null;
    }
    return origGetItem(key);
  };

  localStorage.setItem = function(key, value) {
    if (window.COLLAB_MODE && isBlockedKey(key)) {
      return;
    }
    return origSetItem(key, value);
  };

  localStorage.removeItem = function(key) {
    if (window.COLLAB_MODE && isBlockedKey(key)) return;
    return origRemoveItem(key);
  };

  var origOpen = indexedDB.open.bind(indexedDB);
  indexedDB.open = function(name) {
    if (window.COLLAB_MODE && name && name.toLowerCase().indexOf('theonefile') !== -1) {
      var fakeRequest = {
        result: null,
        error: null,
        onsuccess: null,
        onerror: null,
        onupgradeneeded: null,
        onblocked: null,
        readyState: 'done',
        transaction: null,
        source: null
      };
      setTimeout(function() {
        if (fakeRequest.onerror) fakeRequest.onerror(new Event('error'));
      }, 0);
      return fakeRequest;
    }
    return origOpen.apply(indexedDB, arguments);
  };
})();
</` + `script>`;

      const exposureScript = `<script>
(function(){
  var checkInterval = setInterval(function(){
    if(typeof NODE_DATA !== 'undefined'){
      clearInterval(checkInterval);
      window.__collabGetVar = function(name) {
        try {
          switch(name) {
            case 'NODE_DATA': return NODE_DATA;
            case 'EDGE_DATA': return EDGE_DATA;
            case 'RECT_DATA': return RECT_DATA;
            case 'TEXT_DATA': return TEXT_DATA;
            case 'EDGE_LEGEND': return EDGE_LEGEND;
            case 'ZONE_LEGEND': return typeof ZONE_LEGEND !== 'undefined' ? ZONE_LEGEND : {};
            case 'ZONE_PRESETS': return typeof ZONE_PRESETS !== 'undefined' ? ZONE_PRESETS : {};
            case 'PAGE_STATE': return PAGE_STATE;
            case 'savedPositions': return savedPositions;
            case 'savedSizes': return savedSizes;
            case 'savedStyles': return savedStyles;
            case 'savedStyleSets': return typeof savedStyleSets !== 'undefined' ? savedStyleSets : {};
            case 'canvasState': return canvasState;
            case 'documentTabs': return documentTabs;
            case 'currentTabIndex': return currentTabIndex;
            case 'auditLog': return auditLog;
            case 'autoPingEnabled': return typeof autoPingEnabled !== 'undefined' ? autoPingEnabled : false;
            case 'autoPingInterval': return typeof autoPingInterval !== 'undefined' ? autoPingInterval : 5000;
            case 'savedTopologyView': return typeof savedTopologyView !== 'undefined' ? savedTopologyView : null;
            case 'encryptedSections': return typeof encryptedSections !== 'undefined' ? encryptedSections : {};
            case 'iconCache': return typeof IconLibrary !== 'undefined' ? IconLibrary.iconCache : {};
            case 'ANIM_SETTINGS': return typeof ANIM_SETTINGS !== 'undefined' ? ANIM_SETTINGS : null;
            case 'rollbackVersions': return typeof rollbackVersions !== 'undefined' ? rollbackVersions : [];
            case 'CUSTOM_LANG': return typeof CUSTOM_LANG !== 'undefined' ? CUSTOM_LANG : null;
            case 'PAGE_STATE': return typeof PAGE_STATE !== 'undefined' ? PAGE_STATE : {};
            case 'IMAGE_DATA': return typeof IMAGE_DATA !== 'undefined' ? IMAGE_DATA : { list: [] };
            default: return undefined;
          }
        } catch(e) { return undefined; }
      };
      window.__collabSetVar = function(name, value) {
        try {
          switch(name) {
            case 'NODE_DATA': NODE_DATA = value; return true;
            case 'EDGE_DATA': EDGE_DATA = value; return true;
            case 'RECT_DATA': RECT_DATA = value; return true;
            case 'TEXT_DATA': TEXT_DATA = value; return true;
            case 'EDGE_LEGEND': EDGE_LEGEND = value; return true;
            case 'ZONE_LEGEND': if(typeof ZONE_LEGEND !== 'undefined') ZONE_LEGEND = value; return true;
            case 'ZONE_PRESETS': if(typeof ZONE_PRESETS !== 'undefined') ZONE_PRESETS = value; return true;
            case 'savedPositions': savedPositions = value; return true;
            case 'savedSizes': savedSizes = value; return true;
            case 'savedStyles': savedStyles = value; return true;
            case 'savedStyleSets': if(typeof savedStyleSets !== 'undefined') savedStyleSets = value; return true;
            case 'auditLog': auditLog = value; return true;
            case 'documentTabs': documentTabs = value; return true;
            case 'currentTabIndex': currentTabIndex = value; return true;
            case 'autoPingEnabled': if(typeof autoPingEnabled !== 'undefined') autoPingEnabled = value; return true;
            case 'autoPingInterval': if(typeof autoPingInterval !== 'undefined') autoPingInterval = value; return true;
            case 'savedTopologyView': if(typeof savedTopologyView !== 'undefined') savedTopologyView = value; return true;
            case 'encryptedSections': if(typeof encryptedSections !== 'undefined') encryptedSections = value; return true;
            case 'iconCache': if(typeof IconLibrary !== 'undefined') IconLibrary.iconCache = value; return true;
            case 'ANIM_SETTINGS': if(typeof ANIM_SETTINGS !== 'undefined') { Object.assign(ANIM_SETTINGS, value); return true; } return false;
            case 'rollbackVersions': if(typeof rollbackVersions !== 'undefined') { rollbackVersions = value; return true; } return false;
            case 'CUSTOM_LANG': CUSTOM_LANG = value; if(typeof LANG !== 'undefined' && typeof DEFAULT_LANG !== 'undefined' && value) { LANG = deepMerge(DEFAULT_LANG, value); } return true;
            case 'PAGE_STATE': if(typeof PAGE_STATE !== 'undefined') { Object.assign(PAGE_STATE, value); return true; } return false;
            case 'IMAGE_DATA': if(typeof IMAGE_DATA !== 'undefined') { IMAGE_DATA = value; if(typeof renderCanvasImages === 'function') renderCanvasImages(); return true; } return false;
            default: return false;
          }
        } catch(e) { return false; }
      };
    }
  }, 50);
})();
</` + `script>`;

      let injectedHtml = theOneFileHtml.replace('<head>', '<head>' + autosaveBlockerScript);
      injectedHtml = injectedHtml.replace('</head>', exposureScript + '</head>');

      const saveHookScript = `<script>
(function(){
  var pendingHtmlBlobs = new Map();
  var origCreateObjectURL = URL.createObjectURL;
  var origRevokeObjectURL = URL.revokeObjectURL;

  URL.createObjectURL = function(blob) {
    var url = origCreateObjectURL.apply(URL, arguments);
    if (blob && blob.type && blob.type.indexOf('text/html') !== -1) {
      pendingHtmlBlobs.set(url, blob);
    }
    return url;
  };

  URL.revokeObjectURL = function(url) {
    pendingHtmlBlobs.delete(url);
    return origRevokeObjectURL.apply(URL, arguments);
  };

  document.addEventListener('click', function(e) {
    var anchor = e.target;
    if (!anchor.download) {
      anchor = e.target.closest ? e.target.closest('a[download]') : null;
    }
    if (!anchor || !anchor.download || !anchor.href) return;
    if (!anchor.download.endsWith('.html')) return;
    if (!anchor.href.startsWith('blob:')) return;
    if (typeof window.__collabStripHTML !== 'function') return;

    var blob = pendingHtmlBlobs.get(anchor.href);
    if (!blob) return;

    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    var reader = new FileReader();
    reader.onload = function() {
      var cleanHtml = window.__collabStripHTML(reader.result);
      var cleanBlob = new Blob([cleanHtml], {type: 'text/html'});
      var cleanUrl = origCreateObjectURL.call(URL, cleanBlob);
      var a = document.createElement('a');
      a.href = cleanUrl;
      a.download = anchor.download;
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      setTimeout(function() {
        document.body.removeChild(a);
        origRevokeObjectURL.call(URL, cleanUrl);
      }, 100);
    };
    reader.readAsText(blob);
  }, true);
})();
</` + `script>`;

      const adminUser = await validateAdminUser(req);
      const isAdmin = !!adminUser;

      const configScript = `<script>
window.ROOM_ID = "${id}";
window.ROOM_HAS_PASSWORD = ${!!room.passwordHash && !isAdmin};
window.ROOM_CREATOR_ID = "${room.creatorId}";
window.WS_URL = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + "/ws/${id}";
window.ROOM_IS_ADMIN = ${isAdmin};
window.ROOM_IS_CREATOR = (function(){
  var uid = localStorage.getItem('collab-user-${id}');
  return uid && uid === "${room.creatorId}";
})();
</` + `script>
<link rel="stylesheet" href="/collab.css">
<script src="/collab.js"></` + `script>
${saveHookScript}
</body>`;

      injectedHtml = injectedHtml.replace(/<\/body>\s*<\/html>\s*$/i, configScript + "\n</html>");

      return new Response(injectedHtml, { headers: { "Content-Type": "text/html", ...securityHeaders } });
    }
    
    if (path === "/" || path === "/index.html") {
      const file = Bun.file(join(process.cwd(), "public", "index.html"));
      if (await file.exists()) return new Response(file, { headers: { "Content-Type": "text/html", ...securityHeaders } });
    }

    if (path === "/collab.js") {
      const file = Bun.file(join(process.cwd(), "public", "collab.js"));
      if (await file.exists()) return new Response(file, { headers: { "Content-Type": "application/javascript", ...securityHeaders } });
    }

    if (path === "/collab.css") {
      const file = Bun.file(join(process.cwd(), "public", "collab.css"));
      if (await file.exists()) return new Response(file, { headers: { "Content-Type": "text/css", ...securityHeaders } });
    }

    if (path === "/favicon.ico") {
      return new Response(null, { status: 204 });
    }

    return new Response("Not found", { status: 404, headers: securityHeaders });
  },
  websocket: {
    open(ws) {
      const roomId = (ws.data as any)?.roomId;
      if (!roomId) return;
      const connectionId = crypto.randomUUID();
      (ws.data as any).connectionId = connectionId;
      if (!roomConnections.has(roomId)) roomConnections.set(roomId, new Set());
      roomConnections.get(roomId)!.add(ws);
      if (!roomUsers.has(roomId)) roomUsers.set(roomId, new Map());
      ws.subscribe(roomId);
      const meta = roomMeta.get(roomId) || { connectedUsers: 0 };
      meta.connectedUsers++;
      if (meta.destructTimer) { clearTimeout(meta.destructTimer); meta.destructTimer = undefined; }
      roomMeta.set(roomId, meta);
    },
    message(ws, message) {
      const roomId = (ws.data as any)?.roomId;
      const connectionId = (ws.data as any)?.connectionId;
      if (!roomId || !connectionId) return;
      let msg;
      try { msg = JSON.parse(message.toString()); } catch { return; }

      const validTypes = ['join', 'leave', 'presence', 'state', 'patch', 'chat', 'cursor'];
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
        msg.text = msg.text.replace(/[<>]/g, '');
      }

      if (msg.type === 'join' && msg.user) {
        let userId = msg.user.id;
        if (!userId || !isValidUUID(userId)) return;

        const verifiedUserId = (ws.data as any)?.verifiedUserId;
        if (verifiedUserId) {
          if (userId !== verifiedUserId) {
            ws.send(JSON.stringify({ type: 'error', error: 'User ID mismatch with session token' }));
            return;
          }
        }

        let rawName = msg.user.name;
        if (rawName && typeof rawName === 'string') {
          rawName = rawName.substring(0, 30).replace(/[<>]/g, '').trim();
          msg.user.name = rawName;
        }
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

        (ws.data as any).userId = userId;
        users.delete(userId);
        users.set(userId, msg.user);
        const existingUsers = Array.from(users.values()).filter(u => u.id !== userId);
        if (existingUsers.length > 0) ws.send(JSON.stringify({ type: 'users', users: existingUsers }));

        if (isNewUser) {
          const room = loadRoom(roomId);
          if (room && room.topology) {
            ws.send(JSON.stringify({ type: 'initial-state', state: room.topology }));
          } else {
            ws.send(JSON.stringify({ type: 'initial-state', state: null }));
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
        const users = roomUsers.get(roomId);
        if (users && msg.userId) {
          const user = users.get(msg.userId);
          if (user) { user.selectedNodes = msg.selectedNodes; user.editingNode = msg.editingNode; }
        }
        ws.publish(roomId, message);
      } else if (msg.type === 'state') {
        if (msg.state) {
          const topologyValidation = validateTopology(msg.state);
          if (!topologyValidation.valid) {
            ws.send(JSON.stringify({ type: 'error', error: topologyValidation.error || 'Invalid state data' }));
            return;
          }
          ws.publish(roomId, message);
          const room = loadRoom(roomId);
          if (room) { room.topology = topologyValidation.sanitized; room.lastActivity = new Date().toISOString(); saveRoom(room); }
        } else {
          ws.publish(roomId, message);
        }
      } else {
        ws.publish(roomId, message);
      }
      resetDestructionTimer(roomId);
    },
    close(ws) {
      const roomId = (ws.data as any)?.roomId;
      const userId = (ws.data as any)?.userId;
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
  }
});

const migrationResult = db.migrateFromFlatFiles();
if (migrationResult.rooms > 0 || migrationResult.settings || migrationResult.admin) {
  console.log(`[Migration] Migrated: ${migrationResult.rooms} rooms, settings: ${migrationResult.settings}, admin: ${migrationResult.admin}`);
}

redis.connectRedis().then(connected => {
  if (connected) {
    console.log("[Redis] Connected successfully");
  } else {
    console.log("[Redis] Not available, using in-memory fallback");
  }
});

restartBackupTimer();

db.initializeDefaultEmailTemplates();

const adminUsers = db.listUsersByRole('admin');
for (const admin of adminUsers) {
  if (!admin.emailVerified) {
    admin.emailVerified = true;
    admin.updatedAt = new Date().toISOString();
    db.updateUser(admin);
  }
}

console.log(`TheOneFile Collab running on http://localhost:${PORT}`);
if (ENV_ADMIN_PASSWORD) console.log(`Instance password lock: ENV`);
else if (isInstanceLocked()) console.log(`Instance password lock: Settings`);
if (instanceSettings.skipUpdates) console.log(`Auto-updates: Disabled`);
else if (instanceSettings.updateIntervalHours > 0) console.log(`Auto-updates: Every ${instanceSettings.updateIntervalHours}h`);
if (instanceSettings.backupEnabled) console.log(`Auto-backups: Every ${instanceSettings.backupIntervalHours}h, keep ${instanceSettings.backupRetentionCount}`);
console.log(`Admin: ${isAdminConfigured() ? 'Configured' : 'Not set up'} | Rooms: ${db.countRooms()}`);

const allRooms = db.listRooms();
for (const room of allRooms) {
  if (room.destruct.mode === "time") {
    const elapsed = Date.now() - new Date(room.lastActivity).getTime();
    const remaining = room.destruct.value - elapsed;
    if (remaining <= 0) { deleteRoomData(room.id); }
    else { scheduleDestruction(room.id, remaining); }
  }
}
