import { Database } from "bun:sqlite";
import { existsSync, mkdirSync, readdirSync, readFileSync, unlinkSync } from "fs";
import { join } from "path";

const DATA_DIR = process.env.DATA_DIR || "./data";
const DB_PATH = join(DATA_DIR, "theonefile.db");
const ROOMS_DIR = join(DATA_DIR, "rooms");
const ADMIN_CONFIG_PATH = join(DATA_DIR, "admin.json");
const SETTINGS_PATH = join(DATA_DIR, "settings.json");

if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.exec("PRAGMA journal_mode = WAL");
db.exec("PRAGMA foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY,
    created TEXT NOT NULL,
    last_activity TEXT NOT NULL,
    creator_id TEXT NOT NULL,
    password_hash TEXT,
    destruct_mode TEXT NOT NULL DEFAULT 'time',
    destruct_value INTEGER NOT NULL DEFAULT 86400000,
    topology TEXT,
    owner_user_id TEXT,
    allow_guests INTEGER NOT NULL DEFAULT 1
  )
`);

try {
  db.exec(`ALTER TABLE rooms ADD COLUMN owner_user_id TEXT`);
} catch {}
try {
  db.exec(`ALTER TABLE rooms ADD COLUMN allow_guests INTEGER NOT NULL DEFAULT 1`);
} catch {}

db.exec(`
  CREATE TABLE IF NOT EXISTS admin_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT,
    actor_ip TEXT,
    target_type TEXT,
    target_id TEXT,
    details TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs(target_type, target_id)
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    room_id TEXT NOT NULL,
    user_id TEXT,
    user_name TEXT,
    event_type TEXT NOT NULL,
    details TEXT,
    ip_address TEXT
  )
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_activity_logs_room ON activity_logs(room_id)
`);

db.exec(`
  CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON activity_logs(timestamp)
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    permissions TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used TEXT,
    expires_at TEXT,
    active INTEGER NOT NULL DEFAULT 1
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS backups (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    created_at TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    room_count INTEGER NOT NULL,
    auto_generated INTEGER NOT NULL DEFAULT 0
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    email_verified INTEGER NOT NULL DEFAULT 0,
    display_name TEXT,
    avatar_url TEXT,
    password_hash TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_login TEXT,
    is_active INTEGER NOT NULL DEFAULT 1
  )
`);

db.exec(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)`);

try {
  db.exec(`ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0`);
} catch {}
try {
  db.exec(`ALTER TABLE users ADD COLUMN locked_until TEXT`);
} catch {}

db.exec(`
  CREATE TABLE IF NOT EXISTS user_oidc_links (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    provider_email TEXT,
    access_token_encrypted TEXT,
    refresh_token_encrypted TEXT,
    token_expires_at TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(provider, provider_user_id)
  )
`);

db.exec(`CREATE INDEX IF NOT EXISTS idx_oidc_links_user ON user_oidc_links(user_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_oidc_links_provider ON user_oidc_links(provider, provider_user_id)`);

db.exec(`
  CREATE TABLE IF NOT EXISTS user_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  )
`);

db.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token_hash)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at)`);

db.exec(`
  CREATE TABLE IF NOT EXISTS user_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
  )
`);

db.exec(`CREATE INDEX IF NOT EXISTS idx_user_tokens_hash ON user_tokens(token_hash)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_user_tokens_user ON user_tokens(user_id)`);

db.exec(`
  CREATE TABLE IF NOT EXISTS smtp_configs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    host TEXT,
    port INTEGER,
    secure_mode TEXT NOT NULL DEFAULT 'tls',
    username TEXT,
    password_encrypted TEXT,
    api_key_encrypted TEXT,
    from_email TEXT NOT NULL,
    from_name TEXT,
    is_default INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    allow_insecure_tls INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )
`);

try {
  db.exec(`ALTER TABLE smtp_configs ADD COLUMN allow_insecure_tls INTEGER NOT NULL DEFAULT 0`);
} catch {}

db.exec(`
  CREATE TABLE IF NOT EXISTS oidc_providers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret_encrypted TEXT NOT NULL,
    issuer_url TEXT,
    authorization_url TEXT,
    token_url TEXT,
    userinfo_url TEXT,
    jwks_uri TEXT,
    scopes TEXT NOT NULL DEFAULT 'openid email profile',
    is_active INTEGER NOT NULL DEFAULT 1,
    display_order INTEGER NOT NULL DEFAULT 0,
    icon_url TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS user_preferences (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    theme TEXT DEFAULT 'system',
    email_notifications INTEGER NOT NULL DEFAULT 1,
    default_room_settings TEXT
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS email_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    body_html TEXT NOT NULL,
    body_text TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS email_logs (
    id TEXT PRIMARY KEY,
    to_email TEXT NOT NULL,
    template_name TEXT,
    subject TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
    smtp_config_id TEXT,
    sent_at TEXT NOT NULL
  )
`);

db.exec(`CREATE INDEX IF NOT EXISTS idx_email_logs_date ON email_logs(sent_at)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_email_logs_status ON email_logs(status)`);

db.exec(`
  CREATE TABLE IF NOT EXISTS oidc_states (
    state TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    code_verifier TEXT NOT NULL,
    nonce TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    link_user_id TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  )
`);

db.exec(`CREATE INDEX IF NOT EXISTS idx_oidc_states_expires ON oidc_states(expires_at)`);

db.exec(`
  CREATE TABLE IF NOT EXISTS csrf_tokens (
    token TEXT PRIMARY KEY,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  )
`);

db.exec(`CREATE INDEX IF NOT EXISTS idx_csrf_tokens_expires ON csrf_tokens(expires_at)`);

db.exec(`
  CREATE TABLE IF NOT EXISTS email_rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    action TEXT NOT NULL,
    created_at TEXT NOT NULL
  )
`);

db.exec(`CREATE INDEX IF NOT EXISTS idx_email_rate_limits_lookup ON email_rate_limits(email, action, created_at)`);

export interface OidcState {
  state: string;
  providerId: string;
  codeVerifier: string;
  nonce: string;
  redirectUri: string;
  linkUserId: string | null;
  createdAt: string;
  expiresAt: string;
}

export interface CsrfToken {
  token: string;
  used: boolean;
  createdAt: string;
  expiresAt: string;
}

export interface Room {
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

export interface AuditLog {
  id?: number;
  timestamp: string;
  action: string;
  actor?: string;
  actorIp?: string;
  targetType?: string;
  targetId?: string;
  details?: any;
}

export interface ActivityLog {
  id?: number;
  timestamp: string;
  roomId: string;
  userId?: string;
  userName?: string;
  eventType: string;
  details?: any;
  ipAddress?: string;
}

export interface ApiKey {
  id: string;
  name: string;
  keyHash: string;
  permissions: string[];
  createdAt: string;
  lastUsed?: string;
  expiresAt?: string;
  active: boolean;
}

export interface Backup {
  id: string;
  filename: string;
  createdAt: string;
  sizeBytes: number;
  roomCount: number;
  autoGenerated: boolean;
}

export interface User {
  id: string;
  email: string | null;
  emailVerified: boolean;
  displayName: string | null;
  avatarUrl: string | null;
  passwordHash: string | null;
  role: 'admin' | 'user' | 'guest';
  createdAt: string;
  updatedAt: string;
  lastLogin: string | null;
  isActive: boolean;
  failedLoginAttempts: number;
  lockedUntil: string | null;
}

export interface UserOidcLink {
  id: string;
  userId: string;
  provider: string;
  providerUserId: string;
  providerEmail: string | null;
  accessTokenEncrypted: string | null;
  refreshTokenEncrypted: string | null;
  tokenExpiresAt: string | null;
  createdAt: string;
}

export interface UserSession {
  id: string;
  userId: string;
  tokenHash: string;
  ipAddress: string | null;
  userAgent: string | null;
  expiresAt: string;
  createdAt: string;
}

export interface UserToken {
  id: string;
  userId: string;
  type: 'email_verify' | 'password_reset' | 'magic_link';
  tokenHash: string;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

export interface SmtpConfig {
  id: string;
  name: string;
  providerType: string;
  host: string | null;
  port: number | null;
  secureMode: 'none' | 'tls' | 'starttls';
  username: string | null;
  passwordEncrypted: string | null;
  apiKeyEncrypted: string | null;
  fromEmail: string;
  fromName: string | null;
  isDefault: boolean;
  isActive: boolean;
  allowInsecureTls: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface OidcProvider {
  id: string;
  name: string;
  providerType: string;
  clientId: string;
  clientSecretEncrypted: string;
  issuerUrl: string | null;
  authorizationUrl: string | null;
  tokenUrl: string | null;
  userinfoUrl: string | null;
  jwksUri: string | null;
  scopes: string;
  isActive: boolean;
  displayOrder: number;
  iconUrl: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UserPreferences {
  userId: string;
  theme: string;
  emailNotifications: boolean;
  defaultRoomSettings: any;
}

export interface EmailTemplate {
  id: string;
  name: string;
  subject: string;
  bodyHtml: string;
  bodyText: string;
  createdAt: string;
  updatedAt: string;
}

export interface EmailLog {
  id: string;
  toEmail: string;
  templateName: string | null;
  subject: string;
  status: 'sent' | 'failed' | 'pending';
  errorMessage: string | null;
  smtpConfigId: string | null;
  sentAt: string;
}

const stmtInsertRoom = db.prepare(`
  INSERT INTO rooms (id, created, last_activity, creator_id, password_hash, destruct_mode, destruct_value, topology, owner_user_id, allow_guests)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const stmtUpdateRoom = db.prepare(`
  UPDATE rooms SET last_activity = ?, topology = ? WHERE id = ?
`);

const stmtUpdateRoomSettings = db.prepare(`
  UPDATE rooms SET allow_guests = ?, owner_user_id = ? WHERE id = ?
`);

const stmtGetRoom = db.prepare(`
  SELECT * FROM rooms WHERE id = ?
`);

const stmtDeleteRoom = db.prepare(`
  DELETE FROM rooms WHERE id = ?
`);

const stmtListRooms = db.prepare(`
  SELECT * FROM rooms ORDER BY created DESC
`);

const stmtSearchRooms = db.prepare(`
  SELECT * FROM rooms WHERE id LIKE ? OR creator_id LIKE ? ORDER BY created DESC LIMIT ? OFFSET ?
`);

const stmtCountRooms = db.prepare(`
  SELECT COUNT(*) as count FROM rooms
`);

const stmtGetSetting = db.prepare(`
  SELECT value FROM admin_settings WHERE key = ?
`);

const stmtSetSetting = db.prepare(`
  INSERT OR REPLACE INTO admin_settings (key, value) VALUES (?, ?)
`);

const stmtDeleteSetting = db.prepare(`
  DELETE FROM admin_settings WHERE key = ?
`);

const stmtGetAllSettings = db.prepare(`
  SELECT key, value FROM admin_settings
`);

const stmtInsertAuditLog = db.prepare(`
  INSERT INTO audit_logs (timestamp, action, actor, actor_ip, target_type, target_id, details)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);

const stmtGetAuditLogs = db.prepare(`
  SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?
`);

const stmtSearchAuditLogs = db.prepare(`
  SELECT * FROM audit_logs WHERE action LIKE ? OR actor LIKE ? OR target_id LIKE ? ORDER BY timestamp DESC LIMIT ? OFFSET ?
`);

const stmtInsertActivityLog = db.prepare(`
  INSERT INTO activity_logs (timestamp, room_id, user_id, user_name, event_type, details, ip_address)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);

const stmtGetActivityLogs = db.prepare(`
  SELECT * FROM activity_logs WHERE room_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?
`);

const stmtGetAllActivityLogs = db.prepare(`
  SELECT * FROM activity_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?
`);

const stmtInsertApiKey = db.prepare(`
  INSERT INTO api_keys (id, name, key_hash, permissions, created_at, expires_at, active)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);

const stmtGetApiKey = db.prepare(`
  SELECT * FROM api_keys WHERE id = ? AND active = 1
`);

const stmtGetApiKeyByHash = db.prepare(`
  SELECT * FROM api_keys WHERE key_hash = ? AND active = 1
`);

const stmtUpdateApiKeyLastUsed = db.prepare(`
  UPDATE api_keys SET last_used = ? WHERE id = ?
`);

const stmtListApiKeys = db.prepare(`
  SELECT id, name, permissions, created_at, last_used, expires_at, active FROM api_keys ORDER BY created_at DESC
`);

const stmtDeactivateApiKey = db.prepare(`
  UPDATE api_keys SET active = 0 WHERE id = ?
`);

const stmtInsertBackup = db.prepare(`
  INSERT INTO backups (id, filename, created_at, size_bytes, room_count, auto_generated)
  VALUES (?, ?, ?, ?, ?, ?)
`);

const stmtListBackups = db.prepare(`
  SELECT * FROM backups ORDER BY created_at DESC
`);

const stmtDeleteBackup = db.prepare(`
  DELETE FROM backups WHERE id = ?
`);

const stmtGetOldAutoBackups = db.prepare(`
  SELECT * FROM backups WHERE auto_generated = 1 ORDER BY created_at DESC LIMIT -1 OFFSET ?
`);

function rowToRoom(row: any): Room | null {
  if (!row) return null;
  return {
    id: row.id,
    created: row.created,
    lastActivity: row.last_activity,
    creatorId: row.creator_id,
    passwordHash: row.password_hash,
    destruct: { mode: row.destruct_mode, value: row.destruct_value },
    topology: row.topology ? JSON.parse(row.topology) : null,
    ownerUserId: row.owner_user_id || null,
    allowGuests: row.allow_guests !== 0
  };
}

export function createRoom(room: Room): void {
  stmtInsertRoom.run(
    room.id,
    room.created,
    room.lastActivity,
    room.creatorId,
    room.passwordHash,
    room.destruct.mode,
    room.destruct.value,
    room.topology ? JSON.stringify(room.topology) : null,
    room.ownerUserId || null,
    room.allowGuests ? 1 : 0
  );
}

export function getRoom(id: string): Room | null {
  return rowToRoom(stmtGetRoom.get(id));
}

export function updateRoom(id: string, lastActivity: string, topology: any): void {
  stmtUpdateRoom.run(lastActivity, topology ? JSON.stringify(topology) : null, id);
}

export function updateRoomSettings(id: string, allowGuests: boolean, ownerUserId: string | null): void {
  stmtUpdateRoomSettings.run(allowGuests ? 1 : 0, ownerUserId, id);
}

export function deleteRoom(id: string): boolean {
  const result = stmtDeleteRoom.run(id);
  return result.changes > 0;
}

export function listRooms(): Room[] {
  return (stmtListRooms.all() as any[]).map(rowToRoom).filter(r => r !== null) as Room[];
}

export function searchRooms(query: string, limit: number = 50, offset: number = 0): Room[] {
  const searchPattern = `%${query}%`;
  return (stmtSearchRooms.all(searchPattern, searchPattern, limit, offset) as any[])
    .map(rowToRoom)
    .filter(r => r !== null) as Room[];
}

export function countRooms(): number {
  const result = stmtCountRooms.get() as { count: number };
  return result.count;
}

export function getSetting(key: string): string | null {
  const row = stmtGetSetting.get(key) as { value: string } | undefined;
  return row?.value ?? null;
}

export function setSetting(key: string, value: string): void {
  stmtSetSetting.run(key, value);
}

export function deleteSetting(key: string): void {
  stmtDeleteSetting.run(key);
}

export function getAllSettings(): Record<string, string> {
  const rows = stmtGetAllSettings.all() as { key: string; value: string }[];
  const result: Record<string, string> = {};
  for (const row of rows) {
    result[row.key] = row.value;
  }
  return result;
}

export function addAuditLog(log: AuditLog): void {
  stmtInsertAuditLog.run(
    log.timestamp,
    log.action,
    log.actor || null,
    log.actorIp || null,
    log.targetType || null,
    log.targetId || null,
    log.details ? JSON.stringify(log.details) : null
  );
}

export function getAuditLogs(limit: number = 100, offset: number = 0): AuditLog[] {
  return (stmtGetAuditLogs.all(limit, offset) as any[]).map(row => ({
    id: row.id,
    timestamp: row.timestamp,
    action: row.action,
    actor: row.actor,
    actorIp: row.actor_ip,
    targetType: row.target_type,
    targetId: row.target_id,
    details: row.details ? JSON.parse(row.details) : null
  }));
}

export function searchAuditLogs(query: string, limit: number = 100, offset: number = 0): AuditLog[] {
  const searchPattern = `%${query}%`;
  return (stmtSearchAuditLogs.all(searchPattern, searchPattern, searchPattern, limit, offset) as any[]).map(row => ({
    id: row.id,
    timestamp: row.timestamp,
    action: row.action,
    actor: row.actor,
    actorIp: row.actor_ip,
    targetType: row.target_type,
    targetId: row.target_id,
    details: row.details ? JSON.parse(row.details) : null
  }));
}

export function addActivityLog(log: ActivityLog): void {
  stmtInsertActivityLog.run(
    log.timestamp,
    log.roomId,
    log.userId || null,
    log.userName || null,
    log.eventType,
    log.details ? JSON.stringify(log.details) : null,
    log.ipAddress || null
  );
}

export function getActivityLogs(roomId: string, limit: number = 100, offset: number = 0): ActivityLog[] {
  return (stmtGetActivityLogs.all(roomId, limit, offset) as any[]).map(row => ({
    id: row.id,
    timestamp: row.timestamp,
    roomId: row.room_id,
    userId: row.user_id,
    userName: row.user_name,
    eventType: row.event_type,
    details: row.details ? JSON.parse(row.details) : null,
    ipAddress: row.ip_address
  }));
}

export function getAllActivityLogs(limit: number = 100, offset: number = 0): ActivityLog[] {
  return (stmtGetAllActivityLogs.all(limit, offset) as any[]).map(row => ({
    id: row.id,
    timestamp: row.timestamp,
    roomId: row.room_id,
    userId: row.user_id,
    userName: row.user_name,
    eventType: row.event_type,
    details: row.details ? JSON.parse(row.details) : null,
    ipAddress: row.ip_address
  }));
}

export function createApiKey(apiKey: ApiKey): void {
  stmtInsertApiKey.run(
    apiKey.id,
    apiKey.name,
    apiKey.keyHash,
    JSON.stringify(apiKey.permissions),
    apiKey.createdAt,
    apiKey.expiresAt || null,
    apiKey.active ? 1 : 0
  );
}

export function getApiKeyById(id: string): ApiKey | null {
  const row = stmtGetApiKey.get(id) as any;
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    keyHash: row.key_hash,
    permissions: JSON.parse(row.permissions),
    createdAt: row.created_at,
    lastUsed: row.last_used,
    expiresAt: row.expires_at,
    active: row.active === 1
  };
}

export function getApiKeyByHash(hash: string): ApiKey | null {
  const row = stmtGetApiKeyByHash.get(hash) as any;
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    keyHash: row.key_hash,
    permissions: JSON.parse(row.permissions),
    createdAt: row.created_at,
    lastUsed: row.last_used,
    expiresAt: row.expires_at,
    active: row.active === 1
  };
}

export function updateApiKeyLastUsed(id: string): void {
  stmtUpdateApiKeyLastUsed.run(new Date().toISOString(), id);
}

export function listApiKeys(): Omit<ApiKey, "keyHash">[] {
  return (stmtListApiKeys.all() as any[]).map(row => ({
    id: row.id,
    name: row.name,
    permissions: JSON.parse(row.permissions),
    createdAt: row.created_at,
    lastUsed: row.last_used,
    expiresAt: row.expires_at,
    active: row.active === 1
  }));
}

export function deactivateApiKey(id: string): boolean {
  const result = stmtDeactivateApiKey.run(id);
  return result.changes > 0;
}

export function createBackupRecord(backup: Backup): void {
  stmtInsertBackup.run(
    backup.id,
    backup.filename,
    backup.createdAt,
    backup.sizeBytes,
    backup.roomCount,
    backup.autoGenerated ? 1 : 0
  );
}

export function listBackups(): Backup[] {
  return (stmtListBackups.all() as any[]).map(row => ({
    id: row.id,
    filename: row.filename,
    createdAt: row.created_at,
    sizeBytes: row.size_bytes,
    roomCount: row.room_count,
    autoGenerated: row.auto_generated === 1
  }));
}

export function deleteBackupRecord(id: string): boolean {
  const result = stmtDeleteBackup.run(id);
  return result.changes > 0;
}

export function getOldAutoBackups(keepCount: number): Backup[] {
  return (stmtGetOldAutoBackups.all(keepCount) as any[]).map(row => ({
    id: row.id,
    filename: row.filename,
    createdAt: row.created_at,
    sizeBytes: row.size_bytes,
    roomCount: row.room_count,
    autoGenerated: row.auto_generated === 1
  }));
}

export function migrateFromFlatFiles(): { rooms: number; settings: boolean; admin: boolean } {
  let roomsMigrated = 0;
  let settingsMigrated = false;
  let adminMigrated = false;

  if (existsSync(ROOMS_DIR)) {
    const files = readdirSync(ROOMS_DIR).filter(f => f.endsWith(".json"));
    for (const file of files) {
      try {
        const roomPath = join(ROOMS_DIR, file);
        const roomData = JSON.parse(readFileSync(roomPath, "utf-8"));
        const existing = getRoom(roomData.id);
        if (!existing) {
          createRoom({
            id: roomData.id,
            created: roomData.created,
            lastActivity: roomData.lastActivity,
            creatorId: roomData.creatorId,
            passwordHash: roomData.passwordHash,
            destruct: roomData.destruct,
            topology: roomData.topology
          });
          roomsMigrated++;
        }
        unlinkSync(roomPath);
      } catch (e) {
        console.error(`Failed to migrate room ${file}:`, e);
      }
    }
  }

  if (existsSync(SETTINGS_PATH)) {
    try {
      const settings = JSON.parse(readFileSync(SETTINGS_PATH, "utf-8"));
      for (const [key, value] of Object.entries(settings)) {
        setSetting(key, JSON.stringify(value));
      }
      unlinkSync(SETTINGS_PATH);
      settingsMigrated = true;
    } catch (e) {
      console.error("Failed to migrate settings:", e);
    }
  }

  if (existsSync(ADMIN_CONFIG_PATH)) {
    try {
      const adminConfig = JSON.parse(readFileSync(ADMIN_CONFIG_PATH, "utf-8"));
      setSetting("admin_password_hash", adminConfig.passwordHash);
      setSetting("admin_created_at", adminConfig.createdAt);
      unlinkSync(ADMIN_CONFIG_PATH);
      adminMigrated = true;
    } catch (e) {
      console.error("Failed to migrate admin config:", e);
    }
  }

  return { rooms: roomsMigrated, settings: settingsMigrated, admin: adminMigrated };
}

export function getDatabase(): Database {
  return db;
}

export function closeDatabase(): void {
  db.close();
}

export function logAuthEvent(
  action: string,
  userId: string | null,
  ipAddress: string | null,
  details?: Record<string, any>
): void {
  addAuditLog({
    timestamp: new Date().toISOString(),
    action: `auth:${action}`,
    actor: userId,
    actorIp: ipAddress,
    targetType: 'user',
    targetId: userId,
    details: details
  });
}

const stmtInsertUser = db.prepare(`
  INSERT INTO users (id, email, email_verified, display_name, avatar_url, password_hash, role, created_at, updated_at, last_login, is_active)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const stmtGetUserById = db.prepare(`SELECT * FROM users WHERE id = ?`);
const stmtGetUserByEmail = db.prepare(`SELECT * FROM users WHERE email = ? COLLATE NOCASE`);
const stmtUpdateUser = db.prepare(`
  UPDATE users SET email = ?, email_verified = ?, display_name = ?, avatar_url = ?, password_hash = ?, role = ?, updated_at = ?, last_login = ?, is_active = ?, failed_login_attempts = ?, locked_until = ?
  WHERE id = ?
`);
const stmtIncrementFailedLogin = db.prepare(`UPDATE users SET failed_login_attempts = failed_login_attempts + 1, updated_at = ? WHERE id = ?`);
const stmtResetFailedLogin = db.prepare(`UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?`);
const stmtLockUser = db.prepare(`UPDATE users SET locked_until = ?, updated_at = ? WHERE id = ?`);
const stmtDeleteUser = db.prepare(`DELETE FROM users WHERE id = ?`);
const stmtListUsers = db.prepare(`SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`);
const stmtListUsersByRole = db.prepare(`SELECT * FROM users WHERE role = ? ORDER BY created_at DESC`);
const stmtSearchUsers = db.prepare(`SELECT * FROM users WHERE email LIKE ? OR display_name LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?`);
const stmtCountUsers = db.prepare(`SELECT COUNT(*) as count FROM users`);
const stmtCountUsersByRole = db.prepare(`SELECT COUNT(*) as count FROM users WHERE role = ?`);

function rowToUser(row: any): User | null {
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    emailVerified: row.email_verified === 1,
    displayName: row.display_name,
    avatarUrl: row.avatar_url,
    passwordHash: row.password_hash,
    role: row.role,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastLogin: row.last_login,
    isActive: row.is_active === 1,
    failedLoginAttempts: row.failed_login_attempts || 0,
    lockedUntil: row.locked_until
  };
}

export function createUser(user: User): void {
  stmtInsertUser.run(
    user.id, user.email, user.emailVerified ? 1 : 0, user.displayName, user.avatarUrl,
    user.passwordHash, user.role, user.createdAt, user.updatedAt, user.lastLogin, user.isActive ? 1 : 0
  );
}

export function getUserById(id: string): User | null {
  return rowToUser(stmtGetUserById.get(id));
}

export function getUserByEmail(email: string): User | null {
  return rowToUser(stmtGetUserByEmail.get(email));
}

export function updateUser(user: User): void {
  stmtUpdateUser.run(
    user.email, user.emailVerified ? 1 : 0, user.displayName, user.avatarUrl, user.passwordHash,
    user.role, user.updatedAt, user.lastLogin, user.isActive ? 1 : 0,
    user.failedLoginAttempts, user.lockedUntil, user.id
  );
}

export function incrementFailedLogin(userId: string): void {
  stmtIncrementFailedLogin.run(new Date().toISOString(), userId);
}

export function resetFailedLogin(userId: string): void {
  stmtResetFailedLogin.run(new Date().toISOString(), userId);
}

export function lockUserAccount(userId: string, until: Date): void {
  stmtLockUser.run(until.toISOString(), new Date().toISOString(), userId);
}

export function deleteUser(id: string): boolean {
  return stmtDeleteUser.run(id).changes > 0;
}

export function listUsers(limit: number = 100, offset: number = 0): User[] {
  return (stmtListUsers.all(limit, offset) as any[]).map(rowToUser).filter(u => u !== null) as User[];
}

export function searchUsers(query: string, limit: number = 100, offset: number = 0): User[] {
  const pattern = `%${query}%`;
  return (stmtSearchUsers.all(pattern, pattern, limit, offset) as any[]).map(rowToUser).filter(u => u !== null) as User[];
}

export function countUsers(): number {
  return (stmtCountUsers.get() as { count: number }).count;
}

export function countUsersByRole(role: string): number {
  return (stmtCountUsersByRole.get(role) as { count: number }).count;
}

export function listUsersByRole(role: string): User[] {
  return (stmtListUsersByRole.all(role) as any[]).map(rowToUser).filter(u => u !== null) as User[];
}


const stmtInsertSession = db.prepare(`
  INSERT INTO user_sessions (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);
const stmtGetSessionByToken = db.prepare(`SELECT * FROM user_sessions WHERE token_hash = ?`);
const stmtGetSessionsByUser = db.prepare(`SELECT * FROM user_sessions WHERE user_id = ? ORDER BY created_at DESC`);
const stmtDeleteSession = db.prepare(`DELETE FROM user_sessions WHERE id = ?`);
const stmtDeleteSessionByToken = db.prepare(`DELETE FROM user_sessions WHERE token_hash = ?`);
const stmtDeleteSessionsByUser = db.prepare(`DELETE FROM user_sessions WHERE user_id = ?`);
const stmtDeleteExpiredSessions = db.prepare(`DELETE FROM user_sessions WHERE expires_at < ?`);

function rowToSession(row: any): UserSession | null {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    tokenHash: row.token_hash,
    ipAddress: row.ip_address,
    userAgent: row.user_agent,
    expiresAt: row.expires_at,
    createdAt: row.created_at
  };
}

export function createUserSession(session: UserSession): void {
  stmtInsertSession.run(session.id, session.userId, session.tokenHash, session.ipAddress, session.userAgent, session.expiresAt, session.createdAt);
}

export function getSessionByTokenHash(tokenHash: string): UserSession | null {
  return rowToSession(stmtGetSessionByToken.get(tokenHash));
}

export function getSessionsByUserId(userId: string): UserSession[] {
  return (stmtGetSessionsByUser.all(userId) as any[]).map(rowToSession).filter(s => s !== null) as UserSession[];
}

export function deleteSession(id: string): boolean {
  return stmtDeleteSession.run(id).changes > 0;
}

export function deleteSessionByTokenHash(tokenHash: string): boolean {
  return stmtDeleteSessionByToken.run(tokenHash).changes > 0;
}

export function deleteAllUserSessions(userId: string): number {
  return stmtDeleteSessionsByUser.run(userId).changes;
}

export function cleanupExpiredSessions(): number {
  return stmtDeleteExpiredSessions.run(new Date().toISOString()).changes;
}

export const getUserSessionByTokenHash = getSessionByTokenHash;
export const deleteUserSession = deleteSession;


const stmtInsertUserToken = db.prepare(`
  INSERT INTO user_tokens (id, user_id, type, token_hash, expires_at, used_at, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);
const stmtGetUserTokenByHash = db.prepare(`SELECT * FROM user_tokens WHERE token_hash = ?`);
const stmtMarkUserTokenUsed = db.prepare(`UPDATE user_tokens SET used_at = ? WHERE id = ?`);
const stmtDeleteUserToken = db.prepare(`DELETE FROM user_tokens WHERE id = ?`);
const stmtDeleteExpiredUserTokens = db.prepare(`DELETE FROM user_tokens WHERE expires_at < ?`);
const stmtDeleteUserTokensByUser = db.prepare(`DELETE FROM user_tokens WHERE user_id = ? AND type = ?`);

function rowToUserToken(row: any): UserToken | null {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    type: row.type,
    tokenHash: row.token_hash,
    expiresAt: row.expires_at,
    usedAt: row.used_at,
    createdAt: row.created_at
  };
}

export function createUserToken(token: UserToken): void {
  stmtInsertUserToken.run(token.id, token.userId, token.type, token.tokenHash, token.expiresAt, token.usedAt, token.createdAt);
}

export function getUserTokenByHash(tokenHash: string): UserToken | null {
  return rowToUserToken(stmtGetUserTokenByHash.get(tokenHash));
}

export function markUserTokenUsed(id: string): void {
  stmtMarkUserTokenUsed.run(new Date().toISOString(), id);
}

export function deleteUserToken(id: string): boolean {
  return stmtDeleteUserToken.run(id).changes > 0;
}

export function deleteUserTokensByType(userId: string, type: string): number {
  return stmtDeleteUserTokensByUser.run(userId, type).changes;
}

export function cleanupExpiredUserTokens(): number {
  return stmtDeleteExpiredUserTokens.run(new Date().toISOString()).changes;
}


const stmtInsertOidcLink = db.prepare(`
  INSERT INTO user_oidc_links (id, user_id, provider, provider_user_id, provider_email, access_token_encrypted, refresh_token_encrypted, token_expires_at, created_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const stmtGetOidcLinkById = db.prepare(`SELECT * FROM user_oidc_links WHERE id = ?`);
const stmtGetOidcLinkByProvider = db.prepare(`SELECT * FROM user_oidc_links WHERE provider = ? AND provider_user_id = ?`);
const stmtGetOidcLinksByUser = db.prepare(`SELECT * FROM user_oidc_links WHERE user_id = ?`);
const stmtDeleteOidcLink = db.prepare(`DELETE FROM user_oidc_links WHERE id = ?`);
const stmtUpdateOidcLinkTokens = db.prepare(`UPDATE user_oidc_links SET access_token_encrypted = ?, refresh_token_encrypted = ?, token_expires_at = ? WHERE id = ?`);

function rowToOidcLink(row: any): UserOidcLink | null {
  if (!row) return null;
  return {
    id: row.id,
    userId: row.user_id,
    provider: row.provider,
    providerUserId: row.provider_user_id,
    providerEmail: row.provider_email,
    accessTokenEncrypted: row.access_token_encrypted,
    refreshTokenEncrypted: row.refresh_token_encrypted,
    tokenExpiresAt: row.token_expires_at,
    createdAt: row.created_at
  };
}

export function createOidcLink(link: UserOidcLink): void {
  stmtInsertOidcLink.run(link.id, link.userId, link.provider, link.providerUserId, link.providerEmail, link.accessTokenEncrypted, link.refreshTokenEncrypted, link.tokenExpiresAt, link.createdAt);
}

export function getOidcLinkById(id: string): UserOidcLink | null {
  return rowToOidcLink(stmtGetOidcLinkById.get(id));
}

export function getOidcLinkByProvider(provider: string, providerUserId: string): UserOidcLink | null {
  return rowToOidcLink(stmtGetOidcLinkByProvider.get(provider, providerUserId));
}

export function getOidcLinksByUser(userId: string): UserOidcLink[] {
  return (stmtGetOidcLinksByUser.all(userId) as any[]).map(rowToOidcLink).filter(l => l !== null) as UserOidcLink[];
}

export function deleteOidcLink(id: string): boolean {
  return stmtDeleteOidcLink.run(id).changes > 0;
}

export function updateOidcLinkTokens(id: string, accessToken: string | null, refreshToken: string | null, expiresAt: string | null): void {
  stmtUpdateOidcLinkTokens.run(accessToken, refreshToken, expiresAt, id);
}


const stmtInsertOidcProvider = db.prepare(`
  INSERT INTO oidc_providers (id, name, provider_type, client_id, client_secret_encrypted, issuer_url, authorization_url, token_url, userinfo_url, jwks_uri, scopes, is_active, display_order, icon_url, created_at, updated_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const stmtGetOidcProvider = db.prepare(`SELECT * FROM oidc_providers WHERE id = ?`);
const stmtGetOidcProviderByName = db.prepare(`SELECT * FROM oidc_providers WHERE name = ?`);
const stmtListOidcProviders = db.prepare(`SELECT * FROM oidc_providers ORDER BY display_order ASC, name ASC`);
const stmtListActiveOidcProviders = db.prepare(`SELECT * FROM oidc_providers WHERE is_active = 1 ORDER BY display_order ASC, name ASC`);
const stmtUpdateOidcProvider = db.prepare(`
  UPDATE oidc_providers SET name = ?, provider_type = ?, client_id = ?, client_secret_encrypted = ?, issuer_url = ?, authorization_url = ?, token_url = ?, userinfo_url = ?, jwks_uri = ?, scopes = ?, is_active = ?, display_order = ?, icon_url = ?, updated_at = ?
  WHERE id = ?
`);
const stmtDeleteOidcProvider = db.prepare(`DELETE FROM oidc_providers WHERE id = ?`);

function rowToOidcProvider(row: any): OidcProvider | null {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    providerType: row.provider_type,
    clientId: row.client_id,
    clientSecretEncrypted: row.client_secret_encrypted,
    issuerUrl: row.issuer_url,
    authorizationUrl: row.authorization_url,
    tokenUrl: row.token_url,
    userinfoUrl: row.userinfo_url,
    jwksUri: row.jwks_uri,
    scopes: row.scopes,
    isActive: row.is_active === 1,
    displayOrder: row.display_order,
    iconUrl: row.icon_url,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

export function createOidcProvider(provider: OidcProvider): void {
  stmtInsertOidcProvider.run(
    provider.id, provider.name, provider.providerType, provider.clientId, provider.clientSecretEncrypted,
    provider.issuerUrl, provider.authorizationUrl, provider.tokenUrl, provider.userinfoUrl, provider.jwksUri,
    provider.scopes, provider.isActive ? 1 : 0, provider.displayOrder, provider.iconUrl, provider.createdAt, provider.updatedAt
  );
}

export function getOidcProvider(id: string): OidcProvider | null {
  return rowToOidcProvider(stmtGetOidcProvider.get(id));
}

export function getOidcProviderByName(name: string): OidcProvider | null {
  return rowToOidcProvider(stmtGetOidcProviderByName.get(name));
}

export function listOidcProviders(): OidcProvider[] {
  return (stmtListOidcProviders.all() as any[]).map(rowToOidcProvider).filter(p => p !== null) as OidcProvider[];
}

export function listActiveOidcProviders(): OidcProvider[] {
  return (stmtListActiveOidcProviders.all() as any[]).map(rowToOidcProvider).filter(p => p !== null) as OidcProvider[];
}

export function updateOidcProvider(provider: OidcProvider): void {
  stmtUpdateOidcProvider.run(
    provider.name, provider.providerType, provider.clientId, provider.clientSecretEncrypted,
    provider.issuerUrl, provider.authorizationUrl, provider.tokenUrl, provider.userinfoUrl, provider.jwksUri,
    provider.scopes, provider.isActive ? 1 : 0, provider.displayOrder, provider.iconUrl, provider.updatedAt, provider.id
  );
}

export function deleteOidcProvider(id: string): boolean {
  return stmtDeleteOidcProvider.run(id).changes > 0;
}


const stmtInsertSmtpConfig = db.prepare(`
  INSERT INTO smtp_configs (id, name, provider_type, host, port, secure_mode, username, password_encrypted, api_key_encrypted, from_email, from_name, is_default, is_active, allow_insecure_tls, created_at, updated_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const stmtGetSmtpConfig = db.prepare(`SELECT * FROM smtp_configs WHERE id = ?`);
const stmtGetDefaultSmtpConfig = db.prepare(`SELECT * FROM smtp_configs WHERE is_default = 1 AND is_active = 1 LIMIT 1`);
const stmtListSmtpConfigs = db.prepare(`SELECT * FROM smtp_configs ORDER BY is_default DESC, name ASC`);
const stmtUpdateSmtpConfig = db.prepare(`
  UPDATE smtp_configs SET name = ?, provider_type = ?, host = ?, port = ?, secure_mode = ?, username = ?, password_encrypted = ?, api_key_encrypted = ?, from_email = ?, from_name = ?, is_default = ?, is_active = ?, allow_insecure_tls = ?, updated_at = ?
  WHERE id = ?
`);
const stmtDeleteSmtpConfig = db.prepare(`DELETE FROM smtp_configs WHERE id = ?`);
const stmtClearDefaultSmtp = db.prepare(`UPDATE smtp_configs SET is_default = 0`);

function rowToSmtpConfig(row: any): SmtpConfig | null {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    providerType: row.provider_type,
    host: row.host,
    port: row.port,
    secureMode: row.secure_mode,
    username: row.username,
    passwordEncrypted: row.password_encrypted,
    apiKeyEncrypted: row.api_key_encrypted,
    fromEmail: row.from_email,
    fromName: row.from_name,
    isDefault: row.is_default === 1,
    isActive: row.is_active === 1,
    allowInsecureTls: row.allow_insecure_tls === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

export function createSmtpConfig(config: SmtpConfig): void {
  if (config.isDefault) stmtClearDefaultSmtp.run();
  stmtInsertSmtpConfig.run(
    config.id, config.name, config.providerType, config.host, config.port, config.secureMode,
    config.username, config.passwordEncrypted, config.apiKeyEncrypted, config.fromEmail, config.fromName,
    config.isDefault ? 1 : 0, config.isActive ? 1 : 0, config.allowInsecureTls ? 1 : 0, config.createdAt, config.updatedAt
  );
}

export function getSmtpConfig(id: string): SmtpConfig | null {
  return rowToSmtpConfig(stmtGetSmtpConfig.get(id));
}

export function getDefaultSmtpConfig(): SmtpConfig | null {
  return rowToSmtpConfig(stmtGetDefaultSmtpConfig.get());
}

export function listSmtpConfigs(): SmtpConfig[] {
  return (stmtListSmtpConfigs.all() as any[]).map(rowToSmtpConfig).filter(c => c !== null) as SmtpConfig[];
}

export function updateSmtpConfig(config: SmtpConfig): void {
  if (config.isDefault) stmtClearDefaultSmtp.run();
  stmtUpdateSmtpConfig.run(
    config.name, config.providerType, config.host, config.port, config.secureMode,
    config.username, config.passwordEncrypted, config.apiKeyEncrypted, config.fromEmail, config.fromName,
    config.isDefault ? 1 : 0, config.isActive ? 1 : 0, config.allowInsecureTls ? 1 : 0, config.updatedAt, config.id
  );
}

export function deleteSmtpConfig(id: string): boolean {
  return stmtDeleteSmtpConfig.run(id).changes > 0;
}


const stmtInsertEmailTemplate = db.prepare(`
  INSERT INTO email_templates (id, name, subject, body_html, body_text, created_at, updated_at)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);
const stmtGetEmailTemplate = db.prepare(`SELECT * FROM email_templates WHERE id = ?`);
const stmtGetEmailTemplateByName = db.prepare(`SELECT * FROM email_templates WHERE name = ?`);
const stmtListEmailTemplates = db.prepare(`SELECT * FROM email_templates ORDER BY name ASC`);
const stmtUpdateEmailTemplate = db.prepare(`UPDATE email_templates SET name = ?, subject = ?, body_html = ?, body_text = ?, updated_at = ? WHERE id = ?`);
const stmtDeleteEmailTemplate = db.prepare(`DELETE FROM email_templates WHERE id = ?`);

function rowToEmailTemplate(row: any): EmailTemplate | null {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    subject: row.subject,
    bodyHtml: row.body_html,
    bodyText: row.body_text,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

export function createEmailTemplate(template: EmailTemplate): void {
  stmtInsertEmailTemplate.run(template.id, template.name, template.subject, template.bodyHtml, template.bodyText, template.createdAt, template.updatedAt);
}

export function getEmailTemplate(id: string): EmailTemplate | null {
  return rowToEmailTemplate(stmtGetEmailTemplate.get(id));
}

export function getEmailTemplateByName(name: string): EmailTemplate | null {
  return rowToEmailTemplate(stmtGetEmailTemplateByName.get(name));
}

export function listEmailTemplates(): EmailTemplate[] {
  return (stmtListEmailTemplates.all() as any[]).map(rowToEmailTemplate).filter(t => t !== null) as EmailTemplate[];
}

export function updateEmailTemplate(template: EmailTemplate): void {
  stmtUpdateEmailTemplate.run(template.name, template.subject, template.bodyHtml, template.bodyText, template.updatedAt, template.id);
}

export function deleteEmailTemplate(id: string): boolean {
  return stmtDeleteEmailTemplate.run(id).changes > 0;
}


const stmtInsertEmailLog = db.prepare(`
  INSERT INTO email_logs (id, to_email, template_name, subject, status, error_message, smtp_config_id, sent_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);
const stmtListEmailLogs = db.prepare(`SELECT * FROM email_logs ORDER BY sent_at DESC LIMIT ? OFFSET ?`);
const stmtCountEmailLogs = db.prepare(`SELECT COUNT(*) as count FROM email_logs`);
const stmtCountEmailLogsByStatus = db.prepare(`SELECT COUNT(*) as count FROM email_logs WHERE status = ?`);

function rowToEmailLog(row: any): EmailLog | null {
  if (!row) return null;
  return {
    id: row.id,
    toEmail: row.to_email,
    templateName: row.template_name,
    subject: row.subject,
    status: row.status,
    errorMessage: row.error_message,
    smtpConfigId: row.smtp_config_id,
    sentAt: row.sent_at
  };
}

export function createEmailLog(log: EmailLog): void {
  stmtInsertEmailLog.run(log.id, log.toEmail, log.templateName, log.subject, log.status, log.errorMessage, log.smtpConfigId, log.sentAt);
}

export function listEmailLogs(limit: number = 100, offset: number = 0): EmailLog[] {
  return (stmtListEmailLogs.all(limit, offset) as any[]).map(rowToEmailLog).filter(l => l !== null) as EmailLog[];
}

export function countEmailLogs(): number {
  return (stmtCountEmailLogs.get() as { count: number }).count;
}

export function countEmailLogsByStatus(status: string): number {
  return (stmtCountEmailLogsByStatus.get(status) as { count: number }).count;
}

export function clearEmailLogs(): number {
  return db.exec(`DELETE FROM email_logs`).changes;
}

export function clearAuditLogs(): number {
  return db.exec(`DELETE FROM audit_logs`).changes;
}

export function clearActivityLogs(): number {
  return db.exec(`DELETE FROM activity_logs`).changes;
}


const stmtUpsertUserPreferences = db.prepare(`
  INSERT INTO user_preferences (user_id, theme, email_notifications, default_room_settings)
  VALUES (?, ?, ?, ?)
  ON CONFLICT(user_id) DO UPDATE SET theme = excluded.theme, email_notifications = excluded.email_notifications, default_room_settings = excluded.default_room_settings
`);
const stmtGetUserPreferences = db.prepare(`SELECT * FROM user_preferences WHERE user_id = ?`);

function rowToUserPreferences(row: any): UserPreferences | null {
  if (!row) return null;
  return {
    userId: row.user_id,
    theme: row.theme,
    emailNotifications: row.email_notifications === 1,
    defaultRoomSettings: row.default_room_settings ? JSON.parse(row.default_room_settings) : null
  };
}

export function saveUserPreferences(prefs: UserPreferences): void {
  stmtUpsertUserPreferences.run(prefs.userId, prefs.theme, prefs.emailNotifications ? 1 : 0, prefs.defaultRoomSettings ? JSON.stringify(prefs.defaultRoomSettings) : null);
}

export function getUserPreferences(userId: string): UserPreferences | null {
  return rowToUserPreferences(stmtGetUserPreferences.get(userId));
}


export function initializeDefaultEmailTemplates(): void {
  const now = new Date().toISOString();
  const defaults = [
    {
      id: 'emailVerify',
      name: 'Email Verification',
      subject: 'Verify your email | TheOneFile_Verse',
      bodyHtml: `<!DOCTYPE html><html><body style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
        <h1 style="color:#c9a227;">Verify Your Email</h1>
        <p>Hello {{displayName}},</p>
        <p>Please click the button below to verify your email address:</p>
        <p style="text-align:center;margin:30px 0;">
          <a href="{{verifyUrl}}" style="background:#c9a227;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:bold;">Verify Email</a>
        </p>
        <p>Or copy and paste this link: <a href="{{verifyUrl}}">{{verifyUrl}}</a></p>
        <p>This link expires in 24 hours.</p>
        <p style="color:#666;font-size:12px;margin-top:40px;">If you didn't create an account, you can ignore this email.</p>
      </body></html>`,
      bodyText: `Verify Your Email\n\nHello {{displayName}},\n\nPlease visit this link to verify your email:\n{{verifyUrl}}\n\nThis link expires in 24 hours.\n\nIf you didn't create an account, you can ignore this email.`
    },
    {
      id: 'passwordReset',
      name: 'Password Reset',
      subject: 'Reset your password | TheOneFile_Verse',
      bodyHtml: `<!DOCTYPE html><html><body style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
        <h1 style="color:#c9a227;">Reset Your Password</h1>
        <p>Hello {{displayName}},</p>
        <p>We received a request to reset your password. Click the button below to create a new password:</p>
        <p style="text-align:center;margin:30px 0;">
          <a href="{{resetUrl}}" style="background:#c9a227;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:bold;">Reset Password</a>
        </p>
        <p>Or copy and paste this link: <a href="{{resetUrl}}">{{resetUrl}}</a></p>
        <p>This link expires in 1 hour.</p>
        <p style="color:#666;font-size:12px;margin-top:40px;">If you didn't request a password reset, you can ignore this email.</p>
      </body></html>`,
      bodyText: `Reset Your Password\n\nHello {{displayName}},\n\nWe received a request to reset your password.\n\nVisit this link to create a new password:\n{{resetUrl}}\n\nThis link expires in 1 hour.\n\nIf you didn't request a password reset, you can ignore this email.`
    },
    {
      id: 'magicLink',
      name: 'Magic Link',
      subject: 'Your login link | TheOneFile_Verse',
      bodyHtml: `<!DOCTYPE html><html><body style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
        <h1 style="color:#c9a227;">Your Login Link</h1>
        <p>Hello {{displayName}},</p>
        <p>Click the button below to sign in to TheOneFile_Verse:</p>
        <p style="text-align:center;margin:30px 0;">
          <a href="{{loginUrl}}" style="background:#c9a227;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:bold;">Sign In</a>
        </p>
        <p>Or copy and paste this link: <a href="{{loginUrl}}">{{loginUrl}}</a></p>
        <p>This link expires in 15 minutes and can only be used once.</p>
      </body></html>`,
      bodyText: `Your Login Link\n\nHello {{displayName}},\n\nVisit this link to sign in:\n{{loginUrl}}\n\nThis link expires in 15 minutes and can only be used once.`
    },
    {
      id: 'roomInvite',
      name: 'Room Invitation',
      subject: 'You\'ve been invited to collaborate | TheOneFile_Verse',
      bodyHtml: `<!DOCTYPE html><html><body style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;padding:20px;">
        <h1 style="color:#c9a227;">You're Invited!</h1>
        <p>Hello,</p>
        <p>{{inviterName}} has invited you to collaborate on a room in TheOneFile_Verse.</p>
        <p style="text-align:center;margin:30px 0;">
          <a href="{{roomUrl}}" style="background:#c9a227;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:bold;">Join Room</a>
        </p>
        <p>Or copy and paste this link: <a href="{{roomUrl}}">{{roomUrl}}</a></p>
      </body></html>`,
      bodyText: `You're Invited!\n\nHello,\n\n{{inviterName}} has invited you to collaborate on a room in TheOneFile_Verse.\n\nJoin here: {{roomUrl}}`
    }
  ];

  const legacyNames = ['email_verification', 'password_reset', 'magic_link', 'room_invitation'];
  for (const legacyName of legacyNames) {
    const legacy = getEmailTemplateByName(legacyName);
    if (legacy) {
      deleteEmailTemplate(legacy.id);
    }
  }

  for (const template of defaults) {
    const existing = getEmailTemplateByName(template.name);
    if (!existing) {
      createEmailTemplate({ ...template, createdAt: now, updatedAt: now });
    }
  }
}


const stmtInsertOidcState = db.prepare(`
  INSERT INTO oidc_states (state, provider_id, code_verifier, nonce, redirect_uri, link_user_id, created_at, expires_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);
const stmtGetOidcState = db.prepare(`SELECT * FROM oidc_states WHERE state = ?`);
const stmtDeleteOidcState = db.prepare(`DELETE FROM oidc_states WHERE state = ?`);
const stmtDeleteExpiredOidcStates = db.prepare(`DELETE FROM oidc_states WHERE expires_at < ?`);
const stmtCountOidcStates = db.prepare(`SELECT COUNT(*) as count FROM oidc_states`);
const stmtDeleteOldestOidcStates = db.prepare(`DELETE FROM oidc_states WHERE state IN (SELECT state FROM oidc_states ORDER BY created_at ASC LIMIT ?)`);

function rowToOidcState(row: any): OidcState | null {
  if (!row) return null;
  return {
    state: row.state,
    providerId: row.provider_id,
    codeVerifier: row.code_verifier,
    nonce: row.nonce,
    redirectUri: row.redirect_uri,
    linkUserId: row.link_user_id,
    createdAt: row.created_at,
    expiresAt: row.expires_at
  };
}

export function createOidcState(oidcState: OidcState): void {
  stmtInsertOidcState.run(
    oidcState.state,
    oidcState.providerId,
    oidcState.codeVerifier,
    oidcState.nonce,
    oidcState.redirectUri,
    oidcState.linkUserId,
    oidcState.createdAt,
    oidcState.expiresAt
  );
}

export function getOidcState(state: string): OidcState | null {
  return rowToOidcState(stmtGetOidcState.get(state));
}

export function deleteOidcState(state: string): boolean {
  return stmtDeleteOidcState.run(state).changes > 0;
}

export function cleanupExpiredOidcStates(): number {
  return stmtDeleteExpiredOidcStates.run(new Date().toISOString()).changes;
}

export function countOidcStates(): number {
  return (stmtCountOidcStates.get() as { count: number }).count;
}

export function deleteOldestOidcStates(count: number): number {
  return stmtDeleteOldestOidcStates.run(count).changes;
}


const stmtInsertCsrfToken = db.prepare(`
  INSERT INTO csrf_tokens (token, used, created_at, expires_at)
  VALUES (?, ?, ?, ?)
`);
const stmtGetCsrfToken = db.prepare(`SELECT * FROM csrf_tokens WHERE token = ?`);
const stmtMarkCsrfTokenUsed = db.prepare(`UPDATE csrf_tokens SET used = 1 WHERE token = ?`);
const stmtDeleteCsrfToken = db.prepare(`DELETE FROM csrf_tokens WHERE token = ?`);
const stmtDeleteExpiredCsrfTokens = db.prepare(`DELETE FROM csrf_tokens WHERE expires_at < ?`);
const stmtCountCsrfTokens = db.prepare(`SELECT COUNT(*) as count FROM csrf_tokens`);
const stmtDeleteOldestCsrfTokens = db.prepare(`DELETE FROM csrf_tokens WHERE token IN (SELECT token FROM csrf_tokens ORDER BY created_at ASC LIMIT ?)`);

function rowToCsrfToken(row: any): CsrfToken | null {
  if (!row) return null;
  return {
    token: row.token,
    used: row.used === 1,
    createdAt: row.created_at,
    expiresAt: row.expires_at
  };
}

export function createCsrfToken(csrfToken: CsrfToken): void {
  stmtInsertCsrfToken.run(
    csrfToken.token,
    csrfToken.used ? 1 : 0,
    csrfToken.createdAt,
    csrfToken.expiresAt
  );
}

export function getCsrfToken(token: string): CsrfToken | null {
  return rowToCsrfToken(stmtGetCsrfToken.get(token));
}

export function markCsrfTokenUsed(token: string): boolean {
  return stmtMarkCsrfTokenUsed.run(token).changes > 0;
}

export function deleteCsrfToken(token: string): boolean {
  return stmtDeleteCsrfToken.run(token).changes > 0;
}

export function cleanupExpiredCsrfTokens(): number {
  return stmtDeleteExpiredCsrfTokens.run(new Date().toISOString()).changes;
}

export function countCsrfTokens(): number {
  return (stmtCountCsrfTokens.get() as { count: number }).count;
}

export function deleteOldestCsrfTokens(count: number): number {
  return stmtDeleteOldestCsrfTokens.run(count).changes;
}


const stmtInsertEmailRateLimit = db.prepare(`INSERT INTO email_rate_limits (email, action, created_at) VALUES (?, ?, ?)`);
const stmtCountEmailRateLimits = db.prepare(`SELECT COUNT(*) as count FROM email_rate_limits WHERE email = ? AND action = ? AND created_at > ?`);
const stmtCleanupEmailRateLimits = db.prepare(`DELETE FROM email_rate_limits WHERE created_at < ?`);

export function recordEmailRateLimit(email: string, action: string): void {
  stmtInsertEmailRateLimit.run(email.toLowerCase().trim(), action, new Date().toISOString());
}

export function countEmailRateLimitAttempts(email: string, action: string, windowSeconds: number): number {
  const cutoff = new Date(Date.now() - windowSeconds * 1000).toISOString();
  return (stmtCountEmailRateLimits.get(email.toLowerCase().trim(), action, cutoff) as { count: number }).count;
}

export function cleanupEmailRateLimits(maxAgeSeconds: number = 3600): number {
  const cutoff = new Date(Date.now() - maxAgeSeconds * 1000).toISOString();
  return stmtCleanupEmailRateLimits.run(cutoff).changes;
}
