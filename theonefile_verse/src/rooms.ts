import { existsSync, mkdirSync } from "fs";
import { unlink } from "fs/promises";
import { join } from "path";
import { parseFragment } from "parse5";
import * as db from "./database";
import * as redis from "./redis";
import * as auth from "./auth";
import { DATA_DIR, ROOMS_DIR, getSettings, updateSettings, getMaxRoomSizeBytes, getMaxTotalRoomStorageBytes, isValidUUID, REDIS_FANOUT, MAX_UPDATE_INTERVAL_HOURS, type InstanceSettings } from "./config";
import { sanitizeScene3d, SCENE3D_CODE_TTL_DAYS } from "./scene3d";
import { hostResolvesPublic } from "./net-guard";
import { enforceTopologyShape } from "./topology-shape";

if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
if (!existsSync(ROOMS_DIR)) mkdirSync(ROOMS_DIR, { recursive: true });

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

export interface RoomMeta {
  connectedUsers: number;
  destructTimer?: Timer;
  emptyDestructTimer?: Timer;
  idleCleanupTimer?: Timer;
  ownerWasLast?: boolean;
  lastLeaverWasUser?: boolean;
}

export const roomMeta: Map<string, RoomMeta> = new Map();
export const roomConnections: Map<string, Set<any>> = new Map();
export const roomUsers: Map<string, Map<string, any>> = new Map();
export const roomUsedNames: Map<string, Map<string, string>> = new Map();
export const roomChatHistory: Map<string, any[]> = new Map();

export async function hashPassword(password: string): Promise<string> {
  return await auth.hashPassword(password);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return await auth.verifyPassword(password, hash);
}

export function loadRoom(id: string): Room | null {
  if (!isValidUUID(id)) return null;
  return db.getRoom(id);
}

export function saveRoom(room: Room): void {
  if (!isValidUUID(room.id)) return;
  clearTopologyCache(room.id);
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


export const ROOM_SAVE_DEBOUNCE_MS = 500;

interface PendingWrite { json: string; topology: any; lastActivity: string; timer: Timer }

const lastPersistedHash = new Map<string, string>();
const pendingRoomWrites = new Map<string, PendingWrite>();

export function hashTopologyString(str: string): string {
  let h1 = 5381, h2 = 0;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    h1 = (((h1 << 5) + h1) ^ c) >>> 0;
    h2 = (c + (h2 << 6) + (h2 << 16) - h2) >>> 0;
  }
  return str.length.toString(36) + ':' + h1.toString(36) + ':' + h2.toString(36);
}

function commitRoomWrite(roomId: string): void {
  const pending = pendingRoomWrites.get(roomId);
  if (!pending) return;
  pendingRoomWrites.delete(roomId);
  clearTimeout(pending.timer);
  try {
    db.updateRoomTopologyJson(roomId, pending.lastActivity, pending.json);
    if (redis.isRedisConnected() && pending.topology) {
      redis.setRoomStateCache(roomId, pending.topology, 3600);
    }
  } catch (e: any) {
    lastPersistedHash.delete(roomId);
    console.error('[Room] persist failed:', e?.message);
  }
}

const ROOM_STORAGE_CACHE_MS = 15000;
const roomStorageCache = { bytes: 0, at: 0 };
const knownRoomBytes = new Map<string, number>();

export function totalRoomStorageBytes(): number {
  const now = Date.now();
  if (now - roomStorageCache.at > ROOM_STORAGE_CACHE_MS) {
    try { roomStorageCache.bytes = db.totalRoomStorageBytes(); } catch { roomStorageCache.bytes = 0; }
    roomStorageCache.at = now;
  }
  return roomStorageCache.bytes;
}

export function invalidateRoomStorageCache(): void {
  roomStorageCache.at = 0;
}

export function storedRoomBytes(roomId: string): number {
  const known = knownRoomBytes.get(roomId);
  if (known !== undefined) return known;
  let bytes = 0;
  try { bytes = db.roomTopologyBytes(roomId); } catch { bytes = 0; }
  knownRoomBytes.set(roomId, bytes);
  return bytes;
}

export function storageQuotaAllows(newBytes: number, previousBytes: number = 0): boolean {
  const cap = getMaxTotalRoomStorageBytes();
  if (!cap) return true;
  if (newBytes <= previousBytes) return true;
  return totalRoomStorageBytes() - previousBytes + newBytes <= cap;
}

export const STORAGE_QUOTA_ERROR = "This server has reached its storage limit. Ask the administrator to free space or raise the limit.";

export function persistTopology(roomId: string, topology: any, json: string, lastActivity: string): boolean {
  if (!isValidUUID(roomId)) return false;
  const hash = hashTopologyString(json);
  if (lastPersistedHash.get(roomId) === hash) return false;
  lastPersistedHash.set(roomId, hash);
  const previous = knownRoomBytes.get(roomId);
  knownRoomBytes.set(roomId, json.length);
  if (previous !== undefined && roomStorageCache.at) roomStorageCache.bytes += json.length - previous;
  const existing = pendingRoomWrites.get(roomId);
  if (existing) clearTimeout(existing.timer);
  const timer = setTimeout(() => commitRoomWrite(roomId), ROOM_SAVE_DEBOUNCE_MS);
  if (typeof (timer as any).unref === 'function') (timer as any).unref();
  pendingRoomWrites.set(roomId, { json, topology, lastActivity, timer });
  return true;
}

export function currentTopology(roomId: string): any | null {
  const pending = pendingRoomWrites.get(roomId);
  if (pending) return pending.topology;
  const room = loadRoom(roomId);
  return room ? room.topology : null;
}

export function noteForeignPersist(roomId: string, json: string): boolean {
  if (!isValidUUID(roomId)) return false;
  if (typeof json !== 'string' || !json) return false;
  if (pendingRoomWrites.has(roomId)) return false;
  lastPersistedHash.set(roomId, hashTopologyString(json));
  return true;
}

export function flushPendingRoomWrites(): void {
  for (const roomId of [...pendingRoomWrites.keys()]) commitRoomWrite(roomId);
}

export function clearTopologyCache(roomId?: string): void {
  if (roomId) {
    const pending = pendingRoomWrites.get(roomId);
    if (pending) clearTimeout(pending.timer);
    pendingRoomWrites.delete(roomId);
    lastPersistedHash.delete(roomId);
    knownRoomBytes.delete(roomId);
  } else {
    for (const p of pendingRoomWrites.values()) clearTimeout(p.timer);
    pendingRoomWrites.clear();
    lastPersistedHash.clear();
    knownRoomBytes.clear();
  }
  invalidateRoomStorageCache();
}


const VIEW_ONLY_TTL_MS = 5000;
const viewOnlyCache = new Map<string, { value: boolean; expires: number }>();

export function isRoomViewOnly(roomId: string): boolean {
  const cached = viewOnlyCache.get(roomId);
  const now = Date.now();
  if (cached && cached.expires > now) return cached.value;
  let value = false;
  try { value = db.getSetting(`room:viewOnly:${roomId}`) === '1'; } catch { value = false; }
  viewOnlyCache.set(roomId, { value, expires: now + VIEW_ONLY_TTL_MS });
  return value;
}

export function setRoomViewOnly(roomId: string, viewOnly: boolean): void {
  if (!isValidUUID(roomId)) return;
  db.setSetting(`room:viewOnly:${roomId}`, viewOnly ? '1' : '0');
  viewOnlyCache.set(roomId, { value: viewOnly, expires: Date.now() + VIEW_ONLY_TTL_MS });
}

export function deleteRoomData(id: string): boolean {
  const result = db.deleteRoom(id);
  if (result) {
    clearTopologyCache(id);
    viewOnlyCache.delete(id);
    const meta = roomMeta.get(id);
    if (meta) {
      if (meta.destructTimer) clearTimeout(meta.destructTimer);
      if (meta.emptyDestructTimer) clearTimeout(meta.emptyDestructTimer);
      if (meta.idleCleanupTimer) clearTimeout(meta.idleCleanupTimer);
    }
    roomMeta.delete(id);
    roomUsedNames.delete(id);
    roomChatHistory.delete(id);
    if (redis.isRedisConnected()) {
      redis.deleteRoomStateCache(id);
    }
  }
  return result;
}

const MAX_TIMER_MS = 2_000_000_000;

export function scheduleDestruction(roomId: string, delayMs: number): void {
  const meta = roomMeta.get(roomId) || { connectedUsers: 0 };
  if (meta.destructTimer) clearTimeout(meta.destructTimer);
  const deadline = Date.now() + Math.max(0, Number(delayMs) || 0);
  const arm = () => {
    const left = deadline - Date.now();
    if (left > MAX_TIMER_MS) { meta.destructTimer = setTimeout(arm, MAX_TIMER_MS); return; }
    meta.destructTimer = setTimeout(() => {
      const room = loadRoom(roomId);
      if (room && room.destruct.mode === "time") {
        console.log(`[Room] ${roomId} self destructed`);
        deleteRoomData(roomId);
      }
    }, Math.max(0, left));
  };
  arm();
  roomMeta.set(roomId, meta);
}

export const EMPTY_DESTRUCT_GRACE_MS = 60 * 1000;
export const EMPTY_DESTRUCT_OWNERLESS_GRACE_MS = 10 * 60 * 1000;
export const EMPTY_DESTRUCT_BOOT_GRACE_MS = 5 * 60 * 1000;

export interface PresenceProvider {
  enabled(): boolean;
  count(roomId: string): Promise<number | null>;
  list(roomId: string): Promise<Map<string, any> | null>;
  set(roomId: string, userId: string, user: any, ttlSeconds?: number): Promise<void>;
  touch(roomId: string, userId: string, ttlSeconds?: number): Promise<void>;
  remove(roomId: string, userId: string): Promise<void>;
}

export const PRESENCE_TTL_SECONDS = 300;

export const presence: PresenceProvider = {
  enabled: () => REDIS_FANOUT,
  count: (roomId) => redis.getRoomPresenceCount(roomId),
  list: async (roomId) => (redis.isRedisConnected() ? await redis.getAllUserPresence(roomId) : null),
  set: async (roomId, userId, user, ttl = PRESENCE_TTL_SECONDS) => { await redis.setUserPresence(roomId, userId, user, ttl); },
  touch: async (roomId, userId, ttl = PRESENCE_TTL_SECONDS) => { await redis.refreshUserPresence(roomId, userId, ttl); },
  remove: async (roomId, userId) => { await redis.removeUserPresence(roomId, userId); }
};

export type EmptyDestructVerdict = "allow" | "deny" | "unknown";

export const EMPTY_DESTRUCT_RETRY_MS = 60 * 1000;

async function emptyDestructVerdict(roomId: string): Promise<EmptyDestructVerdict> {
  const meta = roomMeta.get(roomId);
  if (meta && meta.connectedUsers > 0) return "deny";
  if ((roomConnections.get(roomId)?.size || 0) > 0) return "deny";
  if (!presence.enabled()) return "allow";
  let remote: number | null = null;
  try { remote = await presence.count(roomId); } catch { remote = null; }
  if (remote === null) {
    console.warn(`[Room] ${roomId} empty-destruct SKIPPED: cross-instance presence unavailable (failing safe)`);
    return "unknown";
  }
  if (remote > 0) {
    console.log(`[Room] ${roomId} empty-destruct skipped: ${remote} user(s) live on other instance(s)`);
    return "deny";
  }
  return "allow";
}

export async function emptyDestructAllowed(roomId: string): Promise<boolean> {
  return (await emptyDestructVerdict(roomId)) === "allow";
}

export function emptyDestructOwnerGate(room: Room, meta: RoomMeta | undefined): boolean {
  if (room.ownerUserId) return !!meta?.ownerWasLast;
  return meta?.lastLeaverWasUser === true;
}

export async function runEmptyDestruct(roomId: string): Promise<boolean> {
  const current = roomMeta.get(roomId);
  if (current?.emptyDestructTimer) clearTimeout(current.emptyDestructTimer);
  if (current) current.emptyDestructTimer = undefined;
  if (current && current.connectedUsers > 0) return false;
  const room = loadRoom(roomId);
  if (!room || room.destruct.mode !== "empty") return false;
  if (!emptyDestructOwnerGate(room, current)) return false;
  const verdict = await emptyDestructVerdict(roomId);
  if (verdict === "unknown") {
    scheduleEmptyDestruction(roomId, EMPTY_DESTRUCT_RETRY_MS);
    return false;
  }
  if (verdict !== "allow") return false;
  const after = roomMeta.get(roomId);
  if (after && after.connectedUsers > 0) return false;
  if ((roomConnections.get(roomId)?.size || 0) > 0) return false;
  const fresh = loadRoom(roomId);
  if (!fresh || fresh.destruct.mode !== "empty") return false;
  if (!emptyDestructOwnerGate(fresh, roomMeta.get(roomId))) return false;
  console.log(`[Room] ${roomId} destroyed (empty)`);
  deleteRoomData(roomId);
  return true;
}

export function scheduleEmptyDestruction(roomId: string, delayMs: number = EMPTY_DESTRUCT_GRACE_MS): void {
  const meta = roomMeta.get(roomId) || { connectedUsers: 0 };
  if (meta.emptyDestructTimer) clearTimeout(meta.emptyDestructTimer);
  meta.emptyDestructTimer = setTimeout(() => { void runEmptyDestruct(roomId); }, delayMs);
  if (presence.enabled()) {
    const armed = meta.emptyDestructTimer;
    void presence.count(roomId).then(n => {
      if (n !== null && n > 0 && roomMeta.get(roomId)?.emptyDestructTimer === armed) {
        console.log(`[Room] ${roomId} empty-destruct disarmed: ${n} user(s) live on other instance(s)`);
        cancelEmptyDestruction(roomId);
      }
    }).catch(() => {  });
  }
  if (typeof (meta.emptyDestructTimer as any).unref === 'function') (meta.emptyDestructTimer as any).unref();
  roomMeta.set(roomId, meta);
}

export function cancelEmptyDestruction(roomId: string): void {
  const meta = roomMeta.get(roomId);
  if (meta?.emptyDestructTimer) { clearTimeout(meta.emptyDestructTimer); meta.emptyDestructTimer = undefined; }
}

export const ROOM_IDLE_CLEANUP_MS = 5 * 60 * 1000;

export function scheduleIdleCleanup(roomId: string, delayMs: number = ROOM_IDLE_CLEANUP_MS): void {
  const meta = roomMeta.get(roomId) || { connectedUsers: 0 };
  if (meta.idleCleanupTimer) clearTimeout(meta.idleCleanupTimer);
  meta.idleCleanupTimer = setTimeout(() => {
    const current = roomMeta.get(roomId);
    if (current) current.idleCleanupTimer = undefined;
    if (current && current.connectedUsers > 0) return;
    roomUsedNames.delete(roomId);
    roomChatHistory.delete(roomId);
    commitRoomWrite(roomId);
    lastPersistedHash.delete(roomId);
    viewOnlyCache.delete(roomId);
    if (current && !current.destructTimer && !current.emptyDestructTimer) roomMeta.delete(roomId);
  }, delayMs);
  if (typeof (meta.idleCleanupTimer as any).unref === 'function') (meta.idleCleanupTimer as any).unref();
  roomMeta.set(roomId, meta);
}

export function cancelIdleCleanup(roomId: string): void {
  const meta = roomMeta.get(roomId);
  if (meta?.idleCleanupTimer) { clearTimeout(meta.idleCleanupTimer); meta.idleCleanupTimer = undefined; }
}

export function resetDestructionTimer(roomId: string): void {
  const room = loadRoom(roomId);
  if (room && room.destruct.mode === "time") {
    scheduleDestruction(roomId, room.destruct.value);
  }
}

export let theOneFileHtml = "";
const theOneFilePath = join(process.cwd(), "public", "theonefile.html");

export function extractThemePresets(): Array<{key: string, label: string}> {
  if (!theOneFileHtml) return [];
  const themes: Array<{key: string, label: string}> = [];
  const selectMatch = theOneFileHtml.match(/id="welcome-theme-select"[^>]*>([\s\S]*?)<\/select>/);
  if (selectMatch) {
    const optionRegex = /<option\s+value="(\w+)"[^>]*>([^<]+)<\/option>/g;
    let m;
    while ((m = optionRegex.exec(selectMatch[1])) !== null) {
      if (m[1]) themes.push({ key: m[1], label: m[2] });
    }
  }
  if (themes.length === 0) {
    const presetsMatch = theOneFileHtml.match(/THEME_PRESETS\s*=\s*\{([\s\S]*?)\n\};/);
    if (presetsMatch) {
      const keyRegex = /^\s+(\w+)\s*:/gm;
      let km;
      while ((km = keyRegex.exec(presetsMatch[1])) !== null) {
        themes.push({ key: km[1], label: km[1] });
      }
    }
  }
  return themes;
}

export const GITHUB_RAW_URL = "https://raw.githubusercontent.com/gelatinescreams/The-One-File/main/theonefile-networkening.html";

export let currentFileVersion = "";

export function getExpectedTheOneFileHash(): string | null {
  return db.getSetting("theOneFileHash");
}

export function setExpectedTheOneFileHash(hash: string): void {
  db.setSetting("theOneFileHash", hash);
}

export function extractVersionFromHtml(html: string): string {
  const match = html.match(/THE_ONE_FILE_VERSION\s*=\s*["']([^"']+)["']/);
  return match ? match[1].replace(/^["']+|["']+$/g, '') : "unknown";
}

export function isNewerVersion(latest: string, current: string): boolean {
  const parse = (v: string) => v.replace(/^v/i, '').split('.').map(n => parseInt(n) || 0);
  const l = parse(latest);
  const c = parse(current);
  for (let i = 0; i < Math.max(l.length, c.length); i++) {
    const lv = l[i] || 0;
    const cv = c[i] || 0;
    if (lv > cv) return true;
    if (lv < cv) return false;
  }
  return false;
}

export async function computeSha256Hash(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

export async function fetchLatestFromGitHub(repin: boolean = false): Promise<boolean> {
  try {
    console.log("[Update] Fetching from GitHub...");
    const res = await fetch(GITHUB_RAW_URL);
    if (!res.ok) return false;
    const html = await res.text();
    const downloadedHash = await computeSha256Hash(html);
    const expectedHash = getExpectedTheOneFileHash();
    if (expectedHash && !repin) {
      if (downloadedHash !== expectedHash) {
        console.error(`[Update] INTEGRITY CHECK FAILED!`);
        console.error(`[Update] Expected: ${expectedHash}`);
        console.error(`[Update] Got:      ${downloadedHash}`);
        console.error(`[Update] File rejected. An admin must approve this update from the admin panel.`);
        return false;
      }
      console.log(`[Update] Integrity verified (SHA-256: ${downloadedHash.substring(0, 16)}...)`);
    } else {
      setExpectedTheOneFileHash(downloadedHash);
      console.log(`[Update] Integrity hash pinned (SHA-256: ${downloadedHash.substring(0, 16)}...)`);
    }
    const previousVersion = currentFileVersion;
    await Bun.write(theOneFilePath, html);
    theOneFileHtml = html;
    currentFileVersion = extractVersionFromHtml(html);
    db.setSetting("lastUpdateTimestamp", new Date().toISOString());
    db.setSetting("latestFetchedVersion", currentFileVersion);
    console.log(`[Update] Downloaded v${currentFileVersion} (${(html.length / 1024).toFixed(1)}KB)${previousVersion && previousVersion !== currentFileVersion ? ` from v${previousVersion}` : ''}`);
    return true;
  } catch (e: any) { console.error("[Update]", e.message); return false; }
}

export function setTheOneFileHtml(html: string): void {
  theOneFileHtml = html;
  currentFileVersion = extractVersionFromHtml(html);
}

export function getTheOneFilePath(): string {
  return theOneFilePath;
}

let updateTimer: Timer | null = null;

export function restartUpdateTimer(): void {
  const settings = getSettings();
  if (updateTimer) clearInterval(updateTimer);
  updateTimer = null;
  if (settings.updateIntervalHours > 0 && !settings.skipUpdates) {
    const hours = Math.min(MAX_UPDATE_INTERVAL_HOURS, settings.updateIntervalHours);
    updateTimer = setInterval(() => { fetchLatestFromGitHub(); }, hours * 60 * 60 * 1000);
    if (typeof (updateTimer as any).unref === 'function') (updateTimer as any).unref();
    console.log(`[Update] Auto update every ${hours} hours`);
  }
}

export function clearUpdateTimer(): void {
  if (updateTimer) clearInterval(updateTimer);
  updateTimer = null;
}

export async function initializeTheOneFile(): Promise<void> {
  const settings = getSettings();
  if (settings.skipUpdates) {
    const localFile = Bun.file(theOneFilePath);
    if (await localFile.exists()) {
      theOneFileHtml = await localFile.text();
      console.log("[Update] Using local file (updates disabled)");
    }
  } else {
    await fetchLatestFromGitHub();
    if (!theOneFileHtml) {
      const cachedFile = Bun.file(theOneFilePath);
      if (await cachedFile.exists()) {
        theOneFileHtml = await cachedFile.text();
        console.log("[Update] Using cached file");
      }
    }
  }
  if (theOneFileHtml) {
    currentFileVersion = extractVersionFromHtml(theOneFileHtml);
    if (currentFileVersion !== "unknown") console.log(`[Update] Current version: v${currentFileVersion}`);
  }
  restartUpdateTimer();
}

export interface ValidationResult {
  valid: boolean;
  error?: string;
  edition?: string;
}

export interface TopologyValidationResult {
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

const ALLOWED_TAGS = new Set([
  'a', 'abbr', 'address', 'article', 'aside', 'b', 'bdi', 'bdo', 'blockquote',
  'br', 'caption', 'cite', 'code', 'col', 'colgroup', 'dd', 'del', 'details',
  'dfn', 'div', 'dl', 'dt', 'em', 'figcaption', 'figure', 'footer', 'h1', 'h2',
  'h3', 'h4', 'h5', 'h6', 'header', 'hr', 'i', 'img', 'ins', 'kbd', 'li',
  'main', 'mark', 'nav', 'ol', 'p', 'picture', 'pre', 'q', 'rp', 'rt', 'ruby',
  's', 'samp', 'section', 'small', 'source', 'span', 'strong', 'sub', 'summary',
  'sup', 'table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'time', 'tr', 'u',
  'ul', 'var', 'wbr', 'input', 'label', 'select', 'option', 'textarea', 'button',
  'canvas', 'audio', 'video'
]);

const ALLOWED_ATTRS = new Set([
  'id', 'class', 'title', 'lang', 'dir', 'role', 'tabindex', 'aria-label',
  'aria-hidden', 'aria-expanded', 'aria-controls', 'aria-describedby',
  'data-id', 'data-type', 'data-value', 'data-node-id', 'data-edge-id',
  'data-tab-id', 'data-tab', 'data-color', 'data-size', 'data-x', 'data-y',
  'data-width', 'data-height', 'data-source', 'data-target', 'data-label',
  'data-index', 'data-selected', 'data-locked', 'data-visible', 'data-active',
  'data-state', 'data-mode', 'data-theme', 'data-collapsed', 'data-position',
  'data-group', 'data-parent', 'data-layer', 'data-order', 'data-shape',
  'data-font-size', 'data-font-family', 'data-text-align', 'data-stroke',
  'data-fill', 'data-opacity', 'data-rotation', 'data-style', 'data-content',
  'href', 'src', 'alt', 'width', 'height', 'colspan', 'rowspan', 'target',
  'rel', 'type', 'value', 'placeholder', 'name', 'for', 'checked', 'disabled',
  'readonly', 'maxlength', 'min', 'max', 'step', 'rows', 'cols', 'wrap',
  'autoplay', 'controls', 'loop', 'muted', 'preload', 'poster',
  'contenteditable', 'spellcheck', 'draggable', 'hidden', 'open', 'start',
  'reversed', 'datetime', 'cite', 'loading', 'decoding', 'crossorigin',
  'referrerpolicy', 'sizes', 'srcset', 'media'
]);

function isAllowedDataAttr(name: string): boolean {
  if (!name.startsWith('data-')) return false;
  return /^data-[a-z][a-z0-9-]*$/.test(name);
}

function sanitizeUrl(url: string): string {
  const decoded = url
    .replace(/&#x([0-9a-f]+);?/gi, (_: string, h: string) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&#(\d+);?/gi, (_: string, d: string) => String.fromCharCode(parseInt(d, 10)))
    .replace(/[\t\n\r\x00]/g, '');
  const clean = decoded.replace(/\s/g, '').toLowerCase();
  if (clean.startsWith('javascript:') || clean.startsWith('vbscript:')) return '';
  if (clean.startsWith('data:') && !/^data:image\/(png|jpe?g|gif|webp|bmp|ico)/i.test(clean)) return 'data:blocked';
  return url;
}

const TAG_SENTINEL = '\u0001';

const URL_ATTRS = new Set(['href', 'src', 'action', 'poster', 'xlink:href', 'formaction', 'background', 'cite', 'srcset']);

function escapeAllHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function parsedNodeIsSafe(node: any): boolean {
  const name = node.nodeName;
  if (name === '#comment' || name === '#documentType') return false;
  if (name !== '#text' && name !== '#document-fragment') {
    if (node.namespaceURI && node.namespaceURI !== 'http://www.w3.org/1999/xhtml') return false;
    if (!ALLOWED_TAGS.has(String(node.tagName).toLowerCase())) return false;
    for (const attr of node.attrs || []) {
      const an = String(attr.prefix ? attr.prefix + ':' + attr.name : attr.name).toLowerCase();
      if (/^on/.test(an) || an === 'style' || an === 'srcdoc' || an === 'formaction') return false;
      if (!ALLOWED_ATTRS.has(an) && !isAllowedDataAttr(an)) return false;
      if (URL_ATTRS.has(an)) {
        const v = String(attr.value || '');
        if (sanitizeUrl(v) !== v) return false;
        const compact = v.replace(/[\u0000-\u0020\u007f-\u009f]/g, '').toLowerCase();
        if (/^(javascript|vbscript|data(?!:image\/(png|jpe?g|gif|webp|bmp|ico)))[:]/.test(compact)) return false;
      }
    }
  }
  const kids = (node.content && node.content.childNodes) ? node.content.childNodes.concat(node.childNodes || []) : (node.childNodes || []);
  for (const k of kids) if (!parsedNodeIsSafe(k)) return false;
  return true;
}

export function sanitizeHtmlString(str: string): string {
  if (typeof str !== 'string') return str;
  const input = str.replace(/\u0001/g, '');
  str = input;
  let prev: string;
  let rounds = 0;
  do { prev = str; str = sanitizeHtmlPass(str); } while (str !== prev && ++rounds < 5);
  const out = str.replace(/<(?=[A-Za-z\/!?])/g, '&lt;').replace(/\u0001/g, '<');
  if (out.indexOf('<') === -1) return out;
  let safe = false;
  try { safe = parsedNodeIsSafe(parseFragment(out)); } catch { safe = false; }
  return safe ? out : escapeAllHtml(input);
}

function sanitizeHtmlPass(str: string): string {
  str = str.replace(/<!--[\s\S]*?-->/g, '').replace(/<!\[CDATA\[[\s\S]*?\]\]>/gi, '');
  return str.replace(/<\/?([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)?\/?>/g, (match, tagName, attrsStr) => {
    const tag = tagName.toLowerCase();
    const isClosing = match.startsWith('</');
    if (!ALLOWED_TAGS.has(tag)) return '';
    if (isClosing) return `${TAG_SENTINEL}/${tag}>`;
    const selfClosing = match.endsWith('/>') || ['br', 'hr', 'img', 'input', 'col', 'source', 'wbr'].includes(tag);
    let safeAttrs = '';
    if (attrsStr) {
      const attrRegex = /([a-zA-Z][a-zA-Z0-9-]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+)))?/g;
      let attrMatch;
      while ((attrMatch = attrRegex.exec(attrsStr)) !== null) {
        const attrName = attrMatch[1].toLowerCase();
        const attrVal = attrMatch[2] ?? attrMatch[3] ?? attrMatch[4] ?? '';
        if (/^on/i.test(attrName)) continue;
        if (attrName === 'style') continue;
        if (attrName === 'srcdoc') continue;
        if (attrName === 'formaction') continue;
        if (attrName === 'rel') continue;
        if (!ALLOWED_ATTRS.has(attrName) && !isAllowedDataAttr(attrName)) continue;
        let safeVal = attrVal;
        if (attrName === 'href' || attrName === 'src' || attrName === 'action' || attrName === 'poster') {
          safeVal = sanitizeUrl(attrVal);
        }
        if (attrName === 'target') {
          safeVal = '_blank';
        }
        safeAttrs += ` ${attrName}="${safeVal.replace(/"/g, '&quot;')}"`;
        if (attrName === 'target') {
          safeAttrs += ' rel="noopener noreferrer"';
        }
      }
    }
    return selfClosing ? `${TAG_SENTINEL}${tag}${safeAttrs} />` : `${TAG_SENTINEL}${tag}${safeAttrs}>`;
  });
}

function sanitizeStringsDeep(obj: any): any {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return sanitizeHtmlString(obj);
  if (Array.isArray(obj)) return obj.map(sanitizeStringsDeep);
  if (typeof obj === 'object') {
    const result: any = {};
    for (const key of Object.keys(obj)) {
      if (key === '__proto__') continue;
      result[key] = sanitizeStringsDeep(obj[key]);
    }
    return result;
  }
  return obj;
}

export function sanitizeTopologyStrings(obj: any): any {
  return enforceTopologyShape(sanitizeStringsDeep(obj));
}

export function validateTopology(topology: any, maxBytesOverride?: number): TopologyValidationResult {
  if (topology === null || topology === undefined) {
    return { valid: true, sanitized: null };
  }
  let jsonStr: string;
  try {
    jsonStr = JSON.stringify(topology);
  } catch {
    return { valid: false, error: "Topology is not valid JSON" };
  }
  const maxSizeBytes = maxBytesOverride && maxBytesOverride > 0 ? Math.min(maxBytesOverride, getMaxRoomSizeBytes()) : getMaxRoomSizeBytes();
  if (jsonStr.length > maxSizeBytes) {
    return { valid: false, error: `Topology exceeds maximum size of ${Math.round(maxSizeBytes / (1024 * 1024))}MB` };
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
    { key: 'tabVersions', expectedType: 'object' },
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
  const sanitized = sanitizeTopologyStrings(topology);
  capAuditLog(sanitized);
  capTabVersions(sanitized);
  normalizeTextData(sanitized);
  return { valid: true, sanitized };
}

function normalizeTextList(td: any): void {
  if (!td || typeof td !== 'object' || !Array.isArray(td.list)) return;
  td.list = td.list.filter((it: any) => it && typeof it === 'object' && !Array.isArray(it));
  for (const it of td.list) {
    if (typeof it.content !== 'string') it.content = it.content == null ? '' : String(it.content);
  }
}

export function normalizeTextData(topology: any): void {
  if (!topology || typeof topology !== 'object') return;
  normalizeTextList(topology.textData);
  if (Array.isArray(topology.documentTabs)) {
    for (const tab of topology.documentTabs) if (tab && typeof tab === 'object') normalizeTextList(tab.texts);
  }
}

export const AUDIT_MAX_DETAILS_BYTES = 2 * 1024;
export const AUDIT_MAX_TOTAL_BYTES = 512 * 1024;
export const AUDIT_MAX_ENTRIES = 1000;

export function capAuditLog(topology: any): void {
  if (!topology || typeof topology !== 'object') return;
  const log = topology.auditLog;
  if (!Array.isArray(log)) return;
  const out: any[] = [];
  let total = 0;
  for (const entry of log) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    if (out.length >= AUDIT_MAX_ENTRIES) break;
    if (entry.details !== undefined && entry.details !== null) {
      let ser = '';
      try { ser = JSON.stringify(entry.details) ?? ''; } catch { ser = ''; }
      if (ser.length > AUDIT_MAX_DETAILS_BYTES) {
        entry.details = { truncated: true, bytes: ser.length, preview: ser.slice(0, 256) };
      }
    }
    let size = 0;
    try { size = (JSON.stringify(entry) ?? '').length; } catch { size = 0; }
    if (total + size > AUDIT_MAX_TOTAL_BYTES) break;
    total += size;
    out.push(entry);
  }
  topology.auditLog = out;
}

export const TAB_VERSIONS_MAX_ENTRIES = 64;
export const TAB_VERSION_MAX_V = 1099511627776;
export const TAB_VERSION_MAX_BY_LEN = 128;

export function capTabVersions(topology: any): void {
  if (!topology || typeof topology !== 'object') return;
  const versions = topology.tabVersions;
  if (versions === undefined || versions === null) return;
  if (typeof versions !== 'object' || Array.isArray(versions)) {
    delete topology.tabVersions;
    return;
  }
  const out: Record<string, { v: number; by: string }> = {};
  let count = 0;
  for (const key of Object.keys(versions)) {
    if (count >= TAB_VERSIONS_MAX_ENTRIES) break;
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    const entry = (versions as any)[key];
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const v = entry.v;
    if (typeof v !== 'number' || !Number.isInteger(v) || v < 0) continue;
    const by = typeof entry.by === 'string' ? entry.by.slice(0, TAB_VERSION_MAX_BY_LEN) : '';
    out[key] = { v: Math.min(v, TAB_VERSION_MAX_V), by };
    count++;
  }
  topology.tabVersions = out;
}

export function validateTheOneFileHtml(html: string): ValidationResult {
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

export function isValidWebhookUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    let hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    if (hostname === 'localhost' || hostname.endsWith('.localhost')) return false;
    if (hostname === 'metadata.google.internal' || hostname.endsWith('.internal')) return false;
    const mappedMatch = hostname.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mappedMatch) hostname = mappedMatch[1];
    if (/^(0x[0-9a-f]+|\d{8,})$/i.test(hostname)) return false;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
      const parts = hostname.split('.').map(Number);
      if (parts.some(p => p < 0 || p > 255)) return false;
      if (parts[0] === 127 || parts[0] === 10 || parts[0] === 0) return false;
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
      if (parts[0] === 192 && parts[1] === 168) return false;
      if (parts[0] === 169 && parts[1] === 254) return false;
      if (parts.every(p => p === 255)) return false;
    }
    if (hostname.includes(':')) {
      if (hostname === '::1' || hostname === '::') return false;
      if (/^fe80:/i.test(hostname)) return false;
      if (/^f[cd][0-9a-f]{2}:/i.test(hostname)) return false;
      if (/^::ffff:/i.test(hostname)) return false;
      if (/^100::/i.test(hostname)) return false;
    }
    return true;
  } catch { return false; }
}

export async function sendWebhook(event: string, data: any): Promise<void> {
  const settings = getSettings();
  if (!settings.webhookEnabled || !settings.webhookUrl) return;
  if (!isValidWebhookUrl(settings.webhookUrl)) {
    console.error('[Webhook] Blocked request to disallowed URL host:', (() => { try { return new URL(settings.webhookUrl).host; } catch { return '[invalid]'; } })());
    return;
  }
  try {
    const host = new URL(settings.webhookUrl).hostname;
    if (!(await hostResolvesPublic(host))) {
      console.error('[Webhook] Blocked request: host resolves to a private, loopback or link local address:', host);
      return;
    }
    const res = await fetch(settings.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event, timestamp: new Date().toISOString(), data }),
      redirect: "manual",
      signal: AbortSignal.timeout(10000)
    });
    if (res.status >= 300 && res.status < 400) {
      console.error('[Webhook] Redirect not followed, status', res.status);
    }
  } catch (e: any) {
    console.error('[Webhook] Failed to send webhook:', e.message);
  }
}

const BACKUPS_DIR = join(DATA_DIR, "backups");
if (!existsSync(BACKUPS_DIR)) mkdirSync(BACKUPS_DIR, { recursive: true });

export async function createBackup(autoGenerated: boolean = false): Promise<{ id: string; filename: string; size: number } | null> {
  try {
    const settings = getSettings();
    const id = crypto.randomUUID();
    const timestamp = new Date().toISOString().replace(/[:.]/g, "").slice(0, 15);
    const filename = `backup_${timestamp}_${id.slice(0, 8)}.json`;
    const rooms = db.listRooms();
    const dbSettings = db.getAllSettings();
    for (const k of ['encryption_key', 'instancePasswordHash', 'admin_password_hash']) delete (dbSettings as any)[k];
    const scene3d: Record<string, string> = {};
    for (const r of rooms) {
      const blob = db.exportScene3dForRoom((r as any).id);
      if (blob) scene3d[(r as any).id] = blob;
    }
    const backupData = { version: 2, timestamp: new Date().toISOString(), rooms, scene3d, settings: dbSettings };
    const content = JSON.stringify(backupData, null, 2);
    await Bun.write(join(BACKUPS_DIR, filename), content);
    const size = content.length;
    db.createBackupRecord({ id, filename, createdAt: new Date().toISOString(), sizeBytes: size, roomCount: rooms.length, autoGenerated });
    if (autoGenerated && settings.backupRetentionCount > 0) {
      const oldBackups = db.getOldAutoBackups(settings.backupRetentionCount);
      for (const backup of oldBackups) {
        const backupPath = join(BACKUPS_DIR, backup.filename);
        try { await unlink(backupPath); } catch {}
        db.deleteBackupRecord(backup.id);
      }
    }
    try {
      const pruned = db.pruneOrphanSceneCodes(SCENE3D_CODE_TTL_DAYS);
      if (pruned > 0) console.log(`[Backup] Pruned ${pruned} orphaned portable 3D scene code(s)`);
    } catch {  }
    return { id, filename, size };
  } catch (e: any) { console.error("[Backup]", e.message); return null; }
}

export function shouldImportScene3d(roomId: string): boolean {
  let raw: string | null = null;
  try { raw = db.getScene3d(roomId); } catch { return false; }
  if (!raw) return true;
  const trimmed = raw.trim();
  return trimmed === '' || trimmed === '{}';
}

export async function restoreBackup(backupId: string): Promise<{ success: boolean; error?: string; roomsRestored?: number }> {
  const backups = db.listBackups();
  const backup = backups.find(b => b.id === backupId);
  if (!backup) return { success: false, error: "Backup not found" };
  const backupPath = join(BACKUPS_DIR, backup.filename);
  const backupFile = Bun.file(backupPath);
  if (!await backupFile.exists()) return { success: false, error: "Backup file missing" };
  try {
    const content = await backupFile.text();
    const data = JSON.parse(content);
    if (!data.rooms || !Array.isArray(data.rooms)) return { success: false, error: "Invalid backup format" };
    let roomsRestored = 0;
    let scenesRestored = 0;
    for (const room of data.rooms) {
      const existing = db.getRoom(room.id);
      if (!existing) {
        if (room.topology) room.topology = sanitizeTopologyStrings(room.topology);
        db.createRoom(room);
        roomsRestored++;
      }
      if (shouldImportScene3d(room.id)) {
        const blob = data.scene3d && typeof data.scene3d === "object" ? data.scene3d[room.id] : null;
        if (blob && typeof blob === "string") {
          try {
            const parsed = JSON.parse(blob);
            const code = parsed && typeof parsed.code === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(parsed.code)
              ? parsed.code : null;
            const clean = sanitizeScene3d(parsed);
            if (clean) { db.importScene3dForRoom(room.id, JSON.stringify(code ? { ...clean, code } : clean)); scenesRestored++; }
          } catch {  }
        }
      }
    }
    if (scenesRestored > 0) console.log(`[Backup] Restored ${scenesRestored} 3D scene(s)`);
    return { success: true, roomsRestored };
  } catch (e: any) { console.error("[Backup]", e.message); return { success: false, error: "Failed to parse backup" }; }
}

export function getBackupsDir(): string {
  return BACKUPS_DIR;
}

let backupTimer: Timer | null = null;

export function restartBackupTimer(): void {
  const settings = getSettings();
  if (backupTimer) clearInterval(backupTimer);
  backupTimer = null;
  if (settings.backupEnabled && settings.backupIntervalHours > 0) {
    backupTimer = setInterval(() => { createBackup(true); }, settings.backupIntervalHours * 60 * 60 * 1000);
    if (typeof (backupTimer as any).unref === 'function') (backupTimer as any).unref();
    console.log(`[Backup] Auto backup every ${settings.backupIntervalHours} hours`);
  }
}

export function clearBackupTimer(): void {
  if (backupTimer) clearInterval(backupTimer);
  backupTimer = null;
}
