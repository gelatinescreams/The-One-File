import { existsSync, mkdirSync } from "fs";
import { unlink } from "fs/promises";
import { join } from "path";
import * as db from "./database";
import * as redis from "./redis";
import * as auth from "./auth";
import { DATA_DIR, ROOMS_DIR, getSettings, updateSettings, isValidUUID, type InstanceSettings } from "./config";

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

export function deleteRoomData(id: string): boolean {
  const result = db.deleteRoom(id);
  if (result) {
    roomMeta.delete(id);
    roomUsedNames.delete(id);
    roomChatHistory.delete(id);
    if (redis.isRedisConnected()) {
      redis.deleteRoomStateCache(id);
    }
  }
  return result;
}

export function scheduleDestruction(roomId: string, delayMs: number): void {
  const meta = roomMeta.get(roomId) || { connectedUsers: 0 };
  if (meta.destructTimer) clearTimeout(meta.destructTimer);
  meta.destructTimer = setTimeout(() => {
    const room = loadRoom(roomId);
    if (room && room.destruct.mode === "time") {
      console.log(`[Room] ${roomId} self destructed`);
      deleteRoomData(roomId);
    }
  }, delayMs);
  roomMeta.set(roomId, meta);
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

export async function fetchLatestFromGitHub(): Promise<boolean> {
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
    updateTimer = setInterval(() => { fetchLatestFromGitHub(); }, settings.updateIntervalHours * 60 * 60 * 1000);
    console.log(`[Update] Auto update every ${settings.updateIntervalHours} hours`);
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
  let decoded = url
    .replace(/&#x([0-9a-f]+);?/gi, (_: string, h: string) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&#(\d+);?/gi, (_: string, d: string) => String.fromCharCode(parseInt(d, 10)))
    .replace(/[\t\n\r\x00]/g, '');
  const clean = decoded.replace(/\s/g, '').toLowerCase();
  if (clean.startsWith('javascript:') || clean.startsWith('vbscript:')) return '';
  if (clean.startsWith('data:') && !/^data:image\/(png|jpe?g|gif|webp|bmp|ico)/i.test(clean)) return 'data:blocked';
  return url;
}

export function sanitizeHtmlString(str: string): string {
  if (typeof str !== 'string') return str;
  return str.replace(/<\/?([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)?\/?>/g, (match, tagName, attrsStr) => {
    const tag = tagName.toLowerCase();
    const isClosing = match.startsWith('</');
    if (!ALLOWED_TAGS.has(tag)) return '';
    if (isClosing) return `</${tag}>`;
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
    return selfClosing ? `<${tag}${safeAttrs} />` : `<${tag}${safeAttrs}>`;
  });
}

export function sanitizeTopologyStrings(obj: any): any {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return sanitizeHtmlString(obj);
  if (Array.isArray(obj)) return obj.map(sanitizeTopologyStrings);
  if (typeof obj === 'object') {
    const result: any = {};
    for (const key of Object.keys(obj)) {
      result[key] = sanitizeTopologyStrings(obj[key]);
    }
    return result;
  }
  return obj;
}

export function validateTopology(topology: any): TopologyValidationResult {
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
  return { valid: true, sanitized: sanitizeTopologyStrings(topology) };
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
    console.error('[Webhook] Blocked request to disallowed URL:', settings.webhookUrl);
    return;
  }
  try {
    await fetch(settings.webhookUrl, {
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

export async function createBackup(autoGenerated: boolean = false): Promise<{ id: string; filename: string; size: number } | null> {
  try {
    const settings = getSettings();
    const id = crypto.randomUUID();
    const timestamp = new Date().toISOString().replace(/[:.]/g, "").slice(0, 15);
    const filename = `backup_${timestamp}_${id.slice(0, 8)}.json`;
    const rooms = db.listRooms();
    const dbSettings = db.getAllSettings();
    const backupData = { version: 1, timestamp: new Date().toISOString(), rooms, settings: dbSettings };
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
    return { id, filename, size };
  } catch (e: any) { console.error("[Backup]", e.message); return null; }
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
    for (const room of data.rooms) {
      const existing = db.getRoom(room.id);
      if (!existing) {
        if (room.topology) room.topology = sanitizeTopologyStrings(room.topology);
        db.createRoom(room);
        roomsRestored++;
      }
    }
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
    console.log(`[Backup] Auto backup every ${settings.backupIntervalHours} hours`);
  }
}

export function clearBackupTimer(): void {
  if (backupTimer) clearInterval(backupTimer);
  backupTimer = null;
}
