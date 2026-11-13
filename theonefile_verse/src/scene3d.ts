
export const SCENE3D_FURN_KINDS = new Set(["table", "shelf", "lamp", "wall", "plant", "frame", "model"]);
export const SCENE3D_MAX_FURNITURE = 2000;
export const SCENE3D_MAX_MAP_KEYS = 2000;
export const SCENE3D_MAX_TABS = 32;
export const SCENE3D_MAX_TOTAL_FURNITURE = 8000;
export const SCENE3D_MAX_TOTAL_MAP_KEYS = 24000;
export const SCENE3D_WORLD_W = 20000, SCENE3D_WORLD_D = 15000;
export const SCENE3D_MAX_ELEVATION = 3000;
export const SCENE3D_MIN_WALL_HEIGHT = 4;
export const SCENE3D_MAX_WALL_HEIGHT = 3000;
const TWO_PI = Math.PI * 2;
export const SCENE3D_LEGACY_TAB = "__legacy";
export const SCENE3D_CODE_TTL_DAYS = (() => {
  const raw = process.env.SCENE3D_CODE_TTL_DAYS;
  if (raw === undefined || raw === null || String(raw).trim() === "") return 90;
  const s = String(raw).trim().toLowerCase();
  if (s === "off" || s === "false" || s === "no" || s === "disabled" || s === "never") return 0;
  const n = Number(s);
  if (!Number.isFinite(n)) return 90;
  return n > 0 ? Math.floor(n) : 0;
})();

function scene3dFinite(v: any, fb: number): number { const n = Number(v); return Number.isFinite(n) ? n : fb; }
function scene3dClamp(v: number, a: number, b: number): number { return Math.max(a, Math.min(b, v)); }
function scene3dWrapAngle(v: any): number {
  const n = Number(v);
  if (!Number.isFinite(n)) return 0;
  const m = n % TWO_PI;
  return m < 0 ? m + TWO_PI : m;
}

export interface Scene3dTab {
  furniture: any[]; heights: Record<string, number>; buried: Record<string, number>;
  wallHeights: Record<string, number>; rev: number;
  savedAt?: number;
}
export interface Scene3d { version: number; rev: number; mpu: number; wireMode: number; tabs: Record<string, Scene3dTab> }

export interface Scene3dMeta {
  truncated: boolean;
  droppedFurniture: number;
  droppedMapKeys: number;
  bodyTabs: string[];
  hadTabsKey: boolean;
  bodyRevs: Record<string, number | undefined>;
}

export function sanitizeTabKey(k: any): string | null {
  if (typeof k !== "string") return null;
  const s = k.slice(0, 64).replace(/[^A-Za-z0-9_.:#-]/g, "_");
  if (!s || s === "__proto__" || s === "constructor" || s === "prototype") return null;
  return s;
}

export function sanitizeSavedAt(v: any): number {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.min(Math.floor(n), Date.now());
}

export function sanitizeRev(v: any): number {
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.min(Math.floor(n), Number.MAX_SAFE_INTEGER);
}

function sanitizeTabBucket(src: any, budget: { furn: number; keys: number }, drop?: { furn: number; keys: number }): Scene3dTab | null {
  const arr = Array.isArray(src && src.furniture) ? src.furniture : [];
  if (arr.length > SCENE3D_MAX_FURNITURE * 8) return null;
  const furniture: any[] = [];
  let seen = 0;
  for (const f of arr) {
    seen++;
    if (furniture.length >= SCENE3D_MAX_FURNITURE || budget.furn <= 0) { if (drop) drop.furn += arr.length - (seen - 1); break; }
    if (!f || typeof f !== "object" || !SCENE3D_FURN_KINDS.has(f.kind)) { if (drop) drop.furn++; continue; }
    const item: any = {
      id: (typeof f.id === "string" && f.id) ? f.id.slice(0, 80) : ("f-s" + furniture.length),
      kind: f.kind,
      x: Math.round(scene3dClamp(scene3dFinite(f.x, 2000), 0, SCENE3D_WORLD_W)),
      z: Math.round(scene3dClamp(scene3dFinite(f.z, 1500), 0, SCENE3D_WORLD_D)),
      y: scene3dClamp(scene3dFinite(f.y, 0), -200, SCENE3D_MAX_ELEVATION),
      rotY: scene3dWrapAngle(f.rotY),
      scale: scene3dClamp(scene3dFinite(f.scale, 1), 0.2, 6),
    };
    if (typeof f.color === "string" && /^#?[0-9a-zA-Z]{1,20}$/.test(f.color)) item.color = f.color;
    if (typeof f.image === "string" && /^[0-9a-f]{64}$/.test(f.image)) item.image = f.image;
    if (typeof f.model === "string" && /^[0-9a-f]{64}$/.test(f.model)) item.model = f.model;
    furniture.push(item); budget.furn--;
  }
  const numMap = (raw: any, lo: number, hi: number): Record<string, number> => {
    const out: Record<string, number> = {};
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
    let c = 0;
    const keys = Object.keys(raw);
    for (const k of keys) {
      if (c >= SCENE3D_MAX_MAP_KEYS || budget.keys <= 0) { if (drop) drop.keys += keys.length - c; break; }
      c++;
      const v = Number(raw[k]);
      if (Number.isFinite(v)) { out[String(k).slice(0, 80)] = scene3dClamp(v, lo, hi); budget.keys--; }
      else if (drop) drop.keys++;
    }
    return out;
  };
  const heights = numMap(src && src.heights, 0, SCENE3D_MAX_ELEVATION);
  const buried: Record<string, number> = {};
  if (src && src.buried && typeof src.buried === "object" && !Array.isArray(src.buried)) {
    let bc = 0;
    const bkeys = Object.keys(src.buried);
    for (const k of bkeys) {
      if (bc >= SCENE3D_MAX_MAP_KEYS || budget.keys <= 0) { if (drop) drop.keys += bkeys.length - bc; break; }
      bc++;
      if (src.buried[k]) { buried[String(k).slice(0, 80)] = 1; budget.keys--; }
    }
  }
  const wallHeights = numMap(src && src.wallHeights, SCENE3D_MIN_WALL_HEIGHT, SCENE3D_MAX_WALL_HEIGHT);
  return { furniture, heights, buried, wallHeights, rev: sanitizeRev(src && src.rev), savedAt: sanitizeSavedAt(src && src.savedAt) };
}

export function emptyTab(): Scene3dTab { return { furniture: [], heights: {}, buried: {}, wallHeights: {}, rev: 0, savedAt: 0 }; }

export function bucketIsEmpty(b: Scene3dTab | null | undefined): boolean {
  if (!b) return true;
  return !b.furniture.length && !Object.keys(b.heights).length && !Object.keys(b.buried).length && !Object.keys(b.wallHeights).length;
}

export function sanitizeScene3dWithMeta(parsed: any): { scene: Scene3d; meta: Scene3dMeta } | null {
  const mpu = (typeof parsed.mpu === "number" && parsed.mpu >= 0 && parsed.mpu <= 1) ? parsed.mpu : 0;
  const wireMode = (Number.isInteger(parsed.wireMode) && parsed.wireMode >= 0 && parsed.wireMode <= 2) ? parsed.wireMode : 0;
  const budget = { furn: SCENE3D_MAX_TOTAL_FURNITURE, keys: SCENE3D_MAX_TOTAL_MAP_KEYS };
  const drop = { furn: 0, keys: 0 };
  const tabs: Record<string, Scene3dTab> = {};
  const bodyTabs: string[] = [];
  const bodyRevs: Record<string, number | undefined> = {};

  const rawTabs = parsed.tabs;
  const hadTabsKey = !!(rawTabs && typeof rawTabs === "object" && !Array.isArray(rawTabs));
  if (hadTabsKey) {
    const keys = Object.keys(rawTabs);
    if (keys.length > SCENE3D_MAX_TABS * 4) return null;
    let n = 0;
    for (const raw of keys) {
      if (n >= SCENE3D_MAX_TABS) break;
      const key = sanitizeTabKey(raw);
      if (!key || Object.prototype.hasOwnProperty.call(tabs, key)) continue;
      const bucket = sanitizeTabBucket(rawTabs[raw], budget, drop);
      if (!bucket) return null;
      tabs[key] = bucket; n++;
      bodyTabs.push(key);
      const r = rawTabs[raw] && (rawTabs[raw] as any).rev;
      bodyRevs[key] = (r === undefined || r === null) ? undefined : sanitizeRev(r);
    }
  }
  const hasFlat = Array.isArray(parsed.furniture) || (parsed.heights && typeof parsed.heights === "object")
    || (parsed.buried && typeof parsed.buried === "object") || (parsed.wallHeights && typeof parsed.wallHeights === "object");
  if (hasFlat && !Object.prototype.hasOwnProperty.call(tabs, SCENE3D_LEGACY_TAB)) {
    const bucket = sanitizeTabBucket(parsed, budget, drop);
    if (!bucket) return null;
    if (!bucketIsEmpty(bucket)) tabs[SCENE3D_LEGACY_TAB] = bucket;
  }
  if (!Object.keys(tabs).length) tabs[SCENE3D_LEGACY_TAB] = emptyTab();
  const scene: Scene3d = { version: 2, rev: sanitizeRev(parsed.rev), mpu, wireMode, tabs };
  const meta: Scene3dMeta = {
    truncated: drop.furn > 0 || drop.keys > 0,
    droppedFurniture: drop.furn,
    droppedMapKeys: drop.keys,
    bodyTabs, hadTabsKey, bodyRevs,
  };
  return { scene, meta };
}

export function sanitizeScene3d(parsed: any): Scene3d | null {
  const r = sanitizeScene3dWithMeta(parsed);
  return r ? r.scene : null;
}

export function pickSnapshotTab(snapshot: Scene3d, tabKey: string | null): Scene3dTab | null {
  const t = snapshot && snapshot.tabs;
  if (!t) return null;
  if (tabKey && Object.prototype.hasOwnProperty.call(t, tabKey)) return t[tabKey];
  if (Object.prototype.hasOwnProperty.call(t, SCENE3D_LEGACY_TAB)) return t[SCENE3D_LEGACY_TAB];
  const keys = Object.keys(t);
  return keys.length ? t[keys[0]] : null;
}

export interface MergeResult {
  scene: Scene3d;
  conflicts: string[];
  revs: Record<string, number>;
  accepted: string[];
  dropped: BudgetDrop;
}

export interface BudgetDrop {
  furn: number;
  keys: number;
  byTab: Record<string, { furn: number; keys: number }>;
}

export function enforceSceneBudget(scene: Scene3d, protectedTabs?: string[] | Set<string>): BudgetDrop {
  let furnLeft = SCENE3D_MAX_TOTAL_FURNITURE, keysLeft = SCENE3D_MAX_TOTAL_MAP_KEYS;
  const dropped: BudgetDrop = { furn: 0, keys: 0, byTab: {} };
  const prot: Set<string> = protectedTabs instanceof Set ? protectedTabs : new Set(protectedTabs || []);
  const order = Object.keys(scene.tabs).sort((a, b) => {
    const pa = prot.has(a) ? 1 : 0, pb = prot.has(b) ? 1 : 0;
    if (pa !== pb) return pb - pa;
    const sa = sanitizeSavedAt(scene.tabs[a].savedAt), sb = sanitizeSavedAt(scene.tabs[b].savedAt);
    if (sa !== sb) return sb - sa;
    return a < b ? -1 : a > b ? 1 : 0;
  });
  for (const k of order) {
    const b = scene.tabs[k];
    const d = { furn: 0, keys: 0 };
    const trimMap = (m: Record<string, number>): Record<string, number> => {
      const mk = Object.keys(m);
      if (mk.length <= keysLeft) { keysLeft -= mk.length; return m; }
      const out: Record<string, number> = {};
      for (let i = 0; i < keysLeft; i++) out[mk[i]] = m[mk[i]];
      d.keys += mk.length - keysLeft;
      keysLeft = 0;
      return out;
    };
    if (b.furniture.length > furnLeft) { d.furn += b.furniture.length - furnLeft; b.furniture = b.furniture.slice(0, furnLeft); }
    furnLeft -= b.furniture.length;
    b.heights = trimMap(b.heights);
    b.buried = trimMap(b.buried);
    b.wallHeights = trimMap(b.wallHeights);
    if (d.furn || d.keys) { dropped.byTab[k] = d; dropped.furn += d.furn; dropped.keys += d.keys; }
  }
  return dropped;
}

export function mergeScene3d(stored: Scene3d | null, incoming: Scene3d, meta: Scene3dMeta): MergeResult {
  const base: Scene3d = stored
    ? { version: 2, rev: sanitizeRev(stored.rev), mpu: stored.mpu, wireMode: stored.wireMode, tabs: { ...stored.tabs } }
    : { version: 2, rev: 0, mpu: 0, wireMode: 0, tabs: {} };
  base.mpu = incoming.mpu;
  base.wireMode = incoming.wireMode;

  const now = Date.now();
  const conflicts: string[] = [];
  const accepted: string[] = [];
  const revs: Record<string, number> = {};

  const addressed = meta.bodyTabs.length ? meta.bodyTabs.slice() : Object.keys(incoming.tabs);
  if (!meta.hadTabsKey && Object.prototype.hasOwnProperty.call(incoming.tabs, SCENE3D_LEGACY_TAB)
    && addressed.indexOf(SCENE3D_LEGACY_TAB) < 0) addressed.push(SCENE3D_LEGACY_TAB);

  for (const k of addressed) {
    const inc = incoming.tabs[k];
    if (!inc) continue;
    const cur = Object.prototype.hasOwnProperty.call(base.tabs, k) ? base.tabs[k] : null;
    const storedRev = cur ? sanitizeRev(cur.rev) : 0;
    const incRev = meta.bodyRevs[k] === undefined ? sanitizeRev(inc.rev) : (meta.bodyRevs[k] as number);
    if (!meta.hadTabsKey) {
      base.tabs[k] = { ...inc, rev: storedRev + 1, savedAt: now };
      revs[k] = storedRev + 1;
      accepted.push(k);
      continue;
    }
    if (incRev !== storedRev) {
      conflicts.push(k);
      revs[k] = storedRev;
      continue;
    }
    if (!cur && k !== SCENE3D_LEGACY_TAB && Object.keys(base.tabs).length >= SCENE3D_MAX_TABS) {
      conflicts.push(k);
      revs[k] = storedRev;
      continue;
    }
    base.tabs[k] = { ...inc, rev: storedRev + 1, savedAt: now };
    revs[k] = storedRev + 1;
    accepted.push(k);
  }
  if (accepted.length) base.rev = sanitizeRev(base.rev) + 1;
  if (!Object.keys(base.tabs).length) base.tabs[SCENE3D_LEGACY_TAB] = emptyTab();
  const dropped = enforceSceneBudget(base, accepted);
  return { scene: base, conflicts, revs, accepted, dropped };
}

export function storedIsPopulatedV2(stored: Scene3d | null): boolean {
  if (!stored || !stored.tabs) return false;
  for (const k of Object.keys(stored.tabs)) {
    if (k === SCENE3D_LEGACY_TAB) continue;
    if (!bucketIsEmpty(stored.tabs[k])) return true;
  }
  return false;
}
