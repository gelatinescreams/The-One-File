const UNSAFE_ID_CHAR = /['"\\`<>&\u0000-\u001f\u007f\u2028\u2029]/;
const UNSAFE_ID_CHARS = /['"\\`<>&\u0000-\u001f\u007f\u2028\u2029]/g;
const ID_VALUE_KEY = /^(id|from|to|assignedRack)$|[a-z]Id$/;
const ID_KEYED_MAPS = new Set(["nodeData", "nodePositions", "nodeSizes", "nodeStyles", "nodes", "positions", "sizes", "styles", "tabVersions"]);
const COLOR_KEY = /(colou?r|fill|stroke)$/i;
const COLOR_EXACT_KEYS = new Set(["background", "bg", "circleBorder", "groupIndicator", "selectionHandle"]);
const HEX_COLOR = /^#[0-9a-fA-F]{3,8}$/;
const NAMED_COLOR = /^[a-zA-Z]{1,40}$/;
const SAFE_COLOR_INNER = "[#a-zA-Z0-9\\s,.%\\/+-]*";
const FUNC_COLOR = new RegExp(`^(rgb|rgba|hsl|hsla|hwb|lab|lch|oklab|oklch|color|color-mix|var|url|linear-gradient|radial-gradient|conic-gradient)\\(${SAFE_COLOR_INNER}(\\(${SAFE_COLOR_INNER}\\)${SAFE_COLOR_INNER})*\\)$`, "i");
const RECORDING_TEXT_STRIP = /['"\\`<>&\u0000-\u001f\u007f\u2028\u2029]/g;
const ISO_ISH = /^[0-9TZ:.+\- ]{1,40}$/;
const MAX_WALK_DEPTH = 40;

export function isSafeId(id: string): boolean {
  return !UNSAFE_ID_CHAR.test(id);
}

function fnv1a(str: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

export function remapUnsafeId(id: string): string {
  return id.replace(UNSAFE_ID_CHARS, "_") + "_" + fnv1a(id);
}

export function isSafeColor(value: string): boolean {
  const v = value.trim();
  if (v === "") return true;
  if (v.length > 200) return false;
  return HEX_COLOR.test(v) || NAMED_COLOR.test(v) || FUNC_COLOR.test(v);
}

function collectUnsafeIds(node: any, parentKey: string, out: Set<string>, depth: number): void {
  if (depth > MAX_WALK_DEPTH || node === null || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const item of node) collectUnsafeIds(item, parentKey, out, depth + 1);
    return;
  }
  const keyed = ID_KEYED_MAPS.has(parentKey);
  for (const key of Object.keys(node)) {
    if (keyed && !isSafeId(key)) out.add(key);
    const v = node[key];
    if (typeof v === "string") {
      if (ID_VALUE_KEY.test(key) && !isSafeId(v)) out.add(v);
    } else if (v && typeof v === "object") {
      collectUnsafeIds(v, key, out, depth + 1);
    }
  }
}

function rewriteIds(node: any, unsafe: Set<string>, depth: number): any {
  if (depth > MAX_WALK_DEPTH) return node;
  if (typeof node === "string") return unsafe.has(node) ? remapUnsafeId(node) : node;
  if (node === null || typeof node !== "object") return node;
  if (Array.isArray(node)) return node.map(item => rewriteIds(item, unsafe, depth + 1));
  const out: any = {};
  for (const key of Object.keys(node)) {
    if (key === "__proto__") continue;
    const nextKey = unsafe.has(key) ? remapUnsafeId(key) : key;
    out[nextKey] = rewriteIds(node[key], unsafe, depth + 1);
  }
  return out;
}

function scrubColors(node: any, depth: number): number {
  if (depth > MAX_WALK_DEPTH || node === null || typeof node !== "object") return 0;
  let changed = 0;
  if (Array.isArray(node)) {
    for (const item of node) changed += scrubColors(item, depth + 1);
    return changed;
  }
  for (const key of Object.keys(node)) {
    const v = node[key];
    if (typeof v === "string") {
      if ((COLOR_KEY.test(key) || COLOR_EXACT_KEYS.has(key)) && !isSafeColor(v)) {
        node[key] = "";
        changed++;
      }
    } else if (v && typeof v === "object") {
      changed += scrubColors(v, depth + 1);
    }
  }
  return changed;
}

function cleanRecordingText(value: unknown, fallback: string, max: number): string {
  if (typeof value !== "string") return fallback;
  const cleaned = value.replace(/&lt;/g, "").replace(/&gt;/g, "").replace(/&amp;/g, "").replace(/&quot;/g, "").replace(/&#0?39;/g, "").replace(RECORDING_TEXT_STRIP, "").slice(0, max);
  return cleaned || fallback;
}

export function normalizeRecordings(list: unknown): any[] | undefined {
  if (list === undefined) return undefined;
  if (!Array.isArray(list)) return [];
  const out: any[] = [];
  list.forEach((rec, i) => {
    if (!rec || typeof rec !== "object" || Array.isArray(rec)) return;
    const r: any = { ...rec };
    if (typeof r.id === "number" && Number.isFinite(r.id)) r.id = String(r.id);
    if (typeof r.id !== "string" || !r.id) return;
    if (!isSafeId(r.id)) r.id = remapUnsafeId(r.id);
    r.name = cleanRecordingText(r.name, `Recording ${i + 1}`, 200);
    r.duration = typeof r.duration === "number" && Number.isFinite(r.duration) && r.duration >= 0 ? r.duration : 0;
    if (!(typeof r.created === "number" && Number.isFinite(r.created))) {
      r.created = typeof r.created === "string" && ISO_ISH.test(r.created) ? r.created : "";
    }
    r.frames = Array.isArray(r.frames) ? r.frames : [];
    out.push(r);
  });
  return out;
}

export interface ShapeReport { remappedIds: number; scrubbedColors: number }

export function enforceTopologyShape(topology: any, report?: ShapeReport): any {
  if (!topology || typeof topology !== "object" || Array.isArray(topology)) return topology;
  const unsafe = new Set<string>();
  collectUnsafeIds(topology, "", unsafe, 0);
  let out = unsafe.size ? rewriteIds(topology, unsafe, 0) : topology;
  const scrubbed = scrubColors(out, 0);
  if (out.recordings !== undefined) out.recordings = normalizeRecordings(out.recordings);
  if (report) { report.remappedIds = unsafe.size; report.scrubbedColors = scrubbed; }
  return out;
}
