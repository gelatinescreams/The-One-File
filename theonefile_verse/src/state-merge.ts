
const SEP = "\u001f";
const MAPS = ["nodeData", "nodePositions", "nodeSizes", "nodeStyles", "edgeLegend"];
const LISTS = ["edgeData", "rectData", "textData", "imageData"];
const COLLS = MAPS.concat(LISTS);
const TAB_FIELD: Record<string, string> = {
  nodeData: "nodes", nodePositions: "positions", nodeSizes: "sizes", nodeStyles: "styles", edgeLegend: "legend",
  edgeData: "edges", rectData: "rects", textData: "texts", imageData: "images",
};
const TOP_SKIP = new Set(["documentTabs", "currentTabIndex", "tabVersions", ...COLLS]);
export const MAX_CHANGED_KEYS = 50000;

const isObj = (v: any) => !!v && typeof v === "object" && !Array.isArray(v);
const clone = (v: any) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
const own = (o: any, k: string) => !!o && Object.prototype.hasOwnProperty.call(o, k);

function items(state: any, coll: string): Record<string, any> {
  const o = state && state[coll];
  if (LISTS.includes(coll)) {
    const m: Record<string, any> = {};
    for (const it of (o && Array.isArray(o.list)) ? o.list : []) if (it && it.id != null) m[String(it.id)] = it;
    return m;
  }
  return isObj(o) ? o : {};
}

function setItem(out: any, coll: string, id: string, val: any): void {
  if (LISTS.includes(coll)) {
    if (!isObj(out[coll]) || !Array.isArray(out[coll].list)) out[coll] = { ...(isObj(out[coll]) ? out[coll] : {}), list: [] };
    const list = out[coll].list as any[];
    const idx = list.findIndex((x) => x && String(x.id) === id);
    if (val === undefined) { if (idx >= 0) list.splice(idx, 1); }
    else if (idx >= 0) list[idx] = val; else list.push(val);
  } else {
    if (!isObj(out[coll])) out[coll] = {};
    if (val === undefined) delete out[coll][id]; else out[coll][id] = val;
  }
}

export function validChangedKeys(changed: unknown): string[] | null {
  if (!Array.isArray(changed) || changed.length > MAX_CHANGED_KEYS) return null;
  const out: string[] = [];
  for (const k of changed) {
    if (typeof k !== "string" || k.length > 512) return null;
    const p = k.split(SEP);
    if (p.length !== 3 || p[1] === "" || p[1] === "__proto__" || p[2] === "__proto__") return null;
    if (p[0] === "__top") { if (p[2] !== "*" || TOP_SKIP.has(p[1]) || !/^[A-Za-z0-9_]+$/.test(p[1])) return null; }
    else if (p[0] === "__tab") { if (p[2] !== "*") return null; }
    else if (p[0] === "__tabs") { if (p[1] !== "order" || p[2] !== "*") return null; }
    else if (!COLLS.includes(p[0])) return null;
    out.push(k);
  }
  return out;
}

const tabIdOf = (t: any, i: number) => (t && t.id != null ? String(t.id) : `#${i}`);
function curTabId(state: any): string {
  const i = typeof state?.currentTabIndex === "number" ? state.currentTabIndex : 0;
  const tabs = Array.isArray(state?.documentTabs) ? state.documentTabs : [];
  return tabIdOf(tabs[i], i);
}

export function mergeChangedOntoStored(stored: any, incoming: any, changed: string[]): any | null {
  if (!isObj(stored) || !isObj(incoming)) return null;
  const set = new Set(changed);
  const out = clone(incoming);
  const senderCur = curTabId(incoming);
  const storedCur = curTabId(stored);
  const inTabs: any[] = Array.isArray(incoming.documentTabs) ? incoming.documentTabs : [];
  const stTabs: any[] = Array.isArray(stored.documentTabs) ? stored.documentTabs : [];
  const inMap = new Map(inTabs.map((t, i) => [tabIdOf(t, i), t]));
  const stMap = new Map(stTabs.map((t, i) => [tabIdOf(t, i), t]));

  if (inTabs.length || stTabs.length) {
    const order = set.has(`__tabs${SEP}order${SEP}*`) || !stTabs.length ? [...inMap.keys()] : [...stMap.keys()];
    if (!order.includes(senderCur)) return null;
    out.documentTabs = order.map((id) => {
      const takeIncoming = set.has(`__tab${SEP}${id}${SEP}*`) || !stMap.has(id);
      return clone(takeIncoming ? (inMap.get(id) ?? stMap.get(id)) : stMap.get(id));
    }).filter((t) => t !== undefined);
    out.currentTabIndex = out.documentTabs.findIndex((t: any, i: number) => tabIdOf(t, i) === senderCur);
    if (out.currentTabIndex < 0) return null;
    const inV = isObj(incoming.tabVersions) ? incoming.tabVersions : {};
    const stV = isObj(stored.tabVersions) ? stored.tabVersions : {};
    const versions: Record<string, any> = {};
    for (const id of order) {
      const v = set.has(`__tab${SEP}${id}${SEP}*`) || !own(stV, id) ? inV[id] : stV[id];
      if (v !== undefined) versions[id] = clone(v);
    }
    if (incoming.tabVersions !== undefined || stored.tabVersions !== undefined) out.tabVersions = versions;
  }

  let base: any = null;
  if (senderCur === storedCur) base = stored;
  else if (stMap.has(senderCur)) {
    const t = stMap.get(senderCur);
    base = {};
    for (const c of COLLS) if (t && t[TAB_FIELD[c]] !== undefined) base[c] = t[TAB_FIELD[c]];
  }
  if (base) {
    for (const c of COLLS) if (base[c] !== undefined) out[c] = clone(base[c]);
    const ordered = changed.filter((k) => COLLS.includes(k.split(SEP)[0]))
      .sort((a, b) => (a.split(SEP)[2] === "" ? 0 : 1) - (b.split(SEP)[2] === "" ? 0 : 1));
    for (const k of ordered) {
      const [c, id, f] = k.split(SEP);
      const src = items(incoming, c)[id];
      if (f === "" || f === "*") { setItem(out, c, id, clone(src)); continue; }
      const dst = items(out, c)[id];
      if (!isObj(dst) || !isObj(src)) continue;
      if (own(src, f)) dst[f] = clone(src[f]); else delete dst[f];
    }
  }

  const keys = new Set([...Object.keys(stored), ...Object.keys(incoming)]);
  for (const k of keys) {
    if (TOP_SKIP.has(k) || k === "__proto__") continue;
    if (set.has(`__top${SEP}${k}${SEP}*`) || !own(stored, k)) { if (own(incoming, k)) out[k] = clone(incoming[k]); else delete out[k]; }
    else out[k] = clone(stored[k]);
  }

  const ti = out.currentTabIndex;
  if (Array.isArray(out.documentTabs) && isObj(out.documentTabs[ti])) {
    for (const c of COLLS) if (out[c] !== undefined) out.documentTabs[ti][TAB_FIELD[c]] = clone(out[c]);
    const inV = isObj(incoming.tabVersions) ? incoming.tabVersions : null;
    if (inV && inV[senderCur] !== undefined) {
      if (!isObj(out.tabVersions)) out.tabVersions = {};
      out.tabVersions[senderCur] = clone(inV[senderCur]);
    }
  }
  return out;
}
