import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync, unlinkSync } from "fs";
import { join, dirname } from "path";
import { DATA_DIR, getMaxAssetsPerRoomBytes, getMaxAssetsTotalBytes } from "./config";
import * as db from "./database";

const ASSETS_DIR = join(DATA_DIR, "assets");
let tmpCounter = 0;

const HEX64 = /^[0-9a-f]{64}$/;
function validHash(hash: string): boolean { return typeof hash === "string" && HEX64.test(hash); }

export function assetPath(hash: string): string {
  if (!validHash(hash)) throw new Error("invalid asset hash");
  return join(ASSETS_DIR, hash.slice(0, 2), hash.slice(2, 4), hash);
}

export function blobExists(hash: string): boolean {
  return validHash(hash) && existsSync(assetPath(hash));
}

export function readBlob(hash: string): Buffer | null {
  if (!validHash(hash)) return null;
  const p = assetPath(hash);
  return existsSync(p) ? readFileSync(p) : null;
}

export function writeBlob(hash: string, bytes: Uint8Array): void {
  if (!validHash(hash)) return;
  const p = assetPath(hash);
  if (existsSync(p)) return;
  mkdirSync(dirname(p), { recursive: true });
  const tmp = `${p}.tmp-${process.pid}-${tmpCounter++}`;
  writeFileSync(tmp, bytes);
  try {
    renameSync(tmp, p);
  } catch (e) {
    try { unlinkSync(tmp); } catch {  }
    if (!existsSync(p)) throw e;
  }
}

export function deleteBlob(hash: string): void {
  if (!validHash(hash)) return;
  const p = assetPath(hash);
  try {
    if (existsSync(p)) unlinkSync(p);
  } catch {  }
}


export interface QuotaResult {
  ok: boolean;
  reason?: "room" | "instance";
  error?: string;
  roomBytes?: number;
  roomLimit?: number;
  totalBytes?: number;
  totalLimit?: number;
}

export function checkAssetQuota(roomId: string, bytes: number): QuotaResult {
  const size = Number(bytes);
  if (!Number.isFinite(size) || size < 0) return { ok: false, reason: "room", error: "Invalid asset size" };

  const roomLimit = getMaxAssetsPerRoomBytes();
  const totalLimit = getMaxAssetsTotalBytes();

  if (roomLimit > 0) {
    const roomBytes = db.getRoomAssetBytes(roomId);
    if (roomBytes + size > roomLimit) {
      return {
        ok: false, reason: "room", roomBytes, roomLimit,
        error: `This room's asset storage limit (${Math.round(roomLimit / (1024 * 1024))} MB) has been reached`
      };
    }
  }
  if (totalLimit > 0) {
    const totalBytes = db.getTotalAssetBytes();
    if (totalBytes + size > totalLimit) {
      return {
        ok: false, reason: "instance", totalBytes, totalLimit,
        error: "The instance asset storage limit has been reached"
      };
    }
  }
  return { ok: true };
}


export const ASSET_GC_GRACE_MS = 24 * 60 * 60 * 1000;

export interface SweepResult {
  scanned: number;
  stamped: number;
  deleted: number;
  retainedBySnapshot: number;
  errors: number;
}

export function sweepOrphanAssets(graceMs: number = ASSET_GC_GRACE_MS): SweepResult {
  const result: SweepResult = { scanned: 0, stamped: 0, deleted: 0, retainedBySnapshot: 0, errors: 0 };
  const now = Date.now();
  try {
    result.stamped = db.markUnreferencedAssets(new Date(now).toISOString());
    const cutoff = new Date(now - Math.max(0, graceMs)).toISOString();
    const candidates = db.getSweepableAssets(cutoff);
    result.scanned = candidates.length;
    if (candidates.length === 0) return result;

    const pinned = db.getSceneByCodeAssetHashes();
    for (const h of db.getScene3dAssetHashes()) pinned.add(h);

    for (const a of candidates) {
      if (pinned.has(a.hash)) { result.retainedBySnapshot++; continue; }
      try {
        db.deleteAssetRow(a.hash);
        deleteBlob(a.hash);
        result.deleted++;
      } catch (e: any) {
        result.errors++;
        console.error("[Assets] Sweep failed for", a.hash.slice(0, 12), e?.message);
      }
    }
  } catch (e: any) {
    result.errors++;
    console.error("[Assets] Sweep aborted:", e?.message);
  }
  return result;
}

let sweepTimer: ReturnType<typeof setInterval> | null = null;

export function startAssetSweepInterval(intervalMs: number = 6 * 60 * 60 * 1000): void {
  if (sweepTimer) return;
  sweepTimer = setInterval(() => {
    const r = sweepOrphanAssets();
    if (r.deleted > 0 || r.errors > 0) {
      console.log(`[Assets] GC: deleted ${r.deleted}, kept ${r.retainedBySnapshot} (snapshot-referenced), errors ${r.errors}`);
    }
  }, intervalMs);
  (sweepTimer as any)?.unref?.();
}

export function stopAssetSweepInterval(): void {
  if (sweepTimer) { clearInterval(sweepTimer); sweepTimer = null; }
}

export function runAssetSweepNow(graceMs: number = ASSET_GC_GRACE_MS): SweepResult {
  return sweepOrphanAssets(graceMs);
}
