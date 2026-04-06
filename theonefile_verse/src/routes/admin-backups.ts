import { join } from "path";
import { unlink } from "fs/promises";
import * as db from "../database";
import { getClientIP, validateAdminOrApiKey } from "../security";
import { securityHeaders } from "../security";
import { createBackup, restoreBackup, getBackupsDir } from "../rooms";

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  if (path === "/api/admin/backups" && req.method === "GET") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "read");
    if (!user && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const backups = db.listBackups();
    return Response.json({ backups }, { headers: corsHeaders });
  }

  if (path === "/api/admin/backups" && req.method === "POST") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "write");
    if (!user && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const result = await createBackup(false);
    if (result) {
      const actor = user ? user.id : `apikey:${apiKey!.name}`;
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "backup_created", actor, actorIp: getClientIP(req), targetType: "backup", targetId: result.id });
      return Response.json({ success: true, backup: result }, { headers: corsHeaders });
    }
    return Response.json({ error: "Failed to create backup" }, { status: 500, headers: corsHeaders });
  }

  if (path.match(/^\/api\/admin\/backups\/[\w-]+\/restore$/) && req.method === "POST") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "admin");
    if (!user && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const backupId = path.split("/")[4];
    const result = await restoreBackup(backupId);
    if (result.success) {
      const actor = user ? user.id : `apikey:${apiKey!.name}`;
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "backup_restored", actor, actorIp: getClientIP(req), targetType: "backup", targetId: backupId, details: { roomsRestored: result.roomsRestored } });
    }
    return Response.json(result, { headers: corsHeaders });
  }

  if (path.match(/^\/api\/admin\/backups\/[\w-]+\/download$/) && req.method === "GET") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "read");
    if (!user && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const backupId = path.split("/")[4];
    const backups = db.listBackups();
    const backup = backups.find(b => b.id === backupId);
    if (!backup) return Response.json({ error: "Backup not found" }, { status: 404, headers: corsHeaders });
    const BACKUPS_DIR = getBackupsDir();
    const backupPath = join(BACKUPS_DIR, backup.filename);
    const backupFile = Bun.file(backupPath);
    if (!await backupFile.exists()) return Response.json({ error: "Backup file missing" }, { status: 404, headers: corsHeaders });
    return new Response(backupFile, { headers: { "Content-Type": "application/json", "Content-Disposition": `attachment; filename="${backup.filename}"`, ...securityHeaders } });
  }

  if (path.match(/^\/api\/admin\/backups\/[\w-]+$/) && req.method === "DELETE") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "admin");
    if (!user && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const backupId = path.split("/")[4];
    const backups = db.listBackups();
    const backup = backups.find(b => b.id === backupId);
    if (!backup) return Response.json({ error: "Backup not found" }, { status: 404, headers: corsHeaders });
    const BACKUPS_DIR = getBackupsDir();
    const backupPath = join(BACKUPS_DIR, backup.filename);
    try { await unlink(backupPath); } catch {}
    db.deleteBackupRecord(backupId);
    const actor = user ? user.id : `apikey:${apiKey!.name}`;
    db.addAuditLog({ timestamp: new Date().toISOString(), action: "backup_deleted", actor, actorIp: getClientIP(req), targetType: "backup", targetId: backupId });
    return Response.json({ deleted: true }, { headers: corsHeaders });
  }

  return null;
}
