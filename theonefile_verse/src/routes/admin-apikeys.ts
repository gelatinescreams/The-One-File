import * as db from "../database";
import { getClientIP, apiError, validateAdminOrApiKey } from "../security";
import { securityHeaders } from "../security";
import { hashApiKey } from "../tokens";

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  if (path === "/api/admin/api-keys" && req.method === "GET") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "admin");
    if (!user && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const keys = db.listApiKeys();
    return Response.json({ keys }, { headers: corsHeaders });
  }

  if (path === "/api/admin/api-keys" && req.method === "POST") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "admin");
    if (!user && !apiKey) {
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
      const actor = user ? user.id : `apikey:${apiKey!.name}`;
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "api_key_created", actor, actorIp: getClientIP(req), targetType: "api_key", targetId: id, details: { name: body.name } });
      return Response.json({ id, key: rawKey, name: body.name, permissions, expiresAt }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path.match(/^\/api\/admin\/api-keys\/[\w-]+$/) && req.method === "DELETE") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "admin");
    if (!user && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const keyId = path.split("/")[4];
    if (db.deactivateApiKey(keyId)) {
      const actor = user ? user.id : `apikey:${apiKey!.name}`;
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "api_key_revoked", actor, actorIp: getClientIP(req), targetType: "api_key", targetId: keyId });
      return Response.json({ revoked: true }, { headers: corsHeaders });
    }
    return Response.json({ error: "API key not found" }, { status: 404, headers: corsHeaders });
  }

  if (path === "/api/admin/export" && req.method === "GET") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "read");
    if (!user && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const rooms = db.listRooms();
    const settings = db.getAllSettings();
    const exportData = { version: 1, exportedAt: new Date().toISOString(), rooms, settings };
    const actor = user ? user.id : `apikey:${apiKey!.name}`;
    db.addAuditLog({ timestamp: new Date().toISOString(), action: "data_exported", actor, actorIp: getClientIP(req), details: { roomCount: rooms.length } });
    return new Response(JSON.stringify(exportData, null, 2), { headers: { "Content-Type": "application/json", "Content-Disposition": `attachment; filename="theonefile_export_${new Date().toISOString().slice(0, 10)}.json"`, ...securityHeaders } });
  }

  return null;
}
