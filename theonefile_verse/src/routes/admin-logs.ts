import * as db from "../database";
import { getClientIP, validateAdminOrApiKey } from "../security";

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  if (path === "/api/admin/audit-logs" && req.method === "GET") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "read");
    if (!user && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const query = url.searchParams.get("q") || "";
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "100") || 100, 1000);
    const offset = parseInt(url.searchParams.get("offset") || "0");
    const logs = query ? db.searchAuditLogs(query, limit, offset) : db.getAuditLogs(limit, offset);
    return Response.json({ logs }, { headers: corsHeaders });
  }

  if (path === "/api/admin/audit-logs" && req.method === "DELETE") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "admin");
    if (!user && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    db.clearAuditLogs();
    return Response.json({ success: true }, { headers: corsHeaders });
  }

  if (path === "/api/admin/activity-logs" && req.method === "GET") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "read");
    if (!user && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const roomId = url.searchParams.get("room") || "";
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "100") || 100, 1000);
    const offset = parseInt(url.searchParams.get("offset") || "0");
    const logs = roomId ? db.getActivityLogs(roomId, limit, offset) : db.getAllActivityLogs(limit, offset);
    return Response.json({ logs }, { headers: corsHeaders });
  }

  if (path === "/api/admin/activity-logs" && req.method === "DELETE") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "admin");
    if (!user && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const actor = user ? (user.email || "admin") : `apikey:${apiKey!.name}`;
    db.clearActivityLogs();
    db.addAuditLog({ timestamp: new Date().toISOString(), action: "activity_logs_cleared", actor, actorIp: getClientIP(req) });
    return Response.json({ success: true }, { headers: corsHeaders });
  }

  return null;
}
