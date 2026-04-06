import * as auth from "../auth";
import * as db from "../database";
import { getClientIP, apiError, validateAdminUser } from "../security";
import { getExternalOrigin } from "../config";

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  if (path === "/api/admin/users" && req.method === "GET") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const searchQuery = url.searchParams.get("q") || "";
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "100") || 100, 1000);
    const offset = parseInt(url.searchParams.get("offset") || "0");
    const users = searchQuery ? db.searchUsers(searchQuery, limit, offset) : db.listUsers(limit, offset);
    const safeUsers = users.map(u => {
      const { passwordHash, totpSecret, totpBackupCodes, pendingEmailToken, ...safe } = u;
      return safe;
    });
    return Response.json({ users: safeUsers, total: db.countUsers() }, { headers: corsHeaders });
  }

  if (path === "/api/admin/users" && req.method === "POST") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      const result = await auth.adminCreateUser(body.email, body.password, body.displayName, body.role || 'user');
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
      }
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "user_created", actor: adminUser.id, actorIp: getClientIP(req), targetType: "user", targetId: result.userId });
      return Response.json({ success: true, userId: result.userId }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path.match(/^\/api\/admin\/users\/[\w-]+$/) && req.method === "PUT") {
    const userId = path.split("/")[4];
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      const result = auth.adminUpdateUser(userId, body);
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
      }
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "user_updated", actor: adminUser.id, actorIp: getClientIP(req), targetType: "user", targetId: userId, details: body });
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path.match(/^\/api\/admin\/users\/[\w-]+\/reset-password$/) && req.method === "POST") {
    const userId = path.split("/")[4];
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const user = db.getUserById(userId);
      if (!user) {
        return Response.json({ error: "User not found" }, { status: 404, headers: corsHeaders });
      }
      if (!user.email) {
        return Response.json({ error: "User has no email address" }, { status: 400, headers: corsHeaders });
      }
      const baseUrl = getExternalOrigin(req);
      await auth.requestPasswordReset(user.email, baseUrl);
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "user_password_reset_sent", actor: adminUser.id, actorIp: getClientIP(req), targetType: "user", targetId: userId });
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders, "Failed to send reset email", 500); }
  }

  if (path.match(/^\/api\/admin\/users\/[\w-]+\/set-password$/) && req.method === "POST") {
    const userId = path.split("/")[4];
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (!body.password || typeof body.password !== 'string') {
        return Response.json({ error: "Password is required" }, { status: 400, headers: corsHeaders });
      }
      const result = await auth.adminResetPassword(userId, body.password);
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
      }
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "user_password_set", actor: adminUser.id, actorIp: getClientIP(req), targetType: "user", targetId: userId });
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path.match(/^\/api\/admin\/users\/[\w-]+$/) && req.method === "DELETE") {
    const userId = path.split("/")[4];
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const result = auth.adminDeleteUser(userId);
    if (!result.success) {
      return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
    }
    db.addAuditLog({ timestamp: new Date().toISOString(), action: "user_deleted", actor: adminUser.id, actorIp: getClientIP(req), targetType: "user", targetId: userId });
    return Response.json({ success: true }, { headers: corsHeaders });
  }

  return null;
}
