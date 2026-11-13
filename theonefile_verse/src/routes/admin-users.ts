import * as auth from "../auth";
import * as db from "../database";
import { getClientIP, apiError, validateAdminUser, readJsonLimited, BodyTooLargeError } from "../security";
import { getEmailLinkOrigin } from "../config";
import { refreshUserSockets } from "../websocket";

const ROUTE_BODY_CAP = 64 * 1024;

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
      return { ...safe, pendingApproval: db.isPendingApproval(u.id) };
    });
    return Response.json({ users: safeUsers, total: db.countUsers() }, { headers: corsHeaders });
  }

  const decision = path.match(/^\/api\/admin\/users\/([\w-]+)\/(approve|reject)$/);
  if (decision && req.method === "POST") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    const target = db.getUserById(decision[1]);
    if (!target || !db.isPendingApproval(target.id)) return Response.json({ error: "No pending sign up for this user" }, { status: 404, headers: corsHeaders });
    db.setPendingApproval(target.id, false);
    if (decision[2] === "approve") {
      target.isActive = true;
      target.updatedAt = new Date().toISOString();
      db.updateUser(target);
    } else {
      db.deleteUser(target.id);
    }
    db.addAuditLog({ timestamp: new Date().toISOString(), action: decision[2] === "approve" ? "user_approved" : "user_rejected", actor: adminUser.id, actorIp: getClientIP(req), targetType: "user", targetId: target.id });
    return Response.json({ success: true }, { headers: corsHeaders });
  }

  if (path === "/api/admin/users" && req.method === "POST") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await readJsonLimited(req, ROUTE_BODY_CAP);
      const role = body.role || 'user';
      if (!auth.isValidRole(role)) {
        return Response.json({ error: "Invalid role" }, { status: 400, headers: corsHeaders });
      }
      const result = await auth.adminCreateUser(body.email, body.password, body.displayName, role);
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
      const body = await readJsonLimited(req, ROUTE_BODY_CAP);
      const updates: { displayName?: string; role?: 'admin' | 'user'; isActive?: boolean; emailVerified?: boolean } = {};
      if (typeof body.displayName === "string") updates.displayName = body.displayName;
      if (body.role !== undefined) {
        if (!auth.isValidRole(body.role)) {
          return Response.json({ error: "Invalid role" }, { status: 400, headers: corsHeaders });
        }
        updates.role = body.role;
      }
      if (typeof body.isActive === "boolean") updates.isActive = body.isActive;
      if (updates.isActive === true) db.setPendingApproval(path.split("/")[4], false);
      if (typeof body.emailVerified === "boolean") updates.emailVerified = body.emailVerified;
      const result = auth.adminUpdateUser(userId, updates);
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
      }
      refreshUserSockets(userId);
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "user_updated", actor: adminUser.id, actorIp: getClientIP(req), targetType: "user", targetId: userId, details: updates });
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
      const baseUrl = getEmailLinkOrigin("password reset");
      if (!baseUrl) {
        return Response.json({ error: "Set the public URL in instance settings before sending password reset emails." }, { status: 400, headers: corsHeaders });
      }
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
      const body = await readJsonLimited(req, ROUTE_BODY_CAP);
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

  if (path === "/api/admin/invites" && req.method === "GET") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    return Response.json({ invites: auth.listInvites() }, { headers: corsHeaders });
  }

  if (path === "/api/admin/invites" && req.method === "POST") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await readJsonLimited(req, ROUTE_BODY_CAP).catch((e: any) => { if (e instanceof BodyTooLargeError) throw e; return {}; });
      if (body.email !== undefined && body.email !== null && typeof body.email !== "string") {
        return Response.json({ error: "Invalid email" }, { status: 400, headers: corsHeaders });
      }
      const days = body.expiresInDays === undefined || body.expiresInDays === null
        ? null
        : Number(body.expiresInDays);
      if (days !== null && (!Number.isFinite(days) || days <= 0 || days > 365)) {
        return Response.json({ error: "expiresInDays must be between 1 and 365" }, { status: 400, headers: corsHeaders });
      }
      const invite = auth.createInvite(adminUser.id, { email: body.email || null, expiresInDays: days });
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "invite_created", actor: adminUser.id, actorIp: getClientIP(req), targetType: "invite", targetId: invite.id });
      return Response.json(invite, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path.match(/^\/api\/admin\/invites\/[\w-]+$/) && req.method === "DELETE") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const inviteId = path.split("/")[4];
    if (!auth.revokeInvite(inviteId)) {
      return Response.json({ error: "Invite not found" }, { status: 404, headers: corsHeaders });
    }
    db.addAuditLog({ timestamp: new Date().toISOString(), action: "invite_revoked", actor: adminUser.id, actorIp: getClientIP(req), targetType: "invite", targetId: inviteId });
    return Response.json({ success: true }, { headers: corsHeaders });
  }

  if (path.match(/^\/api\/admin\/users\/[\w-]+$/) && req.method === "DELETE") {
    const userId = path.split("/")[4];
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const result = auth.adminDeleteUser(userId);
    if (result.success) db.setPendingApproval(userId, false);
    if (result.success) refreshUserSockets(userId);
    if (!result.success) {
      return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
    }
    db.addAuditLog({ timestamp: new Date().toISOString(), action: "user_deleted", actor: adminUser.id, actorIp: getClientIP(req), targetType: "user", targetId: userId });
    return Response.json({ success: true }, { headers: corsHeaders });
  }

  return null;
}
