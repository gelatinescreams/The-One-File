import * as auth from "../auth";
import * as oidc from "../oidc";
import * as db from "../database";
import * as redis from "../redis";
import { getSettings, getAdminPath, needsAdminMigration, hasAdminUser, verifyAdminPassword, getExternalOrigin } from "../config";
import { getClientIP, serveHtml, apiError, validateAdminUser, getTokenFromRequest, getUserTokenFromRequest, relativeRedirect } from "../security";
import { checkRateLimit } from "../rate-limit";
import { removeAdminToken, removeInstanceToken } from "../tokens";
import { adminDashboardHtml, adminLoginHtml, migrationPageHtml } from "../templates";

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  const adminPath = getAdminPath();
  const settings = getSettings();

  if (path === `/${adminPath}`) {
    if (needsAdminMigration()) {
      const migrationWithPath = migrationPageHtml.replace(/\/admin\b(?!-)/g, `/${adminPath}`);
      return serveHtml(migrationWithPath, 'admin', req);
    }
    if (!hasAdminUser()) {
      return relativeRedirect("/");
    }
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return relativeRedirect(`/${adminPath}/login`);
    }
    const dashboardWithPath = adminDashboardHtml
      .replace('ADMIN_PATH_PLACEHOLDER', adminPath)
      .replace(/\/admin\b(?!-)/g, `/${adminPath}`);
    return serveHtml(dashboardWithPath, 'admin', req);
  }

  if (path === `/${adminPath}/login`) {
    if (needsAdminMigration()) {
      return relativeRedirect(`/${adminPath}`);
    }
    if (!hasAdminUser()) {
      return relativeRedirect("/");
    }
    const loginWithPath = adminLoginHtml.replace('ADMIN_PATH_PLACEHOLDER', adminPath).replace(/\/admin\b(?!-)/g, `/${adminPath}`);
    return serveHtml(loginWithPath, 'admin', req);
  }

  if (path === "/api/admin/login" && req.method === "POST") {
    if (!hasAdminUser()) {
      return Response.json({ error: "No admin user configured" }, { status: 400, headers: corsHeaders });
    }
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "admin-login", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (!body.email || !body.password) {
        return Response.json({ error: "Email and password required" }, { status: 400, headers: corsHeaders });
      }
      const result = await auth.loginWithPassword(body.email, body.password, clientIP, req.headers.get("user-agent") || "");
      if (result.requires2FA) {
        const user = db.getUserByEmail(body.email);
        if (!user || user.role !== 'admin') {
          return Response.json({ error: "Not authorized as admin" }, { status: 403, headers: corsHeaders });
        }
        return Response.json({ requires2FA: true, pendingToken: result.pendingToken }, { headers: corsHeaders });
      }
      if (!result.success || !result.sessionToken) {
        return Response.json({ error: result.error || "Invalid credentials" }, { status: 403, headers: corsHeaders });
      }
      const user = db.getUserByEmail(body.email);
      if (!user || user.role !== 'admin') {
        return Response.json({ error: "Not authorized as admin" }, { status: 403, headers: corsHeaders });
      }
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json",
          "Set-Cookie": oidc.getSessionCookie("user_token", result.sessionToken) }
      });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/admin/migrate" && req.method === "POST") {
    if (!needsAdminMigration()) {
      return Response.json({ error: "Migration not needed" }, { status: 400, headers: corsHeaders });
    }
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "admin-migrate", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (!body.oldPassword || !body.email) {
        return Response.json({ error: "Current password and email required" }, { status: 400, headers: corsHeaders });
      }
      if (!(await verifyAdminPassword(body.oldPassword))) {
        return Response.json({ error: "Invalid current password" }, { status: 403, headers: corsHeaders });
      }
      const emailValidation = auth.validateEmail(body.email);
      if (!emailValidation.valid) {
        return Response.json({ error: emailValidation.error }, { status: 400, headers: corsHeaders });
      }
      const newPassword = body.newPassword || body.oldPassword;
      const passwordValidation = auth.validatePassword(newPassword);
      if (!passwordValidation.valid) {
        return Response.json({ error: passwordValidation.error }, { status: 400, headers: corsHeaders });
      }
      const baseUrl = getExternalOrigin(req);
      const result = await auth.registerUser(body.email, newPassword, body.email.split('@')[0], baseUrl);
      if (!result.success) {
        return Response.json({ error: result.error || "Migration failed" }, { status: 400, headers: corsHeaders });
      }
      db.deleteSetting('admin_password_hash');
      db.deleteSetting('admin_created_at');
      const loginResult = await auth.loginWithPassword(body.email, newPassword, clientIP, req.headers.get("user-agent") || "");
      if (!loginResult.success || !loginResult.sessionToken) {
        return Response.json({ error: "Migration succeeded but login failed" }, { status: 400, headers: corsHeaders });
      }
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json",
          "Set-Cookie": oidc.getSessionCookie("user_token", loginResult.sessionToken) }
      });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/logout" && req.method === "POST") {
    const collabToken = getTokenFromRequest(req);
    if (collabToken) {
      await removeAdminToken(collabToken);
      removeInstanceToken(collabToken);
      if (redis.isRedisConnected()) await redis.deleteSessionToken(collabToken);
    }

    const userToken = getUserTokenFromRequest(req);
    if (userToken) {
      const user = await oidc.validateUserSessionToken(userToken);
      if (user) {
        oidc.revokeUserOidcTokens(user.id).catch(e => console.error('[OIDC] Token revocation error:', e));
      }
      await auth.logout(userToken);
      if (redis.isRedisConnected()) await redis.deleteSessionToken(userToken);
    }

    const clearCookies = [
      oidc.getClearCookie("collab_token"),
      oidc.getClearCookie("user_token")
    ].join(", ");

    return new Response(JSON.stringify({ success: true }), {
      headers: { ...corsHeaders, "Content-Type": "application/json", "Set-Cookie": clearCookies }
    });
  }

  return null;
}
