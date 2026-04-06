import * as auth from "../auth";
import * as oidc from "../oidc";
import * as redis from "../redis";
import { getSettings, getExternalOrigin } from "../config";
import { getClientIP, apiError, validateRequestCsrf, csrfReject, getUserTokenFromRequest, serveHtml, relativeRedirect } from "../security";
import { checkRateLimit, checkEmailRateLimit } from "../rate-limit";
import { userLoginHtml, userRegisterHtml, userForgotPasswordHtml, getPasswordResetHtml } from "../templates";

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  const settings = getSettings();

  if (path === "/api/auth/settings" && req.method === "GET") {
    const authSettings = oidc.getAuthSettings();
    const providers = oidc.getActiveProviders();
    return Response.json({ settings: authSettings, providers }, { headers: corsHeaders });
  }

  if (path === "/api/auth/providers" && req.method === "GET") {
    const providers = oidc.getActiveProviders();
    return Response.json(providers, { headers: corsHeaders });
  }

  if (path === "/api/auth/csrf" && req.method === "GET") {
    const csrfToken = oidc.generateCsrfToken();
    return new Response(JSON.stringify({ token: csrfToken }), {
      headers: { ...corsHeaders, "Content-Type": "application/json", "Set-Cookie": oidc.getCsrfCookie(csrfToken) }
    });
  }

  if (path === "/api/auth/register" && req.method === "POST") {
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "register", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (typeof body.email !== "string" || typeof body.password !== "string" || (body.displayName !== undefined && body.displayName !== null && typeof body.displayName !== "string")) {
        return Response.json({ error: "Invalid input types" }, { status: 400, headers: corsHeaders });
      }
      const csrfToken = body.csrfToken || req.headers.get("x-csrf-token");
      if (!oidc.validateCsrfToken(csrfToken)) {
        return Response.json({ error: "Invalid security token. Please refresh and try again." }, { status: 403, headers: corsHeaders });
      }
      if (body.email && !(await checkEmailRateLimit(body.email, "register", settings))) {
        return Response.json({ error: "Too many registration attempts for this email. Try again later." }, { status: 429, headers: corsHeaders });
      }
      const baseUrl = getExternalOrigin(req);
      const result = await auth.registerUser(body.email, body.password, body.displayName, baseUrl);
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
      }
      if (result.requiresVerification) {
        return Response.json({ success: true, requiresVerification: true }, { headers: corsHeaders });
      }
      const loginResult = await auth.loginWithPassword(body.email, body.password, clientIP, req.headers.get("user-agent") || "");
      if (loginResult.success) {
        return new Response(JSON.stringify({ success: true, userId: loginResult.userId }), {
          headers: { ...corsHeaders, "Content-Type": "application/json",
            "Set-Cookie": oidc.getSessionCookie("user_token", loginResult.sessionToken!) }
        });
      }
      return Response.json({ success: true, userId: result.userId }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/auth/login" && req.method === "POST") {
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "user-login", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (typeof body.email !== "string" || typeof body.password !== "string") {
        return Response.json({ error: "Invalid input types" }, { status: 400, headers: corsHeaders });
      }
      const csrfToken = body.csrfToken || req.headers.get("x-csrf-token");
      if (!oidc.validateCsrfToken(csrfToken)) {
        return Response.json({ error: "Invalid security token. Please refresh and try again." }, { status: 403, headers: corsHeaders });
      }
      const result = await auth.loginWithPassword(body.email, body.password, clientIP, req.headers.get("user-agent") || "");
      if (result.requires2FA) {
        return Response.json({ requires2FA: true, pendingToken: result.pendingToken }, { headers: corsHeaders });
      }
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 401, headers: corsHeaders });
      }
      return new Response(JSON.stringify({ success: true, userId: result.userId }), {
        headers: { ...corsHeaders, "Content-Type": "application/json",
          "Set-Cookie": oidc.getSessionCookie("user_token", result.sessionToken!) }
      });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/auth/2fa/login" && req.method === "POST") {
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "2fa-login", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (!body.pendingToken || !body.code || typeof body.pendingToken !== "string" || typeof body.code !== "string") {
        return Response.json({ error: "Token and code required" }, { status: 400, headers: corsHeaders });
      }
      const result = await auth.loginWith2FA(body.pendingToken, body.code, clientIP, req.headers.get("user-agent") || "");
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 401, headers: corsHeaders });
      }
      return new Response(JSON.stringify({ success: true, userId: result.userId }), {
        headers: { ...corsHeaders, "Content-Type": "application/json",
          "Set-Cookie": oidc.getSessionCookie("user_token", result.sessionToken!) }
      });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/auth/me" && req.method === "GET") {
    const token = getUserTokenFromRequest(req);
    if (!token) {
      return Response.json({ user: null }, { headers: corsHeaders });
    }
    const user = await oidc.validateUserSessionToken(token);
    if (!user) {
      return Response.json({ user: null }, { headers: corsHeaders });
    }
    const { passwordHash, totpSecret, totpBackupCodes, pendingEmailToken, ...safeUser } = user;
    return Response.json({ user: safeUser }, { headers: corsHeaders });
  }

  if (path === "/api/auth/logout" && req.method === "POST") {
    const token = getUserTokenFromRequest(req);
    if (token) {
      const user = await oidc.validateUserSessionToken(token);
      if (user) {
        oidc.revokeUserOidcTokens(user.id).catch(e => console.error('[OIDC] Token revocation error:', e));
      }
      await auth.logout(token);
      if (redis.isRedisConnected()) await redis.deleteSessionToken(token);
    }
    const clearCookies = [
      oidc.getClearCookie("collab_token"),
      oidc.getClearCookie("user_token")
    ].join(", ");
    return new Response(JSON.stringify({ success: true }), {
      headers: { ...corsHeaders, "Content-Type": "application/json", "Set-Cookie": clearCookies }
    });
  }

  if (path.match(/^\/api\/auth\/oidc\/[\w-]+\/login$/) && req.method === "GET") {
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "oidc-init", settings))) {
      return relativeRedirect("/?auth_error=rate_limited");
    }
    const providerId = path.split("/")[4];
    const baseUrl = getExternalOrigin(req);
    const redirectParam = url.searchParams.get("redirect");
    const validatedRedirect = oidc.validateRedirectUrl(redirectParam, baseUrl);
    const result = await oidc.generateAuthorizationUrl(providerId, baseUrl, undefined, validatedRedirect);
    if (!result) {
      return relativeRedirect("/?auth_error=provider_unavailable");
    }
    return Response.redirect(result.url, 302);
  }

  if (path.match(/^\/api\/auth\/oidc\/[\w-]+$/) && req.method === "GET") {
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "oidc-init", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    const providerId = path.split("/")[4];
    const baseUrl = getExternalOrigin(req);
    let linkUserId: string | undefined = undefined;
    const linkParam = url.searchParams.get("link");
    if (linkParam) {
      const token = getUserTokenFromRequest(req);
      if (!token) {
        return Response.json({ error: "Authentication required for account linking" }, { status: 401, headers: corsHeaders });
      }
      const user = await oidc.validateUserSessionToken(token);
      if (!user) {
        return Response.json({ error: "Authentication required for account linking" }, { status: 401, headers: corsHeaders });
      }
      if (user.id !== linkParam) {
        return Response.json({ error: "Cannot link to another user's account" }, { status: 403, headers: corsHeaders });
      }
      linkUserId = linkParam;
    }
    const result = await oidc.generateAuthorizationUrl(providerId, baseUrl, linkUserId);
    if (!result) {
      return Response.json({ error: "Provider not available" }, { status: 400, headers: corsHeaders });
    }
    return Response.json({ url: result.url, state: result.state }, { headers: corsHeaders });
  }

  if (path.match(/^\/auth\/callback\/[\w-]+$/) && req.method === "GET") {
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "oidc-callback", settings))) {
      return relativeRedirect("/?auth_error=rate_limited");
    }
    const providerId = path.split("/")[3];
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    const error = url.searchParams.get("error");

    if (error) {
      return relativeRedirect(`/?auth_error=${encodeURIComponent(error)}`);
    }

    if (!code || !state) {
      return relativeRedirect("/?auth_error=missing_params");
    }

    const currentUserToken = getUserTokenFromRequest(req);
    const result = await oidc.processOidcCallback(providerId, code, state, clientIP, req.headers.get("user-agent") || "", currentUserToken);

    if (!result.success) {
      return relativeRedirect(`/?auth_error=${encodeURIComponent(result.error || "unknown")}`);
    }

    let redirectTo = "/";
    if (result.isNewUser) {
      redirectTo = "/?welcome=true";
    } else if (result.postLoginRedirect && result.postLoginRedirect !== "/") {
      redirectTo = result.postLoginRedirect;
    }

    return new Response(null, {
      status: 302,
      headers: {
        "Location": redirectTo,
        "Set-Cookie": oidc.getSessionCookie("user_token", result.sessionToken!),
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store"
      }
    });
  }

  if (path === "/auth/login" && req.method === "GET") {
    return serveHtml(userLoginHtml, 'public', req);
  }

  if (path === "/auth/register" && req.method === "GET") {
    return serveHtml(userRegisterHtml, 'public', req);
  }

  if (path === "/auth/forgot-password" && req.method === "GET") {
    return serveHtml(userForgotPasswordHtml, 'public', req);
  }

  if (path === "/auth/verify" && req.method === "GET") {
    const token = url.searchParams.get("token");
    if (!token) {
      return relativeRedirect("/?verify_error=missing_token");
    }
    const result = await auth.verifyEmail(token);
    if (!result.success) {
      return relativeRedirect(`/?verify_error=${encodeURIComponent(result.error || "unknown")}`);
    }
    return relativeRedirect("/?verified=true");
  }

  if (path === "/api/auth/forgot-password" && req.method === "POST") {
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "forgot-password", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (typeof body.email !== "string") {
        return Response.json({ error: "Invalid input types" }, { status: 400, headers: corsHeaders });
      }
      if (body.email && !(await checkEmailRateLimit(body.email, "password-reset", settings))) {
        return Response.json({ success: true }, { headers: corsHeaders });
      }
      const baseUrl = getExternalOrigin(req);
      await auth.requestPasswordReset(body.email, baseUrl);
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/auth/reset-password" && req.method === "GET") {
    const token = url.searchParams.get("token");
    if (!token) {
      return relativeRedirect("/?reset_error=missing_token");
    }
    return serveHtml(getPasswordResetHtml(token), 'public', req);
  }

  if (path === "/api/auth/reset-password" && req.method === "POST") {
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "reset-password", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (typeof body.token !== "string" || typeof body.password !== "string") {
        return Response.json({ error: "Invalid input types" }, { status: 400, headers: corsHeaders });
      }
      const csrfToken = body.csrfToken || req.headers.get("x-csrf-token");
      if (!oidc.validateCsrfToken(csrfToken)) {
        return Response.json({ error: "Invalid security token. Please refresh and try again." }, { status: 403, headers: corsHeaders });
      }
      const result = await auth.resetPassword(body.token, body.password);
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
      }
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/auth/magic-link" && req.method === "POST") {
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "magic-link", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (typeof body.email !== "string") {
        return Response.json({ error: "Invalid input types" }, { status: 400, headers: corsHeaders });
      }
      if (body.email && !(await checkEmailRateLimit(body.email, "magic-link", settings))) {
        return Response.json({ success: true }, { headers: corsHeaders });
      }
      const baseUrl = getExternalOrigin(req);
      await auth.requestMagicLink(body.email, baseUrl);
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/auth/magic-link" && req.method === "GET") {
    const token = url.searchParams.get("token");
    if (!token) {
      return relativeRedirect("/?magic_error=missing_token");
    }
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "magic-link-verify", settings))) {
      return relativeRedirect("/?magic_error=rate_limited");
    }
    const result = await auth.loginWithMagicLink(token, clientIP, req.headers.get("user-agent") || "");
    if (!result.success) {
      return relativeRedirect(`/?magic_error=${encodeURIComponent(result.error || "unknown")}`);
    }
    return new Response(null, {
      status: 302,
      headers: {
        "Location": "/",
        "Set-Cookie": oidc.getSessionCookie("user_token", result.sessionToken!),
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store"
      }
    });
  }

  if (path === "/api/auth/profile" && req.method === "PUT") {
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "profile-update", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    const token = getUserTokenFromRequest(req);
    if (!token) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const user = await oidc.validateUserSessionToken(token);
    if (!user) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (!validateRequestCsrf(req, body)) return csrfReject(corsHeaders);
      if (typeof body !== "object" || body === null || Array.isArray(body)) {
        return Response.json({ error: "Invalid input" }, { status: 400, headers: corsHeaders });
      }
      const result = auth.updateProfile(user.id, body);
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
      }
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/auth/change-password" && req.method === "POST") {
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "change-password", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    const token = getUserTokenFromRequest(req);
    if (!token) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const user = await oidc.validateUserSessionToken(token);
    if (!user) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (!validateRequestCsrf(req, body)) return csrfReject(corsHeaders);
      if (typeof body.currentPassword !== "string" || typeof body.newPassword !== "string") {
        return Response.json({ error: "Invalid input types" }, { status: 400, headers: corsHeaders });
      }
      const result = await auth.changePassword(user.id, body.currentPassword, body.newPassword);
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
      }
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/auth/sessions" && req.method === "GET") {
    const token = getUserTokenFromRequest(req);
    if (!token) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const user = await oidc.validateUserSessionToken(token);
    if (!user) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const sessions = auth.getUserSessions(user.id);
    return Response.json({ sessions }, { headers: corsHeaders });
  }

  if (path === "/api/auth/sessions" && req.method === "DELETE") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    const token = getUserTokenFromRequest(req);
    if (!token) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const user = await oidc.validateUserSessionToken(token);
    if (!user) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const count = auth.logoutAll(user.id);
    return Response.json({ success: true, loggedOut: count }, { headers: corsHeaders });
  }

  if (path === "/api/auth/oidc-links" && req.method === "GET") {
    const token = getUserTokenFromRequest(req);
    if (!token) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const user = await oidc.validateUserSessionToken(token);
    if (!user) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const links = auth.getUserOidcLinks(user.id).map(l => ({
      id: l.id,
      provider: l.provider,
      providerEmail: l.providerEmail,
      createdAt: l.createdAt
    }));
    return Response.json({ links }, { headers: corsHeaders });
  }

  if (path.match(/^\/api\/auth\/oidc-links\/[\w-]+$/) && req.method === "DELETE") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    const linkId = path.split("/")[4];
    const token = getUserTokenFromRequest(req);
    if (!token) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const user = await oidc.validateUserSessionToken(token);
    if (!user) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const result = auth.unlinkOidcProvider(user.id, linkId);
    if (!result.success) {
      return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
    }
    return Response.json({ success: true }, { headers: corsHeaders });
  }

  if (path === "/api/auth/2fa/setup" && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "2fa-setup", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    const token = getUserTokenFromRequest(req);
    if (!token) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const user = await oidc.validateUserSessionToken(token);
    if (!user) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const result = await auth.setupTOTP(user.id);
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
      }
      return Response.json({ secret: result.secret, otpauthUrl: result.otpauthUrl }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/auth/2fa/verify" && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "2fa-verify", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    const token = getUserTokenFromRequest(req);
    if (!token) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const user = await oidc.validateUserSessionToken(token);
    if (!user) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (!body.code || typeof body.code !== "string" || body.code.length !== 6) {
        return Response.json({ error: "Valid 6 digit code required" }, { status: 400, headers: corsHeaders });
      }
      const result = await auth.verifyAndEnableTOTP(user.id, body.code);
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
      }
      return Response.json({ success: true, backupCodes: result.backupCodes }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/auth/2fa/disable" && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "2fa-disable", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    const token = getUserTokenFromRequest(req);
    if (!token) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const user = await oidc.validateUserSessionToken(token);
    if (!user) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (!body.password || typeof body.password !== "string") {
        return Response.json({ error: "Password required" }, { status: 400, headers: corsHeaders });
      }
      const result = await auth.disableTOTP(user.id, body.password);
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
      }
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/auth/email-change" && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "email-change", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    const token = getUserTokenFromRequest(req);
    if (!token) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const user = await oidc.validateUserSessionToken(token);
    if (!user) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (!body.newEmail || !body.password || typeof body.newEmail !== "string" || typeof body.password !== "string") {
        return Response.json({ error: "New email and password required" }, { status: 400, headers: corsHeaders });
      }
      const baseUrl = getExternalOrigin(req);
      const result = await auth.requestEmailChange(user.id, body.newEmail, body.password, baseUrl);
      if (!result.success) {
        return Response.json({ error: result.error }, { status: 400, headers: corsHeaders });
      }
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/auth/verify-email-change" && req.method === "GET") {
    const token = url.searchParams.get("token");
    if (!token) {
      return relativeRedirect("/?email_change_error=missing_token");
    }
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "email-change-verify", settings))) {
      return relativeRedirect("/?email_change_error=rate_limited");
    }
    const result = await auth.confirmEmailChange(token);
    if (!result.success) {
      return relativeRedirect(`/?email_change_error=${encodeURIComponent(result.error || "unknown")}`);
    }
    return relativeRedirect("/?email_changed=true");
  }

  return null;
}
