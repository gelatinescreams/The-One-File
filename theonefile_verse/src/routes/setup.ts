import * as auth from "../auth";
import * as oidc from "../oidc";
import * as db from "../database";
import { isAdminConfigured, hasAdminUser, getSettings, getExternalOrigin } from "../config";
import { getClientIP, serveHtml, apiError } from "../security";
import { checkRateLimit } from "../rate-limit";
import { setupPageHtml } from "../templates";

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  if (!isAdminConfigured() && (path === "/" || path === "/index.html")) {
    return serveHtml(setupPageHtml, 'public', req);
  }

  if (path === "/api/setup" && req.method === "POST") {
    if (hasAdminUser()) {
      return Response.json({ error: "Admin already configured" }, { status: 400, headers: corsHeaders });
    }
    const clientIP = getClientIP(req);
    const settings = getSettings();
    if (!(await checkRateLimit(clientIP, "setup", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (!body.email || !body.email.includes('@')) {
        return Response.json({ error: "Valid email required" }, { status: 400, headers: corsHeaders });
      }
      if (!body.password || body.password.length < 8) {
        return Response.json({ error: "Password must be at least 8 characters" }, { status: 400, headers: corsHeaders });
      }
      const emailValidation = auth.validateEmail(body.email);
      if (!emailValidation.valid) {
        return Response.json({ error: emailValidation.error }, { status: 400, headers: corsHeaders });
      }
      const passwordValidation = auth.validatePassword(body.password);
      if (!passwordValidation.valid) {
        return Response.json({ error: passwordValidation.error }, { status: 400, headers: corsHeaders });
      }
      const baseUrl = getExternalOrigin(req);
      const result = await auth.registerUser(body.email, body.password, body.email.split('@')[0], baseUrl);
      if (!result.success) {
        return Response.json({ error: result.error || "Registration failed" }, { status: 400, headers: corsHeaders });
      }
      const loginResult = await auth.loginWithPassword(body.email, body.password, clientIP, req.headers.get("user-agent") || "");
      if (!loginResult.success || !loginResult.sessionToken) {
        return Response.json({ error: "Account created but login failed" }, { status: 400, headers: corsHeaders });
      }
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json",
          "Set-Cookie": oidc.getSessionCookie("user_token", loginResult.sessionToken) }
      });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  return null;
}
