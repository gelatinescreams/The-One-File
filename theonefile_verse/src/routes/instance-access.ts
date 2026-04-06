import * as oidc from "../oidc";
import { ENV_ADMIN_PASSWORD, isInstanceLocked, isAdminRoute, getSettings, verifyAdminPassword, verifyInstancePassword } from "../config";
import { getClientIP, apiError, serveHtml, getTokenFromRequest, validateAdminUser } from "../security";
import { checkRateLimit } from "../rate-limit";
import { validateInstanceToken, storeInstanceToken } from "../tokens";
import { instanceLoginPageHtml } from "../templates";

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  if ((ENV_ADMIN_PASSWORD || isInstanceLocked()) && isAdminRoute(path)) {
    const token = getTokenFromRequest(req);
    const adminUser = await validateAdminUser(req);
    const hasInstanceAccess = (token && validateInstanceToken(token)) || adminUser;
    if (!hasInstanceAccess) {
      if (path === "/" || path === "/index.html" || path.startsWith("/s/")) {
        return serveHtml(instanceLoginPageHtml, 'public', req);
      }
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
  }

  if (path === "/api/instance-login" && req.method === "POST") {
    if (!ENV_ADMIN_PASSWORD && !isInstanceLocked()) {
      return Response.json({ error: "Instance not locked" }, { status: 400, headers: corsHeaders });
    }
    const clientIP = getClientIP(req);
    const settings = getSettings();
    if (!(await checkRateLimit(clientIP, "instance-login", settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      let valid = false;
      if (ENV_ADMIN_PASSWORD) {
        valid = await verifyAdminPassword(body.password);
      } else {
        valid = await verifyInstancePassword(body.password);
      }
      if (valid) {
        const token = crypto.randomUUID();
        storeInstanceToken(token);
        return new Response(JSON.stringify({ success: true }), {
          headers: { ...corsHeaders, "Content-Type": "application/json",
            "Set-Cookie": oidc.getSessionCookie("collab_token", token, 604800) }
        });
      }
      return Response.json({ error: "Invalid password" }, { status: 403, headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  return null;
}
