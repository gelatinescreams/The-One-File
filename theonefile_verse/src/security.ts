import * as oidc from "./oidc";
import * as db from "./database";
import { getSettings, getExternalOrigin } from "./config";
import { validateApiKey } from "./tokens";

const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_REGEX = /^([\da-fA-F]{0,4}:){2,7}[\da-fA-F]{0,4}$/;

export function isValidIP(ip: string): boolean {
  return IPV4_REGEX.test(ip) || IPV6_REGEX.test(ip) || ip === '::1';
}

export function getClientIP(req: Request): string {
  const xForwardedFor = req.headers.get("x-forwarded-for");
  if (xForwardedFor) {
    const ips = xForwardedFor.split(",").map(ip => ip.trim()).filter(isValidIP);
    if (ips.length === 0) return "unknown";
    const settings = getSettings();
    if (settings.trustedProxies.length > 0) {
      for (let i = ips.length - 1; i >= 0; i--) {
        if (!settings.trustedProxies.includes(ips[i])) {
          return ips[i];
        }
      }
    }
    if (settings.trustedProxyCount > 0) {
      const index = Math.max(0, ips.length - settings.trustedProxyCount);
      return ips[index] || ips[0];
    }
    return ips[0];
  }
  const realIp = req.headers.get("x-real-ip");
  if (realIp && isValidIP(realIp.trim())) return realIp.trim();
  return "unknown";
}

export function getSecurityHeaders(pageType: 'admin' | 'public' | 'room' | 'api' = 'public'): Record<string, string> {
  const headers: Record<string, string> = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin"
  };
  headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
  headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload";
  if (pageType === 'api') {
    headers["Cache-Control"] = "no-store";
  } else if (pageType === 'admin') {
    headers["Content-Security-Policy"] = `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`;
  } else if (pageType === 'room') {
    headers["Content-Security-Policy"] = `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' wss: ws: https://cdn.jsdelivr.net https://raw.githubusercontent.com; frame-ancestors 'none'; base-uri 'self'`;
  } else {
    headers["Content-Security-Policy"] = `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' wss: ws:; frame-ancestors 'none'; base-uri 'self'`;
  }
  return headers;
}

export const securityHeaders: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "Cache-Control": "no-store"
};

export function serveHtml(html: string, pageType: 'admin' | 'public' | 'room' = 'public', req?: Request): Response {
  const headers: Record<string, string> = { "Content-Type": "text/html; charset=utf-8", ...getSecurityHeaders(pageType), "Vary": "Accept-Encoding" };
  if (req && html.length > 1024 && (req.headers.get('accept-encoding') || '').includes('gzip')) {
    headers["Content-Encoding"] = "gzip";
    return new Response(Bun.gzipSync(Buffer.from(html)), { headers });
  }
  return new Response(html, { headers });
}

export function apiError(e: any, corsHeaders: Record<string, string>, message = "Invalid request", status = 400): Response {
  console.error("[API]", e.message);
  return Response.json({ error: message }, { status, headers: corsHeaders });
}

export function validateRequestCsrf(req: Request, body?: any): boolean {
  const headerToken = req.headers.get("x-csrf-token");
  const bodyToken = body?.csrfToken;
  const token = headerToken || bodyToken;
  if (token && oidc.validateCsrfToken(token)) return true;
  const origin = req.headers.get("origin");
  const externalOrigin = getExternalOrigin(req);
  if (origin) return origin === externalOrigin;
  const referer = req.headers.get("referer");
  if (referer) {
    try { return new URL(referer).origin === externalOrigin; } catch { return false; }
  }
  return false;
}

export function csrfReject(corsHeaders: Record<string, string>): Response {
  return Response.json({ error: "Invalid security token. Please refresh and try again." }, { status: 403, headers: corsHeaders });
}

export function getTokenFromRequest(req: Request): string | null {
  const cookie = req.headers.get("cookie") || "";
  const match = cookie.match(/(?:^|;\s*)collab_token=([^;]+)/);
  if (match) return match[1];
  const auth = req.headers.get("authorization") || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

export function getUserTokenFromRequest(req: Request): string | null {
  const cookie = req.headers.get("cookie") || "";
  const hostMatch = cookie.match(/__Host-user_token=([^;]+)/);
  if (hostMatch) return hostMatch[1];
  const match = cookie.match(/user_token=([^;]+)/);
  if (match) return match[1];
  const auth = req.headers.get("authorization") || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

export function relativeRedirect(path: string, status: number = 302): Response {
  return new Response(null, { status, headers: { Location: path } });
}

export async function validateAdminUser(req: Request): Promise<db.User | null> {
  const method = req.method;
  if (method === "POST" || method === "PUT" || method === "DELETE") {
    if (!validateRequestCsrf(req)) return null;
  }
  const token = getUserTokenFromRequest(req);
  if (!token) return null;
  const user = await oidc.validateUserSessionToken(token);
  if (!user || user.role !== 'admin') return null;
  return user;
}

export async function validateAdminOrApiKey(
  req: Request,
  requiredPermission: string = "read"
): Promise<{ user: db.User | null; apiKey: db.ApiKey | null }> {
  const auth = req.headers.get("authorization") || "";
  if (auth.startsWith("Bearer tof_")) {
    const key = auth.slice(7);
    const apiKey = await validateApiKey(key);
    if (!apiKey || !apiKey.active) return { user: null, apiKey: null };
    if (!apiKey.permissions.includes(requiredPermission) && !apiKey.permissions.includes("admin")) {
      return { user: null, apiKey: null };
    }
    return { user: null, apiKey };
  }
  const user = await validateAdminUser(req);
  return { user, apiKey: null };
}
