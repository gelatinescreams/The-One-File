import * as oidc from "./oidc";
import * as db from "./database";
import { getSettings, getExternalOrigin } from "./config";
import { validateApiKey } from "./tokens";

const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_REGEX = /^([\da-fA-F]{0,4}:){2,7}[\da-fA-F]{0,4}$/;

export function isValidIP(ip: string): boolean {
  return IPV4_REGEX.test(ip) || IPV6_REGEX.test(ip) || ip === '::1';
}

let serverRef: any = null;
export function setServerRef(s: any): void { serverRef = s; }

function peerIP(req: Request): string | null {
  try {
    const info = serverRef?.requestIP?.(req);
    if (info && info.address) {
      let addr = String(info.address);
      const mapped = addr.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
      if (mapped) addr = mapped[1];
      if (isValidIP(addr)) return addr;
    }
  } catch {}
  return null;
}

export function getClientIP(req: Request): string {
  const settings = getSettings();
  const trustProxy = settings.trustedProxies.length > 0 || settings.trustedProxyCount > 0;
  if (trustProxy) {
    const xForwardedFor = req.headers.get("x-forwarded-for");
    if (xForwardedFor) {
      const ips = xForwardedFor.split(",").map(ip => ip.trim()).filter(isValidIP);
      if (ips.length > 0) {
        if (settings.trustedProxies.length > 0) {
          for (let i = ips.length - 1; i >= 0; i--) {
            if (!settings.trustedProxies.includes(ips[i])) return ips[i];
          }
          return peerIP(req) || ips[0];
        }
        const index = Math.max(0, ips.length - settings.trustedProxyCount);
        return ips[index] || ips[0];
      }
    }
    const realIp = req.headers.get("x-real-ip");
    if (realIp && isValidIP(realIp.trim())) return realIp.trim();
  }
  return peerIP(req) || "unknown";
}

export function getSecurityHeaders(pageType: 'admin' | 'public' | 'room' | 'api' = 'public'): Record<string, string> {
  const headers: Record<string, string> = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin"
  };
  headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
  headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload";
  if (pageType === 'api') {
    headers["Cache-Control"] = "no-store";
  } else if (pageType === 'admin') {
    headers["Content-Security-Policy"] = `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`;
  } else if (pageType === 'room') {
    headers["Content-Security-Policy"] = `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; font-src 'self'; connect-src 'self' https://cdn.jsdelivr.net https://raw.githubusercontent.com; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`;
  } else {
    headers["Content-Security-Policy"] = `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`;
  }
  return headers;
}

export const securityHeaders: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
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

export class BodyTooLargeError extends Error {
  readonly maxBytes: number;
  constructor(maxBytes: number) {
    super(`Request body exceeds ${maxBytes} bytes`);
    this.name = "BodyTooLargeError";
    this.maxBytes = maxBytes;
  }
}

export async function readBodyLimited(req: Request, maxBytes: number): Promise<Uint8Array> {
  const declared = parseInt(req.headers.get("content-length") || "", 10);
  if (Number.isFinite(declared) && declared > maxBytes) throw new BodyTooLargeError(maxBytes);

  const body = req.body;
  if (!body) {
    const buf = new Uint8Array(await req.arrayBuffer());
    if (buf.byteLength > maxBytes) throw new BodyTooLargeError(maxBytes);
    return buf;
  }

  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) throw new BodyTooLargeError(maxBytes);
      chunks.push(value);
    }
  } finally {
    try { await reader.cancel(); } catch {  }
    try { reader.releaseLock(); } catch {  }
  }

  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.byteLength; }
  return out;
}

export async function readTextLimited(req: Request, maxBytes: number): Promise<string> {
  return new TextDecoder().decode(await readBodyLimited(req, maxBytes));
}

export async function readJsonLimited(req: Request, maxBytes: number): Promise<any> {
  const text = await readTextLimited(req, maxBytes);
  return JSON.parse(text);
}

export function tooLargeResponse(corsHeaders: Record<string, string>): Response {
  return Response.json({ error: "Payload too large" }, { status: 413, headers: corsHeaders });
}

export function apiError(e: any, corsHeaders: Record<string, string>, message = "Invalid request", status = 400): Response {
  if (e instanceof BodyTooLargeError) {
    return Response.json({ error: "Payload too large" }, { status: 413, headers: corsHeaders });
  }
  console.error("[API]", e.message);
  return Response.json({ error: message }, { status, headers: corsHeaders });
}

export function getCsrfCookieFromRequest(req: Request): string | null {
  const cookie = req.headers.get("cookie") || "";
  const match = cookie.match(/(?:^|;\s*)csrf_token=([^;]+)/);
  return match ? match[1] : null;
}

export function isSameOriginRequest(req: Request): boolean {
  const externalOrigin = getExternalOrigin(req);
  const origin = req.headers.get("origin");
  if (origin) return origin === externalOrigin;
  const referer = req.headers.get("referer");
  if (referer) {
    try { return new URL(referer).origin === externalOrigin; } catch { return false; }
  }
  return false;
}

export function validateRequestCsrf(req: Request, body?: any): boolean {
  const headerToken = req.headers.get("x-csrf-token");
  const bodyToken = body?.csrfToken;
  const token = headerToken || bodyToken;
  const cookieValue = getCsrfCookieFromRequest(req);
  if (token && cookieValue && oidc.validateCsrfToken(token, cookieValue)) {
    if (oidc.isCsrfTokenBound(token)) return true;
  }
  return isSameOriginRequest(req);
}

export const SECRET_SETTING_KEYS = ['encryption_key', 'instancePasswordHash', 'admin_password_hash'];
export function withoutSecretSettings<T extends Record<string, any>>(settings: T): T {
  const out: any = { ...settings };
  for (const k of SECRET_SETTING_KEYS) delete out[k];
  return out;
}
export function redactForAudit(body: any): any {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return body;
  const out: any = {};
  for (const [k, v] of Object.entries(body)) {
    out[k] = /pass(word)?|secret|token|hash|key$/i.test(k) && k !== 'apiKeyName' ? '[redacted]' : v;
  }
  return out;
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
