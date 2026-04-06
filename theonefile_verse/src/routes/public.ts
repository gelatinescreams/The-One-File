import { join } from "path";
import * as oidc from "../oidc";
import * as db from "../database";
import * as redis from "../redis";
import { APP_VERSION, getSettings, isValidUUID, getAdminPath } from "../config";
import { serveHtml, securityHeaders, getUserTokenFromRequest, validateAdminUser, relativeRedirect } from "../security";
import { theOneFileHtml, loadRoom } from "../rooms";

const STATIC_FILES: Record<string, { path: string; type: string; cache: string }> = {
  "/collab.js": { path: "public/collab.js", type: "application/javascript", cache: "no-cache" },
  "/collab-init.js": { path: "public/collab-init.js", type: "application/javascript", cache: "no-cache" },
  "/collab-save-hook.js": { path: "public/collab-save-hook.js", type: "application/javascript", cache: "no-cache" },
  "/collab.css": { path: "public/collab.css", type: "text/css", cache: "no-cache" },
  "/landing.js": { path: "public/landing.js", type: "application/javascript", cache: "public, max-age=3600" },
  "/admin-dashboard.js": { path: "public/admin-dashboard.js", type: "application/javascript", cache: "public, max-age=3600" },
  "/admin-auth.js": { path: "public/admin-auth.js", type: "application/javascript", cache: "public, max-age=3600" },
  "/admin-pages.js": { path: "public/admin-pages.js", type: "application/javascript", cache: "public, max-age=3600" },
  "/qrcode.min.js": { path: "public/qrcode.min.js", type: "application/javascript", cache: "public, max-age=86400" }
};

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  const settings = getSettings();

  if (path === "/api/version" && req.method === "GET") {
    return Response.json({ version: APP_VERSION }, { headers: corsHeaders });
  }

  if (path === "/api/health" && req.method === "GET") {
    const uptime = process.uptime();
    let dbOk = false;
    try { dbOk = db.healthCheck(); } catch {}
    let redisOk = false;
    try { redisOk = await redis.ping(); } catch {}
    const status = dbOk ? "ok" : "degraded";
    return Response.json({
      status,
      version: APP_VERSION,
      uptime: Math.floor(uptime),
      components: { database: dbOk ? "ok" : "error", redis: redisOk ? "ok" : "unavailable" },
      rooms: db.countRooms()
    }, { headers: corsHeaders });
  }

  if (path === "/api/theme" && req.method === "GET") {
    const authSettings = oidc.getAuthSettings();
    return Response.json({
      forcedTheme: settings.forcedTheme,
      chatEnabled: settings.chatEnabled,
      cursorSharingEnabled: settings.cursorSharingEnabled,
      nameChangeEnabled: settings.nameChangeEnabled,
      shareButtonEnabled: authSettings.shareButtonEnabled,
      showAdminLink: settings.showAdminLink,
      ...(settings.showAdminLink ? { adminPath: getAdminPath() } : {})
    }, { headers: corsHeaders });
  }

  if (path.match(/^\/s\/[\w-]+$/)) {
    const id = path.split("/")[2];
    if (!isValidUUID(id)) {
      return relativeRedirect("/?error=invalid_room");
    }
    const room = loadRoom(id);
    if (!room) return relativeRedirect("/?error=room_not_found");
    if (!theOneFileHtml) return relativeRedirect("/?error=room_unavailable");

    let injectedHtml = theOneFileHtml.replace('<head>', '<head><script src="/collab-init.js"></script>');

    const adminUser = await validateAdminUser(req);
    const isAdmin = !!adminUser;

    let isOwner = false;
    if (room.ownerUserId) {
      const userToken = getUserTokenFromRequest(req);
      if (userToken) {
        const user = await oidc.validateUserSessionToken(userToken);
        if (user && user.id === room.ownerUserId) isOwner = true;
      }
    }

    const roomCsrfToken = oidc.generateCsrfToken();
    const safeRoomConfig = JSON.stringify({
      roomId: id,
      roomHasPassword: !!room.passwordHash && !isAdmin,
      isAdmin,
      csrfToken: roomCsrfToken,
      isCreator: isOwner || isAdmin,
      defaultRoomTheme: settings.defaultRoomTheme || '',
      forceWelcomeModal: settings.forceWelcomeModal || false,
      probeEnabled: settings.probeEnabled,
      discoveryEnabled: settings.discoveryEnabled,
      discoveryAllowed: settings.discoveryEnabled && (isAdmin || !settings.discoveryAdminOnly)
    });

    const configBlock = `<script type="application/json" id="room-config">${safeRoomConfig}</script>
<link rel="stylesheet" href="/collab.css">
<script src="/collab.js"></script>
<script src="/collab-save-hook.js"></script>
</body>`;

    injectedHtml = injectedHtml.replace(/<\/body>\s*<\/html>\s*$/i, configBlock + "\n</html>");

    return serveHtml(injectedHtml, 'room', req);
  }

  if (path === "/" || path === "/index.html") {
    const file = Bun.file(join(process.cwd(), "public", "index.html"));
    if (await file.exists()) return serveHtml(await file.text(), 'public', req);
  }

  const staticEntry = STATIC_FILES[path];
  if (staticEntry) {
    const file = Bun.file(join(process.cwd(), staticEntry.path));
    if (await file.exists()) {
      return new Response(file, {
        headers: { "Content-Type": staticEntry.type, ...securityHeaders, "Cache-Control": staticEntry.cache }
      });
    }
  }

  if (path === "/favicon.ico") {
    return new Response(null, { status: 204 });
  }

  return null;
}
