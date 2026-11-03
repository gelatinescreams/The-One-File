import { join } from "path";
import { createHash } from "crypto";
import * as oidc from "../oidc";
import * as db from "../database";
import * as redis from "../redis";
import { APP_VERSION, getSettings, isValidUUID, getAdminPath, REDIS_FANOUT } from "../config";
import { serveHtml, securityHeaders, getUserTokenFromRequest, validateAdminUser, relativeRedirect } from "../security";
import { theOneFileHtml, loadRoom } from "../rooms";

interface StaticRec { etag: string; type: string; cache: string; raw: Uint8Array; gz: Uint8Array | null; sri?: string }

const staticCache = new Map<string, StaticRec>();

async function getStaticAsset(p: string, entry: { path: string; type: string; cache: string }): Promise<StaticRec | null> {
  const hit = staticCache.get(p);
  if (hit) return hit;
  const file = Bun.file(join(process.cwd(), entry.path));
  if (!(await file.exists())) return null;
  const raw = new Uint8Array(await file.arrayBuffer());
  const etag = '"' + Bun.hash(raw).toString(16) + '"';
  const compressible = entry.type.includes("javascript") || entry.type.includes("css");
  const rec: StaticRec = { etag, type: entry.type, cache: entry.cache, raw, gz: compressible ? Bun.gzipSync(raw) : null };
  staticCache.set(p, rec);
  return rec;
}

export async function integrityFor(p: string): Promise<string> {
  const entry = STATIC_FILES[p];
  if (!entry) return "";
  const rec = await getStaticAsset(p, entry);
  if (!rec) return "";
  if (!rec.sri) {
    rec.sri = "sha384-" + createHash("sha384").update(rec.raw).digest("base64");
  }
  return rec.sri;
}

async function integrityAttr(p: string): Promise<string> {
  const sri = await integrityFor(p);
  return sri ? ` integrity="${sri}"` : "";
}

const STATIC_FILES: Record<string, { path: string; type: string; cache: string }> = {
  "/collab.js": { path: "public/collab.js", type: "application/javascript", cache: "no-cache" },
  "/collab-init.js": { path: "public/collab-init.js", type: "application/javascript", cache: "no-cache" },
  "/collab-save-hook.js": { path: "public/collab-save-hook.js", type: "application/javascript", cache: "no-cache" },
  "/collab.css": { path: "public/collab.css", type: "text/css", cache: "no-cache" },
  "/dompurify.min.js": { path: "public/dompurify.min.js", type: "application/javascript", cache: "public, max-age=86400" },
  "/landing.js": { path: "public/landing.js", type: "application/javascript", cache: "public, max-age=3600" },
  "/admin-dashboard.js": { path: "public/admin-dashboard.js", type: "application/javascript", cache: "public, max-age=3600" },
  "/admin-auth.js": { path: "public/admin-auth.js", type: "application/javascript", cache: "public, max-age=3600" },
  "/admin-pages.js": { path: "public/admin-pages.js", type: "application/javascript", cache: "public, max-age=3600" },
  "/qrcode.min.js": { path: "public/qrcode.min.js", type: "application/javascript", cache: "public, max-age=86400" },
  "/collab-3d.js": { path: "public/collab-3d.js", type: "application/javascript", cache: "no-cache" },
  "/vendor/three/three.module.min.js": { path: "public/vendor/three/three.module.min.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/three.core.min.js": { path: "public/vendor/three/three.core.min.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/loaders/GLTFLoader.js": { path: "public/vendor/three/addons/loaders/GLTFLoader.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/loaders/SVGLoader.js": { path: "public/vendor/three/addons/loaders/SVGLoader.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/utils/BufferGeometryUtils.js": { path: "public/vendor/three/addons/utils/BufferGeometryUtils.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/utils/SkeletonUtils.js": { path: "public/vendor/three/addons/utils/SkeletonUtils.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/environments/RoomEnvironment.js": { path: "public/vendor/three/addons/environments/RoomEnvironment.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/postprocessing/EffectComposer.js": { path: "public/vendor/three/addons/postprocessing/EffectComposer.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/postprocessing/Pass.js": { path: "public/vendor/three/addons/postprocessing/Pass.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/postprocessing/ShaderPass.js": { path: "public/vendor/three/addons/postprocessing/ShaderPass.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/postprocessing/MaskPass.js": { path: "public/vendor/three/addons/postprocessing/MaskPass.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/postprocessing/RenderPass.js": { path: "public/vendor/three/addons/postprocessing/RenderPass.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/postprocessing/UnrealBloomPass.js": { path: "public/vendor/three/addons/postprocessing/UnrealBloomPass.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/postprocessing/OutputPass.js": { path: "public/vendor/three/addons/postprocessing/OutputPass.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/shaders/CopyShader.js": { path: "public/vendor/three/addons/shaders/CopyShader.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/shaders/LuminosityHighPassShader.js": { path: "public/vendor/three/addons/shaders/LuminosityHighPassShader.js", type: "application/javascript", cache: "public, max-age=604800" },
  "/vendor/three/addons/shaders/OutputShader.js": { path: "public/vendor/three/addons/shaders/OutputShader.js", type: "application/javascript", cache: "public, max-age=604800" }
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
      cluster: {
        redisConnected: redis.isRedisConnected(),
        fanout: REDIS_FANOUT,
        instanceId: redis.INSTANCE_ID
      },
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
      discoveryAllowed: settings.discoveryEnabled && (isAdmin || !settings.discoveryAdminOnly),
      maxRoomSizeMB: settings.maxRoomSizeMB,
      enable3d: settings.enable3d !== false
    });

    const [sriInit, sriPurify, sriCollab, sriSaveHook, sri3d] = await Promise.all([
      integrityAttr("/collab-init.js"),
      integrityAttr("/dompurify.min.js"),
      integrityAttr("/collab.js"),
      integrityAttr("/collab-save-hook.js"),
      settings.enable3d !== false ? integrityAttr("/collab-3d.js") : Promise.resolve("")
    ]);

    const threeDTag = settings.enable3d !== false ? `<script type="module" src="/collab-3d.js"${sri3d}></script>\n` : '';
    const configBlock = `<script type="application/json" id="room-config">${safeRoomConfig}</script>
<link rel="stylesheet" href="/collab.css">
<script src="/dompurify.min.js"${sriPurify}></script>
<script src="/collab.js"${sriCollab}></script>
<script src="/collab-save-hook.js"${sriSaveHook}></script>
${threeDTag}</body>`;

    const injectedHtml = theOneFileHtml
      .replace('<head>', `<head><script src="/collab-init.js"${sriInit}></script>`)
      .replace(/<\/body>\s*<\/html>\s*$/i, configBlock + "\n</html>");

    return serveHtml(injectedHtml, 'room', req);
  }

  if (path === "/" || path === "/index.html") {
    const file = Bun.file(join(process.cwd(), "public", "index.html"));
    if (await file.exists()) return serveHtml(await file.text(), 'public', req);
  }

  if (settings.enable3d === false && (path === "/collab-3d.js" || path.startsWith("/vendor/three/"))) {
    return new Response("Not found", { status: 404, headers: { ...corsHeaders, "Cache-Control": "no-store" } });
  }

  const staticEntry = STATIC_FILES[path];
  if (staticEntry) {
    const rec = await getStaticAsset(path, staticEntry);
    if (rec) {
      if (req.headers.get('if-none-match') === rec.etag) {
        return new Response(null, { status: 304, headers: { "ETag": rec.etag, "Cache-Control": rec.cache } });
      }
      const headers: Record<string, string> = { "Content-Type": rec.type, ...securityHeaders, "Cache-Control": rec.cache, "ETag": rec.etag, "Vary": "Accept-Encoding" };
      if (rec.gz && (req.headers.get('accept-encoding') || '').includes('gzip')) {
        headers["Content-Encoding"] = "gzip";
        return new Response(rec.gz as BodyInit, { headers });
      }
      return new Response(rec.raw as BodyInit, { headers });
    }
  }

  if (path === "/favicon.ico") {
    return new Response(null, { status: 204 });
  }

  return null;
}
