import * as db from "./database";
import * as redis from "./redis";
import * as oidc from "./oidc";
import { APP_VERSION, PORT, ENV_ADMIN_PASSWORD, getSettings, isAdminConfigured, isInstanceLocked, isValidUUID } from "./config";
import { securityHeaders, getClientIP, getTokenFromRequest, relativeRedirect } from "./security";
import { startTokenCleanupIntervals, validateInstanceToken } from "./tokens";
import { startRateLimitCleanupIntervals, checkWsConnectionLimit } from "./rate-limit";
import { loadRoom, restartBackupTimer, clearBackupTimer, clearUpdateTimer, deleteRoomData, scheduleDestruction, initializeTheOneFile } from "./rooms";
import { websocketHandlers, type WsData } from "./websocket";

const CONFIGURED_ORIGINS = process.env.CORS_ORIGIN?.split(",").map(o => o.trim()).filter(Boolean) || null;

import * as setupRoutes from "./routes/setup";
import * as adminAuthRoutes from "./routes/admin-auth";
import * as adminRoomsRoutes from "./routes/admin-rooms";
import * as userAuthRoutes from "./routes/user-auth";
import * as adminUsersRoutes from "./routes/admin-users";
import * as adminAuthSettingsRoutes from "./routes/admin-auth-settings";
import * as instanceAccessRoutes from "./routes/instance-access";
import * as adminSettingsRoutes from "./routes/admin-settings";
import * as adminLogsRoutes from "./routes/admin-logs";
import * as adminBackupsRoutes from "./routes/admin-backups";
import * as adminApikeysRoutes from "./routes/admin-apikeys";
import * as roomRoutes from "./routes/room";
import * as networkRoutes from "./routes/network-routes";
import * as publicRoutes from "./routes/public";

async function handleRequest(req: Request, server: any): Promise<Response | undefined> {
  const url = new URL(req.url);
  const path = url.pathname;

  if (req.method === 'POST' || req.method === 'PUT') {
    if (path !== '/api/admin/upload-html') {
      const cl = parseInt(req.headers.get('content-length') || '0');
      if (cl > 5 * 1024 * 1024) {
        return new Response('Payload too large', { status: 413 });
      }
    }
  }

  if (path.match(/^\/ws\/[\w-]+$/)) {
    const clientIp = getClientIP(req);
    if (!checkWsConnectionLimit(clientIp)) {
      return new Response("Too many WebSocket connections", { status: 429 });
    }

    const roomId = path.split("/")[2];
    if (!isValidUUID(roomId)) {
      return new Response("Invalid room ID", { status: 400 });
    }
    const room = loadRoom(roomId);
    if (!room) return new Response("Room not found", { status: 404 });

    if (ENV_ADMIN_PASSWORD || isInstanceLocked()) {
      const token = getTokenFromRequest(req);
      if (!token || !validateInstanceToken(token)) return new Response("Unauthorized", { status: 401 });
    }

    const authSettings = oidc.getAuthSettings();
    const requireWsToken = authSettings.productionMode || process.env.REQUIRE_WS_TOKEN === 'true';

    const upgraded = server.upgrade(req, { data: { roomId, authenticated: !requireWsToken } });
    if (upgraded) return undefined;
    return new Response("WebSocket upgrade failed", { status: 400 });
  }

  const requestOrigin = req.headers.get("origin") || new URL(req.url).origin;

  let allowedOrigin: string;
  if (CONFIGURED_ORIGINS && CONFIGURED_ORIGINS.length > 0) {
    allowedOrigin = CONFIGURED_ORIGINS.includes(requestOrigin) ? requestOrigin : CONFIGURED_ORIGINS[0];
  } else {
    allowedOrigin = new URL(req.url).origin;
  }

  const corsHeaders = {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, x-csrf-token",
    "Access-Control-Allow-Credentials": "true",
    ...securityHeaders
  };

  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  let response: Response | null;

  response = await setupRoutes.handle(req, path, url, corsHeaders);
  if (response) return response;

  response = await adminAuthRoutes.handle(req, path, url, corsHeaders);
  if (response) return response;

  response = await adminRoomsRoutes.handle(req, path, url, corsHeaders);
  if (response) return response;

  response = await userAuthRoutes.handle(req, path, url, corsHeaders);
  if (response) return response;

  response = await adminUsersRoutes.handle(req, path, url, corsHeaders);
  if (response) return response;

  response = await adminAuthSettingsRoutes.handle(req, path, url, corsHeaders);
  if (response) return response;

  response = await instanceAccessRoutes.handle(req, path, url, corsHeaders);
  if (response) return response;

  response = await adminSettingsRoutes.handle(req, path, url, corsHeaders);
  if (response) return response;

  response = await adminLogsRoutes.handle(req, path, url, corsHeaders);
  if (response) return response;

  response = await adminBackupsRoutes.handle(req, path, url, corsHeaders);
  if (response) return response;

  response = await adminApikeysRoutes.handle(req, path, url, corsHeaders);
  if (response) return response;

  response = await roomRoutes.handle(req, path, url, corsHeaders);
  if (response) return response;

  response = await networkRoutes.handle(req, path, url, corsHeaders);
  if (response) return response;

  response = await publicRoutes.handle(req, path, url, corsHeaders);
  if (response) return response;

  return relativeRedirect("/?error=not_found");
}

const server = Bun.serve({
  port: PORT,
  async fetch(req, server) {
    const start = performance.now();
    const response = await handleRequest(req, server);
    if (response) {
      const path = new URL(req.url).pathname;
      if (path !== '/api/health' && !path.startsWith('/ws/')) {
        console.log(`[HTTP] ${req.method} ${path} ${response.status} ${(performance.now() - start).toFixed(1)}ms`);
      }
    }
    return response;
  },
  websocket: {
    perMessageDeflate: true,
    maxPayloadLength: 5 * 1024 * 1024,
    ...websocketHandlers
  }
});

const migrationResult = db.migrateFromFlatFiles();
if (migrationResult.rooms > 0 || migrationResult.settings || migrationResult.admin) {
  console.log(`[Migration] Migrated: ${migrationResult.rooms} rooms, settings: ${migrationResult.settings}, admin: ${migrationResult.admin}`);
}

redis.connectRedis().then(connected => {
  if (connected) console.log("[Redis] Connected successfully");
  else console.log("[Redis] Not available, using in-memory fallback");
});

restartBackupTimer();
db.initializeDefaultEmailTemplates();
db.verifyAllAdminEmails();
await initializeTheOneFile();

startTokenCleanupIntervals();
startRateLimitCleanupIntervals();

const settings = getSettings();
console.log(`TheOneFile Verse v${APP_VERSION} | http://localhost:${PORT}`);
if (ENV_ADMIN_PASSWORD) console.log(`Instance password lock: ENV`);
else if (isInstanceLocked()) console.log(`Instance password lock: Settings`);
if (settings.skipUpdates) console.log(`Auto updates: Disabled`);
else if (settings.updateIntervalHours > 0) console.log(`Auto updates: Every ${settings.updateIntervalHours}h`);
if (settings.backupEnabled) console.log(`Auto backups: Every ${settings.backupIntervalHours}h, keep ${settings.backupRetentionCount}`);
console.log(`Admin: ${isAdminConfigured() ? 'Configured' : 'Not set up'} | Rooms: ${db.countRooms()}`);

const allRooms = db.listRooms();
for (const room of allRooms) {
  if (room.destruct.mode === "time") {
    const elapsed = Date.now() - new Date(room.lastActivity).getTime();
    const remaining = room.destruct.value - elapsed;
    if (remaining <= 0) deleteRoomData(room.id);
    else scheduleDestruction(room.id, remaining);
  }
}

function shutdown() {
  console.log("[Shutdown] Shutting down...");
  server.stop();
  clearUpdateTimer();
  clearBackupTimer();
  redis.disconnectRedis();
  db.closeDatabase();
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
process.on("uncaughtException", (err) => {
  console.error("[Fatal]", err);
  shutdown();
});
process.on("unhandledRejection", (err) => {
  console.error("[UnhandledRejection]", err);
});
