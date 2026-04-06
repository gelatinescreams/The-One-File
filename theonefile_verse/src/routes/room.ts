import * as oidc from "../oidc";
import * as db from "../database";
import { getSettings, isValidUUID } from "../config";
import { getClientIP, apiError, validateRequestCsrf, csrfReject, getUserTokenFromRequest, validateAdminUser } from "../security";
import { checkRateLimit } from "../rate-limit";
import { generateWsSessionToken, generateRoomAccessToken, validateRoomAccessToken, WS_TOKEN_EXPIRY } from "../tokens";
import { loadRoom, saveRoom, deleteRoomData, scheduleDestruction, hashPassword, verifyPassword, validateTopology, sendWebhook, type Room } from "../rooms";

const ROOM_ACCESS_COOKIE_REGEX = /(?:^|;\s*)room_access=([^;]+)/;
const HOST_ROOM_ACCESS_COOKIE_REGEX = /(?:^|;\s*)__Host-room_access=([^;]+)/;

function extractRoomAccessCookie(cookies: string, prodMode: boolean): string {
  const match = cookies.match(prodMode ? HOST_ROOM_ACCESS_COOKIE_REGEX : ROOM_ACCESS_COOKIE_REGEX);
  return match ? match[1] : '';
}

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  const settings = getSettings();

  if (path === "/api/room" && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "room-create", settings))) {
      return Response.json({ error: "Too many rooms created. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      const creatorId = body.creatorId && isValidUUID(body.creatorId) ? body.creatorId : crypto.randomUUID();
      const validDestructModes = ["time", "empty", "never"];
      const destructMode = validDestructModes.includes(body.destructMode) ? body.destructMode : "time";
      const maxDestructValue = 30 * 24 * 60 * 60 * 1000;
      const destructValue = typeof body.destructValue === "number"
        ? Math.min(Math.max(0, body.destructValue), maxDestructValue)
        : 86400000;
      if (body.password && body.password.length > 0 && body.password.length < 8) {
        return Response.json({ error: "Room password must be at least 8 characters" }, { status: 400, headers: corsHeaders });
      }
      const passwordHash = body.password && body.password.length >= 8
        ? await hashPassword(body.password)
        : null;

      const id = crypto.randomUUID();

      const userToken = getUserTokenFromRequest(req);
      let ownerUserId: string | null = null;
      if (userToken) {
        const user = await oidc.validateUserSessionToken(userToken);
        if (user) ownerUserId = user.id;
      }

      const authSettings = oidc.getAuthSettings();
      if (!authSettings.allowGuestRoomCreation && !ownerUserId) {
        return Response.json({ error: "Please sign in to create a room" }, { status: 401, headers: corsHeaders });
      }

      if (settings.maxRoomsPerInstance > 0 && db.countRooms() >= settings.maxRoomsPerInstance) {
        return Response.json({ error: "Maximum number of rooms reached" }, { status: 403, headers: corsHeaders });
      }

      const allowGuests = body.allowGuests !== false && authSettings.allowGuestRoomJoin;

      let validatedTopology = null;
      if (body.topology) {
        const topologyValidation = validateTopology(body.topology);
        if (!topologyValidation.valid) {
          return Response.json({ error: topologyValidation.error || "Invalid topology data" }, { status: 400, headers: corsHeaders });
        }
        validatedTopology = topologyValidation.sanitized;
      }

      const room: Room = {
        id,
        created: new Date().toISOString(),
        lastActivity: new Date().toISOString(),
        creatorId,
        passwordHash,
        destruct: { mode: destructMode, value: destructValue },
        topology: validatedTopology,
        ownerUserId,
        allowGuests
      };
      saveRoom(room);
      if (room.destruct.mode === "time") scheduleDestruction(id, room.destruct.value);
      sendWebhook("room_created", { roomId: id, hasPassword: !!room.passwordHash, destructMode, creatorId });
      return Response.json({ id, url: `/s/${id}`, hasPassword: !!room.passwordHash, allowGuests: room.allowGuests }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path.match(/^\/api\/room\/[\w-]+\/verify$/) && req.method === "POST") {
    const id = path.split("/")[3];
    if (!isValidUUID(id)) {
      return Response.json({ error: "Invalid room ID" }, { status: 400, headers: corsHeaders });
    }
    const room = loadRoom(id);
    if (!room) return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });
    if (!room.passwordHash) return Response.json({ valid: true }, { headers: corsHeaders });
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, `room-verify-${id}`, settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      const valid = await verifyPassword(body.password || "", room.passwordHash);
      if (valid) {
        const accessToken = generateRoomAccessToken(id);
        const prodMode = oidc.getAuthSettings().productionMode;
        const cookieName = prodMode ? '__Host-room_access' : 'room_access';
        const cookieFlags = prodMode ? '; HttpOnly; Secure; SameSite=Strict; Path=/; Partitioned' : '; HttpOnly; SameSite=Strict; Path=/';
        const responseHeaders = { ...corsHeaders, 'Set-Cookie': `${cookieName}=${accessToken}; Max-Age=86400${cookieFlags}` };
        return Response.json({ valid: true }, { headers: responseHeaders });
      }
      return Response.json({ valid: false }, { headers: corsHeaders });
    } catch (e: any) { console.error("[API]", e.message); return Response.json({ valid: false }, { headers: corsHeaders }); }
  }

  if (path.match(/^\/api\/room\/[\w-]+\/access$/) && req.method === "GET") {
    const id = path.split("/")[3];
    if (!isValidUUID(id)) return Response.json({ authorized: false }, { status: 400, headers: corsHeaders });
    const room = loadRoom(id);
    if (!room) return Response.json({ authorized: false }, { status: 404, headers: corsHeaders });
    if (!room.passwordHash) return Response.json({ authorized: true }, { headers: corsHeaders });
    const prodMode = oidc.getAuthSettings().productionMode;
    const cookies = req.headers.get('cookie') || '';
    const token = extractRoomAccessCookie(cookies, prodMode);
    return Response.json({ authorized: validateRoomAccessToken(token, id) }, { headers: corsHeaders });
  }

  if (path.match(/^\/api\/room\/[\w-]+$/) && req.method === "DELETE") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    const id = path.split("/")[3];
    if (!isValidUUID(id)) {
      return Response.json({ error: "Invalid room ID" }, { status: 400, headers: corsHeaders });
    }
    const room = loadRoom(id);
    if (!room) return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });

    const userToken = getUserTokenFromRequest(req);
    if (userToken) {
      const user = await oidc.validateUserSessionToken(userToken);
      if (user) {
        if (user.role === 'admin' || (room.ownerUserId && user.id === room.ownerUserId)) {
          deleteRoomData(id);
          db.addAuditLog({ timestamp: new Date().toISOString(), action: "room_deleted", actor: user.id, actorIp: getClientIP(req), targetType: "room", targetId: id });
          return Response.json({ deleted: true }, { headers: corsHeaders });
        }
      }
    }

    return Response.json({ error: "Only room owner or admin can delete" }, { status: 403, headers: corsHeaders });
  }

  if (path.match(/^\/api\/room\/[\w-]+\/exists$/) && req.method === "GET") {
    const id = path.split("/")[3];
    if (!isValidUUID(id)) {
      return Response.json({ exists: false }, { headers: corsHeaders });
    }
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "room-exists", settings))) {
      return Response.json({ error: "Too many requests. Try again later." }, { status: 429, headers: corsHeaders });
    }
    const room = loadRoom(id);
    if (!room) return Response.json({ exists: false }, { headers: corsHeaders });
    return Response.json({
      exists: true, hasPassword: !!room.passwordHash
    }, { headers: corsHeaders });
  }

  if (path.match(/^\/api\/room\/[\w-]+\/ws-token$/) && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    const id = path.split("/")[3];
    if (!isValidUUID(id)) {
      return Response.json({ error: "Invalid room ID" }, { status: 400, headers: corsHeaders });
    }
    const room = loadRoom(id);
    if (!room) return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });

    if (room.passwordHash) {
      const prodMode = oidc.getAuthSettings().productionMode;
      const cookies = req.headers.get('cookie') || '';
      const accessToken = extractRoomAccessCookie(cookies, prodMode);
      if (!validateRoomAccessToken(accessToken, id)) {
        return Response.json({ error: "Room password required" }, { status: 403, headers: corsHeaders });
      }
    }

    if (room.allowGuests === false) {
      const userToken = getUserTokenFromRequest(req);
      if (!userToken) return Response.json({ error: "Authentication required" }, { status: 401, headers: corsHeaders });
      const user = await oidc.validateUserSessionToken(userToken);
      if (!user) return Response.json({ error: "Authentication required" }, { status: 401, headers: corsHeaders });
    }

    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, `ws-token-${id}`, settings))) {
      return Response.json({ error: "Too many attempts. Try again later." }, { status: 429, headers: corsHeaders });
    }

    try {
      const body = await req.json();
      let collabUserId: string;
      const userToken = getUserTokenFromRequest(req);
      if (userToken) {
        const user = await oidc.validateUserSessionToken(userToken);
        collabUserId = user ? user.id : crypto.randomUUID();
      } else {
        collabUserId = crypto.randomUUID();
      }

      const wsToken = await generateWsSessionToken(id, collabUserId);

      return Response.json({ wsToken, expiresIn: WS_TOKEN_EXPIRY / 1000, collabUserId }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  return null;
}
