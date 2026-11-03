import * as oidc from "../oidc";
import * as db from "../database";
import { getSettings, isValidUUID, getMaxRoomSizeBytes } from "../config";
import { getClientIP, apiError, validateRequestCsrf, csrfReject, getUserTokenFromRequest, validateAdminUser, readJsonLimited, readTextLimited, readBodyLimited } from "../security";
import { checkRateLimit } from "../rate-limit";
import { generateWsSessionToken, generateRoomAccessToken, validateRoomAccessTokenAsync, WS_TOKEN_EXPIRY } from "../tokens";
import { loadRoom, saveRoom, deleteRoomData, scheduleDestruction, hashPassword, verifyPassword, validateTopology, sendWebhook, type Room } from "../rooms";
import { writeBlob, readBlob, checkAssetQuota } from "../assets";
import { createHash } from "crypto";
import { resolveRoomRole, canWrite, broadcastRoomPermissions } from "../websocket";
import { isRoomViewOnly, setRoomViewOnly } from "../rooms";

const VIEW_ONLY_BODY_CAP = 1024;
import {
  sanitizeScene3d, sanitizeScene3dWithMeta, mergeScene3d, pickSnapshotTab, sanitizeTabKey,
  storedIsPopulatedV2, SCENE3D_LEGACY_TAB, SCENE3D_MAX_TABS, type Scene3d,
} from "../scene3d";

const ROOM_ACCESS_COOKIE_REGEX = /(?:^|;\s*)room_access=([^;]+)/;
const HOST_ROOM_ACCESS_COOKIE_REGEX = /(?:^|;\s*)__Host-room_access=([^;]+)/;

function extractRoomAccessCookie(cookies: string, prodMode: boolean): string {
  const match = cookies.match(prodMode ? HOST_ROOM_ACCESS_COOKIE_REGEX : ROOM_ACCESS_COOKIE_REGEX);
  return match ? match[1] : '';
}

export interface RoomCaller { userId?: string; via: 'session' | 'anon' }

async function identifyRoomCaller(req: Request, _roomId: string): Promise<RoomCaller> {
  const userToken = getUserTokenFromRequest(req);
  if (userToken) {
    const user = await oidc.validateUserSessionToken(userToken);
    if (user) return { userId: user.id, via: 'session' };
  }
  return { via: 'anon' };
}

function rateKeyFor(req: Request, caller: RoomCaller): string {
  return caller.userId ? `u:${caller.userId}` : `ip:${getClientIP(req)}`;
}

export {
  sanitizeScene3d, sanitizeScene3dWithMeta, mergeScene3d, pickSnapshotTab, sanitizeTabKey,
  emptyTab, bucketIsEmpty, storedIsPopulatedV2, sanitizeRev,
  SCENE3D_LEGACY_TAB, SCENE3D_MAX_TABS, SCENE3D_MAX_ELEVATION,
  SCENE3D_MIN_WALL_HEIGHT, SCENE3D_MAX_WALL_HEIGHT, SCENE3D_CODE_TTL_DAYS,
} from "../scene3d";
export type { Scene3d, Scene3dTab, Scene3dMeta } from "../scene3d";

const JSON_BODY_CAP = 64 * 1024;
const SCENE3D_BODY_CAP = 2 * 1024 * 1024;
const ASSET_MODEL_CAP = 12 * 1024 * 1024;
const ASSET_IMAGE_CAP = 3 * 1024 * 1024;

const SCENE3D_RATE_WINDOW = 60;
const SCENE3D_PUT_RATE_MAX = 120;
const SCENE3D_CODE_RATE_MAX = 30;

const VIEW_ONLY_RATE_WINDOW = 60;
const VIEW_ONLY_RATE_MAX = 60;

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  const settings = getSettings();

  if (path === "/api/room" && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "room-create", settings))) {
      return Response.json({ error: "Too many rooms created. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await readJsonLimited(req, getMaxRoomSizeBytes() + 1024 * 1024);
      let creatorId = body.creatorId && isValidUUID(body.creatorId) ? body.creatorId : crypto.randomUUID();
      const validDestructModes = ["time", "empty", "never"];
      const destructMode = validDestructModes.includes(body.destructMode) ? body.destructMode
        : (validDestructModes.includes(settings.defaultDestructMode) ? settings.defaultDestructMode : "time");
      const maxDestructValue = 30 * 24 * 60 * 60 * 1000;
      const destructValue = typeof body.destructValue === "number"
        ? Math.min(Math.max(0, body.destructValue), maxDestructValue)
        : Math.min(Math.max(1, settings.defaultDestructHours || 24) * 3600000, maxDestructValue);
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

      if (creatorId !== ownerUserId) {
        let collides = false;
        try { collides = !!db.getUserById(creatorId); } catch { collides = false; }
        if (collides) creatorId = crypto.randomUUID();
      }

      const authSettings = oidc.getAuthSettings();
      if (!settings.allowPublicRoomCreation) {
        const owner = ownerUserId ? db.getUserById(ownerUserId) : null;
        if (!owner || owner.role !== 'admin') {
          return Response.json({ error: "Room creation is restricted to administrators" }, { status: 403, headers: corsHeaders });
        }
      }
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
      if (settings.enable3d) try {
        const tabs = (validatedTopology && Array.isArray((validatedTopology as any).documentTabs)) ? (validatedTopology as any).documentTabs : [];
        const merged: Scene3d = { version: 2, rev: 0, mpu: 0, wireMode: 0, tabs: {} };
        let found = false, n = 0;
        for (const tab of tabs) {
          if (n >= SCENE3D_MAX_TABS) break;
          const m = tab && typeof tab.threeDRoom === "string" && tab.threeDRoom.match(/^3d:([A-Za-z0-9_-]{1,64})$/);
          if (!m) continue;
          const tabKey = sanitizeTabKey(tab.id) || SCENE3D_LEGACY_TAB;
          if (Object.prototype.hasOwnProperty.call(merged.tabs, tabKey)) continue;
          const snap = db.getSceneByCode(m[1]);
          if (!snap) continue;
          try {
            const p = JSON.parse(snap); delete p.code;
            const clean = sanitizeScene3d(p);
            if (!clean) continue;
            const bucket = pickSnapshotTab(clean, tabKey);
            if (!bucket) continue;
            merged.tabs[tabKey] = bucket;
            if (!found) { merged.mpu = clean.mpu; merged.wireMode = clean.wireMode; }
            found = true; n++;
          } catch {  }
        }
        if (found) { const clean = sanitizeScene3d(merged); if (clean) db.persistScene3d(id, clean); }
      } catch {  }
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
      const body = await readJsonLimited(req, JSON_BODY_CAP);
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
    return Response.json({ authorized: await validateRoomAccessTokenAsync(token, id) }, { headers: corsHeaders });
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

  const viewOnlyMatch = path.match(/^\/api\/room\/([\w-]+)\/view-only$/);
  if (viewOnlyMatch && (req.method === "PUT" || req.method === "GET")) {
    const id = viewOnlyMatch[1];
    if (!isValidUUID(id)) return Response.json({ error: "Invalid room ID" }, { status: 400, headers: corsHeaders });
    const viewOnlyIP = getClientIP(req);
    if (!(await checkRateLimit(viewOnlyIP, req.method === "GET" ? "room-view-only-read" : "room-view-only", settings, VIEW_ONLY_RATE_MAX, VIEW_ONLY_RATE_WINDOW))) {
      return Response.json({ error: "Too many requests. Try again later." }, { status: 429, headers: corsHeaders });
    }
    const room = loadRoom(id);
    if (!room) return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });

    if (req.method === "GET") {
      return Response.json({ viewOnly: isRoomViewOnly(id) }, { headers: corsHeaders });
    }

    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    const userToken = getUserTokenFromRequest(req);
    const user = userToken ? await oidc.validateUserSessionToken(userToken) : null;
    const isOwner = !!(room.ownerUserId && user && user.id === room.ownerUserId);
    const isAdmin = user?.role === 'admin';
    if (!isOwner && !isAdmin) {
      return Response.json({ error: "Only room owner or admin can change this" }, { status: 403, headers: corsHeaders });
    }
    try {
      const body = await readJsonLimited(req, VIEW_ONLY_BODY_CAP);
      if (typeof body?.viewOnly !== "boolean") {
        return Response.json({ error: "viewOnly must be a boolean" }, { status: 400, headers: corsHeaders });
      }
      setRoomViewOnly(id, body.viewOnly);
      let notified = 0;
      try { notified = broadcastRoomPermissions(id); } catch {  }
      db.addAuditLog({
        timestamp: new Date().toISOString(),
        action: body.viewOnly ? "room_view_only_on" : "room_view_only_off",
        actor: user!.id, actorIp: getClientIP(req), targetType: "room", targetId: id
      });
      return Response.json({ viewOnly: body.viewOnly, notified }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
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
      if (!(await validateRoomAccessTokenAsync(accessToken, id))) {
        return Response.json({ error: "Room password required" }, { status: 403, headers: corsHeaders });
      }
    }

    if (room.allowGuests === false || !oidc.getAuthSettings().allowGuestRoomJoin) {
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
      await readJsonLimited(req, JSON_BODY_CAP);
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

  const scene3dMatch = path.match(/^\/api\/room\/([\w-]+)\/scene3d(?:\/by-code\/([A-Za-z0-9_-]{1,64}))?$/);
  if (scene3dMatch && (req.method === "GET" || (req.method === "PUT" && !scene3dMatch[2]))) {
    const id = scene3dMatch[1];
    const byCode = scene3dMatch[2] || null;
    if (!settings.enable3d) return Response.json({ error: "3D is disabled on this instance" }, { status: 404, headers: corsHeaders });
    if (!isValidUUID(id)) return Response.json({ error: "Invalid room ID" }, { status: 400, headers: corsHeaders });
    const room = loadRoom(id);
    if (!room) return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });

    if (room.passwordHash) {
      const prodMode = oidc.getAuthSettings().productionMode;
      const accessToken = extractRoomAccessCookie(req.headers.get('cookie') || '', prodMode);
      if (!(await validateRoomAccessTokenAsync(accessToken, id))) return Response.json({ error: "Room password required" }, { status: 403, headers: corsHeaders });
    }
    const caller = await identifyRoomCaller(req, id);
    if (room.allowGuests === false && !caller.userId) {
      return Response.json({ error: "Authentication required" }, { status: 401, headers: corsHeaders });
    }

    if (req.method === "GET") {
      if (byCode) {
        if (!(await checkRateLimit(rateKeyFor(req, caller), `scene3d-code-${id}`, settings, SCENE3D_CODE_RATE_MAX, SCENE3D_RATE_WINDOW))) {
          return Response.json({ error: "Too many requests. Try again later." }, { status: 429, headers: { ...corsHeaders, "Retry-After": String(SCENE3D_RATE_WINDOW) } });
        }
        const snap = db.getSceneByCode(byCode);
        if (!snap) return Response.json({ error: "Unknown scene code" }, { status: 404, headers: corsHeaders });
        let clean: Scene3d | null = null;
        try { const p = JSON.parse(snap); delete p.code; clean = sanitizeScene3d(p); } catch { clean = null; }
        if (!clean) return Response.json({ error: "Unreadable scene" }, { status: 404, headers: corsHeaders });
        return Response.json(clean, { headers: corsHeaders });
      }
      const data = db.getScene3d(id);
      return new Response(data || '{}', { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    if (!canWrite(resolveRoomRole(room, caller.userId), isRoomViewOnly(id))) {
      return Response.json({ error: "This room is view only" }, { status: 403, headers: corsHeaders });
    }
    if (!(await checkRateLimit(rateKeyFor(req, caller), `scene3d-${id}`, settings, SCENE3D_PUT_RATE_MAX, SCENE3D_RATE_WINDOW))) {
      return Response.json({ error: "Too many updates. Try again later." }, { status: 429, headers: { ...corsHeaders, "Retry-After": String(SCENE3D_RATE_WINDOW) } });
    }
    try {
      const raw = await readTextLimited(req, SCENE3D_BODY_CAP);
      if (raw.length > SCENE3D_BODY_CAP) return Response.json({ error: "Scene too large" }, { status: 413, headers: corsHeaders });
      let parsed;
      try { parsed = JSON.parse(raw); } catch { return Response.json({ error: "Invalid JSON" }, { status: 400, headers: corsHeaders }); }
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return Response.json({ error: "Scene must be an object" }, { status: 400, headers: corsHeaders });
      }
      let stored: Scene3d | null = null;
      const existingRaw = db.getScene3d(id);
      if (existingRaw) { try { const p = JSON.parse(existingRaw); delete p.code; stored = sanitizeScene3d(p); } catch { stored = null; } }

      const hadTabsKey = !!(parsed.tabs && typeof parsed.tabs === "object" && !Array.isArray(parsed.tabs));
      if (!hadTabsKey && storedIsPopulatedV2(stored)) {
        return Response.json({ error: "scene-version-conflict" }, { status: 409, headers: corsHeaders });
      }

      const sanitized = sanitizeScene3dWithMeta(parsed);
      if (!sanitized) return Response.json({ error: "Invalid scene" }, { status: 400, headers: corsHeaders });
      const merged = mergeScene3d(stored, sanitized.scene, sanitized.meta);
      const code = db.persistScene3d(id, merged.scene);
      const body: any = { saved: true, code, rev: merged.scene.rev, tabs: {} };
      for (const k of Object.keys(merged.revs)) body.tabs[k] = { rev: merged.revs[k] };
      if (merged.conflicts.length) body.conflicts = merged.conflicts;
      const droppedFurn = sanitized.meta.droppedFurniture + merged.dropped.furn;
      const droppedKeys = sanitized.meta.droppedMapKeys + merged.dropped.keys;
      if (droppedFurn > 0 || droppedKeys > 0) {
        body.truncated = true;
        body.droppedFurniture = droppedFurn;
        body.droppedMapKeys = droppedKeys;
        if (Object.keys(merged.dropped.byTab).length) body.droppedByTab = merged.dropped.byTab;
      }
      return Response.json(body, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path.match(/^\/api\/room\/[\w-]+\/asset$/) && req.method === "POST") {
    const id = path.split("/")[3];
    if (!settings.enable3d) return Response.json({ error: "3D is disabled on this instance" }, { status: 404, headers: corsHeaders });
    if (!isValidUUID(id)) return Response.json({ error: "Invalid room ID" }, { status: 400, headers: corsHeaders });
    const room = loadRoom(id);
    if (!room) return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });
    if (room.passwordHash) {
      const prodMode = oidc.getAuthSettings().productionMode;
      const accessToken = extractRoomAccessCookie(req.headers.get('cookie') || '', prodMode);
      if (!(await validateRoomAccessTokenAsync(accessToken, id))) return Response.json({ error: "Room password required" }, { status: 403, headers: corsHeaders });
    }
    const caller = await identifyRoomCaller(req, id);
    if (room.allowGuests === false && !caller.userId) {
      return Response.json({ error: "Authentication required" }, { status: 401, headers: corsHeaders });
    }
    if (!canWrite(resolveRoomRole(room, caller.userId), isRoomViewOnly(id))) {
      return Response.json({ error: "This room is view only" }, { status: 403, headers: corsHeaders });
    }
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    if (!(await checkRateLimit(rateKeyFor(req, caller), `asset-${id}`, settings))) {
      return Response.json({ error: "Too many uploads. Try again later." }, { status: 429, headers: { ...corsHeaders, "Retry-After": String(SCENE3D_RATE_WINDOW) } });
    }
    try {
      const mime = (req.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
      const ALLOWED = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);
      const isModel = mime === "model/gltf-binary";
      if (!ALLOWED.has(mime) && !isModel) return Response.json({ error: "Unsupported asset type" }, { status: 415, headers: corsHeaders });
      const maxBytes = isModel ? ASSET_MODEL_CAP : ASSET_IMAGE_CAP;
      const bytes = await readBodyLimited(req, maxBytes);
      if (bytes.byteLength < 8 || bytes.byteLength > maxBytes) return Response.json({ error: `Asset must be 8 bytes to ${isModel ? 12 : 3} MB` }, { status: 413, headers: corsHeaders });
      const b = bytes;
      const okMagic = isModel
        ? (b[0] === 0x67 && b[1] === 0x6c && b[2] === 0x54 && b[3] === 0x46)
        : ((mime === "image/png" && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47)
          || (mime === "image/jpeg" && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff)
          || (mime === "image/gif" && b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46)
          || (mime === "image/webp" && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50));
      if (!okMagic) return Response.json({ error: "Content does not match declared type" }, { status: 415, headers: corsHeaders });
      const quota = checkAssetQuota(id, bytes.byteLength);
      if (!quota.ok) return Response.json({ error: quota.error }, { status: 413, headers: corsHeaders });
      const hash = createHash("sha256").update(bytes).digest("hex");
      writeBlob(hash, bytes);
      const now = new Date().toISOString();
      db.insertAsset({ hash, size_bytes: bytes.byteLength, mime, width: null, height: null, created_at: now });
      db.linkRoomAsset(id, hash, now);
      return Response.json({ hash }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }
  if (path.match(/^\/api\/asset\/[0-9a-f]{64}$/) && req.method === "GET") {
    if (!settings.enable3d) return new Response("Not found", { status: 404, headers: corsHeaders });
    const hash = path.split("/")[3];
    const a = db.getAsset(hash);
    const bytes = a ? readBlob(hash) : null;
    if (!a || !bytes) return new Response("Not found", { status: 404, headers: corsHeaders });
    return new Response(bytes as unknown as BodyInit, { headers: { ...corsHeaders, "Content-Type": a.mime, "Cache-Control": "public, max-age=31536000, immutable", "X-Content-Type-Options": "nosniff" } });
  }

  return null;
}
