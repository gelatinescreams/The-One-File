import * as db from "../database";
import { isValidUUID, getSettings, getMaxRoomSizeBytes } from "../config";
import { getClientIP, validateAdminOrApiKey, readJsonLimited, apiError } from "../security";
import { roomMeta, deleteRoomData, saveRoom, loadRoom, scheduleDestruction, setRoomViewOnly, isRoomViewOnly, hashPassword, clearTopologyCache, validateTopology, storageQuotaAllows, storedRoomBytes, STORAGE_QUOTA_ERROR, type Room } from "../rooms";
import { pushRoomReset, disconnectRoomGuestsAfterPasswordChange } from "../websocket";
import { revokeRoomAccessTokensForRoom } from "../tokens";

const ROOM_BODY_CAP = 16 * 1024;
const MAX_DESTRUCT_MS = 30 * 24 * 60 * 60 * 1000;

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  if (path === "/api/admin/rooms" && req.method === "GET") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "read");
    if (!user && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const searchQuery = url.searchParams.get("q") || "";
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "100") || 100, 1000);
    const offset = parseInt(url.searchParams.get("offset") || "0");
    const dbRooms = searchQuery ? db.searchRooms(searchQuery, limit, offset) : db.listRooms(limit, offset);
    const rooms = dbRooms.map(room => {
      const meta = roomMeta.get(room.id);
      return {
        id: room.id,
        created: room.created,
        lastActivity: room.lastActivity,
        hasPassword: !!room.passwordHash,
        destruct: room.destruct,
        connectedUsers: meta?.connectedUsers || 0
      };
    });
    return Response.json({ rooms, total: db.countRooms() }, { headers: corsHeaders });
  }

  if (path === "/api/admin/rooms" && req.method === "POST") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "write");
    if (!user && !apiKey) return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    try {
      const body = await readJsonLimited(req, ROOM_BODY_CAP);
      const settings = getSettings();
      if (settings.maxRoomsPerInstance > 0 && db.countRooms() >= settings.maxRoomsPerInstance) {
        return Response.json({ error: "Maximum number of rooms reached" }, { status: 403, headers: corsHeaders });
      }
      const modes = ["time", "empty", "never"];
      const mode = modes.includes(body.destructMode) ? body.destructMode : settings.defaultDestructMode;
      const value = typeof body.destructValue === "number" ? Math.min(Math.max(0, body.destructValue), MAX_DESTRUCT_MS) : Math.min(Math.max(1, settings.defaultDestructHours || 24) * 3600000, MAX_DESTRUCT_MS);
      if (body.password !== undefined && body.password !== null && (typeof body.password !== "string" || body.password.length < 8)) {
        return Response.json({ error: "Room password must be at least 8 characters" }, { status: 400, headers: corsHeaders });
      }
      const id = crypto.randomUUID();
      const now = new Date().toISOString();
      const room: Room = {
        id, created: now, lastActivity: now, creatorId: crypto.randomUUID(),
        passwordHash: body.password ? await hashPassword(body.password) : null,
        destruct: { mode, value }, topology: null, ownerUserId: user ? user.id : null,
        allowGuests: body.allowGuests !== false
      } as Room;
      saveRoom(room);
      if (mode === "time") scheduleDestruction(id, value);
      const actor = user ? user.id : `apikey:${apiKey!.name}`;
      db.addAuditLog({ timestamp: now, action: "room_created", actor, actorIp: getClientIP(req), targetType: "room", targetId: id });
      return Response.json({ id, url: `/s/${id}`, hasPassword: !!room.passwordHash, destruct: room.destruct, allowGuests: room.allowGuests }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  const viewOnly = path.match(/^\/api\/admin\/rooms\/([\w-]+)\/view-only$/);
  if (viewOnly && req.method === "PUT") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "write");
    if (!user && !apiKey) return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    const id = viewOnly[1];
    if (!isValidUUID(id) || !loadRoom(id)) return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });
    try {
      const body = await readJsonLimited(req, ROOM_BODY_CAP);
      if (typeof body.viewOnly !== "boolean") return Response.json({ error: "viewOnly must be true or false" }, { status: 400, headers: corsHeaders });
      setRoomViewOnly(id, body.viewOnly);
      const actor = user ? user.id : `apikey:${apiKey!.name}`;
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "room_view_only_changed", actor, actorIp: getClientIP(req), targetType: "room", targetId: id, details: { viewOnly: body.viewOnly } });
      return Response.json({ success: true, viewOnly: isRoomViewOnly(id) }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  const topo = path.match(/^\/api\/admin\/rooms\/([\w-]+)\/topology$/);
  if (topo && req.method === "PUT") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "write");
    if (!user && !apiKey) return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    const id = topo[1];
    const room = isValidUUID(id) ? loadRoom(id) : null;
    if (!room) return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });
    try {
      const body = await readJsonLimited(req, getMaxRoomSizeBytes() + 1024 * 1024);
      const v = validateTopology(body.topology);
      if (!v.valid || !v.sanitized) return Response.json({ error: v.error || "Invalid topology" }, { status: 400, headers: corsHeaders });
      if (!storageQuotaAllows(JSON.stringify(v.sanitized).length, storedRoomBytes(id))) return Response.json({ error: STORAGE_QUOTA_ERROR }, { status: 507, headers: corsHeaders });
      clearTopologyCache(id);
      room.topology = v.sanitized;
      room.lastActivity = new Date().toISOString();
      saveRoom(room);
      if (body.resetScene3d === true) db.setScene3d(id, JSON.stringify({ version: 2, rev: 0, mpu: 0, wireMode: 0, tabs: {} }));
      if (body.viewOnly === false || body.viewOnly === true) setRoomViewOnly(id, body.viewOnly);
      const pushed = pushRoomReset(id, v.sanitized);
      const actor = user ? user.id : `apikey:${apiKey!.name}`;
      db.addAuditLog({ timestamp: room.lastActivity, action: "room_topology_replaced", actor, actorIp: getClientIP(req), targetType: "room", targetId: id, details: { resetScene3d: body.resetScene3d === true, pushed } });
      return Response.json({ success: true, pushed }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  const pw = path.match(/^\/api\/admin\/rooms\/([\w-]+)\/password$/);
  if (pw && req.method === "PUT") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "write");
    if (!user && !apiKey) return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    const id = pw[1];
    if (!isValidUUID(id) || !loadRoom(id)) return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });
    try {
      const body = await readJsonLimited(req, ROOM_BODY_CAP);
      if (body.password !== null && (typeof body.password !== "string" || body.password.length < 8)) {
        return Response.json({ error: "Room password must be at least 8 characters, or null to remove it" }, { status: 400, headers: corsHeaders });
      }
      db.updateRoomPassword(id, body.password ? await hashPassword(body.password) : null);
      clearTopologyCache(id);
      const revoked = revokeRoomAccessTokensForRoom(id);
      const disconnected = body.password ? disconnectRoomGuestsAfterPasswordChange(id) : 0;
      const actor = user ? user.id : `apikey:${apiKey!.name}`;
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "room_password_changed", actor, actorIp: getClientIP(req), targetType: "room", targetId: id, details: { hasPassword: !!body.password, revoked, disconnected } });
      return Response.json({ success: true, hasPassword: !!body.password, disconnected }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path.match(/^\/api\/admin\/rooms\/[\w-]+$/) && req.method === "DELETE") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "write");
    if (!user && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const id = path.split("/")[4];
    if (!isValidUUID(id)) {
      return Response.json({ error: "Invalid room ID" }, { status: 400, headers: corsHeaders });
    }
    if (deleteRoomData(id)) {
      const actor = user ? user.id : `apikey:${apiKey!.name}`;
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "room_deleted", actor, actorIp: getClientIP(req), targetType: "room", targetId: id });
      return Response.json({ deleted: true }, { headers: corsHeaders });
    }
    return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });
  }

  return null;
}
