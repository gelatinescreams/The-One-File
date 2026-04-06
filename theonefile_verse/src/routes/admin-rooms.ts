import * as db from "../database";
import { isValidUUID } from "../config";
import { getClientIP, validateAdminOrApiKey } from "../security";
import { roomMeta, deleteRoomData } from "../rooms";

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

  if (path.match(/^\/api\/admin\/rooms\/[\w-]+$/) && req.method === "DELETE") {
    const { user, apiKey } = await validateAdminOrApiKey(req, "admin");
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
