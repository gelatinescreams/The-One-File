import * as network from "../network";
import * as db from "../database";
import { getSettings, isValidUUID } from "../config";
import { getClientIP, apiError, validateRequestCsrf, csrfReject, validateAdminUser, readJsonLimited, getUserTokenFromRequest } from "../security";
import * as oidc from "../oidc";
import { checkRateLimit } from "../rate-limit";
import { roomConnections, loadRoom, currentTopology, type Room } from "../rooms";
import { checkRoomAccess, type RoomCaller } from "./room";
import { fetchLatestFromGitHub, theOneFileHtml } from "../rooms";

const NETWORK_BODY_CAP = 256 * 1024;

export const PROBE_USER_BUDGET_PER_HOUR = 1200;
const PROBE_BUDGET_WINDOW_SECONDS = 3600;

function normalizeProbeTarget(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase().replace(/\.$/, "") : "";
}

function addTargetsFromNodes(nodes: any, out: Set<string>): void {
  if (!nodes || typeof nodes !== "object" || Array.isArray(nodes)) return;
  for (const key of Object.keys(nodes)) {
    const n = nodes[key];
    if (!n || typeof n !== "object") continue;
    const ip = normalizeProbeTarget(n.ip);
    if (ip) out.add(ip);
    const custom = n.ping && typeof n.ping === "object" ? n.ping.customUrl : null;
    const c = normalizeProbeTarget(custom);
    if (c) {
      out.add(c);
      try { const host = new URL(c.includes("://") ? c : `http://${c}`).hostname; if (host) out.add(normalizeProbeTarget(host.replace(/^\[|\]$/g, ""))); } catch {  }
    }
  }
}

export function roomProbeTargets(topology: any): Set<string> {
  const out = new Set<string>();
  if (!topology || typeof topology !== "object") return out;
  addTargetsFromNodes(topology.nodeData, out);
  if (Array.isArray(topology.documentTabs)) {
    for (const tab of topology.documentTabs) if (tab && typeof tab === "object") addTargetsFromNodes(tab.nodes, out);
  }
  return out;
}

async function authorizeRoomMember(req: Request, roomId: unknown, corsHeaders: Record<string, string>): Promise<{ room?: Room; caller?: RoomCaller; response?: Response }> {
  if (typeof roomId !== "string" || !isValidUUID(roomId)) {
    return { response: Response.json({ error: "Valid room ID required" }, { status: 400, headers: corsHeaders }) };
  }
  const room = loadRoom(roomId);
  if (!room) return { response: Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders }) };
  const access = await checkRoomAccess(req, room);
  if (!access.ok) return { response: Response.json({ error: access.error }, { status: access.status, headers: corsHeaders }) };
  return { room, caller: access.caller };
}

interface ScanOwner { owner: string; roomId: string; createdAt: number }
const SCAN_OWNER_TTL_MS = 6 * 60 * 60 * 1000;
const scanOwners = new Map<string, ScanOwner>();

function rememberScanOwner(id: string, owner: string, roomId: string): void {
  const now = Date.now();
  for (const [k, v] of scanOwners) if (now - v.createdAt > SCAN_OWNER_TTL_MS) scanOwners.delete(k);
  scanOwners.set(id, { owner, roomId, createdAt: now });
}

async function scanCallerKey(req: Request): Promise<{ key: string; isAdmin: boolean }> {
  const token = getUserTokenFromRequest(req);
  const user = token ? await oidc.validateUserSessionToken(token) : null;
  if (user) return { key: `u:${user.id}`, isAdmin: user.role === "admin" };
  return { key: `ip:${getClientIP(req)}`, isAdmin: false };
}

async function authorizeScanCancel(req: Request, id: string): Promise<boolean> {
  const caller = await scanCallerKey(req);
  if (caller.isAdmin) return true;
  const rec = scanOwners.get(id);
  return !!rec && rec.owner === caller.key;
}

function randomScanSuffix(): string {
  return oidc.generateSecureToken(16).replace(/[^A-Za-z0-9]/g, "").slice(0, 22);
}

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  const settings = getSettings();

  if (path === "/api/probe" && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    if (!settings.probeEnabled) {
      return Response.json({ error: "Probing is disabled" }, { status: 403, headers: corsHeaders });
    }
    const probeToken = getUserTokenFromRequest(req);
    const probeUser = probeToken ? await oidc.validateUserSessionToken(probeToken) : null;
    if (!probeUser) {
      return Response.json({ error: "Probing requires login" }, { status: 401, headers: corsHeaders });
    }
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "probe", settings, 60))) {
      return Response.json({ error: "Too many probe requests. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await readJsonLimited(req, NETWORK_BODY_CAP);
      const member = await authorizeRoomMember(req, body.roomId, corsHeaders);
      if (member.response) return member.response;
      const target = body.target;
      const probes = body.probes;
      const timeout = Math.min(Math.max(parseInt(body.timeout) || 3000, 1000), 10000);
      if (!target || typeof target !== "string" || !network.validateTarget(target)) {
        return Response.json({ error: "Invalid target" }, { status: 400, headers: corsHeaders });
      }
      if (network.isBlockedProbeTarget(target)) {
        return Response.json({ error: "Target not allowed" }, { status: 400, headers: corsHeaders });
      }
      if (!roomProbeTargets(currentTopology(member.room!.id)).has(normalizeProbeTarget(target))) {
        return Response.json({ error: "Target is not a node in this room" }, { status: 403, headers: corsHeaders });
      }
      if (!network.validateProbeConfig(probes)) {
        return Response.json({ error: "Invalid probe configuration" }, { status: 400, headers: corsHeaders });
      }
      if (!(await checkRateLimit(`u:${probeUser.id}`, "probe-budget", settings, PROBE_USER_BUDGET_PER_HOUR, PROBE_BUDGET_WINDOW_SECONDS))) {
        return Response.json({ error: "Probe budget used up for this hour. Try again later." }, { status: 429, headers: corsHeaders });
      }
      const result = await network.probeTarget(target, probes, timeout);
      return Response.json(network.sanitizeScanText(result), { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/probe/batch" && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    if (!settings.probeEnabled) {
      return Response.json({ error: "Probing is disabled" }, { status: 403, headers: corsHeaders });
    }
    const probeToken = getUserTokenFromRequest(req);
    const probeUser = probeToken ? await oidc.validateUserSessionToken(probeToken) : null;
    if (!probeUser) {
      return Response.json({ error: "Probing requires login" }, { status: 401, headers: corsHeaders });
    }
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "probe-batch", settings, 30))) {
      return Response.json({ error: "Too many batch probe requests. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await readJsonLimited(req, NETWORK_BODY_CAP);
      const member = await authorizeRoomMember(req, body.roomId, corsHeaders);
      if (member.response) return member.response;
      const allowed = roomProbeTargets(currentTopology(member.room!.id));
      if (!body.targets || !Array.isArray(body.targets) || body.targets.length === 0 || body.targets.length > 50) {
        return Response.json({ error: "Invalid targets (1-50 required)" }, { status: 400, headers: corsHeaders });
      }
      const validTargets: network.BatchTarget[] = [];
      for (const t of body.targets) {
        if (!t.nodeId || typeof t.nodeId !== "string") continue;
        if (!t.target || !network.validateTarget(t.target)) continue;
        if (network.isBlockedProbeTarget(t.target)) continue;
        if (!allowed.has(normalizeProbeTarget(t.target))) continue;
        if (!network.validateProbeConfig(t.probes)) continue;
        const timeout = Math.min(Math.max(parseInt(t.timeout) || 3000, 1000), 10000);
        validTargets.push({ nodeId: t.nodeId, target: t.target, probes: t.probes, timeout });
      }
      if (validTargets.length === 0) {
        return Response.json({ error: "No valid targets" }, { status: 400, headers: corsHeaders });
      }
      for (let i = 0; i < validTargets.length; i++) {
        if (!(await checkRateLimit(`u:${probeUser.id}`, "probe-budget", settings, PROBE_USER_BUDGET_PER_HOUR, PROBE_BUDGET_WINDOW_SECONDS))) {
          return Response.json({ error: "Probe budget used up for this hour. Try again later." }, { status: 429, headers: corsHeaders });
        }
      }
      const results = await network.probeBatch(validTargets);
      return Response.json({ results: network.sanitizeScanText(results) }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/discover/ports" && req.method === "GET") {
    return Response.json({ ports: network.getDefaultPortList() }, { headers: corsHeaders });
  }

  if (path === "/api/discover" && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    if (!settings.discoveryEnabled) {
      return Response.json({ error: "Discovery is disabled" }, { status: 403, headers: corsHeaders });
    }
    if (settings.discoveryAdminOnly) {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Discovery requires admin access" }, { status: 401, headers: corsHeaders });
      }
    }
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "discover", settings))) {
      return Response.json({ error: "Too many discovery requests. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await readJsonLimited(req, NETWORK_BODY_CAP);
      const member = await authorizeRoomMember(req, body.roomId, corsHeaders);
      if (member.response) return member.response;
      const roomId = member.room!.id;
      let cidrs: string[] = [];
      if (Array.isArray(body.cidrs) && body.cidrs.length > 0) {
        cidrs = body.cidrs.filter((c: unknown) => typeof c === "string" && c.length > 0);
      } else if (body.cidr && typeof body.cidr === "string") {
        cidrs = [body.cidr];
      }
      if (cidrs.length === 0) {
        return Response.json({ error: "At least one CIDR range required" }, { status: 400, headers: corsHeaders });
      }
      if (cidrs.length > 10) {
        return Response.json({ error: "Maximum 10 ranges per scan" }, { status: 400, headers: corsHeaders });
      }
      let totalCount = 0;
      for (const cidr of cidrs) {
        const validation = network.validateCIDR(cidr, settings.discoveryAllowPublicRanges, settings.discoveryMaxPrefix);
        if (!validation.valid) {
          return Response.json({ error: `${cidr}: ${validation.error}` }, { status: 400, headers: corsHeaders });
        }
        totalCount += validation.count || 0;
      }
      const MAX_DISCOVERY_HOSTS = 8192;
      if (totalCount > MAX_DISCOVERY_HOSTS) {
        return Response.json({ error: `Scan too large (${totalCount} hosts). Maximum is ${MAX_DISCOVERY_HOSTS} per scan.` }, { status: 400, headers: corsHeaders });
      }
      const taskPrefix = `disc-${roomId}`;
      if (network.hasActiveDiscoveryForRoom(roomId, taskPrefix)) {
        return Response.json({ error: "A scan is already running for this room" }, { status: 409, headers: corsHeaders });
      }
      const taskId = `${taskPrefix}-${randomScanSuffix()}`;
      rememberScanOwner(taskId, (await scanCallerKey(req)).key, roomId);
      const options: network.DiscoveryOptions = {
        icmp: body.options?.icmp !== false,
        tcp: body.options?.tcp !== false,
        dns: body.options?.dns !== false,
        netbios: body.options?.netbios !== false,
        mdns: body.options?.mdns !== false,
        snmp: body.options?.snmp === true,
        snmpCommunity: (typeof body.options?.snmpCommunity === "string" && /^[a-zA-Z0-9._-]{1,64}$/.test(body.options.snmpCommunity)) ? body.options.snmpCommunity : "public",
        ports: Array.isArray(body.options?.ports) ? body.options.ports.filter((p: unknown) => typeof p === "number" && network.validatePort(p)).slice(0, 256) : [],
      };
      const connections = roomConnections.get(roomId);
      await network.startDiscovery(
        taskId,
        roomId,
        cidrs,
        options,
        (percent, scanned, total, rangeIndex, totalRanges) => {
          if (connections) {
            const msg = JSON.stringify({ type: "discovery-progress", taskId, percent, scanned, total, rangeIndex, totalRanges });
            for (const ws of connections) ws.send(msg);
          }
        },
        (host) => {
          if (connections) {
            const msg = JSON.stringify({ type: "discovery-found", taskId, host: network.sanitizeScanText(host) });
            for (const ws of connections) ws.send(msg);
          }
        },
        (totalFound) => {
          if (connections) {
            const msg = JSON.stringify({ type: "discovery-complete", taskId, totalFound });
            for (const ws of connections) ws.send(msg);
          }
        },
      );
      return Response.json({ taskId, count: totalCount, ranges: cidrs.length }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/discover/cancel" && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    try {
      const body = await readJsonLimited(req, NETWORK_BODY_CAP);
      if (!body.taskId || typeof body.taskId !== "string") {
        return Response.json({ error: "Task ID required" }, { status: 400, headers: corsHeaders });
      }
      if (!(await authorizeScanCancel(req, body.taskId))) {
        return Response.json({ error: "Only the person who started this scan or an administrator can cancel it" }, { status: 403, headers: corsHeaders });
      }
      const cancelled = network.cancelDiscovery(body.taskId);
      if (cancelled) scanOwners.delete(body.taskId);
      return Response.json({ cancelled }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/discover/deepscan" && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    if (!settings.discoveryEnabled) {
      return Response.json({ error: "Discovery is disabled" }, { status: 403, headers: corsHeaders });
    }
    if (settings.discoveryAdminOnly) {
      const adminUser = await validateAdminUser(req);
      if (!adminUser) {
        return Response.json({ error: "Discovery requires admin access" }, { status: 401, headers: corsHeaders });
      }
    }
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "deepscan", settings, 10, 120))) {
      return Response.json({ error: "Too many deep scan requests. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await readJsonLimited(req, NETWORK_BODY_CAP);
      const member = await authorizeRoomMember(req, body.roomId, corsHeaders);
      if (member.response) return member.response;
      const roomId = member.room!.id;
      const ip = body.ip;
      if (!ip || typeof ip !== "string" || !network.validateIPv4(ip)) {
        return Response.json({ error: "Valid IP address required" }, { status: 400, headers: corsHeaders });
      }
      if (!network.isRFC1918(ip)) {
        return Response.json({ error: "Only private IP addresses allowed for deep scan" }, { status: 400, headers: corsHeaders });
      }
      if (network.hasActiveDeepScan(ip)) {
        return Response.json({ error: "A deep scan is already running for this host" }, { status: 409, headers: corsHeaders });
      }
      const existingPorts: number[] = Array.isArray(body.existingPorts)
        ? body.existingPorts.filter((p: unknown) => typeof p === "number" && network.validatePort(p))
        : [];
      const scanId = `deepscan-${ip}-${randomScanSuffix()}`;
      rememberScanOwner(scanId, (await scanCallerKey(req)).key, roomId);
      const connections = roomConnections.get(roomId);
      await network.startDeepScan(
        scanId,
        ip,
        existingPorts,
        (percent, scanned, total) => {
          if (connections) {
            const msg = JSON.stringify({ type: "deepscan-progress", scanId, ip, percent, scanned, total });
            for (const ws of connections) ws.send(msg);
          }
        },
        (newPorts, newServices, containers) => {
          if (connections) {
            const newIcons = network.getServiceIcons(newPorts);
            const msg = JSON.stringify({ type: "deepscan-update", scanId, ip, newPorts, newServices: network.sanitizeScanText(newServices), containers: network.sanitizeScanText(containers), newIcons });
            for (const ws of connections) ws.send(msg);
          }
        },
        () => {
          if (connections) {
            const msg = JSON.stringify({ type: "deepscan-complete", scanId, ip });
            for (const ws of connections) ws.send(msg);
          }
        },
      );
      return Response.json({ scanId, ip }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/discover/deepscan/cancel" && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    try {
      const body = await readJsonLimited(req, NETWORK_BODY_CAP);
      if (!body.scanId || typeof body.scanId !== "string") {
        return Response.json({ error: "Scan ID required" }, { status: 400, headers: corsHeaders });
      }
      if (!(await authorizeScanCancel(req, body.scanId))) {
        return Response.json({ error: "Only the person who started this scan or an administrator can cancel it" }, { status: 403, headers: corsHeaders });
      }
      const cancelled = network.cancelDeepScan(body.scanId);
      if (cancelled) scanOwners.delete(body.scanId);
      return Response.json({ cancelled }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/refresh" && req.method === "POST") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    if (settings.skipUpdates) return Response.json({ error: "Updates disabled" }, { status: 400, headers: corsHeaders });
    const success = await fetchLatestFromGitHub(true);
    return Response.json({ success, size: theOneFileHtml.length }, { headers: corsHeaders });
  }

  return null;
}
