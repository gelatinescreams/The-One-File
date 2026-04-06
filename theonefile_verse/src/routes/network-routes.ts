import * as network from "../network";
import * as db from "../database";
import { getSettings, isValidUUID } from "../config";
import { getClientIP, apiError, validateRequestCsrf, csrfReject, validateAdminUser } from "../security";
import { checkRateLimit } from "../rate-limit";
import { roomConnections } from "../rooms";
import { fetchLatestFromGitHub, theOneFileHtml } from "../rooms";

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  const settings = getSettings();

  if (path === "/api/probe" && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    if (!settings.probeEnabled) {
      return Response.json({ error: "Probing is disabled" }, { status: 403, headers: corsHeaders });
    }
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "probe", settings, 60))) {
      return Response.json({ error: "Too many probe requests. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      const target = body.target;
      const probes = body.probes;
      const timeout = Math.min(Math.max(parseInt(body.timeout) || 3000, 1000), 10000);
      if (!target || typeof target !== "string" || !network.validateTarget(target)) {
        return Response.json({ error: "Invalid target" }, { status: 400, headers: corsHeaders });
      }
      if (!network.validateProbeConfig(probes)) {
        return Response.json({ error: "Invalid probe configuration" }, { status: 400, headers: corsHeaders });
      }
      const result = await network.probeTarget(target, probes, timeout);
      return Response.json(result, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/probe/batch" && req.method === "POST") {
    if (!validateRequestCsrf(req)) return csrfReject(corsHeaders);
    if (!settings.probeEnabled) {
      return Response.json({ error: "Probing is disabled" }, { status: 403, headers: corsHeaders });
    }
    const clientIP = getClientIP(req);
    if (!(await checkRateLimit(clientIP, "probe-batch", settings, 30))) {
      return Response.json({ error: "Too many batch probe requests. Try again later." }, { status: 429, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (!body.targets || !Array.isArray(body.targets) || body.targets.length === 0 || body.targets.length > 50) {
        return Response.json({ error: "Invalid targets (1-50 required)" }, { status: 400, headers: corsHeaders });
      }
      const validTargets: network.BatchTarget[] = [];
      for (const t of body.targets) {
        if (!t.nodeId || typeof t.nodeId !== "string") continue;
        if (!t.target || !network.validateTarget(t.target)) continue;
        if (!network.validateProbeConfig(t.probes)) continue;
        const timeout = Math.min(Math.max(parseInt(t.timeout) || 3000, 1000), 10000);
        validTargets.push({ nodeId: t.nodeId, target: t.target, probes: t.probes, timeout });
      }
      if (validTargets.length === 0) {
        return Response.json({ error: "No valid targets" }, { status: 400, headers: corsHeaders });
      }
      const results = await network.probeBatch(validTargets);
      return Response.json({ results }, { headers: corsHeaders });
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
      const body = await req.json();
      const roomId = body.roomId;
      if (!roomId || !isValidUUID(roomId)) {
        return Response.json({ error: "Valid room ID required" }, { status: 400, headers: corsHeaders });
      }
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
      const taskPrefix = `disc-${roomId}`;
      if (network.hasActiveDiscoveryForRoom(roomId, taskPrefix)) {
        return Response.json({ error: "A scan is already running for this room" }, { status: 409, headers: corsHeaders });
      }
      const taskId = `${taskPrefix}-${Date.now()}`;
      const options: network.DiscoveryOptions = {
        icmp: body.options?.icmp !== false,
        tcp: body.options?.tcp !== false,
        dns: body.options?.dns !== false,
        netbios: body.options?.netbios !== false,
        mdns: body.options?.mdns !== false,
        snmp: body.options?.snmp === true,
        snmpCommunity: (typeof body.options?.snmpCommunity === "string" && body.options.snmpCommunity.length <= 64) ? body.options.snmpCommunity : "public",
        ports: Array.isArray(body.options?.ports) ? body.options.ports.filter((p: unknown) => typeof p === "number" && network.validatePort(p)) : [],
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
            const msg = JSON.stringify({ type: "discovery-found", taskId, host });
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
      const body = await req.json();
      if (!body.taskId || typeof body.taskId !== "string") {
        return Response.json({ error: "Task ID required" }, { status: 400, headers: corsHeaders });
      }
      const cancelled = network.cancelDiscovery(body.taskId);
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
      const body = await req.json();
      const roomId = body.roomId;
      if (!roomId || !isValidUUID(roomId)) {
        return Response.json({ error: "Valid room ID required" }, { status: 400, headers: corsHeaders });
      }
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
      const scanId = `deepscan-${ip}-${Date.now()}`;
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
            const msg = JSON.stringify({ type: "deepscan-update", scanId, ip, newPorts, newServices, containers, newIcons });
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
      const body = await req.json();
      if (!body.scanId || typeof body.scanId !== "string") {
        return Response.json({ error: "Scan ID required" }, { status: 400, headers: corsHeaders });
      }
      const cancelled = network.cancelDeepScan(body.scanId);
      return Response.json({ cancelled }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/refresh" && req.method === "POST") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    if (settings.skipUpdates) return Response.json({ error: "Updates disabled" }, { status: 400, headers: corsHeaders });
    const success = await fetchLatestFromGitHub();
    return Response.json({ success, size: theOneFileHtml.length }, { headers: corsHeaders });
  }

  return null;
}
