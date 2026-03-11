const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const HOSTNAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
const CIDR_RE = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/;

export interface ProbeConfig {
  type: "icmp" | "tcp" | "http" | "dns";
  port?: number;
  path?: string;
  url?: string;
}

export interface ProbeResult {
  type: string;
  port?: number;
  status: "online" | "offline" | "error";
  responseTime: number | null;
  detail?: string;
}

export interface BatchTarget {
  nodeId: string;
  target: string;
  probes: ProbeConfig[];
  timeout: number;
}

export interface BatchResult {
  status: "online" | "offline" | "unknown";
  rtt: number | null;
  results: ProbeResult[];
}

export interface DiscoveryOptions {
  icmp: boolean;
  tcp: boolean;
  dns: boolean;
  netbios: boolean;
  mdns: boolean;
  snmp: boolean;
  snmpCommunity: string;
  ports: number[];
}

export interface DiscoveredHost {
  ip: string;
  hostname: string;
  ports: number[];
  services: Record<number, string>;
  icon: { library: string; name: string };
  serviceIcons: { library: string; name: string }[];
  dnsName: string;
  netbiosName: string;
  mdnsName: string;
  httpServer: string;
  snmpName: string;
  snmpDescr: string;
}

interface DiscoveryHandle {
  taskId: string;
  cancelled: boolean;
  cancel: () => void;
}

const activeDiscoveries = new Map<string, DiscoveryHandle>();

const PORT_SERVICE_MAP: Record<number, string> = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  111: "RPC",
  135: "MSRPC",
  139: "NetBIOS",
  143: "IMAP",
  161: "SNMP",
  443: "HTTPS",
  445: "SMB",
  465: "SMTPS",
  514: "Syslog",
  515: "LPD",
  587: "Submission",
  631: "IPP",
  993: "IMAPS",
  995: "POP3S",
  1194: "OpenVPN",
  1433: "MSSQL",
  1521: "Oracle",
  1880: "Node RED",
  1883: "MQTT",
  2283: "Immich",
  2342: "PhotoPrism",
  2368: "Ghost",
  2375: "Docker API",
  2376: "Docker TLS",
  3000: "Grafana",
  3001: "Uptime Kuma",
  3100: "Loki",
  3306: "MySQL",
  3389: "RDP",
  3456: "Vikunja",
  3579: "Ombi",
  4533: "Navidrome",
  4646: "Nomad",
  4822: "Guacamole",
  5001: "Dockge",
  5055: "Overseerr",
  5060: "SIP",
  5380: "Technitium",
  5432: "PostgreSQL",
  5601: "Kibana",
  5672: "AMQP",
  5678: "n8n",
  5900: "VNC",
  6052: "ESPHome",
  6379: "Redis",
  6767: "Bazarr",
  6789: "NZBGet",
  7575: "Homarr",
  7878: "Radarr",
  8000: "Paperless ngx",
  8006: "Proxmox VE",
  8007: "Proxmox BS",
  8065: "Mattermost",
  8080: "HTTP Alt",
  8083: "Calibre Web",
  8086: "InfluxDB",
  8096: "Jellyfin",
  8112: "Deluge",
  8123: "Home Assistant",
  8181: "Tautulli",
  8200: "Vault",
  8384: "Syncthing",
  8443: "HTTPS Alt",
  8500: "Consul",
  8686: "Lidarr",
  8787: "Readarr",
  8883: "MQTTS",
  8920: "Emby",
  8971: "Frigate",
  8989: "Sonarr",
  9001: "MinIO",
  9090: "Prometheus",
  9091: "Authelia",
  9100: "JetDirect",
  9117: "Jackett",
  9200: "Elasticsearch",
  9443: "Portainer",
  9696: "Prowlarr",
  10000: "Webmin",
  11434: "Ollama",
  13378: "Audiobookshelf",
  19999: "Netdata",
  25600: "Komga",
  27017: "MongoDB",
  32400: "Plex",
  51820: "WireGuard",
  61208: "Glances",
};

const DEFAULT_SCAN_PORTS = [22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 443, 445, 515, 587, 631, 993, 1433, 1880, 2283, 2342, 2375, 2376, 3000, 3001, 3100, 3306, 3389, 4646, 4822, 5001, 5055, 5380, 5432, 5601, 5678, 5900, 6379, 6767, 7575, 7878, 8000, 8006, 8007, 8065, 8080, 8083, 8086, 8096, 8112, 8123, 8181, 8200, 8384, 8443, 8500, 8686, 8787, 8920, 8971, 8989, 9001, 9090, 9091, 9100, 9117, 9443, 9696, 10000, 11434, 13378, 19999, 25600, 27017, 32400, 61208];

interface ServiceIconEntry {
  ports: number[];
  library: string;
  name: string;
}

const SERVICE_ICON_MAP: ServiceIconEntry[] = [
  { ports: [8006, 8007], library: "selfhst", name: "proxmox" },
  { ports: [32400], library: "selfhst", name: "plex" },
  { ports: [8096], library: "selfhst", name: "jellyfin" },
  { ports: [8920], library: "selfhst", name: "emby" },
  { ports: [8989], library: "selfhst", name: "sonarr" },
  { ports: [7878], library: "selfhst", name: "radarr" },
  { ports: [8686], library: "selfhst", name: "lidarr" },
  { ports: [8787], library: "selfhst", name: "readarr" },
  { ports: [9696], library: "selfhst", name: "prowlarr" },
  { ports: [6767], library: "selfhst", name: "bazarr" },
  { ports: [5055], library: "selfhst", name: "overseerr" },
  { ports: [8181], library: "selfhst", name: "tautulli" },
  { ports: [3579], library: "selfhst", name: "ombi" },
  { ports: [4533], library: "selfhst", name: "navidrome" },
  { ports: [13378], library: "selfhst", name: "audiobookshelf" },
  { ports: [25600], library: "selfhst", name: "komga" },
  { ports: [9117], library: "selfhst", name: "jackett" },
  { ports: [8083], library: "selfhst", name: "calibre-web" },
  { ports: [8971], library: "selfhst", name: "frigate" },
  { ports: [8123], library: "selfhst", name: "home-assistant" },
  { ports: [1880], library: "selfhst", name: "node-red" },
  { ports: [6052], library: "selfhst", name: "esphome" },
  { ports: [5678], library: "selfhst", name: "n8n" },
  { ports: [3001], library: "selfhst", name: "uptime-kuma" },
  { ports: [19999], library: "selfhst", name: "netdata" },
  { ports: [3000], library: "selfhst", name: "grafana" },
  { ports: [9090], library: "selfhst", name: "prometheus" },
  { ports: [5601], library: "selfhst", name: "kibana" },
  { ports: [3100], library: "selfhst", name: "loki" },
  { ports: [61208], library: "selfhst", name: "glances" },
  { ports: [2283], library: "selfhst", name: "immich" },
  { ports: [2342], library: "selfhst", name: "photoprism" },
  { ports: [9443], library: "selfhst", name: "portainer" },
  { ports: [5001], library: "selfhst", name: "dockge" },
  { ports: [2375, 2376], library: "selfhst", name: "docker" },
  { ports: [9091], library: "selfhst", name: "authelia" },
  { ports: [8384], library: "selfhst", name: "syncthing" },
  { ports: [5380], library: "selfhst", name: "technitium-dns" },
  { ports: [8000], library: "selfhst", name: "paperless-ngx" },
  { ports: [8112], library: "selfhst", name: "deluge" },
  { ports: [6789], library: "selfhst", name: "nzbget" },
  { ports: [7575], library: "selfhst", name: "homarr" },
  { ports: [8065], library: "selfhst", name: "mattermost" },
  { ports: [8086], library: "selfhst", name: "influxdb" },
  { ports: [2368], library: "selfhst", name: "ghost" },
  { ports: [3456], library: "selfhst", name: "vikunja" },
  { ports: [11434], library: "selfhst", name: "ollama" },
  { ports: [4822], library: "selfhst", name: "guacamole" },
  { ports: [8500], library: "selfhst", name: "hashicorp-consul" },
  { ports: [8200], library: "selfhst", name: "hashicorp-vault" },
  { ports: [4646], library: "selfhst", name: "hashicorp-nomad" },
  { ports: [9001], library: "selfhst", name: "minio" },
  { ports: [1194], library: "selfhst", name: "openvpn" },
  { ports: [51820], library: "selfhst", name: "wireguard" },
  { ports: [10000], library: "selfhst", name: "webmin" },
  { ports: [3306], library: "selfhst", name: "mysql" },
  { ports: [5432], library: "selfhst", name: "postgresql" },
  { ports: [6379], library: "selfhst", name: "redis" },
  { ports: [27017], library: "selfhst", name: "mongodb" },
  { ports: [9200], library: "selfhst", name: "elasticsearch" },
  { ports: [1883, 8883], library: "selfhst", name: "mosquitto" },
  { ports: [5060], library: "selfhst", name: "asterisk" },
  { ports: [5672], library: "selfhst", name: "rabbitmq" },
  { ports: [9100, 515, 631], library: "selfhst", name: "cups" },
  { ports: [25, 465, 587], library: "selfhst", name: "mailcow" },
  { ports: [179], library: "selfhst", name: "openwrt" },
  { ports: [3389], library: "selfhst", name: "windows" },
  { ports: [5900], library: "selfhst", name: "vnc" },
  { ports: [22], library: "selfhst", name: "terminal" },
];

const DEFAULT_ICON = { library: "selfhst", name: "linux" };

export function validateIPv4(ip: string): boolean {
  const match = IPV4_RE.exec(ip);
  if (!match) return false;
  for (let i = 1; i <= 4; i++) {
    const octet = parseInt(match[i], 10);
    if (octet < 0 || octet > 255) return false;
  }
  return true;
}

export function validateHostname(host: string): boolean {
  if (!host || host.length > 253) return false;
  return HOSTNAME_RE.test(host);
}

export function validateTarget(target: string): boolean {
  return validateIPv4(target) || validateHostname(target);
}

export function isRFC1918(ip: string): boolean {
  const match = IPV4_RE.exec(ip);
  if (!match) return false;
  const a = parseInt(match[1], 10);
  const b = parseInt(match[2], 10);
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

export function validatePort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function ipToInt(ip: string): number {
  const parts = ip.split(".").map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

export function validateCIDR(cidr: string, allowPublic: boolean, maxPrefix: number): { valid: boolean; error?: string; firstIP?: string; lastIP?: string; count?: number } {
  const match = CIDR_RE.exec(cidr);
  if (!match) return { valid: false, error: "Invalid CIDR format" };

  const ip = match[1];
  const prefix = parseInt(match[2], 10);

  if (!validateIPv4(ip)) return { valid: false, error: "Invalid IP address" };
  if (prefix < 0 || prefix > 32) return { valid: false, error: "Prefix must be 0-32" };
  if (prefix < maxPrefix) return { valid: false, error: `Prefix must be /${maxPrefix} or larger (smaller range)` };

  if (!allowPublic && !isRFC1918(ip)) {
    return { valid: false, error: "Only private (RFC1918) ranges allowed" };
  }

  const ipInt = ipToInt(ip);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const network = (ipInt & mask) >>> 0;
  const broadcast = (network | ~mask) >>> 0;
  const count = broadcast - network + 1;

  return {
    valid: true,
    firstIP: intToIp(network),
    lastIP: intToIp(broadcast),
    count,
  };
}

async function probeICMP(target: string, timeoutMs: number): Promise<ProbeResult> {
  const timeoutSec = Math.max(1, Math.ceil(timeoutMs / 1000));
  const start = performance.now();
  try {
    const proc = Bun.spawn(["ping", "-c", "1", "-W", String(timeoutSec), target], {
      stdout: "pipe",
      stderr: "ignore",
    });
    const exitCode = await proc.exited;
    const elapsed = Math.round(performance.now() - start);

    if (exitCode === 0) {
      const output = await new Response(proc.stdout).text();
      const rttMatch = /time[=<](\d+\.?\d*)\s*ms/i.exec(output);
      const rtt = rttMatch ? Math.round(parseFloat(rttMatch[1])) : elapsed;
      return { type: "icmp", status: "online", responseTime: rtt };
    }
    return { type: "icmp", status: "offline", responseTime: null };
  } catch {
    return { type: "icmp", status: "error", responseTime: null, detail: "ping failed" };
  }
}

async function probeTCP(target: string, port: number, timeoutMs: number): Promise<ProbeResult> {
  const start = performance.now();
  try {
    const socket = await Promise.race([
      Bun.connect({
        hostname: target,
        port,
        socket: {
          data() {},
          open(socket) { socket.end(); },
          error() {},
          close() {},
        },
      }),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeoutMs)),
    ]);
    const elapsed = Math.round(performance.now() - start);
    const service = PORT_SERVICE_MAP[port] || "";
    return { type: "tcp", port, status: "online", responseTime: elapsed, detail: service || undefined };
  } catch {
    return { type: "tcp", port, status: "offline", responseTime: null };
  }
}

async function probeHTTP(target: string, config: ProbeConfig, timeoutMs: number): Promise<ProbeResult> {
  const url = config.url || `http://${target}${config.path || "/"}`;
  const start = performance.now();
  try {
    const resp = await fetch(url, {
      method: "HEAD",
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "manual",
    });
    const elapsed = Math.round(performance.now() - start);
    return {
      type: "http",
      status: resp.status < 500 ? "online" : "error",
      responseTime: elapsed,
      detail: `${resp.status} ${resp.statusText}`,
    };
  } catch {
    return { type: "http", status: "offline", responseTime: null };
  }
}

async function probeDNS(target: string, timeoutMs: number): Promise<ProbeResult> {
  const start = performance.now();
  try {
    if (validateIPv4(target)) {
      const proc = Bun.spawn(["nslookup", target], {
        stdout: "pipe",
        stderr: "ignore",
      });
      const raceResult = await Promise.race([
        proc.exited,
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeoutMs)),
      ]);
      const elapsed = Math.round(performance.now() - start);
      const output = await new Response(proc.stdout).text();
      const nameMatch = /name\s*=\s*(\S+)/i.exec(output);
      const hostname = nameMatch ? nameMatch[1].replace(/\.$/, "") : "";
      return { type: "dns", status: raceResult === 0 ? "online" : "offline", responseTime: elapsed, detail: hostname || undefined };
    } else {
      const results = await Bun.dns.resolve(target);
      const elapsed = Math.round(performance.now() - start);
      const ip = results.length > 0 ? (results[0] as any).address || String(results[0]) : "";
      return { type: "dns", status: "online", responseTime: elapsed, detail: ip || undefined };
    }
  } catch {
    return { type: "dns", status: "offline", responseTime: null };
  }
}

export async function probeTarget(target: string, probes: ProbeConfig[], timeout: number): Promise<{ status: "online" | "offline" | "unknown"; rtt: number | null; results: ProbeResult[] }> {
  const cappedTimeout = Math.min(timeout, 10000);
  const results: ProbeResult[] = [];

  for (const probe of probes) {
    let result: ProbeResult;
    switch (probe.type) {
      case "icmp":
        result = await probeICMP(target, cappedTimeout);
        break;
      case "tcp":
        if (!probe.port || !validatePort(probe.port)) continue;
        result = await probeTCP(target, probe.port, cappedTimeout);
        break;
      case "http":
        result = await probeHTTP(target, probe, cappedTimeout);
        break;
      case "dns":
        result = await probeDNS(target, cappedTimeout);
        break;
      default:
        continue;
    }
    results.push(result);
  }

  const onlineResults = results.filter((r) => r.status === "online");
  let status: "online" | "offline" | "unknown" = "unknown";
  if (results.length === 0) status = "unknown";
  else if (onlineResults.length > 0) status = "online";
  else status = "offline";

  const rtts = onlineResults.map((r) => r.responseTime).filter((t): t is number => t !== null);
  const rtt = rtts.length > 0 ? Math.min(...rtts) : null;

  return { status, rtt, results };
}

export async function probeBatch(targets: BatchTarget[]): Promise<Record<string, BatchResult>> {
  const results: Record<string, BatchResult> = {};
  const batchSize = 10;

  for (let i = 0; i < targets.length; i += batchSize) {
    const batch = targets.slice(i, i + batchSize);
    const promises = batch.map(async (t) => {
      const result = await probeTarget(t.target, t.probes, t.timeout);
      results[t.nodeId] = result;
    });
    await Promise.all(promises);
  }

  return results;
}

export function getServiceIcon(ports: number[]): { library: string; name: string } {
  for (const entry of SERVICE_ICON_MAP) {
    for (const port of ports) {
      if (entry.ports.includes(port)) return { library: entry.library, name: entry.name };
    }
  }
  return { ...DEFAULT_ICON };
}

const GENERIC_ICON_NAMES = new Set(["terminal", "windows", "vnc", "cups", "mailcow", "openwrt"]);

export function getServiceIcons(ports: number[]): { library: string; name: string }[] {
  const icons: { library: string; name: string }[] = [];
  const seen = new Set<string>();
  for (const entry of SERVICE_ICON_MAP) {
    if (GENERIC_ICON_NAMES.has(entry.name)) continue;
    for (const port of ports) {
      if (entry.ports.includes(port)) {
        const key = entry.library + "/" + entry.name;
        if (!seen.has(key)) {
          seen.add(key);
          icons.push({ library: entry.library, name: entry.name });
        }
        break;
      }
    }
  }
  return icons;
}

export function getDefaultPortList(): { port: number; service: string; icon: string | null }[] {
  return DEFAULT_SCAN_PORTS.map(port => {
    const service = PORT_SERVICE_MAP[port] || `Port ${port}`;
    let icon: string | null = null;
    for (const entry of SERVICE_ICON_MAP) {
      if (entry.ports.includes(port)) { icon = entry.name; break; }
    }
    return { port, service, icon };
  });
}

function getServicesForPorts(ports: number[]): Record<number, string> {
  const services: Record<number, string> = {};
  for (const port of ports) {
    if (PORT_SERVICE_MAP[port]) services[port] = PORT_SERVICE_MAP[port];
    else services[port] = `Port ${port}`;
  }
  return services;
}

async function reverseDNS(ip: string, timeoutMs: number): Promise<string> {
  try {
    const proc = Bun.spawn(["nslookup", ip], { stdout: "pipe", stderr: "ignore" });
    const raceResult = await Promise.race([
      proc.exited,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeoutMs)),
    ]);
    if (raceResult !== 0) return "";
    const output = await new Response(proc.stdout).text();
    const nameMatch = /name\s*=\s*(\S+)/i.exec(output);
    return nameMatch ? nameMatch[1].replace(/\.$/, "") : "";
  } catch {
    return "";
  }
}

async function resolveNetBIOS(ip: string, timeoutMs: number): Promise<string> {
  try {
    const proc = Bun.spawn(["nmblookup", "-A", ip], { stdout: "pipe", stderr: "ignore" });
    const raceResult = await Promise.race([
      proc.exited,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeoutMs)),
    ]);
    if (raceResult !== 0) {
      const output = await new Response(proc.stdout).text();
      const nameMatch = /(\S+)\s+<00>\s+-\s+/i.exec(output);
      if (nameMatch) return nameMatch[1];
    }
    const output = await new Response(proc.stdout).text();
    const nameMatch = /(\S+)\s+<00>\s+-\s+/i.exec(output);
    return nameMatch ? nameMatch[1] : "";
  } catch {
    return "";
  }
}

async function resolveMDNS(ip: string, timeoutMs: number): Promise<string> {
  try {
    const proc = Bun.spawn(["avahi-resolve", "-a", ip], { stdout: "pipe", stderr: "ignore" });
    const raceResult = await Promise.race([
      proc.exited,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeoutMs)),
    ]);
    if (raceResult !== 0) return "";
    const output = await new Response(proc.stdout).text();
    const parts = output.trim().split(/\s+/);
    return parts.length >= 2 ? parts[1] : "";
  } catch {
    return "";
  }
}

async function resolveHTTPServer(ip: string, timeoutMs: number): Promise<string> {
  try {
    const resp = await fetch(`http://${ip}/`, {
      method: "HEAD",
      signal: AbortSignal.timeout(timeoutMs),
      redirect: "manual",
    });
    const server = resp.headers.get("server") || "";
    if (server) return server;
    const xPowered = resp.headers.get("x-powered-by") || "";
    return xPowered;
  } catch {
    return "";
  }
}

interface DNSFingerprint {
  serviceName: string;
  icon?: { library: string; name: string };
  extraServices?: Record<number, string>;
}

async function fingerprintDNS(ip: string, openPorts: number[], timeoutMs: number): Promise<DNSFingerprint> {
  if (openPorts.includes(5380)) {
    return { serviceName: "Technitium DNS", icon: { library: "selfhst", name: "technitium-dns" } };
  }

  const adguardPorts = [80, 3000, 443].filter(p => openPorts.includes(p));
  for (const port of adguardPorts) {
    try {
      const protocol = port === 443 ? "https" : "http";
      const portSuffix = (port === 80 || port === 443) ? "" : `:${port}`;
      const resp = await fetch(`${protocol}://${ip}${portSuffix}/control/status`, {
        signal: AbortSignal.timeout(timeoutMs),
        redirect: "manual",
      });
      if (resp.status === 401 || resp.status === 403 || resp.ok) {
        const isAdGuard = resp.status === 401 || resp.status === 403;
        if (!isAdGuard && resp.ok) {
          const text = await resp.text();
          if (!text.includes("running") && !text.includes("version")) continue;
        }
        const extra: Record<number, string> = {};
        if (port !== 80 && port !== 443) extra[port] = "AdGuard Home";
        return {
          serviceName: "AdGuard Home",
          icon: { library: "selfhst", name: "adguard-home" },
          extraServices: Object.keys(extra).length > 0 ? extra : undefined,
        };
      }
    } catch {}
  }

  const piholePorts = [80, 443].filter(p => openPorts.includes(p));
  for (const port of piholePorts) {
    const protocol = port === 443 ? "https" : "http";
    try {
      const resp = await fetch(`${protocol}://${ip}/admin/api.php`, {
        signal: AbortSignal.timeout(timeoutMs),
        redirect: "manual",
      });
      if (resp.ok || resp.status === 401 || resp.status === 403) {
        return { serviceName: "Pi-hole", icon: { library: "selfhst", name: "pihole" } };
      }
    } catch {}
    try {
      const resp = await fetch(`${protocol}://${ip}/api/`, {
        signal: AbortSignal.timeout(timeoutMs),
        redirect: "manual",
      });
      if (resp.ok || resp.status === 401 || resp.status === 403) {
        return { serviceName: "Pi-hole", icon: { library: "selfhst", name: "pihole" } };
      }
    } catch {}
  }

  return { serviceName: "DNS" };
}

async function resolveSNMP(ip: string, community: string, timeoutMs: number): Promise<{ sysName: string; sysDescr: string }> {
  const timeoutSec = Math.max(1, Math.ceil(timeoutMs / 1000));
  try {
    const proc = Bun.spawn(
      ["snmpget", "-v2c", "-c", community, "-t", String(timeoutSec), "-r", "0", ip, "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0"],
      { stdout: "pipe", stderr: "ignore" },
    );
    const raceResult = await Promise.race([
      proc.exited,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("timeout")), timeoutMs)),
    ]);
    if (raceResult !== 0) return { sysName: "", sysDescr: "" };
    const output = await new Response(proc.stdout).text();
    const lines = output.split("\n");
    let sysName = "";
    let sysDescr = "";
    for (const line of lines) {
      const valMatch = /STRING:\s*"?([^"]*)"?/i.exec(line);
      if (!valMatch) continue;
      if (line.includes("1.3.6.1.2.1.1.5.0")) sysName = valMatch[1].trim();
      else if (line.includes("1.3.6.1.2.1.1.1.0")) sysDescr = valMatch[1].trim();
    }
    return { sysName, sysDescr };
  } catch {
    return { sysName: "", sysDescr: "" };
  }
}

function bestHostname(host: DiscoveredHost): string {
  return host.netbiosName || host.mdnsName || host.dnsName || host.ip;
}

function cidrToIPs(cidr: string): string[] {
  const validation = validateCIDR(cidr, true, 20);
  if (!validation.valid || !validation.firstIP || !validation.count) return [];
  const firstInt = ipToInt(validation.firstIP);
  const ips: string[] = [];
  for (let i = 0; i < validation.count; i++) {
    const ip = intToIp(firstInt + i);
    if (!ip.endsWith(".0") && !ip.endsWith(".255")) {
      ips.push(ip);
    }
  }
  return ips;
}

export async function startDiscovery(
  taskId: string,
  roomId: string,
  cidrs: string[],
  options: DiscoveryOptions,
  onProgress: (percent: number, scanned: number, total: number, rangeIndex: number, totalRanges: number) => void,
  onFound: (host: DiscoveredHost) => void,
  onComplete: (totalFound: number) => void,
): Promise<DiscoveryHandle> {
  const allIPs: { ip: string; rangeIndex: number }[] = [];
  for (let r = 0; r < cidrs.length; r++) {
    const ips = cidrToIPs(cidrs[r]);
    for (const ip of ips) {
      allIPs.push({ ip, rangeIndex: r });
    }
  }

  if (allIPs.length === 0) throw new Error("No valid IPs in ranges");

  const handle: DiscoveryHandle = {
    taskId,
    cancelled: false,
    cancel() { this.cancelled = true; },
  };
  activeDiscoveries.set(taskId, handle);

  const userPorts = options.ports && options.ports.length > 0 ? options.ports.filter(validatePort) : [];
  const scanPorts = [...new Set([...DEFAULT_SCAN_PORTS, ...userPorts])].sort((a, b) => a - b);
  const totalRanges = cidrs.length;

  (async () => {
    let scanned = 0;
    let found = 0;
    const total = allIPs.length;
    const pingBatchSize = 50;

    try {
      for (let i = 0; i < allIPs.length; i += pingBatchSize) {
        if (handle.cancelled) break;

        const batch = allIPs.slice(i, i + pingBatchSize);
        const pingResults = await Promise.all(
          batch.map(async (entry) => {
            if (handle.cancelled) return null;
            const result = await probeICMP(entry.ip, 1500);
            return result.status === "online" ? entry : null;
          }),
        );

        const aliveEntries = pingResults.filter((e): e is { ip: string; rangeIndex: number } => e !== null);

        for (const entry of aliveEntries) {
          if (handle.cancelled) break;

          const host: DiscoveredHost = {
            ip: entry.ip,
            hostname: "",
            ports: [],
            services: {},
            icon: { ...DEFAULT_ICON },
            serviceIcons: [],
            dnsName: "",
            netbiosName: "",
            mdnsName: "",
            httpServer: "",
            snmpName: "",
            snmpDescr: "",
          };

          if (options.tcp) {
            const portBatchSize = 10;
            for (let p = 0; p < scanPorts.length; p += portBatchSize) {
              if (handle.cancelled) break;
              const portBatch = scanPorts.slice(p, p + portBatchSize);
              const portResults = await Promise.all(
                portBatch.map(async (port) => {
                  const result = await probeTCP(entry.ip, port, 1500);
                  return result.status === "online" ? port : null;
                }),
              );
              const openPorts = portResults.filter((p): p is number => p !== null);
              host.ports.push(...openPorts);
            }
            host.services = getServicesForPorts(host.ports);
            if (host.ports.includes(53)) {
              const dnsResult = await fingerprintDNS(entry.ip, host.ports, 2000);
              host.services[53] = dnsResult.serviceName;
              if (dnsResult.icon) host.icon = dnsResult.icon;
              if (dnsResult.extraServices) {
                for (const [portStr, svcName] of Object.entries(dnsResult.extraServices)) {
                  host.services[parseInt(portStr, 10)] = svcName;
                }
              }
              if (!dnsResult.icon) host.icon = getServiceIcon(host.ports);
            } else {
              host.icon = getServiceIcon(host.ports);
            }
            host.serviceIcons = getServiceIcons(host.ports);
          }

          const namePromises: Promise<void>[] = [];

          if (options.dns) {
            namePromises.push(reverseDNS(entry.ip, 2000).then((name) => { host.dnsName = name; }));
          }
          if (options.netbios) {
            namePromises.push(resolveNetBIOS(entry.ip, 2000).then((name) => { host.netbiosName = name; }));
          }
          if (options.mdns) {
            namePromises.push(resolveMDNS(entry.ip, 2000).then((name) => { host.mdnsName = name; }));
          }
          if (host.ports.includes(80) || host.ports.includes(443) || host.ports.includes(8080)) {
            namePromises.push(resolveHTTPServer(entry.ip, 2000).then((server) => { host.httpServer = server; }));
          }
          if (options.snmp && options.snmpCommunity && (host.ports.includes(161) || !options.tcp)) {
            namePromises.push(
              resolveSNMP(entry.ip, options.snmpCommunity, 3000).then((result) => {
                host.snmpName = result.sysName;
                host.snmpDescr = result.sysDescr;
              }),
            );
          }

          await Promise.all(namePromises);
          host.hostname = bestHostname(host);

          found++;
          onFound(host);
        }

        scanned += batch.length;
        const percent = Math.round((scanned / total) * 100);
        const currentRange = batch.length > 0 ? batch[batch.length - 1].rangeIndex : 0;
        onProgress(percent, scanned, total, currentRange, totalRanges);
      }

      onComplete(found);
    } finally {
      activeDiscoveries.delete(taskId);
    }
  })();

  return handle;
}

export function cancelDiscovery(taskId: string): boolean {
  const handle = activeDiscoveries.get(taskId);
  if (!handle) return false;
  handle.cancel();
  activeDiscoveries.delete(taskId);
  return true;
}

export function hasActiveDiscovery(roomId: string): boolean {
  for (const [, handle] of activeDiscoveries) {
    if (!handle.cancelled) return true;
  }
  return false;
}

export function hasActiveDiscoveryForRoom(roomId: string, taskPrefix: string): boolean {
  for (const [taskId, handle] of activeDiscoveries) {
    if (taskId.startsWith(taskPrefix) && !handle.cancelled) return true;
  }
  return false;
}

export function validateProbeConfig(probes: unknown): probes is ProbeConfig[] {
  if (!Array.isArray(probes)) return false;
  if (probes.length === 0 || probes.length > 20) return false;
  const validTypes = ["icmp", "tcp", "http", "dns"];
  for (const probe of probes) {
    if (!probe || typeof probe !== "object") return false;
    if (!validTypes.includes(probe.type)) return false;
    if (probe.type === "tcp" && (!probe.port || !validatePort(probe.port))) return false;
  }
  return true;
}

export const DOCKER_TRIGGER_PORTS = [2375, 2376, 9443, 5001];

const DOCKER_DEEP_SCAN_PORTS: number[] = [];
for (let p = 1000; p <= 10000; p++) DOCKER_DEEP_SCAN_PORTS.push(p);
for (let p = 30000; p <= 33000; p++) DOCKER_DEEP_SCAN_PORTS.push(p);

export interface DockerContainer {
  name: string;
  image: string;
  ports: { hostPort: number; containerPort: number; protocol: string }[];
  state: string;
}

interface DeepScanHandle {
  scanId: string;
  ip: string;
  cancelled: boolean;
  cancel: () => void;
}

const activeDeepScans = new Map<string, DeepScanHandle>();

async function queryDockerAPI(ip: string, timeoutMs: number): Promise<DockerContainer[] | null> {
  for (const port of [2375, 2376]) {
    try {
      const protocol = port === 2376 ? "https" : "http";
      const resp = await fetch(`${protocol}://${ip}:${port}/containers/json?all=false`, {
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!resp.ok) continue;
      const containers = await resp.json();
      if (!Array.isArray(containers)) continue;
      return containers.map((c: any) => ({
        name: Array.isArray(c.Names) && c.Names.length > 0 ? c.Names[0].replace(/^\//, "") : "unknown",
        image: c.Image || "",
        ports: Array.isArray(c.Ports)
          ? c.Ports.filter((p: any) => p.PublicPort)
                   .map((p: any) => ({
                     hostPort: p.PublicPort,
                     containerPort: p.PrivatePort || p.PublicPort,
                     protocol: p.Type || "tcp",
                   }))
          : [],
        state: c.State || "",
      }));
    } catch {
      continue;
    }
  }
  return null;
}

export async function startDeepScan(
  scanId: string,
  ip: string,
  existingPorts: number[],
  onProgress: (percent: number, scanned: number, total: number) => void,
  onUpdate: (newPorts: number[], newServices: Record<number, string>, containers: DockerContainer[] | null) => void,
  onComplete: () => void,
): Promise<DeepScanHandle> {
  const handle: DeepScanHandle = {
    scanId,
    ip,
    cancelled: false,
    cancel() { this.cancelled = true; },
  };
  activeDeepScans.set(scanId, handle);

  (async () => {
    try {
      const hasDockerAPI = existingPorts.includes(2375) || existingPorts.includes(2376);
      let containers: DockerContainer[] | null = null;
      const discoveredPorts: number[] = [];
      const discoveredServices: Record<number, string> = {};

      if (hasDockerAPI) {
        containers = await queryDockerAPI(ip, 5000);
        if (containers) {
          for (const container of containers) {
            for (const pm of container.ports) {
              if (!existingPorts.includes(pm.hostPort) && !discoveredPorts.includes(pm.hostPort)) {
                discoveredPorts.push(pm.hostPort);
              }
              const imageName = container.image.split(":")[0].split("/").pop() || container.image;
              discoveredServices[pm.hostPort] = `${imageName} (${container.name})`;
            }
          }
          onProgress(100, 1, 1);
          onUpdate(discoveredPorts, discoveredServices, containers);
          onComplete();
          return;
        }
      }

      const existingSet = new Set(existingPorts);
      const portsToScan = DOCKER_DEEP_SCAN_PORTS.filter(p => !existingSet.has(p));
      const total = portsToScan.length;
      let scanned = 0;
      const deepBatchSize = 20;

      for (let i = 0; i < portsToScan.length; i += deepBatchSize) {
        if (handle.cancelled) break;
        const batch = portsToScan.slice(i, i + deepBatchSize);
        const results = await Promise.allSettled(
          batch.map(async (port) => {
            const result = await probeTCP(ip, port, 1500);
            return result.status === "online" ? port : null;
          }),
        );
        for (const r of results) {
          if (r.status === "fulfilled" && r.value !== null) {
            const port = r.value;
            if (!discoveredPorts.includes(port)) {
              discoveredPorts.push(port);
              discoveredServices[port] = PORT_SERVICE_MAP[port] || `Port ${port}`;
            }
          }
        }
        scanned += batch.length;
        const percent = Math.round((scanned / total) * 100);
        onProgress(percent, scanned, total);
      }

      onUpdate(discoveredPorts, discoveredServices, null);
      onComplete();
    } finally {
      activeDeepScans.delete(scanId);
    }
  })();

  return handle;
}

export function cancelDeepScan(scanId: string): boolean {
  const handle = activeDeepScans.get(scanId);
  if (!handle) return false;
  handle.cancel();
  activeDeepScans.delete(scanId);
  return true;
}

export function hasActiveDeepScan(ip: string): boolean {
  for (const [, handle] of activeDeepScans) {
    if (handle.ip === ip && !handle.cancelled) return true;
  }
  return false;
}
