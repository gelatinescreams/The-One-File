const IPV4_LITERAL = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function ipv4Parts(ip: string): number[] | null {
  const m = IPV4_LITERAL.exec(ip);
  if (!m) return null;
  const parts = [m[1], m[2], m[3], m[4]].map(Number);
  if (parts.some(p => p < 0 || p > 255)) return null;
  return parts;
}

export function isIpLiteral(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "");
  return ipv4Parts(h) !== null || h.includes(":");
}

function expandIpv6(ip: string): number[] | null {
  let addr = ip.toLowerCase().replace(/^\[|\]$/g, "");
  const zone = addr.indexOf("%");
  if (zone >= 0) addr = addr.slice(0, zone);
  let tailV4: number[] | null = null;
  const lastColon = addr.lastIndexOf(":");
  if (lastColon >= 0 && addr.slice(lastColon + 1).includes(".")) {
    tailV4 = ipv4Parts(addr.slice(lastColon + 1));
    if (!tailV4) return null;
    addr = addr.slice(0, lastColon + 1) + ((tailV4[0] << 8) | tailV4[1]).toString(16) + ":" + ((tailV4[2] << 8) | tailV4[3]).toString(16);
  }
  const halves = addr.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 && missing !== 0) return null;
  if (missing < 0) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  if (groups.length !== 8) return null;
  const out: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16));
  }
  return out;
}

export function isPrivateIpv4(ip: string): boolean {
  const p = ipv4Parts(ip);
  if (!p) return false;
  const [a, b] = p;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0 && p[2] === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a >= 224) return true;
  return false;
}

export function isPrivateAddress(ip: string): boolean {
  if (ipv4Parts(ip)) return isPrivateIpv4(ip);
  const g = expandIpv6(ip);
  if (!g) return true;
  if (g.every(x => x === 0)) return true;
  if (g.slice(0, 7).every(x => x === 0) && g[7] === 1) return true;
  if (g.slice(0, 5).every(x => x === 0) && (g[5] === 0xffff || g[5] === 0)) {
    return isPrivateIpv4(`${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`);
  }
  if (g[0] === 0x64 && g[1] === 0xff9b) {
    return isPrivateIpv4(`${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`);
  }
  if ((g[0] & 0xffc0) === 0xfe80) return true;
  if ((g[0] & 0xfe00) === 0xfc00) return true;
  if ((g[0] & 0xff00) === 0xff00) return true;
  if (g[0] === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return true;
  return false;
}

export function isLoopbackOrMetadataAddress(ip: string, allowLoopback = false): boolean {
  const p = ipv4Parts(ip);
  if (p) return p[0] === 0 || (!allowLoopback && p[0] === 127) || (p[0] === 169 && p[1] === 254);
  const g = expandIpv6(ip);
  if (!g) return true;
  if (g.every(x => x === 0)) return true;
  if (!allowLoopback && g.slice(0, 7).every(x => x === 0) && g[7] === 1) return true;
  if ((g[0] & 0xffc0) === 0xfe80) return true;
  if (g[0] === 0xfd00 && g[1] === 0x0ec2 && g.slice(2, 7).every(x => x === 0) && g[7] === 0x254) return true;
  if (g.slice(0, 5).every(x => x === 0) && g[5] === 0xffff) {
    return isLoopbackOrMetadataAddress(`${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`, allowLoopback);
  }
  return false;
}

export type HostResolver = (host: string) => Promise<string[]>;

export const defaultResolver: HostResolver = async (host: string) => {
  const results = await Bun.dns.lookup(host);
  return results.map((r: any) => String(r.address));
};

let activeResolver: HostResolver = defaultResolver;

export function setHostResolverForTests(resolver: HostResolver | null): void {
  activeResolver = resolver || defaultResolver;
}

export async function resolveHostAddresses(host: string): Promise<string[]> {
  const h = host.replace(/^\[|\]$/g, "");
  if (isIpLiteral(h)) return [h];
  try {
    return await activeResolver(h);
  } catch {
    return [];
  }
}

export async function hostResolvesPublic(host: string): Promise<boolean> {
  const addrs = await resolveHostAddresses(host);
  if (addrs.length === 0) return false;
  return addrs.every(a => !isPrivateAddress(a));
}

export async function hostAvoidsLoopbackAndMetadata(host: string, allowLoopback = false): Promise<boolean> {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "metadata.google.internal" || h.endsWith(".internal")) return false;
  if (!allowLoopback && (h === "localhost" || h.endsWith(".localhost"))) return false;
  const addrs = await resolveHostAddresses(h);
  if (addrs.length === 0) return false;
  return addrs.every(a => !isLoopbackOrMetadataAddress(a, allowLoopback));
}
