import { test, expect } from "bun:test";

process.env.DATA_DIR = process.env.DATA_DIR || "./.testdata";

const network = await import("../src/network.ts");
const rooms = await import("../src/rooms.ts");
const oidc = await import("../src/oidc.ts");

test("isBlockedProbeTarget blocks loopback, link local metadata and broadcast", () => {
  expect(network.isBlockedProbeTarget("127.0.0.1")).toBe(true);
  expect(network.isBlockedProbeTarget("169.254.169.254")).toBe(true);
  expect(network.isBlockedProbeTarget("0.0.0.0")).toBe(true);
  expect(network.isBlockedProbeTarget("255.255.255.255")).toBe(true);
  expect(network.isBlockedProbeTarget("localhost")).toBe(true);
  expect(network.isBlockedProbeTarget("metadata.google.internal")).toBe(true);
});

test("isBlockedProbeTarget allows private and public monitoring targets", () => {
  expect(network.isBlockedProbeTarget("192.168.1.10")).toBe(false);
  expect(network.isBlockedProbeTarget("10.0.0.5")).toBe(false);
  expect(network.isBlockedProbeTarget("172.16.4.4")).toBe(false);
  expect(network.isBlockedProbeTarget("8.8.8.8")).toBe(false);
  expect(network.isBlockedProbeTarget("server.lan")).toBe(false);
});

test("sanitizeScanText strips angle brackets and truncates", () => {
  expect(network.sanitizeScanText("<img src=x onerror=alert(1)>")).toBe("img src=x onerror=alert(1)");
  const long = "a".repeat(500);
  expect(network.sanitizeScanText(long).length).toBe(256);
  const obj = network.sanitizeScanText({ name: "<b>x</b>", ports: [80, 443] });
  expect(obj.name).toBe("bx/b");
  expect(obj.ports).toEqual([80, 443]);
});

test("validateCIDR rejects public ranges when not allowed and enforces max prefix", () => {
  expect(network.validateCIDR("8.8.8.0/24", false, 20).valid).toBe(false);
  expect(network.validateCIDR("192.168.1.0/24", false, 20).valid).toBe(true);
  expect(network.validateCIDR("10.0.0.0/8", false, 20).valid).toBe(false);
  expect(network.validateCIDR("10.0.0.0/24", false, 20).valid).toBe(true);
});

test("sanitizeHtmlString removes scripts and event handlers but keeps allowed tags", () => {
  expect(rooms.sanitizeHtmlString("<script>alert(1)</script>")).not.toContain("<script");
  expect(rooms.sanitizeHtmlString('<img src=x onerror="alert(1)">')).not.toContain("onerror");
  expect(rooms.sanitizeHtmlString("<svg onload=alert(1)>")).not.toContain("<svg");
  expect(rooms.sanitizeHtmlString("<!-- <script>alert(1)</script> -->")).not.toContain("script");
  expect(rooms.sanitizeHtmlString("<b>bold</b>")).toBe("<b>bold</b>");
});

test("isValidWebhookUrl blocks internal targets and allows public https", () => {
  expect(rooms.isValidWebhookUrl("http://localhost/hook")).toBe(false);
  expect(rooms.isValidWebhookUrl("http://127.0.0.1/hook")).toBe(false);
  expect(rooms.isValidWebhookUrl("http://169.254.169.254/")).toBe(false);
  expect(rooms.isValidWebhookUrl("http://10.0.0.5/hook")).toBe(false);
  expect(rooms.isValidWebhookUrl("https://example.com/hook")).toBe(true);
});

test("validateRedirectUrl rejects dangerous and external redirects", () => {
  expect(oidc.validateRedirectUrl("javascript:alert(1)", "https://app.example")).toBe("/");
  expect(oidc.validateRedirectUrl("//evil.example", "https://app.example")).toBe("/");
  expect(oidc.validateRedirectUrl("https://evil.example/x", "https://app.example")).toBe("/");
  expect(oidc.validateRedirectUrl("/api/admin/users", "https://app.example")).toBe("/");
  expect(oidc.validateRedirectUrl("/s/room", "https://app.example")).toBe("/s/room");
});

test("isBlockedIPv4 flags loopback, link local, broadcast and this-network", () => {
  expect(network.isBlockedIPv4("127.0.0.1")).toBe(true);
  expect(network.isBlockedIPv4("169.254.169.254")).toBe(true);
  expect(network.isBlockedIPv4("0.0.0.0")).toBe(true);
  expect(network.isBlockedIPv4("255.255.255.255")).toBe(true);
  expect(network.isBlockedIPv4("10.0.0.1")).toBe(false);
  expect(network.isBlockedIPv4("8.8.8.8")).toBe(false);
});

test("resolveSafeProbeTarget rejects blocked literals and names, keeps allowed IPs", async () => {
  expect(await network.resolveSafeProbeTarget("127.0.0.1")).toBeNull();
  expect(await network.resolveSafeProbeTarget("169.254.169.254")).toBeNull();
  expect(await network.resolveSafeProbeTarget("localhost")).toBeNull();
  expect(await network.resolveSafeProbeTarget("metadata.google.internal")).toBeNull();
  expect(await network.resolveSafeProbeTarget("192.168.1.10")).toBe("192.168.1.10");
  expect(await network.resolveSafeProbeTarget("8.8.8.8")).toBe("8.8.8.8");
});

test("sanitizeScanText neutralizes HTML inside a nested probe result", () => {
  const r = network.sanitizeScanText({ status: "online", rtt: 5, results: [{ type: "http", status: "online", responseTime: 5, detail: "200 <img src=x onerror=alert(1)>" }] });
  expect(r.results[0].detail).not.toContain("<");
  expect(r.results[0].detail).not.toContain(">");
  expect(r.rtt).toBe(5);
});
