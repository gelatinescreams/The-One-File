import * as db from "../database";
import { getSettings, updateSettings, saveSettings, validateAdminPath, ENV_ADMIN_PASSWORD, APP_VERSION, MAX_ROOM_SIZE_MB_CEILING, normalizeOrigin, ENV_TRUSTED_PROXY_COUNT, ENV_TRUSTED_PROXIES } from "../config";
import { getClientIP, apiError, validateAdminUser, validateAdminOrApiKey, validateRequestCsrf, csrfReject, readJsonLimited, tooLargeResponse, redactForAudit } from "../security";
import { runAssetSweepNow } from "../assets";
import { hashPassword, theOneFileHtml, currentFileVersion, extractThemePresets, computeSha256Hash, validateTheOneFileHtml, fetchLatestFromGitHub, getExpectedTheOneFileHash, setExpectedTheOneFileHash, setTheOneFileHtml, getTheOneFilePath, restartUpdateTimer, clearUpdateTimer, isValidWebhookUrl, restartBackupTimer, extractVersionFromHtml, isNewerVersion } from "../rooms";

const GITHUB_RAW_URL = "https://raw.githubusercontent.com/gelatinescreams/The-One-File/main/theonefile-networkening.html";

const UPLOAD_HTML_BODY_CAP = 12 * 1024 * 1024;

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  if (path === "/api/admin/settings" && req.method === "GET") {
    const { user: adminUser, apiKey } = await validateAdminOrApiKey(req, "read");
    if (!adminUser && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const settings = getSettings();
    const { instancePasswordHash, ...safeSettings } = settings;
    const fileValidation = validateTheOneFileHtml(theOneFileHtml);
    const currentFileHash = theOneFileHtml ? await computeSha256Hash(theOneFileHtml) : null;
    const expectedFileHash = getExpectedTheOneFileHash();
    return Response.json({
      ...safeSettings,
      instancePasswordSet: !!instancePasswordHash,
      envAdminPasswordSet: !!ENV_ADMIN_PASSWORD,
      envTrustedProxyCountSet: ENV_TRUSTED_PROXY_COUNT !== null,
      envTrustedProxiesSet: ENV_TRUSTED_PROXIES !== null,
      currentFileSize: theOneFileHtml.length,
      currentFileEdition: fileValidation.valid ? fileValidation.edition : "invalid",
      currentFileHash,
      expectedFileHash,
      integrityCheckEnabled: !!expectedFileHash,
      integrityCheckPassed: expectedFileHash ? currentFileHash === expectedFileHash : null,
      availableThemes: extractThemePresets(),
      currentFileVersion: currentFileVersion || "unknown",
      lastUpdateTimestamp: db.getSetting("lastUpdateTimestamp") || null,
      latestGitHubVersion: db.getSetting("latestGitHubVersion") || null,
      lastVersionCheck: db.getSetting("lastVersionCheck") || null
    }, { headers: corsHeaders });
  }

  if (path === "/api/admin/settings" && req.method === "POST") {
    const { user: adminUser, apiKey } = await validateAdminOrApiKey(req, "admin");
    if (!adminUser && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    if (adminUser && !validateRequestCsrf(req)) return csrfReject(corsHeaders);
    try {
      const body = await readJsonLimited(req, 64 * 1024);

      if (body.instancePassword !== undefined && body.instancePassword !== "" && body.instancePassword.length < 10) {
        return Response.json({ error: "Password must be at least 10 characters" }, { status: 400, headers: corsHeaders });
      }
      if (body.webhookUrl && !isValidWebhookUrl(body.webhookUrl)) {
        return Response.json({ error: "Invalid webhook URL: must be http(s) and not point to private/internal addresses" }, { status: 400, headers: corsHeaders });
      }
      if (body.adminPath !== undefined) {
        const validation = validateAdminPath(body.adminPath);
        if (!validation.valid) {
          return Response.json({ error: validation.error }, { status: 400, headers: corsHeaders });
        }
      }
      if (body.theOneFileHash !== undefined && body.theOneFileHash !== "" && body.theOneFileHash !== null && body.theOneFileHash !== "current") {
        if (typeof body.theOneFileHash !== "string" || !/^[a-f0-9]{64}$/i.test(body.theOneFileHash)) {
          return Response.json({ error: "Invalid hash format. Must be 64 hex characters, 'current', or empty to disable." }, { status: 400, headers: corsHeaders });
        }
      }

      let publicUrlOriginWarning: string | null = null;
      if (body.publicUrl !== undefined) {
        const raw = typeof body.publicUrl === "string" ? body.publicUrl.trim() : "";
        if (raw === "") {
        } else {
          const origin = normalizeOrigin(raw);
          if (!origin) {
            return Response.json({
              error: "Invalid public URL: must be an absolute http(s) origin, e.g. https://verse.example.com (no path, query, fragment or user:password)"
            }, { status: 400, headers: corsHeaders });
          }
          if (origin.toLowerCase() !== raw.replace(/\/+$/, "").toLowerCase()) {
            return Response.json({
              error: `Invalid public URL: use the bare origin (${origin}), no path, query, fragment or credentials`
            }, { status: 400, headers: corsHeaders });
          }
          let reqOrigin = "";
          try { reqOrigin = new URL(req.url).origin; } catch { reqOrigin = ""; }
          const hdrOrigin = req.headers.get("origin") || "";
          if (reqOrigin && origin !== reqOrigin && (!hdrOrigin || origin !== hdrOrigin)) {
            publicUrlOriginWarning = `Public URL is set to ${origin}, which differs from the origin you are using right now (${hdrOrigin || reqOrigin}). Email links and CSRF origin checks will use ${origin}.`;
          }
        }
      }

      const settings = { ...getSettings() };

      if (typeof body.instancePasswordEnabled === "boolean") {
        settings.instancePasswordEnabled = body.instancePasswordEnabled;
      }
      if (body.instancePassword !== undefined) {
        if (body.instancePassword === "") {
          settings.instancePasswordHash = null;
        } else if (typeof body.instancePassword === "string" && body.instancePassword.length >= 10) {
          settings.instancePasswordHash = await hashPassword(body.instancePassword);
        } else {
          return Response.json({ error: "Instance password must be at least 10 characters" }, { status: 400, headers: corsHeaders });
        }
      }
      if (typeof body.updateIntervalHours === "number") {
        settings.updateIntervalHours = Math.max(0, body.updateIntervalHours);
      }
      if (typeof body.skipUpdates === "boolean") {
        settings.skipUpdates = body.skipUpdates;
      }
      if (typeof body.allowPublicRoomCreation === "boolean") {
        settings.allowPublicRoomCreation = body.allowPublicRoomCreation;
      }
      if (typeof body.maxRoomsPerInstance === "number") {
        settings.maxRoomsPerInstance = Math.max(0, body.maxRoomsPerInstance);
      }
      if (typeof body.maxRoomSizeMB === "number") {
        settings.maxRoomSizeMB = Math.max(1, Math.min(MAX_ROOM_SIZE_MB_CEILING, Math.round(body.maxRoomSizeMB)));
      }
      if (body.defaultDestructMode && ["time", "empty", "never"].includes(body.defaultDestructMode)) {
        settings.defaultDestructMode = body.defaultDestructMode;
      }
      if (typeof body.defaultDestructHours === "number") {
        settings.defaultDestructHours = Math.max(1, body.defaultDestructHours);
      }
      if (body.forcedTheme && ["user", "dark", "light"].includes(body.forcedTheme)) {
        settings.forcedTheme = body.forcedTheme;
      }
      if (typeof body.defaultRoomTheme === 'string') {
        const validKeys = extractThemePresets().map(t => t.key);
        if (body.defaultRoomTheme === '' || validKeys.includes(body.defaultRoomTheme)) {
          settings.defaultRoomTheme = body.defaultRoomTheme;
        }
      }
      if (typeof body.rateLimitEnabled === "boolean") {
        settings.rateLimitEnabled = body.rateLimitEnabled;
      }
      if (typeof body.rateLimitWindow === "number") {
        settings.rateLimitWindow = Math.max(10, Math.min(3600, body.rateLimitWindow));
      }
      if (body.trustedProxyCount !== undefined) {
        if (ENV_TRUSTED_PROXY_COUNT !== null) return Response.json({ error: "Trusted proxy count is set by the TRUSTED_PROXY_COUNT environment variable" }, { status: 400, headers: corsHeaders });
        if (!Number.isInteger(body.trustedProxyCount) || body.trustedProxyCount < 0 || body.trustedProxyCount > 10) return Response.json({ error: "Trusted proxy count must be a whole number from 0 to 10" }, { status: 400, headers: corsHeaders });
        settings.trustedProxyCount = body.trustedProxyCount;
      }
      if (body.trustedProxies !== undefined) {
        if (ENV_TRUSTED_PROXIES !== null) return Response.json({ error: "Trusted proxies are set by the TRUSTED_PROXIES environment variable" }, { status: 400, headers: corsHeaders });
        const list = Array.isArray(body.trustedProxies) ? body.trustedProxies.map((x: unknown) => typeof x === "string" ? x.trim() : "").filter(Boolean) : null;
        const ipRe = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$|^[0-9a-fA-F:]{2,39}$/;
        if (!list || list.length > 20 || list.some((ip: string) => !ipRe.test(ip))) return Response.json({ error: "Trusted proxies must be up to 20 IP addresses" }, { status: 400, headers: corsHeaders });
        settings.trustedProxies = list;
      }
      if (typeof body.rateLimitMaxAttempts === "number") {
        settings.rateLimitMaxAttempts = Math.max(1, Math.min(100, body.rateLimitMaxAttempts));
      }
      if (typeof body.chatEnabled === "boolean") {
        settings.chatEnabled = body.chatEnabled;
      }
      if (typeof body.cursorSharingEnabled === "boolean") {
        settings.cursorSharingEnabled = body.cursorSharingEnabled;
      }
      if (typeof body.nameChangeEnabled === "boolean") {
        settings.nameChangeEnabled = body.nameChangeEnabled;
      }
      if (typeof body.probeEnabled === "boolean") {
        settings.probeEnabled = body.probeEnabled;
      }
      if (typeof body.enable3d === "boolean") {
        settings.enable3d = body.enable3d;
      }
      if (typeof body.maxAssetsPerRoomMB === "number" && Number.isFinite(body.maxAssetsPerRoomMB)) {
        settings.maxAssetsPerRoomMB = Math.max(0, Math.min(10000, Math.round(body.maxAssetsPerRoomMB)));
      }
      if (typeof body.maxAssetsTotalGB === "number" && Number.isFinite(body.maxAssetsTotalGB)) {
        settings.maxAssetsTotalGB = Math.max(0, Math.min(1000, Math.round(body.maxAssetsTotalGB)));
      }
      if (body.publicUrl !== undefined) {
        const raw = typeof body.publicUrl === "string" ? body.publicUrl.trim() : "";
        settings.publicUrl = raw === "" ? "" : (normalizeOrigin(raw) || "");
      }
      if (typeof body.discoveryEnabled === "boolean") {
        settings.discoveryEnabled = body.discoveryEnabled;
      }
      if (typeof body.discoveryAdminOnly === "boolean") {
        settings.discoveryAdminOnly = body.discoveryAdminOnly;
      }
      if (typeof body.discoveryAllowPublicRanges === "boolean") {
        settings.discoveryAllowPublicRanges = body.discoveryAllowPublicRanges;
      }
      if (body.discoveryMaxPrefix !== undefined) {
        if (!Number.isInteger(body.discoveryMaxPrefix) || body.discoveryMaxPrefix < 20 || body.discoveryMaxPrefix > 32) {
          return Response.json({ error: "Discovery max prefix must be a whole number from 20 to 32" }, { status: 400, headers: corsHeaders });
        }
        settings.discoveryMaxPrefix = body.discoveryMaxPrefix;
      }
      if (typeof body.webhookEnabled === "boolean") {
        settings.webhookEnabled = body.webhookEnabled;
      }
      if (body.webhookUrl !== undefined) {
        settings.webhookUrl = body.webhookUrl || null;
      }
      if (typeof body.backupEnabled === "boolean") {
        settings.backupEnabled = body.backupEnabled;
      }
      if (typeof body.backupIntervalHours === "number") {
        settings.backupIntervalHours = Math.max(1, Math.min(168, body.backupIntervalHours));
      }
      if (typeof body.backupRetentionCount === "number") {
        settings.backupRetentionCount = Math.max(1, Math.min(100, body.backupRetentionCount));
      }
      if (body.adminPath !== undefined) {
        settings.adminPath = body.adminPath;
      }
      if (typeof body.showAdminLink === "boolean") {
        settings.showAdminLink = body.showAdminLink;
      }
      if (typeof body.forceWelcomeModal === "boolean") {
        settings.forceWelcomeModal = body.forceWelcomeModal;
      }

      if (body.theOneFileHash !== undefined) {
        if (body.theOneFileHash === "" || body.theOneFileHash === null) {
          db.deleteSetting("theOneFileHash");
          console.log("[Security] TheOneFile integrity checking disabled by admin");
        } else if (body.theOneFileHash === "current") {
          if (theOneFileHtml) {
            const currentHash = await computeSha256Hash(theOneFileHtml);
            setExpectedTheOneFileHash(currentHash);
            console.log(`[Security] TheOneFile integrity hash set to current file: ${currentHash.substring(0, 16)}...`);
          }
        } else {
          setExpectedTheOneFileHash(body.theOneFileHash.toLowerCase());
          console.log(`[Security] TheOneFile integrity hash set: ${body.theOneFileHash.substring(0, 16)}...`);
        }
      }

      if (settings.instancePasswordEnabled && !settings.instancePasswordHash && !ENV_ADMIN_PASSWORD) {
        return Response.json({ error: "Set an instance password before turning on the instance lock" }, { status: 400, headers: corsHeaders });
      }
      if (settings.webhookEnabled && !settings.webhookUrl) {
        return Response.json({ error: "Enter a webhook URL before turning webhooks on" }, { status: 400, headers: corsHeaders });
      }
      updateSettings(settings);
      saveSettings(settings);

      if (typeof body.updateIntervalHours === "number" || typeof body.skipUpdates === "boolean") {
        restartUpdateTimer();
      }
      if (typeof body.backupEnabled === "boolean" || typeof body.backupIntervalHours === "number") {
        restartBackupTimer();
      }

      const actor = adminUser ? adminUser.id : `apikey:${apiKey!.name}`;
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "settings_changed", actor, actorIp: getClientIP(req), details: redactForAudit(body) });
      return Response.json({
        success: true,
        ...(publicUrlOriginWarning ? { warning: publicUrlOriginWarning } : {})
      }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/admin/assets/sweep" && req.method === "POST") {
    const { user: adminUser, apiKey } = await validateAdminOrApiKey(req, "write");
    if (!adminUser && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    if (adminUser && !validateRequestCsrf(req)) return csrfReject(corsHeaders);
    const result = runAssetSweepNow();
    const actor = adminUser ? adminUser.id : `apikey:${apiKey!.name}`;
    db.addAuditLog({ timestamp: new Date().toISOString(), action: "asset_sweep", actor, actorIp: getClientIP(req), details: result });
    return Response.json({ success: true, ...result }, { headers: corsHeaders });
  }

  if (path === "/api/admin/update" && req.method === "POST") {
    const { user: adminUser, apiKey } = await validateAdminOrApiKey(req, "admin");
    if (!adminUser && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    if (adminUser && !validateRequestCsrf(req)) return csrfReject(corsHeaders);
    const settings = getSettings();
    if (settings.skipUpdates) {
      return Response.json({ error: "Updates disabled" }, { status: 400, headers: corsHeaders });
    }
    const previousVersion = currentFileVersion;
    const success = await fetchLatestFromGitHub(true);
    return Response.json({ success, size: theOneFileHtml.length, version: currentFileVersion, previousVersion }, { headers: corsHeaders });
  }

  if (path === "/api/admin/version-check" && req.method === "GET") {
    const { user: adminUser, apiKey } = await validateAdminOrApiKey(req, "read");
    if (!adminUser && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const res = await fetch(GITHUB_RAW_URL, { signal: AbortSignal.timeout(15000) });
      if (!res.ok) {
        return Response.json({ error: "GitHub unreachable" }, { status: 502, headers: corsHeaders });
      }
      const html = await res.text();
      const latestVersion = extractVersionFromHtml(html);
      const now = new Date().toISOString();
      db.setSetting("latestGitHubVersion", latestVersion);
      db.setSetting("lastVersionCheck", now);
      return Response.json({
        currentVersion: currentFileVersion || "unknown",
        latestVersion,
        updateAvailable: latestVersion !== "unknown" && currentFileVersion !== "unknown" && isNewerVersion(latestVersion, currentFileVersion),
        lastChecked: now
      }, { headers: corsHeaders });
    } catch (e: any) {
      return Response.json({ error: e.message || "Version check failed" }, { status: 500, headers: corsHeaders });
    }
  }

  if (path === "/api/admin/upload-html" && req.method === "POST") {
    const { user: adminUser, apiKey } = await validateAdminOrApiKey(req, "admin");
    if (!adminUser && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    if (adminUser && !validateRequestCsrf(req)) return csrfReject(corsHeaders);
    {
      const declared = parseInt(req.headers.get("content-length") || "", 10);
      if (!Number.isFinite(declared)) {
        return Response.json({ error: "Content-Length required for uploads" }, { status: 411, headers: corsHeaders });
      }
      if (declared > UPLOAD_HTML_BODY_CAP) return tooLargeResponse(corsHeaders);
    }
    try {
      const formData = await req.formData();
      const file = formData.get("file") as File | null;
      if (!file) {
        return Response.json({ error: "No file provided" }, { status: 400, headers: corsHeaders });
      }
      if (file.type && !["text/html", "application/octet-stream"].includes(file.type)) {
        return Response.json({ error: "Invalid file type. Upload an HTML file." }, { status: 400, headers: corsHeaders });
      }
      if (file.size > 10 * 1024 * 1024) {
        return Response.json({ error: "File too large. Maximum size is 10MB." }, { status: 400, headers: corsHeaders });
      }
      const html = await file.text();
      const validationResult = validateTheOneFileHtml(html);
      if (!validationResult.valid) {
        return Response.json({ error: validationResult.error }, { status: 400, headers: corsHeaders });
      }
      const theOneFilePath = getTheOneFilePath();
      await Bun.write(theOneFilePath, html);
      setTheOneFileHtml(html);
      setExpectedTheOneFileHash(await computeSha256Hash(html));
      const settings = getSettings();
      settings.skipUpdates = true;
      updateSettings(settings);
      saveSettings(settings);
      clearUpdateTimer();
      console.log(`[Upload] Admin uploaded local file (${(html.length / 1024).toFixed(1)}KB) - ${validationResult.edition}`);
      return Response.json({ success: true, size: html.length, edition: validationResult.edition }, { headers: corsHeaders });
    } catch (e) {
      return Response.json({ error: "Failed to process upload" }, { status: 500, headers: corsHeaders });
    }
  }

  if (path === "/api/admin/source-mode" && req.method === "POST") {
    const { user: adminUser, apiKey } = await validateAdminOrApiKey(req, "admin");
    if (!adminUser && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    if (adminUser && !validateRequestCsrf(req)) return csrfReject(corsHeaders);
    try {
      const body = await readJsonLimited(req, 64 * 1024);
      const settings = getSettings();
      if (body.mode === "github") {
        settings.skipUpdates = false;
        updateSettings(settings);
        saveSettings(settings);
        await fetchLatestFromGitHub();
        restartUpdateTimer();
        return Response.json({ success: true, mode: "github", size: theOneFileHtml.length }, { headers: corsHeaders });
      } else if (body.mode === "local") {
        settings.skipUpdates = true;
        updateSettings(settings);
        saveSettings(settings);
        clearUpdateTimer();
        return Response.json({ success: true, mode: "local" }, { headers: corsHeaders });
      }
      return Response.json({ error: "Invalid mode" }, { status: 400, headers: corsHeaders });
    } catch (e: any) {
      console.error("[API]", e.message); return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders });
    }
  }

  return null;
}
