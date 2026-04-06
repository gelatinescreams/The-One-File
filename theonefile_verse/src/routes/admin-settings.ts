import * as db from "../database";
import { getSettings, updateSettings, saveSettings, validateAdminPath, ENV_ADMIN_PASSWORD, APP_VERSION } from "../config";
import { getClientIP, apiError, validateAdminUser, validateAdminOrApiKey } from "../security";
import { hashPassword, theOneFileHtml, currentFileVersion, extractThemePresets, computeSha256Hash, validateTheOneFileHtml, fetchLatestFromGitHub, getExpectedTheOneFileHash, setExpectedTheOneFileHash, setTheOneFileHtml, getTheOneFilePath, restartUpdateTimer, clearUpdateTimer, isValidWebhookUrl, restartBackupTimer, extractVersionFromHtml } from "../rooms";

const GITHUB_RAW_URL = "https://raw.githubusercontent.com/gelatinescreams/The-One-File/main/theonefile-networkening.html";

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
    try {
      const body = await req.json();

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

      const settings = { ...getSettings() };

      if (typeof body.instancePasswordEnabled === "boolean") {
        settings.instancePasswordEnabled = body.instancePasswordEnabled;
      }
      if (body.instancePassword !== undefined) {
        if (body.instancePassword === "") {
          settings.instancePasswordHash = null;
        } else if (body.instancePassword.length >= 10) {
          settings.instancePasswordHash = await hashPassword(body.instancePassword);
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
      if (typeof body.discoveryEnabled === "boolean") {
        settings.discoveryEnabled = body.discoveryEnabled;
      }
      if (typeof body.discoveryAdminOnly === "boolean") {
        settings.discoveryAdminOnly = body.discoveryAdminOnly;
      }
      if (typeof body.discoveryAllowPublicRanges === "boolean") {
        settings.discoveryAllowPublicRanges = body.discoveryAllowPublicRanges;
      }
      if (typeof body.discoveryMaxPrefix === "number") {
        settings.discoveryMaxPrefix = Math.max(20, Math.min(32, body.discoveryMaxPrefix));
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

      updateSettings(settings);
      saveSettings(settings);

      if (typeof body.updateIntervalHours === "number" || typeof body.skipUpdates === "boolean") {
        restartUpdateTimer();
      }
      if (typeof body.backupEnabled === "boolean" || typeof body.backupIntervalHours === "number") {
        restartBackupTimer();
      }

      const actor = adminUser ? adminUser.id : `apikey:${apiKey!.name}`;
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "settings_changed", actor, actorIp: getClientIP(req), details: body });
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/admin/update" && req.method === "POST") {
    const { user: adminUser, apiKey } = await validateAdminOrApiKey(req, "admin");
    if (!adminUser && !apiKey) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const settings = getSettings();
    if (settings.skipUpdates) {
      return Response.json({ error: "Updates disabled" }, { status: 400, headers: corsHeaders });
    }
    const previousVersion = currentFileVersion;
    const success = await fetchLatestFromGitHub();
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
        updateAvailable: latestVersion !== "unknown" && currentFileVersion !== latestVersion,
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
    try {
      const formData = await req.formData();
      const file = formData.get("file") as File | null;
      if (!file) {
        return Response.json({ error: "No file provided" }, { status: 400, headers: corsHeaders });
      }
      if (file.size > 50 * 1024 * 1024) {
        return Response.json({ error: "File too large. Maximum size is 50MB." }, { status: 400, headers: corsHeaders });
      }
      const html = await file.text();
      const validationResult = validateTheOneFileHtml(html);
      if (!validationResult.valid) {
        return Response.json({ error: validationResult.error }, { status: 400, headers: corsHeaders });
      }
      const theOneFilePath = getTheOneFilePath();
      await Bun.write(theOneFilePath, html);
      setTheOneFileHtml(html);
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
    try {
      const body = await req.json();
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
