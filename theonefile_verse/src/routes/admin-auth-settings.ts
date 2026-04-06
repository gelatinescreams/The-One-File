import * as oidc from "../oidc";
import * as db from "../database";
import * as mailer from "../mailer";
import { getClientIP, apiError, validateAdminUser } from "../security";

export async function handle(req: Request, path: string, url: URL, corsHeaders: Record<string, string>): Promise<Response | null> {
  if (path === "/api/admin/auth-settings" && req.method === "GET") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    return Response.json(oidc.getAuthSettings(), { headers: corsHeaders });
  }

  if (path === "/api/admin/auth-settings" && req.method === "POST") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      oidc.saveAuthSettings(body);
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "auth_settings_changed", actor: adminUser.id, actorIp: getClientIP(req), details: body });
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/admin/oidc-providers" && req.method === "GET") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const providers = db.listOidcProviders().map(p => ({
      id: p.id, name: p.name, providerType: p.providerType, clientId: p.clientId,
      issuerUrl: p.issuerUrl, authorizationUrl: p.authorizationUrl, tokenUrl: p.tokenUrl,
      userinfoUrl: p.userinfoUrl, scopes: p.scopes, isActive: p.isActive, displayOrder: p.displayOrder,
      iconUrl: p.iconUrl, createdAt: p.createdAt
    }));
    return Response.json({ providers }, { headers: corsHeaders });
  }

  if (path === "/api/admin/oidc-providers" && req.method === "POST") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (!body.name || !body.clientId || !body.clientSecret) {
        return Response.json({ error: "Name, client ID, and client secret are required" }, { status: 400, headers: corsHeaders });
      }
      const encryptedSecret = await oidc.encryptSecret(body.clientSecret);
      const now = new Date().toISOString();
      const provider: db.OidcProvider = {
        id: crypto.randomUUID(),
        name: body.name,
        providerType: body.providerType || 'generic',
        clientId: body.clientId,
        clientSecretEncrypted: encryptedSecret,
        issuerUrl: body.issuerUrl || null,
        authorizationUrl: body.authorizationUrl || null,
        tokenUrl: body.tokenUrl || null,
        userinfoUrl: body.userinfoUrl || null,
        jwksUri: body.jwksUri || null,
        scopes: body.scopes || 'openid email profile',
        isActive: body.isActive !== false,
        displayOrder: body.displayOrder || 0,
        iconUrl: body.iconUrl || null,
        createdAt: now,
        updatedAt: now
      };
      db.createOidcProvider(provider);
      db.addAuditLog({ timestamp: now, action: "oidc_provider_created", actor: adminUser.id, actorIp: getClientIP(req), targetType: "oidc_provider", targetId: provider.id, details: { name: provider.name } });
      return Response.json({ success: true, id: provider.id }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path.match(/^\/api\/admin\/oidc-providers\/[\w-]+$/) && req.method === "PUT") {
    const providerId = path.split("/")[4];
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      const existing = db.getOidcProvider(providerId);
      if (!existing) {
        return Response.json({ error: "Provider not found" }, { status: 404, headers: corsHeaders });
      }
      const now = new Date().toISOString();
      const updated: db.OidcProvider = {
        ...existing,
        name: body.name ?? existing.name,
        providerType: body.providerType ?? existing.providerType,
        clientId: body.clientId ?? existing.clientId,
        clientSecretEncrypted: body.clientSecret ? await oidc.encryptSecret(body.clientSecret) : existing.clientSecretEncrypted,
        issuerUrl: body.issuerUrl !== undefined ? body.issuerUrl : existing.issuerUrl,
        authorizationUrl: body.authorizationUrl !== undefined ? body.authorizationUrl : existing.authorizationUrl,
        tokenUrl: body.tokenUrl !== undefined ? body.tokenUrl : existing.tokenUrl,
        userinfoUrl: body.userinfoUrl !== undefined ? body.userinfoUrl : existing.userinfoUrl,
        jwksUri: body.jwksUri !== undefined ? body.jwksUri : existing.jwksUri,
        scopes: body.scopes ?? existing.scopes,
        isActive: body.isActive ?? existing.isActive,
        displayOrder: body.displayOrder ?? existing.displayOrder,
        iconUrl: body.iconUrl !== undefined ? body.iconUrl : existing.iconUrl,
        updatedAt: now
      };
      db.updateOidcProvider(updated);
      db.addAuditLog({ timestamp: now, action: "oidc_provider_updated", actor: adminUser.id, actorIp: getClientIP(req), targetType: "oidc_provider", targetId: providerId });
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path.match(/^\/api\/admin\/oidc-providers\/[\w-]+$/) && req.method === "DELETE") {
    const providerId = path.split("/")[4];
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    if (db.deleteOidcProvider(providerId)) {
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "oidc_provider_deleted", actor: adminUser.id, actorIp: getClientIP(req), targetType: "oidc_provider", targetId: providerId });
      return Response.json({ success: true }, { headers: corsHeaders });
    }
    return Response.json({ error: "Provider not found" }, { status: 404, headers: corsHeaders });
  }

  if (path === "/api/admin/smtp-configs" && req.method === "GET") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const configs = db.listSmtpConfigs().map(c => ({
      id: c.id, name: c.name, providerType: c.providerType, host: c.host, port: c.port,
      secureMode: c.secureMode, username: c.username, fromEmail: c.fromEmail, fromName: c.fromName,
      isDefault: c.isDefault, isActive: c.isActive, createdAt: c.createdAt
    }));
    return Response.json({ configs }, { headers: corsHeaders });
  }

  if (path === "/api/admin/smtp-configs" && req.method === "POST") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      if (!body.name || !body.fromEmail) {
        return Response.json({ error: "Name and from email are required" }, { status: 400, headers: corsHeaders });
      }
      const encryptedPassword = body.password ? await oidc.encryptSecret(body.password) : null;
      const now = new Date().toISOString();
      const config: db.SmtpConfig = {
        id: crypto.randomUUID(),
        name: body.name,
        providerType: body.providerType || 'smtp',
        host: body.host || null,
        port: body.port || null,
        secureMode: body.secureMode || 'tls',
        username: body.username || null,
        passwordEncrypted: encryptedPassword,
        apiKeyEncrypted: null,
        fromEmail: body.fromEmail,
        fromName: body.fromName || null,
        isDefault: body.isDefault || false,
        isActive: body.isActive !== false,
        createdAt: now,
        updatedAt: now
      };
      db.createSmtpConfig(config);
      db.addAuditLog({ timestamp: now, action: "smtp_config_created", actor: adminUser.id, actorIp: getClientIP(req), targetType: "smtp_config", targetId: config.id, details: { name: config.name } });
      return Response.json({ success: true, id: config.id }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path.match(/^\/api\/admin\/smtp-configs\/[\w-]+$/) && req.method === "PUT") {
    const configId = path.split("/")[4];
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      const existing = db.getSmtpConfig(configId);
      if (!existing) {
        return Response.json({ error: "Config not found" }, { status: 404, headers: corsHeaders });
      }
      const now = new Date().toISOString();
      const updated: db.SmtpConfig = {
        ...existing,
        name: body.name ?? existing.name,
        providerType: body.providerType ?? existing.providerType,
        host: body.host !== undefined ? body.host : existing.host,
        port: body.port !== undefined ? body.port : existing.port,
        secureMode: body.secureMode ?? existing.secureMode,
        username: body.username !== undefined ? body.username : existing.username,
        passwordEncrypted: body.password ? await oidc.encryptSecret(body.password) : existing.passwordEncrypted,
        fromEmail: body.fromEmail ?? existing.fromEmail,
        fromName: body.fromName !== undefined ? body.fromName : existing.fromName,
        isDefault: body.isDefault ?? existing.isDefault,
        isActive: body.isActive ?? existing.isActive,
        updatedAt: now
      };
      db.updateSmtpConfig(updated);
      db.addAuditLog({ timestamp: now, action: "smtp_config_updated", actor: adminUser.id, actorIp: getClientIP(req), targetType: "smtp_config", targetId: configId });
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  if (path === "/api/admin/smtp-configs/test" && req.method === "POST") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      const now = new Date().toISOString();
      let passwordEncrypted: string | null = null;
      if (body.password) {
        passwordEncrypted = await oidc.encryptSecret(body.password);
      }
      const testConfig: db.SmtpConfig = {
        id: "test-" + crypto.randomUUID(),
        name: body.name || "Test",
        providerType: "smtp",
        host: body.host,
        port: body.port || 587,
        secureMode: body.secureMode || "starttls",
        username: body.username || null,
        passwordEncrypted,
        apiKeyEncrypted: null,
        fromEmail: body.fromEmail,
        fromName: body.fromName || null,
        isDefault: false,
        isActive: true,
        createdAt: now,
        updatedAt: now
      };
      const result = await mailer.testSmtpConfig(testConfig);
      return Response.json(result, { headers: corsHeaders });
    } catch (e: any) {
      return Response.json({ success: false, error: e.message || "Test failed" }, { headers: corsHeaders });
    }
  }

  if (path.match(/^\/api\/admin\/smtp-configs\/[\w-]+\/test$/) && req.method === "POST") {
    const configId = path.split("/")[4];
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const config = db.getSmtpConfig(configId);
    if (!config) {
      return Response.json({ error: "Config not found" }, { status: 404, headers: corsHeaders });
    }
    const result = await mailer.testSmtpConfig(config);
    return Response.json(result, { headers: corsHeaders });
  }

  if (path.match(/^\/api\/admin\/smtp-configs\/[\w-]+$/) && req.method === "DELETE") {
    const configId = path.split("/")[4];
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    if (db.deleteSmtpConfig(configId)) {
      db.addAuditLog({ timestamp: new Date().toISOString(), action: "smtp_config_deleted", actor: adminUser.id, actorIp: getClientIP(req), targetType: "smtp_config", targetId: configId });
      return Response.json({ success: true }, { headers: corsHeaders });
    }
    return Response.json({ error: "Config not found" }, { status: 404, headers: corsHeaders });
  }

  if (path === "/api/admin/email-logs" && req.method === "GET") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    const limit = Math.min(parseInt(url.searchParams.get("limit") || "100") || 100, 1000);
    const offset = parseInt(url.searchParams.get("offset") || "0");
    const logs = db.listEmailLogs(limit, offset);
    const stats = mailer.getEmailStats();
    return Response.json({ logs, stats }, { headers: corsHeaders });
  }

  if (path === "/api/admin/email-logs" && req.method === "DELETE") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    db.clearEmailLogs();
    db.addAuditLog({ timestamp: new Date().toISOString(), action: "email_logs_cleared", actor: adminUser.email || "admin", actorIp: getClientIP(req) });
    return Response.json({ success: true }, { headers: corsHeaders });
  }

  if (path === "/api/admin/email-templates" && req.method === "GET") {
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    return Response.json({ templates: db.listEmailTemplates() }, { headers: corsHeaders });
  }

  if (path.match(/^\/api\/admin\/email-templates\/[\w-]+$/) && req.method === "PUT") {
    const templateId = path.split("/")[4];
    const adminUser = await validateAdminUser(req);
    if (!adminUser) {
      return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
    }
    try {
      const body = await req.json();
      const existing = db.getEmailTemplate(templateId);
      if (!existing) {
        return Response.json({ error: "Template not found" }, { status: 404, headers: corsHeaders });
      }
      const updated: db.EmailTemplate = {
        ...existing,
        subject: body.subject ?? existing.subject,
        bodyHtml: body.bodyHtml ?? existing.bodyHtml,
        bodyText: body.bodyText ?? existing.bodyText,
        updatedAt: new Date().toISOString()
      };
      db.updateEmailTemplate(updated);
      return Response.json({ success: true }, { headers: corsHeaders });
    } catch (e: any) { return apiError(e, corsHeaders); }
  }

  return null;
}
