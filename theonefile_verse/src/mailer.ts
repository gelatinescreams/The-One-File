import * as db from "./database";
import { decryptSecret } from "./oidc";
import { connect as tlsConnect, TLSSocket } from "tls";
import { Socket } from "net";

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

interface EmailMessage {
  to: string;
  subject: string;
  html: string;
  text: string;
}

interface SendResult {
  success: boolean;
  messageId?: string;
  error?: string;
}

interface SmtpResponse {
  code: number;
  message: string;
  lines: string[];
}

export async function sendEmail(message: EmailMessage): Promise<SendResult> {
  const config = db.getDefaultSmtpConfig();
  if (!config) {
    return { success: false, error: "No SMTP configuration found" };
  }

  return sendEmailWithConfig(message, config);
}

export async function sendEmailWithConfig(
  message: EmailMessage,
  config: db.SmtpConfig
): Promise<SendResult> {
  const logId = crypto.randomUUID();

  if (config.allowInsecureTls) {
    console.warn(`[Mailer] WARNING: Insecure TLS is enabled for SMTP config "${config.name}". This disables certificate verification and is NOT recommended for production use.`);
  }

  try {
    let password: string | null = null;
    if (config.passwordEncrypted) {
      try {
        password = await decryptSecret(config.passwordEncrypted);
      } catch (e) {
        console.error("[Mailer] Failed to decrypt password");
        return logAndReturn(logId, message, config, false, "Failed to decrypt SMTP password");
      }
    }

    const result = await sendViaSMTP(message, config, password);
    return logAndReturn(logId, message, config, result.success, result.error);
  } catch (e: any) {
    console.error("[Mailer] Send error:", e);
    return logAndReturn(logId, message, config, false, e.message || "Unknown error");
  }
}

function logAndReturn(
  id: string,
  message: EmailMessage,
  config: db.SmtpConfig,
  success: boolean,
  error?: string
): SendResult {
  db.createEmailLog({
    id,
    toEmail: message.to,
    templateName: null,
    subject: message.subject,
    status: success ? 'sent' : 'failed',
    errorMessage: error || null,
    smtpConfigId: config.id,
    sentAt: new Date().toISOString()
  });

  return { success, messageId: success ? id : undefined, error };
}

class SmtpClient {
  private socket: any = null;
  private buffer = "";
  private responsePromise: { resolve: (r: SmtpResponse) => void; reject: (e: Error) => void } | null = null;
  private isSecure = false;
  private config: db.SmtpConfig;
  private debug = true;

  constructor(config: db.SmtpConfig) {
    this.config = config;
  }

  private log(...args: any[]) {
    if (this.debug) console.log("[SMTP]", ...args);
  }

  async connect(): Promise<void> {
    const { host, port, secureMode } = this.config;
    if (!host || !port) {
      throw new Error("SMTP host and port are required");
    }

    this.log(`Connecting to ${host}:${port} (${secureMode})`);

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error("Connection timeout"));
      }, 30000);

      if (secureMode === 'tls') {
        const tlsSocket = tlsConnect({
          host: host,
          port: port,
          rejectUnauthorized: !this.config.allowInsecureTls,
          servername: host
        });

        tlsSocket.once('secureConnect', () => {
          clearTimeout(timeout);
          this.isSecure = true;
          this.socket = {
            write: (data: string) => tlsSocket.write(data),
            end: () => tlsSocket.end(),
            rawSocket: tlsSocket
          };

          tlsSocket.on('data', (data) => this.handleData(data));
          tlsSocket.on('error', (err) => this.handleError(err));
          tlsSocket.on('close', () => this.handleClose());

          this.readResponse().then(greeting => {
            if (greeting.code !== 220) {
              reject(new Error(`Server greeting failed: ${greeting.message}`));
            } else {
              this.log("Connected (TLS), greeting:", greeting.code);
              resolve();
            }
          }).catch(reject);
        });

        tlsSocket.once('error', (err) => {
          clearTimeout(timeout);
          reject(err);
        });

      } else {
        const netSocket = new Socket();

        netSocket.connect(port, host, () => {
          clearTimeout(timeout);
          this.socket = {
            write: (data: string) => netSocket.write(data),
            end: () => netSocket.end(),
            rawSocket: netSocket
          };

          netSocket.on('data', (data) => this.handleData(data));
          netSocket.on('error', (err) => this.handleError(err));
          netSocket.on('close', () => this.handleClose());

          this.readResponse().then(greeting => {
            if (greeting.code !== 220) {
              reject(new Error(`Server greeting failed: ${greeting.message}`));
            } else {
              this.log("Connected, greeting:", greeting.code);
              resolve();
            }
          }).catch(reject);
        });

        netSocket.once('error', (err) => {
          clearTimeout(timeout);
          reject(err);
        });
      }
    });
  }

  private handleData(data: Buffer) {
    this.buffer += data.toString();
    this.processBuffer();
  }

  private handleError(error: Error) {
    this.log("Socket error:", error.message);
    if (this.responsePromise) {
      this.responsePromise.reject(error);
      this.responsePromise = null;
    }
  }

  private handleClose() {
    this.log("Socket closed");
    if (this.responsePromise) {
      this.responsePromise.reject(new Error("Connection closed unexpectedly"));
      this.responsePromise = null;
    }
  }

  private processBuffer() {
    const lines = this.buffer.split('\r\n');

    for (let i = 0; i < lines.length - 1; i++) {
      const line = lines[i];
      if (line.length < 3) continue;

      const code = parseInt(line.substring(0, 3), 10);
      const isContinuation = line.charAt(3) === '-';

      if (!isContinuation && this.responsePromise) {
        const allLines = lines.slice(0, i + 1);
        this.buffer = lines.slice(i + 1).join('\r\n');

        this.responsePromise.resolve({
          code,
          message: line.substring(4),
          lines: allLines
        });
        this.responsePromise = null;
        return;
      }
    }
  }

  private readResponse(): Promise<SmtpResponse> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.responsePromise = null;
        reject(new Error("Response timeout"));
      }, 30000);

      this.responsePromise = {
        resolve: (r) => {
          clearTimeout(timeout);
          resolve(r);
        },
        reject: (e) => {
          clearTimeout(timeout);
          reject(e);
        }
      };

      this.processBuffer();
    });
  }

  private async command(cmd: string, expectedCodes: number[] = [250]): Promise<SmtpResponse> {
    this.log(">>>", cmd.startsWith("AUTH") || cmd.includes("@") ? cmd.split(" ")[0] + " ***" : cmd);

    this.socket.write(cmd + "\r\n");
    const response = await this.readResponse();

    this.log("<<<", response.code, response.message);

    if (!expectedCodes.includes(response.code)) {
      throw new Error(`SMTP error ${response.code}: ${response.message}`);
    }

    return response;
  }

  async ehlo(): Promise<string[]> {
    const response = await this.command(`EHLO ${this.config.host}`, [250]);
    return response.lines;
  }

  async startTls(): Promise<string[]> {
    if (this.isSecure) return [];

    await this.command("STARTTLS", [220]);

    this.log("Upgrading to TLS...");

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error("TLS upgrade timeout"));
      }, 15000);

      try {
        const rawSocket = this.socket.rawSocket as Socket;
        if (!rawSocket) {
          clearTimeout(timeout);
          reject(new Error("Cannot upgrade to TLS: no raw socket available"));
          return;
        }

        rawSocket.removeAllListeners('data');
        rawSocket.removeAllListeners('error');
        rawSocket.removeAllListeners('close');

        const tlsSocket = tlsConnect({
          socket: rawSocket,
          host: this.config.host!,
          rejectUnauthorized: !this.config.allowInsecureTls,
          servername: this.config.host!
        });

        tlsSocket.once('secureConnect', () => {
          clearTimeout(timeout);
          this.log("TLS handshake successful");
          this.isSecure = true;
          this.buffer = "";

          this.socket = {
            write: (data: string) => tlsSocket.write(data),
            end: () => tlsSocket.end(),
            rawSocket: tlsSocket
          };

          tlsSocket.on('data', (data) => this.handleData(data));
          tlsSocket.on('error', (err) => this.handleError(err));
          tlsSocket.on('close', () => this.handleClose());

          this.ehlo().then(caps => resolve(caps)).catch(reject);
        });

        tlsSocket.once('error', (err) => {
          clearTimeout(timeout);
          reject(err);
        });

      } catch (e: any) {
        clearTimeout(timeout);
        reject(e);
      }
    });
  }

  async authenticate(username: string, password: string, capabilities: string[]): Promise<void> {
    const supportsLogin = capabilities.some(l => l.toUpperCase().includes('AUTH') && l.toUpperCase().includes('LOGIN'));
    const supportsPlain = capabilities.some(l => l.toUpperCase().includes('AUTH') && l.toUpperCase().includes('PLAIN'));

    if (supportsLogin) {
      await this.command("AUTH LOGIN", [334]);
      await this.command(Buffer.from(username).toString('base64'), [334]);
      await this.command(Buffer.from(password).toString('base64'), [235]);
    } else if (supportsPlain) {
      const credentials = Buffer.from(`\0${username}\0${password}`).toString('base64');
      await this.command(`AUTH PLAIN ${credentials}`, [235]);
    } else {
      throw new Error("Server does not support LOGIN or PLAIN authentication");
    }
    this.log("Authenticated successfully");
  }

  async mailFrom(email: string): Promise<void> {
    await this.command(`MAIL FROM:<${email}>`, [250]);
  }

  async rcptTo(email: string): Promise<void> {
    await this.command(`RCPT TO:<${email}>`, [250, 251]);
  }

  async data(content: string): Promise<void> {
    await this.command("DATA", [354]);

    const escapedContent = content.replace(/^\./gm, '..');
    const finalContent = escapedContent.endsWith('\r\n') ? escapedContent : escapedContent + '\r\n';

    this.socket.write(finalContent + ".\r\n");
    const response = await this.readResponse();

    if (response.code !== 250) {
      throw new Error(`DATA failed: ${response.code} ${response.message}`);
    }
    this.log("Message accepted");
  }

  async quit(): Promise<void> {
    try {
      await this.command("QUIT", [221]);
    } catch {}
    this.close();
  }

  close() {
    if (this.socket) {
      try {
        this.socket.end();
      } catch {}
      this.socket = null;
    }
  }
}

async function sendViaSMTP(
  message: EmailMessage,
  config: db.SmtpConfig,
  password: string | null
): Promise<SendResult> {
  if (!config.host || !config.port) {
    return { success: false, error: "SMTP host and port are required" };
  }

  const client = new SmtpClient(config);

  try {
    console.log(`[Mailer] Connecting to ${config.host}:${config.port} (${config.secureMode})`);
    await client.connect();
    console.log("[Mailer] Connected successfully");

    let capabilities = await client.ehlo();
    console.log("[Mailer] EHLO capabilities:", capabilities.join(", "));

    if (config.secureMode === 'starttls') {
      const supportsTls = capabilities.some(line =>
        line.toUpperCase().includes('STARTTLS')
      );

      if (supportsTls) {
        console.log("[Mailer] Starting TLS upgrade...");
        const newCaps = await client.startTls();
        if (newCaps.length > 0) {
          capabilities = newCaps;
          console.log("[Mailer] Post-TLS capabilities:", capabilities.join(", "));
        }
      } else {
        console.warn("[Mailer] Server doesn't support STARTTLS, continuing without encryption");
      }
    }

    if (config.username && password) {
      console.log("[Mailer] Authenticating as:", config.username);
      await client.authenticate(config.username, password, capabilities);
      console.log("[Mailer] Authentication successful");
    }

    console.log("[Mailer] Sending MAIL FROM:", config.fromEmail);
    await client.mailFrom(config.fromEmail);

    console.log("[Mailer] Sending RCPT TO:", message.to);
    await client.rcptTo(message.to);

    console.log("[Mailer] Sending message data...");
    const messageContent = buildMessage(message, config);
    await client.data(messageContent);

    console.log("[Mailer] Message sent, closing connection");
    await client.quit();

    return { success: true };
  } catch (e: any) {
    client.close();
    console.error("[Mailer] SMTP error:", e.message);
    console.error("[Mailer] Stack:", e.stack);
    return { success: false, error: e.message };
  }
}

function buildMessage(message: EmailMessage, config: db.SmtpConfig): string {
  const boundary = `----=_Part_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  const messageId = `<${crypto.randomUUID()}@${config.host}>`;
  const date = new Date().toUTCString();

  const fromHeader = config.fromName
    ? `"${config.fromName.replace(/"/g, '\\"')}" <${config.fromEmail}>`
    : config.fromEmail;

  const subjectEncoded = encodeSubject(message.subject);

  const headers = [
    `Message-ID: ${messageId}`,
    `Date: ${date}`,
    `From: ${fromHeader}`,
    `To: ${message.to}`,
    `Subject: ${subjectEncoded}`,
    `MIME-Version: 1.0`,
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    `X-Mailer: TheOneFile_Verse`,
    ``
  ];

  const textPart = [
    `--${boundary}`,
    `Content-Type: text/plain; charset="utf-8"`,
    `Content-Transfer-Encoding: quoted-printable`,
    ``,
    encodeQuotedPrintable(message.text),
    ``
  ];

  const htmlPart = [
    `--${boundary}`,
    `Content-Type: text/html; charset="utf-8"`,
    `Content-Transfer-Encoding: quoted-printable`,
    ``,
    encodeQuotedPrintable(message.html),
    ``
  ];

  const ending = [`--${boundary}--`, ``];

  return [...headers, ...textPart, ...htmlPart, ...ending].join('\r\n');
}

function encodeSubject(subject: string): string {
  if (/^[\x20-\x7E]*$/.test(subject)) {
    return subject;
  }
  const encoded = Buffer.from(subject, 'utf-8').toString('base64');
  return `=?UTF-8?B?${encoded}?=`;
}

function encodeQuotedPrintable(text: string): string {
  const lines: string[] = [];
  let currentLine = "";

  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    const code = char.charCodeAt(0);

    let encoded: string;
    if (char === '\r' && text[i + 1] === '\n') {
      if (currentLine) {
        lines.push(currentLine);
        currentLine = "";
      }
      lines.push("");
      i++;
      continue;
    } else if (char === '\n') {
      if (currentLine) {
        lines.push(currentLine);
        currentLine = "";
      }
      lines.push("");
      continue;
    } else if (code >= 33 && code <= 126 && char !== '=') {
      encoded = char;
    } else if (char === ' ' || char === '\t') {
      encoded = char;
    } else {
      const bytes = Buffer.from(char, 'utf-8');
      encoded = Array.from(bytes)
        .map(b => '=' + b.toString(16).toUpperCase().padStart(2, '0'))
        .join('');
    }

    if (currentLine.length + encoded.length > 73) {
      lines.push(currentLine + "=");
      currentLine = encoded;
    } else {
      currentLine += encoded;
    }
  }

  if (currentLine) {
    lines.push(currentLine);
  }

  return lines.join('\r\n');
}

export async function sendTemplatedEmail(
  to: string,
  templateName: string,
  variables: Record<string, string>
): Promise<SendResult> {
  const template = db.getEmailTemplateByName(templateName);
  if (!template) {
    return { success: false, error: `Template '${templateName}' not found` };
  }

  let subject = template.subject;
  let html = template.bodyHtml;
  let text = template.bodyText;

  for (const [key, value] of Object.entries(variables)) {
    const pattern = new RegExp(`\\{\\{${key}\\}\\}`, 'g');
    const escapedValueForHtml = escapeHtml(value);
    subject = subject.replace(pattern, value);
    html = html.replace(pattern, escapedValueForHtml);
    text = text.replace(pattern, value);
  }

  return sendEmail({ to, subject, html, text });
}

export async function sendVerificationEmail(
  to: string,
  displayName: string,
  verifyUrl: string
): Promise<SendResult> {
  return sendTemplatedEmail(to, 'Email Verification', {
    displayName,
    verifyUrl
  });
}

export async function sendPasswordResetEmail(
  to: string,
  displayName: string,
  resetUrl: string
): Promise<SendResult> {
  return sendTemplatedEmail(to, 'Password Reset', {
    displayName,
    resetUrl
  });
}

export async function sendMagicLinkEmail(
  to: string,
  displayName: string,
  loginUrl: string
): Promise<SendResult> {
  return sendTemplatedEmail(to, 'Magic Link', {
    displayName,
    loginUrl
  });
}

export async function sendRoomInvitationEmail(
  to: string,
  inviterName: string,
  roomUrl: string
): Promise<SendResult> {
  return sendTemplatedEmail(to, 'Room Invitation', {
    inviterName,
    roomUrl
  });
}

export async function testSmtpConfig(config: db.SmtpConfig): Promise<SendResult> {
  return sendEmailWithConfig({
    to: config.fromEmail,
    subject: 'TheOneFile_Verse - SMTP Test',
    html: '<h1>SMTP Test Successful</h1><p>Your SMTP configuration is working correctly.</p>',
    text: 'SMTP Test Successful\n\nYour SMTP configuration is working correctly.'
  }, config);
}

export function getEmailStats(): {
  total: number;
  sent: number;
  failed: number;
} {
  return {
    total: db.countEmailLogs(),
    sent: db.countEmailLogsByStatus('sent'),
    failed: db.countEmailLogsByStatus('failed')
  };
}
