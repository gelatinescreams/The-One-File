import * as db from "./database";
import * as oidc from "./oidc";
import * as mailer from "./mailer";
import { createHmac, randomBytes, timingSafeEqual } from "crypto";

function timingSafeEqualStr(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

export async function hashPassword(password: string): Promise<string> {
  return await Bun.password.hash(password, {
    algorithm: "argon2id",
    memoryCost: 65536,
    timeCost: 2
  });
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  if (hash.startsWith('$argon2')) {
    return await Bun.password.verify(password, hash);
  }
  const encoder = new TextEncoder();
  const data = encoder.encode(password + "theonefile-collab-salt-v1");
  const legacyHash = await crypto.subtle.digest("SHA-256", data);
  const computed = Buffer.from(Buffer.from(legacyHash).toString("hex"));
  const stored = Buffer.from(hash);
  if (computed.length !== stored.length) return false;
  return crypto.timingSafeEqual(computed, stored);
}

export function isLegacyHash(hash: string): boolean {
  return !hash.startsWith('$argon2');
}

export async function upgradePasswordHash(userId: string, password: string): Promise<void> {
  const user = db.getUserById(userId);
  if (!user) return;

  const newHash = await hashPassword(password);
  user.passwordHash = newHash;
  user.updatedAt = new Date().toISOString();
  db.updateUser(user);
  console.log(`[Auth] Upgraded password hash for user ${userId} from legacy SHA-256 to Argon2id`);
}

export function validatePassword(password: string): { valid: boolean; error?: string } {
  if (password.length < 8) {
    return { valid: false, error: "Password must be at least 8 characters" };
  }
  if (password.length > 128) {
    return { valid: false, error: "Password must be less than 128 characters" };
  }
  if (!/[0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    return { valid: false, error: "Password must contain at least one number or special character" };
  }
  if (!/[a-zA-Z]/.test(password)) {
    return { valid: false, error: "Password must contain at least one letter" };
  }
  return { valid: true };
}

export function validateEmail(email: string): { valid: boolean; error?: string } {
  if (!email || email.length > 254) {
    return { valid: false, error: "Invalid email address" };
  }
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  if (!emailRegex.test(email)) {
    return { valid: false, error: "Invalid email format" };
  }
  return { valid: true };
}

function normalizeEmail(email: string): string {
  return email.toLowerCase().trim();
}

export async function registerUser(
  email: string,
  password: string,
  displayName?: string,
  baseUrl?: string,
  inviteCode?: string | null,
  options: { bypassRegistrationGate?: boolean } = {}
): Promise<{ success: boolean; userId?: string; error?: string; requiresVerification?: boolean; pendingApproval?: boolean }> {
  const normalizedEmail = normalizeEmail(email);
  const emailValidation = validateEmail(normalizedEmail);
  if (!emailValidation.valid) {
    return { success: false, error: emailValidation.error };
  }

  const passwordValidation = validatePassword(password);
  if (!passwordValidation.valid) {
    return { success: false, error: passwordValidation.error };
  }

  const existing = db.getUserByEmail(normalizedEmail);
  if (existing) {
    return { success: false, error: "Registration failed. Please try again or use a different email." };
  }

  const authSettings = oidc.getAuthSettings();
  let inviteHash: string | null = null;
  if (!options.bypassRegistrationGate) {
    if (authSettings.authMode === 'closed') {
      return { success: false, error: "Registration is closed" };
    }
    if (authSettings.authMode === 'invite_only') {
      const invite = checkInviteCode(inviteCode || null, normalizedEmail);
      if (!invite.valid) {
        return { success: false, error: "Registration requires a valid invitation code" };
      }
      inviteHash = invite.codeHash!;
    }
    if (authSettings.authMode === 'oidc_only') {
      return { success: false, error: "Please use SSO to register" };
    }
    if (authSettings.requireEmailVerification && !db.getDefaultSmtpConfig() && db.listUsers(1, 0).length > 0) {
      return { success: false, error: "Registration requires email verification, but email delivery is not configured. Please contact the administrator." };
    }
  }

  const userId = crypto.randomUUID();
  const now = new Date().toISOString();
  const passwordHash = await hashPassword(password);

  const user: db.User = {
    id: userId,
    email: normalizedEmail,
    emailVerified: !authSettings.requireEmailVerification,
    displayName: displayName || normalizedEmail.split('@')[0],
    avatarUrl: null,
    passwordHash,
    role: 'user',
    createdAt: now,
    updatedAt: now,
    lastLogin: now,
    isActive: true,
    failedLoginAttempts: 0,
    lockedUntil: null,
    totpSecret: null,
    totpEnabled: false,
    totpBackupCodes: null,
    pendingEmail: null,
    pendingEmailToken: null
  };

  const { wasFirst: isFirstUser, promoted } = db.createUserAtomic(user);
  if (inviteHash && !db.consumeInvite(inviteHash, user.id)) {
    db.deleteUser(user.id);
    return { success: false, error: "Registration requires a valid invitation code" };
  }
  db.logAuthEvent('register', user.id, null, { role: user.role, isFirstUser, promoted });
  const needsApproval = !promoted && !options.bypassRegistrationGate && authSettings.authMode === 'approval';
  if (needsApproval) {
    user.isActive = false;
    db.updateUser(user);
    db.setPendingApproval(user.id, true);
  }

  if (!promoted && authSettings.requireEmailVerification && baseUrl) {
    const token = await createVerificationToken(userId);
    const verifyUrl = `${baseUrl}/auth/verify?token=${token}`;
    await mailer.sendVerificationEmail(normalizedEmail, user.displayName || 'User', verifyUrl);
    return { success: true, userId, requiresVerification: true, pendingApproval: needsApproval };
  }

  return { success: true, userId, pendingApproval: needsApproval };
}

export async function createAdminFromLegacy(
  email: string,
  password: string,
  displayName?: string
): Promise<{ success: boolean; userId?: string; error?: string }> {
  const result = await registerUser(email, password, displayName, undefined, null, {
    bypassRegistrationGate: true
  });
  if (!result.success || !result.userId) {
    return { success: false, error: result.error || "Migration failed" };
  }
  const user = db.getUserById(result.userId);
  if (!user) return { success: false, error: "Migration failed" };
  if (user.role !== 'admin' || !user.emailVerified) {
    user.role = 'admin';
    user.emailVerified = true;
    user.updatedAt = new Date().toISOString();
    db.updateUser(user);
  }
  db.logAuthEvent('admin_migrated', user.id, null, { from: 'legacy_admin_password_hash' });
  return { success: true, userId: user.id };
}


export function createInvite(
  createdBy: string | null,
  options: { email?: string | null; expiresInDays?: number | null } = {}
): { id: string; code: string; expiresAt: string | null } {
  const code = oidc.generateSecureToken(24);
  const id = crypto.randomUUID();
  const expiresAt = options.expiresInDays
    ? new Date(Date.now() + options.expiresInDays * 24 * 60 * 60 * 1000).toISOString()
    : null;
  db.createInvite({
    id,
    codeHash: oidc.hashTokenSync(code),
    email: options.email ? normalizeEmail(options.email) : null,
    createdBy,
    createdAt: new Date().toISOString(),
    expiresAt,
    usedAt: null,
    usedBy: null
  });
  return { id, code, expiresAt };
}

export function checkInviteCode(code: string | null, email: string): { valid: boolean; codeHash?: string } {
  if (!code || typeof code !== 'string') return { valid: false };
  const codeHash = oidc.hashTokenSync(code.trim());
  const invite = db.getInviteByHash(codeHash);
  if (!invite) return { valid: false };
  if (invite.usedAt) return { valid: false };
  if (invite.expiresAt && new Date(invite.expiresAt) < new Date()) return { valid: false };
  if (invite.email && invite.email !== normalizeEmail(email)) return { valid: false };
  return { valid: true, codeHash };
}

export function listInvites(): (Omit<db.Invite, 'codeHash'>)[] {
  return db.listInvites().map(({ codeHash, ...rest }) => rest);
}

export function revokeInvite(id: string): boolean {
  return db.deleteInvite(id);
}

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 15;

const GENERIC_LOGIN_ERROR = "Invalid email or password";
const loginThrottle = new Map<string, { count: number; lockedUntil: number; lastSeen: number }>();
const THROTTLE_MAX_ENTRIES = 50000;
const THROTTLE_IDLE_MS = LOCKOUT_DURATION_MINUTES * 60 * 1000;

function throttleKey(email: string, ip: string): string {
  return `${email}|${ip || 'unknown'}`;
}

function throttleLocked(key: string): boolean {
  const entry = loginThrottle.get(key);
  if (!entry) return false;
  if (entry.lockedUntil > Date.now()) return true;
  if (entry.lockedUntil) loginThrottle.delete(key);
  return false;
}

function throttleFail(key: string): number {
  const now = Date.now();
  const entry = loginThrottle.get(key) || { count: 0, lockedUntil: 0, lastSeen: now };
  entry.count += 1;
  entry.lastSeen = now;
  if (entry.count >= MAX_FAILED_ATTEMPTS) {
    entry.lockedUntil = now + LOCKOUT_DURATION_MINUTES * 60 * 1000;
    entry.count = 0;
  }
  loginThrottle.set(key, entry);
  if (loginThrottle.size > THROTTLE_MAX_ENTRIES) {
    for (const [k, v] of loginThrottle) {
      if (v.lockedUntil ? v.lockedUntil < now : now - v.lastSeen > THROTTLE_IDLE_MS) {
        loginThrottle.delete(k);
      }
    }
    if (loginThrottle.size > THROTTLE_MAX_ENTRIES) {
      const oldest = [...loginThrottle.entries()].sort((a, b) => a[1].lastSeen - b[1].lastSeen);
      for (let i = 0; i < oldest.length - THROTTLE_MAX_ENTRIES; i++) loginThrottle.delete(oldest[i][0]);
    }
  }
  return entry.count;
}

function throttleReset(key: string): void {
  loginThrottle.delete(key);
}

export const EMAIL_CEILING_MAX_FAILURES = 50;
export const EMAIL_CEILING_WINDOW_MS = 15 * 60 * 1000;
const EMAIL_CEILING_BUCKET_MS = EMAIL_CEILING_WINDOW_MS / 2;
const EMAIL_CEILING_MAX_ENTRIES = 20000;

interface EmailCeilingEntry { bucket: number; current: number; previous: number; }
const emailFailureWindow = new Map<string, EmailCeilingEntry>();

function currentBucket(now: number): number {
  return Math.floor(now / EMAIL_CEILING_BUCKET_MS);
}

function rollEntry(entry: EmailCeilingEntry, bucket: number): void {
  const delta = bucket - entry.bucket;
  if (delta <= 0) return;
  if (delta === 1) { entry.previous = entry.current; entry.current = 0; }
  else { entry.previous = 0; entry.current = 0; }
  entry.bucket = bucket;
}

function emailCeilingCount(entry: EmailCeilingEntry, now: number): number {
  const elapsed = (now % EMAIL_CEILING_BUCKET_MS) / EMAIL_CEILING_BUCKET_MS;
  return entry.current + entry.previous * (1 - elapsed);
}

function emailCeilingExceeded(email: string): boolean {
  const entry = emailFailureWindow.get(email);
  if (!entry) return false;
  const now = Date.now();
  rollEntry(entry, currentBucket(now));
  if (entry.current === 0 && entry.previous === 0) {
    emailFailureWindow.delete(email);
    return false;
  }
  return emailCeilingCount(entry, now) >= EMAIL_CEILING_MAX_FAILURES;
}

function emailCeilingFail(email: string): number {
  const now = Date.now();
  const bucket = currentBucket(now);
  let entry = emailFailureWindow.get(email);
  if (!entry) {
    entry = { bucket, current: 0, previous: 0 };
    emailFailureWindow.set(email, entry);
  } else {
    rollEntry(entry, bucket);
  }
  entry.current += 1;

  if (emailFailureWindow.size > EMAIL_CEILING_MAX_ENTRIES) {
    const stale = bucket - 1;
    for (const [k, v] of emailFailureWindow) {
      if (v.bucket < stale) emailFailureWindow.delete(k);
    }
    if (emailFailureWindow.size > EMAIL_CEILING_MAX_ENTRIES) {
      const oldest = [...emailFailureWindow.entries()].sort((a, b) => a[1].bucket - b[1].bucket);
      for (let i = 0; i < oldest.length - EMAIL_CEILING_MAX_ENTRIES; i++) {
        emailFailureWindow.delete(oldest[i][0]);
      }
    }
  }
  return Math.ceil(emailCeilingCount(entry, now));
}

function emailCeilingReset(email: string): void {
  emailFailureWindow.delete(email);
}

export function getEmailFailureCount(email: string): number {
  const entry = emailFailureWindow.get(normalizeEmail(email));
  if (!entry) return 0;
  const now = Date.now();
  rollEntry(entry, currentBucket(now));
  return Math.ceil(emailCeilingCount(entry, now));
}

export function resetLoginThrottle(): void {
  loginThrottle.clear();
  emailFailureWindow.clear();
}

export async function loginWithPassword(
  email: string,
  password: string,
  ipAddress: string,
  userAgent: string
): Promise<{ success: boolean; userId?: string; sessionToken?: string; error?: string; requires2FA?: boolean; pendingToken?: string }> {
  const normalizedEmail = normalizeEmail(email);
  const key = throttleKey(normalizedEmail, ipAddress);

  if (throttleLocked(key)) {
    return { success: false, error: GENERIC_LOGIN_ERROR };
  }

  if (emailCeilingExceeded(normalizedEmail)) {
    return { success: false, error: GENERIC_LOGIN_ERROR };
  }

  const fail = (): void => { throttleFail(key); emailCeilingFail(normalizedEmail); };

  const user = db.getUserByEmail(normalizedEmail);
  if (!user) {
    fail();
    return { success: false, error: GENERIC_LOGIN_ERROR };
  }

  if (!user.isActive) {
    if (db.isPendingApproval(user.id) && user.passwordHash && await verifyPassword(password, user.passwordHash)) {
      return { success: false, error: "Your account is waiting for administrator approval." };
    }
    fail();
    return { success: false, error: GENERIC_LOGIN_ERROR };
  }

  if (user.lockedUntil) {
    const lockExpiry = new Date(user.lockedUntil);
    if (lockExpiry > new Date()) {
      return { success: false, error: GENERIC_LOGIN_ERROR };
    }
    db.resetFailedLogin(user.id);
  }

  if (!user.passwordHash) {
    fail();
    return { success: false, error: GENERIC_LOGIN_ERROR };
  }

  const valid = await verifyPassword(password, user.passwordHash);
  if (!valid) {
    db.incrementFailedLogin(user.id);
    const attempts = throttleFail(key);
    const globalFailures = emailCeilingFail(normalizedEmail);
    if (globalFailures >= EMAIL_CEILING_MAX_FAILURES) {
      db.logAuthEvent('account_locked', user.id, ipAddress, {
        reason: 'email_failure_ceiling', scope: 'email-global', failures: globalFailures,
        windowMinutes: EMAIL_CEILING_WINDOW_MS / 60000
      });
    }
    if (attempts === 0) {
      db.logAuthEvent('account_locked', user.id, ipAddress, { reason: 'too_many_failed_attempts', scope: 'email+ip' });
    } else {
      db.logAuthEvent('login_failed', user.id, ipAddress, { reason: 'invalid_password', attempts });
    }
    return { success: false, error: GENERIC_LOGIN_ERROR };
  }

  if (oidc.getAuthSettings().authMode === 'oidc_only' && user.role !== 'admin') {
    return { success: false, error: "Password sign in is disabled. Please use single sign on." };
  }

  throttleReset(key);
  emailCeilingReset(normalizedEmail);
  db.resetFailedLogin(user.id);

  if (isLegacyHash(user.passwordHash)) {
    await upgradePasswordHash(user.id, password);
  }

  const authSettings = oidc.getAuthSettings();
  if (authSettings.requireEmailVerification && !user.emailVerified) {
    return { success: false, error: "Please verify your email first" };
  }

  if (user.totpEnabled) {
    const pendingToken = oidc.generateSecureToken(32);
    const tokenHash = await oidc.hashToken(pendingToken);
    db.deleteUserTokensByType(user.id, 'totp_pending');
    db.createUserToken({
      id: crypto.randomUUID(),
      userId: user.id,
      type: 'totp_pending',
      tokenHash,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
      usedAt: null,
      createdAt: new Date().toISOString()
    });
    return { success: false, requires2FA: true, pendingToken, error: undefined };
  }

  user.lastLogin = new Date().toISOString();
  user.updatedAt = new Date().toISOString();
  user.failedLoginAttempts = 0;
  user.lockedUntil = null;
  db.updateUser(user);

  const sessionToken = await createSessionToken(user.id, ipAddress, userAgent);

  db.logAuthEvent('login_success', user.id, ipAddress, { method: 'password' });

  return { success: true, userId: user.id, sessionToken };
}

const MAX_SESSIONS_PER_USER = 10;

async function createSessionToken(
  userId: string,
  ipAddress: string,
  userAgent: string
): Promise<string> {
  const token = oidc.generateSecureToken(32);
  const tokenHash = await oidc.hashToken(token);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

  const existing = db.getSessionsByUserId(userId);
  if (existing.length >= MAX_SESSIONS_PER_USER) {
    const oldest = existing.slice(MAX_SESSIONS_PER_USER - 1);
    for (const s of oldest) db.deleteSession(s.id);
  }

  db.createUserSession({
    id: crypto.randomUUID(),
    userId,
    tokenHash,
    ipAddress,
    userAgent: userAgent?.substring(0, 500) || null,
    expiresAt: expiresAt.toISOString(),
    createdAt: now.toISOString()
  });

  return token;
}

export async function rotateSessionToken(
  oldToken: string,
  ipAddress: string,
  userAgent: string
): Promise<{ success: boolean; newToken?: string; error?: string }> {
  const tokenHash = await oidc.hashToken(oldToken);
  const session = db.getUserSessionByTokenHash(tokenHash);

  if (!session) {
    return { success: false, error: "Invalid session" };
  }

  if (new Date(session.expiresAt) < new Date()) {
    db.deleteUserSession(session.id);
    return { success: false, error: "Session expired" };
  }

  db.deleteUserSession(session.id);

  const newToken = await createSessionToken(session.userId, ipAddress, userAgent);
  return { success: true, newToken };
}

async function createVerificationToken(userId: string): Promise<string> {
  db.deleteUserTokensByType(userId, 'email_verify');

  const token = oidc.generateSecureToken(32);
  const tokenHash = await oidc.hashToken(token);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000);

  db.createUserToken({
    id: crypto.randomUUID(),
    userId,
    type: 'email_verify',
    tokenHash,
    expiresAt: expiresAt.toISOString(),
    usedAt: null,
    createdAt: now.toISOString()
  });

  return token;
}

export async function verifyEmail(token: string): Promise<{ success: boolean; error?: string }> {
  const tokenHash = await oidc.hashToken(token);
  const userToken = db.getUserTokenByHash(tokenHash);

  if (!userToken) {
    return { success: false, error: "Invalid or expired token" };
  }

  if (userToken.type !== 'email_verify') {
    return { success: false, error: "Invalid token type" };
  }

  if (userToken.usedAt) {
    return { success: false, error: "Token already used" };
  }

  if (new Date(userToken.expiresAt) < new Date()) {
    return { success: false, error: "Token expired" };
  }

  const user = db.getUserById(userToken.userId);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  user.emailVerified = true;
  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  db.markUserTokenUsed(userToken.id);

  return { success: true };
}

const MIN_REQUEST_TIME_MS = 200;

async function normalizeResponseTime(startTime: number): Promise<void> {
  const elapsed = Date.now() - startTime;
  if (elapsed < MIN_REQUEST_TIME_MS) {
    await new Promise(r => setTimeout(r, MIN_REQUEST_TIME_MS - elapsed));
  }
}

export async function requestPasswordReset(
  email: string,
  baseUrl: string
): Promise<{ success: boolean; error?: string }> {
  const startTime = Date.now();
  const user = db.getUserByEmail(normalizeEmail(email));

  if (!user || !user.isActive) {
    await normalizeResponseTime(startTime);
    return { success: true };
  }

  db.deleteUserTokensByType(user.id, 'password_reset');

  const token = oidc.generateSecureToken(32);
  const tokenHash = await oidc.hashToken(token);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 60 * 60 * 1000);

  db.createUserToken({
    id: crypto.randomUUID(),
    userId: user.id,
    type: 'password_reset',
    tokenHash,
    expiresAt: expiresAt.toISOString(),
    usedAt: null,
    createdAt: now.toISOString()
  });

  const resetUrl = `${baseUrl}/auth/reset-password?token=${token}`;
  await mailer.sendPasswordResetEmail(user.email!, user.displayName || 'User', resetUrl);

  await normalizeResponseTime(startTime);
  return { success: true };
}

export async function resetPassword(
  token: string,
  newPassword: string
): Promise<{ success: boolean; error?: string }> {
  const passwordValidation = validatePassword(newPassword);
  if (!passwordValidation.valid) {
    return { success: false, error: passwordValidation.error };
  }

  const tokenHash = await oidc.hashToken(token);
  const userToken = db.getUserTokenByHash(tokenHash);

  if (!userToken) {
    return { success: false, error: "Invalid or expired token" };
  }

  if (userToken.type !== 'password_reset') {
    return { success: false, error: "Invalid token type" };
  }

  if (userToken.usedAt) {
    return { success: false, error: "Token already used" };
  }

  if (new Date(userToken.expiresAt) < new Date()) {
    return { success: false, error: "Token expired" };
  }

  const user = db.getUserById(userToken.userId);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  if (!user.isActive) {
    db.markUserTokenUsed(userToken.id);
    return { success: false, error: "Invalid or expired token" };
  }

  user.passwordHash = await hashPassword(newPassword);
  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  db.markUserTokenUsed(userToken.id);

  db.deleteAllUserSessions(user.id);

  return { success: true };
}

export async function requestMagicLink(
  email: string,
  baseUrl: string
): Promise<{ success: boolean; error?: string }> {
  const startTime = Date.now();
  const authSettings = oidc.getAuthSettings();
  if (!authSettings.allowMagicLinkLogin) {
    return { success: false, error: "Magic link login is disabled" };
  }

  const user = db.getUserByEmail(normalizeEmail(email));
  if (!user || !user.isActive) {
    await normalizeResponseTime(startTime);
    return { success: true };
  }

  db.deleteUserTokensByType(user.id, 'magic_link');

  const token = oidc.generateSecureToken(32);
  const tokenHash = await oidc.hashToken(token);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 15 * 60 * 1000);

  db.createUserToken({
    id: crypto.randomUUID(),
    userId: user.id,
    type: 'magic_link',
    tokenHash,
    expiresAt: expiresAt.toISOString(),
    usedAt: null,
    createdAt: now.toISOString()
  });

  const loginUrl = `${baseUrl}/auth/magic-link?token=${token}`;
  await mailer.sendMagicLinkEmail(user.email!, user.displayName || 'User', loginUrl);

  await normalizeResponseTime(startTime);
  return { success: true };
}

export async function loginWithMagicLink(
  token: string,
  ipAddress: string,
  userAgent: string
): Promise<{ success: boolean; userId?: string; sessionToken?: string; error?: string }> {
  const tokenHash = await oidc.hashToken(token);
  const userToken = db.getUserTokenByHash(tokenHash);

  if (!userToken) {
    return { success: false, error: "Invalid or expired link" };
  }

  if (userToken.type !== 'magic_link') {
    return { success: false, error: "Invalid link type" };
  }

  if (userToken.usedAt) {
    return { success: false, error: "Link already used" };
  }

  if (new Date(userToken.expiresAt) < new Date()) {
    return { success: false, error: "Link expired" };
  }

  const user = db.getUserById(userToken.userId);
  if (!user || !user.isActive) {
    return { success: false, error: "User not found" };
  }

  db.markUserTokenUsed(userToken.id);

  user.lastLogin = new Date().toISOString();
  user.updatedAt = new Date().toISOString();
  user.emailVerified = true;
  db.updateUser(user);

  const sessionToken = await createSessionToken(user.id, ipAddress, userAgent);

  return { success: true, userId: user.id, sessionToken };
}

export async function logout(token: string): Promise<void> {
  const tokenHash = await oidc.hashToken(token);
  db.deleteSessionByTokenHash(tokenHash);
}

export function logoutAll(userId: string): number {
  return db.deleteAllUserSessions(userId);
}

export async function changePassword(
  userId: string,
  currentPassword: string,
  newPassword: string,
  currentSessionToken?: string
): Promise<{ success: boolean; error?: string }> {
  const user = db.getUserById(userId);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  if (!user.passwordHash) {
    return { success: false, error: "Account uses SSO only" };
  }

  const valid = await verifyPassword(currentPassword, user.passwordHash);
  if (!valid) {
    return { success: false, error: "Current password is incorrect" };
  }

  const passwordValidation = validatePassword(newPassword);
  if (!passwordValidation.valid) {
    return { success: false, error: passwordValidation.error };
  }

  user.passwordHash = await hashPassword(newPassword);
  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  db.deleteAllUserSessions(userId);

  return { success: true };
}

export function updateProfile(
  userId: string,
  updates: { displayName?: string; avatarUrl?: string }
): { success: boolean; error?: string } {
  const user = db.getUserById(userId);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  if (updates.displayName !== undefined) {
    if (typeof updates.displayName !== 'string') return { success: false, error: "Invalid display name" };
    const name = updates.displayName.replace(/[\u0000-\u001f\u007f<>]/g, '').trim().substring(0, 100);
    if (!name) return { success: false, error: "Display name cannot be empty" };
    user.displayName = name;
  }
  if (updates.avatarUrl !== undefined) {
    if (typeof updates.avatarUrl !== 'string') return { success: false, error: "Invalid avatar URL" };
    const url = updates.avatarUrl.trim();
    if (url) {
      let ok = false;
      try { const u = new URL(url); ok = (u.protocol === 'https:' || u.protocol === 'http:') && url.length <= 500; } catch { ok = false; }
      if (!ok) return { success: false, error: "Avatar URL must be an http(s) URL" };
    }
    user.avatarUrl = url;
  }

  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  return { success: true };
}

export function deleteAccount(userId: string): { success: boolean; error?: string } {
  const user = db.getUserById(userId);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  if (user.role === 'admin') {
    const adminCount = db.countUsersByRole('admin');
    if (adminCount <= 1) {
      return { success: false, error: "Cannot delete the last admin" };
    }
  }

  db.deleteUser(userId);

  return { success: true };
}

export interface ParsedSession extends Omit<db.UserSession, 'tokenHash'> {
  current: boolean;
  browser: string;
  os: string;
  device: string;
  location: string;
}

function parseUserAgent(ua: string | null): { browser: string; os: string; device: string } {
  if (!ua) return { browser: 'Unknown', os: 'Unknown', device: 'Unknown' };

  let browser = 'Unknown';
  let os = 'Unknown';
  let device = 'Desktop';

  if (ua.includes('Mobile') || ua.includes('Android')) device = 'Mobile';
  else if (ua.includes('Tablet') || ua.includes('iPad')) device = 'Tablet';

  if (ua.includes('Firefox/')) browser = 'Firefox';
  else if (ua.includes('Edg/')) browser = 'Edge';
  else if (ua.includes('Chrome/')) browser = 'Chrome';
  else if (ua.includes('Safari/') && !ua.includes('Chrome')) browser = 'Safari';
  else if (ua.includes('Opera') || ua.includes('OPR/')) browser = 'Opera';

  if (ua.includes('Windows')) os = 'Windows';
  else if (ua.includes('Mac OS X') || ua.includes('macOS')) os = 'macOS';
  else if (ua.includes('Linux') && !ua.includes('Android')) os = 'Linux';
  else if (ua.includes('Android')) os = 'Android';
  else if (ua.includes('iOS') || ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';

  return { browser, os, device };
}

function formatIPLocation(ip: string | null): string {
  if (!ip || ip === 'unknown') return 'Unknown location';
  if (ip.startsWith('127.') || ip === '::1') return 'Localhost';
  if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) return 'Local network';
  return ip;
}

export function getUserSessions(userId: string, currentTokenHash?: string): ParsedSession[] {
  const sessions = db.getSessionsByUserId(userId);
  return sessions.map(session => {
    const parsed = parseUserAgent(session.userAgent);
    const { tokenHash: _omit, ...rest } = session as any;
    return {
      ...rest,
      current: !!currentTokenHash && session.tokenHash === currentTokenHash,
      browser: parsed.browser,
      os: parsed.os,
      device: parsed.device,
      location: formatIPLocation(session.ipAddress)
    };
  });
}

export function getUserOidcLinks(userId: string): db.UserOidcLink[] {
  return db.getOidcLinksByUser(userId);
}

export function unlinkOidcProvider(userId: string, linkId: string): { success: boolean; error?: string } {
  const links = db.getOidcLinksByUser(userId);
  const link = links.find(l => l.id === linkId);

  if (!link) {
    return { success: false, error: "Link not found" };
  }

  const user = db.getUserById(userId);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  if (!user.passwordHash && links.length <= 1) {
    return { success: false, error: "Cannot unlink last login method" };
  }

  db.deleteOidcLink(linkId);
  return { success: true };
}

export async function adminCreateUser(
  email: string,
  password: string | null,
  displayName: string | null,
  role: 'admin' | 'user'
): Promise<{ success: boolean; userId?: string; error?: string }> {
  const normalizedEmail = normalizeEmail(email || "");
  const emailValidation = validateEmail(normalizedEmail);
  if (!emailValidation.valid) {
    return { success: false, error: emailValidation.error };
  }

  if (!isValidRole(role)) {
    return { success: false, error: "Invalid role" };
  }

  if (password) {
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return { success: false, error: passwordValidation.error };
    }
  }

  const existing = db.getUserByEmail(normalizedEmail);
  if (existing) {
    return { success: false, error: "Registration failed. Please try again or use a different email." };
  }

  const userId = crypto.randomUUID();
  const now = new Date().toISOString();
  const sanitizedDisplayName = displayName ? displayName.substring(0, 100) : normalizedEmail.split('@')[0];

  const user: db.User = {
    id: userId,
    email: normalizedEmail,
    emailVerified: true,
    displayName: sanitizedDisplayName,
    avatarUrl: null,
    passwordHash: password ? await hashPassword(password) : null,
    role,
    createdAt: now,
    updatedAt: now,
    lastLogin: null,
    isActive: true,
    failedLoginAttempts: 0,
    lockedUntil: null,
    totpSecret: null,
    totpEnabled: false,
    totpBackupCodes: null,
    pendingEmail: null,
    pendingEmailToken: null
  };

  db.createUser(user);

  return { success: true, userId };
}

export const ASSIGNABLE_ROLES = ['admin', 'user'] as const;

export function isValidRole(role: any): role is 'admin' | 'user' {
  return typeof role === 'string' && (ASSIGNABLE_ROLES as readonly string[]).includes(role);
}

export function adminUpdateUser(
  userId: string,
  updates: {
    displayName?: string;
    role?: 'admin' | 'user';
    isActive?: boolean;
    emailVerified?: boolean;
  }
): { success: boolean; error?: string } {
  const user = db.getUserById(userId);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  if (updates.role !== undefined && !isValidRole(updates.role)) {
    return { success: false, error: "Invalid role" };
  }
  if (updates.displayName !== undefined && typeof updates.displayName !== 'string') {
    return { success: false, error: "Invalid display name" };
  }
  if (updates.isActive !== undefined && typeof updates.isActive !== 'boolean') {
    return { success: false, error: "Invalid isActive value" };
  }
  if (updates.emailVerified !== undefined && typeof updates.emailVerified !== 'boolean') {
    return { success: false, error: "Invalid emailVerified value" };
  }

  if (updates.role === 'user' && user.role === 'admin') {
    const adminCount = db.countUsersByRole('admin');
    if (adminCount <= 1) {
      return { success: false, error: "Cannot demote the last admin" };
    }
  }

  if (updates.isActive === false && user.role === 'admin') {
    const adminCount = db.countUsersByRole('admin');
    if (adminCount <= 1) {
      return { success: false, error: "Cannot disable the last admin" };
    }
  }

  const roleChanged = updates.role !== undefined && updates.role !== user.role;

  if (updates.displayName !== undefined) user.displayName = updates.displayName.substring(0, 100);
  if (updates.role !== undefined) user.role = updates.role;
  if (updates.isActive !== undefined) user.isActive = updates.isActive;
  if (updates.emailVerified !== undefined) user.emailVerified = updates.emailVerified;

  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  if (roleChanged || updates.isActive === false) {
    db.deleteAllUserSessions(userId);
    db.logAuthEvent('sessions_revoked', userId, null, { reason: roleChanged ? 'role_change' : 'deactivated' });
  }

  return { success: true };
}

export async function adminResetPassword(
  userId: string,
  newPassword: string
): Promise<{ success: boolean; error?: string }> {
  const user = db.getUserById(userId);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  const passwordValidation = validatePassword(newPassword);
  if (!passwordValidation.valid) {
    return { success: false, error: passwordValidation.error };
  }

  user.passwordHash = await hashPassword(newPassword);
  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  db.deleteAllUserSessions(userId);

  return { success: true };
}

export function adminDeleteUser(userId: string): { success: boolean; error?: string } {
  return deleteAccount(userId);
}

export function cleanupExpiredTokens(): { sessions: number; tokens: number } {
  return {
    sessions: db.cleanupExpiredSessions(),
    tokens: db.cleanupExpiredUserTokens()
  };
}

function base32Encode(buffer: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let result = '';
  let bits = 0;
  let value = 0;
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    result += alphabet[(value << (5 - bits)) & 31];
  }
  return result;
}

function base32Decode(encoded: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleanInput = encoded.toUpperCase().replace(/=+$/, '');
  const result: number[] = [];
  let bits = 0;
  let value = 0;
  for (const char of cleanInput) {
    const index = alphabet.indexOf(char);
    if (index === -1) continue;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      result.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(result);
}

function generateTOTPCode(secret: Uint8Array, counter: number): string {
  const buffer = Buffer.alloc(8);
  buffer.writeUInt32BE(0, 0);
  buffer.writeUInt32BE(counter, 4);

  const hmac = createHmac('sha1', Buffer.from(secret));
  hmac.update(buffer);
  const hash = hmac.digest();

  const offset = hash[hash.length - 1] & 0x0f;
  const code = ((hash[offset] & 0x7f) << 24) |
               ((hash[offset + 1] & 0xff) << 16) |
               ((hash[offset + 2] & 0xff) << 8) |
               (hash[offset + 3] & 0xff);

  return (code % Math.pow(10, 6)).toString().padStart(6, '0');
}

export function verifyTOTPCodeStep(secret: string, code: string): number | null {
  const secretBytes = base32Decode(secret);
  const timeStep = Math.floor(Date.now() / 1000 / 30);

  let matched: number | null = null;
  for (let i = -1; i <= 1; i++) {
    if (timingSafeEqualStr(generateTOTPCode(secretBytes, timeStep + i), code)) {
      matched = timeStep + i;
    }
  }
  return matched;
}

export function verifyTOTPCode(secret: string, code: string): boolean {
  return verifyTOTPCodeStep(secret, code) !== null;
}

const HASHED_BACKUP_CODES_PREFIX = 'h1:';

function hashBackupCode(code: string): string {
  return oidc.hashTokenSync(code.toLowerCase().trim());
}

export function serializeHashedBackupCodes(codes: string[]): string {
  return HASHED_BACKUP_CODES_PREFIX + JSON.stringify(codes.map(hashBackupCode));
}

export async function setupTOTP(userId: string): Promise<{ success: boolean; secret?: string; otpauthUrl?: string; error?: string }> {
  const user = db.getUserById(userId);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  if (user.totpEnabled) {
    return { success: false, error: "2FA is already enabled" };
  }

  const secretBytes = randomBytes(20);
  const base32secret = base32Encode(new Uint8Array(secretBytes));

  const encryptedSecret = await oidc.encryptSecret(base32secret);
  user.totpSecret = encryptedSecret;
  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  const otpauthUrl = `otpauth://totp/TheOneFileVerse:${user.email}?secret=${base32secret}&issuer=TheOneFileVerse&algorithm=SHA1&digits=6&period=30`;

  db.logAuthEvent('totp_setup_started', userId, null, {});

  return { success: true, secret: base32secret, otpauthUrl };
}

export async function verifyAndEnableTOTP(
  userId: string,
  code: string,
  session?: { token: string; ipAddress: string; userAgent: string }
): Promise<{ success: boolean; backupCodes?: string[]; newSessionToken?: string; error?: string }> {
  const user = db.getUserById(userId);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  if (user.totpEnabled) {
    return { success: false, error: "2FA is already enabled" };
  }

  if (!user.totpSecret) {
    return { success: false, error: "2FA setup not started" };
  }

  const decryptedSecret = await oidc.decryptSecret(user.totpSecret);

  const matchedStep = verifyTOTPCodeStep(decryptedSecret, code);
  if (matchedStep === null) {
    return { success: false, error: "Invalid verification code" };
  }
  user.totpLastStep = matchedStep;

  const backupCodes: string[] = [];
  for (let i = 0; i < 10; i++) {
    backupCodes.push(randomBytes(8).toString('hex'));
  }

  user.totpEnabled = true;
  user.totpBackupCodes = serializeHashedBackupCodes(backupCodes);
  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  db.logAuthEvent('totp_enabled', userId, null, {});

  let newSessionToken: string | undefined;
  if (session?.token) {
    const rotated = await rotateSessionToken(session.token, session.ipAddress, session.userAgent);
    if (rotated.success) newSessionToken = rotated.newToken;
  }

  return { success: true, backupCodes, newSessionToken };
}

export async function disableTOTP(userId: string, password: string): Promise<{ success: boolean; error?: string }> {
  const user = db.getUserById(userId);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  if (!user.totpEnabled) {
    return { success: false, error: "2FA is not enabled" };
  }

  if (!user.passwordHash) {
    return { success: false, error: "Account uses SSO only" };
  }

  const valid = await verifyPassword(password, user.passwordHash);
  if (!valid) {
    return { success: false, error: "Invalid password" };
  }

  user.totpSecret = null;
  user.totpEnabled = false;
  user.totpBackupCodes = null;
  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  db.logAuthEvent('totp_disabled', userId, null, {});

  return { success: true };
}

export async function verifyBackupCode(userId: string, code: string): Promise<boolean> {
  const user = db.getUserById(userId);
  if (!user || !user.totpBackupCodes) {
    return false;
  }

  let hashes: string[];
  const stored = user.totpBackupCodes;
  if (stored.startsWith(HASHED_BACKUP_CODES_PREFIX)) {
    try {
      hashes = JSON.parse(stored.slice(HASHED_BACKUP_CODES_PREFIX.length));
    } catch { return false; }
  } else {
    try {
      const decrypted = await oidc.decryptSecret(stored);
      hashes = (JSON.parse(decrypted) as string[]).map(hashBackupCode);
    } catch {
      return false;
    }
  }

  const candidate = hashBackupCode(code);
  let index = -1;
  for (let i = 0; i < hashes.length; i++) {
    if (timingSafeEqualStr(hashes[i], candidate)) {
      index = i;
    }
  }
  if (index === -1) {
    if (!stored.startsWith(HASHED_BACKUP_CODES_PREFIX)) {
      user.totpBackupCodes = HASHED_BACKUP_CODES_PREFIX + JSON.stringify(hashes);
      user.updatedAt = new Date().toISOString();
      db.updateUser(user);
    }
    return false;
  }

  hashes.splice(index, 1);
  user.totpBackupCodes = HASHED_BACKUP_CODES_PREFIX + JSON.stringify(hashes);
  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  db.logAuthEvent('backup_code_used', userId, null, { remainingCodes: hashes.length });

  return true;
}

export async function loginWith2FA(
  pendingToken: string,
  totpCode: string,
  ipAddress: string,
  userAgent: string
): Promise<{ success: boolean; userId?: string; sessionToken?: string; error?: string }> {
  const tokenHash = await oidc.hashToken(pendingToken);
  const userToken = db.getUserTokenByHash(tokenHash);

  if (!userToken) {
    return { success: false, error: "Invalid or expired 2FA session" };
  }

  if (userToken.type !== 'totp_pending') {
    return { success: false, error: "Invalid token type" };
  }

  if (userToken.usedAt) {
    return { success: false, error: "Token already used" };
  }

  if (new Date(userToken.expiresAt) < new Date()) {
    db.deleteUserToken(userToken.id);
    return { success: false, error: "2FA session expired" };
  }

  if (userToken.failedAttempts >= 3) {
    db.deleteUserToken(userToken.id);
    return { success: false, error: "Too many failed attempts. Please log in again." };
  }

  const user = db.getUserById(userToken.userId);
  if (!user || !user.isActive) {
    return { success: false, error: "User not found" };
  }

  if (!user.totpSecret) {
    return { success: false, error: "2FA is not configured" };
  }

  const decryptedSecret = await oidc.decryptSecret(user.totpSecret);
  const matchedStep = verifyTOTPCodeStep(decryptedSecret, totpCode);
  const lastStep = user.totpLastStep ?? null;
  let codeValid = matchedStep !== null && (lastStep === null || matchedStep > lastStep);
  let usedStep: number | null = codeValid ? matchedStep : null;

  if (!codeValid) {
    codeValid = await verifyBackupCode(user.id, totpCode);
    usedStep = null;
  }

  if (!codeValid) {
    const attempts = db.incrementTokenFailedAttempts(userToken.id);
    db.logAuthEvent('login_failed', user.id, ipAddress, { reason: 'invalid_2fa_code', attempts });
    if (attempts >= 3) {
      db.deleteUserToken(userToken.id);
      return { success: false, error: "Too many failed attempts. Please log in again." };
    }
    return { success: false, error: "Invalid 2FA code" };
  }

  db.markUserTokenUsed(userToken.id);

  const fresh = db.getUserById(user.id) || user;
  fresh.lastLogin = new Date().toISOString();
  fresh.updatedAt = new Date().toISOString();
  fresh.failedLoginAttempts = 0;
  fresh.lockedUntil = null;
  if (usedStep !== null) fresh.totpLastStep = usedStep;
  db.updateUser(fresh);

  const sessionToken = await createSessionToken(user.id, ipAddress, userAgent);

  db.logAuthEvent('login_success', user.id, ipAddress, { method: 'password_2fa' });

  return { success: true, userId: user.id, sessionToken };
}

export async function requestEmailChange(
  userId: string,
  newEmail: string,
  password: string,
  baseUrl: string
): Promise<{ success: boolean; error?: string }> {
  const user = db.getUserById(userId);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  const emailValidation = validateEmail(newEmail);
  if (!emailValidation.valid) {
    return { success: false, error: emailValidation.error };
  }

  if (!user.passwordHash) {
    return { success: false, error: "Account uses SSO only" };
  }

  const valid = await verifyPassword(password, user.passwordHash);
  if (!valid) {
    return { success: false, error: "Invalid password" };
  }

  const normalizedNewEmail = newEmail.toLowerCase().trim();
  const existing = db.getUserByEmail(normalizedNewEmail);
  if (existing) {
    return { success: false, error: "Email is already in use" };
  }

  const token = oidc.generateSecureToken(32);
  const tokenHash = await oidc.hashToken(token);

  db.deleteUserTokensByType(user.id, 'email_change');

  db.createUserToken({
    id: crypto.randomUUID(),
    userId: user.id,
    type: 'email_change',
    tokenHash,
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    usedAt: null,
    createdAt: new Date().toISOString()
  });

  user.pendingEmail = normalizedNewEmail;
  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  const verifyUrl = `${baseUrl}/auth/verify-email-change?token=${token}`;
  const sent = await mailer.sendVerificationEmail(normalizedNewEmail, user.displayName || 'User', verifyUrl);
  if (!sent || !sent.success) {
    db.deleteUserTokensByType(user.id, 'email_change');
    user.pendingEmail = null;
    db.updateUser(user);
    return { success: false, error: "Could not send the verification email. Email delivery may not be configured." };
  }

  db.logAuthEvent('email_change_requested', userId, null, { newEmail: normalizedNewEmail });

  return { success: true };
}

export async function confirmEmailChange(token: string): Promise<{ success: boolean; error?: string }> {
  const tokenHash = await oidc.hashToken(token);
  const userToken = db.getUserTokenByHash(tokenHash);

  if (!userToken) {
    return { success: false, error: "Invalid or expired token" };
  }

  if (userToken.type !== 'email_change') {
    return { success: false, error: "Invalid token type" };
  }

  if (userToken.usedAt) {
    return { success: false, error: "Token already used" };
  }

  if (new Date(userToken.expiresAt) < new Date()) {
    return { success: false, error: "Token expired" };
  }

  const user = db.getUserById(userToken.userId);
  if (!user) {
    return { success: false, error: "User not found" };
  }

  if (!user.pendingEmail) {
    return { success: false, error: "No email change pending" };
  }

  const existing = db.getUserByEmail(user.pendingEmail);
  if (existing) {
    return { success: false, error: "Email is already in use" };
  }

  const oldEmail = user.email;
  user.email = user.pendingEmail;
  user.pendingEmail = null;
  user.pendingEmailToken = null;
  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  db.markUserTokenUsed(userToken.id);

  db.logAuthEvent('email_changed', user.id, null, { oldEmail, newEmail: user.email });

  return { success: true };
}

setInterval(() => {
  cleanupExpiredTokens();
}, 60 * 60 * 1000);
