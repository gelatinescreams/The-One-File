import * as db from "./database";
import * as oidc from "./oidc";
import * as mailer from "./mailer";
import { createHmac, randomBytes } from "crypto";

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
  baseUrl?: string
): Promise<{ success: boolean; userId?: string; error?: string; requiresVerification?: boolean }> {
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
  if (authSettings.authMode === 'closed') {
    return { success: false, error: "Registration is closed" };
  }
  if (authSettings.authMode === 'invite_only') {
    return { success: false, error: "Registration requires an invitation" };
  }
  if (authSettings.authMode === 'oidc_only') {
    return { success: false, error: "Please use SSO to register" };
  }

  const userId = crypto.randomUUID();
  const now = new Date().toISOString();
  const passwordHash = await hashPassword(password);

  const userCount = db.countUsers();
  const isFirstUser = userCount === 0;
  const role = isFirstUser ? 'admin' : 'user';

  const user: db.User = {
    id: userId,
    email: normalizedEmail,
    emailVerified: isFirstUser || !authSettings.requireEmailVerification,
    displayName: displayName || normalizedEmail.split('@')[0],
    avatarUrl: null,
    passwordHash,
    role,
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

  db.createUser(user);
  db.logAuthEvent('register', userId, null, { role, isFirstUser });

  if (!isFirstUser && authSettings.requireEmailVerification && baseUrl) {
    const token = await createVerificationToken(userId);
    const verifyUrl = `${baseUrl}/auth/verify?token=${token}`;
    await mailer.sendVerificationEmail(normalizedEmail, user.displayName || 'User', verifyUrl);
    return { success: true, userId, requiresVerification: true };
  }

  return { success: true, userId };
}

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 15;

export async function loginWithPassword(
  email: string,
  password: string,
  ipAddress: string,
  userAgent: string
): Promise<{ success: boolean; userId?: string; sessionToken?: string; error?: string; requires2FA?: boolean; pendingToken?: string }> {
  const normalizedEmail = normalizeEmail(email);
  const user = db.getUserByEmail(normalizedEmail);
  if (!user) {
    return { success: false, error: "Invalid email or password" };
  }

  if (!user.isActive) {
    return { success: false, error: "Invalid email or password" };
  }

  if (user.lockedUntil) {
    const lockExpiry = new Date(user.lockedUntil);
    if (lockExpiry > new Date()) {
      const remainingMinutes = Math.ceil((lockExpiry.getTime() - Date.now()) / 60000);
      return { success: false, error: `Account is temporarily locked. Try again in ${remainingMinutes} minute${remainingMinutes !== 1 ? 's' : ''}.` };
    }
    db.resetFailedLogin(user.id);
  }

  if (!user.passwordHash) {
    return { success: false, error: "Please use SSO to login" };
  }

  const valid = await verifyPassword(password, user.passwordHash);
  if (!valid) {
    db.incrementFailedLogin(user.id);
    const updatedUser = db.getUserById(user.id);
    if (updatedUser && updatedUser.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
      const lockUntil = new Date(Date.now() + LOCKOUT_DURATION_MINUTES * 60 * 1000);
      db.lockUserAccount(user.id, lockUntil);
      db.logAuthEvent('account_locked', user.id, ipAddress, { reason: 'too_many_failed_attempts' });
      return { success: false, error: `Too many failed attempts. Account locked for ${LOCKOUT_DURATION_MINUTES} minutes.` };
    }
    db.logAuthEvent('login_failed', user.id, ipAddress, { reason: 'invalid_password', attempts: updatedUser?.failedLoginAttempts });
    const attemptsRemaining = MAX_FAILED_ATTEMPTS - (updatedUser?.failedLoginAttempts || 0);
    if (attemptsRemaining <= 2 && attemptsRemaining > 0) {
      return { success: false, error: `Invalid email or password. ${attemptsRemaining} attempt${attemptsRemaining !== 1 ? 's' : ''} remaining.` };
    }
    return { success: false, error: "Invalid email or password" };
  }

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

async function createSessionToken(
  userId: string,
  ipAddress: string,
  userAgent: string
): Promise<string> {
  const token = oidc.generateSecureToken(32);
  const tokenHash = await oidc.hashToken(token);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

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
  const user = db.getUserByEmail(email);

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

  const user = db.getUserByEmail(email);
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
    user.displayName = updates.displayName.substring(0, 100);
  }
  if (updates.avatarUrl !== undefined) {
    if (typeof updates.avatarUrl !== 'string') return { success: false, error: "Invalid avatar URL" };
    user.avatarUrl = updates.avatarUrl.substring(0, 500);
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

export interface ParsedSession extends db.UserSession {
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

export function getUserSessions(userId: string): ParsedSession[] {
  const sessions = db.getSessionsByUserId(userId);
  return sessions.map(session => {
    const parsed = parseUserAgent(session.userAgent);
    return {
      ...session,
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
  const emailValidation = validateEmail(email);
  if (!emailValidation.valid) {
    return { success: false, error: emailValidation.error };
  }

  if (password) {
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return { success: false, error: passwordValidation.error };
    }
  }

  const existing = db.getUserByEmail(email);
  if (existing) {
    return { success: false, error: "Registration failed. Please try again or use a different email." };
  }

  const userId = crypto.randomUUID();
  const now = new Date().toISOString();
  const sanitizedDisplayName = displayName ? displayName.substring(0, 100) : email.split('@')[0];

  const user: db.User = {
    id: userId,
    email,
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

  if (updates.displayName !== undefined) user.displayName = updates.displayName.substring(0, 100);
  if (updates.role !== undefined) user.role = updates.role;
  if (updates.isActive !== undefined) user.isActive = updates.isActive;
  if (updates.emailVerified !== undefined) user.emailVerified = updates.emailVerified;

  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

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

export function verifyTOTPCode(secret: string, code: string): boolean {
  const secretBytes = base32Decode(secret);
  const timeStep = Math.floor(Date.now() / 1000 / 30);

  for (let i = -1; i <= 1; i++) {
    if (generateTOTPCode(secretBytes, timeStep + i) === code) {
      return true;
    }
  }
  return false;
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

export async function verifyAndEnableTOTP(userId: string, code: string): Promise<{ success: boolean; backupCodes?: string[]; error?: string }> {
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

  if (!verifyTOTPCode(decryptedSecret, code)) {
    return { success: false, error: "Invalid verification code" };
  }

  const backupCodes: string[] = [];
  for (let i = 0; i < 10; i++) {
    backupCodes.push(randomBytes(8).toString('hex'));
  }

  const encryptedBackupCodes = await oidc.encryptSecret(JSON.stringify(backupCodes));

  user.totpEnabled = true;
  user.totpBackupCodes = encryptedBackupCodes;
  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  db.logAuthEvent('totp_enabled', userId, null, {});

  return { success: true, backupCodes };
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

  let backupCodes: string[];
  try {
    const decrypted = await oidc.decryptSecret(user.totpBackupCodes);
    backupCodes = JSON.parse(decrypted);
  } catch {
    return false;
  }

  const normalizedCode = code.toLowerCase().trim();
  const index = backupCodes.findIndex(c => c.toLowerCase() === normalizedCode);
  if (index === -1) {
    return false;
  }

  backupCodes.splice(index, 1);
  user.totpBackupCodes = await oidc.encryptSecret(JSON.stringify(backupCodes));
  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  db.logAuthEvent('backup_code_used', userId, null, { remainingCodes: backupCodes.length });

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
  let codeValid = verifyTOTPCode(decryptedSecret, totpCode);

  if (!codeValid) {
    codeValid = await verifyBackupCode(user.id, totpCode);
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

  user.lastLogin = new Date().toISOString();
  user.updatedAt = new Date().toISOString();
  user.failedLoginAttempts = 0;
  user.lockedUntil = null;
  db.updateUser(user);

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
  user.pendingEmailToken = tokenHash;
  user.updatedAt = new Date().toISOString();
  db.updateUser(user);

  const verifyUrl = `${baseUrl}/auth/verify-email-change?token=${token}`;
  await mailer.sendVerificationEmail(normalizedNewEmail, user.displayName || 'User', verifyUrl);

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
