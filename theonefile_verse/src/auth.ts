import * as db from "./database";
import * as oidc from "./oidc";
import * as mailer from "./mailer";

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
  return Buffer.from(legacyHash).toString("hex") === hash;
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
    return { success: false, error: "Email already registered" };
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
    lockedUntil: null
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
): Promise<{ success: boolean; userId?: string; sessionToken?: string; error?: string }> {
  const normalizedEmail = normalizeEmail(email);
  const user = db.getUserByEmail(normalizedEmail);
  if (!user) {
    return { success: false, error: "Invalid email or password" };
  }

  if (!user.isActive) {
    return { success: false, error: "Account is disabled" };
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
    user.displayName = updates.displayName.substring(0, 100);
  }
  if (updates.avatarUrl !== undefined) {
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
    return { success: false, error: "Email already registered" };
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
    isActive: true
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

setInterval(() => {
  cleanupExpiredTokens();
}, 60 * 60 * 1000);
