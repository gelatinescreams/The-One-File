import * as db from "./database";

const DEBUG_OIDC = process.env.DEBUG_OIDC === 'true';

if (DEBUG_OIDC) {
  const authSettings = db.getSetting('authSettings');
  const isProduction = authSettings ? JSON.parse(authSettings).productionMode : false;
  if (isProduction) {
    console.warn('[Security] WARNING: DEBUG_OIDC is enabled in production mode!');
    console.warn('[Security] This may expose sensitive information in logs. Disable DEBUG_OIDC for production.');
  }
}

function logOidcError(message: string, ...args: any[]): void {
  if (DEBUG_OIDC) {
    console.error('[OIDC]', message, ...args);
  } else {
    console.error('[OIDC]', message);
  }
}

function logOidcDebug(message: string, ...args: any[]): void {
  if (DEBUG_OIDC) {
    console.log('[OIDC]', message, ...args);
  }
}

const MAX_OIDC_STATES = 10000;
const OIDC_STATE_TTL_MS = 10 * 60 * 1000;
const ID_TOKEN_CLOCK_SKEW_MS = parseInt(process.env.OIDC_CLOCK_SKEW_SECONDS || '120') * 1000;
const CSRF_TOKEN_TTL_MS = 60 * 60 * 1000;
const MAX_CSRF_TOKENS = 10000;

function cleanupOldestOidcStates(): void {
  const count = db.countOidcStates();
  if (count <= MAX_OIDC_STATES) return;
  db.deleteOldestOidcStates(count - MAX_OIDC_STATES + 100);
}

setInterval(() => {
  db.cleanupExpiredOidcStates();
  db.cleanupExpiredCsrfTokens();
}, 60 * 1000);

function generateRandomString(length: number): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

function generateCodeVerifier(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64UrlEncode(array);
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hash));
}

function base64UrlEncode(buffer: Uint8Array): string {
  let str = '';
  for (const byte of buffer) {
    str += String.fromCharCode(byte);
  }
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

const ENCRYPTION_KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_SALT_LENGTH = 16;
let encryptionKey: CryptoKey | null = null;

async function deriveKeyFromSecret(secret: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function getEncryptionKeyMaterial(): Promise<Uint8Array> {
  const envKey = process.env.ENCRYPTION_KEY;

  if (envKey) {
    const encoder = new TextEncoder();
    const hash = await crypto.subtle.digest('SHA-256', encoder.encode(envKey));
    return new Uint8Array(hash);
  }

  let keyHex = db.getSetting('encryption_key');

  if (!keyHex) {
    const keyBytes = new Uint8Array(ENCRYPTION_KEY_LENGTH);
    crypto.getRandomValues(keyBytes);
    keyHex = Array.from(keyBytes, b => b.toString(16).padStart(2, '0')).join('');
    db.setSetting('encryption_key', keyHex);
    console.warn('='.repeat(70));
    console.warn('[SECURITY WARNING] ENCRYPTION_KEY environment variable not set.');
    console.warn('[SECURITY WARNING] A random key has been generated and stored in the database.');
    console.warn('[SECURITY WARNING] This means the encryption key lives alongside the encrypted data,');
    console.warn('[SECURITY WARNING] defeating the purpose of encryption if the database is compromised.');
    console.warn('[SECURITY WARNING] Set ENCRYPTION_KEY in your environment for production deployments.');
    console.warn('='.repeat(70));
  }

  return new Uint8Array(keyHex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
}

async function getEncryptionKey(salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await getEncryptionKeyMaterial();

  const importedKey = await crypto.subtle.importKey(
    'raw',
    keyMaterial,
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    importedKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptSecret(plaintext: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(PBKDF2_SALT_LENGTH));
  const key = await getEncryptionKey(salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoder.encode(plaintext)
  );

  const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
  combined.set(salt);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encrypted), salt.length + iv.length);

  return base64UrlEncode(combined);
}

export async function decryptSecret(ciphertext: string): Promise<string> {
  const combined = Uint8Array.from(atob(ciphertext.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

  const isNewFormat = combined.length >= 44;

  if (isNewFormat) {
    const salt = combined.slice(0, PBKDF2_SALT_LENGTH);
    const iv = combined.slice(PBKDF2_SALT_LENGTH, PBKDF2_SALT_LENGTH + 12);
    const encrypted = combined.slice(PBKDF2_SALT_LENGTH + 12);

    const key = await getEncryptionKey(salt);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encrypted
    );

    return new TextDecoder().decode(decrypted);
  } else {
    const legacySalt = new TextEncoder().encode('theonefile-verse-encryption-v1');
    const key = await getEncryptionKey(legacySalt);

    const iv = combined.slice(0, 12);
    const encrypted = combined.slice(12);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encrypted
    );

    return new TextDecoder().decode(decrypted);
  }
}

interface OidcDiscovery {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  scopes_supported?: string[];
  revocation_endpoint?: string;
}

async function discoverOidcEndpoints(issuerUrl: string): Promise<OidcDiscovery | null> {
  try {
    const wellKnownUrl = issuerUrl.replace(/\/$/, '') + '/.well-known/openid-configuration';
    const res = await fetch(wellKnownUrl);
    if (!res.ok) return null;
    const disc = await res.json();
    if (!disc.authorization_endpoint || !disc.token_endpoint) return null;
    const normExpected = issuerUrl.replace(/\/$/, '');
    const normActual = (disc.issuer || '').replace(/\/$/, '');
    if (normActual && normActual !== normExpected) {
      logOidcError('Discovery issuer mismatch', { expected: normExpected, got: normActual });
      return null;
    }
    return disc;
  } catch {
    return null;
  }
}

export interface OidcAuthUrl {
  url: string;
  state: string;
}

export interface OidcUserInfo {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  picture?: string;
}

export interface OidcTokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
}

export async function generateAuthorizationUrl(
  providerId: string,
  baseUrl: string,
  linkUserId?: string,
  postLoginRedirect?: string
): Promise<OidcAuthUrl | null> {
  const provider = db.getOidcProvider(providerId);
  if (!provider || !provider.isActive) return null;

  const codeVerifier = generateCodeVerifier();
  const codeChallenge = await generateCodeChallenge(codeVerifier);
  const state = generateRandomString(32);
  const nonce = generateRandomString(32);
  const redirectUri = `${baseUrl}/auth/callback/${providerId}`;

  cleanupOldestOidcStates();

  const now = new Date();
  const expiresAt = new Date(now.getTime() + OIDC_STATE_TTL_MS);

  db.createOidcState({
    state,
    providerId,
    codeVerifier,
    nonce,
    redirectUri,
    linkUserId: linkUserId || null,
    postLoginRedirect: postLoginRedirect || null,
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString()
  });

  let authUrl = provider.authorizationUrl;

  if (provider.issuerUrl && !authUrl) {
    const discovery = await discoverOidcEndpoints(provider.issuerUrl);
    if (discovery) {
      authUrl = discovery.authorization_endpoint;
    }
  }

  if (!authUrl) return null;

  let scopes = provider.scopes || 'openid email profile';
  if (!scopes.split(' ').includes('openid')) scopes = 'openid ' + scopes;

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: provider.clientId,
    redirect_uri: redirectUri,
    scope: scopes,
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  return {
    url: `${authUrl}?${params.toString()}`,
    state
  };
}

export async function exchangeCodeForTokens(
  providerId: string,
  code: string,
  state: string
): Promise<{ tokens: OidcTokenResponse; userInfo: OidcUserInfo; linkUserId?: string; postLoginRedirect?: string } | null> {
  const storedState = db.getOidcState(state);
  if (!storedState || storedState.providerId !== providerId) {
    return null;
  }

  if (new Date(storedState.expiresAt) < new Date()) {
    db.deleteOidcState(state);
    return null;
  }

  db.deleteOidcState(state);

  const provider = db.getOidcProvider(providerId);
  if (!provider) return null;

  let tokenUrl = provider.tokenUrl;
  let userinfoUrl = provider.userinfoUrl;
  let jwksUri = provider.jwksUri;

  if (provider.issuerUrl && (!tokenUrl || !userinfoUrl || !jwksUri)) {
    const discovery = await discoverOidcEndpoints(provider.issuerUrl);
    if (discovery) {
      tokenUrl = tokenUrl || discovery.token_endpoint;
      userinfoUrl = userinfoUrl || discovery.userinfo_endpoint;
      jwksUri = jwksUri || discovery.jwks_uri;
    }
  }

  if (!tokenUrl) return null;

  let clientSecret: string;
  try {
    clientSecret = await decryptSecret(provider.clientSecretEncrypted);
  } catch {
    return null;
  }

  const tokenParams = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: provider.clientId,
    client_secret: clientSecret,
    code,
    redirect_uri: storedState.redirectUri,
    code_verifier: storedState.codeVerifier
  });
  const storedNonce = storedState.nonce;
  const storedLinkUserId = storedState.linkUserId;
  const storedPostLoginRedirect = storedState.postLoginRedirect;

  try {
    const tokenRes = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: tokenParams.toString()
    });

    if (!tokenRes.ok) {
      logOidcError('Token exchange failed', await tokenRes.text());
      return null;
    }

    const tokens: OidcTokenResponse = await tokenRes.json();

    if (tokens.token_type && tokens.token_type.toLowerCase() !== 'bearer') {
      logOidcError('Unsupported token type', tokens.token_type);
      return null;
    }

    let userInfo: OidcUserInfo | null = null;

    if (tokens.id_token) {
      userInfo = await parseIdToken(
        tokens.id_token,
        storedNonce,
        jwksUri,
        provider.issuerUrl,
        provider.clientId
      );
    }

    if (!userInfo && userinfoUrl) {
      const userInfoRes = await fetch(userinfoUrl, {
        headers: { 'Authorization': `Bearer ${tokens.access_token}` }
      });

      if (userInfoRes.ok) {
        userInfo = await userInfoRes.json();
      }
    }

    if (!userInfo || !userInfo.sub) {
      logOidcError('Could not get user info');
      return null;
    }

    return { tokens, userInfo, linkUserId: storedLinkUserId || undefined, postLoginRedirect: storedPostLoginRedirect || undefined };
  } catch (e) {
    logOidcError('Token exchange error', e);
    return null;
  }
}

const MAX_JWKS_CACHE_ENTRIES = 100;
const jwksCache = new Map<string, { keys: JsonWebKey[]; fetchedAt: number }>();

function cleanupJwksCache(): void {
  if (jwksCache.size <= MAX_JWKS_CACHE_ENTRIES) return;

  const entries = Array.from(jwksCache.entries())
    .sort((a, b) => a[1].fetchedAt - b[1].fetchedAt);

  const toRemove = entries.slice(0, jwksCache.size - MAX_JWKS_CACHE_ENTRIES + 10);
  for (const [key] of toRemove) {
    jwksCache.delete(key);
  }
}

async function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function fetchJwks(jwksUri: string): Promise<JsonWebKey[]> {
  const cached = jwksCache.get(jwksUri);
  if (cached && Date.now() - cached.fetchedAt < 60 * 60 * 1000) {
    return cached.keys;
  }

  const maxRetries = 3;
  const baseDelayMs = 100;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const res = await fetch(jwksUri);
      if (!res.ok) {
        if (attempt < maxRetries - 1) {
          const delay = baseDelayMs * Math.pow(2, attempt) + Math.random() * 100;
          await sleep(delay);
          continue;
        }
        return [];
      }
      const data = await res.json();
      const keys = data.keys || [];
      cleanupJwksCache();
      jwksCache.set(jwksUri, { keys, fetchedAt: Date.now() });
      return keys;
    } catch {
      if (attempt < maxRetries - 1) {
        const delay = baseDelayMs * Math.pow(2, attempt) + Math.random() * 100;
        await sleep(delay);
        continue;
      }
      return [];
    }
  }
  return [];
}

function getHashAlgorithm(alg: string): string {
  if (alg.endsWith('384')) return 'SHA-384';
  if (alg.endsWith('512')) return 'SHA-512';
  return 'SHA-256';
}

async function importJwkForVerify(jwk: JsonWebKey): Promise<CryptoKey | null> {
  try {
    const alg = jwk.alg || 'RS256';
    let algorithm: RsaHashedImportParams | EcKeyImportParams;

    if (alg.startsWith('RS')) {
      algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: { name: getHashAlgorithm(alg) } };
    } else if (alg.startsWith('ES')) {
      algorithm = { name: 'ECDSA', namedCurve: jwk.crv || 'P-256' };
    } else {
      return null;
    }

    return await crypto.subtle.importKey('jwk', jwk, algorithm, false, ['verify']);
  } catch {
    return null;
  }
}

async function verifyJwtSignature(token: string, jwks: JsonWebKey[]): Promise<boolean> {
  const parts = token.split('.');
  if (parts.length !== 3) return false;

  try {
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const signature = Uint8Array.from(atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const signedData = new TextEncoder().encode(parts[0] + '.' + parts[1]);

    const matchingKeys = header.kid
      ? jwks.filter(k => k.kid === header.kid)
      : jwks;

    for (const jwk of matchingKeys) {
      const key = await importJwkForVerify(jwk);
      if (!key) continue;

      const alg = jwk.alg || header.alg || 'RS256';
      let verifyAlg: AlgorithmIdentifier | RsaPssParams | EcdsaParams;

      if (alg.startsWith('RS')) {
        verifyAlg = { name: 'RSASSA-PKCS1-v1_5' };
      } else if (alg.startsWith('ES')) {
        verifyAlg = { name: 'ECDSA', hash: { name: getHashAlgorithm(alg) } };
      } else {
        continue;
      }

      const valid = await crypto.subtle.verify(verifyAlg, key, signature, signedData);
      if (valid) return true;
    }

    return false;
  } catch (e) {
    logOidcError('JWT signature verification error', e);
    return false;
  }
}

async function parseIdToken(
  idToken: string,
  expectedNonce: string,
  jwksUri?: string | null,
  expectedIssuer?: string | null,
  expectedAudience?: string | null
): Promise<OidcUserInfo | null> {
  try {
    const parts = idToken.split('.');
    if (parts.length !== 3) return null;

    if (jwksUri) {
      const jwks = await fetchJwks(jwksUri);
      if (jwks.length === 0) {
        logOidcError('Failed to fetch JWKS for signature verification');
        return null;
      }
      const signatureValid = await verifyJwtSignature(idToken, jwks);
      if (!signatureValid) {
        logOidcError('ID token signature verification failed');
        return null;
      }
    }

    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

    if (expectedIssuer) {
      const normalizedExpected = expectedIssuer.replace(/\/$/, '');
      const normalizedActual = (payload.iss || '').replace(/\/$/, '');
      if (normalizedActual !== normalizedExpected) {
        logOidcError('Issuer mismatch', { expected: normalizedExpected, got: normalizedActual });
        return null;
      }
    }

    if (expectedAudience) {
      const aud = payload.aud;
      const audArray = Array.isArray(aud) ? aud : [aud];
      if (!audArray.includes(expectedAudience)) {
        logOidcError('Audience mismatch', { expected: expectedAudience, got: aud });
        return null;
      }

      if (audArray.length > 1 && payload.azp !== expectedAudience) {
        logOidcError('Authorized party (azp) mismatch for multi-audience token');
        return null;
      }
    }

    if (payload.nonce !== expectedNonce) {
      logOidcError('Nonce mismatch');
      return null;
    }

    if (payload.exp && payload.exp * 1000 < Date.now() - ID_TOKEN_CLOCK_SKEW_MS) {
      logOidcError('ID token expired');
      return null;
    }

    if (payload.nbf && payload.nbf * 1000 > Date.now() + ID_TOKEN_CLOCK_SKEW_MS) {
      logOidcError('ID token not yet valid (nbf)');
      return null;
    }

    if (payload.iat && payload.iat * 1000 < Date.now() - getIdTokenMaxAgeMs()) {
      logOidcError('ID token too old');
      return null;
    }

    if (payload.iat && payload.iat * 1000 > Date.now() + ID_TOKEN_CLOCK_SKEW_MS) {
      logOidcError('ID token issued in the future');
      return null;
    }

    if (!payload.sub) {
      logOidcError('ID token missing required sub claim');
      return null;
    }

    return {
      sub: payload.sub,
      email: payload.email,
      email_verified: payload.email_verified,
      name: payload.name || payload.preferred_username,
      preferred_username: payload.preferred_username,
      picture: payload.picture
    };
  } catch {
    return null;
  }
}

export async function processOidcCallback(
  providerId: string,
  code: string,
  state: string,
  ipAddress: string,
  userAgent: string,
  currentUserToken?: string | null
): Promise<{
  success: boolean;
  userId?: string;
  sessionToken?: string;
  error?: string;
  isNewUser?: boolean;
  isLinked?: boolean;
  message?: string;
  postLoginRedirect?: string;
}> {
  const result = await exchangeCodeForTokens(providerId, code, state);
  if (!result) {
    return { success: false, error: 'Failed to exchange code for tokens' };
  }

  const { tokens, userInfo, linkUserId, postLoginRedirect } = result;
  const provider = db.getOidcProvider(providerId);
  if (!provider) {
    return { success: false, error: 'Provider not found' };
  }

  const existingLink = db.getOidcLinkByProvider(provider.name, userInfo.sub);

  if (existingLink) {
    const encryptedAccess = tokens.access_token ? await encryptSecret(tokens.access_token) : null;
    const encryptedRefresh = tokens.refresh_token ? await encryptSecret(tokens.refresh_token) : null;
    const expiresAt = tokens.expires_in
      ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
      : null;

    db.updateOidcLinkTokens(existingLink.id, encryptedAccess, encryptedRefresh, expiresAt);

    const user = db.getUserById(existingLink.userId);
    if (user) {
      user.lastLogin = new Date().toISOString();
      user.updatedAt = new Date().toISOString();
      db.updateUser(user);
    }

    const sessionToken = await createUserSessionToken(existingLink.userId, ipAddress, userAgent);

    db.logAuthEvent('oidc_login', existingLink.userId, ipAddress, { provider: provider.name, providerUserId: userInfo.sub });
    return { success: true, userId: existingLink.userId, sessionToken, isNewUser: false, postLoginRedirect };
  }

  if (linkUserId) {
    if (currentUserToken) {
      const currentUser = await validateUserSessionToken(currentUserToken);
      if (!currentUser || currentUser.id !== linkUserId) {
        return { success: false, error: 'Session expired or invalid for account linking' };
      }
    } else {
      return { success: false, error: 'Authentication required for account linking' };
    }

    const user = db.getUserById(linkUserId);
    if (!user) {
      return { success: false, error: 'User not found for linking' };
    }

    const encryptedAccess = tokens.access_token ? await encryptSecret(tokens.access_token) : null;
    const encryptedRefresh = tokens.refresh_token ? await encryptSecret(tokens.refresh_token) : null;
    const expiresAt = tokens.expires_in
      ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
      : null;

    db.createOidcLink({
      id: crypto.randomUUID(),
      userId: linkUserId,
      provider: provider.name,
      providerUserId: userInfo.sub,
      providerEmail: userInfo.email || null,
      accessTokenEncrypted: encryptedAccess,
      refreshTokenEncrypted: encryptedRefresh,
      tokenExpiresAt: expiresAt,
      createdAt: new Date().toISOString()
    });

    db.logAuthEvent('oidc_link', linkUserId, ipAddress, { provider: provider.name, providerUserId: userInfo.sub });
    return { success: true, userId: linkUserId, isNewUser: false, isLinked: true, message: `Successfully linked ${provider.name} account`, postLoginRedirect };
  }

  const authSettings = getAuthSettings();
  let existingUser: db.User | null = null;

  if (authSettings.oidcEmailMatching && userInfo.email && userInfo.email_verified) {
    existingUser = db.getUserByEmail(userInfo.email);
  }

  if (existingUser) {
    const encryptedAccess = tokens.access_token ? await encryptSecret(tokens.access_token) : null;
    const encryptedRefresh = tokens.refresh_token ? await encryptSecret(tokens.refresh_token) : null;
    const expiresAt = tokens.expires_in
      ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
      : null;

    db.createOidcLink({
      id: crypto.randomUUID(),
      userId: existingUser.id,
      provider: provider.name,
      providerUserId: userInfo.sub,
      providerEmail: userInfo.email || null,
      accessTokenEncrypted: encryptedAccess,
      refreshTokenEncrypted: encryptedRefresh,
      tokenExpiresAt: expiresAt,
      createdAt: new Date().toISOString()
    });

    existingUser.lastLogin = new Date().toISOString();
    existingUser.updatedAt = new Date().toISOString();
    db.updateUser(existingUser);

    const sessionToken = await createUserSessionToken(existingUser.id, ipAddress, userAgent);
    db.logAuthEvent('oidc_login_email_match', existingUser.id, ipAddress, { provider: provider.name, providerUserId: userInfo.sub, matchedEmail: userInfo.email });
    return { success: true, userId: existingUser.id, sessionToken, isNewUser: false, postLoginRedirect };
  }

  const userId = crypto.randomUUID();
  const now = new Date().toISOString();

  const userCount = db.countUsers();
  const isFirstUser = userCount === 0;
  const role = isFirstUser ? 'admin' : 'user';

  const newUser: db.User = {
    id: userId,
    email: userInfo.email || null,
    emailVerified: isFirstUser || userInfo.email_verified || false,
    displayName: userInfo.name || userInfo.preferred_username || null,
    avatarUrl: userInfo.picture || null,
    passwordHash: null,
    role,
    createdAt: now,
    updatedAt: now,
    lastLogin: now,
    isActive: true
  };

  db.createUser(newUser);

  const encryptedAccess = tokens.access_token ? await encryptSecret(tokens.access_token) : null;
  const encryptedRefresh = tokens.refresh_token ? await encryptSecret(tokens.refresh_token) : null;
  const expiresAt = tokens.expires_in
    ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
    : null;

  db.createOidcLink({
    id: crypto.randomUUID(),
    userId,
    provider: provider.name,
    providerUserId: userInfo.sub,
    providerEmail: userInfo.email || null,
    accessTokenEncrypted: encryptedAccess,
    refreshTokenEncrypted: encryptedRefresh,
    tokenExpiresAt: expiresAt,
    createdAt: now
  });

  const sessionToken = await createUserSessionToken(userId, ipAddress, userAgent);

  db.logAuthEvent('oidc_register', userId, ipAddress, { provider: provider.name, providerUserId: userInfo.sub, role, isFirstUser });
  return { success: true, userId, sessionToken, isNewUser: true, postLoginRedirect };
}

async function createUserSessionToken(
  userId: string,
  ipAddress: string,
  userAgent: string
): Promise<string> {
  const token = generateSecureToken(32);
  const tokenHash = await hashToken(token);
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

export async function hashToken(token: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash), b => b.toString(16).padStart(2, '0')).join('');
}

export function generateSecureToken(bytes: number = 32): string {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

export async function validateUserSessionToken(
  token: string,
  currentIP?: string,
  currentUserAgent?: string
): Promise<db.User | null> {
  const tokenHash = await hashToken(token);
  const session = db.getSessionByTokenHash(tokenHash);

  if (!session) return null;

  if (new Date(session.expiresAt) < new Date()) {
    db.deleteSession(session.id);
    return null;
  }

  const user = db.getUserById(session.userId);
  if (!user || !user.isActive) return null;

  if (currentIP && session.ipAddress && session.ipAddress !== currentIP) {
    db.logAuthEvent('session_ip_change', session.userId, currentIP, {
      originalIP: session.ipAddress,
      newIP: currentIP,
      sessionId: session.id
    });
  }

  return user;
}

export async function refreshOidcTokens(linkId: string): Promise<{
  success: boolean;
  accessToken?: string;
  error?: string;
}> {
  const link = db.getOidcLinkById(linkId);
  if (!link || !link.refreshTokenEncrypted) {
    return { success: false, error: 'No refresh token available' };
  }

  const provider = db.getOidcProviderByName(link.provider);
  if (!provider) {
    return { success: false, error: 'Provider not found' };
  }

  let tokenUrl = provider.tokenUrl;
  if (!tokenUrl && provider.issuerUrl) {
    const discovery = await discoverOidcEndpoints(provider.issuerUrl);
    if (discovery) {
      tokenUrl = discovery.token_endpoint;
    }
  }

  if (!tokenUrl) {
    return { success: false, error: 'No token endpoint configured for provider' };
  }

  let refreshToken: string;
  try {
    refreshToken = await decryptSecret(link.refreshTokenEncrypted);
  } catch {
    return { success: false, error: 'Failed to decrypt refresh token' };
  }

  let clientSecret: string | null = null;
  if (provider.clientSecretEncrypted) {
    try {
      clientSecret = await decryptSecret(provider.clientSecretEncrypted);
    } catch {
      return { success: false, error: 'Failed to decrypt client secret' };
    }
  }

  try {
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: provider.clientId
    });

    if (clientSecret) {
      params.set('client_secret', clientSecret);
    }

    const tokenRes = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString()
    });

    if (!tokenRes.ok) {
      logOidcError('Token refresh failed', await tokenRes.text());
      return { success: false, error: 'Token refresh failed' };
    }

    const tokens = await tokenRes.json();

    const encryptedAccess = tokens.access_token ? await encryptSecret(tokens.access_token) : null;
    const encryptedRefresh = tokens.refresh_token ? await encryptSecret(tokens.refresh_token) : link.refreshTokenEncrypted;
    const expiresAt = tokens.expires_in
      ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
      : null;

    db.updateOidcLinkTokens(link.id, encryptedAccess, encryptedRefresh, expiresAt);

    return { success: true, accessToken: tokens.access_token };
  } catch (e: any) {
    logOidcError('Token refresh error', e);
    return { success: false, error: 'Token refresh error' };
  }
}

export async function revokeUserOidcTokens(userId: string): Promise<void> {
  const links = db.getOidcLinksByUser(userId);
  for (const link of links) {
    try {
      const provider = db.getOidcProviderByName(link.provider);
      if (!provider) continue;

      let revocationUrl: string | undefined;
      if (provider.issuerUrl) {
        const discovery = await discoverOidcEndpoints(provider.issuerUrl);
        revocationUrl = discovery?.revocation_endpoint ?? undefined;
      }
      if (!revocationUrl) continue;

      let clientSecret: string | null = null;
      if (provider.clientSecretEncrypted) {
        try { clientSecret = await decryptSecret(provider.clientSecretEncrypted); } catch { continue; }
      }

      const tokensToRevoke: { token: string; hint: string }[] = [];

      if (link.accessTokenEncrypted) {
        try {
          const accessToken = await decryptSecret(link.accessTokenEncrypted);
          tokensToRevoke.push({ token: accessToken, hint: 'access_token' });
        } catch {}
      }
      if (link.refreshTokenEncrypted) {
        try {
          const refreshToken = await decryptSecret(link.refreshTokenEncrypted);
          tokensToRevoke.push({ token: refreshToken, hint: 'refresh_token' });
        } catch {}
      }

      for (const { token, hint } of tokensToRevoke) {
        try {
          const params = new URLSearchParams({
            token,
            token_type_hint: hint,
            client_id: provider.clientId
          });
          if (clientSecret) params.set('client_secret', clientSecret);

          await fetch(revocationUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params.toString()
          });
        } catch (e: any) {
          logOidcError(`Token revocation failed for provider ${link.provider}`, e);
        }
      }

      db.updateOidcLinkTokens(link.id, null, null, null);
    } catch (e: any) {
      logOidcError(`Failed to revoke tokens for OIDC link ${link.id}`, e);
    }
  }
}

export interface AuthSettings {
  authMode: 'open' | 'registration' | 'oidc_only' | 'invite_only' | 'closed';
  allowGuestRoomCreation: boolean;
  allowGuestRoomJoin: boolean;
  allowRoomCreatorGuestSetting: boolean;
  oidcEmailMatching: boolean;
  requireEmailVerification: boolean;
  allowMagicLinkLogin: boolean;
  shareButtonEnabled: boolean;
  productionMode: boolean;
  idTokenMaxAgeHours: number;
  emailRateLimitWindowSeconds: number;
  emailRateLimitMaxAttempts: number;
}

export function getAuthSettings(): AuthSettings {
  const defaults: AuthSettings = {
    authMode: 'open',
    allowGuestRoomCreation: true,
    allowGuestRoomJoin: true,
    allowRoomCreatorGuestSetting: true,
    oidcEmailMatching: true,
    requireEmailVerification: false,
    allowMagicLinkLogin: true,
    shareButtonEnabled: true,
    productionMode: false,
    idTokenMaxAgeHours: 2,
    emailRateLimitWindowSeconds: 300,
    emailRateLimitMaxAttempts: 3
  };

  try {
    const stored = db.getSetting('authSettings');
    if (stored) {
      return { ...defaults, ...JSON.parse(stored) };
    }
  } catch (e: any) {
    console.error('[OIDC] Failed to parse auth settings:', e.message);
  }

  return defaults;
}

export function saveAuthSettings(settings: Partial<AuthSettings>): void {
  const current = getAuthSettings();
  const merged = { ...current, ...settings };
  db.setSetting('authSettings', JSON.stringify(merged));
}

function getIdTokenMaxAgeMs(): number {
  const settings = getAuthSettings();
  return settings.idTokenMaxAgeHours * 60 * 60 * 1000;
}

function sanitizeIconUrl(url: string | null): string | null {
  if (!url) return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') return url;
    return null;
  } catch {
    return null;
  }
}

export function getActiveProviders(): { id: string; name: string; iconUrl: string | null }[] {
  return db.listActiveOidcProviders().map(p => ({
    id: p.id,
    name: p.name,
    iconUrl: sanitizeIconUrl(p.iconUrl)
  }));
}

export function getSessionCookie(name: string, value: string, maxAge: number = 2592000): string {
  const settings = getAuthSettings();
  if (settings.productionMode) {
    return `__Host-${name}=${value}; Path=/; HttpOnly; SameSite=Strict; Secure; Partitioned; Max-Age=${maxAge}`;
  }
  return `${name}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}`;
}

export function getClearCookie(name: string): string {
  const settings = getAuthSettings();
  if (settings.productionMode) {
    return `__Host-${name}=; Path=/; HttpOnly; SameSite=Strict; Secure; Partitioned; Max-Age=0`;
  }
  return `${name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
}

export function getSessionCookieName(baseName: string): string {
  const settings = getAuthSettings();
  return settings.productionMode ? `__Host-${baseName}` : baseName;
}

function cleanupOldestCsrfTokens(): void {
  const count = db.countCsrfTokens();
  if (count <= MAX_CSRF_TOKENS) return;
  db.deleteOldestCsrfTokens(count - MAX_CSRF_TOKENS + 100);
}

export function generateCsrfToken(): string {
  cleanupOldestCsrfTokens();

  const token = generateSecureToken(32);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + CSRF_TOKEN_TTL_MS);

  db.createCsrfToken({
    token,
    used: false,
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString()
  });

  return token;
}

export function validateCsrfToken(token: string): boolean {
  if (!token) return false;

  const data = db.getCsrfToken(token);
  if (!data) return false;

  if (new Date(data.expiresAt) < new Date()) {
    db.deleteCsrfToken(token);
    return false;
  }

  if (data.used) {
    db.deleteCsrfToken(token);
    return false;
  }

  db.markCsrfTokenUsed(token);
  return true;
}

export function getCsrfCookie(token: string): string {
  const settings = getAuthSettings();
  const secure = settings.productionMode ? '; Secure' : '';
  return `csrf_token=${token}; Path=/; HttpOnly; SameSite=Strict${secure}; Max-Age=3600`;
}

export function validateRedirectUrl(redirectUrl: string | null, baseUrl: string): string {
  if (!redirectUrl) {
    return '/';
  }

  const sanitized = redirectUrl.trim().toLowerCase();

  const dangerousSchemes = ['javascript:', 'data:', 'vbscript:', 'file:', 'blob:'];
  for (const scheme of dangerousSchemes) {
    if (sanitized.startsWith(scheme)) {
      return '/';
    }
  }

  const original = redirectUrl.trim();

  if (original.startsWith('/') && !original.startsWith('//')) {
    if (original.includes('..') || original.includes('\\')) {
      return '/';
    }
    return original;
  }

  try {
    const redirectOrigin = new URL(original).origin;
    const baseOrigin = new URL(baseUrl).origin;

    if (redirectOrigin === baseOrigin) {
      const url = new URL(original);
      return url.pathname + url.search + url.hash;
    }
  } catch {
  }

  return '/';
}
