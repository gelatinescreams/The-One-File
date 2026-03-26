### TheOneFile_Verse changelog

**3/26/26 Theonefile_verse 1.8.6** : **Further improvements to Network Auto Discovery scanner/editor one page setup**

* **Network Discovery : Connections**
  * Thanks to [ahmaddxb](https://github.com/ahmaddxb) [#44](https://github.com/gelatinescreams/The-One-File/issues/44)
  * Added connections section to host editor cards
  * Connect discovered hosts to each other or to existing canvas nodes
  * From port and To port added to host editor cards
  * Icon syling added to host editor cards
  * Layer added to host editor cards
  * Notes added to host editor cards

**3/11/26 Theonefile_verse 1.8.5** : **Real ping, mutli network host discovery with selfh.st/icons matching and various other tidbits**

* **Real PING**
  * Overrides built in TheOneFileNetworkening "HTTP PING" with real server side methods
  * New probe types: ICMP ping, TCP port check, HTTP/HTTPS, DNS and Multi Probe (all combined)
  * Custom user ports
  
* **Network Discovery**
  * Added "Discover Network Hosts" button to settings panel under Auto Status Checking section (at the bottom)
  * Full subnet discovery with CIDR range input and preset common ranges
  * Multiple range support
  * Port scanning on discovered hosts across 70+ common ports covering infrastructure and self hosted services (more soon)
  * Custom user ports
  * Export hosts to canvas as nodes and racks with all scanned and edited information
  * Admin only mode and public range restrictions available in Admin settings

* **Popular Service + selfh.st/icons Detection**
  * Reverse DNS hostname resolution
  * NetBIOS name resolution (Windows network names)
  * mDNS / Avahi multicast DNS resolution
  * HTTP server header detection (Server and X Powered By)
  * SNMPv2c system name and description queries with configurable community string
  * Automatic port to service mapping for 70+ common ports
  * Automatic icon detection and assignment for 70+ services via selfh.st icons
  * Smart icon tagging via popular ports
  * Self hosted media: Plex, Jellyfin, Emby, Sonarr, Radarr, Lidarr, Prowlarr, Bazarr, Overseerr, Tautulli, Ombi, Navidrome, Audiobookshelf, Komga, Jackett, Calibre web
  * Automation and IoT: Home Assistant, Node RED, ESPHome, n8n
  * +tons more

* **DNS Detection**
  * Hosts running port 53 are probed further:) to identify the DNS software
  * AdGuard Home detected via /control/status endpoint (should work with password protected instances)
  * Pi-hole detected via /admin/api.php (v5) and /api/ (v6), (should work with password protected instances)
  * Technitium detected via port 5380 presence

* **Docker Detection**
  * Looks for docker api, dockge, portainer etc
  * "Deep Scan" button will popup next to host
  * This will scan the host more indepth for containers running though docker IF api is not available
  * Docker container names from "Deep Scan" are also added as tags
  
* **Automated Service Tagging**
  * Services column in Network Discovery table shows tags that will be saved with the host
  * Named services (Jellyfin, Grafana, Dockge, etc.) automatic detection
  * Generic port detection (Port 3003, Port 8810, etc.)
  * Docker container names from "Deep Scan" are also added as tags

**3/4/26 Theonefile_verse 1.8.0** : **Added a few settings, fixed some bugs, annoyances, security and production friendly hierarchical structure**

*Now that most of the core TheOneFile_Verse development is done, I have begun breaking the code into a more production friendly hierarchical structure. This will be completed by 2.0 Stable.*

* **New admin settings.**
  * Added admin setting to set room themes as default. Custom themes from imported versions will also be able to set as default. Thanks to [ahmaddxb](https://github.com/ahmaddxb) [#45](https://github.com/gelatinescreams/The-One-File/issues/45)
  * Added admin setting to show hide admin login link on homepage
  * Added admin setting to force welcome modal to all users even if custom data present

* **Changes + Bug Fixes** 
  * Fixed an issue where custom styles were not being applied after leaving the room
  * Changed QR code library to local library
  * Changed crypto.randomUUID() to oidc.generateSecureToken(32) for room ID creation
  * Backup code login as fallback (single use)
  * Password required to disable 2FA
  * AES 256 GCM encrypted secret and backup code storage
  * Removed all remaining innerHTML references
  * XSS audit passed
  * Added futher error logging to docker logs
  * Tons of security + performance fixes
  
* **OIDC Fixes**
  * Fixed an admin promotion issue when OIDC is the first user registered

* **Redis Fixes**
  * Changed Redis KEYS to SCAN.
  * Added redis.conf with safe limits

* **Docker Fixes** 
  * Added docker resource limits to default compose file

**3/2/26 Theonefile_verse 1.7.0** : *2FA, responsive overhaul, email change, path to stable, further security improvements*

*Now that most of the core TheOneFile_Verse development is done, I have begun breaking the code into a more production friendly hierarchical structure. This will be completed by 2.0 Stable.*

* **Two Factor Authentication (TOTP)**
  * Full TOTP implementation (RFC 6238, HMAC SHA1, 30 second window with ±1 tolerance)
  * QR code setup flow with manual secret entry fallback
  * 10 encrypted backup codes generated on enable
  * 2FA verification on login for both user and admin login pages
  * Backup code login as fallback (single use)
  * Password required to disable 2FA
  * AES 256 GCM encrypted secret and backup code storage
  * 5 minute expiry on pending 2FA tokens with replay prevention

* **Email Change**
  * Request email change with password confirmation
  * Verification email sent to new address
  * Token hash verification pattern (raw token to user, SHA 256 hash stored)
  * Uniqueness check on both request and confirmation
  * 24 hour token expiry

* **Responsive & Mobile Overhaul**
  * Full responsive design on landing page, all 9 auth page templates, and admin dashboard

* **User Settings Modal**
  * New account settings modal accessible from user menu
  * 2FA setup and disable UI with QR code display
  * Backup codes display after 2FA enable
  * Email change form with password confirmation
  * Verification status feedback

* **Security Hardening**
  * Per token 2FA attempt limit (3 maximum) prevents brute force on TOTP codes
  * PBKDF2 key derivation iterations increased from 100,000 to 600,000
  * OIDC email matching defaults to disabled (requires explicit opt in)
  * typeof input validation on all authentication API endpoints
  * typeof validation on profile update fields
  * CSRF validation added to all authenticated endpoints
  * OIDC token values redacted from debug logs
  * Proper autocomplete attributes on all auth inputs (email, current password, new password, one time code)
  * HSTS header now sent unconditionally (removed production mode guard)
  * WebSocket per message deflate compression enabled
  * Trusted proxy count and trusted proxy list configurable via TRUSTED_PROXY_COUNT and TRUSTED_PROXIES env vars

* **Bug Fixes**
  * Fixed registration failing with "Invalid security token" in some instances. (CSRF token was never fetched on landing page)
  * Fixed closeModal throwing error on modals without error elements (settings modal)
  * Fixed error text elements not showing when set via textContent (added not empty CSS rule)
  * Chat input alignment changed from flex end to center
  * Chat emoji changed from text entity to actual emoji character
  * Room creator_id database index added for search optimization

**2/15/26 Theonefile_verse 1.6.0** : **Security hardening, chat overhaul, UX improvements**
* **Security Hardening**
  * Timing safe comparison for legacy password hashes using crypto.timingSafeEqual
  * Length padded admin password comparison to prevent length oracle attacks
  * Full HTML entity escaping on chat messages and usernames (& < > " ')
  * Content Security Policy headers applied to all pages
  * OIDC provider name/type XSS protection with esc() in admin panel
  * PUT method added to CORS allowed methods
  * 50MB file upload size limit enforced before processing
  * Generic error messages on registration and disabled accounts to prevent user enumeration
  * CRLF injection prevention in all email headers (from, to, subject)
  * STARTTLS downgrade now throws error instead of continuing in plaintext
  * Template subject variable CRLF sanitization

* **Chat System Overhaul**
  * Chat message persistence sffrf
  * Typing indicators with "user is typing" display
  * Message replies with quoted reference
  * @mention highlighting with notification sound
  * 500 character counter with visual warning
  * Emoji picker with most common emojis
  * Relative timestamps (2m ago, 1h ago)

* **UX Improvements**
  * iOS safe area inset support on collab bar, modals, toasts
  * User avatars with colored initials in user list
  * Connection status indicator (green/yellow/red dot with pulse)
  * Offline/reconnecting banner with manual reconnect button
  * Stacking notification toasts with slide animations
  * Full screen mobile chat at 640px breakpoint
  * Smooth CSS transitions on remote cursors
  * Room expiry countdown display for auto destruct rooms

* **Server**
  * Typing message type with dedicated rate limit (5 bucket, 1/sec refill)
  * Chat history cleanup on room deletion

**2/14/26 Theonefile_verse 1.5.2** : **Auth flow fixes, error logging, version tracking**
* **Auth Flow Fixes**
  * Fixed setup page JavaScript SyntaxError that prevented form submission
  * Fixed missing SetCookie header on /api/setup route
  * Fixed password reset form variable shadowing window.confirm
  * Added defensive semicolons to OIDC button rendering across all forms
* **Error Logging**
  * All server side catch blocks now log errors with tagged prefixes
  * Tags: [Setup], [Login], [Register], [AdminLogin], [API], [Backup], [Update], etc.
* **Infrastructure**
  * Docker entrypoint now handles volume permissions automatically via su exec
  * Database migrations use safe column existence check before ALTER TABLE (BUN FIX)
  * Added /api/version endpoint for build verification
  * Version displayed in startup logs
  * CSRF cookie now includes HttpOnly flag

**2/14/26 Theonefile_verse 1.5.1** : **Fixes and further security hardening**
* **OIDC/SSO**
  * JWT signature verification now correctly maps hash algorithms (SHA 256/384/512) per token header
  * Discovery document validation ensures authorization and token endpoints exist and issuer matches
  * Sub claim enforcement on all ID tokens per OIDC spec
  * Openid scope automatically enforced on all provider configurations
  * Token type validation on token exchange responses
  * Post login redirect persistence across SSO flows
  * Account linking reverification ensures session is still valid before linking
  * Increased entropy in random string generation for required values

* **Security Hardening**
  * Added CSRF token protection on password reset endpoint
  * Constant time token comparison using crypto.timingSafeEqual
  * SSRF protection on webhook URLs (blocks private/internal IP ranges)
  * WebSocket connection rate limiting per IP address
  * IP validation on all rate limited endpoints
  * Automatic admin token cleanup on startup
  * Rate limit store memory management improvements
  * Token revocation on session termination
  * Docker Redis password security via --requirepass
  * Dockerfile now uses non root USER directive

**1/26/26 Theonefile_verse 1.5.0** *The Identity Update* 
* **Full User Account System**
  * User registration with email verification
  * Magic link login for passwordless authentication
  * Session management with device tracking (browser, OS, IP)
  * Multiple active sessions per user
  * Account lockout protection
  * User profile management (display name, avatar)
  * User preferences (theme, email notifications)
  * Self service account deletion

* **Single Sign On (SSO/OIDC)**
  * Sign in with Authentik, Google, GitHub, Microsoft, or any OpenID Connect provider
  * Link multiple SSO providers to a single account
  * Auto account linking by email
  * Configurable provider settings (scopes, display order, icons)
  * Secure encrypted token storage

* **Email System**
  * SMTP configuration with TLS/STARTTLS support
  * Email verification on signup
  * Password reset via email
  * Magic link authentication
  * Room invitation emails
  * Customizable email templates with variables
  * Email delivery logging with status tracking
  * Multiple SMTP configurations supported

* **Enhanced Security**
  * AES 256 GCM encryption for all stored secrets
  * PBKDF2 key derivation (100,000 iterations)
  * CSRF token protection on all forms
  * Secure HTTP only cookies
  * SameSite cookie policy
  * Production mode with HSTS headers
  * WebSocket session tokens for authenticated connections
  * Custom admin path option
  * Configurable trusted proxy support
  * Content Security Policy headers

* **Rate Limiting**
  * Endpoint rate limiting (configurable window and max attempts)
  * Email action rate limiting (signup, password reset, magic link)
  * WebSocket token bucket rate limiting per message type
  * Brute force protection on login attempts

* **Authentication Modes**
  * Open registration 
  * Email verification required mode
  * OIDC only
  * Invite only
  * Closed
  * Guest room join controls

* **Admin Dashboard Enhancements**
  * Full user management (create, edit, deactivate, delete)
  * Role based access control (admin, user, guest)
  * OIDC provider configuration UI
  * SMTP configuration management
  * Email template customization
  * Email delivery logs
  * Auth settings configuration

* **Bug Fixes**
  * Many bug and security fixes. As above and so below

**1/18/26 Theonefile_verse 1.4.0** *From Alpha to Beta status*
*  **New Features**
*  **Database & Storage Migration**
   * Migrated from flat JSON files to SQLite with WAL mode for better performance
*  **Redis Integration**
   * Added Redis support for data with graceful fallback to in memory
   * Rate limiting via Redis with automatic expiration
   * Session token storage with TTL
   * User presence tracking per room
   * Room state caching
   * Pub/sub messaging infrastructure for future scaling
   * Admin Dashboard Enhancements
*  **Full Api System** [api.md](api.md)
*  **New Tabs**
   * Logs tab: View activity logs (joins/leaves) and audit logs (admin actions)
   * Backups tab: Create, download, restore, and delete backups
   * API Keys tab: Create and revoke API keys with granular permissions

*  **New Admin Settings**
   * Toggle chat
   * Toggle cursor sharing
   * Toggle name changes globally
   * Webhooks: Enable webhook notifications with configurable URL
   * Automatic Backups: Enable scheduled backups with interval and retention settings
   * Room search/filter by ID or creator
   * Activity logging (who joined which room, when)
   * Audit logging for all admin actions
   * Backup & Recovery System
   * Manual backup creation via admin panel
   * Automatic scheduled backups with configurable interval (hours)
   * Backup retention policy (keeps N most recent auto backups)
   * One click restore from any backup
   * Export all rooms as JSON with settings
   * API Key System
   * Create API keys with custom names
   * Granular permissions: read, write, admin
   * Optional expiration (days)
   * Last used tracking
   * Revoke keys instantly
   * Webhook Notifications
   * POST notifications to configured URL
   * Events: room creation (with room ID, password status, destruct mode)
   * JSON payload with timestamp
*  **Bug Fixes**
   * Fixed a rare bug affecting custom image persistence
   * Fixed rare instances where images would not be restored on tab change
   * Further Cursor Precision Improvements
   * Polling every 100ms detects canvas state changes
   * Reduced throttle from 50ms to 25ms (20Hz → 40Hz)
   * Various performance and security improvements

**1/17/26 Theonefile_verse 1.3.1** Updated for Image and Notes update

**1/12/26 Theonefile_verse 1.3** Its all coming together now
  * Completely rewrote the cross user mouse logic. It is much more reliable now.
  * Fixed an issue where styles and some variables were not saving across user instances
  * Various bug fixes

**1/6/26 Theonefile_verse 1.2** Flip it and reverse it
  * Fixed an issue where revere proxies did not pick us WSS correctly
  * Fixed an issue where username did not persist in some rare cases
  * various fixes

**1/6/26 Theonefile_verse 1.1** Getting chatty
  * 1.1 gitea bleeding edge version main lined
  * adds instant message chat per room
  * adds duplciate name detection
  * adds real time mutli user cursor engine
  * adds current tab to the users top bar name plate
  * various fixes

**1/6/26 Theonefile_verse intitial upload 1.0**
  * initial upload

