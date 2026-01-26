### TheOneFile_Verse changelog

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

