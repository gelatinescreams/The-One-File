### TheOneFile_Verse

<p align="center">
  <img src="https://img.shields.io/badge/License-Unlicense-576169?style=for-the-badge&labelColor=01284b" alt="License: Unlicense">
  <img src="https://img.shields.io/badge/TheOneFile-4.1.5-blue" alt="TheOneFile 4.1.5">
  <a href="https://github.com/gelatinescreams/The-One-File/tree/main/theonefile_verse">
  <img src="https://img.shields.io/badge/TheOneFile_Verse-1.8.6-blue" alt="Docker Version 1.8.6">
  </a>
</p>

*As it turns out, there can be more than one (in 3d soon :) )*

![The One File Verse Mutli User Collaboration](https://raw.githubusercontent.com/gelatinescreams/The-One-File/refs/heads/main/assets/collab-preview.gif)

An easily deployable, Docker based, real time collaboration server with mutli network device discovery, auto service & selfh.st/icons tagging, user accounts, email authentication, SSO, role based access control and more. All configurable via a robust admin panel.

When you're done collaborating, each person can save their own portable copy. That file works exactly like the original TheOneFile: fully offline, self contained, editable anywhere. Import it back into the TheOneFile_Verse anytime to continue collaborating.

**AND/OR**

Rooms auto save your work, no manual exports required. Admins can run as many rooms as needed, a multiOneFileverse of parallel diagrams. Host it privately or open it to the internet (use tons of caution and a secure reverse proxy).

* [TheOneFile_Verse online demo](https://multiverse.therecanonlybe.one/s/2ab95062-9d96-4e32-b373-d1994c210d82)
* *join from different browsers to see real time changes*
* [TheOneFile_Verse landing page](https://multiverse.therecanonlybe.one)
* [TheOneFile_Verse admin demo](https://therecanonlybe.one/theonefile_verse/demo-admin.html)

### Option 1: Easiest

```bash
docker run -d -p 10101:10101 -v theonefile-data:/app/data ghcr.io/gelatinescreams/theonefile_verse:latest
```

Or with docker compose, create a `docker-compose.yml`:

```yaml
services:
  theonefile_verse:
    image: ghcr.io/gelatinescreams/theonefile_verse:latest
    ports:
      - "10101:10101"
    volumes:
      - ./data:/app/data
    restart: unless-stopped
```

Then run:
```bash
docker compose up -d
```

Open `http://localhost:10101`

## Configuration

All settings are configured via the admin panel at `/admin`. On first run, you'll set up an admin account.

### .env

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `10101` | Server port |
| `DATA_DIR` | `./data` | Where settings and room data are stored |
| `REDIS_URL` | | Optional Redis connection for scaling |
| `CORS_ORIGIN` | | Comma separated list of allowed origins |
| `REQUIRE_WS_TOKEN` | `false` | Require WebSocket session tokens |
| `TRUSTED_PROXY_COUNT` | | Number of trusted reverse proxies for X Forwarded For |
| `TRUSTED_PROXIES` | | Comma separated list of trusted proxy IPs |
| `DEBUG_OIDC` | `false` | Enable OIDC debug logging (dev only) |


### TheOneFile_Verse Features
* **Current Version 1.8.6 BETA** **Further improvements to Network Auto Discovery scanner/editor one page setup**
  * See [changelog](changelog.md) for full 1.8.6 list of changes
  
*Now that most of the core TheOneFile_Verse development is done, I have begun breaking the code into a more production friendly hierarchical structure. This will be completed by 2.0 Stable.*

#### Core Collaboration
* Realtime sync via WebSocket
* Realtime chat per room with message persistence
* Typing indicators, message replies, @mentions
* Emoji picker and sound notifications
* Real time multi user cursor engine with smooth transitions
* Room based sessions with optional passwords
* Auto destruct rooms (time based or when empty) with countdown display
* Guest access controls per room
* All the functions of TheOneFile_Networkening

#### Full User Account System
* User registration with email verification
* Secure password login with Argon2id hashing
* Two factor authentication (TOTP) with backup codes **NEW 1.7**
* Email change with verification **NEW 1.7**
* Magic link login (passwordless authentication)
* Session management with device tracking
* Multiple active sessions per user
* Account lockout protection

#### Single Sign On (SSO/OIDC)
* Sign in with Authentik, Google, GitHub, Microsoft, or any OIDC provider
* Link multiple SSO providers to one account
* Auto account linking by email
* Configurable per provider settings
* Full OIDC spec compliance (JWT algorithm mapping, discovery validation, sub claim enforcement)
* Post login redirect persistence across SSO flows
* Secure account linking re verification

#### Real PING
* Overrides built in TheOneFileNetworkening "HTTP PING" with real server side methods
* New probe types: ICMP ping, TCP port check, HTTP/HTTPS, DNS and Multi Probe (all combined)
* Custom user ports
  
#### etwork Discovery
* Added "Discover Network Hosts" button to settings panel under Auto Status Checking section (at the bottom)
* Full subnet discovery with CIDR range input and preset common ranges
* Multiple range support
* Port scanning on discovered hosts across 70+ common ports covering infrastructure and self hosted services (more soon)
* Custom user ports
* Export hosts to canvas as nodes and racks with all scanned and edited information
* Admin only mode and public range restrictions available in Admin settings

#### Popular Service + selfh.st/icons Detection
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

#### DNS Detection
* Hosts running port 53 are probed further:) to identify the DNS software
* AdGuard Home detected via /control/status endpoint (should work with password protected instances)
* Pi-hole detected via /admin/api.php (v5) and /api/ (v6), (should work with password protected instances)
* Technitium detected via port 5380 presence

#### Docker Detection
* Looks for docker api, dockge, portainer etc
* "Deep Scan" button will popup next to host
* This will scan the host more indepth for containers running though docker IF api is not available
* Docker container names from "Deep Scan" are also added as tags
  
#### Automated Service Tagging
* Services column in Network Discovery table shows tags that will be saved with the host
* Named services (Jellyfin, Grafana, Dockge, etc.) automatic detection
* Generic port detection (Port 3003, Port 8810, etc.)
* Docker container names from "Deep Scan" are also added as tags

#### Email System
* SMTP configuration with TLS/STARTTLS support
* Email verification on signup
* Password reset via email
* Magic link authentication
* Room invitation emails
* Customizable email templates
* Email delivery logging
* Multiple SMTP configurations supported

#### Admin Dashboard
* Full user management (create, edit, deactivate, delete)
* Role based access control (admin, user, guest)
* OIDC provider configuration
* SMTP configuration management
* Email template customization
* Comprehensive audit logging
* Activity logs per room
* Email delivery logs
* System settings management

#### Security & Protection
* AES 256 GCM encryption for all secrets (including TOTP secrets and backup codes)
* PBKDF2 key derivation (600,000 iterations) **Enhanced 1.7**
* Argon2id password hashing
* TOTP two factor authentication (RFC 6238 compliant) **NEW 1.7**
* Secure HTTP only cookies with proper autocomplete attributes
* SameSite cookie policy
* HSTS headers on all responses
* WebSocket session tokens
* WebSocket connection rate limiting per IP
* IP based rate limiting
* Email rate limiting
* Configurable trusted proxy support with environment variable overrides **NEW 1.7**
* Custom admin path (security through obscurity but not everyone likes the default)
* Constant time token comparison with length padding
* SSRF protection on webhook URLs
* Automatic admin token cleanup
* Full HTML entity escaping on all user generated content
* CRLF injection prevention in email headers
* STARTTLS downgrade protection
* File upload size limits
* Generic error messages to prevent user enumeration

#### Responsive & Mobile
* Full responsive design across all pages (landing, auth, admin dashboard)

#### Rate Limiting
* Endpoint rate limiting (configurable window and max attempts)
* Email action rate limiting (signup, password reset, magic link)
* WebSocket token bucket rate limiting per message type

#### Authentication Modes
* Open registration
* Email verification required
* OIDC only (SSO required)
* Invite only (admin must create accounts)
* Closed (no new registrations)
* Guest room access controls

#### Full Api System [api.md](api.md)
* REST API with authentication
* API key management
* Webhook notifications for events

#### Backup & Recovery
* Manual and automatic backups
* Configurable backup intervals
* Backup retention policies
* One click restore

## How It Works
1. Server fetches the latest TheOneFile Networkening HTML from GitHub on startup or upload your own custom template.
2. When users create or join rooms, the HTML is served with collaboration scripts injected.
3. All edits sync in realtime via WebSocket.
4. Data can be saved in the room and can be export into a fully editable and portable version of The One File.
5. Or data can be exported in all popular editing formats.
6. Bring it back later and import the HTML, CSV, JSON, or MD right back into your TheOneFile_Verse room.