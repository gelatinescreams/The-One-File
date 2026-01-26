### TheOneFile_Verse

<p align="center">
  <img src="https://img.shields.io/badge/License-Unlicense-576169?style=for-the-badge&labelColor=01284b" alt="License: Unlicense">
  <img src="https://img.shields.io/github/v/release/gelatinescreams/The-One-File?style=for-the-badge&labelColor=01284b&color=576169&logo=github" alt="GitHub Release Version">
  <a href="https://github.com/gelatinescreams/The-One-File/tree/main/theonefile_verse">
  <img src="https://img.shields.io/github/v/release/gelatinescreams/The-One-File?style=for-the-badge&labelColor=01284b&color=576169&label=docker&logo=docker&logoColor=white" alt="Docker Ready">
  </a>
</p>

*As it turns out, there can be more than one*

![The One File Verse Mutli User Collaboration](https://raw.githubusercontent.com/gelatinescreams/The-One-File/refs/heads/main/assets/collab-preview.gif)

An easily deployable, Docker based, real time collaboration server with user accounts, email authentication, SSO, and role based access control. All configurable via a robust admin panel.

When you're done collaborating, each person can save their own portable copy. That file works exactly like the original TheOneFile: fully offline, self contained, editable anywhere. Import it back into the TheOneFile_Verse anytime to continue collaborating.

**AND/OR**

Rooms auto save your work, no manual exports required. Admins can run as many rooms as needed, a multiOneFileverse of parallel diagrams. Host it privately or open it to the internet (use tons of caution and a secure reverse proxy).

* [TheOneFile_Verse online demo](https://multiverse.therecanonlybe.one/s/b208667b-7a9e-4a18-ac98-5cb6e73bb669)
* *join from different browsers to see real time changes*
* [TheOneFile_Verse landing page](https://multiverse.therecanonlybe.one)

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
| `DEBUG_OIDC` | `false` | Enable OIDC debug logging (dev only) |


### TheOneFile_Verse Features

* **Current Version 1.5** **The Identity Update**  [changelog](changelog.md)

#### Core Collaboration
* Realtime sync via WebSocket
* Realtime chat per room
* Real time multi user cursor engine
* Room based sessions with optional passwords
* Auto destruct rooms (time based or when empty)
* Guest access controls per room
* All the functions of TheOneFile_Networkening

#### Full User Account System **NEW 1.5**
* User registration with email verification
* Secure password login with Argon2id hashing
* Magic link login (passwordless authentication)
* Session management with device tracking
* Multiple active sessions per user
* Account lockout protection

#### Single Sign On (SSO/OIDC) **NEW 1.5**
* Sign in with Authentik, Google, GitHub, Microsoft, or any OIDC provider
* Link multiple SSO providers to one account
* Auto account linking by email
* Configurable per provider settings

#### Email System **NEW 1.5**
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

#### Security & Protection **NEW 1.5**
* AES 256 GCM encryption for all secrets
* PBKDF2 key derivation (100,000 iterations)
* Argon2id password hashing
* CSRF token protection
* Secure HTTP only cookies
* SameSite cookie policy
* Production mode with HSTS
* WebSocket session tokens
* IP based rate limiting
* Email rate limiting
* Configurable trusted proxy support
* Custom admin path (security through obscurity but not everyone likes the default)

#### Rate Limiting **NEW 1.5**
* Endpoint rate limiting (configurable window and max attempts)
* Email action rate limiting (signup, password reset, magic link)
* WebSocket token bucket rate limiting per message type

#### Authentication Modes **NEW 1.5**
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
6. Bring it back later and import the HTML, CSV, JSON, or MD right back into your room.
