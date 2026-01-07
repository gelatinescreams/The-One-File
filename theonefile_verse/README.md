### TheOneFile_Verse 

<p align="center">
  <img src="https://img.shields.io/badge/License-Unlicense-576169?style=for-the-badge&labelColor=01284b" alt="License: Unlicense">
  <img src="https://img.shields.io/github/v/release/gelatinescreams/The-One-File?style=for-the-badge&labelColor=01284b&color=576169&logo=github" alt="GitHub Release Version">
  <a href="https://github.com/gelatinescreams/The-One-File/tree/main/theonefile_verse">
  <img src="https://img.shields.io/github/v/release/gelatinescreams/The-One-File?style=for-the-badge&labelColor=01284b&color=576169&label=docker&logo=docker&logoColor=white" alt="Docker Ready">
  </a>
</p>

*As it turns out, there can be more than one*

![The One File Verse Mutli User Collaboration](assets/https://raw.githubusercontent.com/gelatinescreams/The-One-File/refs/heads/main/assets/collab-preview.gif)

An easily deployable, Docker based, real time collaboration wrapper that enables multiple users to work together!

When you're done collaborating, each person can save their own portable copy. That file works exactly like the original TheOneFile: fully offline, self contained, editable anywhere. Import it back into the TheOneFile_Verse anytime to continue collaborating.

**AND/OR**

Rooms auto save your work, no manual exports required. Admins can run as many rooms as needed, a multiOneFileverse of parallel diagrams. Host it privately or open it to the internet (use tons of caution and a secure reverse proxy) with built in password protection and Argon2id encryption.

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

### Option 2: Build from Source

```bash
git clone https://github.com/gelatinescreams/The-One-File.git
cd The-One-File/theonefile_verse
docker-compose up -d
```

### Option 3: Direct with Bun

```bash
# Install Bun if you don't have it
curl -fsSL https://bun.sh/install | bash

# Clone and run
git clone https://github.com/gelatinescreams/The-One-File.git
cd The-One-File/theonefile_verse
bun run src/index.ts
```

## Configuration

All settings are configured via the admin panel at `/admin`. On first run, you'll set up an admin password.

### .env

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `10101` | Server port |
| `DATA_DIR` | `./data` | Where settings and room data are stored |

Admin panel settings for:
* theOnefile update interval from github. *always downloads latest version*
* instance password. *lock the entire install down. no public access*
* theme
* default room settings


### TheOneFile

[TheOneFile features available here](https://github.com/gelatinescreams/The-One-File)

### TheOneFile_Verse
- Full admin panel
- Realtime sync via WebSocket
- Realtime chat **1.1** [changelog](changelog.md)
- Real time mutli user cursor engine **1.1** [changelog](changelog.md)
- Room based sessions with optional passwords
- Auto destruct rooms
- All the functions of TheOneFile
- Argon2id password hashing

## How It Works
1. Server fetches the latest TheOneFile Networkening HTML from GitHub on startup
2. When users create or join rooms, the HTML is served with collaboration scripts injected
3. All edits sync in realtime via WebSocket
