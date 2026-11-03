# TheOneFile Verse API Documentation

Base URL: `http://localhost:10101` (or your deployed instance)

## Authentication

### API Key Authentication

```
Authorization: Bearer yourapikey
```

API keys have granular permissions:
- `read`: view rooms, settings, logs, backups and export (GET endpoints)
- `write`: create and delete rooms, set view only or a room password, create and restore backups, run the asset sweep
- `admin`: everything above plus instance settings, auth settings, OIDC, SMTP and API keys

User management (`/api/admin/users`) always requires an admin session, never an API key.

---

## Public Endpoints

### Check Room Exists

```
GET /api/room/{roomId}/exists
```

**Response**
```json
{
  "exists": true,
  "hasPassword": false,
  "created": "2024-01-15T10:30:00.000Z",
  "destruct": {
    "mode": "time",
    "value": 86400000
  }
}
```

### Create Room

```
POST /api/room
Content-Type: application/json

{
  "creatorId": "optional uuid",
  "password": "optional room password",
  "destructMode": "time",
  "destructValue": 86400000,
  "topology": null
}
```

**Parameters**
| Field | Type | Description |
|-------|------|-------------|
| creatorId | string (UUID) | Optional. Auto generated if not provided |
| password | string | Optional. Minimum 4 characters |
| destructMode | string | `time`, `empty`, or `never` |
| destructValue | number | Milliseconds until destruction (max 30 days) |
| topology | object | Optional initial state |

**Response**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "/s/550e8400-e29b-41d4-a716-446655440000",
  "hasPassword": false
}
```

### Verify Room Password

```
POST /api/room/{roomId}/verify
Content-Type: application/json

{
  "password": "room password"
}
```

**Response**
```json
{
  "valid": true
}
```

### Delete Room (Creator Only)

```
DELETE /api/room/{roomId}
Content-Type: application/json

{
  "creatorId": "creator uuid"
}
```

**Response**
```json
{
  "deleted": true
}
```

### Room View-Only Lock

Marks a room read-only for everyone except its owner and instance admins. The flag is enforced in
**both** transports, the WebSocket write gate (`state` frames and 3D `furnOp`s) and
`PUT /api/room/{roomId}/scene3d`, through the same `canWrite(role, viewOnly)` policy, so it cannot
be bypassed by dropping to HTTP.

```
GET /api/room/{roomId}/view-only
```

Readable by anyone who can reach the room (the same fact is already on the `permissions` frame).
Rate limited to 60 requests / 60 s per IP, it answers `404` for an unknown room, so it is a
room-existence oracle like `GET /api/room/{roomId}/exists` and gets the same kind of ceiling. The
`PUT` has its own separate bucket of the same size.

**Response**
```json
{
  "viewOnly": true
}
```

```
PUT /api/room/{roomId}/view-only
Content-Type: application/json
x-csrf-token: <token>
Cookie: user_token=<session>

{
  "viewOnly": true
}
```

**Response**
```json
{
  "viewOnly": true,
  "notified": 3
}
```

`notified` is how many live sockets in the room were sent a fresh `permissions` frame (local
instance only, see the WebSocket section).

| Status | When |
|---|---|
| `400` | malformed room id, or `viewOnly` is not a boolean |
| `403` | failed CSRF, **or** the caller is not the room owner and not an instance admin. One message for all three of "not signed in", "not the owner" and "the room is ownerless", so this cannot be used to probe who owns a room |
| `404` | no such room |
| `413` | body over 1 KB |

Authorization is the same shape as `DELETE /api/room/{roomId}`: owner **or** instance admin, over a
user session cookie. Deliberately **not** `canWrite`, which is true for an ordinary editor in an
unlocked room and would therefore let any editor lock someone else's room. An **ownerless** room can
only be locked by an instance admin.

### 3D Scene (scene3d)

Every endpoint in this section returns **`404 {"error": "3D is disabled on this instance"}`** when
the `enable3d` instance setting is off.

Access is gated exactly like the WebSocket token endpoint: the room access cookie when the room has
a password, and the guest policy when it does not. Writes additionally enforce the **same role gate
as the WebSocket path**, a viewer, or a guest/editor in a view-only room, gets `403`. Identity for
that check comes from the **user session cookie only**. Rate limits are keyed by user id when
authenticated and by IP otherwise, so collaborators behind one NAT do not starve each other.

**Get Scene**
```
GET /api/room/{roomId}/scene3d
```

Returns the stored scene, or `{}` when the room has none.

**Save Scene**
```
PUT /api/room/{roomId}/scene3d
Content-Type: application/json
x-csrf-token: <token>
```

2 MB body cap (`413` over it, and the body is abandoned one chunk past the limit rather than
buffered whole). 120 requests / 60 s per identity per room; a `429` carries `Retry-After: 60`.

The scene is namespaced **per 2D document tab**, and each tab bucket carries an integer `rev` for
optimistic concurrency:

```json
{
  "version": 2,
  "rev": 7,
  "mpu": 0.05,
  "wireMode": "elevated",
  "tabs": {
    "main": {
      "furniture": [ { "id": "f1", "kind": "table", "x": 2000, "z": 1500, "rotY": 0, "scale": 1 } ],
      "heights":     { "node-1": 200 },
      "buried":      { "edge-1": 1 },
      "wallHeights": { "rect-1": 150 },
      "rev": 4
    }
  }
}
```

`mpu` and `wireMode` are room-global (view settings, plain last-write-wins). Send **only the tabs
you have touched plus the active tab**, a tab absent from `tabs` is never read and never written.
Tab keys are the 2D app's stable `documentTabs[i].id` (`main`, `tab-<ts>`), charset-restricted to
`[A-Za-z0-9_.:#-]{1,64}`. `__legacy` is reserved: a pre-tabs flat scene is folded into it.

Merge rule, applied per tab:

| incoming `tabs[k].rev` | server does |
|---|---|
| equals the stored rev | accept the bucket, stored rev becomes `rev + 1` |
| differs from the stored rev | **keep the server's bucket**, list `k` in `conflicts` |
| `k` absent | never read, never written |

Limits: 2000 furniture and 2000 keys per map **per tab**; 8000 furniture, 24000 map keys and 32
tabs **per scene**; furniture kinds `table`, `shelf`, `lamp`, `wall`, `plant`, `frame`, `model`;
world 4000 x 3000.

**Response**
```json
{
  "saved": true,
  "code": "aB3xQ_9z",
  "rev": 8,
  "tabs": { "main": { "rev": 5 } },
  "conflicts": ["tab-1737000000000"],
  "truncated": true,
  "droppedFurniture": 12,
  "droppedMapKeys": 3,
  "droppedByTab": { "tab-1737000000000": { "furn": 12, "keys": 3 } }
}
```

* `code` is this room's stable portable `3d:<code>` token.
* `conflicts` is present only when at least one bucket was refused; re-`GET` those tabs, replay
  your own unaccepted ops onto them, and save again against the rev you just adopted.
* `truncated` / `droppedFurniture` / `droppedMapKeys` appear only when a cap actually dropped
  something. `droppedByTab` says **where** the whole-scene budget had to cut, the tabs in the
  request are protected first, so the loss is usually in a tab the caller never opened.

**Errors**

| Status | Body | Meaning |
|---|---|---|
| `400` | `{"error": "Invalid JSON"}` / `{"error": "Scene must be an object"}` / `{"error": "Invalid scene"}` | malformed body |
| `403` | `{"error": "This room is view-only"}` | the role gate refused the write |
| `403` | `{"error": "Room password required"}` | missing or invalid room access cookie |
| `401` | `{"error": "Authentication required"}` | the room does not allow guests |
| **`409`** | `{"error": "scene-version-conflict"}` | a **flat (pre-v2) body with no `tabs` key** was sent over a scene that already has populated per-tab data. The client must reload; it must not keep saving. A `__legacy`-only stored scene deliberately does not trigger this |
| `413` | `{"error": "Scene too large"}` | over the 2 MB cap |
| `429` | `{"error": "Too many updates. Try again later."}` | plus `Retry-After: 60` |

**Resolve a Portable Scene Code**
```
GET /api/room/{roomId}/scene3d/by-code/{code}
```

Read-only. Resolves a `3d:<code>` carried by an imported One File into a scene the client can merge
into the tab that carries it. The 128-bit random code **is** the capability, and this never mutates
the room it is called on. Codes are `[A-Za-z0-9_-]{1,64}`. 30 requests / 60 s per identity per room;
a `429` carries `Retry-After: 60`.

Returns the sanitized scene object (with `code` stripped), `404 {"error": "Unknown scene code"}`, or
`404 {"error": "Unreadable scene"}`.

### 3D Assets

**Upload an Asset**
```
POST /api/room/{roomId}/asset
Content-Type: image/png | image/jpeg | image/webp | image/gif | model/gltf-binary
x-csrf-token: <token>

[raw bytes]
```

The body is the raw file, not multipart, not base64. The declared `Content-Type` is checked against
the payload's **magic bytes**, so a mislabelled file is rejected. Caps: **3 MB** for images, **12 MB**
for `.glb` models. The same access and write gate as the scene3d PUT applies.

**Response**
```json
{
  "hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}
```

**Errors**

| Status | Body | Meaning |
|---|---|---|
| `415` | `{"error": "Unsupported asset type"}` | `Content-Type` not in the allow-list |
| `415` | `{"error": "Content does not match declared type"}` | magic-byte check failed |
| `413` | `{"error": "Asset must be 8 bytes to 3 MB"}` (or `, 12 MB`) | over the per-type cap |
| **`413`** | `{"error": "..."}` from the quota gate | the room's `maxAssetsPerRoomMB` or the instance's `maxAssetsTotalGB` would be exceeded. Checked **before** hashing and before anything touches the disk. Blobs are content-addressed and deduped, so a re-upload the room does not yet reference is deliberately counted, over-counting is the safe direction. `0` on either setting means unlimited |
| `403` / `401` / `429` | | as for the scene3d PUT |

**Fetch an Asset**
```
GET /api/asset/{sha256}
```

The 256-bit content hash is the capability, so this needs no room context. Responds with the stored
bytes, the stored `Content-Type`, `Cache-Control: public, max-age=31536000, immutable` and
`X-Content-Type-Options: nosniff`. `404` when unknown or when 3D is disabled.

### Health

```
GET /api/health
```

**Response**
```json
{
  "status": "ok",
  "version": "2.0.0",
  "uptime": 86400,
  "components": { "database": "ok", "redis": "unavailable" },
  "cluster": {
    "redisConnected": false,
    "fanout": false,
    "instanceId": "8f2c1a09"
  },
  "rooms": 12
}
```

`status` is `degraded` when the database check fails. The `cluster` block is what tells one replica
from another when a room's roster or auto-destruct behaviour looks wrong: whether this process is
actually talking to Redis, whether cross-instance fan-out is enabled, and which instance answered.
`REDIS_URL`, credentials and key contents are deliberately never exposed.

### Get Theme Settings

```
GET /api/theme
```

**Response**
```json
{
  "forcedTheme": "user",
  "chatEnabled": true,
  "cursorSharingEnabled": true,
  "nameChangeEnabled": true
}
```

---

### Rooms

**Create Room** (`write`)
```
POST /api/admin/rooms
{ "password": "optional, 8+ chars", "destructMode": "time|empty|never", "destructValue": 86400000, "allowGuests": true }
```
Returns `{ id, url, hasPassword, destruct, allowGuests }`. Omitted destruct fields use the instance defaults.

**Set View Only** (`write`)
```
PUT /api/admin/rooms/:id/view-only
{ "viewOnly": true }
```

**Set or Remove Room Password** (`write`)
```
PUT /api/admin/rooms/:id/password
{ "password": "newpassword" }   or   { "password": null }
```

**Delete Room** (`write`)
```
DELETE /api/admin/rooms/:id
```

**List All Rooms**
```
GET /api/admin/rooms
GET /api/admin/rooms?q=searchterm
```

**Response**
```json
{
  "rooms": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "created": "2024-01-15T10:30:00.000Z",
      "lastActivity": "2024-01-15T12:00:00.000Z",
      "hasPassword": false,
      "connectedUsers": 2,
      "destruct": {
        "mode": "time",
        "value": 86400000
      }
    }
  ],
  "total": 1
}
```

**Delete Room**
```
DELETE /api/admin/rooms/{roomId}
```

**Response**
```json
{
  "deleted": true
}
```

### Settings

**Get Settings**
```
GET /api/admin/settings
```

**Response**
```json
{
  "instancePasswordEnabled": false,
  "instancePasswordSet": false,
  "updateIntervalHours": 24,
  "skipUpdates": false,
  "allowPublicRoomCreation": true,
  "maxRoomsPerInstance": 0,
  "defaultDestructMode": "time",
  "defaultDestructHours": 24,
  "forcedTheme": "user",
  "rateLimitEnabled": true,
  "rateLimitWindow": 60,
  "rateLimitMaxAttempts": 10,
  "chatEnabled": true,
  "cursorSharingEnabled": true,
  "nameChangeEnabled": true,
  "webhookEnabled": false,
  "webhookUrl": null,
  "backupEnabled": false,
  "backupIntervalHours": 24,
  "backupRetentionCount": 7
}
```

**Update Settings**
```
POST /api/admin/settings
Content-Type: application/json

{
  "chatEnabled": false,
  "webhookEnabled": true,
  "webhookUrl": "https://example.com/webhook"
}
```

Only include fields you want to update.

### Activity Logs

**Get Activity Logs**
```
GET /api/admin/activity-logs
GET /api/admin/activity-logs?room={roomId}
```

**Response**
```json
{
  "logs": [
    {
      "id": 1,
      "timestamp": "2024-01-15T10:30:00.000Z",
      "roomId": "550e8400-e29b-41d4-a716-446655440000",
      "userId": "user uuid",
      "userName": "Connor MacLeod",
      "eventType": "join",
      "ipAddress": "192.168.1.1"
    }
  ]
}
```

### Audit Logs

**Get Audit Logs**
```
GET /api/admin/audit-logs
GET /api/admin/audit-logs?q=searchterm
```

**Response**
```json
{
  "logs": [
    {
      "id": 1,
      "timestamp": "2024-01-15T10:30:00.000Z",
      "action": "room_deleted",
      "actor": "admin",
      "actorIp": "192.168.1.1",
      "targetType": "room",
      "targetId": "550e8400-e29b-41d4-a716-446655440000",
      "details": null
    }
  ]
}
```

### Backups

**List Backups**
```
GET /api/admin/backups
```

**Response**
```json
{
  "backups": [
    {
      "id": "backup uuid",
      "filename": "backup_2024-01-15T10-30-00.json",
      "createdAt": "2024-01-15T10:30:00.000Z",
      "sizeBytes": 15234,
      "roomCount": 5,
      "autoGenerated": false
    }
  ]
}
```

**Create Backup**
```
POST /api/admin/backups
```

**Response**
```json
{
  "success": true,
  "backup": {
    "id": "backup uuid",
    "filename": "backup_2024-01-15T10-30-00.json",
    "sizeBytes": 15234,
    "roomCount": 5
  }
}
```

**Download Backup**
```
GET /api/admin/backups/{backupId}/download
```

Returns the backup file as JSON download.

**Restore Backup**
```
POST /api/admin/backups/{backupId}/restore
```

**Response**
```json
{
  "success": true,
  "roomsRestored": 3
}
```

**Delete Backup**
```
DELETE /api/admin/backups/{backupId}
```

**Response**
```json
{
  "deleted": true
}
```

### Export

**Export All Data**
```
GET /api/admin/export
```

Returns a JSON file containing all rooms and settings.

**Response Structure**
```json
{
  "version": 1,
  "exportedAt": "2024-01-15T10:30:00.000Z",
  "rooms": [...],
  "settings": {...}
}
```

### API Keys

**List API Keys**
```
GET /api/admin/api-keys
```

**Response**
```json
{
  "keys": [
    {
      "id": "key uuid",
      "name": "My Integration",
      "permissions": ["read", "write"],
      "createdAt": "2024-01-15T10:30:00.000Z",
      "lastUsed": "2024-01-15T12:00:00.000Z",
      "expiresAt": null,
      "active": true
    }
  ]
}
```

**Create API Key**
```
POST /api/admin/api-keys
Content-Type: application/json

{
  "name": "My Integration",
  "permissions": ["read", "write"],
  "expiresInDays": 30
}
```

**Parameters**
| Field | Type | Description |
|-------|------|-------------|
| name | string | Required. Display name for the key |
| permissions | array | `read`, `write`, `admin` |
| expiresInDays | number | Optional. 0 or null for no expiration |

**Response**
```json
{
  "id": "key uuid",
  "key": "tof_a1b2c3d4e5f6...",
  "name": "My Integration",
  "permissions": ["read", "write"]
}
```

> **Important**: The `key` value is only returned once at creation. Store it securely.

**Revoke API Key**
```
DELETE /api/admin/api-keys/{keyId}
```

**Response**
```json
{
  "revoked": true
}
```

### Invites

Used when the instance auth mode is `invite_only`. Only the SHA-256 of an invite code is
stored, so **the raw code is returned exactly once, in the create response**, there is no way
to read it back afterwards. All three endpoints require an authenticated admin session
(`__Host-user_token` / `user_token` cookie); an API key is not accepted.

These endpoints are also driven from the admin dashboard: **Authentication → Invite Codes**
(list, create with an optional expiry, delete). The list there shows only the invite's id and
status, there is no code to show, because the server never stored one.

**List Invites**
```
GET /api/admin/invites
```

**Response**, never includes `codeHash`.
```json
{
  "invites": [
    {
      "id": "invite uuid",
      "email": "invitee@example.com",
      "createdBy": "admin user uuid",
      "createdAt": "2026-09-18T12:00:00.000Z",
      "expiresAt": "2026-09-25T12:00:00.000Z",
      "usedAt": null,
      "usedBy": null
    }
  ]
}
```

**Create Invite**
```
POST /api/admin/invites
Content-Type: application/json
```
```json
{
  "email": "invitee@example.com",
  "expiresInDays": 7
}
```

Both fields are optional. `email` binds the code to one address, registration with any other
address is refused. `expiresInDays` must be between `1` and `365`; omit it or send `null` for a
code that never expires.

**Response**
```json
{
  "id": "invite uuid",
  "code": "the raw invite code - shown once, never again",
  "expiresAt": "2026-09-25T12:00:00.000Z"
}
```

**Revoke Invite**
```
DELETE /api/admin/invites/{inviteId}
```

**Response**
```json
{
  "success": true
}
```
Returns `404` if the invite does not exist. Revoking is permanent; an already-used invite
cannot be reused regardless.

### Asset Storage

**Sweep Orphaned Assets**
```
POST /api/admin/assets/sweep
```

Runs the 3D asset garbage collector immediately. The same sweep also runs on a 6 hour timer.
Requires an admin session or an `admin`-scoped API key. CSRF is enforced for the
**cookie-authenticated admin only**, an API key is a bearer credential a browser never attaches
cross-site.

The 24 hour grace period is **not** settable from the request: a caller-supplied `0` would race
uploads whose room link has not landed yet. An asset that any stored 3D scene or any portable
`3d:<code>` snapshot still names by hash is never reaped.

**Response**
```json
{
  "success": true,
  "scanned": 12,
  "stamped": 3,
  "deleted": 2,
  "retainedBySnapshot": 1,
  "errors": 0
}
```

Logged to the audit log as `asset_sweep`.

### Source Management

**Change Source Mode**
```
POST /api/admin/source-mode
Content-Type: application/json

{
  "mode": "github"
}
```

Modes: `github` (auto update from GitHub) or `local` (manual upload)

**Trigger GitHub Update**
```
POST /api/admin/update
```

**Response**
```json
{
  "success": true,
  "size": 245678
}
```

**Upload Local HTML**
```
POST /api/admin/upload-html
Content-Type: multipart/form-data

file: [HTML file]
```

**Response**
```json
{
  "success": true,
  "size": 245678,
  "edition": "networkening"
}
```

---

### Sign Up Approval

With auth mode `approval`, new accounts are created inactive and wait for an admin. Admin session only.
```
GET  /api/admin/users              each user has "pendingApproval": true|false
POST /api/admin/users/:id/approve  activates the account
POST /api/admin/users/:id/reject   deletes the pending account
```
A pending user who signs in with the right password gets `"Your account is waiting for administrator approval."`.

### Your Sessions

```
GET    /api/auth/sessions        your sessions; the one making the call has "current": true
DELETE /api/auth/sessions/:id    sign out one of your own sessions
DELETE /api/auth/sessions        sign out everywhere
```

---

## WebSocket API

```
ws://localhost:10101/ws/{roomId}
```

### Message Types

**Join Room**
```json
{
  "type": "join",
  "user": {
    "id": "user uuid",
    "name": "Connor MacLeod",
    "color": "#e63946"
  }
}
```

**Leave Room**
```json
{
  "type": "leave",
  "userId": "user uuid"
}
```

**Presence Update**
```json
{
  "type": "presence",
  "userId": "user uuid",
  "selectedNodes": ["node-1", "node-2"],
  "editingNode": "node-1",
  "currentTab": "Main"
}
```

**State Sync**
```json
{
  "type": "state",
  "state": {
    "nodeData": {...},
    "edgeData": {...},
    "imageData": {...},
    ...
  }
}
```

**Cursor Position**
```json
{
  "type": "cursor",
  "userId": "user uuid",
  "x": 1500,
  "y": 1200,
  "isCanvasCoords": true
}
```

**Chat Message**
```json
{
  "type": "chat",
  "userId": "user uuid",
  "userName": "Connor MacLeod",
  "userColor": "#e63946",
  "text": "Hello everyone!",
  "timestamp": 1705312200000
}
```

### Server Messages

**Initial State**
```json
{
  "type": "initial-state",
  "state": {...}
}
```

**User List**
```json
{
  "type": "users",
  "users": [...]
}
```

**Name Rejected**
```json
{
  "type": "name-rejected",
  "reason": "Name already taken in this room"
}
```

With `REDIS_FANOUT` enabled the rejection can come from **another instance**, so its provenance is
no longer necessarily "somebody in your own tab list". The cluster-wide check is advisory, there
is no distributed lock, so two simultaneous joins on different instances can both pass.

**Permissions**

Sent unconditionally in the `join` handler, before the join is fanned out, so guests and the
tokenless path receive it too, **and again, out of band, to every socket in the room whenever
`PUT /api/room/{roomId}/view-only` flips the lock** (`websocket.broadcastRoomPermissions`). A
client must therefore treat this frame as idempotent and re-appliable at any time, not only once
per join.

```json
{
  "type": "permissions",
  "role": "editor",
  "canWrite": true,
  "viewOnly": false,
  "pingIntervalMs": 60000
}
```

| Field | Meaning |
|---|---|
| `role` | `owner` \| `admin` \| `editor` \| `guest` \| `viewer`. Resolved server-side from the ws-session token, or, on the **tokenless** path, from the HTTP user session cookie presented at upgrade, and **pinned for the session**: an ownership change mid-session needs a reconnect |
| `canWrite` | whether this connection may send mutating frames. `viewOnly` is re-resolved at apply time (5 s memo), so this can change without a reconnect |
| `viewOnly` | whether the **room** is locked, independent of this connection's role. `canWrite: false` with `viewOnly: false` means "you personally may not write"; the owner sees `canWrite: true` with `viewOnly: true` |
| `pingIntervalMs` | see below |

The out-of-band broadcast is **instance-local**: it is not fanned out over Redis. Every instance
reads the same `viewOnly` row and enforces it for its own sockets within the 5 s memo, so a peer
instance's clients see the lock take effect on their next write attempt, up to 5 s later, rather
than instantly.

**Auth OK**
```json
{
  "type": "auth-ok",
  "pingIntervalMs": 60000
}
```

**`pingIntervalMs`, server-advertised heartbeat.** `WS_PING_INTERVAL_MS = max(15000,
floor(WS_IDLE_TIMEOUT * 1000 / 2))`, i.e. 45000-127500 ms given the 90-255 s clamp on
`WS_IDLE_TIMEOUT`. It rides **both** `auth-ok` and `permissions`. A client should send
`{"type":"ping"}` at least this often or Bun's `idleTimeout` reaps the socket; the browser client
re-arms its timer from any frame carrying the field (validated to 5-300 s, falling back to 45 s,
and a no-op when unchanged so a `permissions` frame per reconnect does not churn the timer). `ping`
is answered with `pong` and is exempt from the join gate.

**Error**

```json
{
  "type": "error",
  "code": "forbidden",
  "error": "This room is view-only, your change was not saved.",
  "messageType": "state"
}
```

| `code` | When | Notes |
|---|---|---|
| `forbidden` | a mutating frame (`state`, or a 3D `furnOp` riding the `cursor` channel) from a connection whose role may not write, or in a view-only room | Sent **to the sender only**. Nothing is broadcast and nothing is persisted. `messageType` echoes the rejected frame's type. Because the client's state poll retries continuously, the browser client folds these into one keyed persistent warning bar rather than stacking toasts |
| `join-required` | any message type other than `join` or `ping` from a socket that has not joined | |
| `rate-limited` | a `furnOp` dropped by its own token bucket (60 burst / 30 refill, separate from the 15/s `cursor` bucket) | Carries `channel: "furnOp"`, `retryAfterMs`, and `op`, the exact dropped op, **omitted when it serializes past 1 KB**. Generic non-`furnOp` throttling instead sends the older `{"type":"rate-limited","messageType":"..."}` frame |
| `room-full` | the room is at `MAX_ROOM_CONNECTIONS` (default 64, `0` disables) | Sent immediately before the socket is closed with code **`4008`**. A client must **not** treat 4008 as a transient disconnect and burn its reconnect budget on it, surface a manual reconnect instead |

Non-`state` frames are capped at **1024 bytes** on the wire; anything larger is dropped silently,
so a 3D client must measure its op and fall back to the debounced HTTP save when it does not fit.

### Removed message types

**`patch`, removed.** The server no longer relays it and the browser client ignores it
(`public/collab.js`). It was never emitted by any client, yet the receiving side applied it as
a **full state replacement**, while server-side it was only string-sanitized, never put
through the structural validation `state` gets, and never persisted. Send topology changes as
`state`. A client that still sends `patch` will simply have the message dropped.

---

## Rate Limiting

When rate limiting is enabled, endpoints return `429 Too Many Requests` if limits are exceeded.

Default limits:
- 10 attempts per 60 seconds per IP per endpoint

Per-endpoint overrides:

| Endpoint | Budget | Key |
|---|---|---|
| `PUT /api/room/{id}/scene3d` | 120 / 60 s | user id when authenticated, IP otherwise |
| `GET /api/room/{id}/scene3d/by-code/{code}` | 30 / 60 s | user id when authenticated, IP otherwise |
| `POST /api/room/{id}/asset` | the default | user id when authenticated, IP otherwise |

The 3D endpoints need the headroom because scene saves are debounced at 600 ms client-side, and
they are keyed by identity rather than purely by IP so that a dozen collaborators behind one NAT do
not share and starve a single bucket. All three send **`Retry-After: 60`** with their `429`, so a
client can back off for exactly the remaining window instead of guessing.

Response:
```json
{
  "error": "Too many attempts. Try again later."
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": "Error message description"
}
```

Common HTTP status codes:
- `400` Bad Request (invalid input)
- `401` Unauthorized (missing or invalid auth)
- `403` Forbidden (insufficient permissions)
- `404` Not Found
- `429` Too Many Requests (rate limited)
- `500` Internal Server Error

---

## Webhook Events

When webhooks are enabled, POST requests are sent to your configured URL.

**Room Created**
```json
{
  "event": "room_created",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "data": {
    "roomId": "550e8400-e29b-41d4-a716-446655440000",
    "hasPassword": false,
    "destructMode": "time",
    "creatorId": "creator uuid"
  }
}
```
