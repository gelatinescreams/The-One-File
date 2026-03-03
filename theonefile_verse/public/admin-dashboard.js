(function() {
  'use strict';
  var pageData = JSON.parse((document.getElementById('page-data') || {}).textContent || '{}');
  var ADMIN_PATH = pageData.adminPath || 'admin';
  var forcedTheme = null;

  function getTheme() {
    if (forcedTheme && forcedTheme !== 'user') return forcedTheme;
    return localStorage.getItem('theme') || 'dark';
  }

  function setTheme(theme) {
    if (!forcedTheme || forcedTheme === 'user') {
      localStorage.setItem('theme', theme);
    }
    document.documentElement.setAttribute('data-theme', theme);
    document.getElementById('theme-icon').textContent = theme === 'dark' ? '\u2600' : '\u263E';
  }

  function toggleTheme() {
    if (forcedTheme && forcedTheme !== 'user') return;
    setTheme(getTheme() === 'dark' ? 'light' : 'dark');
  }

  function updateThemeToggleVisibility() {
    var btn = document.getElementById('theme-toggle');
    if (forcedTheme && forcedTheme !== 'user') {
      btn.style.display = 'none';
    } else {
      btn.style.display = 'block';
    }
  }

  setTheme(getTheme());

  fetch('/api/theme')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.forcedTheme && data.forcedTheme !== 'user') {
        forcedTheme = data.forcedTheme;
        setTheme(forcedTheme);
      }
      updateThemeToggleVisibility();
    })
    .catch(function() {
      updateThemeToggleVisibility();
    });
  function esc(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }
  var rooms = [];
  var selected = new Set();
  var settings = {};
  var totalRooms = 0;
  var searchTimeout = null;
  var users = [];
  var authSettings = {};
  var oidcProviders = [];
  var smtpConfigs = [];
  var emailLogs = [];
  function showTab(name) {
    document.querySelectorAll('.tab').forEach(function(t) {
      t.classList.remove('active');
    });
    document.querySelectorAll('.tab-content').forEach(function(t) {
      t.classList.remove('active');
    });
    document.querySelector('.tab-content#tab-' + name).classList.add('active');
    document.querySelector('.tab[data-tab="' + name + '"]').classList.add('active');

    if (name === 'settings') loadSettings();
    if (name === 'logs') {
      loadActivityLogs();
      loadAuditLogs();
    }
    if (name === 'backups') loadBackups();
    if (name === 'apikeys') loadApiKeys();
    if (name === 'users') loadUsers();
    if (name === 'auth') {
      loadAuthSettings();
      loadOidcProviders();
      loadSmtpConfigs();
      loadEmailTemplates();
      loadEmailLogs();
    }
  }

  async function loadData(query) {
    query = query || '';
    try {
      var url = query
        ? '/api/admin/rooms?q=' + encodeURIComponent(query)
        : '/api/admin/rooms';
      var res = await fetch(url);
      if (!res.ok) {
        if (res.status === 401) {
          window.location.href = '/' + ADMIN_PATH + '/login';
        }
        return;
      }
      var data = await res.json();
      rooms = data.rooms || data;
      totalRooms = data.total || rooms.length;
      renderStats();
      renderRooms();
      updateBulkUI();
    } catch (e) {
      console.error(e);
    }
  }

  function searchRooms(q) {
    if (searchTimeout) clearTimeout(searchTimeout);
    searchTimeout = setTimeout(function() { loadData(q); }, 300);
  }

  async function loadSettings() {
    try {
      var res = await fetch('/api/admin/settings');
      if (!res.ok) return;
      settings = await res.json();
      renderSettings();
    } catch (e) {
      console.error(e);
    }
  }

  function renderSettings() {
    document.getElementById('toggle-instance-lock').classList.toggle('active', settings.instancePasswordEnabled);
    document.getElementById('toggle-public-rooms').classList.toggle('active', settings.allowPublicRoomCreation);
    document.getElementById('toggle-rate-limit').classList.toggle('active', settings.rateLimitEnabled !== false);
    document.getElementById('update-interval').value = settings.updateIntervalHours || 0;
    document.getElementById('default-destruct-mode').value = settings.defaultDestructMode || 'time';
    document.getElementById('default-destruct-hours').value = settings.defaultDestructHours || 24;
    document.getElementById('max-rooms').value = settings.maxRoomsPerInstance || 0;
    document.getElementById('forced-theme').value = settings.forcedTheme || 'user';
    document.getElementById('rate-limit-attempts').value = settings.rateLimitMaxAttempts || 10;
    document.getElementById('rate-limit-window').value = settings.rateLimitWindow || 60;
    document.getElementById('rate-limit-options').style.display = settings.rateLimitEnabled !== false ? 'flex' : 'none';
    document.getElementById('instance-pwd-row').style.display = settings.instancePasswordEnabled ? 'flex' : 'none';
    document.getElementById('instance-pwd-status').textContent = settings.instancePasswordSet ? 'Password is set' : 'No password set';

    if (settings.envAdminPasswordSet) {
      document.getElementById('toggle-instance-lock').style.opacity = '0.5';
      document.getElementById('toggle-instance-lock').setAttribute('data-disabled', 'true');
    }

    document.getElementById('toggle-chat').classList.toggle('active', settings.chatEnabled !== false);
    document.getElementById('toggle-cursor').classList.toggle('active', settings.cursorSharingEnabled !== false);
    document.getElementById('toggle-namechange').classList.toggle('active', settings.nameChangeEnabled !== false);
    document.getElementById('toggle-webhook').classList.toggle('active', settings.webhookEnabled);
    document.getElementById('webhook-url').value = settings.webhookUrl || '';
    document.getElementById('webhook-url-row').style.display = settings.webhookEnabled ? 'flex' : 'none';
    document.getElementById('toggle-backup').classList.toggle('active', settings.backupEnabled);
    document.getElementById('backup-interval').value = settings.backupIntervalHours || 24;
    document.getElementById('backup-retention').value = settings.backupRetentionCount || 7;
    document.getElementById('backup-options').style.display = settings.backupEnabled ? 'flex' : 'none';
    document.getElementById('admin-path').value = settings.adminPath || 'admin';
    document.getElementById('admin-path-info').style.display = 'flex';
    document.getElementById('admin-path-current').textContent = 'Current path: /' + (settings.adminPath || 'admin');
    updateSourceUI();
  }

  async function saveAdminPath() {
    var newPath = document.getElementById('admin-path').value.trim();
    if (!newPath) {
      showStatus('Admin path cannot be empty', 'error');
      return;
    }
    if (!/^[a-zA-Z0-9_-]+$/.test(newPath)) {
      showStatus('Admin path can only contain letters, numbers, hyphens, and underscores', 'error');
      return;
    }
    if (newPath.length < 2) {
      showStatus('Admin path must be at least 2 characters', 'error');
      return;
    }
    var reserved = ['api', 's', 'ws', 'auth', 'public', 'static', 'assets'];
    if (reserved.includes(newPath.toLowerCase())) {
      showStatus('This path is reserved', 'error');
      return;
    }
    try {
      var res = await fetch('/api/admin/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ adminPath: newPath })
      });
      var data = await res.json();
      if (!res.ok) {
        showStatus(data.error || 'Failed to save', 'error');
        return;
      }
      document.getElementById('admin-path-current').textContent = 'Current path: /' + newPath;
      showStatus('Admin path saved! Redirecting to new path...', 'success');
      setTimeout(function() {
        window.location.href = '/' + newPath;
      }, 1500);
    } catch (e) {
      showStatus('Error saving admin path', 'error');
    }
  }

  async function saveRateLimitSettings() {
    var attempts = parseInt(document.getElementById('rate-limit-attempts').value) || 10;
    var windowVal = parseInt(document.getElementById('rate-limit-window').value) || 60;
    await fetch('/api/admin/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rateLimitMaxAttempts: attempts, rateLimitWindow: windowVal })
    });
    showStatus('Rate limit settings saved', 'success');
  }

  async function saveForcedTheme() {
    var val = document.getElementById('forced-theme').value;
    await fetch('/api/admin/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ forcedTheme: val })
    });
    showStatus('Theme setting saved', 'success');
  }

  async function toggleSetting(key) {
    if (key === 'instancePasswordEnabled' && settings.envAdminPasswordSet) return;
    settings[key] = !settings[key];
    renderSettings();
    await fetch('/api/admin/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [key]: settings[key] })
    });
    showStatus('Setting updated', 'success');
  }

  async function setInstancePassword() {
    var pwd = document.getElementById('instance-password').value;
    if (pwd.length < 10) {
      showStatus('Password must be at least 10 characters', 'error');
      return;
    }
    await fetch('/api/admin/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ instancePassword: pwd })
    });
    document.getElementById('instance-password').value = '';
    showStatus('Password updated', 'success');
    loadSettings();
  }

  async function saveUpdateInterval() {
    var val = parseInt(document.getElementById('update-interval').value) || 0;
    await fetch('/api/admin/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ updateIntervalHours: val })
    });
    showStatus('Update interval saved', 'success');
  }

  async function triggerUpdate() {
    var btn = document.getElementById('update-btn');
    btn.disabled = true;
    btn.textContent = 'Updating...';
    try {
      var res = await fetch('/api/admin/update', { method: 'POST' });
      var data = await res.json();
      if (data.success) {
        showStatus('Updated successfully (' + Math.round(data.size / 1024) + 'KB)', 'success');
        loadSettings();
      } else {
        showStatus(data.error || 'Update failed', 'error');
      }
    } catch (e) {
      showStatus('Update failed', 'error');
    }
    btn.disabled = false;
    btn.textContent = 'Update Now';
  }

  async function changeSourceMode() {
    var mode = document.getElementById('source-mode').value;
    try {
      var res = await fetch('/api/admin/source-mode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: mode })
      });
      var data = await res.json();
      if (data.success) {
        showStatus('Source mode changed to ' + mode, 'success');
        loadSettings();
      } else {
        showStatus(data.error || 'Failed to change mode', 'error');
      }
    } catch (e) {
      showStatus('Failed to change mode', 'error');
    }
  }

  async function uploadFile() {
    var input = document.getElementById('upload-file');
    if (!input.files || !input.files[0]) return;
    var file = input.files[0];
    var formData = new FormData();
    formData.append('file', file);
    try {
      var res = await fetch('/api/admin/upload-html', { method: 'POST', body: formData });
      var data = await res.json();
      if (data.success) {
        showStatus('Uploaded successfully (' + Math.round(data.size / 1024) + 'KB), ' + data.edition + ' edition', 'success');
        loadSettings();
      } else {
        showStatus(data.error || 'Upload failed', 'error');
      }
    } catch (e) {
      showStatus('Upload failed', 'error');
    }
    input.value = '';
  }

  function updateSourceUI() {
    var isLocal = settings.skipUpdates;
    document.getElementById('source-mode').value = isLocal ? 'local' : 'github';
    document.getElementById('github-settings').style.display = isLocal ? 'none' : 'flex';
    document.getElementById('github-update-row').style.display = isLocal ? 'none' : 'flex';
    document.getElementById('upload-row').style.display = isLocal ? 'flex' : 'none';
    var sizeKB = settings.currentFileSize ? Math.round(settings.currentFileSize / 1024) : 0;
    var edition = settings.currentFileEdition || 'unknown';
    var source = isLocal ? 'Local upload' : 'GitHub';
    document.getElementById('current-file-info').textContent = sizeKB + 'KB, ' + edition + ' edition (' + source + ')';
  }

  async function saveRoomDefaults() {
    await fetch('/api/admin/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        defaultDestructMode: document.getElementById('default-destruct-mode').value,
        defaultDestructHours: parseInt(document.getElementById('default-destruct-hours').value) || 24,
        maxRoomsPerInstance: parseInt(document.getElementById('max-rooms').value) || 0
      })
    });
    showStatus('Room defaults saved', 'success');
  }

  function showStatus(msg, type) {
    var el = document.getElementById('settings-status');
    el.innerHTML = '<div class="status-msg ' + type + '">' + msg + '</div>';
    setTimeout(function() { el.innerHTML = ''; }, 3000);
  }

  function showAuthStatus(msg, type) {
    var el = document.getElementById('auth-status');
    el.innerHTML = '<div class="status-msg ' + type + '">' + msg + '</div>';
    setTimeout(function() { el.innerHTML = ''; }, 3000);
  }

  function renderStats() {
    var active = rooms.filter(function(r) { return r.connectedUsers > 0; }).length;
    var withPwd = rooms.filter(function(r) { return r.hasPassword; }).length;
    var totalUsers = rooms.reduce(function(a, r) { return a + r.connectedUsers; }, 0);
    document.getElementById('stats').innerHTML =
      '<div class="stat-card"><div class="stat-value">' + rooms.length + '</div><div class="stat-label">Total Rooms</div></div>' +
      '<div class="stat-card"><div class="stat-value">' + active + '</div><div class="stat-label">Active</div></div>' +
      '<div class="stat-card"><div class="stat-value">' + withPwd + '</div><div class="stat-label">Protected</div></div>' +
      '<div class="stat-card"><div class="stat-value">' + totalUsers + '</div><div class="stat-label">Users Online</div></div>';
  }

  function renderRooms() {
    if (rooms.length === 0) {
      document.getElementById('room-list').innerHTML =
        '<div class="empty-state"><h3>No rooms yet</h3><p>Rooms will appear here when created</p></div>';
      return;
    }

    var html = '<div class="room-header">' +
      '<input type="checkbox" class="room-checkbox" data-action="toggleAll" ' +
      (selected.size === rooms.length && rooms.length > 0 ? 'checked' : '') + '>' +
      '<span>Room</span><span>Users</span><span>Created</span><span>Password</span><span>Actions</span></div>';

    rooms.forEach(function(r) {
      var created = new Date(r.created).toLocaleDateString();
      var usersHtml = r.connectedUsers > 0
        ? '<span class="badge badge-green">' + r.connectedUsers + '</span>'
        : '<span class="badge badge-gray">0</span>';
      var pwd = r.hasPassword
        ? '<span class="badge badge-yellow">Yes</span>'
        : '<span class="badge badge-gray">No</span>';
      var isSelected = selected.has(r.id);

      html += '<div class="room-row' + (isSelected ? ' selected' : '') + '">' +
        '<input type="checkbox" class="room-checkbox" ' + (isSelected ? 'checked' : '') +
        ' data-action="toggleSelect" data-id="' + r.id + '">' +
        '<div><div class="room-name">Room</div><div class="room-id">' + r.id + '</div></div>' +
        '<div>' + usersHtml + '</div>' +
        '<div>' + created + '</div>' +
        '<div>' + pwd + '</div>' +
        '<div class="room-actions">' +
        '<button class="btn btn-secondary btn-sm" data-action="viewRoom" data-id="' + r.id + '">View</button>' +
        '<button class="btn btn-primary btn-sm" data-action="joinRoom" data-id="' + r.id + '">Join</button>' +
        '<button class="btn btn-danger btn-sm" data-action="deleteRoom" data-id="' + r.id + '">Del</button>' +
        '</div></div>';
    });

    document.getElementById('room-list').innerHTML = html;
  }

  function toggleSelect(id, checked) {
    if (checked) {
      selected.add(id);
    } else {
      selected.delete(id);
    }
    updateBulkUI();
    renderRooms();
  }

  function toggleAll(checked) {
    if (checked) {
      rooms.forEach(function(r) { selected.add(r.id); });
    } else {
      selected.clear();
    }
    updateBulkUI();
    renderRooms();
  }

  function clearSelection() {
    selected.clear();
    updateBulkUI();
    renderRooms();
  }

  function updateBulkUI() {
    var bulk = document.getElementById('bulk-actions');
    var count = document.getElementById('selected-count');
    if (selected.size > 0) {
      bulk.classList.add('active');
      count.textContent = selected.size + ' selected';
    } else {
      bulk.classList.remove('active');
    }
  }

  async function deleteSelected() {
    if (selected.size === 0) return;
    if (!confirm('Delete ' + selected.size + ' room(s) permanently?')) return;
    for (var id of selected) {
      try {
        await fetch('/api/admin/rooms/' + id, { method: 'DELETE' });
      } catch (e) {
      }
    }
    selected.clear();
    loadData();
  }

  function viewRoom(id) {
    var room = rooms.find(function(r) { return r.id === id; });
    if (!room) return;

    var destruct = 'Never';
    if (room.destruct.mode === 'time') {
      var h = room.destruct.value / 3600000;
      destruct = h < 1
        ? Math.round(h * 60) + ' min'
        : h < 24
          ? h + ' hours'
          : Math.round(h / 24) + ' days';
    } else if (room.destruct.mode === 'empty') {
      destruct = 'When empty';
    }

    document.getElementById('modal-title').textContent = 'Room Details';
    document.getElementById('modal-body').innerHTML =
      '<div class="info-row"><span class="info-label">Room ID</span>' +
      '<span class="info-value" style="font-family:monospace;font-size:12px">' + room.id + '</span></div>' +
      '<div class="info-row"><span class="info-label">Created</span>' +
      '<span class="info-value">' + new Date(room.created).toLocaleString() + '</span></div>' +
      '<div class="info-row"><span class="info-label">Last Activity</span>' +
      '<span class="info-value">' + new Date(room.lastActivity).toLocaleString() + '</span></div>' +
      '<div class="info-row"><span class="info-label">Connected Users</span>' +
      '<span class="info-value">' + room.connectedUsers + '</span></div>' +
      '<div class="info-row"><span class="info-label">Password Protected</span>' +
      '<span class="info-value">' + (room.hasPassword ? 'Yes' : 'No') + '</span></div>' +
      '<div class="info-row"><span class="info-label">Self-Destruct</span>' +
      '<span class="info-value">' + destruct + '</span></div>' +
      '<div style="margin-top:20px;display:flex;gap:12px;flex-wrap:wrap">' +
      '<button class="btn btn-primary" data-action="joinRoom" data-id="' + room.id + '">Join Room</button>' +
      '<button class="btn btn-danger" data-action="deleteRoom" data-id="' + room.id + '">Delete Room</button>' +
      '</div>';

    document.getElementById('room-modal').classList.add('active');
  }

  function closeModal() {
    document.getElementById('room-modal').classList.remove('active');
  }

  function joinRoom(id) {
    window.open('/s/' + id, '_blank');
  }

  async function deleteRoom(id) {
    if (!confirm('Delete this room permanently?')) return;
    try {
      var res = await fetch('/api/admin/rooms/' + id, { method: 'DELETE' });
      if (res.ok) {
        selected.delete(id);
        loadData();
      } else {
        alert('Failed to delete room');
      }
    } catch (e) {
      alert('Error deleting room');
    }
  }

  async function logout() {
    await fetch('/api/logout', { method: 'POST', credentials: 'include' });
    window.location.href = '/';
  }

  document.getElementById('room-modal').addEventListener('click', function(e) {
    if (e.target.id === 'room-modal') closeModal();
  });
  document.getElementById('apikey-modal').addEventListener('click', function(e) {
    if (e.target.id === 'apikey-modal') closeApiKeyModal();
  });

  async function saveWebhookUrl() {
    var url = document.getElementById('webhook-url').value;
    await fetch('/api/admin/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ webhookUrl: url })
    });
    showStatus('Webhook URL saved', 'success');
  }

  async function saveBackupSettings() {
    var interval = parseInt(document.getElementById('backup-interval').value) || 24;
    var retention = parseInt(document.getElementById('backup-retention').value) || 7;
    await fetch('/api/admin/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ backupIntervalHours: interval, backupRetentionCount: retention })
    });
    showStatus('Backup settings saved', 'success');
  }

  async function loadActivityLogs() {
    try {
      var room = document.getElementById('activity-search').value;
      var url = room
        ? '/api/admin/activity-logs?room=' + encodeURIComponent(room)
        : '/api/admin/activity-logs';
      var res = await fetch(url);
      if (!res.ok) return;
      var data = await res.json();
      renderActivityLogs(data.logs);
    } catch (e) {
    }
  }

  async function loadAuditLogs() {
    try {
      var q = document.getElementById('audit-search').value;
      var url = q
        ? '/api/admin/audit-logs?q=' + encodeURIComponent(q)
        : '/api/admin/audit-logs';
      var res = await fetch(url);
      if (!res.ok) return;
      var data = await res.json();
      renderAuditLogs(data.logs);
    } catch (e) {
    }
  }

  function renderActivityLogs(logs) {
    var el = document.getElementById('activity-log-list');
    if (!logs || logs.length === 0) {
      el.innerHTML = '<p style="color:var(--text-soft);padding:12px">No activity logs</p>';
      return;
    }
    el.innerHTML = logs.map(function(l) {
      return '<div style="padding:8px 0;border-bottom:1px solid var(--border);font-size:13px">' +
        '<span style="color:var(--text-soft)">' + new Date(l.timestamp).toLocaleString() + '</span> ' +
        '<span class="badge badge-' + (l.eventType === 'join' ? 'green' : 'gray') + '">' + l.eventType + '</span> ' +
        (l.userName || 'Unknown') +
        ' <span style="color:var(--text-soft);font-size:11px">' + l.roomId.slice(0, 8) + '</span></div>';
    }).join('');
  }

  function renderAuditLogs(logs) {
    var el = document.getElementById('audit-log-list');
    if (!logs || logs.length === 0) {
      el.innerHTML = '<p style="color:var(--text-soft);padding:12px">No audit logs</p>';
      return;
    }
    el.innerHTML = logs.map(function(l) {
      return '<div style="padding:8px 0;border-bottom:1px solid var(--border);font-size:13px">' +
        '<span style="color:var(--text-soft)">' + new Date(l.timestamp).toLocaleString() + '</span> ' +
        '<span class="badge badge-yellow">' + l.action + '</span> ' +
        (l.actor || 'system') +
        (l.targetId ? ' <span style="color:var(--text-soft);font-size:11px">' + l.targetId.slice(0, 8) + '</span>' : '') +
        '</div>';
    }).join('');
  }

  async function loadBackups() {
    try {
      var res = await fetch('/api/admin/backups');
      if (!res.ok) return;
      var data = await res.json();
      renderBackups(data.backups);
    } catch (e) {
    }
  }

  function renderBackups(backups) {
    var el = document.getElementById('backup-list');
    if (!backups || backups.length === 0) {
      el.innerHTML = '<p style="color:var(--text-soft);padding:12px">No backups</p>';
      return;
    }
    el.innerHTML = backups.map(function(b) {
      return '<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)">' +
        '<div><div style="font-weight:500">' + b.filename + '</div>' +
        '<div style="font-size:12px;color:var(--text-soft)">' +
        new Date(b.createdAt).toLocaleString() + ' | ' +
        Math.round(b.sizeBytes / 1024) + 'KB | ' +
        b.roomCount + ' rooms' +
        (b.autoGenerated ? ' | Auto' : '') +
        '</div></div>' +
        '<div style="display:flex;gap:6px">' +
        '<button class="btn btn-sm btn-secondary" data-action="downloadBackup" data-id="' + b.id + '">Download</button>' +
        '<button class="btn btn-sm btn-success" data-action="restoreBackup" data-id="' + b.id + '">Restore</button>' +
        '<button class="btn btn-sm btn-danger" data-action="deleteBackup" data-id="' + b.id + '">Delete</button>' +
        '</div></div>';
    }).join('');
  }

  async function createBackup() {
    try {
      var res = await fetch('/api/admin/backups', { method: 'POST' });
      var data = await res.json();
      if (data.success) {
        showStatus('Backup created', 'success');
        loadBackups();
      } else {
        showStatus(data.error || 'Failed', 'error');
      }
    } catch (e) {
      showStatus('Failed to create backup', 'error');
    }
  }

  async function downloadBackup(id) {
    window.open('/api/admin/backups/' + id + '/download', '_blank');
  }

  async function restoreBackup(id) {
    if (!confirm('Restore this backup? This will add missing rooms.')) return;
    try {
      var res = await fetch('/api/admin/backups/' + id + '/restore', { method: 'POST' });
      var data = await res.json();
      if (data.success) {
        showStatus('Restored ' + data.roomsRestored + ' rooms', 'success');
        loadData();
      } else {
        showStatus(data.error || 'Failed', 'error');
      }
    } catch (e) {
      showStatus('Failed to restore', 'error');
    }
  }

  async function deleteBackup(id) {
    if (!confirm('Delete this backup?')) return;
    try {
      await fetch('/api/admin/backups/' + id, { method: 'DELETE' });
      loadBackups();
    } catch (e) {
    }
  }

  async function exportAll() {
    window.open('/api/admin/export', '_blank');
  }

  async function loadApiKeys() {
    try {
      var res = await fetch('/api/admin/api-keys');
      if (!res.ok) return;
      var data = await res.json();
      renderApiKeys(data.keys);
    } catch (e) {
    }
  }

  function renderApiKeys(keys) {
    var el = document.getElementById('apikey-list');
    if (!keys || keys.length === 0) {
      el.innerHTML = '<p style="color:var(--text-soft);padding:12px">No API keys</p>';
      return;
    }
    el.innerHTML = keys.map(function(k) {
      return '<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)">' +
        '<div><div style="font-weight:500">' + k.name + '</div>' +
        '<div style="font-size:12px;color:var(--text-soft)">' +
        k.permissions.join(', ') + ' | Created: ' + new Date(k.createdAt).toLocaleDateString() +
        (k.lastUsed ? ' | Last used: ' + new Date(k.lastUsed).toLocaleDateString() : '') +
        (k.expiresAt ? ' | Expires: ' + new Date(k.expiresAt).toLocaleDateString() : '') +
        '</div></div>' +
        '<button class="btn btn-sm btn-danger" data-action="revokeApiKey" data-id="' + k.id + '">Revoke</button></div>';
    }).join('');
  }

  function showCreateApiKey() {
    document.getElementById('apikey-modal').classList.add('active');
    document.getElementById('new-key-display').style.display = 'none';
  }

  function closeApiKeyModal() {
    document.getElementById('apikey-modal').classList.remove('active');
  }

  async function createApiKey() {
    var name = document.getElementById('apikey-name').value;
    if (!name) {
      alert('Name required');
      return;
    }
    var perms = [];
    if (document.getElementById('perm-read').checked) perms.push('read');
    if (document.getElementById('perm-write').checked) perms.push('write');
    if (document.getElementById('perm-admin').checked) perms.push('admin');
    var expires = parseInt(document.getElementById('apikey-expires').value) || 0;
    try {
      var res = await fetch('/api/admin/api-keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name, permissions: perms, expiresInDays: expires || null })
      });
      var data = await res.json();
      if (data.key) {
        closeApiKeyModal();
        document.getElementById('new-key-display').style.display = 'block';
        document.getElementById('new-key-value').textContent = data.key;
        loadApiKeys();
      } else {
        alert(data.error || 'Failed');
      }
    } catch (e) {
      alert('Failed to create key');
    }
  }

  async function revokeApiKey(id) {
    if (!confirm('Revoke this API key?')) return;
    try {
      await fetch('/api/admin/api-keys/' + id, { method: 'DELETE' });
      loadApiKeys();
    } catch (e) {
    }
  }

  async function loadUsers(q) {
    q = q || '';
    try {
      var url = q
        ? '/api/admin/users?q=' + encodeURIComponent(q)
        : '/api/admin/users';
      var res = await fetch(url);
      if (!res.ok) return;
      var data = await res.json();
      users = data.users || [];
      renderUsers();
    } catch (e) {
    }
  }

  function searchUsers(q) {
    if (searchTimeout) clearTimeout(searchTimeout);
    searchTimeout = setTimeout(function() { loadUsers(q); }, 300);
  }

  function renderUsers() {
    var el = document.getElementById('user-list');
    if (!users || users.length === 0) {
      el.innerHTML = '<div class="empty-state"><h3>No users yet</h3><p>Users will appear here when registered</p></div>';
      return;
    }

    var html = '<div class="room-header"><span>User</span><span>Role</span><span>Status</span><span>Created</span><span>Actions</span></div>';

    users.forEach(function(u) {
      var role = u.role === 'admin'
        ? '<span class="badge badge-yellow">Admin</span>'
        : '<span class="badge badge-gray">User</span>';
      var status = u.isActive
        ? '<span class="badge badge-green">Active</span>'
        : '<span class="badge badge-gray">Inactive</span>';
      var verified = u.emailVerified ? '' : '<span class="badge badge-yellow">Unverified</span>';

      html += '<div class="room-row">' +
        '<div><div class="room-name">' + (u.displayName || 'No name') + '</div>' +
        '<div class="room-id">' + u.email + '</div></div>' +
        '<div>' + role + '</div>' +
        '<div>' + status + verified + '</div>' +
        '<div>' + new Date(u.createdAt).toLocaleDateString() + '</div>' +
        '<div class="room-actions">' +
        '<button class="btn btn-secondary btn-sm" data-action="editUser" data-id="' + u.id + '">Edit</button>' +
        '<button class="btn btn-danger btn-sm" data-action="deleteUser" data-id="' + u.id + '">Del</button>' +
        '</div></div>';
    });

    el.innerHTML = html;
  }

  function showCreateUser() {
    document.getElementById('user-modal').classList.add('active');
  }

  function closeUserModal() {
    document.getElementById('user-modal').classList.remove('active');
    document.getElementById('user-email').value = '';
    document.getElementById('user-displayname').value = '';
    document.getElementById('user-password').value = '';
    document.getElementById('user-role').value = 'user';
  }

  async function createUser() {
    var email = document.getElementById('user-email').value;
    var displayName = document.getElementById('user-displayname').value;
    var password = document.getElementById('user-password').value || null;
    var role = document.getElementById('user-role').value;
    if (!email) {
      alert('Email required');
      return;
    }
    try {
      var res = await fetch('/api/admin/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email, displayName: displayName, password: password, role: role })
      });
      var data = await res.json();
      if (data.success) {
        closeUserModal();
        loadUsers();
        showAuthStatus('User created', 'success');
      } else {
        alert(data.error || 'Failed');
      }
    } catch (e) {
      alert('Failed to create user');
    }
  }

  async function deleteUser(id) {
    if (!confirm('Delete this user permanently?')) return;
    try {
      await fetch('/api/admin/users/' + id, { method: 'DELETE' });
      loadUsers();
    } catch (e) {
      alert('Error deleting user');
    }
  }

  function editUser(id) {
    var u = users.find(function(x) { return x.id === id; });
    if (!u) return;
    document.getElementById('edit-user-id').value = id;
    document.getElementById('edit-user-email').value = u.email;
    document.getElementById('edit-user-displayname').value = u.displayName || '';
    document.getElementById('edit-user-password').value = '';
    document.getElementById('edit-user-role').value = u.role || 'user';
    document.getElementById('edit-user-active').checked = u.isActive !== false;
    document.getElementById('edit-user-verified').checked = u.emailVerified === true;
    document.getElementById('edit-user-modal').classList.add('active');
  }

  function closeEditUserModal() {
    document.getElementById('edit-user-modal').classList.remove('active');
  }

  async function saveUserEdit() {
    var id = document.getElementById('edit-user-id').value;
    var data = {
      displayName: document.getElementById('edit-user-displayname').value,
      role: document.getElementById('edit-user-role').value,
      isActive: document.getElementById('edit-user-active').checked,
      emailVerified: document.getElementById('edit-user-verified').checked
    };
    var password = document.getElementById('edit-user-password').value;
    if (password) data.password = password;
    try {
      var res = await fetch('/api/admin/users/' + id, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      var result = await res.json();
      if (result.success) {
        closeEditUserModal();
        loadUsers();
        showAuthStatus('User updated', 'success');
      } else {
        alert(result.error || 'Failed to update user');
      }
    } catch (e) {
      alert('Failed to update user');
    }
  }

  async function resetUserPassword() {
    var id = document.getElementById('edit-user-id').value;
    var email = document.getElementById('edit-user-email').value;
    if (!confirm('Send password reset email to ' + email + '?')) return;
    try {
      var res = await fetch('/api/admin/users/' + id + '/reset-password', { method: 'POST' });
      var result = await res.json();
      if (result.success) {
        alert('Password reset email sent!');
      } else {
        alert(result.error || 'Failed to send reset email');
      }
    } catch (e) {
      alert('Failed to send reset email');
    }
  }

  document.getElementById('user-modal').addEventListener('click', function(e) {
    if (e.target.id === 'user-modal') closeUserModal();
  });
  document.getElementById('edit-user-modal').addEventListener('click', function(e) {
    if (e.target.id === 'edit-user-modal') closeEditUserModal();
  });

  async function loadAuthSettings() {
    try {
      var res = await fetch('/api/admin/auth-settings');
      if (!res.ok) return;
      authSettings = await res.json();
      renderAuthSettings();
    } catch (e) {
    }
  }

  function renderAuthSettings() {
    document.getElementById('auth-mode').value = authSettings.authMode || 'open';
    document.getElementById('toggle-require-email-verify').classList.toggle('active', authSettings.requireEmailVerification);
    document.getElementById('toggle-magic-link').classList.toggle('active', authSettings.allowMagicLinkLogin);
    document.getElementById('toggle-oidc-email-match').classList.toggle('active', authSettings.oidcEmailMatching);
    document.getElementById('toggle-production-mode').classList.toggle('active', authSettings.productionMode);
    document.getElementById('toggle-guest-room-create').classList.toggle('active', authSettings.allowGuestRoomCreation !== false);
    document.getElementById('toggle-guest-room-join').classList.toggle('active', authSettings.allowGuestRoomJoin !== false);
    document.getElementById('toggle-room-creator-guest').classList.toggle('active', authSettings.allowRoomCreatorGuestSetting !== false);
    document.getElementById('toggle-share-button').classList.toggle('active', authSettings.shareButtonEnabled !== false);
    document.getElementById('input-id-token-max-age').value = authSettings.idTokenMaxAgeHours || 2;
    document.getElementById('input-email-rate-window').value = authSettings.emailRateLimitWindowSeconds || 300;
    document.getElementById('input-email-rate-max').value = authSettings.emailRateLimitMaxAttempts || 3;
  }

  async function saveAuthSettings() {
    var mode = document.getElementById('auth-mode').value;
    await fetch('/api/admin/auth-settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ authMode: mode })
    });
    showAuthStatus('Auth mode saved', 'success');
  }

  async function toggleAuthSetting(key) {
    authSettings[key] = !authSettings[key];
    renderAuthSettings();
    await fetch('/api/admin/auth-settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [key]: authSettings[key] })
    });
    showAuthStatus('Setting updated', 'success');
  }

  async function updateAuthNumber(key, value) {
    var num = parseInt(value);
    if (isNaN(num)) return;
    authSettings[key] = num;
    await fetch('/api/admin/auth-settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [key]: num })
    });
    showAuthStatus('Setting updated', 'success');
  }

  async function loadOidcProviders() {
    try {
      var res = await fetch('/api/admin/oidc-providers');
      if (!res.ok) return;
      var data = await res.json();
      oidcProviders = data.providers || [];
      renderOidcProviders();
    } catch (e) {
    }
  }

  function renderOidcProviders() {
    var el = document.getElementById('oidc-provider-list');
    if (!oidcProviders || oidcProviders.length === 0) {
      el.innerHTML = '<p style="color:var(--text-soft);padding:12px">No OIDC providers configured</p>';
      return;
    }
    el.innerHTML = oidcProviders.map(function(p) {
      return '<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)">' +
        '<div><div style="font-weight:500">' + esc(p.name) + '</div>' +
        '<div style="font-size:12px;color:var(--text-soft)">' + esc(p.providerType) + ' | ' +
        (p.isActive ? '<span style="color:#22c55e">Active</span>' : '<span style="color:#94a3b8">Inactive</span>') +
        '</div></div>' +
        '<div style="display:flex;gap:6px">' +
        '<button class="btn btn-sm btn-secondary" data-action="editOidcProvider" data-id="' + p.id + '">Edit</button>' +
        '<button class="btn btn-sm btn-danger" data-action="deleteOidcProvider" data-id="' + p.id + '">Delete</button>' +
        '</div></div>';
    }).join('');
  }

  function showAddOidcProvider() {
    document.getElementById('oidc-modal-title').textContent = 'Add OIDC Provider';
    document.getElementById('oidc-edit-id').value = '';
    document.getElementById('oidc-name').value = '';
    document.getElementById('oidc-type').value = 'generic';
    document.getElementById('oidc-client-id').value = '';
    document.getElementById('oidc-client-secret').value = '';
    document.getElementById('oidc-issuer').value = '';
    document.getElementById('oidc-auth-url').value = '';
    document.getElementById('oidc-token-url').value = '';
    document.getElementById('oidc-userinfo-url').value = '';
    document.getElementById('oidc-scopes').value = 'openid email profile';
    document.getElementById('oidc-active').checked = true;
    document.getElementById('oidc-modal').classList.add('active');
  }

  function editOidcProvider(id) {
    var p = oidcProviders.find(function(x) { return x.id === id; });
    if (!p) return;
    document.getElementById('oidc-modal-title').textContent = 'Edit OIDC Provider';
    document.getElementById('oidc-edit-id').value = id;
    document.getElementById('oidc-name').value = p.name;
    document.getElementById('oidc-type').value = p.providerType;
    document.getElementById('oidc-client-id').value = p.clientId;
    document.getElementById('oidc-client-secret').value = '';
    document.getElementById('oidc-issuer').value = p.issuerUrl || '';
    document.getElementById('oidc-auth-url').value = p.authorizationUrl || '';
    document.getElementById('oidc-token-url').value = p.tokenUrl || '';
    document.getElementById('oidc-userinfo-url').value = p.userinfoUrl || '';
    document.getElementById('oidc-scopes').value = p.scopes || 'openid email profile';
    document.getElementById('oidc-active').checked = p.isActive;
    document.getElementById('oidc-modal').classList.add('active');
  }

  function closeOidcModal() {
    document.getElementById('oidc-modal').classList.remove('active');
  }

  async function saveOidcProvider() {
    var id = document.getElementById('oidc-edit-id').value;
    var data = {
      name: document.getElementById('oidc-name').value,
      providerType: document.getElementById('oidc-type').value,
      clientId: document.getElementById('oidc-client-id').value,
      clientSecret: document.getElementById('oidc-client-secret').value || undefined,
      issuerUrl: document.getElementById('oidc-issuer').value,
      authorizationUrl: document.getElementById('oidc-auth-url').value,
      tokenUrl: document.getElementById('oidc-token-url').value,
      userinfoUrl: document.getElementById('oidc-userinfo-url').value,
      scopes: document.getElementById('oidc-scopes').value,
      isActive: document.getElementById('oidc-active').checked
    };
    if (!data.name || !data.clientId) {
      alert('Name and Client ID required');
      return;
    }
    try {
      var url = id ? '/api/admin/oidc-providers/' + id : '/api/admin/oidc-providers';
      var method = id ? 'PUT' : 'POST';
      var res = await fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      var result = await res.json();
      if (result.success) {
        closeOidcModal();
        loadOidcProviders();
        showAuthStatus('Provider saved', 'success');
      } else {
        alert(result.error || 'Failed');
      }
    } catch (e) {
      alert('Failed to save provider');
    }
  }

  async function deleteOidcProvider(id) {
    if (!confirm('Delete this OIDC provider?')) return;
    try {
      await fetch('/api/admin/oidc-providers/' + id, { method: 'DELETE' });
      loadOidcProviders();
    } catch (e) {
    }
  }

  document.getElementById('oidc-modal').addEventListener('click', function(e) {
    if (e.target.id === 'oidc-modal') closeOidcModal();
  });

  async function loadSmtpConfigs() {
    try {
      var res = await fetch('/api/admin/smtp-configs');
      if (!res.ok) return;
      var data = await res.json();
      smtpConfigs = data.configs || [];
      renderSmtpConfigs();
    } catch (e) {
    }
  }

  function renderSmtpConfigs() {
    var el = document.getElementById('smtp-config-list');
    if (!smtpConfigs || smtpConfigs.length === 0) {
      el.innerHTML = '<p style="color:var(--text-soft);padding:12px">No SMTP configurations</p>';
      return;
    }
    el.innerHTML = smtpConfigs.map(function(s) {
      return '<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)">' +
        '<div><div style="font-weight:500">' + s.name +
        (s.isDefault ? ' <span class="badge badge-green">Default</span>' : '') +
        '</div>' +
        '<div style="font-size:12px;color:var(--text-soft)">' + s.host + ':' + s.port + ' (' + s.secureMode + ') | ' +
        (s.isActive ? '<span style="color:#22c55e">Active</span>' : '<span style="color:#94a3b8">Inactive</span>') +
        '</div></div>' +
        '<div style="display:flex;gap:6px">' +
        '<button class="btn btn-sm btn-secondary" data-action="editSmtpConfig" data-id="' + s.id + '">Edit</button>' +
        '<button class="btn btn-sm btn-danger" data-action="deleteSmtpConfig" data-id="' + s.id + '">Delete</button>' +
        '</div></div>';
    }).join('');
  }

  function showAddSmtpConfig() {
    document.getElementById('smtp-modal-title').textContent = 'Add SMTP Configuration';
    document.getElementById('smtp-edit-id').value = '';
    document.getElementById('smtp-name').value = '';
    document.getElementById('smtp-host').value = '';
    document.getElementById('smtp-port').value = '587';
    document.getElementById('smtp-secure-mode').value = 'starttls';
    document.getElementById('smtp-username').value = '';
    document.getElementById('smtp-password').value = '';
    document.getElementById('smtp-from-email').value = '';
    document.getElementById('smtp-from-name').value = '';
    document.getElementById('smtp-default').checked = false;
    document.getElementById('smtp-active').checked = true;
    document.getElementById('smtp-modal').classList.add('active');
  }

  function editSmtpConfig(id) {
    var s = smtpConfigs.find(function(x) { return x.id === id; });
    if (!s) return;
    document.getElementById('smtp-modal-title').textContent = 'Edit SMTP Configuration';
    document.getElementById('smtp-edit-id').value = id;
    document.getElementById('smtp-name').value = s.name;
    document.getElementById('smtp-host').value = s.host || '';
    document.getElementById('smtp-port').value = s.port || 587;
    document.getElementById('smtp-secure-mode').value = s.secureMode || 'starttls';
    document.getElementById('smtp-username').value = s.username || '';
    document.getElementById('smtp-password').value = '';
    document.getElementById('smtp-from-email').value = s.fromEmail || '';
    document.getElementById('smtp-from-name').value = s.fromName || '';
    document.getElementById('smtp-default').checked = s.isDefault;
    document.getElementById('smtp-active').checked = s.isActive;
    document.getElementById('smtp-modal').classList.add('active');
  }

  function closeSmtpModal() {
    document.getElementById('smtp-modal').classList.remove('active');
  }

  async function saveSmtpConfig() {
    var id = document.getElementById('smtp-edit-id').value;
    var data = {
      name: document.getElementById('smtp-name').value,
      host: document.getElementById('smtp-host').value,
      port: parseInt(document.getElementById('smtp-port').value),
      secureMode: document.getElementById('smtp-secure-mode').value,
      username: document.getElementById('smtp-username').value,
      password: document.getElementById('smtp-password').value || undefined,
      fromEmail: document.getElementById('smtp-from-email').value,
      fromName: document.getElementById('smtp-from-name').value,
      isDefault: document.getElementById('smtp-default').checked,
      isActive: document.getElementById('smtp-active').checked
    };
    if (!data.name || !data.host) {
      alert('Name and Host required');
      return;
    }
    try {
      var url = id ? '/api/admin/smtp-configs/' + id : '/api/admin/smtp-configs';
      var method = id ? 'PUT' : 'POST';
      var res = await fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      var result = await res.json();
      if (result.success) {
        closeSmtpModal();
        loadSmtpConfigs();
        showAuthStatus('SMTP config saved', 'success');
      } else {
        alert(result.error || 'Failed');
      }
    } catch (e) {
      alert('Failed to save config');
    }
  }

  async function testSmtpConfig() {
    var data = {
      name: document.getElementById('smtp-name').value,
      host: document.getElementById('smtp-host').value,
      port: parseInt(document.getElementById('smtp-port').value),
      secureMode: document.getElementById('smtp-secure-mode').value,
      username: document.getElementById('smtp-username').value,
      password: document.getElementById('smtp-password').value,
      fromEmail: document.getElementById('smtp-from-email').value,
      fromName: document.getElementById('smtp-from-name').value
    };
    try {
      var res = await fetch('/api/admin/smtp-configs/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      var result = await res.json();
      if (result.success) {
        alert('Test email sent successfully!');
      } else {
        alert('Test failed: ' + (result.error || 'Unknown error'));
      }
    } catch (e) {
      alert('Test failed');
    }
  }

  async function deleteSmtpConfig(id) {
    if (!confirm('Delete this SMTP configuration?')) return;
    try {
      await fetch('/api/admin/smtp-configs/' + id, { method: 'DELETE' });
      loadSmtpConfigs();
    } catch (e) {
    }
  }

  document.getElementById('smtp-modal').addEventListener('click', function(e) {
    if (e.target.id === 'smtp-modal') closeSmtpModal();
  });

  var emailTemplates = [];
  var currentEditTemplate = null;
  var isHtmlSourceView = false;

  async function loadEmailTemplates() {
    try {
      var res = await fetch('/api/admin/email-templates');
      if (!res.ok) return;
      var data = await res.json();
      emailTemplates = data.templates || [];
      renderEmailTemplates(emailTemplates);
    } catch (e) {
    }
  }

  function renderEmailTemplates(templates) {
    var el = document.getElementById('email-template-list');
    if (!templates || templates.length === 0) {
      el.innerHTML = '<p style="color:var(--text-soft);padding:12px">No email templates. Default templates will be used.</p>';
      return;
    }
    el.innerHTML = templates.map(function(t) {
      return '<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)">' +
        '<div><div style="font-weight:500">' + esc(t.name) + '</div>' +
        '<div style="font-size:12px;color:var(--text-soft)">Subject: ' + esc(t.subject) + '</div></div>' +
        '<button class="btn btn-sm btn-secondary" data-action="editTemplate" data-id="' + esc(t.id) + '">Edit</button></div>';
    }).join('');
  }

  function editTemplate(id) {
    var t = emailTemplates.find(function(x) { return x.id === id; });
    if (!t) return;
    currentEditTemplate = t;
    document.getElementById('template-edit-id').value = id;
    document.getElementById('template-name').value = t.name;
    document.getElementById('template-subject').value = t.subject || '';
    document.getElementById('template-editor').innerHTML = t.bodyHtml || '';
    document.getElementById('template-html-source').value = t.bodyHtml || '';
    document.getElementById('template-text').value = t.bodyText || '';
    isHtmlSourceView = false;
    showWysiwygView();
    document.getElementById('template-modal').classList.add('active');
  }

  function closeTemplateModal() {
    document.getElementById('template-modal').classList.remove('active');
    currentEditTemplate = null;
  }

  function showWysiwygView() {
    document.getElementById('template-editor').style.display = 'block';
    document.getElementById('template-editor-toolbar').style.display = 'flex';
    document.getElementById('template-html-source').style.display = 'none';
  }

  function showHtmlSourceView() {
    document.getElementById('template-html-source').value = document.getElementById('template-editor').innerHTML;
    document.getElementById('template-editor').style.display = 'none';
    document.getElementById('template-editor-toolbar').style.display = 'none';
    document.getElementById('template-html-source').style.display = 'block';
  }

  function toggleTemplateView() {
    if (isHtmlSourceView) {
      document.getElementById('template-editor').innerHTML = document.getElementById('template-html-source').value;
      showWysiwygView();
    } else {
      showHtmlSourceView();
    }
    isHtmlSourceView = !isHtmlSourceView;
  }

  function execCmd(cmd) {
    document.execCommand(cmd, false, null);
    document.getElementById('template-editor').focus();
  }

  function execCmdArg(cmd, arg) {
    if (!arg) return;
    document.execCommand(cmd, false, arg);
    document.getElementById('template-editor').focus();
  }

  function insertTemplateVar(varName) {
    var editor = document.getElementById('template-editor');
    editor.focus();
    document.execCommand('insertText', false, '{{' + varName + '}}');
  }

  function insertLink() {
    var url = prompt('Enter URL:');
    if (url) {
      document.execCommand('createLink', false, url);
    }
  }

  function insertImage() {
    var url = prompt('Enter image URL:');
    if (url) {
      document.execCommand('insertImage', false, url);
    }
  }

  function insertButton() {
    var url = prompt('Enter button URL:');
    var text = prompt('Enter button text:', 'Click Here');
    if (url && text) {
      var btn = '<a href="' + url + '" style="display:inline-block;padding:12px 24px;background:#c9a227;color:#fff;text-decoration:none;border-radius:6px;font-weight:600">' + text + '</a>';
      document.execCommand('insertHTML', false, btn);
    }
  }

  async function saveTemplate() {
    var id = document.getElementById('template-edit-id').value;
    if (!id) {
      alert('No template selected');
      return;
    }
    var html = isHtmlSourceView
      ? document.getElementById('template-html-source').value
      : document.getElementById('template-editor').innerHTML;
    var data = {
      subject: document.getElementById('template-subject').value,
      bodyHtml: html,
      bodyText: document.getElementById('template-text').value
    };
    try {
      var res = await fetch('/api/admin/email-templates/' + id, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      var result = await res.json();
      if (result.success) {
        closeTemplateModal();
        loadEmailTemplates();
        showAuthStatus('Template saved', 'success');
      } else {
        alert(result.error || 'Failed to save');
      }
    } catch (e) {
      alert('Failed to save template');
    }
  }

  function previewTemplate() {
    var subject = document.getElementById('template-subject').value
      .replace(/\{\{displayName\}\}/g, 'John Doe')
      .replace(/\{\{actionUrl\}\}/g, 'https://example.com/action')
      .replace(/\{\{appName\}\}/g, 'TheOneFile_Verse');
    var html = (isHtmlSourceView
      ? document.getElementById('template-html-source').value
      : document.getElementById('template-editor').innerHTML)
      .replace(/\{\{displayName\}\}/g, 'John Doe')
      .replace(/\{\{actionUrl\}\}/g, 'https://example.com/action')
      .replace(/\{\{appName\}\}/g, 'TheOneFile_Verse');
    document.getElementById('preview-subject').textContent = subject;
    var frame = document.getElementById('preview-frame');
    frame.srcdoc = '<!DOCTYPE html><html><head><style>body{font-family:system-ui,sans-serif;padding:20px;line-height:1.6;color:#333}</style></head><body>' + html + '</body></html>';
    document.getElementById('template-preview-modal').classList.add('active');
  }

  function closeTemplatePreview() {
    document.getElementById('template-preview-modal').classList.remove('active');
  }

  document.getElementById('template-modal').addEventListener('click', function(e) {
    if (e.target.id === 'template-modal') closeTemplateModal();
  });
  document.getElementById('template-preview-modal').addEventListener('click', function(e) {
    if (e.target.id === 'template-preview-modal') closeTemplatePreview();
  });

  async function loadEmailLogs() {
    try {
      var email = document.getElementById('email-log-search').value;
      var url = email
        ? '/api/admin/email-logs?email=' + encodeURIComponent(email)
        : '/api/admin/email-logs';
      var res = await fetch(url);
      if (!res.ok) return;
      var data = await res.json();
      emailLogs = data.logs || [];
      renderEmailLogs();
    } catch (e) {
    }
  }

  function renderEmailLogs() {
    var el = document.getElementById('email-log-list');
    if (!emailLogs || emailLogs.length === 0) {
      el.innerHTML = '<p style="color:var(--text-soft);padding:12px">No email logs</p>';
      return;
    }
    el.innerHTML = emailLogs.map(function(l) {
      return '<div style="padding:8px 0;border-bottom:1px solid var(--border);font-size:13px">' +
        '<span style="color:var(--text-soft)">' + esc(new Date(l.sentAt).toLocaleString()) + '</span> ' +
        '<span class="badge badge-' + (l.status === 'sent' ? 'green' : 'gray') + '">' + esc(l.status) + '</span> ' +
        esc(l.toEmail) +
        ' <span style="color:var(--text-soft)">' + esc(l.subject) + '</span>' +
        (l.errorMessage ? ' <span style="color:#ef4444">' + esc(l.errorMessage) + '</span>' : '') +
        '</div>';
    }).join('');
  }

  async function clearEmailLogs() {
    if (!confirm('Clear all email logs? This cannot be undone.')) return;
    try {
      var res = await fetch('/api/admin/email-logs', { method: 'DELETE' });
      if (res.ok) {
        loadEmailLogs();
        showAuthStatus('Email logs cleared', 'success');
      }
    } catch (e) {
    }
  }

  async function clearActivityLogs() {
    if (!confirm('Clear all activity logs? This cannot be undone.')) return;
    try {
      var res = await fetch('/api/admin/activity-logs', { method: 'DELETE' });
      if (res.ok) {
        loadActivityLogs();
        showAuthStatus('Activity logs cleared', 'success');
      }
    } catch (e) {
    }
  }

  async function clearAuditLogs() {
    if (!confirm('Clear all audit logs? This cannot be undone.')) return;
    try {
      var res = await fetch('/api/admin/audit-logs', { method: 'DELETE' });
      if (res.ok) {
        loadAuditLogs();
        showAuthStatus('Audit logs cleared', 'success');
      }
    } catch (e) {
    }
  }

  document.addEventListener('click', function(e) {
    var target = e.target.closest('[data-action]');
    if (!target) return;
    if (target.getAttribute('data-disabled') === 'true') return;
    var action = target.dataset.action;
    var handlers = {
      toggleTheme: toggleTheme,
      logout: logout,
      showTab: function() { showTab(target.dataset.tab); },
      deleteSelected: deleteSelected,
      clearSelection: clearSelection,
      viewRoom: function() { viewRoom(target.dataset.id); },
      joinRoom: function() { joinRoom(target.dataset.id); },
      deleteRoom: function() { deleteRoom(target.dataset.id); },
      toggleSetting: function() { toggleSetting(target.dataset.setting); },
      toggleAuthSetting: function() { toggleAuthSetting(target.dataset.setting); },
      showAddOidcProvider: showAddOidcProvider,
      showAddSmtpConfig: showAddSmtpConfig,
      editOidcProvider: function() { editOidcProvider(target.dataset.id); },
      deleteOidcProvider: function() { deleteOidcProvider(target.dataset.id); },
      editSmtpConfig: function() { editSmtpConfig(target.dataset.id); },
      deleteSmtpConfig: function() { deleteSmtpConfig(target.dataset.id); },
      saveOidcProvider: saveOidcProvider,
      saveSmtpConfig: saveSmtpConfig,
      testSmtpConfig: testSmtpConfig,
      closeModal: closeModal,
      closeApiKeyModal: closeApiKeyModal,
      closeUserModal: closeUserModal,
      closeEditUserModal: closeEditUserModal,
      closeOidcModal: closeOidcModal,
      closeSmtpModal: closeSmtpModal,
      closeTemplateModal: closeTemplateModal,
      closeTemplatePreview: closeTemplatePreview,
      showCreateApiKey: showCreateApiKey,
      createApiKey: createApiKey,
      showCreateUser: showCreateUser,
      createUser: createUser,
      editUser: function() { editUser(target.dataset.id); },
      deleteUser: function() { deleteUser(target.dataset.id); },
      saveUserEdit: saveUserEdit,
      resetUserPassword: resetUserPassword,
      revokeApiKey: function() { revokeApiKey(target.dataset.id); },
      setInstancePassword: setInstancePassword,
      saveAdminPath: saveAdminPath,
      saveUpdateInterval: saveUpdateInterval,
      triggerUpdate: triggerUpdate,
      saveForcedTheme: saveForcedTheme,
      saveRoomDefaults: saveRoomDefaults,
      saveRateLimitSettings: saveRateLimitSettings,
      saveWebhookUrl: saveWebhookUrl,
      saveBackupSettings: saveBackupSettings,
      createBackup: createBackup,
      exportAll: exportAll,
      downloadBackup: function() { downloadBackup(target.dataset.id); },
      restoreBackup: function() { restoreBackup(target.dataset.id); },
      deleteBackup: function() { deleteBackup(target.dataset.id); },
      editTemplate: function() { editTemplate(target.dataset.id); },
      saveTemplate: saveTemplate,
      previewTemplate: previewTemplate,
      insertTemplateVar: function() { insertTemplateVar(target.dataset.varname); },
      toggleTemplateView: toggleTemplateView,
      execCmd: function() { execCmd(target.dataset.cmd); },
      insertLink: insertLink,
      insertImage: insertImage,
      insertButton: insertButton,
      uploadFileClick: function() { document.getElementById('upload-file').click(); },
      clearEmailLogs: clearEmailLogs,
      clearActivityLogs: clearActivityLogs,
      clearAuditLogs: clearAuditLogs
    };
    if (handlers[action]) handlers[action]();
  });

  document.addEventListener('change', function(e) {
    var target = e.target.closest('[data-action]');
    if (!target) return;
    var action = target.dataset.action;
    if (action === 'saveAuthSettings') saveAuthSettings();
    else if (action === 'changeSourceMode') changeSourceMode();
    else if (action === 'saveForcedTheme') saveForcedTheme();
    else if (action === 'updateAuthNumber') updateAuthNumber(target.dataset.setting, target.value);
    else if (action === 'execCmdArg') { execCmdArg(target.dataset.cmd, target.value); target.selectedIndex = 0; }
    else if (action === 'uploadFile') uploadFile();
    else if (action === 'toggleAll') toggleAll(target.checked);
    else if (action === 'toggleSelect') toggleSelect(target.dataset.id, target.checked);
    else if (action === 'templateColor') execCmdArg('foreColor', target.value);
  });

  document.addEventListener('keyup', function(e) {
    var target = e.target.closest('[data-action]');
    if (!target) return;
    var action = target.dataset.action;
    if (action === 'searchRooms') searchRooms(target.value);
    else if (action === 'searchUsers') searchUsers(target.value);
    else if (action === 'loadActivityLogs') loadActivityLogs();
    else if (action === 'loadAuditLogs') loadAuditLogs();
    else if (action === 'loadEmailLogs') loadEmailLogs();
  });

  loadData();
  setInterval(loadData, 10000);

})();
