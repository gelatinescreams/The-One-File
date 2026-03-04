(function() {
  'use strict';
  var pageData = JSON.parse((document.getElementById('page-data') || {}).textContent || '{}');
  var ADMIN_PATH = pageData.adminPath || 'admin';
  var csrfToken = '';
  if (window.__authCsrfRefresh) {
    window.__authCsrfRefresh().then(function() { csrfToken = window.__authCsrfToken; });
  }
  function csrfHeaders(extra) {
    var h = { 'x-csrf-token': csrfToken };
    if (extra) { for (var k in extra) { if (extra.hasOwnProperty(k)) h[k] = extra[k]; } }
    return h;
  }
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
  function h(tag, props) {
    var node = document.createElement(tag);
    if (props) {
      for (var key in props) {
        if (!props.hasOwnProperty(key)) continue;
        if (key === 'className') node.className = props[key];
        else if (key === 'style') node.setAttribute('style', props[key]);
        else if (key === 'textContent') node.textContent = props[key];
        else if (key.slice(0, 5) === 'data-') node.setAttribute(key, props[key]);
        else if (key === 'checked') { if (props[key]) node.checked = true; }
        else node[key] = props[key];
      }
    }
    for (var i = 2; i < arguments.length; i++) _append(node, arguments[i]);
    return node;
  }
  function _append(parent, child) {
    if (child == null || child === false) return;
    if (typeof child === 'string' || typeof child === 'number') {
      parent.appendChild(document.createTextNode(String(child)));
    } else if (Array.isArray(child)) {
      for (var j = 0; j < child.length; j++) _append(parent, child[j]);
    } else {
      parent.appendChild(child);
    }
  }
  function clearNode(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
  }
  function setContent(container, children) {
    clearNode(container);
    var frag = document.createDocumentFragment();
    _append(frag, children);
    container.appendChild(frag);
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
    var themeSelect = document.getElementById('default-room-theme');
    if (themeSelect) {
      themeSelect.innerHTML = '<option value="">Default (from file)</option>';
      if (settings.availableThemes) {
        settings.availableThemes.forEach(function(t) {
          var opt = document.createElement('option');
          opt.value = t.key;
          opt.textContent = t.label;
          themeSelect.appendChild(opt);
        });
      }
      themeSelect.value = settings.defaultRoomTheme || '';
    }
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
    document.getElementById('toggle-welcome-modal').classList.toggle('active', settings.forceWelcomeModal);
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
    document.getElementById('toggle-show-admin-link').classList.toggle('active', settings.showAdminLink !== false);
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
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
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
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ rateLimitMaxAttempts: attempts, rateLimitWindow: windowVal })
    });
    showStatus('Rate limit settings saved', 'success');
  }

  async function saveForcedTheme() {
    var val = document.getElementById('forced-theme').value;
    await fetch('/api/admin/settings', {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
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
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
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
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
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
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ updateIntervalHours: val })
    });
    showStatus('Update interval saved', 'success');
  }

  async function triggerUpdate() {
    var btn = document.getElementById('update-btn');
    btn.disabled = true;
    btn.textContent = 'Updating...';
    try {
      var res = await fetch('/api/admin/update', { method: 'POST', headers: csrfHeaders() });
      var data = await res.json();
      if (data.success) {
        var msg = 'Updated to v' + (data.version || '?') + ' (' + Math.round(data.size / 1024) + 'KB)';
        if (data.previousVersion && data.previousVersion !== data.version) msg = 'Updated v' + data.previousVersion + ' → v' + data.version + ' (' + Math.round(data.size / 1024) + 'KB)';
        showStatus(msg, 'success');
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

  async function checkForUpdates() {
    var btn = document.getElementById('check-update-btn');
    btn.disabled = true;
    btn.textContent = 'Checking...';
    try {
      var res = await fetch('/api/admin/version-check');
      var data = await res.json();
      if (data.error) {
        showStatus(data.error, 'error');
      } else if (data.updateAvailable) {
        showStatus('Update available: v' + data.latestVersion + ' (current: v' + data.currentVersion + ')', 'success');
        var updateBtn = document.getElementById('update-btn');
        if (updateBtn) updateBtn.style.background = '#22c55e';
      } else {
        showStatus('Up to date (v' + data.currentVersion + ')', 'success');
      }
      settings.latestGitHubVersion = data.latestVersion;
      settings.lastVersionCheck = data.lastChecked;
      updateSourceUI();
    } catch (e) {
      showStatus('Version check failed', 'error');
    }
    btn.disabled = false;
    btn.textContent = 'Check for Updates';
  }

  async function changeSourceMode() {
    var mode = document.getElementById('source-mode').value;
    try {
      var res = await fetch('/api/admin/source-mode', {
        method: 'POST',
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
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
      var res = await fetch('/api/admin/upload-html', { method: 'POST', headers: csrfHeaders(), body: formData });
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
    var ver = settings.currentFileVersion || 'unknown';
    var edition = settings.currentFileEdition || 'unknown';
    var sizeKB = settings.currentFileSize ? Math.round(settings.currentFileSize / 1024) : 0;
    var versionEl = document.getElementById('current-version-badge');
    var editionEl = document.getElementById('current-edition-badge');
    var sizeEl = document.getElementById('file-size-info');
    var lastUpdateEl = document.getElementById('last-update-info');
    var statusBadge = document.getElementById('version-status-badge');
    if (versionEl) versionEl.textContent = 'v' + ver;
    if (editionEl) editionEl.textContent = edition.charAt(0).toUpperCase() + edition.slice(1) + ' edition';
    if (sizeEl) sizeEl.textContent = sizeKB + 'KB';
    if (lastUpdateEl) {
      if (settings.lastUpdateTimestamp) {
        var d = new Date(settings.lastUpdateTimestamp);
        lastUpdateEl.textContent = 'Last updated: ' + d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) + ' at ' + d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
      } else {
        lastUpdateEl.textContent = 'Never updated from GitHub';
      }
    }
    if (statusBadge) {
      var latest = settings.latestGitHubVersion;
      if (latest && latest !== 'unknown' && ver !== 'unknown') {
        if (latest === ver) {
          statusBadge.textContent = 'Up to date';
          statusBadge.style.background = '#166534';
          statusBadge.style.color = '#4ade80';
        } else {
          statusBadge.textContent = 'v' + latest + ' available';
          statusBadge.style.background = '#854d0e';
          statusBadge.style.color = '#fbbf24';
        }
      } else {
        statusBadge.textContent = '';
      }
    }
  }

  async function saveRoomDefaults() {
    await fetch('/api/admin/settings', {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({
        defaultDestructMode: document.getElementById('default-destruct-mode').value,
        defaultDestructHours: parseInt(document.getElementById('default-destruct-hours').value) || 24,
        maxRoomsPerInstance: parseInt(document.getElementById('max-rooms').value) || 0,
        defaultRoomTheme: document.getElementById('default-room-theme').value
      })
    });
    showStatus('Room defaults saved', 'success');
  }

  function showStatus(msg, type) {
    var container = document.getElementById('settings-status');
    setContent(container, h('div', {className: 'status-msg ' + type}, msg));
    setTimeout(function() { clearNode(container); }, 3000);
  }

  function showAuthStatus(msg, type) {
    var container = document.getElementById('auth-status');
    setContent(container, h('div', {className: 'status-msg ' + type}, msg));
    setTimeout(function() { clearNode(container); }, 3000);
  }

  function renderStats() {
    var active = rooms.filter(function(r) { return r.connectedUsers > 0; }).length;
    var withPwd = rooms.filter(function(r) { return r.hasPassword; }).length;
    var totalUsers = rooms.reduce(function(a, r) { return a + r.connectedUsers; }, 0);
    function statCard(value, label) {
      return h('div', {className: 'stat-card'},
        h('div', {className: 'stat-value'}, String(value)),
        h('div', {className: 'stat-label'}, label)
      );
    }
    setContent(document.getElementById('stats'), [
      statCard(rooms.length, 'Total Rooms'),
      statCard(active, 'Active'),
      statCard(withPwd, 'Protected'),
      statCard(totalUsers, 'Users Online')
    ]);
  }

  function renderRooms() {
    var container = document.getElementById('room-list');
    if (rooms.length === 0) {
      setContent(container, h('div', {className: 'empty-state'},
        h('h3', null, 'No rooms yet'),
        h('p', null, 'Rooms will appear here when created')
      ));
      return;
    }

    var header = h('div', {className: 'room-header'},
      h('input', {type: 'checkbox', className: 'room-checkbox', 'data-action': 'toggleAll', checked: selected.size === rooms.length && rooms.length > 0}),
      h('span', null, 'Room'), h('span', null, 'Users'), h('span', null, 'Created'), h('span', null, 'Password'), h('span', null, 'Actions')
    );

    var rows = rooms.map(function(r) {
      var isSelected = selected.has(r.id);
      return h('div', {className: 'room-row' + (isSelected ? ' selected' : '')},
        h('input', {type: 'checkbox', className: 'room-checkbox', checked: isSelected, 'data-action': 'toggleSelect', 'data-id': r.id}),
        h('div', null,
          h('div', {className: 'room-name'}, 'Room'),
          h('div', {className: 'room-id'}, r.id)
        ),
        h('div', null, h('span', {className: 'badge badge-' + (r.connectedUsers > 0 ? 'green' : 'gray')}, String(r.connectedUsers))),
        h('div', null, new Date(r.created).toLocaleDateString()),
        h('div', null, h('span', {className: 'badge badge-' + (r.hasPassword ? 'yellow' : 'gray')}, r.hasPassword ? 'Yes' : 'No')),
        h('div', {className: 'room-actions'},
          h('button', {className: 'btn btn-secondary btn-sm', 'data-action': 'viewRoom', 'data-id': r.id}, 'View'),
          h('button', {className: 'btn btn-primary btn-sm', 'data-action': 'joinRoom', 'data-id': r.id}, 'Join'),
          h('button', {className: 'btn btn-danger btn-sm', 'data-action': 'deleteRoom', 'data-id': r.id}, 'Del')
        )
      );
    });

    setContent(container, [header].concat(rows));
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
        await fetch('/api/admin/rooms/' + id, { method: 'DELETE', headers: csrfHeaders() });
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
      var hours = room.destruct.value / 3600000;
      destruct = hours < 1
        ? Math.round(hours * 60) + ' min'
        : hours < 24
          ? hours + ' hours'
          : Math.round(hours / 24) + ' days';
    } else if (room.destruct.mode === 'empty') {
      destruct = 'When empty';
    }

    document.getElementById('modal-title').textContent = 'Room Details';
    function infoRow(label, value, extraStyle) {
      return h('div', {className: 'info-row'},
        h('span', {className: 'info-label'}, label),
        h('span', {className: 'info-value', style: extraStyle || ''}, value)
      );
    }
    setContent(document.getElementById('modal-body'), [
      infoRow('Room ID', room.id, 'font-family:monospace;font-size:12px'),
      infoRow('Created', new Date(room.created).toLocaleString()),
      infoRow('Last Activity', new Date(room.lastActivity).toLocaleString()),
      infoRow('Connected Users', String(room.connectedUsers)),
      infoRow('Password Protected', room.hasPassword ? 'Yes' : 'No'),
      infoRow('Self-Destruct', destruct),
      h('div', {style: 'margin-top:20px;display:flex;gap:12px;flex-wrap:wrap'},
        h('button', {className: 'btn btn-primary', 'data-action': 'joinRoom', 'data-id': room.id}, 'Join Room'),
        h('button', {className: 'btn btn-danger', 'data-action': 'deleteRoom', 'data-id': room.id}, 'Delete Room')
      )
    ]);

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
      var res = await fetch('/api/admin/rooms/' + id, { method: 'DELETE', headers: csrfHeaders() });
      if (res.ok) {
        selected.delete(id);
        loadData();
      } else {
        showStatus('Failed to delete room', 'error');
      }
    } catch (e) {
      showStatus('Error deleting room', 'error');
    }
  }

  async function logout() {
    await fetch('/api/logout', { method: 'POST', credentials: 'include', headers: csrfHeaders() });
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
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ webhookUrl: url })
    });
    showStatus('Webhook URL saved', 'success');
  }

  async function saveBackupSettings() {
    var interval = parseInt(document.getElementById('backup-interval').value) || 24;
    var retention = parseInt(document.getElementById('backup-retention').value) || 7;
    await fetch('/api/admin/settings', {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
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
    var container = document.getElementById('activity-log-list');
    if (!logs || logs.length === 0) {
      setContent(container, h('p', {style: 'color:var(--text-soft);padding:12px'}, 'No activity logs'));
      return;
    }
    setContent(container, logs.map(function(l) {
      return h('div', {style: 'padding:8px 0;border-bottom:1px solid var(--border);font-size:13px'},
        h('span', {style: 'color:var(--text-soft)'}, new Date(l.timestamp).toLocaleString()), ' ',
        h('span', {className: 'badge badge-' + (l.eventType === 'join' ? 'green' : 'gray')}, l.eventType), ' ',
        l.userName || 'Unknown', ' ',
        h('span', {style: 'color:var(--text-soft);font-size:11px'}, l.roomId.slice(0, 8))
      );
    }));
  }

  function renderAuditLogs(logs) {
    var container = document.getElementById('audit-log-list');
    if (!logs || logs.length === 0) {
      setContent(container, h('p', {style: 'color:var(--text-soft);padding:12px'}, 'No audit logs'));
      return;
    }
    setContent(container, logs.map(function(l) {
      return h('div', {style: 'padding:8px 0;border-bottom:1px solid var(--border);font-size:13px'},
        h('span', {style: 'color:var(--text-soft)'}, new Date(l.timestamp).toLocaleString()), ' ',
        h('span', {className: 'badge badge-yellow'}, l.action), ' ',
        l.actor || 'system',
        l.targetId ? [' ', h('span', {style: 'color:var(--text-soft);font-size:11px'}, l.targetId.slice(0, 8))] : null
      );
    }));
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
    var container = document.getElementById('backup-list');
    if (!backups || backups.length === 0) {
      setContent(container, h('p', {style: 'color:var(--text-soft);padding:12px'}, 'No backups'));
      return;
    }
    setContent(container, backups.map(function(b) {
      return h('div', {style: 'display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)'},
        h('div', null,
          h('div', {style: 'font-weight:500'}, b.filename),
          h('div', {style: 'font-size:12px;color:var(--text-soft)'},
            new Date(b.createdAt).toLocaleString() + ' | ' + Math.round(b.sizeBytes / 1024) + 'KB | ' + b.roomCount + ' rooms' + (b.autoGenerated ? ' | Auto' : '')
          )
        ),
        h('div', {style: 'display:flex;gap:6px'},
          h('button', {className: 'btn btn-sm btn-secondary', 'data-action': 'downloadBackup', 'data-id': b.id}, 'Download'),
          h('button', {className: 'btn btn-sm btn-success', 'data-action': 'restoreBackup', 'data-id': b.id}, 'Restore'),
          h('button', {className: 'btn btn-sm btn-danger', 'data-action': 'deleteBackup', 'data-id': b.id}, 'Delete')
        )
      );
    }));
  }

  async function createBackup() {
    try {
      var res = await fetch('/api/admin/backups', { method: 'POST', headers: csrfHeaders() });
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
      var res = await fetch('/api/admin/backups/' + id + '/restore', { method: 'POST', headers: csrfHeaders() });
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
      await fetch('/api/admin/backups/' + id, { method: 'DELETE', headers: csrfHeaders() });
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
    var container = document.getElementById('apikey-list');
    if (!keys || keys.length === 0) {
      setContent(container, h('p', {style: 'color:var(--text-soft);padding:12px'}, 'No API keys'));
      return;
    }
    setContent(container, keys.map(function(k) {
      return h('div', {style: 'display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)'},
        h('div', null,
          h('div', {style: 'font-weight:500'}, k.name),
          h('div', {style: 'font-size:12px;color:var(--text-soft)'},
            k.permissions.join(', ') + ' | Created: ' + new Date(k.createdAt).toLocaleDateString() +
            (k.lastUsed ? ' | Last used: ' + new Date(k.lastUsed).toLocaleDateString() : '') +
            (k.expiresAt ? ' | Expires: ' + new Date(k.expiresAt).toLocaleDateString() : '')
          )
        ),
        h('button', {className: 'btn btn-sm btn-danger', 'data-action': 'revokeApiKey', 'data-id': k.id}, 'Revoke')
      );
    }));
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
      showStatus('Name required', 'error');
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
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ name: name, permissions: perms, expiresInDays: expires || null })
      });
      var data = await res.json();
      if (data.key) {
        closeApiKeyModal();
        document.getElementById('new-key-display').style.display = 'block';
        document.getElementById('new-key-value').textContent = data.key;
        loadApiKeys();
      } else {
        showStatus(data.error || 'Failed to create key', 'error');
      }
    } catch (e) {
      showStatus('Failed to create key', 'error');
    }
  }

  async function revokeApiKey(id) {
    if (!confirm('Revoke this API key?')) return;
    try {
      await fetch('/api/admin/api-keys/' + id, { method: 'DELETE', headers: csrfHeaders() });
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
    var container = document.getElementById('user-list');
    if (!users || users.length === 0) {
      setContent(container, h('div', {className: 'empty-state'},
        h('h3', null, 'No users yet'),
        h('p', null, 'Users will appear here when registered')
      ));
      return;
    }

    var header = h('div', {className: 'room-header'},
      h('span', null, 'User'), h('span', null, 'Role'), h('span', null, 'Status'), h('span', null, 'Created'), h('span', null, 'Actions')
    );

    var rows = users.map(function(u) {
      return h('div', {className: 'room-row'},
        h('div', null,
          h('div', {className: 'room-name'}, u.displayName || 'No name'),
          h('div', {className: 'room-id'}, u.email)
        ),
        h('div', null, h('span', {className: 'badge badge-' + (u.role === 'admin' ? 'yellow' : 'gray')}, u.role === 'admin' ? 'Admin' : 'User')),
        h('div', null,
          h('span', {className: 'badge badge-' + (u.isActive ? 'green' : 'gray')}, u.isActive ? 'Active' : 'Inactive'),
          u.emailVerified ? null : h('span', {className: 'badge badge-yellow'}, 'Unverified')
        ),
        h('div', null, new Date(u.createdAt).toLocaleDateString()),
        h('div', {className: 'room-actions'},
          h('button', {className: 'btn btn-secondary btn-sm', 'data-action': 'editUser', 'data-id': u.id}, 'Edit'),
          h('button', {className: 'btn btn-danger btn-sm', 'data-action': 'deleteUser', 'data-id': u.id}, 'Del')
        )
      );
    });

    setContent(container, [header].concat(rows));
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
      showAuthStatus('Email required', 'error');
      return;
    }
    try {
      var res = await fetch('/api/admin/users', {
        method: 'POST',
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ email: email, displayName: displayName, password: password, role: role })
      });
      var data = await res.json();
      if (data.success) {
        closeUserModal();
        loadUsers();
        showAuthStatus('User created', 'success');
      } else {
        showAuthStatus(data.error || 'Failed to create user', 'error');
      }
    } catch (e) {
      showAuthStatus('Failed to create user', 'error');
    }
  }

  async function deleteUser(id) {
    if (!confirm('Delete this user permanently?')) return;
    try {
      await fetch('/api/admin/users/' + id, { method: 'DELETE', headers: csrfHeaders() });
      loadUsers();
    } catch (e) {
      showAuthStatus('Error deleting user', 'error');
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
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(data)
      });
      var result = await res.json();
      if (result.success) {
        closeEditUserModal();
        loadUsers();
        showAuthStatus('User updated', 'success');
      } else {
        showAuthStatus(result.error || 'Failed to update user', 'error');
      }
    } catch (e) {
      showAuthStatus('Failed to update user', 'error');
    }
  }

  async function resetUserPassword() {
    var id = document.getElementById('edit-user-id').value;
    var email = document.getElementById('edit-user-email').value;
    if (!confirm('Send password reset email to ' + email + '?')) return;
    try {
      var res = await fetch('/api/admin/users/' + id + '/reset-password', { method: 'POST', headers: csrfHeaders() });
      var result = await res.json();
      if (result.success) {
        showAuthStatus('Password reset email sent!', 'success');
      } else {
        showAuthStatus(result.error || 'Failed to send reset email', 'error');
      }
    } catch (e) {
      showAuthStatus('Failed to send reset email', 'error');
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
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ authMode: mode })
    });
    showAuthStatus('Auth mode saved', 'success');
  }

  async function toggleAuthSetting(key) {
    authSettings[key] = !authSettings[key];
    renderAuthSettings();
    await fetch('/api/admin/auth-settings', {
      method: 'POST',
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
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
      headers: csrfHeaders({ 'Content-Type': 'application/json' }),
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
    var container = document.getElementById('oidc-provider-list');
    if (!oidcProviders || oidcProviders.length === 0) {
      setContent(container, h('p', {style: 'color:var(--text-soft);padding:12px'}, 'No OIDC providers configured'));
      return;
    }
    setContent(container, oidcProviders.map(function(p) {
      return h('div', {style: 'display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)'},
        h('div', null,
          h('div', {style: 'font-weight:500'}, p.name),
          h('div', {style: 'font-size:12px;color:var(--text-soft)'},
            p.providerType, ' | ',
            h('span', {style: 'color:' + (p.isActive ? '#22c55e' : '#94a3b8')}, p.isActive ? 'Active' : 'Inactive')
          )
        ),
        h('div', {style: 'display:flex;gap:6px'},
          h('button', {className: 'btn btn-sm btn-secondary', 'data-action': 'editOidcProvider', 'data-id': p.id}, 'Edit'),
          h('button', {className: 'btn btn-sm btn-danger', 'data-action': 'deleteOidcProvider', 'data-id': p.id}, 'Delete')
        )
      );
    }));
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
      showAuthStatus('Name and Client ID required', 'error');
      return;
    }
    try {
      var url = id ? '/api/admin/oidc-providers/' + id : '/api/admin/oidc-providers';
      var method = id ? 'PUT' : 'POST';
      var res = await fetch(url, {
        method: method,
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(data)
      });
      var result = await res.json();
      if (result.success) {
        closeOidcModal();
        loadOidcProviders();
        showAuthStatus('Provider saved', 'success');
      } else {
        showAuthStatus(result.error || 'Failed to save provider', 'error');
      }
    } catch (e) {
      showAuthStatus('Failed to save provider', 'error');
    }
  }

  async function deleteOidcProvider(id) {
    if (!confirm('Delete this OIDC provider?')) return;
    try {
      await fetch('/api/admin/oidc-providers/' + id, { method: 'DELETE', headers: csrfHeaders() });
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
    var container = document.getElementById('smtp-config-list');
    if (!smtpConfigs || smtpConfigs.length === 0) {
      setContent(container, h('p', {style: 'color:var(--text-soft);padding:12px'}, 'No SMTP configurations'));
      return;
    }
    setContent(container, smtpConfigs.map(function(s) {
      return h('div', {style: 'display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)'},
        h('div', null,
          h('div', {style: 'font-weight:500'},
            s.name,
            s.isDefault ? [' ', h('span', {className: 'badge badge-green'}, 'Default')] : null
          ),
          h('div', {style: 'font-size:12px;color:var(--text-soft)'},
            s.host, ':', String(s.port), ' (', s.secureMode, ') | ',
            h('span', {style: 'color:' + (s.isActive ? '#22c55e' : '#94a3b8')}, s.isActive ? 'Active' : 'Inactive')
          )
        ),
        h('div', {style: 'display:flex;gap:6px'},
          h('button', {className: 'btn btn-sm btn-secondary', 'data-action': 'editSmtpConfig', 'data-id': s.id}, 'Edit'),
          h('button', {className: 'btn btn-sm btn-danger', 'data-action': 'deleteSmtpConfig', 'data-id': s.id}, 'Delete')
        )
      );
    }));
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
      showAuthStatus('Name and Host required', 'error');
      return;
    }
    try {
      var url = id ? '/api/admin/smtp-configs/' + id : '/api/admin/smtp-configs';
      var method = id ? 'PUT' : 'POST';
      var res = await fetch(url, {
        method: method,
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(data)
      });
      var result = await res.json();
      if (result.success) {
        closeSmtpModal();
        loadSmtpConfigs();
        showAuthStatus('SMTP config saved', 'success');
      } else {
        showAuthStatus(result.error || 'Failed to save config', 'error');
      }
    } catch (e) {
      showAuthStatus('Failed to save config', 'error');
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
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(data)
      });
      var result = await res.json();
      if (result.success) {
        showAuthStatus('Test email sent successfully!', 'success');
      } else {
        showAuthStatus('Test failed: ' + (result.error || 'Unknown error'), 'error');
      }
    } catch (e) {
      showAuthStatus('Test failed', 'error');
    }
  }

  async function deleteSmtpConfig(id) {
    if (!confirm('Delete this SMTP configuration?')) return;
    try {
      await fetch('/api/admin/smtp-configs/' + id, { method: 'DELETE', headers: csrfHeaders() });
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
    var container = document.getElementById('email-template-list');
    if (!templates || templates.length === 0) {
      setContent(container, h('p', {style: 'color:var(--text-soft);padding:12px'}, 'No email templates. Default templates will be used.'));
      return;
    }
    setContent(container, templates.map(function(t) {
      return h('div', {style: 'display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)'},
        h('div', null,
          h('div', {style: 'font-weight:500'}, t.name),
          h('div', {style: 'font-size:12px;color:var(--text-soft)'}, 'Subject: ', t.subject)
        ),
        h('button', {className: 'btn btn-sm btn-secondary', 'data-action': 'editTemplate', 'data-id': t.id}, 'Edit')
      );
    }));
  }

  function sanitizeTemplateHtml(html) {
    var doc = new DOMParser().parseFromString(html, 'text/html');
    doc.querySelectorAll('script,iframe,object,embed,form').forEach(function(el) { el.remove(); });
    doc.querySelectorAll('*').forEach(function(el) {
      Array.from(el.attributes).forEach(function(attr) {
        if (attr.name.startsWith('on') || (typeof attr.value === 'string' && attr.value.trim().toLowerCase().startsWith('javascript:'))) {
          el.removeAttribute(attr.name);
        }
      });
      if (el.hasAttribute('href') && el.getAttribute('href').trim().toLowerCase().startsWith('javascript:')) {
        el.removeAttribute('href');
      }
      if (el.hasAttribute('src') && el.getAttribute('src').trim().toLowerCase().startsWith('javascript:')) {
        el.removeAttribute('src');
      }
    });
    return doc.body.innerHTML;
  }

  function editTemplate(id) {
    var t = emailTemplates.find(function(x) { return x.id === id; });
    if (!t) return;
    currentEditTemplate = t;
    document.getElementById('template-edit-id').value = id;
    document.getElementById('template-name').value = t.name;
    document.getElementById('template-subject').value = t.subject || '';
    var safeHtml = sanitizeTemplateHtml(t.bodyHtml || '');
    document.getElementById('template-editor').innerHTML = safeHtml;
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
      document.getElementById('template-editor').innerHTML = sanitizeTemplateHtml(document.getElementById('template-html-source').value);
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
      var safeUrl = url.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      var safeText = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      if (/^javascript:/i.test(safeUrl.trim())) return;
      var btn = '<a href="' + safeUrl + '" style="display:inline-block;padding:12px 24px;background:#c9a227;color:#fff;text-decoration:none;border-radius:6px;font-weight:600">' + safeText + '</a>';
      document.execCommand('insertHTML', false, btn);
    }
  }

  async function saveTemplate() {
    var id = document.getElementById('template-edit-id').value;
    if (!id) {
      showAuthStatus('No template selected', 'error');
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
        headers: csrfHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(data)
      });
      var result = await res.json();
      if (result.success) {
        closeTemplateModal();
        loadEmailTemplates();
        showAuthStatus('Template saved', 'success');
      } else {
        showAuthStatus(result.error || 'Failed to save template', 'error');
      }
    } catch (e) {
      showAuthStatus('Failed to save template', 'error');
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
    frame.sandbox = '';
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
    var container = document.getElementById('email-log-list');
    if (!emailLogs || emailLogs.length === 0) {
      setContent(container, h('p', {style: 'color:var(--text-soft);padding:12px'}, 'No email logs'));
      return;
    }
    setContent(container, emailLogs.map(function(l) {
      return h('div', {style: 'padding:8px 0;border-bottom:1px solid var(--border);font-size:13px'},
        h('span', {style: 'color:var(--text-soft)'}, new Date(l.sentAt).toLocaleString()), ' ',
        h('span', {className: 'badge badge-' + (l.status === 'sent' ? 'green' : 'gray')}, l.status), ' ',
        l.toEmail, ' ',
        h('span', {style: 'color:var(--text-soft)'}, l.subject),
        l.errorMessage ? [' ', h('span', {style: 'color:#ef4444'}, l.errorMessage)] : null
      );
    }));
  }

  async function clearEmailLogs() {
    if (!confirm('Clear all email logs? This cannot be undone.')) return;
    try {
      var res = await fetch('/api/admin/email-logs', { method: 'DELETE', headers: csrfHeaders() });
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
      var res = await fetch('/api/admin/activity-logs', { method: 'DELETE', headers: csrfHeaders() });
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
      var res = await fetch('/api/admin/audit-logs', { method: 'DELETE', headers: csrfHeaders() });
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
      checkForUpdates: checkForUpdates,
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
