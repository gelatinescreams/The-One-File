(function() {
  'use strict';

  function withLoading(fn) {
    return async function() {
      var btn = this instanceof HTMLElement ? this : null;
      if (btn) btn.disabled = true;
      try { await fn.call(this); }
      finally { if (btn) btn.disabled = false; }
    };
  }

  function showToast(message, type) {
    var stack = document.getElementById('toast-stack');
    if (!stack) {
      stack = document.createElement('div');
      stack.id = 'toast-stack';
      stack.className = 'toast-stack';
      document.body.appendChild(stack);
    }
    var toast = document.createElement('div');
    toast.className = 'toast-item' + (type ? ' ' + type : '');
    toast.textContent = message;
    stack.appendChild(toast);
    setTimeout(function() {
      toast.remove();
      if (stack.children.length === 0) stack.remove();
    }, 4000);
  }

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
    var btn = document.querySelector('.theme-toggle');
    if (forcedTheme && forcedTheme !== 'user') {
      btn.style.display = 'none';
    } else {
      btn.style.display = 'block';
    }
  }

  setTheme(getTheme());

  fetch('/api/theme').then(function(r) { return r.json(); }).then(function(data) {
    if (data.forcedTheme && data.forcedTheme !== 'user') {
      forcedTheme = data.forcedTheme;
      setTheme(forcedTheme);
    }
    updateThemeToggleVisibility();
    if (data.showAdminLink !== false) {
      var footer = document.getElementById('admin-footer');
      if (footer) footer.style.display = '';
    }
    if (data.adminPath) {
      var link = document.getElementById('admin-link');
      if (link) link.href = '/' + data.adminPath;
    }
  }).catch(function() { updateThemeToggleVisibility(); });

  var selectedFile = null;
  var selectedFileContent = null;

  function generateUUID() {
    if (crypto.randomUUID) return crypto.randomUUID();
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      var r = Math.random() * 16 | 0;
      return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
  }

  function getOrCreateUserId(roomId) {
    var key = 'collab-user-' + roomId;
    var id = localStorage.getItem(key);
    if (!id) { id = generateUUID(); localStorage.setItem(key, id); }
    return id;
  }

  function openModal(type) { document.getElementById(type + '-modal').classList.add('active'); }

  function closeModal(type) {
    var modal = document.getElementById(type + '-modal');
    modal.classList.remove('active');
    modal.querySelectorAll('input:not([type="checkbox"]):not([type="file"]):not([type="hidden"])').forEach(function(el) { el.value = ''; });
    modal.querySelectorAll('select').forEach(function(el) { var sel = el.querySelector('[selected]'); el.selectedIndex = sel ? sel.index : 0; });
    modal.querySelectorAll('.error-text').forEach(function(el) { el.textContent = ''; el.classList.remove('active'); });
    if (type === '2fa') { pending2FAToken = null; }
  }

  function clearAllAuthForms() {
    ['login-email', 'login-password', 'register-name', 'register-email', 'register-password',
     'forgot-email', 'magic-email', '2fa-code', 'settings-new-email', 'settings-email-password'
    ].forEach(function(id) { var el = document.getElementById(id); if (el) el.value = ''; });
    ['login-error', 'register-error', 'forgot-error', 'forgot-success', 'magic-error',
     'magic-success', '2fa-error', 'email-change-error', 'email-change-success'
    ].forEach(function(id) { var el = document.getElementById(id); if (el) { el.textContent = ''; el.classList.remove('active'); } });
    pending2FAToken = null;
  }

  function showError(type, msg) {
    var el = document.getElementById(type + '-error');
    el.textContent = msg;
    el.classList.add('active');
    el.setAttribute('role', 'alert');
  }

  var fileDrop = document.getElementById('create-file-drop');
  var fileInput = document.getElementById('create-file-input');

  fileDrop.addEventListener('click', function() { fileInput.click(); });
  fileDrop.addEventListener('dragover', function(e) { e.preventDefault(); });
  fileDrop.addEventListener('drop', function(e) { e.preventDefault(); handleFile(e.dataTransfer.files[0]); });
  fileInput.addEventListener('change', function(e) { handleFile(e.target.files[0]); });

  var MAX_FILE_SIZE_MB = 10;
  var MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;

  async function handleFile(file) {
    if (!file) return;
    if (file.size > MAX_FILE_SIZE_BYTES) {
      showError('create', 'File too large. Maximum size is ' + MAX_FILE_SIZE_MB + 'MB');
      return;
    }
    var ext = file.name.split('.').pop().toLowerCase();
    if (['html', 'json', 'csv', 'md', 'markdown', 'txt'].indexOf(ext) === -1) {
      showError('create', 'Invalid file type');
      return;
    }
    selectedFile = file;
    selectedFileContent = await file.text();
    document.getElementById('create-file-drop').style.display = 'none';
    document.getElementById('create-file-selected').classList.add('active');
    document.getElementById('create-file-name').textContent = file.name + ' (' + (file.size / 1024).toFixed(1) + 'KB)';
  }

  function clearFile() {
    selectedFile = null;
    selectedFileContent = null;
    document.getElementById('create-file-drop').style.display = 'block';
    document.getElementById('create-file-selected').classList.remove('active');
    fileInput.value = '';
  }

  function parseTopologyFile(content, filename) {
    var ext = filename.split('.').pop().toLowerCase();
    if (ext === 'json') { try { return JSON.parse(content); } catch(e) { return null; } }
    if (ext === 'html') {
      var match = content.match(/<script[^>]*id="topology-state"[^>]*>([\s\S]*?)<\/script>/i);
      if (match) { try { return JSON.parse(match[1]); } catch(e) {} }
      return null;
    }
    if (ext === 'csv') {
      var m = content.match(/#THEONEFILE_CONFIG:(.+)/);
      if (m) { try { return JSON.parse(m[1]); } catch(e) {} }
      return null;
    }
    if (['md', 'markdown', 'txt'].indexOf(ext) !== -1) {
      var m2 = content.match(/<!--THEONEFILE_CONFIG\s*([\s\S]*?)\s*THEONEFILE_CONFIG-->/);
      if (m2) { try { return JSON.parse(m2[1].trim()); } catch(e) {} }
      return null;
    }
    return null;
  }

  async function createRoom() {
    var password = document.getElementById('create-password').value;
    var destructVal = document.getElementById('create-destruct').value;
    var allowGuestsCheckbox = document.getElementById('create-allow-guests');
    var allowGuests = allowGuestsCheckbox ? allowGuestsCheckbox.checked : true;
    var destructMode = 'time', destructMs = parseInt(destructVal);
    if (destructVal === 'empty') { destructMode = 'empty'; destructMs = 0; }
    else if (destructVal === 'never') { destructMode = 'never'; destructMs = 0; }
    var topology = null;
    if (selectedFileContent) topology = parseTopologyFile(selectedFileContent, selectedFile.name);
    var tempId = generateUUID();
    var creatorId = getOrCreateUserId(tempId);
    try {
      var res = await fetch('/api/room', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
        body: JSON.stringify({ password: password || null, destructMode: destructMode, destructValue: destructMs, topology: topology, creatorId: creatorId, allowGuests: allowGuests })
      });
      var data = await res.json();
      if (data.error) { showError('create', data.error); return; }
      localStorage.setItem('collab-user-' + data.id, creatorId);
      window.location.href = data.url;
    } catch(e) { showError('create', 'Failed to create room'); }
  }

  var joinInput = document.getElementById('join-room-id');
  var checking = false;

  var joinDebounceTimer = null;
  joinInput.addEventListener('input', function() {
    var id = joinInput.value.trim();
    if (id.indexOf('/s/') !== -1) { id = id.split('/s/')[1].split('?')[0]; joinInput.value = id; }
    if (id.length < 36) return;
    if (joinDebounceTimer) clearTimeout(joinDebounceTimer);
    joinDebounceTimer = setTimeout(async function() {
      if (checking) return;
      checking = true;
      try {
        var res = await fetch('/api/room/' + id + '/exists');
        var data = await res.json();
        document.getElementById('join-password-group').style.display = data.hasPassword ? 'block' : 'none';
        if (!data.exists) showError('join', 'Room not found');
        else document.getElementById('join-error').classList.remove('active');
      } catch(e) {}
      checking = false;
    }, 300);
  });

  async function joinRoom() {
    var id = document.getElementById('join-room-id').value.trim();
    if (id.indexOf('/s/') !== -1) id = id.split('/s/')[1].split('?')[0];
    var password = document.getElementById('join-password').value;
    if (!id) { showError('join', 'Enter a room ID'); return; }
    try {
      var existsRes = await fetch('/api/room/' + id + '/exists');
      var exists = await existsRes.json();
      if (!exists.exists) { showError('join', 'Room not found'); return; }
      if (exists.hasPassword) {
        var verifyRes = await fetch('/api/room/' + id + '/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ password: password })
        });
        if (!(await verifyRes.json()).valid) { showError('join', 'Invalid password'); return; }
      }
      window.location.href = '/s/' + id;
    } catch(e) { showError('join', 'Failed to join room'); }
  }

  document.querySelectorAll('.modal-overlay').forEach(function(el) {
    el.addEventListener('click', function(e) {
      if (e.target === el) { var type = el.id.replace('-modal', ''); closeModal(type); }
    });
  });
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') document.querySelectorAll('.modal-overlay.active').forEach(function(m) { var type = m.id.replace('-modal', ''); closeModal(type); });
  });

  var currentUser = null;
  var authSettings = null;
  var oidcProviders = [];
  var csrfToken = '';
  var pending2FAToken = null;

  fetch('/api/auth/csrf').then(function(r) { return r.json(); }).then(function(d) { csrfToken = d.token; }).catch(function() {});

  async function loadAuthState() {
    try {
      var settingsRes = await fetch('/api/auth/settings', { credentials: 'include' });
      var settingsData = await settingsRes.json();
      authSettings = settingsData.settings;
      oidcProviders = settingsData.providers || [];
      var userRes = await fetch('/api/auth/me', { credentials: 'include' });
      var userData = await userRes.json();
      currentUser = userData.user;
      updateAuthUI();
    } catch(e) {
      console.error('Failed to load auth state:', e);
    }
  }

  function updateAuthUI() {
    var userMenu = document.getElementById('user-menu');
    var authButtonsEl = document.getElementById('auth-buttons');
    var guestToggle = document.getElementById('guest-toggle-container');

    if (currentUser) {
      userMenu.style.display = 'flex';
      authButtonsEl.style.display = 'none';
      document.getElementById('user-avatar').textContent = (currentUser.displayName || currentUser.email || 'U')[0].toUpperCase();
      document.getElementById('user-name').textContent = currentUser.displayName || (currentUser.email ? currentUser.email.split('@')[0] : 'User');
    } else if (authSettings) {
      userMenu.style.display = 'none';
      var hasOidc = oidcProviders && oidcProviders.length > 0;
      var registrationOpen = authSettings.authMode === 'open' || authSettings.authMode === 'registration';
      if (registrationOpen || hasOidc) {
        authButtonsEl.style.display = 'flex';
      }
    }

    if (authSettings && authSettings.allowRoomCreatorGuestSetting) {
      if (currentUser || authSettings.allowGuestRoomCreation) {
        guestToggle.style.display = 'flex';
      } else {
        guestToggle.style.display = 'none';
      }
    } else {
      guestToggle.style.display = 'none';
    }
    renderOidcProviders('login-oidc-providers', 'login');
    renderOidcProviders('register-oidc-providers', 'register');
  }

  function renderOidcProviders(containerId, mode) {
    var container = document.getElementById(containerId);
    var divider = document.getElementById(mode + '-divider');
    clearNode(container);

    if (oidcProviders.length === 0) {
      container.style.display = 'none';
      divider.style.display = 'none';
      return;
    }

    container.style.display = 'flex';
    divider.style.display = 'flex';

    oidcProviders.forEach(function(provider) {
      var btn = document.createElement('button');
      btn.className = 'oidc-btn';
      var safeUrl = provider.iconUrl && /^https?:\/\//i.test(provider.iconUrl) ? provider.iconUrl : null;
      var safeName = document.createElement('span');
      safeName.textContent = 'Continue with ' + (provider.name || 'SSO');
      if (safeUrl) {
        var img = document.createElement('img');
        img.src = safeUrl;
        img.alt = provider.name || 'SSO';
        btn.appendChild(img);
      }
      btn.appendChild(safeName);
      btn.addEventListener('click', function() { startOidcLogin(provider.id); });
      container.appendChild(btn);
    });
  }

  async function startOidcLogin(providerId) {
    try {
      var res = await fetch('/api/auth/oidc/' + providerId);
      var data = await res.json();
      if (data.url) {
        window.location.href = data.url;
      } else {
        showError('login', data.error || 'Failed to start SSO');
      }
    } catch(e) {
      showError('login', 'Failed to start SSO');
    }
  }

  async function loginWithPassword() {
    var email = document.getElementById('login-email').value.trim();
    var password = document.getElementById('login-password').value;
    if (!email || !password) { showError('login', 'Please enter email and password'); return; }
    try {
      var res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email: email, password: password, csrfToken: csrfToken })
      });
      var data = await res.json();
      if (data.requires2FA) {
        pending2FAToken = data.pendingToken;
        closeModal('login');
        openModal('2fa');
        setTimeout(function() { document.getElementById('2fa-code').focus(); }, 100);
        return;
      }
      if (res.ok && data.success) {
        window.location.reload();
      } else {
        showError('login', data.error || 'Login failed');
        fetch('/api/auth/csrf').then(function(r) { return r.json(); }).then(function(d) { csrfToken = d.token; }).catch(function() {});
      }
    } catch(e) {
      showError('login', 'Connection error');
    }
  }

  async function verify2FA() {
    var code = document.getElementById('2fa-code').value.trim();
    if (!code) { showError('2fa', 'Please enter your code'); return; }
    try {
      var res = await fetch('/api/auth/2fa/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ pendingToken: pending2FAToken, code: code })
      });
      var data = await res.json();
      if (res.ok && data.success) {
        window.location.reload();
      } else {
        showError('2fa', data.error || 'Invalid code');
      }
    } catch(e) {
      showError('2fa', 'Connection error');
    }
  }

  async function openSettingsModal() {
    openModal('settings');
    await load2FAStatus();
  }

  async function load2FAStatus() {
    var container = document.getElementById('2fa-status');
    try {
      var res = await fetch('/api/auth/me', { credentials: 'include' });
      var data = await res.json();
      if (!data.user) return;
      currentUser = data.user;
      if (data.user.totpEnabled) {
        setContent(container, [
          h('p', {style: 'color:#22c55e;font-size:14px;margin-bottom:12px'}, '\u2713 2FA is enabled'),
          h('div', {className: 'form-group'}, h('label', null, 'Password to Disable'), h('input', {type: 'password', id: '2fa-disable-password', placeholder: 'Enter password'})),
          h('div', {className: 'error-text', id: '2fa-setup-error'}),
          h('button', {className: 'btn btn-secondary', 'data-action': 'disable2FA', style: 'margin-top:8px'}, 'Disable 2FA')
        ]);
      } else {
        setContent(container, [
          h('p', {style: 'color:var(--text-soft);font-size:14px;margin-bottom:12px'}, '2FA is not enabled'),
          h('div', {className: 'error-text', id: '2fa-setup-error'}),
          h('button', {className: 'btn btn-secondary', 'data-action': 'setup2FA', style: 'margin-top:8px'}, 'Enable 2FA')
        ]);
      }
    } catch(e) {}
  }

  async function setup2FA() {
    var errEl = document.getElementById('2fa-setup-error');
    if (errEl) errEl.textContent = '';
    try {
      var res = await fetch('/api/auth/2fa/setup', { method: 'POST', credentials: 'include', headers: { 'x-csrf-token': csrfToken } });
      var data = await res.json();
      if (data.error) {
        if (errEl) errEl.textContent = data.error;
        return;
      }
      var container = document.getElementById('2fa-status');
      setContent(container, [
        h('p', {style: 'font-size:14px;color:var(--text-soft);margin-bottom:12px'}, 'Scan this QR code with your authenticator app, then enter the code below.'),
        h('div', {style: 'text-align:center;margin-bottom:16px'}, h('div', {id: '2fa-qr', style: 'display:inline-block;background:white;padding:16px;border-radius:8px'})),
        h('p', {style: 'font-size:12px;color:var(--text-soft);margin-bottom:16px;word-break:break-all;text-align:center'}, 'Manual entry: ', data.secret),
        h('div', {className: 'form-group'}, h('label', null, 'Verification Code'), h('input', {type: 'text', id: '2fa-setup-code', placeholder: '000000', maxLength: '6', inputMode: 'numeric', style: 'text-align:center;font-size:20px;letter-spacing:6px'})),
        h('div', {className: 'error-text', id: '2fa-setup-error'}),
        h('button', {className: 'btn btn-primary', 'data-action': 'verify2FASetup', style: 'margin-top:8px'}, 'Verify & Enable')
      ]);
      var renderSetupQR = function() {
        try {
          var el = document.getElementById('2fa-qr');
          var qr = qrcode(0, 'M');
          qr.addData(data.otpauthUrl);
          qr.make();
          var svg = qr.createSvgTag({ cellSize: 4, margin: 4 });
          var parsed = new DOMParser().parseFromString(svg, 'image/svg+xml');
          el.appendChild(document.importNode(parsed.documentElement, true));
        } catch(e) {}
      };
      if (typeof qrcode !== 'undefined') {
        renderSetupQR();
      } else {
        var s = document.createElement('script');
        s.src = '/qrcode.min.js';
        s.onload = renderSetupQR;
        document.head.appendChild(s);
      }
    } catch(e) {
      if (errEl) errEl.textContent = 'Connection error';
    }
  }

  async function verify2FASetup() {
    var code = document.getElementById('2fa-setup-code').value.trim();
    var errEl = document.getElementById('2fa-setup-error');
    if (!code || code.length !== 6) {
      if (errEl) errEl.textContent = 'Enter the 6 digit code';
      return;
    }
    try {
      var res = await fetch('/api/auth/2fa/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
        credentials: 'include',
        body: JSON.stringify({ code: code })
      });
      var data = await res.json();
      if (data.backupCodes) {
        var container = document.getElementById('2fa-status');
        var codeElements = [];
        data.backupCodes.forEach(function(code, i) {
          if (i > 0) codeElements.push(h('br', null));
          codeElements.push(code);
        });
        setContent(container, [
          h('p', {style: 'color:#22c55e;font-size:14px;margin-bottom:12px'}, '\u2713 2FA has been enabled!'),
          h('p', {style: 'font-size:14px;color:var(--text-soft);margin-bottom:12px'}, 'Save these backup codes in a safe place. Each can only be used once.'),
          h('div', {style: 'background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:16px;font-family:monospace;font-size:14px;line-height:2'}, codeElements),
          h('button', {className: 'btn btn-secondary', 'data-action': 'load2FAStatus', style: 'margin-top:16px'}, 'Done')
        ]);
      } else {
        if (errEl) errEl.textContent = data.error || 'Verification failed';
      }
    } catch(e) {
      if (errEl) errEl.textContent = 'Connection error';
    }
  }

  async function disable2FA() {
    var password = document.getElementById('2fa-disable-password').value;
    var errEl = document.getElementById('2fa-setup-error');
    if (!password) { if (errEl) errEl.textContent = 'Password required'; return; }
    try {
      var res = await fetch('/api/auth/2fa/disable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
        credentials: 'include',
        body: JSON.stringify({ password: password })
      });
      var data = await res.json();
      if (res.ok && data.success) {
        await load2FAStatus();
      } else {
        if (errEl) errEl.textContent = data.error || 'Failed to disable 2FA';
      }
    } catch(e) {
      if (errEl) errEl.textContent = 'Connection error';
    }
  }

  async function requestEmailChange() {
    var newEmail = document.getElementById('settings-new-email').value.trim();
    var password = document.getElementById('settings-email-password').value;
    var errEl = document.getElementById('email-change-error');
    var successEl = document.getElementById('email-change-success');
    errEl.textContent = '';
    successEl.textContent = '';
    if (!newEmail || !password) { errEl.textContent = 'Email and password required'; return; }
    try {
      var res = await fetch('/api/auth/email-change', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
        credentials: 'include',
        body: JSON.stringify({ newEmail: newEmail, password: password })
      });
      var data = await res.json();
      if (res.ok && data.success) {
        successEl.textContent = 'Verification email sent to ' + newEmail;
        document.getElementById('settings-new-email').value = '';
        document.getElementById('settings-email-password').value = '';
      } else {
        errEl.textContent = data.error || 'Failed to request email change';
      }
    } catch(e) {
      errEl.textContent = 'Connection error';
    }
  }

  async function registerUser() {
    var displayName = document.getElementById('register-name').value.trim();
    var email = document.getElementById('register-email').value.trim();
    var password = document.getElementById('register-password').value;
    if (!email || !password) { showError('register', 'Please enter email and password'); return; }
    if (password.length < 8) { showError('register', 'Password must be at least 8 characters'); return; }
    if (!/[a-zA-Z]/.test(password)) { showError('register', 'Password must contain at least one letter'); return; }
    if (!/[0-9!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]/.test(password)) { showError('register', 'Password must contain a number or special character'); return; }
    try {
      var res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email: email, password: password, displayName: displayName, csrfToken: csrfToken })
      });
      var data = await res.json();
      if (data.success) {
        if (data.requiresVerification) {
          closeModal('register');
          showToast('Please check your email to verify your account.', 'success');
        } else {
          window.location.reload();
        }
      } else {
        showError('register', data.error || 'Registration failed');
        fetch('/api/auth/csrf').then(function(r) { return r.json(); }).then(function(d) { csrfToken = d.token; }).catch(function() {});
      }
    } catch(e) {
      showError('register', 'Connection error');
    }
  }

  async function requestPasswordReset() {
    var email = document.getElementById('forgot-email').value.trim();
    if (!email) { showError('forgot', 'Please enter your email'); return; }
    try {
      var res = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email: email })
      });
      var data = await res.json();
      document.getElementById('forgot-error').classList.remove('active');
      var success = document.getElementById('forgot-success');
      success.textContent = 'If an account exists, we\'ve sent a reset link.';
      success.classList.add('active');
    } catch(e) {
      showError('forgot', 'Connection error');
    }
  }

  async function requestMagicLink() {
    var email = document.getElementById('magic-email').value.trim();
    if (!email) { showError('magic', 'Please enter your email'); return; }
    try {
      var res = await fetch('/api/auth/magic-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email: email })
      });
      var data = await res.json();
      document.getElementById('magic-error').classList.remove('active');
      var success = document.getElementById('magic-success');
      success.textContent = 'If an account exists, we\'ve sent a magic link.';
      success.classList.add('active');
    } catch(e) {
      showError('magic', 'Connection error');
    }
  }

  async function logout() {
    try {
      await fetch('/api/logout', { method: 'POST', credentials: 'include' });
    } catch(e) {}
    localStorage.removeItem('collab_token');
    localStorage.removeItem('user_token');
    currentUser = null;
    clearAllAuthForms();
    document.querySelectorAll('.modal-overlay.active').forEach(function(m) { m.classList.remove('active'); });
    window.location.reload();
  }

  var urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('auth_error')) {
    showToast('Authentication error: ' + urlParams.get('auth_error'), 'error');
    history.replaceState({}, '', '/');
  }
  if (urlParams.get('verified') === 'true') {
    showToast('Email verified! You can now sign in.', 'success');
    history.replaceState({}, '', '/');
  }
  if (urlParams.get('welcome') === 'true') {
    showToast('Welcome! Your account has been created.', 'success');
    history.replaceState({}, '', '/');
  }
  if (urlParams.get('error')) {
    var errorMessages = {
      'invalid_room': 'That room link is invalid.',
      'room_not_found': 'That room no longer exists.',
      'room_unavailable': 'Room is temporarily unavailable.',
      'not_found': 'Page not found.'
    };
    showToast(errorMessages[urlParams.get('error')] || 'Something went wrong.', 'error');
    history.replaceState({}, '', '/');
  }

  loadAuthState();

  document.querySelector('.theme-toggle').addEventListener('click', toggleTheme);

  document.querySelector('[data-action="openSettings"]').addEventListener('click', openSettingsModal);
  document.querySelector('[data-action="logout"]').addEventListener('click', logout);

  document.querySelector('[data-action="openLogin"]').addEventListener('click', function() { openModal('login'); });
  document.querySelector('[data-action="openRegister"]').addEventListener('click', function() { openModal('register'); });

  document.querySelector('[data-action="openCreate"]').addEventListener('click', function() { openModal('create'); });
  document.querySelector('[data-action="openJoin"]').addEventListener('click', function() { openModal('join'); });

  document.querySelectorAll('[data-close-modal]').forEach(function(btn) {
    btn.addEventListener('click', function() { closeModal(btn.dataset.closeModal); });
  });

  document.querySelector('[data-action="createRoom"]').addEventListener('click', withLoading(createRoom));
  document.querySelector('[data-action="joinRoom"]').addEventListener('click', withLoading(joinRoom));
  document.querySelector('[data-action="loginWithPassword"]').addEventListener('click', withLoading(loginWithPassword));
  document.querySelector('[data-action="registerUser"]').addEventListener('click', withLoading(registerUser));
  document.querySelector('[data-action="requestPasswordReset"]').addEventListener('click', withLoading(requestPasswordReset));
  document.querySelector('[data-action="requestMagicLink"]').addEventListener('click', withLoading(requestMagicLink));
  document.querySelector('[data-action="verify2FA"]').addEventListener('click', withLoading(verify2FA));
  document.querySelector('[data-action="requestEmailChange"]').addEventListener('click', withLoading(requestEmailChange));
  document.querySelector('[data-action="clearFile"]').addEventListener('click', clearFile);

  document.querySelector('[data-action="openForgot"]').addEventListener('click', function(e) {
    e.preventDefault();
    openModal('forgot');
    closeModal('login');
  });
  document.querySelector('[data-action="openMagic"]').addEventListener('click', function(e) {
    e.preventDefault();
    openModal('magic');
    closeModal('login');
  });

  document.getElementById('2fa-status').addEventListener('click', async function(e) {
    var target = e.target.closest('[data-action]');
    if (!target) return;
    target.disabled = true;
    try {
      var action = target.dataset.action;
      if (action === 'disable2FA') await disable2FA();
      else if (action === 'setup2FA') await setup2FA();
      else if (action === 'verify2FASetup') await verify2FASetup();
      else if (action === 'load2FAStatus') await load2FAStatus();
    } finally { target.disabled = false; }
  });

})();
