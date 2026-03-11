(function() {
  'use strict';

  const roomConfigEl = document.getElementById('room-config');
  if (!roomConfigEl) return;
  let _rc;
  try { _rc = JSON.parse(roomConfigEl.textContent); } catch { return; }
  if (!_rc.roomId) return;

  const ROOM_ID = _rc.roomId;
  const WS_URL = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws/' + _rc.roomId;
  const HAS_PASSWORD = _rc.roomHasPassword;
  const IS_ADMIN = _rc.isAdmin || false;
  const IS_CREATOR = _rc.isCreator || IS_ADMIN;
  if (_rc.csrfToken) window.CSRF_TOKEN = _rc.csrfToken;
  if (_rc.defaultRoomTheme) window.DEFAULT_ROOM_THEME = _rc.defaultRoomTheme;

  let shareButtonEnabled = true;

  function h(tag, props, ...children) {
    const node = document.createElement(tag);
    if (props) {
      for (const key of Object.keys(props)) {
        if (key === 'className') node.className = props[key];
        else if (key === 'style') node.setAttribute('style', props[key]);
        else if (key === 'textContent') node.textContent = props[key];
        else if (key.startsWith('data-')) node.setAttribute(key, props[key]);
        else if (key === 'checked') { if (props[key]) node.checked = true; }
        else if (key === 'readonly') { if (props[key]) node.readOnly = true; }
        else node[key] = props[key];
      }
    }
    for (const child of children) _append(node, child);
    return node;
  }
  function _append(parent, child) {
    if (child == null || child === false) return;
    if (typeof child === 'string' || typeof child === 'number') {
      parent.appendChild(document.createTextNode(String(child)));
    } else if (Array.isArray(child)) {
      for (const c of child) _append(parent, c);
    } else {
      parent.appendChild(child);
    }
  }
  function clearNode(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
  }
  function setContent(container, children) {
    clearNode(container);
    const frag = document.createDocumentFragment();
    _append(frag, Array.isArray(children) ? children : [children]);
    container.appendChild(frag);
  }

  function generateUUID() {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
      return crypto.randomUUID();
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  function getOrCreateUserId() {
    const globalKey = 'collab-global-user-id';
    let userId = localStorage.getItem(globalKey);
    if (!userId) {
      userId = generateUUID();
      localStorage.setItem(globalKey, userId);
    }
    return userId;
  }

  function getStoredUserName() {
    return localStorage.getItem(`collab-name-${ROOM_ID}`);
  }

  function setStoredUserName(name) {
    localStorage.setItem(`collab-name-${ROOM_ID}`, name);
  }

  const COLORS = [
    '#e63946', '#f4a261', '#2a9d8f', '#264653',
    '#e9c46a', '#8338ec', '#ff006e', '#3b82ff',
    '#06d6a0', '#118ab2', '#ef476f', '#ffd166',
    '#073b4c', '#06aed5', '#f72585', '#7209b7'
  ];

  const HIGHLANDER_NAMES = [
    'Connor MacLeod', 'Duncan MacLeod', 'Ramirez', 'The Kurgan',
    'Methos', 'Amanda Darieux', 'Richie Ryan', 'Joe Dawson',
    'Cassandra', 'Kronos', 'Silas', 'Caspian',
    'Xavier St. Cloud', 'Kalas', 'Fitzcairn', 'Darius',
    'Kenny', 'Ceirdwyn', 'Rebecca Horne', 'Grace Chandel',
    'Nakano', 'Kastagir', 'Sean Burns', 'Grayson',
    'Kern', 'Kell', 'Jacob Kell', 'Faith', 'Kane',
    'Quentin MacLeod', 'Kortan', 'Arak', 'Asklepios',
    'Hugh Fitzcairn', 'Carl Robinson', 'Annie Devlin'
  ];

  const HIGHLANDER_SYNC_QUOTES = [
    "There can be only one... state.",
    "I am immortal. Your data is eternal.",
    "The Quickening approaches...",
    "Gathering the power of all Immortals...",
    "From the dawn of time we came...",
    "In the end, there can be only one... source of truth.",
    "I have something to say! Syncing...",
    "It's better to burn out than to fade away... loading.",
    "The Prize awaits... synchronizing.",
    "Feel the Quickening!"
  ];

  const EMOJI_LIST = [
    '😀','😂','🤣','😊','😍','🤔','😎','🙄','😴','🤯',
    '👍','👎','👏','🙌','🤝','💪','🔥','❤️','💯','⭐',
    '✅','❌','⚡','💡','🎉','🚀','👀','🤷','😭','🥳'
  ];

  function getRandomSyncQuote() {
    return HIGHLANDER_SYNC_QUOTES[Math.floor(Math.random() * HIGHLANDER_SYNC_QUOTES.length)];
  }

  let syncOverlayTimeout = null;

  function showSyncingOverlay() {
    if (document.getElementById('collab-sync-overlay')) return;
    const overlay = document.createElement('div');
    overlay.id = 'collab-sync-overlay';
    overlay.appendChild(
      h('div', {className: 'collab-sync-content'},
        h('div', {className: 'collab-sync-sword'}),
        h('div', {className: 'collab-sync-lightning'}),
        h('div', {className: 'collab-sync-text'}, getRandomSyncQuote()),
        h('div', {className: 'collab-sync-subtext'}, 'Synchronizing with the realm...')
      )
    );
    document.body.appendChild(overlay);
    syncOverlayTimeout = setTimeout(() => {
      hideSyncingOverlay();
      showToast('Sync timed out. You may need to refresh.');
    }, 30000);
  }

  function hideSyncingOverlay() {
    if (syncOverlayTimeout) {
      clearTimeout(syncOverlayTimeout);
      syncOverlayTimeout = null;
    }
    const overlay = document.getElementById('collab-sync-overlay');
    if (overlay) {
      overlay.classList.add('fade-out');
      setTimeout(() => overlay.remove(), 300);
    }
  }

  function leaveRoom() {
    if (ws) {
      sendMessage('leave', { userId: window.COLLAB_USER.id });
      ws.close();
      ws = null;
    }

    localStorage.removeItem(`collab-name-${ROOM_ID}`);
    localStorage.removeItem(`collab-color-${ROOM_ID}`);

    window.location.href = '/';
  }

  function generateHighlanderName() {
    return HIGHLANDER_NAMES[Math.floor(Math.random() * HIGHLANDER_NAMES.length)];
  }

  function isValidColor(color) {
    return typeof color === 'string' && /^#[0-9a-fA-F]{6}$/.test(color);
  }

  function sanitizeColor(color) {
    return isValidColor(color) ? color : COLORS[0];
  }

  function getOrCreateUserColor() {
    const storageKey = `collab-color-${ROOM_ID}`;
    let color = localStorage.getItem(storageKey);
    if (!color || !isValidColor(color)) {
      color = pickUniqueColor();
      localStorage.setItem(storageKey, color);
    }
    return color;
  }

  function pickUniqueColor() {
    const usedColors = new Set();
    users.forEach(u => usedColors.add(u.color));
    const available = COLORS.filter(c => !usedColors.has(c));
    if (available.length > 0) {
      return available[Math.floor(Math.random() * available.length)];
    }
    return COLORS[Math.floor(Math.random() * COLORS.length)];
  }

  function getInitials(name) {
    if (!name) return '?';
    const parts = name.trim().split(/\s+/);
    if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
    return name.substring(0, 2).toUpperCase();
  }

  window.COLLAB_USER = {
    id: getOrCreateUserId(),
    name: null,
    color: null,
    selectedNodes: [],
    editingNode: null
  };

  const users = new Map();
  let ws = null;
  let reconnectAttempts = 0;
  let lastStateHash = null;
  let syncPaused = false;
  let hasReceivedInitialState = false;
  let chatMessages = [];
  let unreadCount = 0;
  let chatOpen = false;
  let replyingTo = null;
  let typingUsers = new Map();
  let typingTimeout = null;
  let lastTypingSent = 0;
  let connectionState = 'disconnected';
  let roomExpiryData = null;
  let expiryInterval = null;
  let chatSoundEnabled = localStorage.getItem('collab-chat-sound') !== 'false';
  let emojiPickerOpen = false;

  let currentWsToken = null;

  async function fetchWsToken() {
    try {
      const res = await fetch(`/api/room/${ROOM_ID}/ws-token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': window.CSRF_TOKEN || '' },
        body: JSON.stringify({ collabUserId: window.COLLAB_USER.id })
      });
      if (!res.ok) return null;
      const data = await res.json();
      if (data.collabUserId && data.collabUserId !== window.COLLAB_USER.id) {
        window.COLLAB_USER.id = data.collabUserId;
      }
      return data.wsToken;
    } catch (e) {
      console.warn('[Collab] Failed to fetch WS token:', e);
      return null;
    }
  }

  function setConnectionState(state) {
    connectionState = state;
    const dot = document.getElementById('collab-conn-dot');
    if (dot) {
      dot.className = 'collab-conn-status ' + state;
    }
    const banner = document.getElementById('collab-reconnect-banner');
    if (banner) {
      if (state === 'connected') {
        banner.classList.remove('active', 'offline');
      } else if (state === 'reconnecting') {
        banner.classList.add('active');
        banner.classList.remove('offline');
        banner.querySelector('span').textContent = 'Reconnecting...';
      } else if (state === 'disconnected') {
        banner.classList.add('active', 'offline');
        banner.querySelector('span').textContent = 'Connection lost';
      }
    }
  }

  async function connect() {
    if (ws && ws.readyState === WebSocket.OPEN) return;

    setConnectionState('reconnecting');
    currentWsToken = await fetchWsToken();

    ws = new WebSocket(WS_URL);

    ws.onopen = () => {
      if (currentWsToken) {
        ws.send(JSON.stringify({ type: 'auth', token: currentWsToken }));
      } else {
        reconnectAttempts = 0;
        setConnectionState('connected');
        window.COLLAB_USER.color = getOrCreateUserColor();
        hasReceivedInitialState = false;
        showSyncingOverlay();
        sendMessage('join', { user: window.COLLAB_USER });
      }
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        handleMessage(msg);
      } catch (e) {}
    };

    ws.onclose = () => {
      setConnectionState('reconnecting');
      scheduleReconnect();
    };
    ws.onerror = () => {};
  }

  function scheduleReconnect() {
    if (reconnectAttempts >= 10) {
      setConnectionState('disconnected');
      return;
    }
    const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
    reconnectAttempts++;
    setTimeout(connect, delay);
  }

  function sendMessage(type, data) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type, ...data }));
    }
  }

  function sanitizeUser(user) {
    if (user && user.color) {
      user.color = sanitizeColor(user.color);
    }
    return user;
  }

  function handleMessage(msg) {
    switch (msg.type) {
      case 'auth-ok':
        reconnectAttempts = 0;
        setConnectionState('connected');
        window.COLLAB_USER.color = getOrCreateUserColor();
        hasReceivedInitialState = false;
        showSyncingOverlay();
        sendMessage('join', { user: window.COLLAB_USER });
        return;
      case 'auth-error':
        console.error('[Collab] Auth failed:', msg.error);
        return;
      case 'join':
        users.set(msg.user.id, sanitizeUser(msg.user));
        renderUsers();
        renderUserIndicators();
        break;
      case 'leave':
        users.delete(msg.userId);
        removeUserIndicators(msg.userId);
        removeRemoteCursor(msg.userId);
        typingUsers.delete(msg.userId);
        updateTypingIndicator();
        renderUsers();
        break;
      case 'users':
        msg.users.forEach(u => {
          if (u.id !== window.COLLAB_USER.id) users.set(u.id, sanitizeUser(u));
        });
        renderUsers();
        renderUserIndicators();
        break;
      case 'presence':
        if (msg.userId !== window.COLLAB_USER.id) {
          const user = users.get(msg.userId);
          if (user) {
            user.selectedNodes = msg.selectedNodes || [];
            user.editingNode = msg.editingNode || null;
            user.currentTab = msg.currentTab || null;
            users.set(msg.userId, user);
            renderUserIndicators();
            renderUsers();
          }
        }
        break;
      case 'initial-state':
        hideSyncingOverlay();
        hasReceivedInitialState = true;
        if (msg.state) {
          applyRemoteState(msg.state);
          if (!msg.state.themeState && window.DEFAULT_ROOM_THEME) {
            var dPresets = typeof THEME_PRESETS !== 'undefined' ? THEME_PRESETS : null;
            if (dPresets && dPresets[window.DEFAULT_ROOM_THEME]) {
              setGlobal('PAGE_STATE', dPresets[window.DEFAULT_ROOM_THEME]);
              if (typeof wieldThePower === 'function') try { wieldThePower(); } catch(e) {}
              var dSel = document.getElementById('welcome-theme-select');
              if (dSel) dSel.value = window.DEFAULT_ROOM_THEME;
            }
          }
        } else {
          if (window.DEFAULT_ROOM_THEME) {
            var dPresets2 = typeof THEME_PRESETS !== 'undefined' ? THEME_PRESETS : null;
            if (dPresets2 && dPresets2[window.DEFAULT_ROOM_THEME]) {
              setGlobal('PAGE_STATE', dPresets2[window.DEFAULT_ROOM_THEME]);
              if (typeof wieldThePower === 'function') try { wieldThePower(); } catch(e) {}
              var dSel2 = document.getElementById('welcome-theme-select');
              if (dSel2) dSel2.value = window.DEFAULT_ROOM_THEME;
            }
          }
          sendFullState();
        }
        window.__collabSuppressWelcome = false;
        var _nd = getGlobal('NODE_DATA');
        var _ed = getGlobal('EDGE_DATA');
        var _roomEmpty = (!_nd || Object.keys(_nd).length === 0) && (!_ed || !_ed.list || _ed.list.length === 0);
        if (_roomEmpty || _rc.forceWelcomeModal) {
          if (typeof showWelcomeModal === 'function') showWelcomeModal();
        } else {
          var _wm = document.getElementById('welcome-modal');
          if (_wm) _wm.classList.remove('active');
        }
        break;
      case 'state':
        if (!syncPaused && hasReceivedInitialState) applyRemoteState(msg.state);
        break;
      case 'patch':
        if (!syncPaused && hasReceivedInitialState) applyRemoteState(msg.patch);
        break;
      case 'chat':
        addChatMessage(msg);
        break;
      case 'chat-history':
        if (msg.messages && Array.isArray(msg.messages)) {
          msg.messages.forEach(m => {
            if (!chatMessages.some(existing => existing.timestamp === m.timestamp && existing.userId === m.userId)) {
              chatMessages.push(m);
            }
          });
          chatMessages.sort((a, b) => a.timestamp - b.timestamp);
          if (chatMessages.length > 100) chatMessages = chatMessages.slice(-100);
          renderChatMessages();
        }
        break;
      case 'typing':
        if (msg.userId !== window.COLLAB_USER.id) {
          typingUsers.set(msg.userId, { name: msg.userName, expires: Date.now() + 3000 });
          updateTypingIndicator();
        }
        break;
      case 'cursor':
        if (msg.userId !== window.COLLAB_USER.id) {
          const user = users.get(msg.userId);
          if (user) {
            user.cursorX = msg.x;
            user.cursorY = msg.y;
            user.isRatio = msg.isRatio || false;
            user.isCanvasCoords = msg.isCanvasCoords || false;
            users.set(msg.userId, user);
            updateRemoteCursor(msg.userId, user);
            renderUsers();
          }
        }
        break;
      case 'name-rejected':
        handleNameRejected(msg.reason);
        break;
      case 'discovery-progress':
        updateDiscoveryProgress(msg.percent, msg.scanned, msg.total, msg.rangeIndex, msg.totalRanges);
        break;
      case 'discovery-found':
        addDiscoveryResult(msg.host);
        break;
      case 'discovery-complete':
        finalizeDiscovery(msg.totalFound);
        break;
      case 'deepscan-progress':
        handleDeepScanProgress(msg.scanId, msg.ip, msg.percent, msg.scanned, msg.total);
        break;
      case 'deepscan-update':
        handleDeepScanUpdate(msg.scanId, msg.ip, msg.newPorts, msg.newServices, msg.containers, msg.newIcons);
        break;
      case 'deepscan-complete':
        handleDeepScanComplete(msg.scanId, msg.ip);
        break;
    }
  }

  let nameRejectedRecovery = false;

  function handleNameRejected(reason) {
    hideSyncingOverlay();
    localStorage.removeItem(`collab-name-${ROOM_ID}`);
    window.COLLAB_USER.name = null;
    nameRejectedRecovery = true;
    showNameModal(false, reason);
  }

  let msgIdCounter = 0;

  function addChatMessage(msg) {
    const chatMsg = {
      id: msg.id || (Date.now() + '-' + (msgIdCounter++)),
      userId: msg.userId,
      userName: msg.userName,
      userColor: msg.userColor,
      text: msg.text,
      timestamp: msg.timestamp || Date.now(),
      replyTo: msg.replyTo || null
    };
    chatMessages.push(chatMsg);
    if (chatMessages.length > 100) chatMessages.shift();

    const isMentioned = msg.text && window.COLLAB_USER.name &&
      msg.text.toLowerCase().includes('@' + window.COLLAB_USER.name.toLowerCase());

    if (!chatOpen && msg.userId !== window.COLLAB_USER.id) {
      unreadCount++;
      updateChatBadge();
      if (chatSoundEnabled) playChatSound(isMentioned);
    }
    renderChatMessages();
  }

  function playChatSound(isMention) {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.type = 'sine';
      osc.frequency.value = isMention ? 880 : 660;
      gain.gain.value = 0.08;
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.15);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.15);
    } catch (e) {}
  }

  function sendChatMessage(text) {
    if (!text.trim()) return;
    let trimmedText = text.trim();
    if (trimmedText.length > 500) {
      trimmedText = trimmedText.substring(0, 500);
      showToast('Message truncated to 500 characters');
    }
    const msg = {
      id: Date.now() + '-' + (msgIdCounter++),
      userId: window.COLLAB_USER.id,
      userName: window.COLLAB_USER.name,
      userColor: window.COLLAB_USER.color,
      text: trimmedText,
      timestamp: Date.now(),
      replyTo: replyingTo ? { id: replyingTo.id, userName: replyingTo.userName, text: replyingTo.text.substring(0, 80) } : null
    };
    sendMessage('chat', msg);
    addChatMessage(msg);
    clearReply();
  }

  function setReplyTo(msg) {
    replyingTo = msg;
    const preview = document.getElementById('collab-reply-preview');
    if (preview) {
      preview.querySelector('span').textContent = `${msg.userName}: ${msg.text.substring(0, 60)}`;
      preview.classList.add('active');
    }
    const input = document.getElementById('collab-chat-input');
    if (input) input.focus();
  }

  function clearReply() {
    replyingTo = null;
    const preview = document.getElementById('collab-reply-preview');
    if (preview) preview.classList.remove('active');
  }

  function sendTypingIndicator() {
    const now = Date.now();
    if (now - lastTypingSent < 2000) return;
    lastTypingSent = now;
    sendMessage('typing', { userId: window.COLLAB_USER.id, userName: window.COLLAB_USER.name });
  }

  function updateTypingIndicator() {
    const now = Date.now();
    const active = [];
    typingUsers.forEach((data, userId) => {
      if (data.expires > now) active.push(data.name);
      else typingUsers.delete(userId);
    });
    const el = document.getElementById('collab-typing');
    if (!el) return;
    if (active.length === 0) {
      el.classList.remove('active');
    } else {
      el.classList.add('active');
      if (active.length === 1) el.textContent = active[0] + ' is typing...';
      else if (active.length === 2) el.textContent = active[0] + ' and ' + active[1] + ' are typing...';
      else el.textContent = active.length + ' people are typing...';
    }
  }

  setInterval(updateTypingIndicator, 1000);

  function showToast(message) {
    let stack = document.getElementById('collab-toast-stack');
    if (!stack) {
      stack = document.createElement('div');
      stack.id = 'collab-toast-stack';
      stack.className = 'collab-toast-stack';
      document.body.appendChild(stack);
    }
    const toast = document.createElement('div');
    toast.className = 'collab-toast-item';
    toast.textContent = message;
    stack.appendChild(toast);
    setTimeout(() => {
      toast.classList.add('fade-out');
      setTimeout(() => toast.remove(), 300);
    }, 3000);
    if (stack.children.length > 5) stack.firstChild.remove();
  }

  function updateChatBadge() {
    const badge = document.getElementById('collab-chat-badge');
    if (badge) {
      if (unreadCount > 0) {
        badge.textContent = unreadCount > 99 ? '99+' : unreadCount;
        badge.style.display = 'flex';
      } else {
        badge.style.display = 'none';
      }
    }
  }

  function highlightMentions(text) {
    const allNames = [window.COLLAB_USER.name];
    users.forEach(u => { if (u.name) allNames.push(u.name); });
    const validNames = allNames.filter(n => n);
    if (validNames.length === 0) return [text];
    const escaped = validNames.map(n => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    const regex = new RegExp('@(?:' + escaped.join('|') + ')', 'gi');
    const children = [];
    let lastIndex = 0;
    let match;
    while ((match = regex.exec(text)) !== null) {
      if (match.index > lastIndex) children.push(text.slice(lastIndex, match.index));
      children.push(h('span', {className: 'collab-chat-mention'}, match[0]));
      lastIndex = regex.lastIndex;
    }
    if (lastIndex < text.length) children.push(text.slice(lastIndex));
    return children.length > 0 ? children : [text];
  }

  function formatTimeAgo(timestamp) {
    const diff = Date.now() - timestamp;
    if (diff < 60000) return 'now';
    if (diff < 3600000) return Math.floor(diff / 60000) + 'm ago';
    if (diff < 86400000) return Math.floor(diff / 3600000) + 'h ago';
    return new Date(timestamp).toLocaleDateString([], { month: 'short', day: 'numeric' });
  }

  function renderChatMessages() {
    const container = document.getElementById('collab-chat-messages');
    if (!container) return;
    clearNode(container);
    chatMessages.forEach(msg => {
      const time = formatTimeAgo(msg.timestamp);
      const safeColor = sanitizeColor(msg.userColor);
      const isMentioned = msg.text && window.COLLAB_USER.name &&
        msg.text.toLowerCase().includes('@' + window.COLLAB_USER.name.toLowerCase());
      const msgDiv = h('div', {className: 'collab-chat-msg' + (isMentioned ? ' mentioned' : ''), 'data-msg-id': msg.id});
      if (msg.replyTo) {
        msgDiv.appendChild(h('div', {className: 'collab-chat-reply-ref'}, msg.replyTo.userName + ': ' + msg.replyTo.text));
      }
      msgDiv.appendChild(h('span', {className: 'collab-chat-name', style: 'color: ' + safeColor}, msg.userName));
      msgDiv.appendChild(h('span', {className: 'collab-chat-time'}, time));
      const replyBtn = h('button', {className: 'collab-chat-reply-btn', 'data-reply-id': msg.id}, 'Reply');
      replyBtn.addEventListener('click', () => {
        const m = chatMessages.find(x => x.id === msg.id);
        if (m) setReplyTo(m);
      });
      msgDiv.appendChild(replyBtn);
      msgDiv.appendChild(h('div', {className: 'collab-chat-text'}, highlightMentions(msg.text)));
      container.appendChild(msgDiv);
    });
    container.scrollTop = container.scrollHeight;
  }

  const CANVAS_WIDTH = 4000;
  const CANVAS_HEIGHT = 3000;

  function getCanvasState() {
    const state = getGlobal('canvasState');
    return state || { zoom: 1, panX: 0, panY: 0 };
  }

  function screenToCanvasCoords(screenX, screenY) {
    const viewport = document.getElementById('canvas-viewport');
    if (!viewport) return null;

    const rect = viewport.getBoundingClientRect();
    const cs = getCanvasState();

    const viewportX = screenX - rect.left;
    const viewportY = screenY - rect.top;

    const viewWidth = CANVAS_WIDTH / cs.zoom;
    const viewHeight = CANVAS_HEIGHT / cs.zoom;

    const canvasX = cs.panX + (viewportX / rect.width) * viewWidth;
    const canvasY = cs.panY + (viewportY / rect.height) * viewHeight;

    return { x: canvasX, y: canvasY };
  }

  function canvasToScreenCoords(canvasX, canvasY) {
    const viewport = document.getElementById('canvas-viewport');
    if (!viewport) return null;

    const rect = viewport.getBoundingClientRect();
    const cs = getCanvasState();

    const viewWidth = CANVAS_WIDTH / cs.zoom;
    const viewHeight = CANVAS_HEIGHT / cs.zoom;

    const ratioX = (canvasX - cs.panX) / viewWidth;
    const ratioY = (canvasY - cs.panY) / viewHeight;

    const screenX = rect.left + ratioX * rect.width;
    const screenY = rect.top + ratioY * rect.height;

    return { x: screenX, y: screenY };
  }

  function safeElementId(userId) {
    return typeof CSS !== 'undefined' && CSS.escape ? CSS.escape(userId) : userId.replace(/[^a-zA-Z0-9-_]/g, '');
  }

  function updateRemoteCursor(userId, user) {
    const safeId = safeElementId(userId);
    let cursor = document.getElementById(`collab-cursor-${safeId}`);
    if (!cursor && user.cursorX !== undefined) {
      cursor = document.createElement('div');
      cursor.id = `collab-cursor-${safeId}`;
      cursor.className = 'collab-remote-cursor';
      const safeColor = sanitizeColor(user.color);
      const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      svg.setAttribute('width', '16');
      svg.setAttribute('height', '16');
      svg.setAttribute('viewBox', '0 0 16 16');
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', 'M0 0L16 12L8 12L4 16L0 0Z');
      path.setAttribute('fill', safeColor);
      svg.appendChild(path);
      cursor.appendChild(svg);
      cursor.appendChild(h('span', {className: 'collab-cursor-name', style: 'background:' + safeColor}, user.name));
      document.body.appendChild(cursor);
    }
    if (cursor && user.cursorX !== undefined) {
      const viewport = document.getElementById('canvas-viewport');
      if (!viewport) {
        cursor.style.display = 'none';
        return;
      }

      const rect = viewport.getBoundingClientRect();
      let screenX, screenY;

      if (user.isCanvasCoords) {
        const screen = canvasToScreenCoords(user.cursorX, user.cursorY);
        if (!screen) {
          cursor.style.display = 'none';
          return;
        }
        screenX = screen.x;
        screenY = screen.y;
      } else if (user.isRatio) {
        screenX = rect.left + user.cursorX * rect.width;
        screenY = rect.top + user.cursorY * rect.height;
      } else {
        screenX = user.cursorX;
        screenY = user.cursorY;
      }

      const margin = 100;
      if (screenX < rect.left - margin || screenX > rect.right + margin ||
          screenY < rect.top - margin || screenY > rect.bottom + margin) {
        cursor.style.display = 'none';
        return;
      }

      cursor.style.display = 'block';
      cursor.style.left = screenX + 'px';
      cursor.style.top = screenY + 'px';
    }
  }

  function refreshAllRemoteCursors() {
    users.forEach((user, userId) => {
      if (user.cursorX !== undefined) {
        updateRemoteCursor(userId, user);
      }
    });
  }

  function removeRemoteCursor(userId) {
    const cursor = document.getElementById(`collab-cursor-${safeElementId(userId)}`);
    if (cursor) cursor.remove();
  }

  function trackCursor() {
    let lastSent = 0;
    let pendingPos = null;
    let rafId = null;

    function sendCursorUpdate() {
      if (!pendingPos) return;
      const canvas = screenToCanvasCoords(pendingPos.x, pendingPos.y);
      if (canvas) {
        sendMessage('cursor', {
          userId: window.COLLAB_USER.id,
          x: canvas.x,
          y: canvas.y,
          isCanvasCoords: true
        });
      }
      pendingPos = null;
      rafId = null;
    }

    document.addEventListener('mousemove', (e) => {
      const now = Date.now();
      if (now - lastSent < 25) return;
      lastSent = now;

      pendingPos = { x: e.clientX, y: e.clientY };
      if (rafId === null) {
        rafId = requestAnimationFrame(sendCursorUpdate);
      }
    });

    let lastZoom = null;
    let lastPanX = null;
    let lastPanY = null;
    setInterval(() => {
      const cs = getCanvasState();
      if (cs.zoom !== lastZoom || cs.panX !== lastPanX || cs.panY !== lastPanY) {
        lastZoom = cs.zoom;
        lastPanX = cs.panX;
        lastPanY = cs.panY;
        refreshAllRemoteCursors();
      }
    }, 100);
  }

  function getGlobal(name) {
    if (typeof window.__collabGetVar === 'function') return window.__collabGetVar(name);
    return undefined;
  }

  function setGlobal(name, value) {
    if (typeof window.__collabSetVar === 'function') return window.__collabSetVar(name, value);
    return false;
  }

  function captureState() {
    let state = null;

    if (typeof captureTheQuickening === 'function') {
      try {
        state = captureTheQuickening();
        delete state.canvas;
        if (state.documentTabs) {
          state.documentTabs = state.documentTabs.map(tab => {
            const { pageState, ...rest } = tab;
            return rest;
          });
        }
      } catch (e) { console.error('captureTheQuickening error:', e); }
    }

    if (!state) {
      const nodeData = getGlobal('NODE_DATA');
      if (!nodeData) return null;
      state = {
        nodeData: nodeData,
        edgeData: getGlobal('EDGE_DATA'),
        rectData: getGlobal('RECT_DATA'),
        textData: getGlobal('TEXT_DATA'),
        imageData: getGlobal('IMAGE_DATA'),
        nodePositions: getGlobal('savedPositions'),
        nodeSizes: getGlobal('savedSizes'),
        nodeStyles: getGlobal('savedStyles'),
        edgeLegend: getGlobal('EDGE_LEGEND'),
        zoneLegend: getGlobal('ZONE_LEGEND'),
        zonePresets: getGlobal('ZONE_PRESETS'),
        documentTabs: getGlobal('documentTabs'),
        currentTabIndex: getGlobal('currentTabIndex'),
        iconCache: getGlobal('iconCache'),
        auditLog: getGlobal('auditLog'),
        savedStyleSets: getGlobal('savedStyleSets'),
        autoPingEnabled: getGlobal('autoPingEnabled'),
        autoPingInterval: getGlobal('autoPingInterval'),
        savedTopologyView: getGlobal('savedTopologyView'),
        encryptedSections: getGlobal('encryptedSections')
      };
    }

    state.animSettings = getGlobal('ANIM_SETTINGS');
    state.rollbackVersions = getGlobal('rollbackVersions');
    state.customLang = getGlobal('CUSTOM_LANG');

    const pageState = getGlobal('PAGE_STATE');
    if (pageState) {
      state.themeState = {};
      const themeKeys = ['panel','panelAlt','accent','danger','textMain','textSoft',
        'background','canvasGrid','tagFill','tagText','tagBorder','sidebarBg',
        'btnBg','btnText','inputBg','inputText','inputBorder','toolbarBg',
        'toolbarBorder','toolbarText','toolbarBtnBg','toolbarBtnText'];
      for (const k of themeKeys) {
        if (pageState[k] !== undefined) state.themeState[k] = pageState[k];
      }
    }

    if (window.COLLAB_DEBUG) {
      console.log('[Collab] Captured state keys:', Object.keys(state));
      console.log('[Collab] nodeStyles count:', state.nodeStyles ? Object.keys(state.nodeStyles).length : 0);
      console.log('[Collab] savedStyleSets count:', state.savedStyleSets ? state.savedStyleSets.length : 0);
    }

    return state;
  }

  function hashState(state) {
    const str = JSON.stringify(state);
    let hash = 5381;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) + hash) + str.charCodeAt(i);
      hash = hash & hash;
    }
    return hash.toString(36);
  }

  function sendFullState() {
    const state = captureState();
    if (!state) return;
    lastStateHash = hashState(state);
    sendMessage('state', { state });
  }

  function applyRemoteState(state) {
    if (!state) return;
    syncPaused = true;
    try {
      if (window.COLLAB_DEBUG) {
        console.log('[Collab] Applying remote state, keys:', Object.keys(state));
        console.log('[Collab] Incoming nodeStyles:', state.nodeStyles ? Object.keys(state.nodeStyles).length : 'none');
      }

      const localTabIndex = getGlobal('currentTabIndex') || 0;
      const senderTabIndex = state.currentTabIndex !== undefined ? state.currentTabIndex : 0;

      if (state.documentTabs) {
        const localTabs = getGlobal('documentTabs') || [];
        const mergedTabs = state.documentTabs.map((remoteTab, i) => {
          const localTab = localTabs[i];
          return {
            ...remoteTab,
            pageState: localTab?.pageState || remoteTab.pageState || {}
          };
        });
        setGlobal('documentTabs', mergedTabs);
      }

      if (state.zoneLegend) setGlobal('ZONE_LEGEND', state.zoneLegend);
      if (state.zonePresets) setGlobal('ZONE_PRESETS', state.zonePresets);

      const tabs = getGlobal('documentTabs') || [];
      const myTab = tabs[localTabIndex];

      if (localTabIndex === senderTabIndex) {
        if (window.COLLAB_DEBUG) console.log('[Collab] Same tab, applying directly');
        if (state.nodeData) setGlobal('NODE_DATA', state.nodeData);
        if (state.edgeData) setGlobal('EDGE_DATA', state.edgeData);
        if (state.rectData) setGlobal('RECT_DATA', state.rectData);
        if (state.textData) setGlobal('TEXT_DATA', state.textData);
        if (state.imageData) setGlobal('IMAGE_DATA', state.imageData);
        if (state.nodePositions) setGlobal('savedPositions', state.nodePositions);
        if (state.nodeSizes) setGlobal('savedSizes', state.nodeSizes);
        if (state.nodeStyles) {
          if (window.COLLAB_DEBUG) console.log('[Collab] Setting savedStyles from nodeStyles');
          setGlobal('savedStyles', state.nodeStyles);
        }
        if (state.edgeLegend) setGlobal('EDGE_LEGEND', state.edgeLegend);
      } else if (myTab) {
        if (myTab.nodes) setGlobal('NODE_DATA', myTab.nodes);
        if (myTab.edges) setGlobal('EDGE_DATA', myTab.edges);
        if (myTab.positions) setGlobal('savedPositions', myTab.positions);
        if (myTab.sizes) setGlobal('savedSizes', myTab.sizes);
        if (myTab.styles) setGlobal('savedStyles', myTab.styles);
        if (myTab.legend) setGlobal('EDGE_LEGEND', myTab.legend);
        if (myTab.rects) setGlobal('RECT_DATA', myTab.rects);
        if (myTab.texts) setGlobal('TEXT_DATA', myTab.texts);
        if (myTab.images) setGlobal('IMAGE_DATA', myTab.images);
      }

      if (state.iconCache) setGlobal('iconCache', state.iconCache);
      if (state.auditLog) setGlobal('auditLog', state.auditLog);
      if (state.savedStyleSets) setGlobal('savedStyleSets', state.savedStyleSets);
      if (state.autoPingEnabled !== undefined) setGlobal('autoPingEnabled', state.autoPingEnabled);
      if (state.autoPingInterval !== undefined) setGlobal('autoPingInterval', state.autoPingInterval);
      if (state.savedTopologyView) setGlobal('savedTopologyView', state.savedTopologyView);
      if (state.animSettings) setGlobal('ANIM_SETTINGS', state.animSettings);
      if (state.rollbackVersions) setGlobal('rollbackVersions', state.rollbackVersions);
      if (state.customLang) setGlobal('CUSTOM_LANG', state.customLang);
      if (state.encryptedSections) setGlobal('encryptedSections', state.encryptedSections);

      if (typeof forgeTheTopology === 'function') {
        try { forgeTheTopology(); } catch (e) {}
      }
      if (state.themeState) {
        setGlobal('PAGE_STATE', state.themeState);
        if (typeof wieldThePower === 'function') {
          try { wieldThePower(); } catch (e) {}
        }
      }
    } finally {
      setTimeout(() => { syncPaused = false; }, 200);
    }
  }

  const STATE_SYNC_MIN_INTERVAL = 500;
  const STATE_SYNC_DEBOUNCE = 300;
  let lastStateSyncTime = 0;
  let stateSyncTimeout = null;

  function syncStateIfChanged() {
    const state = captureState();
    if (!state) return;
    const currentHash = hashState(state);
    if (currentHash === lastStateHash) return;
    lastStateHash = currentHash;
    sendMessage('state', { state });
    lastStateSyncTime = Date.now();
  }

  function startStatePolling() {
    setInterval(() => {
      if (syncPaused || !hasReceivedInitialState) return;

      const now = Date.now();
      const timeSinceLastSync = now - lastStateSyncTime;

      if (timeSinceLastSync < STATE_SYNC_MIN_INTERVAL) {
        if (!stateSyncTimeout) {
          stateSyncTimeout = setTimeout(() => {
            stateSyncTimeout = null;
            syncStateIfChanged();
          }, STATE_SYNC_DEBOUNCE);
        }
        return;
      }

      syncStateIfChanged();
    }, 250);
  }

  function sendPresence() {
    sendMessage('presence', {
      userId: window.COLLAB_USER.id,
      selectedNodes: window.COLLAB_USER.selectedNodes || [],
      editingNode: window.COLLAB_USER.editingNode,
      currentTab: getCurrentTabName()
    });
  }

  function trackSelection() {
    const map = document.getElementById('map');
    if (!map) { setTimeout(trackSelection, 500); return; }

    let lastTab = getCurrentTabName();
    setInterval(() => {
      const currentTab = getCurrentTabName();
      if (currentTab !== lastTab) {
        lastTab = currentTab;
        sendPresence();
        renderUsers();
      }
    }, 500);

    const observer = new MutationObserver(() => {
      const selected = [];
      document.querySelectorAll('.node-group.selected, [data-id].selected').forEach(el => {
        const id = el.dataset?.id || el.getAttribute('data-id');
        if (id) selected.push(id);
      });
      if (JSON.stringify(selected) !== JSON.stringify(window.COLLAB_USER.selectedNodes)) {
        window.COLLAB_USER.selectedNodes = selected;
        sendPresence();
        renderUsers();
      }
    });
    observer.observe(map, { subtree: true, attributes: true, attributeFilter: ['class'] });
  }

  function setupAuditLogInjection() {
    if (typeof window.__collabGetVar !== 'function') return;

    if (typeof window.addAuditEntry === 'function') {
      window.__collabOriginalAddAudit = window.addAuditEntry;
      window.addAuditEntry = function(type, description, details) {
        const entry = {
          timestamp: Date.now(),
          type: type,
          description: description,
          details: details || {},
          tab: window.__collabGetVar('documentTabs')?.[window.__collabGetVar('currentTabIndex')]?.name || 'Main',
          user: window.COLLAB_USER?.name || 'Unknown',
          userColor: window.COLLAB_USER?.color || '#888'
        };
        const auditLog = window.__collabGetVar('auditLog') || [];
        auditLog.unshift(entry);
        if (auditLog.length > 1000) auditLog.pop();
        window.__collabSetVar('auditLog', auditLog);
        return entry;
      };
    }
  }

  function getCurrentTabName() {
    try {
      const tabs = getGlobal('documentTabs');
      const idx = getGlobal('currentTabIndex') || 0;
      if (tabs && tabs[idx]) return tabs[idx].name || 'Main';
      return 'Main';
    } catch { return 'Main'; }
  }

  function renderUsers() {
    const container = document.querySelector('.collab-users');
    if (!container) return;
    const myTab = getCurrentTabName();
    const allUsers = [window.COLLAB_USER, ...users.values()];
    clearNode(container);
    allUsers.forEach(user => {
      const isMe = user.id === window.COLLAB_USER.id;
      const tabName = isMe ? myTab : (user.currentTab || 'Main');
      const safeColor = sanitizeColor(user.color);
      const initials = getInitials(user.name);
      container.appendChild(
        h('div', {className: 'collab-user' + (isMe ? ' me' : ''), 'data-user-id': user.id},
          h('div', {className: 'collab-user-avatar', style: 'background: ' + safeColor}, initials),
          h('div', {className: 'collab-user-info'},
            h('span', {className: 'collab-user-name'}, user.name),
            user.editingNode ? h('span', {className: 'collab-user-editing'}, 'editing') : null,
            h('span', {className: 'collab-user-tab'}, tabName)
          )
        )
      );
    });
  }

  function renderUserIndicators() {
    document.querySelectorAll('.collab-node-indicator, .collab-selection-ring').forEach(el => el.remove());
    users.forEach(user => {
      if (!user.selectedNodes) return;
      user.selectedNodes.forEach(nodeId => {
        if (typeof nodeId !== 'string' || !/^[\w-]+$/.test(nodeId)) return;
        const nodeEl = document.querySelector(`[data-id="${nodeId}"]`);
        if (!nodeEl) return;
        const ring = document.createElement('div');
        ring.className = 'collab-selection-ring';
        ring.style.borderColor = user.color;
        ring.dataset.collabUserId = user.id;
        const nodeGroup = nodeEl.closest('.node-group') || nodeEl;
        nodeGroup.style.position = 'relative';
        nodeGroup.appendChild(ring);
        const label = document.createElement('div');
        label.className = 'collab-node-indicator';
        label.style.background = user.color;
        label.style.color = '#fff';
        label.textContent = user.name;
        label.dataset.collabUserId = user.id;
        nodeGroup.appendChild(label);
      });
    });
  }

  function removeUserIndicators(userId) {
    document.querySelectorAll(`[data-collab-user-id="${userId}"]`).forEach(el => el.remove());
  }

  function updateCharCount() {
    const input = document.getElementById('collab-chat-input');
    const counter = document.getElementById('collab-char-count');
    if (!input || !counter) return;
    const len = input.value.length;
    const remaining = 500 - len;
    if (remaining <= 50) {
      counter.textContent = remaining;
      counter.className = 'collab-chat-char-count' + (remaining <= 20 ? ' danger' : ' warning');
    } else {
      counter.textContent = '';
      counter.className = 'collab-chat-char-count';
    }
  }

  function toggleEmojiPicker() {
    emojiPickerOpen = !emojiPickerOpen;
    const picker = document.getElementById('collab-emoji-picker');
    if (picker) picker.classList.toggle('active', emojiPickerOpen);
  }

  function insertEmoji(emoji) {
    const input = document.getElementById('collab-chat-input');
    if (!input) return;
    const start = input.selectionStart || input.value.length;
    input.value = input.value.substring(0, start) + emoji + input.value.substring(input.selectionEnd || start);
    input.focus();
    input.selectionStart = input.selectionEnd = start + emoji.length;
    updateCharCount();
    emojiPickerOpen = false;
    const picker = document.getElementById('collab-emoji-picker');
    if (picker) picker.classList.remove('active');
  }

  function updateExpiryCountdown() {
    const el = document.getElementById('collab-expiry');
    if (!el || !roomExpiryData) { if (el) el.style.display = 'none'; return; }
    if (!roomExpiryData.destruct || roomExpiryData.destruct.mode === 'none') { el.style.display = 'none'; return; }

    if (roomExpiryData.destruct.mode === 'empty') {
      el.style.display = 'flex';
      el.textContent = 'Destroys when empty';
      return;
    }

    if (roomExpiryData.destruct.mode === 'time') {
      const created = new Date(roomExpiryData.created).getTime();
      const expiresAt = created + roomExpiryData.destruct.value;
      const remaining = expiresAt - Date.now();
      if (remaining <= 0) {
        el.style.display = 'flex';
        el.textContent = 'Expiring...';
        return;
      }
      el.style.display = 'flex';
      const hours = Math.floor(remaining / 3600000);
      const mins = Math.floor((remaining % 3600000) / 60000);
      if (hours > 24) el.textContent = Math.ceil(hours / 24) + 'd left';
      else if (hours > 0) el.textContent = hours + 'h ' + mins + 'm left';
      else el.textContent = mins + 'm left';
    }
  }

  function injectCollabBar() {
    document.body.classList.add('collab-active');

    const bar = document.createElement('div');
    bar.id = 'collab-bar';
    _append(bar, [
      h('div', {id: 'collab-conn-dot', className: 'collab-conn-status connected'}),
      h('div', {className: 'collab-users'}),
      h('div', {id: 'collab-expiry', className: 'collab-room-expiry', style: 'display:none'}),
      h('div', {className: 'collab-actions'},
        h('button', {className: 'collab-btn', id: 'collab-chat-btn'},
          h('span', {className: 'collab-btn-icon'}, '\u2709'),
          h('span', null, 'Chat'),
          h('span', {className: 'collab-chat-badge', id: 'collab-chat-badge'})
        ),
        h('button', {className: 'collab-btn', id: 'collab-share-btn', style: shareButtonEnabled ? '' : 'display:none'},
          h('span', {className: 'collab-btn-icon'}, '+'),
          h('span', null, 'Share')
        ),
        h('button', {className: 'collab-btn', id: 'collab-menu-btn'},
          h('span', {className: 'collab-btn-icon'}, '=')
        )
      )
    ]);
    document.body.prepend(bar);

    const reconnectBanner = document.createElement('div');
    reconnectBanner.id = 'collab-reconnect-banner';
    reconnectBanner.className = 'collab-reconnect-banner';
    _append(reconnectBanner, [
      h('span', null, 'Reconnecting...'),
      h('button', {className: 'collab-reconnect-btn', id: 'collab-reconnect-btn'}, 'Reconnect')
    ]);
    document.body.appendChild(reconnectBanner);

    document.getElementById('collab-reconnect-btn').addEventListener('click', () => {
      reconnectAttempts = 0;
      connect();
    });

    const chatPanel = document.createElement('div');
    chatPanel.id = 'collab-chat-panel';
    _append(chatPanel, [
      h('div', {className: 'collab-chat-header'},
        h('span', null, 'Chat'),
        h('button', {className: 'collab-chat-close', id: 'collab-chat-close'}, '\u00d7')
      ),
      h('div', {className: 'collab-chat-messages', id: 'collab-chat-messages'}),
      h('div', {id: 'collab-typing', className: 'collab-typing-indicator'}),
      h('div', {className: 'collab-chat-input-area', style: 'position:relative'},
        h('div', {id: 'collab-reply-preview', className: 'collab-chat-reply-preview'},
          h('span', null, ''),
          h('button', {className: 'collab-chat-reply-cancel', id: 'collab-reply-cancel'}, '\u00d7')
        ),
        h('div', {id: 'collab-emoji-picker', className: 'collab-emoji-picker'},
          h('div', {className: 'collab-emoji-grid'},
            EMOJI_LIST.map(e => h('button', {className: 'collab-emoji-btn', 'data-emoji': e}, e))
          )
        ),
        h('div', {className: 'collab-chat-input-wrap'},
          h('button', {className: 'collab-emoji-toggle', id: 'collab-emoji-toggle'}, '\ud83d\ude0a'),
          h('div', {className: 'collab-chat-input-inner'},
            h('input', {type: 'text', id: 'collab-chat-input', placeholder: 'Type a message...', maxLength: 500, autocomplete: 'off'}),
            h('div', {className: 'collab-chat-char-count', id: 'collab-char-count'})
          ),
          h('button', {id: 'collab-chat-send'}, 'Send')
        )
      )
    ]);
    document.body.appendChild(chatPanel);

    const shareModal = document.createElement('div');
    shareModal.id = 'collab-share-modal';
    shareModal.className = 'collab-modal-overlay';
    shareModal.appendChild(
      h('div', {className: 'collab-modal'},
        h('div', {className: 'collab-modal-header'},
          h('h3', null, 'Share Room'),
          h('button', {className: 'collab-modal-close'}, '\u00d7')
        ),
        h('div', {className: 'collab-modal-body'},
          h('div', {className: 'collab-share-url'},
            h('input', {type: 'text', readonly: true, value: window.location.href, id: 'collab-share-input'}),
            h('button', {id: 'collab-copy-btn'}, 'Copy')
          ),
          h('div', {className: 'collab-qr', id: 'collab-qr'}),
          h('p', {className: 'collab-share-note'}, HAS_PASSWORD ? 'Password protected. Share password separately.' : 'Anyone with this link can join.')
        )
      )
    );
    document.body.appendChild(shareModal);

    const infoModal = document.createElement('div');
    infoModal.id = 'collab-info-modal';
    infoModal.className = 'collab-modal-overlay';
    infoModal.appendChild(
      h('div', {className: 'collab-modal'},
        h('div', {className: 'collab-modal-header'},
          h('h3', null, 'Room Info'),
          h('button', {className: 'collab-modal-close'}, '\u00d7')
        ),
        h('div', {className: 'collab-modal-body'},
          h('div', {id: 'collab-info-content'})
        )
      )
    );
    document.body.appendChild(infoModal);

    const menuDropdown = document.createElement('div');
    menuDropdown.id = 'collab-menu-dropdown';
    _append(menuDropdown, [
      shareButtonEnabled ? h('button', {className: 'collab-menu-item', id: 'collab-menu-copy'}, 'Copy Link') : null,
      h('button', {className: 'collab-menu-item', id: 'collab-menu-info'}, 'Room Info'),
      h('button', {className: 'collab-menu-item', id: 'collab-menu-name'}, 'Change Name'),
      h('button', {className: 'collab-menu-item', id: 'collab-menu-sound'}, chatSoundEnabled ? 'Mute Sounds' : 'Unmute Sounds'),
      h('div', {className: 'collab-menu-divider'}),
      h('button', {className: 'collab-menu-item', id: 'collab-menu-leave'}, 'Leave Room'),
      IS_CREATOR ? h('button', {className: 'collab-menu-item danger', id: 'collab-menu-delete'}, 'Delete Room') : null
    ]);
    document.body.appendChild(menuDropdown);

    document.getElementById('collab-chat-btn').addEventListener('click', () => {
      chatOpen = !chatOpen;
      chatPanel.classList.toggle('active', chatOpen);
      if (chatOpen) {
        unreadCount = 0;
        updateChatBadge();
        document.getElementById('collab-chat-input').focus();
      }
    });

    document.getElementById('collab-chat-close').addEventListener('click', () => {
      chatOpen = false;
      chatPanel.classList.remove('active');
      emojiPickerOpen = false;
      const picker = document.getElementById('collab-emoji-picker');
      if (picker) picker.classList.remove('active');
    });

    document.getElementById('collab-chat-send').addEventListener('click', () => {
      const input = document.getElementById('collab-chat-input');
      sendChatMessage(input.value);
      input.value = '';
      updateCharCount();
    });

    const chatInput = document.getElementById('collab-chat-input');
    chatInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendChatMessage(e.target.value);
        e.target.value = '';
        updateCharCount();
      }
    });

    chatInput.addEventListener('input', () => {
      updateCharCount();
      sendTypingIndicator();
    });

    document.getElementById('collab-reply-cancel').addEventListener('click', clearReply);

    document.getElementById('collab-emoji-toggle').addEventListener('click', (e) => {
      e.stopPropagation();
      toggleEmojiPicker();
    });

    document.getElementById('collab-emoji-picker').addEventListener('click', (e) => {
      e.stopPropagation();
      const emoji = e.target.dataset?.emoji;
      if (emoji) insertEmoji(emoji);
    });

    document.getElementById('collab-share-btn').addEventListener('click', () => {
      shareModal.classList.add('active');
      generateQR();
    });

    shareModal.querySelector('.collab-modal-close').addEventListener('click', () => shareModal.classList.remove('active'));
    shareModal.addEventListener('click', (e) => { if (e.target === shareModal) shareModal.classList.remove('active'); });
    infoModal.querySelector('.collab-modal-close').addEventListener('click', () => infoModal.classList.remove('active'));
    infoModal.addEventListener('click', (e) => { if (e.target === infoModal) infoModal.classList.remove('active'); });

    document.getElementById('collab-copy-btn').addEventListener('click', () => {
      navigator.clipboard.writeText(document.getElementById('collab-share-input').value);
      const btn = document.getElementById('collab-copy-btn');
      btn.textContent = 'OK';
      setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
    });

    const menuBtn = document.getElementById('collab-menu-btn');
    menuBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const rect = menuBtn.getBoundingClientRect();
      menuDropdown.style.top = `${rect.bottom + 8}px`;
      menuDropdown.style.right = `${window.innerWidth - rect.right}px`;
      menuDropdown.classList.toggle('active');
    });
    document.addEventListener('click', () => {
      menuDropdown.classList.remove('active');
      if (emojiPickerOpen) {
        emojiPickerOpen = false;
        const picker = document.getElementById('collab-emoji-picker');
        if (picker) picker.classList.remove('active');
      }
    });

    const copyBtn = document.getElementById('collab-menu-copy');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(window.location.href);
        showToast('Link copied');
      });
    }

    document.getElementById('collab-menu-sound').addEventListener('click', () => {
      chatSoundEnabled = !chatSoundEnabled;
      localStorage.setItem('collab-chat-sound', chatSoundEnabled);
      document.getElementById('collab-menu-sound').textContent = chatSoundEnabled ? 'Mute Sounds' : 'Unmute Sounds';
      showToast(chatSoundEnabled ? 'Sound notifications on' : 'Sound notifications off');
    });

    document.getElementById('collab-menu-info').addEventListener('click', async () => {
      try {
        const res = await fetch(`/api/room/${ROOM_ID}/exists`);
        const data = await res.json();
        roomExpiryData = data;
        updateExpiryCountdown();
        let destructText = 'Never';
        if (data.destruct) {
          if (data.destruct.mode === 'time') {
            const hours = data.destruct.value / 3600000;
            if (hours < 1) destructText = `${Math.round(hours * 60)} minutes after last activity`;
            else if (hours < 24) destructText = `${hours} hours after last activity`;
            else destructText = `${Math.round(hours / 24)} days after last activity`;
          } else if (data.destruct.mode === 'empty') {
            destructText = 'When everyone leaves';
          }
        }
        function infoRow(label, value, extraClass) {
          return h('div', {className: 'collab-info-row'},
            h('span', {className: 'collab-info-label'}, label),
            h('span', {className: 'collab-info-value' + (extraClass ? ' ' + extraClass : '')}, value)
          );
        }
        setContent(document.getElementById('collab-info-content'), [
          infoRow('Room ID', ROOM_ID, 'collab-info-id'),
          infoRow('Created', new Date(data.created).toLocaleString()),
          infoRow('Self Destruct', destructText),
          infoRow('Password', data.hasPassword ? 'Yes' : 'No'),
          infoRow('Connected', (users.size + 1) + ' users'),
          infoRow('You are', IS_CREATOR ? 'Room Creator' : 'Participant')
        ]);
        infoModal.classList.add('active');
      } catch {
        setContent(document.getElementById('collab-info-content'), h('p', null, 'Failed to load room info'));
        infoModal.classList.add('active');
      }
    });

    document.getElementById('collab-menu-name').addEventListener('click', () => showNameModal(true));
    document.getElementById('collab-menu-leave').addEventListener('click', () => {
      if (confirm('Leave this room? You will need to enter your name again to rejoin.')) {
        leaveRoom();
      }
    });

    const deleteBtn = document.getElementById('collab-menu-delete');
    if (deleteBtn) {
      deleteBtn.addEventListener('click', async () => {
        if (!confirm('Delete this room permanently?')) return;
        try {
          const res = await fetch(`/api/room/${ROOM_ID}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json', 'x-csrf-token': window.CSRF_TOKEN || '' },
            body: JSON.stringify({ creatorId: localStorage.getItem('collab-user-' + ROOM_ID) })
          });
          if (res.ok) window.location.href = '/';
          else showToast((await res.json()).error || 'Failed to delete');
        } catch { showToast('Failed to delete room'); }
      });
    }

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        if (chatOpen) {
          chatOpen = false;
          chatPanel.classList.remove('active');
          emojiPickerOpen = false;
          const picker = document.getElementById('collab-emoji-picker');
          if (picker) picker.classList.remove('active');
        }
        shareModal.classList.remove('active');
        infoModal.classList.remove('active');
        menuDropdown.classList.remove('active');
      }
    });

    renderUsers();

    fetch(`/api/room/${ROOM_ID}/exists`).then(r => r.json()).then(data => {
      roomExpiryData = data;
      updateExpiryCountdown();
    }).catch(() => {});
    expiryInterval = setInterval(updateExpiryCountdown, 30000);
  }

  function generateQR() {
    const container = document.getElementById('collab-qr');
    const url = window.location.href;

    if (typeof qrcode === 'undefined') {
      const script = document.createElement('script');
      script.src = '/qrcode.min.js';
      script.onload = () => renderQR(container, url);
      script.onerror = () => { setContent(container, h('p', {style: 'color:#888;font-size:12px'}, 'QR unavailable')); };
      document.head.appendChild(script);
    } else {
      renderQR(container, url);
    }
  }

  function renderQR(container, url) {
    try {
      const qr = qrcode(0, 'M');
      qr.addData(url);
      qr.make();
      const svgHtml = qr.createSvgTag({ cellSize: 4, margin: 4 });
      const parsed = new DOMParser().parseFromString(svgHtml, 'image/svg+xml');
      clearNode(container);
      container.appendChild(document.importNode(parsed.documentElement, true));
    } catch {
      setContent(container, h('p', {style: 'color:#888;font-size:12px'}, 'QR unavailable'));
    }
  }

  function showNameModal(isChange = false, errorMsg = null) {
    const existing = document.getElementById('collab-name-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'collab-name-modal';
    modal.className = 'collab-modal-overlay active';
    modal.appendChild(
      h('div', {className: 'collab-modal'},
        h('div', {className: 'collab-modal-header'},
          h('h3', null, isChange ? 'Change Name' : 'Enter Your Name'),
          isChange ? h('button', {className: 'collab-modal-close'}, '\u00d7') : null
        ),
        h('div', {className: 'collab-modal-body'},
          h('input', {type: 'text', id: 'collab-name-input', className: 'collab-input', placeholder: 'Your name', maxLength: 30}),
          h('div', {className: 'collab-name-error', id: 'collab-name-error'}, errorMsg || ''),
          h('div', {className: 'collab-name-actions'},
            h('button', {id: 'collab-name-random', className: 'collab-btn-secondary'}, 'Random'),
            h('button', {id: 'collab-name-submit', className: 'collab-btn-primary'}, isChange ? 'Update' : 'Join')
          )
        )
      )
    );
    document.body.appendChild(modal);

    const errorEl = document.getElementById('collab-name-error');
    if (errorMsg) errorEl.classList.add('active');

    const input = document.getElementById('collab-name-input');
    if (isChange && window.COLLAB_USER.name) input.value = window.COLLAB_USER.name;
    input.focus();

    input.addEventListener('input', () => {
      errorEl.classList.remove('active');
    });

    document.getElementById('collab-name-random').addEventListener('click', () => {
      input.value = generateHighlanderName();
      errorEl.classList.remove('active');
    });

    document.getElementById('collab-name-submit').addEventListener('click', () => {
      const name = input.value.trim() || generateHighlanderName();
      setStoredUserName(name);
      window.COLLAB_USER.name = name;
      modal.remove();
      if (isChange || nameRejectedRecovery) {
        nameRejectedRecovery = false;
        sendMessage('join', { user: window.COLLAB_USER });
        renderUsers();
      } else {
        startCollab();
      }
    });

    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') document.getElementById('collab-name-submit').click();
    });

    const closeBtn = modal.querySelector('.collab-modal-close');
    if (closeBtn) closeBtn.addEventListener('click', () => modal.remove());
  }

  async function checkPassword() {
    if (!HAS_PASSWORD) return true;
    try {
      const res = await fetch(`/api/room/${ROOM_ID}/access`, { credentials: 'include' });
      if (res.ok && (await res.json()).authorized) return true;
    } catch {}
    return new Promise((resolve) => {
      const modal = document.createElement('div');
      modal.id = 'collab-password-modal';
      modal.className = 'collab-modal-overlay active';
      modal.appendChild(
        h('div', {className: 'collab-modal'},
          h('div', {className: 'collab-modal-header'},
            h('h3', null, 'Password Required')
          ),
          h('div', {className: 'collab-modal-body'},
            h('input', {type: 'password', id: 'collab-pwd-input', className: 'collab-input', placeholder: 'Room password'}),
            h('div', {className: 'collab-pwd-error', id: 'collab-pwd-error'}, 'Invalid password'),
            h('button', {id: 'collab-pwd-submit', className: 'collab-btn-primary', style: 'width:100%;margin-top:12px'}, 'Enter')
          )
        )
      );
      document.body.appendChild(modal);
      const input = document.getElementById('collab-pwd-input');
      const error = document.getElementById('collab-pwd-error');
      input.focus();
      async function tryPwd() {
        const res = await fetch(`/api/room/${ROOM_ID}/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ password: input.value })
        });
        if ((await res.json()).valid) {
          modal.remove();
          resolve(true);
        } else {
          error.classList.add('active');
          input.value = '';
          input.focus();
        }
      }
      document.getElementById('collab-pwd-submit').addEventListener('click', tryPwd);
      input.addEventListener('keypress', (e) => { if (e.key === 'Enter') tryPwd(); });
    });
  }

  async function init() {
    const authorized = await checkPassword();
    if (!authorized) { window.location.href = '/'; return; }

    try {
      const themeRes = await fetch('/api/theme');
      if (themeRes.ok) {
        const themeData = await themeRes.json();
        if (themeData.shareButtonEnabled !== undefined) {
          shareButtonEnabled = themeData.shareButtonEnabled;
        }
      }
    } catch (e) {
      console.error('[Collab] Failed to fetch theme settings:', e);
    }

    function waitForApp() {
      const hasForge = typeof forgeTheTopology === 'function';
      const hasHelper = typeof window.__collabGetVar === 'function';
      const hasNodeData = hasHelper ? window.__collabGetVar('NODE_DATA') !== undefined : false;
      if (hasForge && hasNodeData) {
        const storedName = getStoredUserName();
        if (storedName) {
          window.COLLAB_USER.name = storedName;
          startCollab();
        } else {
          if (window.DEFAULT_ROOM_THEME) {
            var drt = typeof THEME_PRESETS !== 'undefined' ? THEME_PRESETS : null;
            if (drt && drt[window.DEFAULT_ROOM_THEME]) {
              setGlobal('PAGE_STATE', drt[window.DEFAULT_ROOM_THEME]);
              if (typeof wieldThePower === 'function') try { wieldThePower(); } catch(e) {}
              var tsel = document.getElementById('welcome-theme-select');
              if (tsel) tsel.value = window.DEFAULT_ROOM_THEME;
            }
          }
          showNameModal(false);
        }
      } else {
        setTimeout(waitForApp, 200);
      }
    }
    waitForApp();
  }

  function stripCollabFromHTML(htmlString) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(htmlString, 'text/html');

    const collabElements = [
      '#collab-bar',
      '#collab-share-modal',
      '#collab-info-modal',
      '#collab-menu-dropdown',
      '#collab-name-modal',
      '#collab-password-modal',
      '#collab-sync-overlay',
      '#collab-chat-panel',
      '#collab-reconnect-banner',
      '#collab-toast-stack',
      '.collab-node-indicator',
      '.collab-selection-ring',
      '.collab-remote-cursor',
      '#verse-discovery-modal',
      '#verse-disc-edit-modal',
      '#verse-discover-btn',
      '.verse-probe-ui'
    ];
    collabElements.forEach(sel => {
      doc.querySelectorAll(sel).forEach(el => el.remove());
    });

    const body = doc.querySelector('body');
    if (body) {
      body.classList.remove('collab-active');
    }

    doc.querySelectorAll('script[src*="collab"], link[href*="collab.css"], #room-config').forEach(el => el.remove());

    var topoState = doc.querySelector('#topology-state');
    if (topoState && topoState.textContent) {
      try {
        var topo = JSON.parse(topoState.textContent);
        function scrubProbeResults(nodeData) {
          if (!nodeData || typeof nodeData !== 'object') return;
          Object.keys(nodeData).forEach(function(nid) {
            if (nodeData[nid] && nodeData[nid].ping) {
              delete nodeData[nid].ping.probeResults;
            }
          });
        }
        if (topo.nodeData) scrubProbeResults(topo.nodeData);
        if (topo.documentTabs && Array.isArray(topo.documentTabs)) {
          topo.documentTabs.forEach(function(tab) {
            if (tab && tab.nodes) scrubProbeResults(tab.nodes);
          });
        }
        topoState.textContent = JSON.stringify(topo);
      } catch(e) {}
    }

    return '<!DOCTYPE html>\n' + doc.documentElement.outerHTML;
  }

  function hookSaveFunction() {
    window.__collabStripHTML = stripCollabFromHTML;
  }

  function buildProbeList(ping) {
    if (ping.probeTypes && Array.isArray(ping.probeTypes) && ping.probeTypes.length > 0) {
      return ping.probeTypes;
    }
    var probes = [{ type: 'icmp' }];
    if (ping.protocol === 'custom' && ping.customUrl) {
      probes.push({ type: 'http', url: ping.customUrl });
    } else if (ping.protocol === 'https') {
      probes.push({ type: 'http' });
    } else {
      probes.push({ type: 'http' });
    }
    return probes;
  }

  function updateProbeResultsPanel(nodeId) {
    var panel = document.getElementById('verse-probe-results');
    if (!panel) return;
    var nd = getGlobal('NODE_DATA');
    var data = nd[nodeId];
    if (!data || !data.ping || !data.ping.probeResults || data.ping.probeResults.length === 0) {
      panel.innerHTML = '';
      return;
    }
    var html = '';
    data.ping.probeResults.forEach(function(r) {
      var color = r.status === 'online' ? 'var(--accent)' : r.status === 'offline' ? 'var(--danger)' : 'var(--text-soft)';
      var label = r.type.toUpperCase();
      if (r.port) label += ':' + r.port;
      var detail = '';
      if (r.responseTime !== null) detail = r.responseTime + 'ms';
      if (r.detail) detail += (detail ? ' ' : '') + r.detail;
      html += '<div style="display:flex;justify-content:space-between;align-items:center;padding:3px 0;font-size:12px">';
      html += '<span style="color:var(--text-soft)">' + label + '</span>';
      html += '<span style="color:' + color + '">● ' + (detail || r.status) + '</span>';
      html += '</div>';
    });
    panel.innerHTML = html;
  }

  function overridePingFunctions() {
    if (!window.COLLAB_MODE || !_rc.probeEnabled) return;

    window.checkNodeStatus = async function(nodeId) {
      var nd = getGlobal('NODE_DATA');
      var data = nd[nodeId];
      if (!data || !data.ping || !data.ping.enabled) return;

      data.ping.status = 'checking';
      data.ping.lastCheck = new Date().toISOString();
      data.ping.responseTime = null;
      var updateIndicator = window.__collabGetVar('updatePingIndicator');
      var updateDisplay = window.__collabGetVar('updatePingStatusDisplay');
      if (updateIndicator) updateIndicator(nodeId);
      var curId = window.__collabGetVar('currentNodeId');
      if (curId === nodeId && updateDisplay) updateDisplay(nodeId);

      var target = data.ip || '';
      if (!target && data.ping.protocol === 'custom') target = data.ping.customUrl;
      if (!target) { data.ping.status = 'unknown'; return; }

      var probes = buildProbeList(data.ping);

      try {
        var resp = await fetch('/api/probe', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-csrf-token': window.CSRF_TOKEN },
          body: JSON.stringify({ target: target, probes: probes, timeout: data.ping.timeout || 3000 })
        });
        var result = await resp.json();
        if (resp.ok) {
          data.ping.status = result.status;
          data.ping.responseTime = result.rtt || null;
          data.ping.probeResults = result.results || [];
        } else {
          data.ping.status = 'offline';
          data.ping.responseTime = null;
        }
      } catch(e) {
        data.ping.status = 'offline';
        data.ping.responseTime = null;
      }

      data.ping.lastCheck = new Date().toISOString();
      if (updateIndicator) updateIndicator(nodeId);
      curId = window.__collabGetVar('currentNodeId');
      if (curId === nodeId && updateDisplay) updateDisplay(nodeId);
      updateProbeResultsPanel(nodeId);
    };

    window.checkAllNodesStatus = async function() {
      var nd = getGlobal('NODE_DATA');
      var targets = [];
      Object.keys(nd).forEach(function(nid) {
        if (nd[nid] && nd[nid].ping && nd[nid].ping.enabled) {
          var t = nd[nid].ip || '';
          if (!t && nd[nid].ping.protocol === 'custom') t = nd[nid].ping.customUrl;
          if (t) targets.push({ nodeId: nid, target: t, probes: buildProbeList(nd[nid].ping), timeout: nd[nid].ping.timeout || 3000 });
        }
      });
      if (!targets.length) return;
      var btn = document.getElementById('check-all-ping-btn');
      if (btn) {
        btn.disabled = true;
        btn.textContent = 'Checking...';
        btn.style.opacity = '0.7';
      }
      var checked = 0;
      try {
        for (var i = 0; i < targets.length; i += 50) {
          var batch = targets.slice(i, i + 50);
          try {
            var resp = await fetch('/api/probe/batch', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'x-csrf-token': window.CSRF_TOKEN },
              body: JSON.stringify({ targets: batch })
            });
            if (!resp.ok) { checked += batch.length; continue; }
            var result = await resp.json();
            var updateIndicator = window.__collabGetVar('updatePingIndicator');
            Object.keys(result.results).forEach(function(nid) {
              var r = result.results[nid];
              if (!nd[nid] || !nd[nid].ping) return;
              nd[nid].ping.status = r.status;
              nd[nid].ping.responseTime = r.rtt || null;
              nd[nid].ping.probeResults = r.results || [];
              nd[nid].ping.lastCheck = new Date().toISOString();
              if (updateIndicator) updateIndicator(nid);
            });
            checked += batch.length;
            if (btn) btn.textContent = 'Checking ' + Math.min(checked, targets.length) + '/' + targets.length;
          } catch(e) { checked += batch.length; }
        }
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = 'Check Pings';
          btn.style.opacity = '';
        }
      }
    };

    var checkAllBtn = document.getElementById('check-all-ping-btn');
    if (checkAllBtn) {
      var newBtn = checkAllBtn.cloneNode(true);
      checkAllBtn.parentNode.replaceChild(newBtn, checkAllBtn);
      newBtn.addEventListener('click', window.checkAllNodesStatus);
    }
  }

  function injectProbeUI() {
    if (!_rc.probeEnabled) return;

    var observer = new MutationObserver(function() {
      var pingSection = document.getElementById('node-ping-options');
      if (!pingSection || document.getElementById('verse-probe-type')) return;

      var protocolRow = document.getElementById('node-ping-protocol');
      if (!protocolRow) return;
      var insertAfter = protocolRow.closest('.style-row') || protocolRow.parentElement;

      var probeRow = document.createElement('div');
      probeRow.className = 'style-row verse-probe-ui';
      probeRow.style.marginTop = '8px';
      probeRow.innerHTML = '<label style="font-size:13px;color:var(--text-soft)">Probe Type:</label>' +
        '<select id="verse-probe-type" style="flex:1">' +
        '<option value="auto">Auto (ICMP + HTTP)</option>' +
        '<option value="icmp">ICMP Ping Only</option>' +
        '<option value="tcp">TCP Port Check</option>' +
        '<option value="http">HTTP/HTTPS Only</option>' +
        '<option value="multi">Multi Probe</option>' +
        '</select>';
      insertAfter.parentNode.insertBefore(probeRow, insertAfter.nextSibling);

      var portsRow = document.createElement('div');
      portsRow.className = 'verse-probe-ui';
      portsRow.id = 'verse-tcp-ports-row';
      portsRow.style.cssText = 'display:none;margin-top:8px';
      portsRow.innerHTML = '<label style="display:block;margin-bottom:4px;font-size:13px;color:var(--text-soft)">TCP Ports (comma separated):</label>' +
        '<input type="text" id="verse-tcp-ports" placeholder="22, 80, 443, 3389" style="width:100%">';
      probeRow.parentNode.insertBefore(portsRow, probeRow.nextSibling);

      var resultsPanel = document.createElement('div');
      resultsPanel.className = 'verse-probe-ui';
      resultsPanel.id = 'verse-probe-results';
      resultsPanel.style.cssText = 'margin-top:8px;padding:8px;background:var(--panel);border-radius:6px;border:1px solid var(--edge-main)';
      portsRow.parentNode.insertBefore(resultsPanel, portsRow.nextSibling);

      var probeSelect = document.getElementById('verse-probe-type');
      probeSelect.addEventListener('change', function() {
        var val = probeSelect.value;
        document.getElementById('verse-tcp-ports-row').style.display = (val === 'tcp' || val === 'multi') ? 'block' : 'none';
        saveProbeConfig();
      });

      document.getElementById('verse-tcp-ports').addEventListener('change', function() {
        saveProbeConfig();
      });
    });
    observer.observe(document.body, { childList: true, subtree: true, attributes: true });

    var origNodePingable = null;
    document.addEventListener('change', function(e) {
      if (e.target && e.target.id === 'node-pingable') {
        setTimeout(loadProbeConfig, 50);
      }
    });

    var lastSelectedNode = null;
    setInterval(function() {
      var curId = window.__collabGetVar('currentNodeId');
      if (curId !== lastSelectedNode) {
        lastSelectedNode = curId;
        if (curId) setTimeout(function() { loadProbeConfig(); updateProbeResultsPanel(curId); }, 100);
      }
    }, 200);
  }

  function loadProbeConfig() {
    var curId = window.__collabGetVar('currentNodeId');
    if (!curId) return;
    var nd = getGlobal('NODE_DATA');
    var data = nd[curId];
    if (!data || !data.ping) return;

    var probeSelect = document.getElementById('verse-probe-type');
    var portsInput = document.getElementById('verse-tcp-ports');
    if (!probeSelect) return;

    if (data.ping.probeTypes && data.ping.probeTypes.length > 0) {
      var types = data.ping.probeTypes.map(function(p) { return p.type; });
      var hasTcp = types.indexOf('tcp') !== -1;
      var hasIcmp = types.indexOf('icmp') !== -1;
      var hasHttp = types.indexOf('http') !== -1;

      if (hasTcp && hasIcmp && hasHttp) probeSelect.value = 'multi';
      else if (hasTcp && !hasHttp) probeSelect.value = 'tcp';
      else if (hasIcmp && !hasHttp && !hasTcp) probeSelect.value = 'icmp';
      else if (hasHttp && !hasTcp) probeSelect.value = 'http';
      else probeSelect.value = 'auto';

      if (hasTcp && portsInput) {
        var ports = data.ping.probeTypes.filter(function(p) { return p.type === 'tcp'; }).map(function(p) { return p.port; });
        portsInput.value = ports.join(', ');
      }
    } else {
      probeSelect.value = 'auto';
      if (portsInput) portsInput.value = '';
    }

    var portsRow = document.getElementById('verse-tcp-ports-row');
    if (portsRow) portsRow.style.display = (probeSelect.value === 'tcp' || probeSelect.value === 'multi') ? 'block' : 'none';
  }

  function saveProbeConfig() {
    var curId = window.__collabGetVar('currentNodeId');
    if (!curId) return;
    var nd = getGlobal('NODE_DATA');
    var data = nd[curId];
    if (!data || !data.ping) return;

    var probeSelect = document.getElementById('verse-probe-type');
    var portsInput = document.getElementById('verse-tcp-ports');
    if (!probeSelect) return;

    var val = probeSelect.value;
    var probes = [];

    if (val === 'auto') {
      probes = [];
    } else if (val === 'icmp') {
      probes = [{ type: 'icmp' }];
    } else if (val === 'tcp') {
      probes = [{ type: 'icmp' }];
      var ports = parsePorts(portsInput ? portsInput.value : '');
      ports.forEach(function(p) { probes.push({ type: 'tcp', port: p }); });
    } else if (val === 'http') {
      probes = [{ type: 'http' }];
    } else if (val === 'multi') {
      probes = [{ type: 'icmp' }, { type: 'http' }];
      var ports2 = parsePorts(portsInput ? portsInput.value : '');
      ports2.forEach(function(p) { probes.push({ type: 'tcp', port: p }); });
      probes.push({ type: 'dns' });
    }

    data.ping.probeTypes = probes.length > 0 ? probes : undefined;
  }

  function parsePorts(str) {
    if (!str) return [];
    return str.split(',').map(function(s) { return parseInt(s.trim(), 10); }).filter(function(p) { return p >= 1 && p <= 65535; });
  }

  var discoveryResults = [];
  var discoveryTaskId = null;
  var discoveryScanning = false;
  var discoveryOverrides = {};
  var _renderEditModal = null;

  var DISC_SHAPES = {
    basic: ['circle','square','rectangle','triangle','hexagon','diamond','star','stop-sign','octagon','pentagon','cross','rounded-square','pill','parallelogram','trapezoid'],
    computers: ['server','pc','laptop','phone','printer','pi','sensor'],
    network: ['router','switch','firewall','access-point','load-balancer','gateway','vpn','nas'],
    cloud: ['cloud','database','docker','container','vm','kubernetes','api','queue','lambda','bucket'],
    security: ['shield','camera','monitor'],
    smarthome: ['thermostat','doorbell','smart-lock','smart-bulb','smart-plug','smart-speaker','smart-tv','hub','smoke-detector','motion-sensor','garage','sprinkler','vacuum'],
    sports: ['basketball-ball','football-ball','soccer-ball','hockey-puck','baseball-ball','tennis-ball','volleyball','rugby-ball','golf-ball','frisbee','cricket-ball','lacrosse-stick','golf-flag','tactical-x','tactical-o','tactical-star'],
    rack: ['patch-panel','ups','pdu','rack-shelf','blank-panel','cable-management','kvm']
  };

  var SHAPE_PREVIEW_SVGS = {
    'circle': '<circle cx="16" cy="16" r="11" fill="none" stroke="currentColor" stroke-width="2"/>',
    'square': '<rect x="5" y="5" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2"/>',
    'rectangle': '<rect x="3" y="8" width="26" height="16" fill="none" stroke="currentColor" stroke-width="2"/>',
    'triangle': '<polygon points="16,4 28,28 4,28" fill="none" stroke="currentColor" stroke-width="2"/>',
    'hexagon': '<polygon points="16,3 27,9 27,22 16,28 5,22 5,9" fill="none" stroke="currentColor" stroke-width="2"/>',
    'diamond': '<polygon points="16,3 29,16 16,29 3,16" fill="none" stroke="currentColor" stroke-width="2"/>',
    'star': '<polygon points="16,3 19,12 29,12 21,18 24,28 16,22 8,28 11,18 3,12 13,12" fill="none" stroke="currentColor" stroke-width="1.5"/>',
    'stop-sign': '<polygon points="11,3 21,3 29,11 29,21 21,29 11,29 3,21 3,11" fill="none" stroke="currentColor" stroke-width="2"/>',
    'octagon': '<polygon points="11,3 21,3 29,11 29,21 21,29 11,29 3,21 3,11" fill="none" stroke="currentColor" stroke-width="2"/>',
    'pentagon': '<polygon points="16,3 29,13 24,28 8,28 3,13" fill="none" stroke="currentColor" stroke-width="2"/>',
    'cross': '<path d="M12,4 h8 v8 h8 v8 h-8 v8 h-8 v-8 h-8 v-8 h8 z" fill="none" stroke="currentColor" stroke-width="1.5"/>',
    'rounded-square': '<rect x="5" y="5" width="22" height="22" rx="5" fill="none" stroke="currentColor" stroke-width="2"/>',
    'pill': '<rect x="4" y="10" width="24" height="12" rx="6" fill="none" stroke="currentColor" stroke-width="2"/>',
    'parallelogram': '<polygon points="8,6 28,6 24,26 4,26" fill="none" stroke="currentColor" stroke-width="2"/>',
    'trapezoid': '<polygon points="8,6 24,6 28,26 4,26" fill="none" stroke="currentColor" stroke-width="2"/>',
    'server': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="6" y="4" width="20" height="24" rx="2"/><line x1="6" y1="12" x2="26" y2="12"/><line x1="6" y1="20" x2="26" y2="20"/><circle cx="22" cy="8" r="1.5" fill="currentColor"/><circle cx="22" cy="16" r="1.5" fill="currentColor"/><circle cx="22" cy="24" r="1.5" fill="currentColor"/></g>',
    'pc': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="5" y="4" width="22" height="16" rx="1"/><line x1="12" y1="24" x2="20" y2="24"/><line x1="16" y1="20" x2="16" y2="24"/></g>',
    'laptop': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="6" y="6" width="20" height="14" rx="1"/><path d="M3,22 h26 l-2,4 h-22 z"/></g>',
    'phone': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="3" width="14" height="26" rx="2"/><line x1="13" y1="25" x2="19" y2="25"/></g>',
    'printer': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="8" y="12" width="16" height="10" rx="1"/><rect x="10" y="4" width="12" height="8"/><rect x="10" y="22" width="12" height="6"/></g>',
    'pi': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="5" y="8" width="22" height="16" rx="2"/><circle cx="10" cy="13" r="1.5" fill="currentColor"/><rect x="18" y="11" width="6" height="4" rx="0.5"/><line x1="14" y1="20" x2="22" y2="20"/></g>',
    'sensor': '<g fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="16" cy="16" r="6"/><circle cx="16" cy="16" r="2" fill="currentColor"/><path d="M8,8 Q4,16 8,24"/><path d="M24,8 Q28,16 24,24"/></g>',
    'router': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="4" y="14" width="24" height="12" rx="2"/><line x1="10" y1="14" x2="10" y2="8"/><line x1="16" y1="14" x2="16" y2="6"/><line x1="22" y1="14" x2="22" y2="8"/><circle cx="10" cy="7" r="1.5" fill="currentColor"/><circle cx="16" cy="5" r="1.5" fill="currentColor"/><circle cx="22" cy="7" r="1.5" fill="currentColor"/><circle cx="8" cy="22" r="1.5" fill="#4ade80"/><circle cx="13" cy="22" r="1.5" fill="#facc15"/></g>',
    'switch': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="26" height="10" rx="2"/><circle cx="8" cy="16" r="1.5" fill="currentColor"/><circle cx="13" cy="16" r="1.5" fill="currentColor"/><circle cx="18" cy="16" r="1.5" fill="currentColor"/><circle cx="23" cy="16" r="1.5" fill="currentColor"/></g>',
    'firewall': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="5" y="5" width="22" height="22" rx="1"/><line x1="5" y1="11" x2="27" y2="11"/><line x1="5" y1="17" x2="27" y2="17"/><line x1="5" y1="23" x2="27" y2="23"/><line x1="11" y1="5" x2="11" y2="27"/><line x1="17" y1="5" x2="17" y2="27"/><line x1="23" y1="5" x2="23" y2="27"/></g>',
    'access-point': '<g fill="none" stroke="currentColor" stroke-width="1.5"><path d="M16,18 L10,26 h12 z"/><circle cx="16" cy="16" r="2" fill="currentColor"/><path d="M9,10 Q16,4 23,10" stroke-linecap="round"/><path d="M6,7 Q16,0 26,7" stroke-linecap="round"/></g>',
    'load-balancer': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="6" y="12" width="20" height="8" rx="2"/><line x1="16" y1="8" x2="16" y2="12"/><line x1="16" y1="20" x2="8" y2="26"/><line x1="16" y1="20" x2="16" y2="26"/><line x1="16" y1="20" x2="24" y2="26"/><circle cx="16" cy="7" r="2" fill="currentColor"/></g>',
    'gateway': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="4" y="10" width="24" height="12" rx="2"/><line x1="4" y1="16" x2="0" y2="16"/><line x1="28" y1="16" x2="32" y2="16"/><circle cx="16" cy="16" r="3"/></g>',
    'vpn': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="5" y="8" width="22" height="16" rx="2"/><path d="M16,12 v6 M13,14 h6" stroke-width="2.5" stroke-linecap="round"/><circle cx="11" cy="20" r="1" fill="currentColor"/><circle cx="21" cy="20" r="1" fill="currentColor"/></g>',
    'nas': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="6" y="4" width="20" height="24" rx="2"/><line x1="6" y1="10" x2="26" y2="10"/><line x1="6" y1="16" x2="26" y2="16"/><line x1="6" y1="22" x2="26" y2="22"/><circle cx="22" cy="7" r="1" fill="currentColor"/><circle cx="22" cy="13" r="1" fill="currentColor"/><circle cx="22" cy="19" r="1" fill="currentColor"/><circle cx="22" cy="25" r="1" fill="currentColor"/></g>',
    'cloud': '<path d="M8,22 Q2,22 2,17 Q2,13 6,12 Q6,7 11,6 Q16,5 19,8 Q21,6 24,7 Q28,8 28,12 Q30,13 30,17 Q30,22 24,22 z" fill="none" stroke="currentColor" stroke-width="1.5"/>',
    'database': '<g fill="none" stroke="currentColor" stroke-width="1.5"><ellipse cx="16" cy="8" rx="10" ry="4"/><path d="M6,8 v16 Q6,28 16,28 Q26,28 26,24 v-16"/><path d="M6,14 Q6,18 16,18 Q26,18 26,14"/></g>',
    'docker': '<g fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2,16 h6 v-6 h4 v-4 h4 v4 h4 v-4 h4 v8 Q28,24 20,26 Q10,28 4,22 z"/><rect x="10" y="12" width="3" height="3"/><rect x="14" y="12" width="3" height="3"/><rect x="14" y="8" width="3" height="3"/></g>',
    'container': '<g fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4,12 L16,6 L28,12 L16,18 z"/><path d="M4,12 v8 L16,26 v-8"/><path d="M28,12 v8 L16,26 v-8"/></g>',
    'vm': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="4" y="4" width="24" height="24" rx="2"/><rect x="7" y="7" width="18" height="14" rx="1"/><line x1="12" y1="24" x2="20" y2="24"/></g>',
    'kubernetes': '<g fill="none" stroke="currentColor" stroke-width="1.5"><polygon points="16,2 28,9 28,23 16,30 4,23 4,9"/><circle cx="16" cy="16" r="4"/><line x1="16" y1="12" x2="16" y2="4"/><line x1="19" y1="14" x2="26" y2="10"/><line x1="19" y1="18" x2="26" y2="22"/><line x1="16" y1="20" x2="16" y2="28"/><line x1="13" y1="18" x2="6" y2="22"/><line x1="13" y1="14" x2="6" y2="10"/></g>',
    'api': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="4" y="6" width="24" height="20" rx="2"/><path d="M10,16 l2,-6 2,6 M10.5,14 h3" stroke-linecap="round"/><path d="M17,10 h3 Q22,10 22,13 Q22,16 20,16 h-3 M17,16 v6" stroke-linecap="round"/><line x1="25" y1="10" x2="25" y2="22"/></g>',
    'queue': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="4" y="8" width="24" height="16" rx="2"/><line x1="12" y1="8" x2="12" y2="24"/><line x1="20" y1="8" x2="20" y2="24"/><path d="M6,16 h3 M14,16 h4 M22,16 h4" stroke-linecap="round"/></g>',
    'lambda': '<g fill="none" stroke="currentColor" stroke-width="2"><path d="M8,6 L16,26 L24,6" stroke-linecap="round" stroke-linejoin="round"/><line x1="6" y1="16" x2="12" y2="16" stroke-linecap="round"/></g>',
    'bucket': '<g fill="none" stroke="currentColor" stroke-width="1.5"><path d="M6,8 h20 l-2,18 h-16 z"/><ellipse cx="16" cy="8" rx="10" ry="3"/></g>',
    'shield': '<path d="M16,3 L27,8 v10 Q27,26 16,29 Q5,26 5,18 v-10 z" fill="none" stroke="currentColor" stroke-width="1.5"/>',
    'camera': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="4" y="10" width="24" height="16" rx="2"/><circle cx="16" cy="18" r="5"/><circle cx="16" cy="18" r="2" fill="currentColor"/><rect x="10" y="6" width="12" height="4" rx="1"/></g>',
    'monitor': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="4" y="4" width="24" height="16" rx="2"/><line x1="12" y1="24" x2="20" y2="24"/><line x1="16" y1="20" x2="16" y2="24"/><path d="M8,8 h4 M8,11 h6 M8,14 h5 M18,8 Q20,8 20,14 Q20,16 18,16" stroke-width="1"/></g>',
    'thermostat': '<g fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="16" cy="16" r="11"/><circle cx="16" cy="16" r="7"/><line x1="16" y1="9" x2="16" y2="16" stroke-width="2" stroke-linecap="round"/></g>',
    'doorbell': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="3" width="14" height="26" rx="4"/><circle cx="16" cy="14" r="4"/><circle cx="16" cy="22" r="1.5" fill="currentColor"/></g>',
    'smart-lock': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="7" y="14" width="18" height="14" rx="2"/><path d="M11,14 v-4 Q11,4 16,4 Q21,4 21,10 v4"/><circle cx="16" cy="21" r="2" fill="currentColor"/></g>',
    'smart-bulb': '<g fill="none" stroke="currentColor" stroke-width="1.5"><path d="M11,18 Q6,12 8,7 Q10,3 16,3 Q22,3 24,7 Q26,12 21,18 z"/><rect x="11" y="18" width="10" height="4" rx="1"/><line x1="12" y1="24" x2="20" y2="24"/><line x1="13" y1="26" x2="19" y2="26"/></g>',
    'smart-plug': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="6" y="8" width="20" height="16" rx="3"/><circle cx="12" cy="16" r="2" fill="currentColor"/><circle cx="20" cy="16" r="2" fill="currentColor"/><line x1="16" y1="24" x2="16" y2="28" stroke-width="2"/></g>',
    'smart-speaker': '<g fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8,28 Q8,8 16,4 Q24,8 24,28 z"/><circle cx="16" cy="20" r="4"/><circle cx="16" cy="20" r="1.5" fill="currentColor"/></g>',
    'smart-tv': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="5" width="26" height="18" rx="1"/><line x1="10" y1="27" x2="22" y2="27"/><line x1="12" y1="23" x2="12" y2="27"/><line x1="20" y1="23" x2="20" y2="27"/></g>',
    'hub': '<g fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="16" cy="16" r="5"/><circle cx="16" cy="16" r="2" fill="currentColor"/><line x1="16" y1="5" x2="16" y2="11"/><line x1="16" y1="21" x2="16" y2="27"/><line x1="5" y1="16" x2="11" y2="16"/><line x1="21" y1="16" x2="27" y2="16"/><line x1="8" y1="8" x2="12.5" y2="12.5"/><line x1="19.5" y1="19.5" x2="24" y2="24"/><line x1="8" y1="24" x2="12.5" y2="19.5"/><line x1="19.5" y1="12.5" x2="24" y2="8"/></g>',
    'smoke-detector': '<g fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="16" cy="16" r="11"/><circle cx="16" cy="16" r="3"/><line x1="16" y1="5" x2="16" y2="7"/><line x1="16" y1="25" x2="16" y2="27"/><line x1="5" y1="16" x2="7" y2="16"/><line x1="25" y1="16" x2="27" y2="16"/></g>',
    'motion-sensor': '<g fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8,24 Q4,12 16,6 Q28,12 24,24" /><circle cx="16" cy="16" r="3" fill="currentColor"/><path d="M12,20 Q10,16 14,12"/><path d="M20,20 Q22,16 18,12"/></g>',
    'garage': '<g fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4,28 v-14 L16,4 L28,14 v14 z"/><rect x="8" y="16" width="16" height="12"/><line x1="8" y1="20" x2="24" y2="20"/><line x1="8" y1="24" x2="24" y2="24"/></g>',
    'sprinkler': '<g fill="none" stroke="currentColor" stroke-width="1.5"><line x1="16" y1="4" x2="16" y2="14"/><path d="M10,14 h12 v3 Q16,22 10,17 z"/><path d="M8,20 Q6,24 4,26" stroke-linecap="round"/><path d="M16,22 v6" stroke-linecap="round"/><path d="M24,20 Q26,24 28,26" stroke-linecap="round"/></g>',
    'vacuum': '<g fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="16" cy="16" r="11"/><circle cx="16" cy="16" r="6"/><circle cx="16" cy="16" r="2" fill="currentColor"/><line x1="16" y1="5" x2="20" y2="3" stroke-linecap="round"/></g>',
    'basketball-ball': '<g fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="16" cy="16" r="12"/><path d="M4,16 h24"/><path d="M16,4 v24"/><path d="M6,7 Q16,14 6,25"/><path d="M26,7 Q16,14 26,25"/></g>',
    'football-ball': '<g fill="none" stroke="currentColor" stroke-width="1.5"><ellipse cx="16" cy="16" rx="12" ry="8" transform="rotate(-30,16,16)"/><path d="M10,10 L22,22 M12,8 L24,20" stroke-linecap="round"/><line x1="14" y1="12" x2="18" y2="16" stroke-linecap="round"/><line x1="16" y1="14" x2="20" y2="18" stroke-linecap="round"/></g>',
    'soccer-ball': '<g fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="16" cy="16" r="12"/><polygon points="16,8 20,12 18,17 14,17 12,12" fill="currentColor" stroke="none"/></g>',
    'hockey-puck': '<g fill="none" stroke="currentColor" stroke-width="1.5"><ellipse cx="16" cy="14" rx="12" ry="5"/><path d="M4,14 v4 Q4,23 16,23 Q28,23 28,18 v-4"/></g>',
    'baseball-ball': '<g fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="16" cy="16" r="12"/><path d="M8,6 Q14,12 8,26"/><path d="M24,6 Q18,12 24,26"/></g>',
    'tennis-ball': '<g fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="16" cy="16" r="12"/><path d="M6,6 Q16,16 6,26"/><path d="M26,6 Q16,16 26,26"/></g>',
    'volleyball': '<g fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="16" cy="16" r="12"/><path d="M16,4 Q12,16 16,28"/><path d="M5,10 Q16,14 27,10"/><path d="M5,22 Q16,18 27,22"/></g>',
    'rugby-ball': '<g fill="none" stroke="currentColor" stroke-width="1.5"><ellipse cx="16" cy="16" rx="13" ry="8" transform="rotate(-30,16,16)"/><path d="M10,10 L22,22"/></g>',
    'golf-ball': '<g fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="16" cy="16" r="10"/><circle cx="14" cy="14" r="0.8" fill="currentColor"/><circle cx="18" cy="12" r="0.8" fill="currentColor"/><circle cx="16" cy="16" r="0.8" fill="currentColor"/><circle cx="12" cy="17" r="0.8" fill="currentColor"/><circle cx="19" cy="16" r="0.8" fill="currentColor"/></g>',
    'frisbee': '<g fill="none" stroke="currentColor" stroke-width="1.5"><ellipse cx="16" cy="16" rx="13" ry="5"/><ellipse cx="16" cy="15" rx="8" ry="3"/></g>',
    'cricket-ball': '<g fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="16" cy="16" r="11"/><path d="M10,6 Q16,16 10,26" stroke-dasharray="2,2"/></g>',
    'lacrosse-stick': '<g fill="none" stroke="currentColor" stroke-width="1.5"><line x1="8" y1="28" x2="20" y2="6" stroke-width="2"/><path d="M18,8 Q26,4 26,12 Q26,16 20,14"/><line x1="20" y1="9" x2="24" y2="13"/></g>',
    'golf-flag': '<g fill="none" stroke="currentColor" stroke-width="1.5"><line x1="10" y1="4" x2="10" y2="28" stroke-width="2"/><polygon points="10,4 26,10 10,16" fill="currentColor" opacity="0.3" stroke="currentColor"/><ellipse cx="16" cy="28" rx="10" ry="2"/></g>',
    'tactical-x': '<g stroke="currentColor" stroke-width="3" stroke-linecap="round"><line x1="6" y1="6" x2="26" y2="26"/><line x1="26" y1="6" x2="6" y2="26"/></g>',
    'tactical-o': '<circle cx="16" cy="16" r="10" fill="none" stroke="currentColor" stroke-width="3"/>',
    'tactical-star': '<polygon points="16,3 19,12 29,12 21,18 24,28 16,22 8,28 11,18 3,12 13,12" fill="currentColor" opacity="0.3" stroke="currentColor" stroke-width="1.5"/>',
    'patch-panel': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="10" width="26" height="12" rx="1"/><circle cx="8" cy="14" r="1.5"/><circle cx="13" cy="14" r="1.5"/><circle cx="18" cy="14" r="1.5"/><circle cx="23" cy="14" r="1.5"/><circle cx="8" cy="19" r="1.5"/><circle cx="13" cy="19" r="1.5"/><circle cx="18" cy="19" r="1.5"/><circle cx="23" cy="19" r="1.5"/></g>',
    'ups': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="6" y="4" width="20" height="24" rx="2"/><rect x="10" y="8" width="12" height="6" rx="1"/><circle cx="12" cy="20" r="1.5" fill="currentColor"/><circle cx="16" cy="20" r="1.5"/><circle cx="20" cy="20" r="1.5"/></g>',
    'pdu': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="11" y="2" width="10" height="28" rx="1"/><circle cx="16" cy="7" r="2"/><circle cx="16" cy="13" r="2"/><circle cx="16" cy="19" r="2"/><circle cx="16" cy="25" r="2" fill="currentColor"/></g>',
    'rack-shelf': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="12" width="26" height="8" rx="1"/><line x1="3" y1="17" x2="29" y2="17" stroke-dasharray="3,2"/><circle cx="7" cy="14.5" r="1" fill="currentColor"/></g>',
    'blank-panel': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="12" width="26" height="8" rx="1"/><circle cx="6" cy="16" r="1"/><circle cx="26" cy="16" r="1"/></g>',
    'cable-management': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="26" height="10" rx="1"/><path d="M7,14 Q10,18 13,14 Q16,10 19,14 Q22,18 25,14" stroke-linecap="round"/></g>',
    'kvm': '<g fill="none" stroke="currentColor" stroke-width="1.5"><rect x="4" y="8" width="24" height="16" rx="2"/><rect x="8" y="11" width="10" height="7" rx="1"/><circle cx="23" cy="14.5" r="2"/><line x1="12" y1="20" x2="20" y2="20"/></g>'
  };

  function getLayerName(val) {
    var sel = document.getElementById('node-layer');
    if (sel) {
      for (var i = 0; i < sel.options.length; i++) {
        if (sel.options[i].value === val) return sel.options[i].textContent;
      }
    }
    var fallback = { layer1: 'Physical Layer', layer2: 'Logical Layer', layer3: 'Security Layer', layer4: 'Application Layer' };
    return fallback[val] || val;
  }

  var _iconCache = {};
  function fetchDiscoveryIcon(library, name, el, size) {
    var sz = size || 20;
    var key = library + '/' + name;
    if (_iconCache[key] === false) return;
    var url = '';
    if (library === 'selfhst') url = 'https://cdn.jsdelivr.net/gh/selfhst/icons@master/png/' + encodeURIComponent(name) + '.png';
    else if (library === 'mdi') url = 'https://cdn.jsdelivr.net/npm/@mdi/svg@latest/svg/' + encodeURIComponent(name) + '.svg';
    if (!url) return;
    if (_iconCache[key]) {
      el.innerHTML = '<img src="' + _iconCache[key] + '" style="width:' + sz + 'px;height:' + sz + 'px;object-fit:contain" alt="' + name + '">';
      return;
    }
    _iconCache[key] = url;
    el.innerHTML = '<img src="' + url + '" style="width:' + sz + 'px;height:' + sz + 'px;object-fit:contain" alt="' + name + '">';
    var img = el.querySelector('img');
    if (img) {
      img.onerror = function() {
        _iconCache[key] = false;
        el.innerHTML = '';
      };
    }
  }

  function getShapePreviewSVG(shape) {
    var svg = SHAPE_PREVIEW_SVGS[shape];
    if (svg) return '<svg width="36" height="36" viewBox="0 0 32 32" style="color:var(--accent)">' + svg + '</svg>';
    return '<span style="font-size:10px;color:var(--text-soft);text-align:center;line-height:1.2">' + escapeHtml(shape || 'circle') + '</span>';
  }

  function updateDiscoveryProgress(percent, scanned, total, rangeIndex, totalRanges) {
    var bar = document.getElementById('verse-discovery-progress-fill');
    var text = document.getElementById('verse-discovery-progress-text');
    if (bar) bar.style.width = percent + '%';
    if (text) {
      var label = percent + '% (' + scanned + '/' + total + ')';
      if (totalRanges > 1) label = 'Range ' + (rangeIndex + 1) + '/' + totalRanges + ' : ' + label;
      text.textContent = label;
    }
  }

  var _scanRenderInterval = null;
  function addDiscoveryResult(host) {
    discoveryResults.push(host);
    var countEl = document.getElementById('verse-discovery-count');
    if (countEl) countEl.textContent = discoveryResults.length + ' hosts found';
    if (!_scanRenderInterval) {
      _scanRenderInterval = setInterval(function() {
        renderDiscoveryResults();
      }, 2000);
    }
  }

  function finalizeDiscovery(totalFound) {
    discoveryScanning = false;
    discoveryTaskId = null;
    if (_scanRenderInterval) { clearInterval(_scanRenderInterval); _scanRenderInterval = null; }
    var btn = document.getElementById('verse-discovery-start');
    var cancelBtn = document.getElementById('verse-discovery-cancel');
    if (btn) { btn.textContent = 'Start Scan'; btn.disabled = false; }
    if (cancelBtn) cancelBtn.style.display = 'none';
    var text = document.getElementById('verse-discovery-progress-text');
    if (text) text.textContent = 'Complete - ' + totalFound + ' hosts found';
    renderDiscoveryResults();
  }

  var activeDeepScans = {};

  function handleDeepScanProgress(scanId, ip, percent) {
    activeDeepScans[ip] = { scanId: scanId, percent: percent };
    var cell = document.querySelector('[data-deepscan-ip="' + ip + '"]');
    if (cell) {
      var bar = cell.querySelector('.deepscan-bar-fill');
      var text = cell.querySelector('.deepscan-text');
      if (bar) bar.style.width = percent + '%';
      if (text) text.textContent = percent + '%';
    }
  }

  function handleDeepScanUpdate(scanId, ip, newPorts, newServices, containers, newIcons) {
    for (var i = 0; i < discoveryResults.length; i++) {
      if (discoveryResults[i].ip === ip) {
        var host = discoveryResults[i];
        if (!host.ports) host.ports = [];
        if (!host.services) host.services = {};
        newPorts.forEach(function(p) {
          if (host.ports.indexOf(p) === -1) host.ports.push(p);
        });
        Object.keys(newServices).forEach(function(portStr) {
          host.services[parseInt(portStr, 10)] = newServices[portStr];
        });
        if (containers) host.dockerContainers = containers;
        if (!discoveryOverrides[ip]) discoveryOverrides[ip] = {};
        var ov = discoveryOverrides[ip];
        var existing = ov.tags ? ov.tags.split(',').map(function(t) { return t.trim(); }).filter(function(t) { return t; }) : [];
        Object.values(newServices).forEach(function(s) {
          if (s && s.indexOf('Port ') !== 0 && existing.indexOf(s) === -1) existing.push(s);
        });
        if (containers && containers.length > 0) {
          containers.forEach(function(c) {
            var label = c.name || '';
            if (label && existing.indexOf(label) === -1) existing.push(label);
          });
        }
        ov.tags = existing.join(', ');
        ov._tagsSeeded = true;
        if (newIcons && newIcons.length > 0) {
          if (!ov.iconTags) ov.iconTags = [];
          newIcons.forEach(function(icon) {
            var exists = ov.iconTags.some(function(t) {
              return t.library === icon.library && t.name === icon.name;
            });
            if (!exists) {
              ov.iconTags.push({ type: 'icon', library: icon.library, name: icon.name, svg: '' });
            }
          });
        }
        break;
      }
    }
  }

  function handleDeepScanComplete(scanId, ip) {
    delete activeDeepScans[ip];
    renderDiscoveryResults();
  }

  var DOCKER_TRIGGER_PORTS = [2375, 2376, 9443, 5001];

  function buildDeepScanCell(ip) {
    var active = activeDeepScans[ip];
    if (active) {
      return '<div data-deepscan-ip="' + escapeHtml(ip) + '" style="display:inline-flex;align-items:center;gap:4px">' +
        '<div style="width:48px;height:4px;background:var(--edge-main);border-radius:2px;overflow:hidden">' +
          '<div class="deepscan-bar-fill" style="width:' + (active.percent || 0) + '%;height:100%;background:var(--accent);border-radius:2px;transition:width 0.3s"></div>' +
        '</div>' +
        '<span class="deepscan-text" style="font-size:9px;color:var(--text-soft)">' + (active.percent || 0) + '%</span>' +
        '<button class="deepscan-cancel-btn" data-ip="' + escapeHtml(ip) + '" style="background:none;border:none;color:var(--danger);cursor:pointer;font-size:11px;padding:0 2px" title="Cancel deep scan">\u2715</button>' +
      '</div>';
    }
    return '<button class="deepscan-start-btn" data-ip="' + escapeHtml(ip) + '" style="padding:2px 6px;font-size:10px;background:var(--panel);color:var(--text-soft);border:1px solid var(--edge-main);border-radius:4px;cursor:pointer" title="Scan for Docker container ports">Deep Scan</button>';
  }

  var discoveryRanges = [];

  function getCurrentCIDR() {
    var sel = document.getElementById('verse-disc-preset');
    if (!sel) return '';
    if (sel.value === 'custom') {
      var custom = document.getElementById('verse-disc-custom-cidr');
      return custom ? custom.value.trim() : '';
    }
    return sel.value || '';
  }

  function getDiscoveryCIDRs() {
    if (discoveryRanges.length > 0) return discoveryRanges.slice();
    var current = getCurrentCIDR();
    return current ? [current] : [];
  }

  function renderRangePills() {
    var container = document.getElementById('verse-disc-ranges');
    if (!container) return;
    container.innerHTML = '';
    discoveryRanges.forEach(function(cidr, idx) {
      var pill = document.createElement('span');
      pill.style.cssText = 'display:inline-flex;align-items:center;gap:4px;padding:4px 10px;background:var(--accent);color:var(--bg);border-radius:16px;font-size:12px;font-family:monospace';
      pill.textContent = cidr;
      var x = document.createElement('button');
      x.style.cssText = 'background:none;border:none;color:var(--bg);font-size:14px;cursor:pointer;padding:0 2px;line-height:1';
      x.textContent = '\u2715';
      x.addEventListener('click', function() {
        discoveryRanges.splice(idx, 1);
        renderRangePills();
      });
      pill.appendChild(x);
      container.appendChild(pill);
    });
  }

  function updateRackDropdowns() {
    var nd = getGlobal('NODE_DATA') || {};
    var canvasRacks = [];
    Object.keys(nd).forEach(function(nid) {
      if (nd[nid] && nd[nid].isRack) {
        canvasRacks.push({ value: 'canvas:' + nid, label: (nd[nid].name || nid) + ' (on canvas)', capacity: parseInt(nd[nid].rackCapacity) || 42 });
      }
    });
    var newRacks = [];
    discoveryResults.forEach(function(host) {
      var ov = discoveryOverrides[host.ip] || {};
      if (ov.typeToggle === 'rack') {
        var rackName = ov.name || host.hostname || host.ip;
        var cap = parseInt(ov.rackCapacity) || 42;
        newRacks.push({ value: 'new:' + host.ip, label: rackName + ' (new)', capacity: cap, ip: host.ip });
      }
    });

    document.querySelectorAll('.disc-rack-cell').forEach(function(cell) {
      var ip = cell.getAttribute('data-ip');
      var ov = discoveryOverrides[ip] || {};
      var isRack = ov.typeToggle === 'rack';

      if (isRack) {
        cell.innerHTML = '';
        return;
      }

      var savedRef = ov.assignedRackRef || '';
      var savedUnit = ov.rackUnit || '';
      var savedUHeight = ov.uHeight || '1';

      var opts = '<option value="">None</option>';
      canvasRacks.forEach(function(r) {
        opts += '<option value="' + escapeHtml(r.value) + '"' + (savedRef === r.value ? ' selected' : '') + '>' + escapeHtml(r.label) + '</option>';
      });
      newRacks.forEach(function(r) {
        if (r.ip === ip) return;
        opts += '<option value="' + escapeHtml(r.value) + '"' + (savedRef === r.value ? ' selected' : '') + '>' + escapeHtml(r.label) + '</option>';
      });

      var html = '<select class="disc-rack-select" data-ip="' + escapeHtml(ip) + '" style="width:100%;padding:3px 6px;border-radius:4px;border:1px solid var(--edge-main);background:var(--panel);color:var(--text-main);font-size:11px">' + opts + '</select>';

      if (savedRef) {
        var capacity = 42;
        canvasRacks.forEach(function(r) { if (r.value === savedRef) capacity = r.capacity; });
        newRacks.forEach(function(r) { if (r.value === savedRef) capacity = r.capacity; });

        var unitOpts = '<option value="">U Pos</option>';
        for (var u = 1; u <= capacity; u++) {
          unitOpts += '<option value="' + u + '"' + (savedUnit === String(u) ? ' selected' : '') + '>U' + u + '</option>';
        }

        var uhOpts = '';
        for (var h = 1; h <= 4; h++) {
          uhOpts += '<option value="' + h + '"' + (savedUHeight === String(h) ? ' selected' : '') + '>' + h + 'U</option>';
        }

        html += '<div style="display:flex;gap:4px;margin-top:4px">' +
          '<select class="disc-rack-unit" data-ip="' + escapeHtml(ip) + '" style="flex:1;padding:2px 4px;border-radius:4px;border:1px solid var(--edge-main);background:var(--panel);color:var(--text-main);font-size:10px">' + unitOpts + '</select>' +
          '<select class="disc-rack-uheight" data-ip="' + escapeHtml(ip) + '" style="width:48px;padding:2px 4px;border-radius:4px;border:1px solid var(--edge-main);background:var(--panel);color:var(--text-main);font-size:10px">' + uhOpts + '</select>' +
        '</div>';
      }

      cell.innerHTML = html;
    });

    document.querySelectorAll('.disc-rack-select').forEach(function(sel) {
      sel.addEventListener('change', function() {
        var ip = sel.getAttribute('data-ip');
        if (!discoveryOverrides[ip]) discoveryOverrides[ip] = {};
        if (sel.value) {
          discoveryOverrides[ip].assignedRackRef = sel.value;
        } else {
          delete discoveryOverrides[ip].assignedRackRef;
          delete discoveryOverrides[ip].rackUnit;
        }
        updateRackDropdowns();
      });
    });

    document.querySelectorAll('.disc-rack-unit').forEach(function(sel) {
      sel.addEventListener('change', function() {
        var ip = sel.getAttribute('data-ip');
        if (!discoveryOverrides[ip]) discoveryOverrides[ip] = {};
        discoveryOverrides[ip].rackUnit = sel.value;
      });
    });

    document.querySelectorAll('.disc-rack-uheight').forEach(function(sel) {
      sel.addEventListener('change', function() {
        var ip = sel.getAttribute('data-ip');
        if (!discoveryOverrides[ip]) discoveryOverrides[ip] = {};
        discoveryOverrides[ip].uHeight = sel.value;
      });
    });
  }

  function renderDiscoveryResults() {
    var tbody = document.getElementById('verse-discovery-tbody');
    if (!tbody) return;
    var count = document.getElementById('verse-discovery-count');
    if (count) count.textContent = discoveryResults.length + ' hosts found';
    var searchEl = document.getElementById('verse-disc-table-search');
    var savedSearch = searchEl ? searchEl.value : '';
    tbody.innerHTML = '';

    var nd = getGlobal('NODE_DATA') || {};
    var canvasIPs = {};
    Object.keys(nd).forEach(function(nid) {
      if (nd[nid] && nd[nid].ip) canvasIPs[nd[nid].ip] = nid;
    });

    discoveryResults.forEach(function(host) {
      var nodeId = canvasIPs[host.ip];
      if (!nodeId) return;
      var node = nd[nodeId];
      if (!node) return;
      if (!discoveryOverrides[host.ip]) discoveryOverrides[host.ip] = {};
      var ov = discoveryOverrides[host.ip];
      if (ov.name === undefined && node.name) {
        ov.name = node.name;
      }
      if (ov.layer === undefined && node.layer) {
        ov.layer = node.layer;
      }
      if (ov.assignedRackRef === undefined && node.assignedRack && nd[node.assignedRack]) {
        ov.assignedRackRef = 'canvas:' + node.assignedRack;
        if (ov.rackUnit === undefined) ov.rackUnit = node.rackUnit || '';
        if (ov.uHeight === undefined) ov.uHeight = node.uHeight || '1';
      }
      if (ov.typeToggle === undefined && node.isRack) {
        ov.typeToggle = 'rack';
      }
      ov._seeded = true;
    });

    discoveryResults.forEach(function(host) {
      if (!host.icon || host.icon.name === 'linux' || host.icon.name === 'terminal') return;
      if (!discoveryOverrides[host.ip]) discoveryOverrides[host.ip] = {};
      var ov = discoveryOverrides[host.ip];
      if (ov.iconData === undefined) {
        ov.iconData = { library: host.icon.library, name: host.icon.name };
        if (!ov._seeded) ov._seeded = true;
      }
    });

    discoveryResults.forEach(function(host) {
      if (!host.services) return;
      if (!discoveryOverrides[host.ip]) discoveryOverrides[host.ip] = {};
      var ov = discoveryOverrides[host.ip];
      if (ov._tagsSeeded) return;
      var svcNames = Object.values(host.services).filter(function(s) { return s && s.indexOf('Port ') !== 0; });
      if (svcNames.length > 0) {
        var existing = ov.tags ? ov.tags.split(',').map(function(t) { return t.trim(); }).filter(function(t) { return t; }) : [];
        svcNames.forEach(function(s) {
          if (existing.indexOf(s) === -1) existing.push(s);
        });
        ov.tags = existing.join(', ');
        ov._tagsSeeded = true;
        if (!ov._seeded) ov._seeded = true;
      }
    });

    discoveryResults.forEach(function(host) {
      if (!host.serviceIcons || host.serviceIcons.length === 0) return;
      if (!discoveryOverrides[host.ip]) discoveryOverrides[host.ip] = {};
      var ov = discoveryOverrides[host.ip];
      if (ov._iconTagsSeeded) return;
      if (!ov.iconTags) ov.iconTags = [];
      host.serviceIcons.forEach(function(icon) {
        if (ov.iconData && ov.iconData.library === icon.library && ov.iconData.name === icon.name) return;
        var exists = ov.iconTags.some(function(t) {
          return t.library === icon.library && t.name === icon.name;
        });
        if (!exists) {
          ov.iconTags.push({ type: 'icon', library: icon.library, name: icon.name, svg: '' });
        }
      });
      ov._iconTagsSeeded = true;
      if (!ov._seeded) ov._seeded = true;
    });

    var editBtn = document.getElementById('verse-disc-edit-btn');
    if (editBtn) editBtn.style.display = discoveryResults.length > 0 ? 'inline' : 'none';

    var sortedResults = discoveryResults.slice().sort(function(a, b) {
      var aOnCanvas = canvasIPs[a.ip] ? 1 : 0;
      var bOnCanvas = canvasIPs[b.ip] ? 1 : 0;
      return aOnCanvas - bOnCanvas;
    });

    sortedResults.forEach(function(host) {
      var idx = discoveryResults.indexOf(host);
      var svcValues = Object.values(host.services || {});
      var serviceTags = svcValues.map(function(s) {
        var isGeneric = s.indexOf('Port ') === 0;
        var bg = isGeneric ? 'var(--panel)' : 'var(--panel-alt)';
        var border = isGeneric ? 'var(--edge-main)' : 'var(--accent)';
        var color = isGeneric ? 'var(--text-soft)' : 'var(--accent)';
        return '<span style="display:inline-block;padding:1px 6px;margin:1px;font-size:10px;border-radius:3px;background:' + bg + ';border:1px solid ' + border + ';color:' + color + ';white-space:nowrap">' + escapeHtml(s) + '</span>';
      }).join('');
      if (host.dockerContainers && host.dockerContainers.length > 0) {
        host.dockerContainers.forEach(function(c) {
          var name = c.name || '';
          if (!name) return;
          serviceTags += '<span style="display:inline-block;padding:1px 6px;margin:1px;font-size:10px;border-radius:3px;background:var(--panel-alt);border:1px solid #2496ed;color:#2496ed;white-space:nowrap" title="Docker container">' + escapeHtml(name) + '</span>';
        });
      }
      var hostname = host.hostname || '';
      var nameDetails = [];
      if (host.dnsName) nameDetails.push('DNS: ' + host.dnsName);
      if (host.netbiosName) nameDetails.push('NetBIOS: ' + host.netbiosName);
      if (host.mdnsName) nameDetails.push('mDNS: ' + host.mdnsName);
      if (host.httpServer) nameDetails.push('HTTP: ' + host.httpServer);
      if (host.snmpName) nameDetails.push('SNMP: ' + host.snmpName);
      if (host.snmpDescr) nameDetails.push('Descr: ' + host.snmpDescr);
      var detailTitle = nameDetails.length > 0 ? nameDetails.join('\n') : '';

      var onCanvas = canvasIPs[host.ip];
      var hasOverride = discoveryOverrides[host.ip];
      var ov = hasOverride || {};
      var displayName = ov.name || hostname;
      var userEdited = hasOverride && !ov._seeded;
      var overrideIndicator = userEdited ? ' <span style="color:var(--accent);font-size:11px" title="Edited">&#9998;</span>' : '';
      var canvasBadge = onCanvas ? '<br><span style="font-size:9px;color:var(--accent);font-style:italic">on canvas</span>' : '';

      var isRackOverride = ov.typeToggle === 'rack';
      var isNodeOverride = !ov.typeToggle || ov.typeToggle === 'node';
      var nodeActive = isNodeOverride ? 'active' : '';
      var rackActive = isRackOverride ? 'active' : '';
      var nodeBg = isNodeOverride ? 'var(--accent)' : 'var(--panel)';
      var nodeColor = isNodeOverride ? 'var(--bg)' : 'var(--text-soft)';
      var rackBg = isRackOverride ? 'var(--accent)' : 'var(--panel)';
      var rackColor = isRackOverride ? 'var(--bg)' : 'var(--text-soft)';

      var hasDocker = host.ports && DOCKER_TRIGGER_PORTS.some(function(p) { return host.ports.indexOf(p) !== -1; });
      var deepScanHtml = hasDocker ? ' ' + buildDeepScanCell(host.ip) : '';

      var tr = document.createElement('tr');
      tr.style.borderBottom = '1px solid var(--edge-main)';
      if (onCanvas) tr.style.opacity = '0.5';
      tr.setAttribute('data-ip', host.ip);
      tr.innerHTML = '<td style="padding:6px 8px"><label class="toggle-switch"><input type="checkbox" data-idx="' + idx + '" class="verse-discovery-check"' + (onCanvas ? '' : ' checked') + '><span class="toggle-slider"></span></label></td>' +
        '<td style="padding:6px 8px;font-family:monospace;font-size:12px">' + escapeHtml(host.ip) + canvasBadge + '</td>' +
        '<td style="padding:6px 8px;font-size:12px" title="' + escapeHtml(detailTitle) + '">' + escapeHtml(displayName) + overrideIndicator + ' <span style="display:inline-flex;gap:4px;margin-left:4px;vertical-align:middle"><button class="disc-row-edit-btn" data-ip="' + escapeHtml(host.ip) + '" style="padding:2px 6px;font-size:10px;background:var(--panel);color:var(--text-soft);border:1px solid var(--edge-main);border-radius:4px;cursor:pointer" title="Edit this host">Editor</button>' + deepScanHtml + '</span></td>' +
        '<td style="padding:6px 8px;font-size:12px"><div style="display:flex;flex-wrap:wrap;gap:0;align-items:center">' + serviceTags + '</div></td>' +
        '<td style="padding:6px 4px;text-align:center"><span class="disc-icon-cell" data-icon-ip="' + escapeHtml(host.ip) + '" style="display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px" title="' + escapeHtml(ov.iconData && ov.iconData.name ? ov.iconData.library + '/' + ov.iconData.name : '') + '"></span></td>' +
        '<td style="padding:6px 8px">' +
          '<div class="verse-type-toggle" data-idx="' + idx + '" data-ip="' + escapeHtml(host.ip) + '" style="display:inline-flex;border-radius:4px;overflow:hidden;border:1px solid var(--edge-main)">' +
            '<button data-type="node" class="verse-type-btn ' + nodeActive + '" style="padding:3px 10px;font-size:11px;border:none;cursor:pointer;background:' + nodeBg + ';color:' + nodeColor + '">Node</button>' +
            '<button data-type="rack" class="verse-type-btn ' + rackActive + '" style="padding:3px 10px;font-size:11px;border:none;cursor:pointer;background:' + rackBg + ';color:' + rackColor + '">Rack</button>' +
          '</div>' +
        '</td>' +
        '<td style="padding:6px 8px;min-width:120px" class="disc-rack-cell" data-ip="' + escapeHtml(host.ip) + '"></td>' +
        '<td style="padding:6px 8px">' +
          '<select class="disc-layer-select" data-ip="' + escapeHtml(host.ip) + '" style="width:100%;padding:3px 6px;border-radius:4px;border:1px solid var(--edge-main);background:var(--panel);color:var(--text-main);font-size:11px">' +
            '<option value="layer1"' + ((ov.layer || 'layer1') === 'layer1' ? ' selected' : '') + '>' + escapeHtml(getLayerName('layer1')) + '</option>' +
            '<option value="layer2"' + (ov.layer === 'layer2' ? ' selected' : '') + '>' + escapeHtml(getLayerName('layer2')) + '</option>' +
            '<option value="layer3"' + (ov.layer === 'layer3' ? ' selected' : '') + '>' + escapeHtml(getLayerName('layer3')) + '</option>' +
            '<option value="layer4"' + (ov.layer === 'layer4' ? ' selected' : '') + '>' + escapeHtml(getLayerName('layer4')) + '</option>' +
          '</select>' +
        '</td>';
      tbody.appendChild(tr);
    });

    updateRackDropdowns();

    document.querySelectorAll('.disc-icon-cell').forEach(function(el) {
      var ip = el.getAttribute('data-icon-ip');
      var ov = discoveryOverrides[ip] || {};
      if (ov.iconData && ov.iconData.name) {
        if (ov.iconData.svg) {
          el.innerHTML = ov.iconData.svg;
          var svgEl = el.querySelector('svg');
          if (svgEl) { svgEl.style.width = '20px'; svgEl.style.height = '20px'; }
        } else {
          fetchDiscoveryIcon(ov.iconData.library, ov.iconData.name, el);
        }
      }
    });

    document.querySelectorAll('.disc-layer-select').forEach(function(sel) {
      sel.addEventListener('change', function() {
        var ip = sel.getAttribute('data-ip');
        if (!discoveryOverrides[ip]) discoveryOverrides[ip] = {};
        discoveryOverrides[ip].layer = sel.value;
      });
    });

    document.querySelectorAll('.verse-type-toggle').forEach(function(toggle) {
      toggle.addEventListener('click', function(e) {
        var btn = e.target.closest('.verse-type-btn');
        if (!btn) return;
        var ip = toggle.getAttribute('data-ip');
        toggle.querySelectorAll('.verse-type-btn').forEach(function(b) {
          if (b === btn) {
            b.classList.add('active');
            b.style.background = 'var(--accent)';
            b.style.color = 'var(--bg)';
          } else {
            b.classList.remove('active');
            b.style.background = 'var(--panel)';
            b.style.color = 'var(--text-soft)';
          }
        });
        if (ip) {
          if (!discoveryOverrides[ip]) discoveryOverrides[ip] = {};
          var prevType = discoveryOverrides[ip].typeToggle || 'node';
          discoveryOverrides[ip].typeToggle = btn.dataset.type;
          if (btn.dataset.type === 'rack') {
            delete discoveryOverrides[ip].assignedRackRef;
            delete discoveryOverrides[ip].rackUnit;
          }
          if (prevType === 'rack' && btn.dataset.type === 'node') {
            Object.keys(discoveryOverrides).forEach(function(otherIp) {
              if (discoveryOverrides[otherIp].assignedRackRef === 'new:' + ip) {
                delete discoveryOverrides[otherIp].assignedRackRef;
                delete discoveryOverrides[otherIp].rackUnit;
              }
            });
          }
          updateRackDropdowns();
        }
      });
    });

    document.querySelectorAll('.disc-row-edit-btn').forEach(function(btn) {
      btn.addEventListener('click', function(e) {
        e.stopPropagation();
        var ip = btn.getAttribute('data-ip');
        var editModalEl = document.getElementById('verse-disc-edit-modal');
        if (editModalEl && _renderEditModal) {
          _renderEditModal(ip);
          editModalEl.classList.add('active');
        }
      });
    });

    document.querySelectorAll('.deepscan-start-btn').forEach(function(btn) {
      btn.addEventListener('click', function(e) {
        e.stopPropagation();
        var ip = btn.getAttribute('data-ip');
        var host = null;
        for (var i = 0; i < discoveryResults.length; i++) {
          if (discoveryResults[i].ip === ip) { host = discoveryResults[i]; break; }
        }
        if (!host) return;
        btn.disabled = true;
        btn.textContent = 'Starting...';
        fetch('/api/discover/deepscan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-csrf-token': window.CSRF_TOKEN },
          body: JSON.stringify({
            roomId: ROOM_ID,
            ip: ip,
            existingPorts: host.ports || []
          })
        }).then(function(resp) {
          return resp.json().then(function(result) {
            if (!resp.ok) {
              btn.textContent = 'Deep Scan';
              btn.disabled = false;
              return;
            }
            activeDeepScans[ip] = { scanId: result.scanId, percent: 0 };
            renderDiscoveryResults();
          });
        }).catch(function() {
          btn.textContent = 'Deep Scan';
          btn.disabled = false;
        });
      });
    });

    document.querySelectorAll('.deepscan-cancel-btn').forEach(function(btn) {
      btn.addEventListener('click', function(e) {
        e.stopPropagation();
        var ip = btn.getAttribute('data-ip');
        var active = activeDeepScans[ip];
        if (!active) return;
        fetch('/api/discover/deepscan/cancel', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-csrf-token': window.CSRF_TOKEN },
          body: JSON.stringify({ scanId: active.scanId })
        }).catch(function() {});
        delete activeDeepScans[ip];
        renderDiscoveryResults();
      });
    });

    var tableSearch = document.getElementById('verse-disc-table-search');
    if (tableSearch) {
      var filterRows = function() {
        var q = tableSearch.value.toLowerCase().trim();
        var rows = document.querySelectorAll('#verse-discovery-tbody tr');
        rows.forEach(function(row) {
          var ip = (row.getAttribute('data-ip') || '').toLowerCase();
          var text = row.textContent.toLowerCase();
          row.style.display = (!q || ip.indexOf(q) !== -1 || text.indexOf(q) !== -1) ? '' : 'none';
        });
      };
      tableSearch.addEventListener('input', filterRows);
      if (savedSearch) {
        tableSearch.value = savedSearch;
        filterRows();
      }
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function injectDiscoveryUI() {
    if (!_rc.discoveryAllowed) return;

    var waitForPing = setInterval(function() {
      var autoPingSection = document.getElementById('auto-ping-settings');
      var checkAllBtn = document.getElementById('check-all-ping-btn');
      var target = autoPingSection || checkAllBtn;
      if (!target) return;
      clearInterval(waitForPing);

      var btn = document.createElement('button');
      btn.id = 'verse-discover-btn';
      btn.style.cssText = 'display:block;width:100%;padding:10px;margin-top:12px;background:var(--accent);color:var(--bg);border:none;border-radius:6px;cursor:pointer;font-size:14px;font-weight:600';
      btn.textContent = 'Discover Network Hosts';
      btn.addEventListener('click', function() {
        var modal = document.getElementById('verse-discovery-modal');
        if (modal) modal.classList.add('active');
        var portRef = document.getElementById('verse-disc-port-ref-body');
        if (portRef && !portRef.dataset.loaded) {
          fetch('/api/discover/ports').then(function(r) { return r.json(); }).then(function(data) {
            if (!data.ports) return;
            portRef.dataset.loaded = '1';
            var summary = portRef.parentElement.querySelector('summary');
            if (summary) summary.textContent = 'Default Scan Ports (' + data.ports.length + ')';
            var html = '<div style="display:flex;flex-wrap:wrap;gap:4px">';
            data.ports.forEach(function(p) {
              var iconHtml = p.icon ? '<span class="disc-port-ref-icon" data-icon-name="' + escapeHtml(p.icon) + '" style="display:inline-flex;width:14px;height:14px;margin-right:3px;vertical-align:middle"></span>' : '';
              html += '<span style="display:inline-flex;align-items:center;padding:2px 8px;background:var(--panel);border:1px solid var(--edge-main);border-radius:4px;font-size:11px;color:var(--text-main)">' + iconHtml + '<strong>' + p.port + '</strong>&nbsp;<span style="color:var(--text-soft)">' + escapeHtml(p.service) + '</span></span>';
            });
            html += '</div>';
            portRef.innerHTML = html;
            portRef.querySelectorAll('.disc-port-ref-icon').forEach(function(el) {
              fetchDiscoveryIcon('selfhst', el.dataset.iconName, el, 14);
            });
          }).catch(function() {});
        }
      });
      var details = target.closest('details') || target.parentNode;
      details.parentNode.insertBefore(btn, details.nextSibling);
    }, 200);

    var modal = document.createElement('div');
    modal.id = 'verse-discovery-modal';
    modal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.7);z-index:10000001;justify-content:center;align-items:center';
    modal.innerHTML =
      '<div style="background:var(--panel);border-radius:12px;width:80%;max-height:85vh;display:flex;flex-direction:column;border:1px solid var(--edge-main);overflow:hidden">' +
        '<div style="padding:16px 20px;border-bottom:1px solid var(--edge-main);display:flex;justify-content:space-between;align-items:center">' +
          '<h3 style="margin:0;font-size:16px;color:var(--text-main)">Network Discovery</h3>' +
          '<button id="verse-discovery-close" style="background:none;border:none;color:var(--text-soft);font-size:20px;cursor:pointer;padding:0 4px">\u2715</button>' +
        '</div>' +
        '<div style="padding:20px;overflow-y:auto;flex:1">' +
          '<div style="margin-bottom:12px">' +
            '<label style="display:block;margin-bottom:4px;font-size:13px;color:var(--text-soft)">Subnet</label>' +
            '<div style="display:flex;gap:8px;align-items:center">' +
              '<select id="verse-disc-preset" style="flex:1;padding:8px;border-radius:6px;border:1px solid var(--edge-main);background:var(--panel-alt);color:var(--text-main)">' +
                '<option value="192.168.1.0/24">192.168.1.0/24 Home Network (.1 Gateway)</option>' +
                '<option value="192.168.0.0/24">192.168.0.0/24 Home Network (.0 Gateway)</option>' +
                '<option value="10.0.0.0/24">10.0.0.0/24 Small Office / VPN</option>' +
                '<option value="10.0.1.0/24">10.0.1.0/24 Enterprise VLAN 1</option>' +
                '<option value="10.0.2.0/24">10.0.2.0/24 Enterprise VLAN 2</option>' +
                '<option value="172.16.0.0/24">172.16.0.0/24 Enterprise Private</option>' +
                '<option value="172.16.1.0/24">172.16.1.0/24 Enterprise Private 2</option>' +
                '<option value="custom">Custom...</option>' +
              '</select>' +
              '<button id="verse-disc-add-range" style="padding:8px 12px;background:var(--accent);color:var(--bg);border:none;border-radius:6px;cursor:pointer;font-weight:600;white-space:nowrap">+ Add Range</button>' +
            '</div>' +
          '</div>' +
          '<div id="verse-disc-custom-row" style="display:none;margin-bottom:12px">' +
            '<input type="text" id="verse-disc-custom-cidr" placeholder="e.g. 10.10.0.0/24" style="width:100%;padding:8px;border-radius:6px;border:1px solid var(--edge-main);background:var(--panel-alt);color:var(--text-main)">' +
          '</div>' +
          '<div id="verse-disc-ranges" style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px"></div>' +
          '<div style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:12px;align-items:center">' +
            '<div style="display:flex;align-items:center;gap:6px"><label class="toggle-switch"><input type="checkbox" id="verse-disc-icmp" checked><span class="toggle-slider"></span></label><span style="font-size:13px;color:var(--text-soft)">ICMP</span></div>' +
            '<div style="display:flex;align-items:center;gap:6px"><label class="toggle-switch"><input type="checkbox" id="verse-disc-tcp" checked><span class="toggle-slider"></span></label><span style="font-size:13px;color:var(--text-soft)">TCP Ports</span></div>' +
            '<div style="display:flex;align-items:center;gap:6px"><label class="toggle-switch"><input type="checkbox" id="verse-disc-dns" checked><span class="toggle-slider"></span></label><span style="font-size:13px;color:var(--text-soft)">DNS</span></div>' +
            '<div style="display:flex;align-items:center;gap:6px"><label class="toggle-switch"><input type="checkbox" id="verse-disc-netbios" checked><span class="toggle-slider"></span></label><span style="font-size:13px;color:var(--text-soft)">NetBIOS</span></div>' +
            '<div style="display:flex;align-items:center;gap:6px"><label class="toggle-switch"><input type="checkbox" id="verse-disc-mdns" checked><span class="toggle-slider"></span></label><span style="font-size:13px;color:var(--text-soft)">mDNS</span></div>' +
            '<div style="display:flex;align-items:center;gap:6px"><label class="toggle-switch"><input type="checkbox" id="verse-disc-snmp"><span class="toggle-slider"></span></label><span style="font-size:13px;color:var(--text-soft)">SNMP</span></div>' +
          '</div>' +
          '<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">' +
            '<div style="flex:1;min-width:200px">' +
              '<label style="display:block;margin-bottom:4px;font-size:12px;color:var(--text-soft)">TCP Ports</label>' +
              '<input type="text" id="verse-disc-ports" placeholder="Leave empty for all 50+ ports or enter custom" style="width:100%;padding:6px 8px;border-radius:6px;border:1px solid var(--edge-main);background:var(--panel-alt);color:var(--text-main);font-size:12px">' +
            '</div>' +
            '<div id="verse-disc-snmp-row" style="display:none;min-width:140px">' +
              '<label style="display:block;margin-bottom:4px;font-size:12px;color:var(--text-soft)">SNMP Community</label>' +
              '<input type="text" id="verse-disc-snmp-community" value="public" style="width:100%;padding:6px 8px;border-radius:6px;border:1px solid var(--edge-main);background:var(--panel-alt);color:var(--text-main);font-size:12px">' +
            '</div>' +
          '</div>' +
          '<details id="verse-disc-port-ref" style="margin-bottom:12px">' +
            '<summary style="cursor:pointer;font-size:12px;color:var(--text-soft);user-select:none;padding:4px 0">Default Scan Ports (loading...)</summary>' +
            '<div id="verse-disc-port-ref-body" style="max-height:200px;overflow-y:auto;margin-top:6px;padding:8px;background:var(--panel-alt);border-radius:6px;border:1px solid var(--edge-main)">' +
            '</div>' +
          '</details>' +
          '<div style="display:flex;gap:8px;margin-bottom:12px">' +
            '<button id="verse-discovery-start" style="padding:8px 20px;background:var(--accent);color:var(--bg);border:none;border-radius:6px;cursor:pointer;font-weight:600">Start Scan</button>' +
            '<button id="verse-discovery-cancel" style="display:none;padding:8px 20px;background:var(--danger);color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:600">Cancel</button>' +
          '</div>' +
          '<div style="margin-bottom:12px;padding:8px 12px;background:var(--panel-alt);border-radius:6px;border:1px solid var(--edge-main)">' +
            '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">' +
              '<span id="verse-discovery-progress-text" style="font-size:12px;color:var(--text-soft)">Ready</span>' +
              '<span id="verse-discovery-count" style="font-size:12px;color:var(--text-soft)"></span>' +
            '</div>' +
            '<div style="width:100%;height:6px;background:var(--edge-main);border-radius:3px;overflow:hidden">' +
              '<div id="verse-discovery-progress-fill" style="width:0%;height:100%;background:var(--accent);border-radius:3px;transition:width 0.3s"></div>' +
            '</div>' +
          '</div>' +
          '<input type="text" id="verse-disc-table-search" placeholder="Search by IP or name..." style="width:100%;padding:6px 10px;border-radius:6px;border:1px solid var(--edge-main);background:var(--panel-alt);color:var(--text-main);font-size:12px;margin-bottom:8px;box-sizing:border-box">' +
          '<div style="overflow-x:auto">' +
            '<table style="width:100%;border-collapse:collapse;font-size:13px">' +
              '<thead><tr style="border-bottom:2px solid var(--edge-main)">' +
                '<th style="padding:8px;text-align:left;width:50px"><label class="toggle-switch"><input type="checkbox" id="verse-discovery-select-all" checked><span class="toggle-slider"></span></label></th>' +
                '<th style="padding:8px;text-align:left;color:var(--text-soft)">IP</th>' +
                '<th style="padding:8px;text-align:left;color:var(--text-soft)">Hostname <button id="verse-disc-edit-btn" title="Edit host details before adding" style="padding:2px 6px;font-size:10px;background:var(--panel);color:var(--accent);border:1px solid var(--accent);border-radius:4px;cursor:pointer;vertical-align:middle;display:none">Edit All</button></th>' +
                '<th style="padding:8px;text-align:left;color:var(--text-soft)">Services</th>' +
                '<th style="padding:8px;text-align:center;color:var(--text-soft)">Icon</th>' +
                '<th style="padding:8px;text-align:left;color:var(--text-soft)">Type</th>' +
                '<th style="padding:8px;text-align:left;color:var(--text-soft)">Rack</th>' +
                '<th style="padding:8px;text-align:left;color:var(--text-soft)">Layer</th>' +
              '</tr></thead>' +
              '<tbody id="verse-discovery-tbody"></tbody>' +
            '</table>' +
          '</div>' +
        '</div>' +
        '<div style="padding:12px 20px;border-top:1px solid var(--edge-main);display:flex;justify-content:flex-end">' +
          '<button id="verse-discovery-add" style="padding:8px 20px;background:var(--accent);color:var(--bg);border:none;border-radius:6px;cursor:pointer;font-weight:600">Add Selected to Canvas</button>' +
        '</div>' +
      '</div>';

    document.body.appendChild(modal);

    var editModal = document.createElement('div');
    editModal.id = 'verse-disc-edit-modal';
    editModal.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.75);z-index:10000002;justify-content:center;align-items:center';
    editModal.innerHTML =
      '<div style="background:var(--panel);border-radius:12px;width:80%;max-height:85vh;display:flex;flex-direction:column;border:1px solid var(--edge-main);overflow:hidden">' +
        '<div style="padding:16px 20px;border-bottom:1px solid var(--edge-main);display:flex;align-items:center;gap:12px">' +
          '<h3 style="margin:0;font-size:16px;color:var(--text-main);white-space:nowrap">Edit Host Details</h3>' +
          '<input type="text" id="verse-disc-edit-search" placeholder="Search by IP or name..." style="flex:1;padding:6px 10px;border-radius:6px;border:1px solid var(--edge-main);background:var(--panel-alt);color:var(--text-main);font-size:12px">' +
          '<button id="verse-disc-edit-close" style="background:none;border:none;color:var(--text-soft);font-size:20px;cursor:pointer;padding:0 4px">\u2715</button>' +
        '</div>' +
        '<div id="verse-disc-edit-body" style="padding:20px;overflow-y:auto;flex:1"></div>' +
        '<div style="padding:12px 20px;border-top:1px solid var(--edge-main);display:flex;justify-content:flex-end">' +
          '<button id="verse-disc-edit-done" style="padding:8px 20px;background:var(--accent);color:var(--bg);border:none;border-radius:6px;cursor:pointer;font-weight:600">Done</button>' +
        '</div>' +
      '</div>';
    document.body.appendChild(editModal);
    _renderEditModal = renderEditModal;

    function buildShapeOptions(category, selectedShape) {
      var shapes = DISC_SHAPES[category] || DISC_SHAPES.basic;
      return shapes.map(function(s) {
        return '<option value="' + s + '"' + (s === selectedShape ? ' selected' : '') + '>' + s + '</option>';
      }).join('');
    }

    function buildCategoryOptions(selected) {
      var cats = Object.keys(DISC_SHAPES);
      return cats.map(function(c) {
        return '<option value="' + c + '"' + (c === selected ? ' selected' : '') + '>' + c + '</option>';
      }).join('');
    }

    function renderIconTagBadges(container, ip) {
      container.innerHTML = '';
      var tags = (discoveryOverrides[ip] && discoveryOverrides[ip].iconTags) || [];
      tags.forEach(function(tag, ti) {
        var badge = document.createElement('span');
        badge.style.cssText = 'display:inline-flex;align-items:center;gap:4px;padding:2px 8px;background:var(--panel);border:1px solid var(--edge-main);border-radius:12px;font-size:11px;color:var(--text-main)';
        var svgSpan = '';
        if (tag.svg) svgSpan = '<span style="width:16px;height:16px;display:inline-flex;align-items:center;justify-content:center">' + tag.svg + '</span>';
        badge.innerHTML = svgSpan + '<span>' + escapeHtml(tag.name) + '</span>';
        var removeBtn = document.createElement('button');
        removeBtn.style.cssText = 'background:none;border:none;color:var(--danger);cursor:pointer;font-size:12px;padding:0 2px;line-height:1';
        removeBtn.textContent = '\u2715';
        removeBtn.addEventListener('click', function() {
          if (discoveryOverrides[ip] && discoveryOverrides[ip].iconTags) {
            discoveryOverrides[ip].iconTags.splice(ti, 1);
            renderIconTagBadges(container, ip);
          }
        });
        badge.appendChild(removeBtn);
        container.appendChild(badge);
      });
    }

    function renderEditModal(scrollToIp) {
      var body = document.getElementById('verse-disc-edit-body');
      if (!body) return;
      body.innerHTML = '';
      var searchInput = document.getElementById('verse-disc-edit-search');
      if (searchInput) searchInput.value = '';

      var nd = getGlobal('NODE_DATA') || {};
      var canvasIPs = {};
      Object.keys(nd).forEach(function(nid) {
        if (nd[nid] && nd[nid].ip) canvasIPs[nd[nid].ip] = true;
      });

      var hasCards = false;

      discoveryResults.forEach(function(host, idx) {
        if (!host) return;

        hasCards = true;
        var ov = discoveryOverrides[host.ip] || {};
        var displayName = ov.name || host.hostname || host.ip;
        var ipVal = ov.ip || host.ip;
        var tagsVal = ov.tags || '';
        var cat = ov.category || 'network';
        var shp = ov.shape || 'circle';
        var pingEnabled = ov.pingEnabled !== undefined ? ov.pingEnabled : true;
        var probeType = ov.probeType || 'auto';
        var tcpPorts = ov.tcpPorts || (host.ports && host.ports.length > 0 ? host.ports.join(', ') : '22, 80, 443');
        var pingTimeout = ov.pingTimeout || 3000;
        var rackCap = ov.rackCapacity || '42';
        var iconPreview = '';
        if (ov.iconData && ov.iconData.svg) {
          iconPreview = '<span style="width:24px;height:24px;display:inline-flex;align-items:center;justify-content:center">' + ov.iconData.svg + '</span>' +
            '<span style="font-size:11px;color:var(--accent)">' + escapeHtml(ov.iconData.library + '/' + ov.iconData.name) + '</span>';
        } else if (ov.iconData && ov.iconData.name) {
          iconPreview = '<span class="disc-edit-icon-fetch" data-lib="' + escapeHtml(ov.iconData.library) + '" data-name="' + escapeHtml(ov.iconData.name) + '" style="width:24px;height:24px;display:inline-flex;align-items:center;justify-content:center"></span>' +
            '<span style="font-size:11px;color:var(--accent)">' + escapeHtml(ov.iconData.library + '/' + ov.iconData.name) + '</span>';
        }

        var toggle = document.querySelector('.verse-type-toggle[data-ip="' + host.ip + '"]');
        var activeBtn = toggle ? toggle.querySelector('.verse-type-btn.active') : null;
        var isRack = (ov.typeToggle === 'rack') || (activeBtn && activeBtn.dataset.type === 'rack');
        var rackDisplay = isRack ? 'flex' : 'none';
        var tcpDisplay = (probeType === 'tcp' || probeType === 'multi') ? 'block' : 'none';

        var onCanvas = canvasIPs[host.ip];
        var canvasTag = onCanvas ? ' <span style="font-size:10px;font-weight:400;color:var(--accent);font-style:italic;margin-left:6px">on canvas</span>' : '';

        var card = document.createElement('div');
        card.style.cssText = 'margin-bottom:16px;padding:14px;border:1px solid var(--edge-main);border-radius:8px;background:var(--panel-alt);transition:border-color 0.3s' + (onCanvas ? ';opacity:0.6' : '');
        card.setAttribute('data-edit-ip', host.ip);
        card.innerHTML =
          '<div style="margin-bottom:10px;font-weight:600;font-size:13px;color:var(--text-main);font-family:monospace">' + escapeHtml(host.ip) + canvasTag + '</div>' +
          '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">' +
            '<div>' +
              '<label style="display:block;font-size:11px;color:var(--text-soft);margin-bottom:2px">Name</label>' +
              '<input type="text" class="disc-edit-name" value="' + escapeHtml(displayName) + '" style="width:100%;padding:6px 8px;border-radius:4px;border:1px solid var(--edge-main);background:var(--panel);color:var(--text-main);font-size:12px">' +
            '</div>' +
            '<div>' +
              '<label style="display:block;font-size:11px;color:var(--text-soft);margin-bottom:2px">IP</label>' +
              '<input type="text" class="disc-edit-ip" value="' + escapeHtml(ipVal) + '" style="width:100%;padding:6px 8px;border-radius:4px;border:1px solid var(--edge-main);background:var(--panel);color:var(--text-main);font-size:12px">' +
            '</div>' +
            '<div style="grid-column:1/-1">' +
              '<label style="display:block;font-size:11px;color:var(--text-soft);margin-bottom:2px">Tags (comma separated)</label>' +
              '<input type="text" class="disc-edit-tags" value="' + escapeHtml(tagsVal) + '" placeholder="e.g. Production, Core, VLAN10" style="width:100%;padding:6px 8px;border-radius:4px;border:1px solid var(--edge-main);background:var(--panel);color:var(--text-main);font-size:12px">' +
            '</div>' +
            '<div style="grid-column:1/-1;display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
              '<button class="disc-edit-icon-tag-btn" style="padding:4px 10px;background:var(--panel);color:var(--text-main);border:1px solid var(--edge-main);border-radius:4px;cursor:pointer;font-size:11px">Add Web Icon Tag</button>' +
              '<div class="disc-edit-icon-tags-list" style="display:flex;flex-wrap:wrap;gap:6px"></div>' +
            '</div>' +
            '<div style="grid-column:1/-1;display:grid;grid-template-columns:1fr 1fr 56px;gap:8px;align-items:end">' +
              '<div>' +
                '<label style="display:block;font-size:11px;color:var(--text-soft);margin-bottom:2px">Category</label>' +
                '<select class="disc-edit-category" style="width:100%;padding:6px 8px;border-radius:4px;border:1px solid var(--edge-main);background:var(--panel);color:var(--text-main);font-size:12px">' + buildCategoryOptions(cat) + '</select>' +
              '</div>' +
              '<div>' +
                '<label style="display:block;font-size:11px;color:var(--text-soft);margin-bottom:2px">Shape</label>' +
                '<select class="disc-edit-shape" style="width:100%;padding:6px 8px;border-radius:4px;border:1px solid var(--edge-main);background:var(--panel);color:var(--text-main);font-size:12px">' + buildShapeOptions(cat, shp) + '</select>' +
              '</div>' +
              '<div class="disc-edit-shape-preview" style="display:flex;align-items:center;justify-content:center;width:48px;height:48px;border:1px solid var(--edge-main);border-radius:6px;background:var(--panel)"' + (ov.iconData && ov.iconData.name && !ov.iconData.svg ? ' data-fetch-lib="' + escapeHtml(ov.iconData.library) + '" data-fetch-name="' + escapeHtml(ov.iconData.name) + '"' : '') + '>' +
                (ov.iconData && ov.iconData.svg ? '<span style="width:36px;height:36px;display:inline-flex;align-items:center;justify-content:center">' + ov.iconData.svg + '</span>' : getShapePreviewSVG(shp || 'circle')) +
              '</div>' +
            '</div>' +
            '<div style="grid-column:1/-1;display:flex;align-items:center;gap:8px">' +
              '<button class="disc-edit-icon-btn" style="padding:6px 12px;background:var(--accent);color:var(--bg);border:none;border-radius:4px;cursor:pointer;font-size:11px;font-weight:600">Or Search Web Icons</button>' +
              '<span class="disc-edit-icon-preview" style="display:inline-flex;align-items:center;gap:6px">' + iconPreview + '</span>' +
            '</div>' +
            '<div class="disc-edit-rack-section" style="grid-column:1/-1;display:' + rackDisplay + ';align-items:center;gap:8px;padding:8px;border:1px solid var(--edge-main);border-radius:4px;background:var(--panel)">' +
              '<label style="font-size:11px;color:var(--text-soft);white-space:nowrap">Rack Capacity</label>' +
              '<select class="disc-edit-rack-cap" style="flex:1;padding:6px 8px;border-radius:4px;border:1px solid var(--edge-main);background:var(--panel-alt);color:var(--text-main);font-size:12px">' +
                '<option value="6"' + (rackCap === '6' ? ' selected' : '') + '>6U Mini Rack</option>' +
                '<option value="12"' + (rackCap === '12' ? ' selected' : '') + '>12U Small Wall Mount</option>' +
                '<option value="24"' + (rackCap === '24' ? ' selected' : '') + '>24U Half Rack</option>' +
                '<option value="42"' + (rackCap === '42' ? ' selected' : '') + '>42U Standard Full Rack</option>' +
                '<option value="48"' + (rackCap === '48' ? ' selected' : '') + '>48U Large Rack</option>' +
              '</select>' +
            '</div>' +
            '<div style="grid-column:1/-1;border-top:1px solid var(--edge-main);padding-top:8px;margin-top:4px">' +
              '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">' +
                '<span style="font-size:11px;color:var(--text-soft)">Probe Enabled</span>' +
                '<label class="toggle-switch"><input type="checkbox" class="disc-edit-ping-enabled"' + (pingEnabled ? ' checked' : '') + '><span class="toggle-slider"></span></label>' +
              '</div>' +
              '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
                '<div style="flex:1;min-width:140px">' +
                  '<label style="display:block;font-size:11px;color:var(--text-soft);margin-bottom:2px">Probe Type</label>' +
                  '<select class="disc-edit-probe-type" style="width:100%;padding:6px 8px;border-radius:4px;border:1px solid var(--edge-main);background:var(--panel);color:var(--text-main);font-size:12px">' +
                    '<option value="auto"' + (probeType === 'auto' ? ' selected' : '') + '>Auto (ICMP + HTTP)</option>' +
                    '<option value="icmp"' + (probeType === 'icmp' ? ' selected' : '') + '>ICMP Ping Only</option>' +
                    '<option value="tcp"' + (probeType === 'tcp' ? ' selected' : '') + '>TCP Port Check</option>' +
                    '<option value="http"' + (probeType === 'http' ? ' selected' : '') + '>HTTP/HTTPS Only</option>' +
                    '<option value="multi"' + (probeType === 'multi' ? ' selected' : '') + '>Multi Probe</option>' +
                  '</select>' +
                '</div>' +
                '<div style="min-width:80px">' +
                  '<label style="display:block;font-size:11px;color:var(--text-soft);margin-bottom:2px">Timeout (ms)</label>' +
                  '<input type="number" class="disc-edit-ping-timeout" value="' + pingTimeout + '" min="1000" max="10000" step="500" style="width:100%;padding:6px 8px;border-radius:4px;border:1px solid var(--edge-main);background:var(--panel);color:var(--text-main);font-size:12px">' +
                '</div>' +
              '</div>' +
              '<div class="disc-edit-tcp-row" style="display:' + tcpDisplay + ';margin-top:6px">' +
                '<label style="display:block;font-size:11px;color:var(--text-soft);margin-bottom:2px">TCP Ports</label>' +
                '<input type="text" class="disc-edit-tcp-ports" value="' + escapeHtml(tcpPorts) + '" placeholder="22, 80, 443, 3389" style="width:100%;padding:6px 8px;border-radius:4px;border:1px solid var(--edge-main);background:var(--panel);color:var(--text-main);font-size:12px">' +
              '</div>' +
            '</div>' +
          '</div>';
        body.appendChild(card);

        var iconTagsList = card.querySelector('.disc-edit-icon-tags-list');
        if (iconTagsList) renderIconTagBadges(iconTagsList, host.ip);
      });

      if (!hasCards) {
        body.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-soft)">No editable hosts selected. Select hosts in the discovery table first, or all selected hosts are already on canvas.</div>';
      }

      body.querySelectorAll('.disc-edit-category').forEach(function(sel) {
        sel.addEventListener('change', function() {
          var card = sel.closest('[data-edit-ip]');
          var ip = card.getAttribute('data-edit-ip');
          var shapeSel = card.querySelector('.disc-edit-shape');
          shapeSel.innerHTML = buildShapeOptions(sel.value, '');
          var preview = card.querySelector('.disc-edit-shape-preview');
          if (preview) preview.innerHTML = getShapePreviewSVG(shapeSel.value);
          if (discoveryOverrides[ip]) delete discoveryOverrides[ip].iconData;
          var iconPreviewEl = card.querySelector('.disc-edit-icon-preview');
          if (iconPreviewEl) iconPreviewEl.innerHTML = '';
          saveCardOverride(card, ip);
        });
      });

      body.querySelectorAll('.disc-edit-shape').forEach(function(sel) {
        sel.addEventListener('change', function() {
          var card = sel.closest('[data-edit-ip]');
          var ip = card.getAttribute('data-edit-ip');
          var preview = card.querySelector('.disc-edit-shape-preview');
          if (preview) preview.innerHTML = getShapePreviewSVG(sel.value);
          if (discoveryOverrides[ip]) delete discoveryOverrides[ip].iconData;
          var iconPreviewEl = card.querySelector('.disc-edit-icon-preview');
          if (iconPreviewEl) iconPreviewEl.innerHTML = '';
          saveCardOverride(card, ip);
        });
      });

      body.querySelectorAll('.disc-edit-probe-type').forEach(function(sel) {
        sel.addEventListener('change', function() {
          var card = sel.closest('[data-edit-ip]');
          var tcpRow = card.querySelector('.disc-edit-tcp-row');
          if (tcpRow) tcpRow.style.display = (sel.value === 'tcp' || sel.value === 'multi') ? 'block' : 'none';
          var ip = card.getAttribute('data-edit-ip');
          saveCardOverride(card, ip);
        });
      });

      body.querySelectorAll('.disc-edit-icon-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var card = btn.closest('[data-edit-ip]');
          var ip = card.getAttribute('data-edit-ip');
          if (typeof window.openIconPicker === 'function') {
            window.openIconPicker(function(iconData) {
              if (!discoveryOverrides[ip]) discoveryOverrides[ip] = {};
              discoveryOverrides[ip].iconData = iconData;
              var preview = card.querySelector('.disc-edit-icon-preview');
              if (preview && iconData && iconData.name) {
                if (iconData.svg) {
                  preview.innerHTML = '<span style="width:24px;height:24px;display:inline-flex;align-items:center;justify-content:center">' + iconData.svg + '</span>' +
                    '<span style="font-size:11px;color:var(--accent)">' + escapeHtml(iconData.library + '/' + iconData.name) + '</span>';
                } else {
                  var fetchSpan = document.createElement('span');
                  fetchSpan.style.cssText = 'width:24px;height:24px;display:inline-flex;align-items:center;justify-content:center';
                  preview.innerHTML = '';
                  preview.appendChild(fetchSpan);
                  fetchDiscoveryIcon(iconData.library, iconData.name, fetchSpan, 24);
                  var label = document.createElement('span');
                  label.style.cssText = 'font-size:11px;color:var(--accent)';
                  label.textContent = iconData.library + '/' + iconData.name;
                  preview.appendChild(label);
                }
              }
              var shapePreview = card.querySelector('.disc-edit-shape-preview');
              if (shapePreview && iconData && iconData.name) {
                if (iconData.svg) {
                  shapePreview.innerHTML = '<span style="width:36px;height:36px;display:inline-flex;align-items:center;justify-content:center">' + iconData.svg + '</span>';
                } else {
                  fetchDiscoveryIcon(iconData.library, iconData.name, shapePreview, 36);
                }
              }
            });
          }
        });
      });

      body.querySelectorAll('.disc-edit-icon-tag-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
          var card = btn.closest('[data-edit-ip]');
          var ip = card.getAttribute('data-edit-ip');
          if (typeof window.openIconPicker === 'function') {
            window.openIconPicker(function(iconData) {
              if (!discoveryOverrides[ip]) discoveryOverrides[ip] = {};
              if (!discoveryOverrides[ip].iconTags) discoveryOverrides[ip].iconTags = [];
              discoveryOverrides[ip].iconTags.push({ type: 'icon', library: iconData.library, name: iconData.name, svg: iconData.svg || '' });
              var list = card.querySelector('.disc-edit-icon-tags-list');
              if (list) renderIconTagBadges(list, ip);
            });
          }
        });
      });

      body.querySelectorAll('.disc-edit-shape-preview[data-fetch-name]').forEach(function(el) {
        fetchDiscoveryIcon(el.getAttribute('data-fetch-lib'), el.getAttribute('data-fetch-name'), el, 36);
      });

      body.querySelectorAll('.disc-edit-icon-fetch').forEach(function(el) {
        fetchDiscoveryIcon(el.getAttribute('data-lib'), el.getAttribute('data-name'), el, 24);
      });

      body.querySelectorAll('input, select').forEach(function(el) {
        el.addEventListener('change', function() {
          var card = el.closest('[data-edit-ip]');
          if (!card) return;
          var ip = card.getAttribute('data-edit-ip');
          saveCardOverride(card, ip);
        });
      });

      if (scrollToIp) {
        var target = body.querySelector('[data-edit-ip="' + scrollToIp + '"]');
        if (target) {
          setTimeout(function() {
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            target.style.borderColor = 'var(--accent)';
            setTimeout(function() { target.style.borderColor = ''; }, 2000);
          }, 100);
        }
      }
    }

    function saveCardOverride(card, ip) {
      if (!discoveryOverrides[ip]) discoveryOverrides[ip] = {};
      var ov = discoveryOverrides[ip];
      var nameEl = card.querySelector('.disc-edit-name');
      var ipEl = card.querySelector('.disc-edit-ip');
      var tagsEl = card.querySelector('.disc-edit-tags');
      var catEl = card.querySelector('.disc-edit-category');
      var shapeEl = card.querySelector('.disc-edit-shape');
      var rackCapEl = card.querySelector('.disc-edit-rack-cap');
      var pingEnabledEl = card.querySelector('.disc-edit-ping-enabled');
      var probeTypeEl = card.querySelector('.disc-edit-probe-type');
      var tcpPortsEl = card.querySelector('.disc-edit-tcp-ports');
      var pingTimeoutEl = card.querySelector('.disc-edit-ping-timeout');
      delete ov._seeded;
      if (nameEl) ov.name = nameEl.value;
      if (ipEl) ov.ip = ipEl.value;
      if (tagsEl) ov.tags = tagsEl.value;
      if (catEl) ov.category = catEl.value;
      if (shapeEl) ov.shape = shapeEl.value;
      if (rackCapEl) ov.rackCapacity = rackCapEl.value;
      if (pingEnabledEl) ov.pingEnabled = pingEnabledEl.checked;
      if (probeTypeEl) ov.probeType = probeTypeEl.value;
      if (tcpPortsEl) ov.tcpPorts = tcpPortsEl.value;
      if (pingTimeoutEl) ov.pingTimeout = parseInt(pingTimeoutEl.value, 10) || 3000;
    }

    modal.addEventListener('click', function(e) {
      if (e.target === modal) modal.classList.remove('active');
    });

    document.getElementById('verse-discovery-close').addEventListener('click', function() {
      modal.classList.remove('active');
    });

    editModal.addEventListener('click', function(e) {
      if (e.target === editModal) {
        editModal.classList.remove('active');
        renderDiscoveryResults();
      }
    });

    document.getElementById('verse-disc-edit-close').addEventListener('click', function() {
      editModal.classList.remove('active');
      renderDiscoveryResults();
    });

    document.getElementById('verse-disc-edit-done').addEventListener('click', function() {
      editModal.classList.remove('active');
      renderDiscoveryResults();
    });

    document.getElementById('verse-disc-edit-btn').addEventListener('click', function() {
      renderEditModal();
      editModal.classList.add('active');
    });

    document.getElementById('verse-disc-edit-search').addEventListener('input', function() {
      var q = this.value.toLowerCase().trim();
      var body = document.getElementById('verse-disc-edit-body');
      if (!body) return;
      var cards = body.querySelectorAll('[data-edit-ip]');
      var visibleCount = 0;
      var lastVisible = null;
      cards.forEach(function(card) {
        var ip = card.getAttribute('data-edit-ip').toLowerCase();
        var nameInput = card.querySelector('.disc-edit-name');
        var name = nameInput ? nameInput.value.toLowerCase() : '';
        if (!q || ip.indexOf(q) !== -1 || name.indexOf(q) !== -1) {
          card.style.display = '';
          visibleCount++;
          lastVisible = card;
        } else {
          card.style.display = 'none';
        }
      });
      if (visibleCount === 1 && lastVisible) {
        lastVisible.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });

    document.getElementById('verse-disc-preset').addEventListener('change', function() {
      document.getElementById('verse-disc-custom-row').style.display = this.value === 'custom' ? 'block' : 'none';
    });

    document.getElementById('verse-disc-snmp').addEventListener('change', function() {
      document.getElementById('verse-disc-snmp-row').style.display = this.checked ? 'block' : 'none';
    });

    document.getElementById('verse-disc-add-range').addEventListener('click', function() {
      var cidr = getCurrentCIDR();
      if (cidr && discoveryRanges.indexOf(cidr) === -1) {
        discoveryRanges.push(cidr);
        renderRangePills();
      }
    });

    document.getElementById('verse-discovery-select-all').addEventListener('change', function(e) {
      var checks = document.querySelectorAll('.verse-discovery-check');
      checks.forEach(function(cb) { cb.checked = e.target.checked; });
    });

    document.getElementById('verse-discovery-start').addEventListener('click', async function() {
      var cidrs = discoveryRanges.length > 0 ? discoveryRanges.slice() : getDiscoveryCIDRs();
      if (cidrs.length === 0) return;

      if (discoveryTaskId) {
        try {
          await fetch('/api/discover/cancel', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-csrf-token': window.CSRF_TOKEN },
            body: JSON.stringify({ taskId: discoveryTaskId })
          });
        } catch(e) {}
        discoveryTaskId = null;
      }

      discoveryResults = [];
      discoveryScanning = true;
      renderDiscoveryResults();
      updateDiscoveryProgress(0, 0, 0);

      var btn = document.getElementById('verse-discovery-start');
      var cancelBtn = document.getElementById('verse-discovery-cancel');
      btn.textContent = 'Scanning...';
      btn.disabled = true;
      cancelBtn.style.display = 'inline-block';

      var ports = parsePorts(document.getElementById('verse-disc-ports').value);

      try {
        var resp = await fetch('/api/discover', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-csrf-token': window.CSRF_TOKEN },
          body: JSON.stringify({
            cidrs: cidrs,
            roomId: ROOM_ID,
            options: {
              icmp: document.getElementById('verse-disc-icmp').checked,
              tcp: document.getElementById('verse-disc-tcp').checked,
              dns: document.getElementById('verse-disc-dns').checked,
              netbios: document.getElementById('verse-disc-netbios').checked,
              mdns: document.getElementById('verse-disc-mdns').checked,
              snmp: document.getElementById('verse-disc-snmp').checked,
              snmpCommunity: document.getElementById('verse-disc-snmp-community').value || 'public',
              ports: ports
            }
          })
        });
        var result = await resp.json();
        if (!resp.ok) {
          btn.textContent = 'Start Scan';
          btn.disabled = false;
          cancelBtn.style.display = 'none';
          discoveryScanning = false;
          var progressText = document.getElementById('verse-discovery-progress-text');
          if (progressText) progressText.textContent = 'Error: ' + (result.error || 'Scan failed');
          return;
        }
        discoveryTaskId = result.taskId;
      } catch(e) {
        btn.textContent = 'Start Scan';
        btn.disabled = false;
        cancelBtn.style.display = 'none';
        discoveryScanning = false;
      }
    });

    document.getElementById('verse-discovery-cancel').addEventListener('click', async function() {
      if (!discoveryTaskId) return;
      try {
        await fetch('/api/discover/cancel', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-csrf-token': window.CSRF_TOKEN },
          body: JSON.stringify({ taskId: discoveryTaskId })
        });
      } catch(e) {}
      finalizeDiscovery(discoveryResults.length);
    });

    document.getElementById('verse-discovery-add').addEventListener('click', function() {
      var checks = document.querySelectorAll('.verse-discovery-check:checked');
      if (checks.length === 0) return;

      var nd = getGlobal('NODE_DATA');
      var positions = getGlobal('savedPositions');
      var sizes = getGlobal('savedSizes');
      var styles = getGlobal('savedStyles');
      var pushUndo = window.__collabGetVar('pushUndo');
      if (pushUndo) pushUndo('add discovered nodes');

      var existingIPs = {};
      Object.keys(nd).forEach(function(nid) {
        if (nd[nid] && nd[nid].ip) existingIPs[nd[nid].ip] = true;
      });

      var cols = Math.ceil(Math.sqrt(checks.length));
      var spacing = 120;
      var cs = getGlobal('canvasState') || { panX: 0, panY: 0, zoom: 1 };
      var startX = (-cs.panX / cs.zoom) + 200;
      var startY = (-cs.panY / cs.zoom) + 200;
      var added = 0;

      var entries = [];
      checks.forEach(function(cb) {
        var idx = parseInt(cb.dataset.idx, 10);
        var host = discoveryResults[idx];
        if (!host || existingIPs[host.ip]) return;
        var ov = discoveryOverrides[host.ip] || {};
        var toggle = document.querySelector('.verse-type-toggle[data-idx="' + idx + '"]');
        var activeBtn = toggle ? toggle.querySelector('.verse-type-btn.active') : null;
        var isRack = (ov.typeToggle === 'rack') || (activeBtn && activeBtn.dataset.type === 'rack');
        entries.push({ host: host, ov: ov, isRack: isRack, idx: idx });
      });

      entries.sort(function(a, b) {
        return (b.isRack ? 1 : 0) - (a.isRack ? 1 : 0);
      });

      var newRackIpToNodeId = {};

      entries.forEach(function(entry) {
        var host = entry.host;
        var ov = entry.ov;
        var isRack = entry.isRack;

        var nodeName = ov.name || host.hostname || host.ip;
        var nodeIp = ov.ip || host.ip;
        var nodeShape = ov.shape || (isRack ? 'server' : 'circle');
        var nodeTags = [];
        if (ov.tags) {
          nodeTags = ov.tags.split(',').map(function(t) { return t.trim(); }).filter(function(t) { return t; });
        }
        if (ov.iconTags && ov.iconTags.length > 0) {
          ov.iconTags.forEach(function(it) {
            nodeTags.push({ type: 'icon', library: it.library, name: it.name });
          });
        }
        var pingEnabled = ov.pingEnabled !== undefined ? ov.pingEnabled : true;
        var pingTimeout = ov.pingTimeout || 3000;

        var probeType = ov.probeType || 'auto';
        var tcpPortsStr = ov.tcpPorts || (host.ports && host.ports.length > 0 ? host.ports.join(', ') : '');
        var tcpPortsList = tcpPortsStr ? tcpPortsStr.split(',').map(function(s) { return parseInt(s.trim(), 10); }).filter(function(p) { return p >= 1 && p <= 65535; }) : [];
        var probeTypes;
        if (probeType === 'icmp') {
          probeTypes = [{ type: 'icmp' }];
        } else if (probeType === 'tcp') {
          probeTypes = [{ type: 'icmp' }];
          tcpPortsList.forEach(function(p) { probeTypes.push({ type: 'tcp', port: p }); });
        } else if (probeType === 'http') {
          probeTypes = [{ type: 'http' }];
        } else if (probeType === 'multi') {
          probeTypes = [{ type: 'icmp' }, { type: 'http' }];
          tcpPortsList.forEach(function(p) { probeTypes.push({ type: 'tcp', port: p }); });
          probeTypes.push({ type: 'dns' });
        } else {
          probeTypes = [{ type: 'icmp' }, { type: 'http' }];
        }

        var nodeId = generateUUID();
        var col = added % cols;
        var row = Math.floor(added / cols);

        var resolvedRack = '';
        var resolvedUnit = '';
        var resolvedUHeight = '1';
        if (!isRack && ov.assignedRackRef) {
          var parts = ov.assignedRackRef.split(':');
          var refType = parts[0];
          var refId = parts.slice(1).join(':');
          if (refType === 'canvas' && nd[refId]) {
            resolvedRack = refId;
          } else if (refType === 'new' && newRackIpToNodeId[refId]) {
            resolvedRack = newRackIpToNodeId[refId];
          }
          if (resolvedRack) {
            resolvedUnit = ov.rackUnit || '';
            resolvedUHeight = ov.uHeight || '1';
          }
        }

        nd[nodeId] = {
          shape: nodeShape,
          name: nodeName,
          ip: nodeIp,
          role: isRack ? 'Rack' : '',
          tags: nodeTags,
          notes: [],
          mac: '',
          rackUnit: resolvedUnit,
          uHeight: resolvedUHeight,
          layer: ov.layer || 'layer1',
          assignedRack: resolvedRack,
          hostedOn: '',
          locked: false,
          groupId: null,
          ping: {
            enabled: pingEnabled,
            protocol: 'http',
            customUrl: '',
            timeout: pingTimeout,
            status: 'unknown',
            lastCheck: null,
            probeTypes: probeTypes,
            detectedServices: host.services || {},
            dnsHostname: host.dnsName || '',
            netbiosName: host.netbiosName || '',
            mdnsName: host.mdnsName || '',
            httpServer: host.httpServer || '',
            snmpName: host.snmpName || ''
          }
        };

        if (isRack) {
          nd[nodeId].isRack = true;
          nd[nodeId].rackCapacity = ov.rackCapacity || '42';
          newRackIpToNodeId[host.ip] = nodeId;
        }

        positions[nodeId] = { x: startX + col * spacing, y: startY + row * spacing };
        sizes[nodeId] = 50;
        if (!styles[nodeId]) styles[nodeId] = {};
        if (!styles[nodeId]['all']) styles[nodeId]['all'] = {};
        if (ov.iconData && ov.iconData.name) {
          styles[nodeId]['all'].icon = { library: ov.iconData.library, name: ov.iconData.name };
        }

        added++;
        existingIPs[host.ip] = true;
        delete discoveryOverrides[host.ip];
      });

      setGlobal('NODE_DATA', nd);
      setGlobal('savedPositions', positions);
      setGlobal('savedSizes', sizes);
      setGlobal('savedStyles', styles);
      var forge = window.__collabGetVar('forgeTheTopology');
      if (forge) forge();

      renderDiscoveryResults();
      sendFullState();
    });

    var style = document.createElement('style');
    style.textContent = '#verse-discovery-modal{display:none}#verse-discovery-modal.active{display:flex}#verse-disc-edit-modal{display:none}#verse-disc-edit-modal.active{display:flex}';
    document.head.appendChild(style);
  }

  function startCollab() {
    setupAuditLogInjection();
    injectCollabBar();
    hookSaveFunction();
    overridePingFunctions();
    injectProbeUI();
    injectDiscoveryUI();
    connect();
    startStatePolling();
    setTimeout(trackSelection, 1000);
    trackCursor();
  }

  init();
})();
