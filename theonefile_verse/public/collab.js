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
      '.collab-remote-cursor'
    ];
    collabElements.forEach(sel => {
      doc.querySelectorAll(sel).forEach(el => el.remove());
    });

    const body = doc.querySelector('body');
    if (body) {
      body.classList.remove('collab-active');
    }

    doc.querySelectorAll('script[src*="collab"], link[href*="collab.css"], #room-config').forEach(el => el.remove());

    return '<!DOCTYPE html>\n' + doc.documentElement.outerHTML;
  }

  function hookSaveFunction() {
    window.__collabStripHTML = stripCollabFromHTML;
  }

  function startCollab() {
    setupAuditLogInjection();
    injectCollabBar();
    hookSaveFunction();
    connect();
    startStatePolling();
    setTimeout(trackSelection, 1000);
    trackCursor();
  }

  init();
})();
