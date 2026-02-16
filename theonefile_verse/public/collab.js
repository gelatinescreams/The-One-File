(function() {
  'use strict';

  if (!window.ROOM_ID) return;

  const ROOM_ID = window.ROOM_ID;
  const WS_URL = window.WS_URL;
  const HAS_PASSWORD = window.ROOM_HAS_PASSWORD;
  const IS_ADMIN = window.ROOM_IS_ADMIN || false;
  const IS_CREATOR = window.ROOM_IS_CREATOR || IS_ADMIN;

  let shareButtonEnabled = true;

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
    overlay.innerHTML = `
      <div class="collab-sync-content">
        <div class="collab-sync-sword"></div>
        <div class="collab-sync-lightning"></div>
        <div class="collab-sync-text">${getRandomSyncQuote()}</div>
        <div class="collab-sync-subtext">Synchronizing with the realm...</div>
      </div>
    `;
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
    sessionStorage.removeItem(`room-${ROOM_ID}-pwd`);

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
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ collabUserId: window.COLLAB_USER.id })
      });
      if (!res.ok) return null;
      const data = await res.json();
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

    let wsUrl = WS_URL;
    if (currentWsToken) {
      wsUrl += (WS_URL.includes('?') ? '&' : '?') + 'token=' + encodeURIComponent(currentWsToken);
    }

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      reconnectAttempts = 0;
      setConnectionState('connected');
      window.COLLAB_USER.color = getOrCreateUserColor();
      hasReceivedInitialState = false;
      showSyncingOverlay();
      sendMessage('join', { user: window.COLLAB_USER });
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
        } else {
          sendFullState();
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
    let result = text;
    allNames.forEach(name => {
      if (!name) return;
      const escapedName = escapeHtml(name).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp('@' + escapedName, 'gi');
      result = result.replace(regex, '<span class="collab-chat-mention">@' + escapeHtml(name) + '</span>');
    });
    return result;
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
    container.innerHTML = chatMessages.map(msg => {
      const time = formatTimeAgo(msg.timestamp);
      const safeColor = sanitizeColor(msg.userColor);
      const isMentioned = msg.text && window.COLLAB_USER.name &&
        msg.text.toLowerCase().includes('@' + window.COLLAB_USER.name.toLowerCase());
      const mentionClass = isMentioned ? ' mentioned' : '';
      let replyHtml = '';
      if (msg.replyTo) {
        replyHtml = `<div class="collab-chat-reply-ref">${escapeHtml(msg.replyTo.userName)}: ${escapeHtml(msg.replyTo.text)}</div>`;
      }
      const textWithMentions = highlightMentions(escapeHtml(msg.text));
      return `<div class="collab-chat-msg${mentionClass}" data-msg-id="${escapeHtml(msg.id)}">
        ${replyHtml}
        <span class="collab-chat-name" style="color: ${safeColor}">${escapeHtml(msg.userName)}</span>
        <span class="collab-chat-time">${time}</span>
        <button class="collab-chat-reply-btn" data-reply-id="${escapeHtml(msg.id)}">Reply</button>
        <div class="collab-chat-text">${textWithMentions}</div>
      </div>`;
    }).join('');
    container.scrollTop = container.scrollHeight;

    container.querySelectorAll('.collab-chat-reply-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const msgId = e.target.dataset.replyId;
        const msg = chatMessages.find(m => m.id === msgId);
        if (msg) setReplyTo(msg);
      });
    });
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
      cursor.innerHTML = `<svg width="16" height="16" viewBox="0 0 16 16"><path d="M0 0L16 12L8 12L4 16L0 0Z" fill="${safeColor}"/></svg><span class="collab-cursor-name" style="background:${safeColor}">${escapeHtml(user.name)}</span>`;
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
    container.innerHTML = allUsers.map(user => {
      const isMe = user.id === window.COLLAB_USER.id;
      const editingText = user.editingNode ? `<span class="collab-user-editing">editing</span>` : '';
      const tabName = isMe ? myTab : (user.currentTab || 'Main');
      const tabDisplay = `<span class="collab-user-tab">${escapeHtml(tabName)}</span>`;
      const safeColor = sanitizeColor(user.color);
      const initials = getInitials(user.name);
      return `<div class="collab-user ${isMe ? 'me' : ''}" data-user-id="${escapeHtml(user.id)}">
        <div class="collab-user-avatar" style="background: ${safeColor}">${escapeHtml(initials)}</div>
        <div class="collab-user-info">
          <span class="collab-user-name">${escapeHtml(user.name)}</span>${editingText}
          ${tabDisplay}
        </div>
      </div>`;
    }).join('');
  }

  function renderUserIndicators() {
    document.querySelectorAll('.collab-node-indicator, .collab-selection-ring').forEach(el => el.remove());
    users.forEach(user => {
      if (!user.selectedNodes) return;
      user.selectedNodes.forEach(nodeId => {
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

  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
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
    bar.innerHTML = `<div id="collab-conn-dot" class="collab-conn-status connected"></div>
      <div class="collab-users"></div>
      <div id="collab-expiry" class="collab-room-expiry" style="display:none"></div>
      <div class="collab-actions">
        <button class="collab-btn" id="collab-chat-btn"><span class="collab-btn-icon">&#9993;</span><span>Chat</span><span class="collab-chat-badge" id="collab-chat-badge"></span></button>
        <button class="collab-btn" id="collab-share-btn" style="${shareButtonEnabled ? '' : 'display:none'}"><span class="collab-btn-icon">+</span><span>Share</span></button>
        <button class="collab-btn" id="collab-menu-btn"><span class="collab-btn-icon">=</span></button>
      </div>`;
    document.body.prepend(bar);

    const reconnectBanner = document.createElement('div');
    reconnectBanner.id = 'collab-reconnect-banner';
    reconnectBanner.className = 'collab-reconnect-banner';
    reconnectBanner.innerHTML = `<span>Reconnecting...</span><button class="collab-reconnect-btn" id="collab-reconnect-btn">Reconnect</button>`;
    document.body.appendChild(reconnectBanner);

    document.getElementById('collab-reconnect-btn').addEventListener('click', () => {
      reconnectAttempts = 0;
      connect();
    });

    const chatPanel = document.createElement('div');
    chatPanel.id = 'collab-chat-panel';
    chatPanel.innerHTML = `
      <div class="collab-chat-header">
        <span>Chat</span>
        <button class="collab-chat-close" id="collab-chat-close">&times;</button>
      </div>
      <div class="collab-chat-messages" id="collab-chat-messages"></div>
      <div id="collab-typing" class="collab-typing-indicator"></div>
      <div class="collab-chat-input-area" style="position:relative">
        <div id="collab-reply-preview" class="collab-chat-reply-preview">
          <span></span>
          <button class="collab-chat-reply-cancel" id="collab-reply-cancel">&times;</button>
        </div>
        <div id="collab-emoji-picker" class="collab-emoji-picker">
          <div class="collab-emoji-grid">
            ${EMOJI_LIST.map(e => `<button class="collab-emoji-btn" data-emoji="${e}">${e}</button>`).join('')}
          </div>
        </div>
        <div class="collab-chat-input-wrap">
          <button class="collab-emoji-toggle" id="collab-emoji-toggle">&#9786;</button>
          <div class="collab-chat-input-inner">
            <input type="text" id="collab-chat-input" placeholder="Type a message..." maxlength="500" autocomplete="off">
            <div class="collab-chat-char-count" id="collab-char-count"></div>
          </div>
          <button id="collab-chat-send">Send</button>
        </div>
      </div>
    `;
    document.body.appendChild(chatPanel);

    const shareModal = document.createElement('div');
    shareModal.id = 'collab-share-modal';
    shareModal.className = 'collab-modal-overlay';
    shareModal.innerHTML = `<div class="collab-modal">
      <div class="collab-modal-header"><h3>Share Room</h3><button class="collab-modal-close">&times;</button></div>
      <div class="collab-modal-body">
        <div class="collab-share-url">
          <input type="text" readonly value="${window.location.href}" id="collab-share-input">
          <button id="collab-copy-btn">Copy</button>
        </div>
        <div class="collab-qr" id="collab-qr"></div>
        <p class="collab-share-note">${HAS_PASSWORD ? 'Password protected. Share password separately.' : 'Anyone with this link can join.'}</p>
      </div>
    </div>`;
    document.body.appendChild(shareModal);

    const infoModal = document.createElement('div');
    infoModal.id = 'collab-info-modal';
    infoModal.className = 'collab-modal-overlay';
    infoModal.innerHTML = `<div class="collab-modal">
      <div class="collab-modal-header"><h3>Room Info</h3><button class="collab-modal-close">&times;</button></div>
      <div class="collab-modal-body"><div id="collab-info-content"></div></div>
    </div>`;
    document.body.appendChild(infoModal);

    const menuDropdown = document.createElement('div');
    menuDropdown.id = 'collab-menu-dropdown';
    let menuHtml = '';
    if (shareButtonEnabled) {
      menuHtml += `<button class="collab-menu-item" id="collab-menu-copy">Copy Link</button>`;
    }
    menuHtml += `<button class="collab-menu-item" id="collab-menu-info">Room Info</button>
      <button class="collab-menu-item" id="collab-menu-name">Change Name</button>
      <button class="collab-menu-item" id="collab-menu-sound">${chatSoundEnabled ? 'Mute Sounds' : 'Unmute Sounds'}</button>
      <div class="collab-menu-divider"></div>
      <button class="collab-menu-item" id="collab-menu-leave">Leave Room</button>`;
    if (IS_CREATOR) {
      menuHtml += `<button class="collab-menu-item danger" id="collab-menu-delete">Delete Room</button>`;
    }
    menuDropdown.innerHTML = menuHtml;
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
        document.getElementById('collab-info-content').innerHTML = `
          <div class="collab-info-row"><span class="collab-info-label">Room ID</span><span class="collab-info-value collab-info-id">${escapeHtml(ROOM_ID)}</span></div>
          <div class="collab-info-row"><span class="collab-info-label">Created</span><span class="collab-info-value">${escapeHtml(new Date(data.created).toLocaleString())}</span></div>
          <div class="collab-info-row"><span class="collab-info-label">Self Destruct</span><span class="collab-info-value">${escapeHtml(destructText)}</span></div>
          <div class="collab-info-row"><span class="collab-info-label">Password</span><span class="collab-info-value">${data.hasPassword ? 'Yes' : 'No'}</span></div>
          <div class="collab-info-row"><span class="collab-info-label">Connected</span><span class="collab-info-value">${users.size + 1} users</span></div>
          <div class="collab-info-row"><span class="collab-info-label">You are</span><span class="collab-info-value">${IS_CREATOR ? 'Room Creator' : 'Participant'}</span></div>`;
        infoModal.classList.add('active');
      } catch {
        document.getElementById('collab-info-content').innerHTML = '<p>Failed to load room info</p>';
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
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ creatorId: window.COLLAB_USER.id })
          });
          if (res.ok) window.location.href = '/';
          else alert((await res.json()).error || 'Failed to delete');
        } catch { alert('Failed to delete room'); }
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

    if (!window.QRCode) {
      const script = document.createElement('script');
      script.src = 'https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js';
      script.onload = () => renderQR(container, url);
      script.onerror = () => { container.innerHTML = '<p style="color:#888;font-size:12px;">QR unavailable</p>'; };
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
      container.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 4 });
    } catch {
      container.innerHTML = '<p style="color:#888;font-size:12px;">QR unavailable</p>';
    }
  }

  function showNameModal(isChange = false, errorMsg = null) {
    const existing = document.getElementById('collab-name-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'collab-name-modal';
    modal.className = 'collab-modal-overlay active';
    const safeErrorMsg = errorMsg ? escapeHtml(errorMsg) : '';
    modal.innerHTML = `<div class="collab-modal">
      <div class="collab-modal-header">
        <h3>${isChange ? 'Change Name' : 'Enter Your Name'}</h3>
        ${isChange ? '<button class="collab-modal-close">&times;</button>' : ''}
      </div>
      <div class="collab-modal-body">
        <input type="text" id="collab-name-input" class="collab-input" placeholder="Your name" maxlength="30">
        <div class="collab-name-error" id="collab-name-error">${safeErrorMsg}</div>
        <div class="collab-name-actions">
          <button id="collab-name-random" class="collab-btn-secondary">Random</button>
          <button id="collab-name-submit" class="collab-btn-primary">${isChange ? 'Update' : 'Join'}</button>
        </div>
      </div>
    </div>`;
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
    const storedPwd = sessionStorage.getItem(`room-${ROOM_ID}-pwd`);
    if (storedPwd) {
      const res = await fetch(`/api/room/${ROOM_ID}/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: storedPwd })
      });
      if ((await res.json()).valid) return true;
    }
    return new Promise((resolve) => {
      const modal = document.createElement('div');
      modal.id = 'collab-password-modal';
      modal.className = 'collab-modal-overlay active';
      modal.innerHTML = `<div class="collab-modal">
        <div class="collab-modal-header"><h3>Password Required</h3></div>
        <div class="collab-modal-body">
          <input type="password" id="collab-pwd-input" class="collab-input" placeholder="Room password">
          <div class="collab-pwd-error" id="collab-pwd-error">Invalid password</div>
          <button id="collab-pwd-submit" class="collab-btn-primary" style="width:100%;margin-top:12px;">Enter</button>
        </div>
      </div>`;
      document.body.appendChild(modal);

      const input = document.getElementById('collab-pwd-input');
      const error = document.getElementById('collab-pwd-error');
      input.focus();

      async function tryPwd() {
        const res = await fetch(`/api/room/${ROOM_ID}/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: input.value })
        });
        if ((await res.json()).valid) {
          sessionStorage.setItem(`room-${ROOM_ID}-pwd`, input.value);
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

    doc.querySelectorAll('script[src*="collab.js"], link[href*="collab.css"]').forEach(el => el.remove());

    doc.querySelectorAll('script').forEach(script => {
      const text = script.textContent || '';
      if (text.includes('window.ROOM_ID') ||
          text.includes('window.__collabGetVar') ||
          text.includes('window.__collabSetVar') ||
          text.includes('origCreateObjectURL') ||
          text.includes('window.COLLAB_MODE') ||
          text.includes('isBlockedKey')) {
        script.remove();
      }
    });

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
