(function() {
  'use strict';
  
  if (!window.ROOM_ID) return;
  
  const ROOM_ID = window.ROOM_ID;
  const WS_URL = window.WS_URL;
  const HAS_PASSWORD = window.ROOM_HAS_PASSWORD;
  const IS_ADMIN = window.ROOM_IS_ADMIN || false;
  const IS_CREATOR = window.ROOM_IS_CREATOR || IS_ADMIN;
  
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

  function getRandomSyncQuote() {
    return HIGHLANDER_SYNC_QUOTES[Math.floor(Math.random() * HIGHLANDER_SYNC_QUOTES.length)];
  }

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
  }

  function hideSyncingOverlay() {
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
  
  function getOrCreateUserColor() {
    const storageKey = `collab-color-${ROOM_ID}`;
    let color = localStorage.getItem(storageKey);
    if (!color) {
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
  
  function connect() {
    if (ws && ws.readyState === WebSocket.OPEN) return;
    ws = new WebSocket(WS_URL);
    
    ws.onopen = () => {
      reconnectAttempts = 0;
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
    
    ws.onclose = () => { scheduleReconnect(); };
    ws.onerror = () => {};
  }
  
  function scheduleReconnect() {
    if (reconnectAttempts >= 10) return;
    const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
    reconnectAttempts++;
    setTimeout(connect, delay);
  }
  
  function sendMessage(type, data) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type, ...data }));
    }
  }
  
  function handleMessage(msg) {
    switch (msg.type) {
      case 'join':
        users.set(msg.user.id, msg.user);
        renderUsers();
        renderUserIndicators();
        break;
      case 'leave':
        users.delete(msg.userId);
        removeUserIndicators(msg.userId);
        removeRemoteCursor(msg.userId);
        renderUsers();
        break;
      case 'users':
        msg.users.forEach(u => {
          if (u.id !== window.COLLAB_USER.id) users.set(u.id, u);
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
      case 'cursor':
        if (msg.userId !== window.COLLAB_USER.id) {
          const user = users.get(msg.userId);
          if (user) {
            user.cursorX = msg.x;
            user.cursorY = msg.y;
            user.isRatio = msg.isRatio || false;
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

  function addChatMessage(msg) {
    chatMessages.push({
      userId: msg.userId,
      userName: msg.userName,
      userColor: msg.userColor,
      text: msg.text,
      timestamp: msg.timestamp || Date.now()
    });
    if (chatMessages.length > 100) chatMessages.shift();
    if (!chatOpen) {
      unreadCount++;
      updateChatBadge();
    }
    renderChatMessages();
  }

  function sendChatMessage(text) {
    if (!text.trim()) return;
    const msg = {
      userId: window.COLLAB_USER.id,
      userName: window.COLLAB_USER.name,
      userColor: window.COLLAB_USER.color,
      text: text.trim(),
      timestamp: Date.now()
    };
    sendMessage('chat', msg);
    addChatMessage(msg);
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

  function renderChatMessages() {
    const container = document.getElementById('collab-chat-messages');
    if (!container) return;
    container.innerHTML = chatMessages.map(msg => {
      const time = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      return `<div class="collab-chat-msg">
        <span class="collab-chat-name" style="color: ${msg.userColor}">${escapeHtml(msg.userName)}</span>
        <span class="collab-chat-time">${time}</span>
        <div class="collab-chat-text">${escapeHtml(msg.text)}</div>
      </div>`;
    }).join('');
    container.scrollTop = container.scrollHeight;
  }

  function updateRemoteCursor(userId, user) {
    let cursor = document.getElementById(`collab-cursor-${userId}`);
    if (!cursor && user.cursorX !== undefined) {
      cursor = document.createElement('div');
      cursor.id = `collab-cursor-${userId}`;
      cursor.className = 'collab-remote-cursor';
      cursor.innerHTML = `<svg width="16" height="16" viewBox="0 0 16 16"><path d="M0 0L16 12L8 12L4 16L0 0Z" fill="${user.color}"/></svg><span class="collab-cursor-name" style="background:${user.color}">${escapeHtml(user.name)}</span>`;
      document.body.appendChild(cursor);
    }
    if (cursor && user.cursorX !== undefined) {
      let screenX = user.cursorX;
      let screenY = user.cursorY;
      if (user.isRatio) {
        const viewport = document.getElementById('canvas-viewport');
        if (viewport) {
          const rect = viewport.getBoundingClientRect();
          screenX = rect.left + user.cursorX * rect.width;
          screenY = rect.top + user.cursorY * rect.height;
        }
      }
      cursor.style.left = screenX + 'px';
      cursor.style.top = screenY + 'px';
    }
  }

  function removeRemoteCursor(userId) {
    const cursor = document.getElementById(`collab-cursor-${userId}`);
    if (cursor) cursor.remove();
  }

  function trackCursor() {
    let lastSent = 0;
    document.addEventListener('mousemove', (e) => {
      const now = Date.now();
      if (now - lastSent < 50) return;
      lastSent = now;
      const viewport = document.getElementById('canvas-viewport');
      if (viewport) {
        const rect = viewport.getBoundingClientRect();
        const ratioX = (e.clientX - rect.left) / rect.width;
        const ratioY = (e.clientY - rect.top) / rect.height;
        sendMessage('cursor', {
          userId: window.COLLAB_USER.id,
          x: ratioX,
          y: ratioY,
          isRatio: true
        });
      } else {
        sendMessage('cursor', {
          userId: window.COLLAB_USER.id,
          x: e.clientX,
          y: e.clientY
        });
      }
    });
  }
  
  function getGlobal(name) {
    if (typeof window.__collabGetVar === 'function') return window.__collabGetVar(name);
    try { return (0, eval)(name); } catch { return undefined; }
  }
  
  function setGlobal(name, value) {
    if (typeof window.__collabSetVar === 'function') return window.__collabSetVar(name, value);
    try { (0, eval)(`${name} = ${JSON.stringify(value)}`); return true; } catch { return false; }
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
  
  function hashState(state) { return JSON.stringify(state); }
  
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
      }

      if (state.iconCache) setGlobal('iconCache', state.iconCache);
      if (state.auditLog) setGlobal('auditLog', state.auditLog);

      if (state.savedStyleSets !== undefined) setGlobal('savedStyleSets', state.savedStyleSets);
      if (state.animSettings !== undefined) setGlobal('ANIM_SETTINGS', state.animSettings);
      if (state.autoPingEnabled !== undefined) setGlobal('autoPingEnabled', state.autoPingEnabled);
      if (state.autoPingInterval !== undefined) setGlobal('autoPingInterval', state.autoPingInterval);
      if (state.savedTopologyView !== undefined) setGlobal('savedTopologyView', state.savedTopologyView);
      if (state.encryptedSections !== undefined) setGlobal('encryptedSections', state.encryptedSections);

      if (state.rollbackVersions !== undefined) setGlobal('rollbackVersions', state.rollbackVersions);
      if (state.customLang !== undefined) setGlobal('CUSTOM_LANG', state.customLang);

      if (state.page) {
        setGlobal('PAGE_STATE', state.page);
        if (typeof wieldThePower === 'function') wieldThePower();
      }

      if (typeof forgeTheTopology === 'function') forgeTheTopology();
      if (typeof forgeTheLegend === 'function') forgeTheLegend();
      if (typeof updateZoneLegend === 'function') updateZoneLegend();
      if (typeof updateViewBox === 'function') updateViewBox();
      if (typeof displayTabs === 'function') displayTabs();
      if (typeof applyAnimZoneSettings === 'function') applyAnimZoneSettings();
      if (typeof rebuildThemeDropdown === 'function') rebuildThemeDropdown();

      lastStateHash = hashState(state);
    } catch (e) { console.error('applyRemoteState error:', e); } finally { syncPaused = false; }
  }
  
  function startStatePolling() {
    setInterval(() => {
      if (syncPaused || !hasReceivedInitialState) return;
      const state = captureState();
      if (!state) return;
      const hash = hashState(state);
      if (hash !== lastStateHash) {
        lastStateHash = hash;
        sendMessage('state', { state });
      }
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
    
    const originalAddAuditEntry = window.addAuditEntry;
    if (typeof addAuditEntry === 'function') {
      window.__collabOriginalAddAudit = addAuditEntry;
      const newFn = function(type, description, details) {
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
      eval('addAuditEntry = ' + newFn.toString());
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
      return `<div class="collab-user ${isMe ? 'me' : ''}" data-user-id="${user.id}">
        <span class="collab-user-dot" style="background: ${user.color}"></span>
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
  
  function injectCollabBar() {
    document.body.classList.add('collab-active');

    const bar = document.createElement('div');
    bar.id = 'collab-bar';
    bar.innerHTML = `<div class="collab-users"></div>
      <div class="collab-actions">
        <button class="collab-btn" id="collab-chat-btn"><span class="collab-btn-icon">&#9993;</span><span>Chat</span><span class="collab-chat-badge" id="collab-chat-badge"></span></button>
        <button class="collab-btn" id="collab-share-btn"><span class="collab-btn-icon">+</span><span>Share</span></button>
        <button class="collab-btn" id="collab-menu-btn"><span class="collab-btn-icon">=</span></button>
      </div>`;
    document.body.prepend(bar);

    const chatPanel = document.createElement('div');
    chatPanel.id = 'collab-chat-panel';
    chatPanel.innerHTML = `
      <div class="collab-chat-header">
        <span>Chat</span>
        <button class="collab-chat-close" id="collab-chat-close">&times;</button>
      </div>
      <div class="collab-chat-messages" id="collab-chat-messages"></div>
      <div class="collab-chat-input-wrap">
        <input type="text" id="collab-chat-input" placeholder="Type a message..." maxlength="500">
        <button id="collab-chat-send">Send</button>
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
    let menuHtml = `<button class="collab-menu-item" id="collab-menu-copy">Copy Link</button>
      <button class="collab-menu-item" id="collab-menu-info">Room Info</button>
      <button class="collab-menu-item" id="collab-menu-name">Change Name</button>
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
    });

    document.getElementById('collab-chat-send').addEventListener('click', () => {
      const input = document.getElementById('collab-chat-input');
      sendChatMessage(input.value);
      input.value = '';
    });

    document.getElementById('collab-chat-input').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        sendChatMessage(e.target.value);
        e.target.value = '';
      }
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
    document.addEventListener('click', () => menuDropdown.classList.remove('active'));
    
    document.getElementById('collab-menu-copy').addEventListener('click', () => {
      navigator.clipboard.writeText(window.location.href);
    });
    
    document.getElementById('collab-menu-info').addEventListener('click', async () => {
      try {
        const res = await fetch(`/api/room/${ROOM_ID}/exists`);
        const data = await res.json();
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
          <div class="collab-info-row"><span class="collab-info-label">Room ID</span><span class="collab-info-value collab-info-id">${ROOM_ID}</span></div>
          <div class="collab-info-row"><span class="collab-info-label">Created</span><span class="collab-info-value">${new Date(data.created).toLocaleString()}</span></div>
          <div class="collab-info-row"><span class="collab-info-label">Self-Destruct</span><span class="collab-info-value">${destructText}</span></div>
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
    
    renderUsers();
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
    modal.innerHTML = `<div class="collab-modal">
      <div class="collab-modal-header">
        <h3>${isChange ? 'Change Name' : 'Enter Your Name'}</h3>
        ${isChange ? '<button class="collab-modal-close">&times;</button>' : ''}
      </div>
      <div class="collab-modal-body">
        <input type="text" id="collab-name-input" class="collab-input" placeholder="Your name" maxlength="30">
        <div class="collab-name-error" id="collab-name-error">${errorMsg || ''}</div>
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

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
