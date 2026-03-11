(function(){
  window.COLLAB_MODE = true;

  var origGetItem = localStorage.getItem.bind(localStorage);
  var origSetItem = localStorage.setItem.bind(localStorage);
  var origRemoveItem = localStorage.removeItem.bind(localStorage);
  var blockedKeys = ['topology', 'autosave', 'savedState', 'nodeData', 'edgeData', 'canvasState', 'lastState', 'PAGE_STATE', 'theonefile'];

  function isBlockedKey(key) {
    if (!key) return false;
    var lk = key.toLowerCase();
    for (var i = 0; i < blockedKeys.length; i++) {
      if (lk.indexOf(blockedKeys[i].toLowerCase()) !== -1) return true;
    }
    return false;
  }

  localStorage.getItem = function(key) {
    if (window.COLLAB_MODE && isBlockedKey(key)) {
      return null;
    }
    return origGetItem(key);
  };

  localStorage.setItem = function(key, value) {
    if (window.COLLAB_MODE && isBlockedKey(key)) {
      return;
    }
    return origSetItem(key, value);
  };

  localStorage.removeItem = function(key) {
    if (window.COLLAB_MODE && isBlockedKey(key)) return;
    return origRemoveItem(key);
  };

  var origOpen = indexedDB.open.bind(indexedDB);
  indexedDB.open = function(name) {
    if (window.COLLAB_MODE && name && name.toLowerCase().indexOf('theonefile') !== -1) {
      var fakeRequest = {
        result: null,
        error: null,
        onsuccess: null,
        onerror: null,
        onupgradeneeded: null,
        onblocked: null,
        readyState: 'done',
        transaction: null,
        source: null
      };
      setTimeout(function() {
        if (fakeRequest.onerror) fakeRequest.onerror(new Event('error'));
      }, 0);
      return fakeRequest;
    }
    return origOpen.apply(indexedDB, arguments);
  };

  window.__collabSuppressWelcome = true;
  new MutationObserver(function(mutations) {
    if (!window.__collabSuppressWelcome) return;
    for (var i = 0; i < mutations.length; i++) {
      var el = mutations[i].target;
      if (el.id === 'welcome-modal' && el.classList.contains('active')) {
        el.classList.remove('active');
      }
    }
  }).observe(document.documentElement, { subtree: true, attributes: true, attributeFilter: ['class'] });
})();

(function(){
  var checkInterval = setInterval(function(){
    if(typeof NODE_DATA !== 'undefined'){
      clearInterval(checkInterval);
      window.__collabGetVar = function(name) {
        try {
          switch(name) {
            case 'NODE_DATA': return NODE_DATA;
            case 'EDGE_DATA': return EDGE_DATA;
            case 'RECT_DATA': return RECT_DATA;
            case 'TEXT_DATA': return TEXT_DATA;
            case 'EDGE_LEGEND': return EDGE_LEGEND;
            case 'ZONE_LEGEND': return typeof ZONE_LEGEND !== 'undefined' ? ZONE_LEGEND : {};
            case 'ZONE_PRESETS': return typeof ZONE_PRESETS !== 'undefined' ? ZONE_PRESETS : {};
            case 'PAGE_STATE': return PAGE_STATE;
            case 'savedPositions': return savedPositions;
            case 'savedSizes': return savedSizes;
            case 'savedStyles': return savedStyles;
            case 'savedStyleSets': return typeof savedStyleSets !== 'undefined' ? savedStyleSets : {};
            case 'canvasState': return canvasState;
            case 'documentTabs': return documentTabs;
            case 'currentTabIndex': return currentTabIndex;
            case 'auditLog': return auditLog;
            case 'autoPingEnabled': return typeof autoPingEnabled !== 'undefined' ? autoPingEnabled : false;
            case 'autoPingInterval': return typeof autoPingInterval !== 'undefined' ? autoPingInterval : 5000;
            case 'savedTopologyView': return typeof savedTopologyView !== 'undefined' ? savedTopologyView : null;
            case 'encryptedSections': return typeof encryptedSections !== 'undefined' ? encryptedSections : {};
            case 'iconCache': return typeof IconLibrary !== 'undefined' ? IconLibrary.iconCache : {};
            case 'ANIM_SETTINGS': return typeof ANIM_SETTINGS !== 'undefined' ? ANIM_SETTINGS : null;
            case 'rollbackVersions': return typeof rollbackVersions !== 'undefined' ? rollbackVersions : [];
            case 'CUSTOM_LANG': return typeof CUSTOM_LANG !== 'undefined' ? CUSTOM_LANG : null;
            case 'IMAGE_DATA': return typeof IMAGE_DATA !== 'undefined' ? IMAGE_DATA : { list: [] };
            case 'checkNodeStatus': return typeof checkNodeStatus !== 'undefined' ? checkNodeStatus : undefined;
            case 'checkAllNodesStatus': return typeof checkAllNodesStatus !== 'undefined' ? checkAllNodesStatus : undefined;
            case 'updatePingIndicator': return typeof updatePingIndicator !== 'undefined' ? updatePingIndicator : undefined;
            case 'updatePingStatusDisplay': return typeof updatePingStatusDisplay !== 'undefined' ? updatePingStatusDisplay : undefined;
            case 'forgeTheTopology': return typeof forgeTheTopology !== 'undefined' ? forgeTheTopology : undefined;
            case 'currentNodeId': return typeof currentNodeId !== 'undefined' ? currentNodeId : undefined;
            case 'pushUndo': return typeof pushUndo !== 'undefined' ? pushUndo : undefined;
            default: return undefined;
          }
        } catch(e) { return undefined; }
      };
      window.__collabSetVar = function(name, value) {
        try {
          switch(name) {
            case 'NODE_DATA': NODE_DATA = value; return true;
            case 'EDGE_DATA': EDGE_DATA = value; return true;
            case 'RECT_DATA': RECT_DATA = value; return true;
            case 'TEXT_DATA': TEXT_DATA = value; return true;
            case 'EDGE_LEGEND': EDGE_LEGEND = value; return true;
            case 'ZONE_LEGEND': if(typeof ZONE_LEGEND !== 'undefined') ZONE_LEGEND = value; return true;
            case 'ZONE_PRESETS': if(typeof ZONE_PRESETS !== 'undefined') ZONE_PRESETS = value; return true;
            case 'savedPositions': savedPositions = value; return true;
            case 'savedSizes': savedSizes = value; return true;
            case 'savedStyles': savedStyles = value; return true;
            case 'savedStyleSets': if(typeof savedStyleSets !== 'undefined') savedStyleSets = value; return true;
            case 'auditLog': auditLog = value; return true;
            case 'documentTabs': documentTabs = value; return true;
            case 'currentTabIndex': currentTabIndex = value; return true;
            case 'autoPingEnabled': if(typeof autoPingEnabled !== 'undefined') autoPingEnabled = value; return true;
            case 'autoPingInterval': if(typeof autoPingInterval !== 'undefined') autoPingInterval = value; return true;
            case 'savedTopologyView': if(typeof savedTopologyView !== 'undefined') savedTopologyView = value; return true;
            case 'encryptedSections': if(typeof encryptedSections !== 'undefined') encryptedSections = value; return true;
            case 'iconCache': if(typeof IconLibrary !== 'undefined') IconLibrary.iconCache = value; return true;
            case 'ANIM_SETTINGS': if(typeof ANIM_SETTINGS !== 'undefined') { Object.assign(ANIM_SETTINGS, value); return true; } return false;
            case 'rollbackVersions': if(typeof rollbackVersions !== 'undefined') { rollbackVersions = value; return true; } return false;
            case 'CUSTOM_LANG': CUSTOM_LANG = value; if(typeof LANG !== 'undefined' && typeof DEFAULT_LANG !== 'undefined' && value) { LANG = deepMerge(DEFAULT_LANG, value); } return true;
            case 'PAGE_STATE': if(typeof PAGE_STATE !== 'undefined') { Object.assign(PAGE_STATE, value); return true; } return false;
            case 'IMAGE_DATA': if(typeof IMAGE_DATA !== 'undefined') { IMAGE_DATA = value; if(typeof renderCanvasImages === 'function') renderCanvasImages(); return true; } return false;
            default: return false;
          }
        } catch(e) { return false; }
      };
    }
  }, 50);
})();
