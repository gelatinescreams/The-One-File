import * as THREE from '/vendor/three/three.module.min.js';

(function () {
  'use strict';
  if (!document.getElementById('room-config')) return;

  const WORLD_W = 4000, WORLD_D = 3000, PAD = 100;
  const RACK_WIDTH_3D = 320, RACK_DEPTH_3D = 220, RACK_PER_U = 40;
  const WALL_HEIGHT_3D = 150, WALL_THICK_3D = 14;

  const LIGHT = {
    hemi: 0.55,
    ambient: 0.14,
    sun: 0.78,
    env: 0.35,
    exposure: 1.0,
    bloomStrength: 0.28,
    bloomRadius: 0.35,
    bloomThreshold: 1.02,
  };
  function applyLook() {
    try {
      if (renderer) renderer.toneMappingExposure = LIGHT.exposure;
      if (scene) scene.environmentIntensity = LIGHT.env;
      if (bloomPass) { bloomPass.strength = LIGHT.bloomStrength; bloomPass.radius = LIGHT.bloomRadius; bloomPass.threshold = LIGHT.bloomThreshold; }
    } catch (e) {}
  }
  const TEXT_WORLD_SCALE = 2.2;
  const FURN_KINDS = new Set(['table', 'shelf', 'lamp', 'wall', 'plant', 'frame', 'model']);
  const HEX64_RE = /^[0-9a-f]{64}$/;
  const MAX_FURNITURE = 2000;
  const MAX_ELEVATION = 3000;
  const MIN_WALL_HEIGHT = 4, MAX_WALL_HEIGHT = 3000;
  const TWO_PI = Math.PI * 2;
  const wrapAngle = (v) => { const n = Number(v); if (!Number.isFinite(n)) return 0; const m = n % TWO_PI; return m < 0 ? m + TWO_PI : m; };

  function getVar(n) { try { return typeof window.__collabGetVar === 'function' ? window.__collabGetVar(n) : undefined; } catch (e) { return undefined; } }
  function setVar(n, v) { try { if (typeof window.__collabSetVar === 'function') window.__collabSetVar(n, v); } catch (e) {} }
  const sx = (x) => x - WORLD_W / 2, sz = (y) => y - WORLD_D / 2;
  const wx = (X) => X + WORLD_W / 2, wy = (Z) => Z + WORLD_D / 2;
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const num = (v, fb) => { const n = Number(v); return Number.isFinite(n) ? n : fb; };
  const rad = (d) => (Number(d) || 0) * Math.PI / 180;
  const isTrue = (v) => v === true || v === 'true';
  let ROOM_ID = null, ENABLE_3D = true;
  try {
    const _rc = JSON.parse(document.getElementById('room-config').textContent) || {};
    ROOM_ID = _rc.roomId || null;
    ENABLE_3D = _rc.enable3d !== false;
  } catch (e) {}
  if (!ENABLE_3D) return;

  const MAX_CANVAS_IMAGES = 40;
  const MAX_IMAGE_SIZE = 250;
  const IMG_BORDER_PX = { thin: 1, medium: 2, thick: 4 };
  const IMG_SHADOW_PX = { small: 4, medium: 8, large: 16 };

  function isViewOnly() { const ps = getVar('PAGE_STATE'); return !!(ps && ps.viewOnly === true); }
  function isLocked(kind, id) {
    if (id == null) return false;
    if (kind === 'furniture' || kind === 'edge') return false;
    if (kind === 'rect' || kind === 'text' || kind === 'image') {
      const d = getVar(kind === 'rect' ? 'RECT_DATA' : kind === 'text' ? 'TEXT_DATA' : 'IMAGE_DATA');
      const it = d && Array.isArray(d.list) && d.list.find((x) => x && x.id === id);
      return !!(it && it.locked);
    }
    const nd = getVar('NODE_DATA'); return !!(nd && nd[id] && nd[id].locked);
  }
  let _guardToastTimer = null, lastGuard = null;
  function guardToast(msg) {
    if (!overlay) return;
    let e = document.getElementById('threed-guard-toast');
    if (!e) {
      e = document.createElement('div');
      e.id = 'threed-guard-toast';
      e.setAttribute('role', 'status');
      e.setAttribute('aria-live', 'polite');
      e.setAttribute('aria-atomic', 'true');
      e.style.cssText = 'position:absolute;left:50%;top:60px;transform:translateX(-50%);z-index:7;max-width:60%;text-align:center;background:rgba(120,53,15,.95);color:#fde68a;font:12px/1.4 system-ui,sans-serif;padding:8px 14px;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,.5);pointer-events:none';
      overlay.appendChild(e);
    }
    e.textContent = msg; e.style.display = 'block';
    if (_guardToastTimer) clearTimeout(_guardToastTimer);
    _guardToastTimer = setTimeout(function () { e.style.display = 'none'; }, 2400);
  }
  function editBlocked(kind, id) {
    if (isViewOnly()) { lastGuard = { reason: 'viewOnly', kind: kind || null, id: id == null ? null : id, at: Date.now() }; guardToast('👁 View Only is on, editing is disabled. Turn it off in the 2D settings panel.'); return true; }
    if (isLocked(kind, id)) { lastGuard = { reason: 'locked', kind: kind || null, id: id, at: Date.now() }; guardToast('🔒 This ' + (kind === 'rect' ? 'shape' : (kind || 'object')) + ' is locked. Unlock it in 2D to move, edit or delete it.'); return true; }
    return false;
  }

  let overlay, canvas, statEl, inspectEl, modeBtn;
  let renderer, scene, camera, rafId = null, active = false, frame = 0, lastFrameAt = 0;

  function mkBtn(txt, bg, fg, on, label) {
    const el = document.createElement('button');
    el.type = 'button'; el.textContent = txt;
    el.style.cssText = 'padding:8px 12px;background:' + bg + ';color:' + fg + ';border:none;border-radius:8px;font:600 13px system-ui,sans-serif;cursor:pointer'
      + (COARSE_POINTER ? ';min-height:44px;min-width:44px;padding:10px 14px' : '');
    if (label) el.setAttribute('aria-label', label);
    el.addEventListener('click', on); return el;
  }
  function setPressed(el, on) { if (el) el.setAttribute('aria-pressed', on ? 'true' : 'false'); }
  let srEl = null;
  const SR_ONLY = 'position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0 0 0 0);clip-path:inset(50%);white-space:nowrap;border:0';
  let srTimer = null, srPending = null, srLastAt = 0;
  const SR_COALESCE_MS = 250;
  function srWrite(msg) {
    if (!srEl) return;
    if (srEl.textContent === msg) srEl.textContent = '';
    srEl.textContent = msg;
  }
  function announce(msg) {
    if (!srEl || !msg) return;
    const text = String(msg);
    let now = 0; try { now = performance.now(); } catch (e) { now = Date.now(); }
    if (now - srLastAt >= SR_COALESCE_MS && !srTimer) { srLastAt = now; srWrite(text); return; }
    srPending = text;
    if (srTimer) return;
    srTimer = setTimeout(function () {
      srTimer = null;
      const t = srPending; srPending = null;
      if (t == null) return;
      try { srLastAt = performance.now(); } catch (e) { srLastAt = Date.now(); }
      srWrite(t);
    }, Math.max(0, SR_COALESCE_MS - (now - srLastAt)));
  }
  function cancelAnnounce() { if (srTimer) { clearTimeout(srTimer); srTimer = null; } srPending = null; srLastAt = 0; }
  function makeButton() {
    const b = mkBtn('⛶ Enter 3D', '#4fd1c5', '#06201d', enter3D);
    b.id = 'enter-3d-btn';
    b.style.cssText += ';position:fixed;right:16px;bottom:16px;z-index:99990;box-shadow:0 4px 16px rgba(0,0,0,.4);padding:10px 14px;font-size:14px';
    document.body.appendChild(b);
  }
  function makeOverlay() {
    overlay = document.createElement('div');
    overlay.id = 'threed-overlay';
    overlay.style.cssText = 'position:fixed;inset:0;z-index:100000;display:none;background:#0b0f14';
    overlay.setAttribute('role', 'region');
    overlay.setAttribute('aria-label', '3D view');
    const a11yStyle = document.createElement('style');
    a11yStyle.textContent =
      '#threed-overlay :focus-visible{outline:3px solid #38bdf8;outline-offset:2px}' +
      '#threed-overlay canvas:focus-visible{outline:3px solid #38bdf8;outline-offset:-3px}' +
      '#threed-overlay canvas{touch-action:none}' +
      (COARSE_POINTER ? '#threed-overlay button,#threed-overlay [role="button"]{min-height:44px;min-width:44px}' : '') +
      '@media (prefers-reduced-motion: reduce){#threed-overlay *{animation:none!important;transition:none!important}}';
    overlay.appendChild(a11yStyle);
    canvas = document.createElement('canvas');
    canvas.style.cssText = 'display:block;width:100%;height:100%';
    canvas.tabIndex = 0;
    canvas.setAttribute('role', 'application');
    canvas.setAttribute('aria-label', '3D topology view. Arrow keys orbit, plus and minus zoom, Tab cycles selection, Enter opens the editor for the selection.');
    overlay.appendChild(canvas);

    srEl = document.createElement('div');
    srEl.id = 'threed-sr';
    srEl.setAttribute('aria-live', 'polite');
    srEl.setAttribute('aria-atomic', 'true');
    srEl.style.cssText = SR_ONLY;
    overlay.appendChild(srEl);

    const bar = document.createElement('div');
    bar.style.cssText = 'position:absolute;top:14px;right:14px;z-index:2;display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;max-width:70vw';
    bar.setAttribute('role', 'toolbar');
    bar.setAttribute('aria-label', '3D view controls');
    modeBtn = mkBtn('🚶 Walk', '#334155', '#e2e8f0', toggleMode, 'Switch to walk mode');
    if (!COARSE_POINTER) bar.appendChild(modeBtn);
    moveBtn = mkBtn('🔒 Move: off', '#334155', '#e2e8f0', toggleMove, 'Move mode: drag to reposition objects');
    bar.appendChild(moveBtn);
    scaleBtn = mkBtn('📐 Scale: off', '#334155', '#e2e8f0', cycleScale, 'Real world scale preset');
    bar.appendChild(scaleBtn);
    wireBtn = mkBtn('🔌 Wires: elevated', '#334155', '#e2e8f0', cycleWire, 'Wire routing mode');
    bar.appendChild(wireBtn);
    fxBtn = mkBtn('✨ FX: on', '#334155', '#e2e8f0', toggleFx, 'Visual effects and motion');
    bar.appendChild(fxBtn);
    rmBtn = mkBtn('♿ Motion: auto', '#334155', '#e2e8f0', cycleReduceMotion, 'Reduced motion');
    bar.appendChild(rmBtn);
    freeLookBtn = mkBtn('👁 Free look: off', '#334155', '#e2e8f0', toggleFreeLook, 'Free look without pointer lock');
    if (!COARSE_POINTER) bar.appendChild(freeLookBtn);
    devBtn = mkBtn('🖥 Device models: on', '#334155', '#e2e8f0', toggleDevModels, 'Device models');
    bar.appendChild(devBtn);
    ico3dBtn = mkBtn('🔷 3D icons: on', '#334155', '#e2e8f0', toggleIcon3d, '3D extruded icons');
    bar.appendChild(ico3dBtn);
    refreshDevBtn(); refreshIcon3dBtn(); refreshRmBtn(); refreshFreeLookBtn();
    hudBtn = mkBtn('🗂 Legend', '#334155', '#e2e8f0', toggleHud, 'Legend and layer visibility');
    bar.appendChild(hudBtn);
    recBtn = mkBtn('🎬 Rec', '#334155', '#e2e8f0', toggleRecPanel, 'Recording transport');
    bar.appendChild(recBtn);
    xrBtn = mkBtn('🥽 VR', '#334155', '#e2e8f0', toggleVR, 'Enter virtual reality');
    xrBtn.style.display = 'none';
    bar.appendChild(xrBtn);
    bar.appendChild(mkBtn('↻ Refresh', '#1f2937', '#e2e8f0', () => { if (active) { buildScene(); fitCamera(true); } }, 'Rebuild the scene and refit the camera'));
    bar.appendChild(mkBtn(COARSE_POINTER ? '✏ Edit in 2D' : '✕ Return to 2D', '#f56565', '#fff', exit3D, COARSE_POINTER ? 'Leave 3D and edit in the 2D view' : 'Return to the 2D view'));
    overlay.appendChild(bar);

    const hint = document.createElement('div');
    hint.style.cssText = 'position:absolute;left:14px;bottom:14px;z-index:2;color:#9fb0c0;font:12px/1.5 system-ui,sans-serif;background:rgba(0,0,0,.45);padding:8px 12px;border-radius:8px;pointer-events:none';
    hint.setAttribute('role', 'note');
    hint.innerHTML = COARSE_POINTER
      ? '<b>Touch:</b> one finger drag = orbit · two fingers pinch = zoom · two fingers drag = pan · <b>tap = select</b> · <b>press &amp; hold = open the editor</b><br>' +
        '<b>Read only by default:</b> nothing moves unless you turn <b>✋ Move</b> on. Edit through the 📖 book forms, or use <b>✏ Edit in 2D</b>.<br>' +
        '<b>Keyboard:</b> arrows orbit · + / − zoom · Tab cycles the selection · Enter opens its editor · Delete removes it'
      : '<b>Mouse:</b> <b>Left click = select</b> (opens Edit ✏ / Delete 🗑) · <b>Right click = place</b> the held item · drag = orbit<br>' +
      '<b>Moving things:</b> dragging only moves an object while <b>✋ Move</b> is ON (button or <b>M</b>), off by default so nothing shifts by accident · <b>drop a node on a rack to mount it</b><br>' +
      '<b>Walk</b> (Minecraft bindings): <b>W A S D</b> move · <b>Space</b> jump · <b>double tap Space</b> fly · <b>Ctrl</b> sprint · <b>Shift</b> sneak / descend while flying · mouse look · wheel cycles hotbar · Esc<br>' +
      '<b>Items:</b> <b>1 to 9</b> hotbar slot · <b>E</b> inventory · <b>Q</b> put away · <b>L</b> legend &amp; layers · <b>R</b> recording · ✨ FX toggles motion<br>' +
      '<b>Build:</b> Node · Rack · Wall · Zone · Text · Image · Furniture, placed pieces sync to everyone<br>' +
      '<b>Orbit:</b> drag rotate · scroll zoom · <b>double click to focus</b> · <b>W A S D</b> pan · <b>Space/Shift</b> raise/lower<br>' +
      '<b>Keyboard only:</b> <b>arrows</b> orbit · <b>+ / −</b> zoom · <b>Tab</b> cycles the selection · <b>Enter</b> opens its editor · <b>♿ Motion</b> and <b>👁 Free look</b> are in the toolbar';
    overlay.appendChild(hint);

    statEl = document.createElement('div');
    statEl.id = 'threed-stat';
    statEl.style.cssText = 'position:absolute;left:14px;top:14px;z-index:2;color:#7dd3c8;font:12px/1.4 system-ui,sans-serif;background:rgba(0,0,0,.4);padding:6px 10px;border-radius:8px;pointer-events:none';
    statEl.setAttribute('role', 'status');
    statEl.setAttribute('aria-live', 'polite');
    statEl.setAttribute('aria-atomic', 'true');
    overlay.appendChild(statEl);

    inspectEl = document.createElement('div');
    inspectEl.style.cssText = 'position:absolute;right:14px;bottom:14px;z-index:2;min-width:200px;max-width:300px;display:none;color:#e2e8f0;font:12px/1.5 system-ui,sans-serif;background:rgba(15,23,42,.92);border:1px solid #334155;border-radius:10px;padding:12px 14px';
    inspectEl.setAttribute('role', 'region');
    inspectEl.setAttribute('aria-label', 'Selection details');
    overlay.appendChild(inspectEl);

    const invBtn = mkBtn('🎒 Inventory (I)', '#1f2937', '#e2e8f0', toggleInventory, 'Inventory: choose what the hotbar places');
    invBtn.style.cssText += ';position:absolute;left:50%;transform:translateX(-50%);bottom:78px;z-index:3;padding:4px 12px;font-size:11px';
    if (COARSE_POINTER) invBtn.style.display = 'none';
    overlay.appendChild(invBtn);

    hotbarEl = document.createElement('div');
    hotbarEl.style.cssText = 'position:absolute;left:50%;transform:translateX(-50%);bottom:18px;z-index:3;display:flex;gap:4px;background:rgba(15,23,42,.85);padding:6px;border-radius:12px';
    hotbarEl.setAttribute('role', 'toolbar');
    hotbarEl.setAttribute('aria-label', 'Hotbar: the item placed by a right click');
    if (COARSE_POINTER) hotbarEl.style.display = 'none';
    slotEls = [];
    for (let i = 0; i < HOTBAR_SLOTS; i++) {
      const s = document.createElement('button');
      s.type = 'button';
      s.style.cssText = 'position:relative;width:50px;height:50px;border-radius:8px;background:#0f172a;border:2px solid #334155;display:flex;align-items:center;justify-content:center;font-size:26px;cursor:pointer;user-select:none;padding:0;color:inherit'
        + (COARSE_POINTER ? ';min-width:50px;min-height:50px' : '');
      const numTag = document.createElement('span');
      numTag.style.cssText = 'position:absolute;top:1px;left:5px;font-size:10px;color:#64748b';
      numTag.textContent = (i + 1);
      s.appendChild(numTag);
      const iconSpan = document.createElement('span'); iconSpan.className = 'hb-icon'; s.appendChild(iconSpan);
      s.addEventListener('click', ((idx) => () => selectHotbar(idx))(i));
      hotbarEl.appendChild(s); slotEls.push(s);
    }
    overlay.appendChild(hotbarEl);
    renderHotbar();

    document.body.appendChild(overlay);
  }

  let mode = 'orbit';
  const target = new THREE.Vector3(0, 60, 0);
  let radius = 2600, theta = Math.PI * 0.25, phi = Math.PI * 0.34;
  const EYE_HEIGHT = 120;
  const WALK_SPEED = 320;
  const RUN_MULT = 2.6;
  const SNEAK_MULT = 0.35;
  const FLY_SPEED = 260;
  const ORBIT_PAN_FACTOR = 0.55;
  const GRAVITY = 900;
  const JUMP_SPEED = 380;
  const DOUBLE_TAP_MS = 320;
  const walkPos = new THREE.Vector3(0, EYE_HEIGHT, 1400);
  let walkYaw = Math.PI, walkPitch = -0.1;
  let walkFly = 0;
  let walkVelY = 0;
  let walkFlying = false;
  let lastSpaceAt = 0;
  const keys = Object.create(null);

  function updateCameraOrbit() {
    const sp = Math.sin(phi);
    camera.position.set(target.x + radius * sp * Math.sin(theta), target.y + radius * Math.cos(phi), target.z + radius * sp * Math.cos(theta));
    camera.lookAt(target);
  }
  function updateCameraWalk() {
    const cp = Math.cos(walkPitch);
    const dx = Math.sin(walkYaw) * cp, dy = Math.sin(walkPitch), dz = Math.cos(walkYaw) * cp;
    camera.position.copy(walkPos);
    camera.lookAt(walkPos.x + dx, walkPos.y + dy, walkPos.z + dz);
  }
  function applyKeys(dt) {
    if (keys['w'] || keys['a'] || keys['s'] || keys['d'] || keys[' '] || keys['shift']) camGoal = null;
    if (mode === 'walk') {
      const s = WALK_SPEED * dt * (keys['ctrl'] ? RUN_MULT : (keys['shift'] && !walkFlying ? SNEAK_MULT : 1));
      const fX = Math.sin(walkYaw), fZ = Math.cos(walkYaw), rX = -Math.cos(walkYaw), rZ = Math.sin(walkYaw);
      if (keys['w']) { walkPos.x += fX * s; walkPos.z += fZ * s; }
      if (keys['s']) { walkPos.x -= fX * s; walkPos.z -= fZ * s; }
      if (keys['a']) { walkPos.x -= rX * s; walkPos.z -= rZ * s; }
      if (keys['d']) { walkPos.x += rX * s; walkPos.z += rZ * s; }
      if (padMove.fwd || padMove.rgt) { walkPos.x += (padMove.fwd * fX + padMove.rgt * rX) * s; walkPos.z += (padMove.fwd * fZ + padMove.rgt * rZ) * s; }
      const f = FLY_SPEED * dt;
      if (walkFlying) {
        if (keys[' ']) walkFly = clamp(walkFly + f, 0, 2880);
        if (keys['shift']) walkFly = clamp(walkFly - f, 0, 2880);
        if (padMove.up) walkFly = clamp(walkFly + padMove.up * f, 0, 2880);
        walkVelY = 0;
      } else {
        if (padMove.up > 0.5 && walkFly <= 0 && walkVelY <= 0) walkVelY = JUMP_SPEED;
        walkVelY -= GRAVITY * dt;
        walkFly += walkVelY * dt;
        if (walkFly <= 0) { walkFly = 0; walkVelY = 0; }
      }
      walkPos.y = EYE_HEIGHT + walkFly;
    } else {
      const s = radius * ORBIT_PAN_FACTOR * dt * (keys['ctrl'] ? RUN_MULT : 1);
      const fX = Math.sin(theta), fZ = Math.cos(theta), rX = Math.cos(theta), rZ = -Math.sin(theta);
      if (keys['w']) { target.x -= fX * s; target.z -= fZ * s; }
      if (keys['s']) { target.x += fX * s; target.z += fZ * s; }
      if (keys['a']) { target.x -= rX * s; target.z -= rZ * s; }
      if (keys['d']) { target.x += rX * s; target.z += rZ * s; }
      if (keys[' ']) target.y = clamp(target.y + s, -400, 4000);
      if (keys['shift']) target.y = clamp(target.y - s, -400, 4000);
    }
  }
  function toggleMode() { setMode(mode === 'orbit' ? 'walk' : 'orbit'); }
  function setMode(m) {
    if (m === 'walk' && COARSE_POINTER) { guardToast('🚶 Walk mode needs a keyboard and mouse. This device stays in orbit view.'); return; }
    mode = m;
    if (m === 'walk') {
      walkFly = 0; walkVelY = 0;
      walkPos.set(camera.position.x, EYE_HEIGHT, camera.position.z);
      walkYaw = theta + Math.PI; walkPitch = -0.15;
      modeBtn.textContent = '🧭 Orbit';
      modeBtn.setAttribute('aria-label', 'Switch to orbit mode');
      if (!freeLook) { try { canvas.requestPointerLock(); } catch (e) {} }
      announce(freeLook ? 'Walk mode. Drag to look around; W A S D to move.' : 'Walk mode. Mouse look captured; press Escape to release.');
    } else {
      modeBtn.textContent = '🚶 Walk';
      modeBtn.setAttribute('aria-label', 'Switch to walk mode');
      if (document.pointerLockElement === canvas) document.exitPointerLock();
      announce('Orbit mode.');
    }
  }

  '@collab-3d-select-helpers:start';
  const SEL_KEY_SEP = String.fromCharCode(0);
  function selKeyOf(kind, id) { return String(kind) + SEL_KEY_SEP + String(id); }
  function selIndexOf(list, kind, id) {
    const k = selKeyOf(kind, id);
    for (let i = 0; i < list.length; i++) if (list[i] && selKeyOf(list[i].kind, list[i].id) === k) return i;
    return -1;
  }
  function selToggle(list, kind, id) {
    const i = selIndexOf(list, kind, id);
    if (i < 0) return list.concat([{ kind: kind, id: id }]);
    const out = list.slice(); out.splice(i, 1); return out;
  }
  function selUnion(list, add) {
    let out = list.slice();
    for (let i = 0; i < add.length; i++) { const a = add[i]; if (a && selIndexOf(out, a.kind, a.id) < 0) out = out.concat([{ kind: a.kind, id: a.id }]); }
    return out;
  }
  function selCounts(list) {
    const out = {};
    for (let i = 0; i < list.length; i++) { const it = list[i]; if (!it) continue; out[it.kind] = (out[it.kind] || 0) + 1; }
    return out;
  }
  const SEL_KIND_ORDER = ['node', 'furniture', 'rect', 'text', 'image', 'edge'];
  const SEL_KIND_LABEL = { node: ['node', 'nodes'], furniture: ['furniture item', 'furniture items'], rect: ['shape', 'shapes'], text: ['text', 'texts'], image: ['image', 'images'], edge: ['connection', 'connections'] };
  function selSummary(list) {
    const c = selCounts(list), parts = [];
    for (let i = 0; i < SEL_KIND_ORDER.length; i++) {
      const k = SEL_KIND_ORDER[i]; if (!c[k]) continue;
      const lab = SEL_KIND_LABEL[k]; parts.push(c[k] + ' ' + (c[k] === 1 ? lab[0] : lab[1]));
    }
    for (const k in c) if (SEL_KIND_ORDER.indexOf(k) < 0) parts.push(c[k] + ' ' + k);
    return { n: list.length, counts: c, text: list.length + ' selected', detail: parts.join(', ') };
  }
  function marqueeRect(a, b) {
    return { x0: Math.min(a.x, b.x), x1: Math.max(a.x, b.x), z0: Math.min(a.z, b.z), z1: Math.max(a.z, b.z) };
  }
  function marqueeArea(r) { return Math.abs(r.x1 - r.x0) * Math.abs(r.z1 - r.z0); }
  function marqueeHits(rect, items) {
    const out = [];
    for (let i = 0; i < items.length; i++) {
      const it = items[i]; if (!it) continue;
      const x = Number(it.x), z = Number(it.z);
      if (!Number.isFinite(x) || !Number.isFinite(z)) continue;
      if (x >= rect.x0 && x <= rect.x1 && z >= rect.z0 && z <= rect.z1) out.push({ kind: it.kind, id: it.id });
    }
    return out;
  }
  function groupDelta(from, to) { return { dx: Number(to.x) - Number(from.x), dz: Number(to.z) - Number(from.z) }; }
  function clampGroupDelta(d, items, loX, hiX, loZ, hiZ) {
    let dx = Number(d.dx) || 0, dz = Number(d.dz) || 0;
    let minX = Infinity, maxX = -Infinity, minZ = Infinity, maxZ = -Infinity;
    for (let i = 0; i < items.length; i++) {
      const it = items[i]; if (!it) continue;
      const x = Number(it.x), z = Number(it.z);
      if (!Number.isFinite(x) || !Number.isFinite(z)) continue;
      if (x < minX) minX = x; if (x > maxX) maxX = x;
      if (z < minZ) minZ = z; if (z > maxZ) maxZ = z;
    }
    if (minX === Infinity) return { dx: 0, dz: 0 };
    if (dx < 0) dx = Math.min(0, Math.max(dx, loX - minX));
    else if (dx > 0) dx = Math.max(0, Math.min(dx, hiX - maxX));
    if (dz < 0) dz = Math.min(0, Math.max(dz, loZ - minZ));
    else if (dz > 0) dz = Math.max(0, Math.min(dz, hiZ - maxZ));
    return { dx: dx, dz: dz };
  }
  '@collab-3d-select-helpers:end';

  '@collab-3d-a11y-helpers:start';

  const TOUCH_SLOP = 10;
  const PINCH_SLOP = 12;
  const PAN_SLOP = 10;
  const LONG_PRESS_MS = 550;
  function touchDist(a, b) { const dx = Number(b.x) - Number(a.x), dy = Number(b.y) - Number(a.y); return Math.sqrt(dx * dx + dy * dy); }
  function touchCentroid(pts) {
    let x = 0, y = 0, n = 0;
    for (let i = 0; i < pts.length; i++) { const p = pts[i]; if (!p) continue; const px = Number(p.x), py = Number(p.y); if (!Number.isFinite(px) || !Number.isFinite(py)) continue; x += px; y += py; n++; }
    return n ? { x: x / n, y: y / n } : { x: 0, y: 0 };
  }
  function classifyGesture(start, now, opts) {
    const o = opts || {};
    const slop = o.slop === undefined ? TOUCH_SLOP : o.slop;
    const pinchSlop = o.pinchSlop === undefined ? PINCH_SLOP : o.pinchSlop;
    const panSlop = o.panSlop === undefined ? PAN_SLOP : o.panSlop;
    if (!Array.isArray(start) || !Array.isArray(now) || start.length !== now.length) return 'none';
    if (now.length === 1) return touchDist(start[0], now[0]) > slop ? 'orbit' : 'none';
    if (now.length !== 2) return 'none';
    const d0 = touchDist(start[0], start[1]), d1 = touchDist(now[0], now[1]);
    const dSep = Math.abs(d1 - d0);
    const c0 = touchCentroid(start), c1 = touchCentroid(now);
    const dPan = touchDist(c0, c1);
    const pinchOver = dSep > pinchSlop, panOver = dPan > panSlop;
    if (pinchOver && panOver) return (dSep / pinchSlop >= dPan / panSlop) ? 'pinch' : 'pan';
    if (pinchOver) return 'pinch';
    if (panOver) return 'pan';
    return 'none';
  }
  function pinchScale(startDist, nowDist) {
    const a = Number(startDist), b = Number(nowDist);
    if (!Number.isFinite(a) || !Number.isFinite(b) || a <= 0 || b <= 0) return 1;
    return b / a;
  }
  function pinchDolly(radius, startDist, nowDist, lo, hi) {
    const r = Number(radius);
    if (!Number.isFinite(r)) return Number(lo) || 0;
    const s = pinchScale(startDist, nowDist);
    const out = r / s;
    if (!Number.isFinite(out)) return r;
    return Math.max(Number(lo), Math.min(Number(hi), out));
  }
  function tapClassify(dt, dist, opts) {
    const o = opts || {};
    const slop = o.slop === undefined ? TOUCH_SLOP : o.slop;
    const hold = o.hold === undefined ? LONG_PRESS_MS : o.hold;
    if (!(Number(dist) <= slop)) return 'drag';
    return Number(dt) >= hold ? 'longpress' : 'tap';
  }

  const RM_MODES = ['auto', 'on', 'off'];
  function rmNormalize(v) { const s = String(v == null ? '' : v); return RM_MODES.indexOf(s) === -1 ? 'auto' : s; }
  function rmNext(v) { return RM_MODES[(RM_MODES.indexOf(rmNormalize(v)) + 1) % RM_MODES.length]; }
  function reducedMotionDecision(mediaMatches, override) {
    const o = rmNormalize(override);
    if (o === 'on') return true;
    if (o === 'off') return false;
    return !!mediaMatches;
  }

  const AVATAR_SHAPES = ['box', 'sphere', 'cone', 'cylinder', 'octahedron', 'wedge'];
  function avatarHash(id) {
    const s = String(id == null ? '' : id);
    let h = 2166136261;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
    return h >>> 0;
  }
  function avatarShapeIndex(id, count) {
    const n = Math.max(1, Math.floor(Number(count) || AVATAR_SHAPES.length));
    return avatarHash(id) % n;
  }
  function avatarShapeName(id) { return AVATAR_SHAPES[avatarShapeIndex(id, AVATAR_SHAPES.length)]; }

  function focusTrapNext(count, current, shift) {
    const n = Math.floor(Number(count) || 0);
    if (n <= 0) return -1;
    const c = Math.floor(Number(current));
    if (!Number.isFinite(c) || c < 0 || c >= n) return shift ? n - 1 : 0;
    return shift ? (c - 1 + n) % n : (c + 1) % n;
  }

  const PHOTO_MIN_PERIOD = 0.34;
  function safePeriod(seconds, minPeriod) {
    const p = Number(seconds), m = Number(minPeriod === undefined ? PHOTO_MIN_PERIOD : minPeriod);
    if (!Number.isFinite(p) || p <= 0) return m;
    return Math.max(m, p);
  }
  '@collab-3d-a11y-helpers:end';

  const COARSE_POINTER = (function () {
    try { if (window.matchMedia && window.matchMedia('(pointer: coarse)').matches) return true; } catch (e) {}
    try { return (navigator.maxTouchPoints || 0) > 0; } catch (e) { return false; }
  })();
  const LS_RM = 'tof3d.reduceMotion', LS_FREELOOK = 'tof3d.freeLook';
  function lsGetStr(k, dflt) { try { const v = localStorage.getItem(k); return v === null ? dflt : v; } catch (e) { return dflt; } }
  function lsSetStr(k, v) { try { localStorage.setItem(k, String(v)); } catch (e) {} }
  let rmOverride = rmNormalize(lsGetStr(LS_RM, 'auto'));
  let rmMedia = null, rmMediaMatches = false, rmBtn = null;
  try { rmMedia = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : null; rmMediaMatches = !!(rmMedia && rmMedia.matches); } catch (e) {}
  function reduceMotion() { return reducedMotionDecision(rmMediaMatches, rmOverride); }
  let _rmStatic = false;

  let freeLook = lsGetStr(LS_FREELOOK, COARSE_POINTER ? '1' : '0') === '1', freeLookBtn = null;

  const raycaster = new THREE.Raycaster();
  const pickables = [];
  const planeY0 = new THREE.Plane(new THREE.Vector3(0, 1, 0), 0);
  let selectedId = null, selectedKind = null, selBox = null;
  let selection = [];
  const selHalos = [];
  let dragId = null, dragKind = null, dragObj = null, dragMoved = false, orbiting = false, lastX = 0, lastY = 0, downX = 0, downY = 0;
  let dragGroup = null, dragAnchor = null;
  let marqStart = null, marqEnd = null, marqEl = null, marqScreen = null;
  let keyDelArmed = 0;
  let placeCandidate = false;
  let moveArmed = false, moveBtn = null;
  function refreshMoveBtn() {
    if (!moveBtn) return;
    moveBtn.textContent = moveArmed ? '✋ Move: ON' : '🔒 Move: off';
    moveBtn.style.background = moveArmed ? '#b45309' : '#334155';
    moveBtn.style.color = moveArmed ? '#fff7ed' : '#e2e8f0';
    setPressed(moveBtn, moveArmed);
    moveBtn.setAttribute('aria-label', 'Move mode: ' + (moveArmed ? 'on, drag repositions objects' : 'off, drag orbits the camera'));
  }
  function toggleMove() {
    moveArmed = !moveArmed; refreshMoveBtn();
    guardToast(moveArmed ? '✋ Move mode ON: drag to reposition objects.' : '🔒 Move mode off, objects can no longer be dragged.');
    announce(moveArmed ? 'Move mode on. Dragging repositions objects.' : 'Move mode off. Dragging orbits the camera.');
  }
  const MAX_SCENE_TABS = 32;
  const LEGACY_TAB_KEY = '__legacy';
  const TAB_KEY_RE = /[^A-Za-z0-9_.:#-]/g;
  function tabKey() {
    try {
      const tabs = getVar('documentTabs');
      const i = num(getVar('currentTabIndex'), 0) | 0;
      const t = (Array.isArray(tabs) && tabs[i]) ? tabs[i] : null;
      const raw = (t && typeof t.id === 'string' && t.id) ? t.id : ('tab#' + i);
      const k = raw.slice(0, 64).replace(TAB_KEY_RE, '_');
      return (!k || k === '__proto__' || k === 'constructor' || k === 'prototype') ? 'main' : k;
    } catch (e) { return 'main'; }
  }
  function tabNameForKey(key) {
    try {
      const tabs = getVar('documentTabs');
      if (Array.isArray(tabs)) {
        for (let i = 0; i < tabs.length; i++) {
          const t = tabs[i]; if (!t) continue;
          const raw = (typeof t.id === 'string' && t.id) ? t.id : ('tab#' + i);
          const k = raw.slice(0, 64).replace(TAB_KEY_RE, '_');
          if (k === key && t.name) return String(t.name);
        }
      }
    } catch (e) {}
    return String(key);
  }
  const DROPPED_TAB_LIST_MAX = 4;
  function droppedByTabDetail(byTab) {
    if (!byTab || typeof byTab !== 'object') return '';
    const parts = [];
    let extra = 0;
    for (const k in byTab) {
      if (!Object.prototype.hasOwnProperty.call(byTab, k)) continue;
      const d = byTab[k] || {};
      const furn = d.furn | 0, keys = d.keys | 0;
      if (!furn && !keys) continue;
      if (parts.length >= DROPPED_TAB_LIST_MAX) { extra++; continue; }
      parts.push('Tab ' + tabNameForKey(k) + ': ' + furn + ' furniture / ' + keys + ' keys dropped');
    }
    if (!parts.length) return '';
    return ' ' + parts.join('; ') + (extra ? '; and ' + extra + ' more tab(s)' : '') + '.';
  }
  function emptyBucket() { return { furniture: [], heights: {}, buried: {}, wallHeights: {} }; }
  const tabRevs = Object.create(null);
  const dirtyTabs = new Set();
  let sceneRev = 0;
  let reloadRequired = false;
  function tabRev(k) { return Object.prototype.hasOwnProperty.call(tabRevs, k) ? (tabRevs[k] | 0) : 0; }
  function markTabDirty(k) { if (typeof k === 'string' && k) dirtyTabs.add(k); }
  const localOps = Object.create(null);
  const MAX_LOCAL_OPS = 400;
  function clearLocalOps() { for (const k in localOps) delete localOps[k]; }
  function logLocalOp(k, op) {
    if (typeof k !== 'string' || !k || !op) return;
    const a = localOps[k] || (localOps[k] = []);
    a.push(op);
    if (a.length > MAX_LOCAL_OPS) a.shift();
  }
  function bucketFor(key) {
    const k = (typeof key === 'string' && key) ? key.slice(0, 64).replace(TAB_KEY_RE, '_') : tabKey();
    const t = scene3d.tabs;
    if (!Object.prototype.hasOwnProperty.call(t, k)) {
      if (Object.keys(t).length >= MAX_SCENE_TABS) return null;
      t[k] = emptyBucket();
    }
    return t[k];
  }
  function activeBucket() {
    const k = tabKey(), t = scene3d.tabs;
    if (!Object.prototype.hasOwnProperty.call(t, k)) t[k] = emptyBucket();
    return t[k];
  }
  const scene3d = {
    mpu: 0, wireMode: 0, tabs: Object.create(null),
    get furniture() { return activeBucket().furniture; },
    set furniture(v) { activeBucket().furniture = Array.isArray(v) ? v : []; },
    get heights() { return activeBucket().heights; },
    set heights(v) { activeBucket().heights = (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; },
    get buried() { return activeBucket().buried; },
    set buried(v) { activeBucket().buried = (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; },
    get wallHeights() { return activeBucket().wallHeights; },
    set wallHeights(v) { activeBucket().wallHeights = (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; },
  };
  const WIRE_MODES = [
    { id: 'elevated', label: 'Wires: elevated', y: 40, floor: false },
    { id: 'floor', label: 'Wires: floor', y: 5, floor: true },
    { id: 'hidden', label: 'Wires: hidden', y: 0, hidden: true },
  ];
  let wireBtn = null;
  function wireModeDef() { return WIRE_MODES[clamp(scene3d.wireMode | 0, 0, WIRE_MODES.length - 1)]; }
  function refreshWireBtn() { if (wireBtn) wireBtn.textContent = '🔌 ' + wireModeDef().label; }
  function cycleWire() {
    scene3d.wireMode = ((scene3d.wireMode | 0) + 1) % WIRE_MODES.length;
    refreshWireBtn();
    if (sceneReady) { scheduleSave(); broadcastFurn({ op: 'wire', wireMode: scene3d.wireMode }); }
    if (active) buildScene();
  }

  let fxOn = true, fxBtn = null;
  const anims = { fov: [], flow: [], ping: [] };
  function fxAllowed() { if (!fxOn) return false; const as = getVar('ANIM_SETTINGS'); return !(as && as.masterAnim === false); }

  const ANIM_SHAPE_CAT = {
    camera: 'camera', cctv: 'camera', 'ptz-cam': 'camera',
    doorbell: 'doorbell',
    'motion-sensor': 'motion', 'motion-detect': 'motion',
    'smoke-detector': 'smoke', 'smoke-alarm': 'smoke',
    'access-point': 'wifi', wifi: 'wifi', router: 'wifi', 'wifi-strong': 'wifi', 'wifi-weak': 'wifi',
    sensor: 'sensor', iot: 'sensor',
    sprinkler: 'sprinkler', 'sprinkler-arc': 'sprinkler',
  };
  const ANIM_ALL_ON = { masterAnim: true, masterZones: true };
  function animSettings() { const as = getVar('ANIM_SETTINGS'); return (as && typeof as === 'object') ? as : ANIM_ALL_ON; }
  function getShapeCategory(shape) { return ANIM_SHAPE_CAT[shape] || null; }
  const animFlag = (sub, k) => (!sub || typeof sub !== 'object') ? true : !!sub[k];
  function isAnimationAllowed(shape, animType) {
    const as = animSettings();
    if (as.masterAnim === false) return false;
    if (!animFlag(as.animTypes, animType)) return false;
    const cat = getShapeCategory(shape);
    if (cat && !animFlag(as.animCategories, cat)) return false;
    return true;
  }
  function isZoneAllowed(shape) {
    const as = animSettings();
    if (as.masterZones === false) return false;
    const cat = getShapeCategory(shape);
    if (cat && !animFlag(as.zoneCategories, cat)) return false;
    return true;
  }
  function connectionsAnimAllowed() { return isAnimationAllowed(null, 'connections') && animFlag(animSettings().animCategories, 'connections'); }
  function refreshFxBtn() { if (fxBtn) { fxBtn.textContent = '✨ FX: ' + (fxOn ? 'on' : 'off'); setPressed(fxBtn, fxOn); } }
  function toggleFx() { fxOn = !fxOn; refreshFxBtn(); if (active) buildScene(); }

  const LS_DEV = 'tof3d.deviceModels', LS_ICO3D = 'tof3d.icons3d';
  function lsGet(k, dflt) { try { const v = localStorage.getItem(k); return v === null ? dflt : v === '1'; } catch (e) { return dflt; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v ? '1' : '0'); } catch (e) {} }
  let devModelsOn = lsGet(LS_DEV, true), devBtn = null;
  let icon3dOn = lsGet(LS_ICO3D, true), ico3dBtn = null;
  function refreshDevBtn() { if (devBtn) { devBtn.textContent = '🖥 Device models: ' + (devModelsOn ? 'on' : 'off'); setPressed(devBtn, devModelsOn); } }
  function refreshIcon3dBtn() { if (ico3dBtn) { ico3dBtn.textContent = '🔷 3D icons: ' + (icon3dOn ? 'on' : 'off'); setPressed(ico3dBtn, icon3dOn); } }
  function toggleDevModels() { devModelsOn = !devModelsOn; lsSet(LS_DEV, devModelsOn); refreshDevBtn(); if (active) buildScene(); }
  function toggleIcon3d() { icon3dOn = !icon3dOn; lsSet(LS_ICO3D, icon3dOn); refreshIcon3dBtn(); if (active) buildScene(); }

  function rmLabel() { return rmOverride === 'on' ? 'reduced' : rmOverride === 'off' ? 'full' : ('auto (' + (rmMediaMatches ? 'reduced' : 'full') + ')'); }
  function refreshRmBtn() {
    if (!rmBtn) return;
    rmBtn.textContent = '♿ Motion: ' + rmLabel();
    rmBtn.setAttribute('aria-label', 'Motion setting: ' + rmLabel() + '. Activate to change.');
    setPressed(rmBtn, reduceMotion());
  }
  function applyReduceMotion(announceIt) {
    _rmStatic = false;
    refreshRmBtn();
    if (announceIt) announce(reduceMotion() ? 'Reduced motion on. Animations are static and camera moves are instant.' : 'Full motion on.');
    if (active) buildScene();
  }
  function cycleReduceMotion() { rmOverride = rmNext(rmOverride); lsSetStr(LS_RM, rmOverride); applyReduceMotion(true); }
  try {
    if (rmMedia) {
      const onRm = function (e) { rmMediaMatches = !!(e && e.matches !== undefined ? e.matches : rmMedia.matches); applyReduceMotion(false); };
      if (rmMedia.addEventListener) rmMedia.addEventListener('change', onRm);
      else if (rmMedia.addListener) rmMedia.addListener(onRm);
    }
  } catch (e) {}

  function refreshFreeLookBtn() {
    if (!freeLookBtn) return;
    freeLookBtn.textContent = '👁 Free look: ' + (freeLook ? 'on' : 'off');
    freeLookBtn.setAttribute('aria-label', 'Free look without pointer lock: ' + (freeLook ? 'on' : 'off'));
    setPressed(freeLookBtn, freeLook);
  }
  function toggleFreeLook() {
    freeLook = !freeLook; lsSetStr(LS_FREELOOK, freeLook ? '1' : '0'); refreshFreeLookBtn();
    if (freeLook && document.pointerLockElement === canvas) { try { document.exitPointerLock(); } catch (e) {} }
    guardToast(freeLook ? '👁 Free look ON: drag to look around; no pointer lock.' : '👁 Free look off, walk mode captures the pointer again.');
    announce(freeLook ? 'Free look without pointer lock enabled' : 'Free look disabled');
  }
  const PING_COLORS = { online: '#22c55e', offline: '#ef4444', checking: '#f59e0b', unknown: null };
  const SCALE_PRESETS = [
    { id: 'off', label: 'Scale: off', mpu: 0 },
    { id: 'house', label: 'House ~20×15 m', mpu: 0.005 },
    { id: 'datahall', label: 'Data hall ~40×30 m', mpu: 0.01 },
    { id: 'office', label: 'Office ~80×60 m', mpu: 0.02 },
    { id: 'warehouse', label: 'Warehouse ~200×150 m', mpu: 0.05 },
    { id: 'hangar', label: 'Hangar ~400×300 m', mpu: 0.1 },
  ];
  let scaleBtn = null;
  function scalePreset(mpu) { return SCALE_PRESETS.find((p) => Math.abs(p.mpu - (mpu || 0)) < 1e-9) || SCALE_PRESETS[0]; }
  function refreshScaleBtn() { if (scaleBtn) scaleBtn.textContent = '📐 ' + scalePreset(scene3d.mpu).label; }
  function cycleScale() {
    const i = SCALE_PRESETS.indexOf(scalePreset(scene3d.mpu));
    scene3d.mpu = SCALE_PRESETS[(i + 1) % SCALE_PRESETS.length].mpu;
    refreshScaleBtn();
    if (sceneReady) { scheduleSave(); broadcastFurn({ op: 'scale', mpu: scene3d.mpu }); }
    if (active) { buildScene(); }
  }

  const ITEM_CATALOG = [
    { id: 'node',  icon: '🖥️', label: 'Node',  cat: 'Network',   place: 'node' },
    { id: 'rack',  icon: '🗄️', label: 'Rack',  cat: 'Network',   place: 'rack' },
    { id: 'wall',  icon: '🧱', label: 'Wall',  cat: 'Structure', place: 'rect', rectKind: 'wall' },
    { id: 'zone',  icon: '🟧', label: 'Zone',  cat: 'Structure', place: 'rect', rectKind: 'zone' },
    { id: 'text',  icon: '🔤', label: 'Text',  cat: 'Structure', place: 'text' },
    { id: 'image', icon: '🏞️', label: 'Image', cat: 'Structure', place: 'image' },
    { id: 'table', icon: '🪑', label: 'Table', cat: 'Furniture', place: 'furniture', furnKind: 'table' },
    { id: 'shelf', icon: '📚', label: 'Shelf', cat: 'Furniture', place: 'furniture', furnKind: 'shelf' },
    { id: 'lamp',  icon: '💡', label: 'Lamp',  cat: 'Furniture', place: 'furniture', furnKind: 'lamp' },
    { id: 'panel', icon: '🚧', label: 'Panel', cat: 'Furniture', place: 'furniture', furnKind: 'wall' },
    { id: 'plant', icon: '🪴', label: 'Plant', cat: 'Furniture', place: 'furniture', furnKind: 'plant' },
    { id: 'frame', icon: '🖼️', label: 'Frame', cat: 'Furniture', place: 'furniture', furnKind: 'frame' },
    { id: 'model', icon: '📦', label: 'Model', cat: 'Furniture', place: 'furniture', furnKind: 'model' },
  ];
  const ITEM_BY_ID = {}; ITEM_CATALOG.forEach((it) => { ITEM_BY_ID[it.id] = it; });
  const BOOK_SHAPE_CATEGORIES = {
    basic: [['circle', 'Circle'], ['square', 'Square'], ['rectangle', 'Rectangle'], ['triangle', 'Triangle'], ['hexagon', 'Hexagon'], ['diamond', 'Diamond'], ['star', 'Star'], ['stop-sign', 'Stop Sign'], ['octagon', 'Octagon'], ['pentagon', 'Pentagon'], ['cross', 'Cross'], ['rounded-square', 'Rounded Square'], ['pill', 'Pill'], ['parallelogram', 'Parallelogram'], ['trapezoid', 'Trapezoid']],
    computers: [['server', 'Server'], ['pc', 'PC / Desktop'], ['laptop', 'Laptop'], ['phone', 'Phone / Mobile'], ['printer', 'Printer'], ['pi', 'Raspberry Pi'], ['sensor', 'Sensor / IoT']],
    network: [['router', 'Router'], ['switch', 'Switch'], ['firewall', 'Firewall'], ['access-point', 'Access Point'], ['load-balancer', 'Load Balancer'], ['gateway', 'Gateway'], ['vpn', 'VPN / Tunnel'], ['nas', 'NAS / Storage']],
    cloud: [['cloud', 'Cloud'], ['database', 'Database'], ['docker', 'Docker'], ['container', 'Container'], ['vm', 'Virtual Machine'], ['kubernetes', 'Kubernetes'], ['api', 'API / Endpoint'], ['queue', 'Queue / Message'], ['lambda', 'Lambda / Function'], ['bucket', 'Bucket / S3']],
    security: [['shield', 'Shield'], ['camera', 'Camera / CCTV'], ['monitor', 'Monitor / Dashboard']],
    smarthome: [['thermostat', 'Thermostat'], ['doorbell', 'Video Doorbell'], ['smart-lock', 'Smart Lock'], ['smart-bulb', 'Smart Bulb'], ['smart-plug', 'Smart Plug'], ['smart-speaker', 'Smart Speaker'], ['smart-tv', 'Smart TV'], ['hub', 'Smart Hub'], ['smoke-detector', 'Smoke Detector'], ['motion-sensor', 'Motion Sensor'], ['garage', 'Garage Door'], ['sprinkler', 'Sprinkler'], ['vacuum', 'Robot Vacuum']],
    sports: [['basketball-ball', 'Basketball'], ['football-ball', 'Football'], ['soccer-ball', 'Soccer Ball'], ['hockey-puck', 'Hockey Puck'], ['baseball-ball', 'Baseball'], ['tennis-ball', 'Tennis Ball'], ['volleyball', 'Volleyball'], ['rugby-ball', 'Rugby Ball'], ['golf-ball', 'Golf Ball'], ['frisbee', 'Frisbee'], ['cricket-ball', 'Cricket Ball'], ['lacrosse-stick', 'Lacrosse Stick'], ['golf-flag', 'Golf Flag'], ['tactical-x', 'Tactical X'], ['tactical-o', 'Tactical O'], ['tactical-star', 'Tactical Star']],
    rack: [['patch-panel', 'Patch Panel'], ['ups', 'UPS'], ['pdu', 'PDU'], ['rack-shelf', 'Rack Shelf'], ['blank-panel', 'Blank Panel'], ['cable-management', 'Cable Management'], ['kvm', 'KVM Switch']],
  };
  const BOOK_CATEGORY_OPTS = [['basic', 'Basic Shapes'], ['computers', 'Computers & Devices'], ['network', 'Network Equipment'], ['cloud', 'Cloud & Services'], ['security', 'Security & Monitoring'], ['smarthome', 'Smart Home'], ['sports', 'Sports'], ['rack', 'Rack Equipment']];
  const BOOK_MODE_DEFAULT_CATS = { network: 'network', mindmap: 'basic', sports: 'sports', smarthome: 'smarthome', floorplan: 'basic' };
  function bookFindCategory(shape) {
    const ps = getVar('PAGE_STATE') || {};
    const fb = BOOK_MODE_DEFAULT_CATS[ps.mappingMode || 'network'] || 'basic';
    if (!shape) return fb;
    for (const c in BOOK_SHAPE_CATEGORIES) { if (BOOK_SHAPE_CATEGORIES[c].some((s) => s[0] === shape)) return c; }
    return fb;
  }
  const BOOK_COVERAGE_SHAPES = new Set(['camera', 'cctv', 'doorbell', 'motion-sensor', 'smoke-detector', 'access-point', 'wifi', 'router', 'sensor', 'iot', 'sprinkler']);
  const BOOK_COVERAGE_DEFAULTS = {
    camera: { angle: 90, distance: 150, animationType: 'sweep' },
    cctv: { angle: 90, distance: 150, animationType: 'sweep' },
    doorbell: { angle: 120, distance: 100, animationType: 'sweep' },
    'motion-sensor': { angle: 120, distance: 100, animationType: 'pulse' },
    'smoke-detector': { angle: 360, distance: 80, animationType: 'pulse' },
    'access-point': { angle: 360, distance: 200, animationType: 'rings' },
    wifi: { angle: 360, distance: 200, animationType: 'rings' },
    router: { angle: 360, distance: 200, animationType: 'rings' },
    sensor: { angle: 90, distance: 100, animationType: 'pulse' },
    iot: { angle: 90, distance: 100, animationType: 'pulse' },
    sprinkler: { angle: 90, distance: 120, animationType: 'spin' },
  };
  const hasCoverageZone = (shape) => BOOK_COVERAGE_SHAPES.has(shape);
  const coverageDefaults = (shape) => BOOK_COVERAGE_DEFAULTS[shape] || { angle: 90, distance: 150, animationType: 'sweep' };
  const BOOK_FONTS = [['', 'Theme default'], ['system-ui, sans-serif', 'System UI'], ['monospace', 'Monospace'], ['serif', 'Serif'], ['cursive', 'Cursive'], ["'Courier New', monospace", 'Courier'], ['Arial, sans-serif', 'Arial'], ["'Times New Roman', serif", 'Times']];
  const BOOK_FOV_ANIMS = [['sweep', 'Sweep (Pan)'], ['pulse', 'Pulse (Breathe)'], ['rings', 'Rings (Emanate)'], ['spin', 'Spin (Rotate)']];
  const BOOK_FOV_BORDER_STYLES = [['solid', 'Solid'], ['dashed', 'Dashed'], ['dotted', 'Dotted']];
  const BOOK_FOV_LABEL_POS = [['center', 'Center'], ['edge', 'Edge'], ['outside', 'Outside']];
  const BOOK_ICON_LIBS = ['mdi', 'simple', 'selfhst'];
  const BOOK_LAYERS = ['layer1', 'layer2', 'layer3', 'layer4'];
  const BOOK_RACK_CAPS = ['42', '48', '24', '12', '6'];
  const BOOK_PING_PROTOS = ['http', 'https', 'custom'];
  const BOOK_FLAT_STYLE_PROPS = ['circleColor', 'circleBorder', 'titleColor', 'titleFont', 'titleSize', 'subColor', 'subFont', 'subSize'];
  function bookBreakpoint() { const w = window.innerWidth; return w <= 380 ? 'fold' : w <= 768 ? 'mobile' : w <= 1024 ? 'tablet' : 'desktop'; }
  function bookResolveStyles(entry) {
    if (!entry || typeof entry !== 'object') return {};
    if (BOOK_FLAT_STYLE_PROPS.some((p) => entry[p])) return entry;
    const base = entry.all && typeof entry.all === 'object' ? entry.all : {};
    const bp = entry[bookBreakpoint()];
    return Object.assign({}, base, bp && typeof bp === 'object' ? bp : {});
  }
  function bookStyleScope(sv, id) {
    if (!sv[id] || typeof sv[id] !== 'object') sv[id] = {};
    const entry = sv[id];
    if (BOOK_FLAT_STYLE_PROPS.some((p) => Object.prototype.hasOwnProperty.call(entry, p))) {
      const all = entry.all && typeof entry.all === 'object' ? entry.all : {};
      BOOK_FLAT_STYLE_PROPS.forEach((p) => { if (entry[p] !== undefined) { all[p] = entry[p]; delete entry[p]; } });
      entry.all = all;
    }
    if (!entry.all || typeof entry.all !== 'object') entry.all = {};
    return entry.all;
  }
  const HOTBAR_SLOTS = 9;
  let hotbar = ['node', 'rack', 'wall', 'zone', 'text', 'image', 'table', 'lamp', null];
  let hotbarSel = HOTBAR_SLOTS - 1;
  let slotEls = [], hotbarEl = null, invEl = null;
  function heldItem() { return ITEM_BY_ID[hotbar[hotbarSel]] || null; }
  function selectHotbar(i) { if (i < 0 || i >= HOTBAR_SLOTS) return; hotbarSel = i; renderHotbar(); }
  function dropHeld() {
    if (!heldItem()) return;
    hotbar[hotbarSel] = null; renderHotbar();
    guardToast('Put away, hand is empty. Press E for the inventory to pick something else.');
  }
  function cycleHotbar(dir) { selectHotbar((hotbarSel + dir + HOTBAR_SLOTS) % HOTBAR_SLOTS); }
  function renderHotbar() {
    if (!slotEls.length) return;
    slotEls.forEach((s, i) => {
      const it = ITEM_BY_ID[hotbar[i]];
      const icon = s.querySelector('.hb-icon'); if (icon) icon.textContent = it ? it.icon : '';
      const sel = i === hotbarSel;
      s.style.border = sel ? '2px solid #4fd1c5' : '2px solid #334155';
      s.style.boxShadow = sel ? '0 0 10px rgba(79,209,197,.6)' : 'none';
      s.title = it ? ('Place ' + it.label) : 'Empty hand: click to select/inspect, drag to move';
      s.setAttribute('aria-label', 'Hotbar slot ' + (i + 1) + ': ' + (it ? it.label : 'empty hand'));
      setPressed(s, sel);
    });
  }
  function buildInventory() {
    invEl = document.createElement('div');
    invEl.id = 'threed-inventory';
    invEl.style.cssText = 'position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);z-index:4;display:none;max-width:540px;background:rgba(15,23,42,.98);border:1px solid #334155;border-radius:12px;padding:16px 18px;box-shadow:0 12px 40px rgba(0,0,0,.6);color:#e2e8f0;font:13px system-ui,sans-serif';
    const title = document.createElement('div'); title.style.cssText = 'font-weight:700;margin-bottom:2px;font-size:15px'; title.textContent = '🎒 Inventory'; invEl.appendChild(title);
    const sub = document.createElement('div'); sub.style.cssText = 'color:#94a3b8;margin-bottom:10px;font-size:12px'; sub.textContent = 'Click a hotbar slot below to target it, then click an item to assign it. (I to close)'; invEl.appendChild(sub);
    const cats = {}; ITEM_CATALOG.forEach((it) => { (cats[it.cat] = cats[it.cat] || []).push(it); });
    const mkTile = (icon, label, onClick) => {
      const tile = document.createElement('div');
      tile.style.cssText = 'width:80px;height:66px;border-radius:8px;background:#0f172a;border:1px solid #334155;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;cursor:pointer';
      const ic = document.createElement('div'); ic.style.cssText = 'font-size:24px'; ic.textContent = icon; tile.appendChild(ic);
      const lb = document.createElement('div'); lb.style.cssText = 'font-size:11px;color:#cbd5e1'; lb.textContent = label; tile.appendChild(lb);
      tile.addEventListener('mouseenter', () => { tile.style.borderColor = '#4fd1c5'; });
      tile.addEventListener('mouseleave', () => { tile.style.borderColor = '#334155'; });
      tile.addEventListener('click', onClick);
      return tile;
    };
    Object.keys(cats).forEach((cat) => {
      const h = document.createElement('div'); h.style.cssText = 'color:#7dd3c8;font-weight:600;margin:10px 0 6px'; h.textContent = cat; invEl.appendChild(h);
      const grid = document.createElement('div'); grid.style.cssText = 'display:flex;flex-wrap:wrap;gap:8px';
      cats[cat].forEach((it) => grid.appendChild(mkTile(it.icon, it.label, () => { hotbar[hotbarSel] = it.id; renderHotbar(); })));
      invEl.appendChild(grid);
    });
    const th = document.createElement('div'); th.style.cssText = 'color:#7dd3c8;font-weight:600;margin:10px 0 6px'; th.textContent = 'Tools'; invEl.appendChild(th);
    const tg = document.createElement('div'); tg.style.cssText = 'display:flex;gap:8px';
    tg.appendChild(mkTile('🖐️', 'Hand', () => { hotbar[hotbarSel] = null; renderHotbar(); }));
    invEl.appendChild(tg);
    overlay.appendChild(invEl);
  }
  function toggleInventory() { if (!invEl) buildInventory(); invEl.style.display = (invEl.style.display === 'block') ? 'none' : 'block'; }

  function ndcFrom(e) {
    const r = canvas.getBoundingClientRect();
    return new THREE.Vector2(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
  }
  function pick(ndc) {
    raycaster.setFromCamera(ndc, camera);
    const hits = raycaster.intersectObjects(pickables, true);
    if (!hits.length) return null;
    let o = hits[0].object;
    while (o && !(o.userData && (o.userData.nodeId || o.userData.furnId || o.userData.rectId || o.userData.textId || o.userData.imageId || o.userData.edgeId))) o = o.parent;
    if (!o) return null;
    const u = o.userData;
    if (u.furnId) return { kind: 'furniture', id: u.furnId, obj: o };
    if (u.rectId) return { kind: 'rect', id: u.rectId, obj: o };
    if (u.textId) return { kind: 'text', id: u.textId, obj: o };
    if (u.imageId) return { kind: 'image', id: u.imageId, obj: o };
    if (u.edgeId) return { kind: 'edge', id: u.edgeId, obj: o };
    return { kind: 'node', id: u.nodeId, obj: o };
  }
  function floorPoint(ndc) {
    raycaster.setFromCamera(ndc, camera);
    const out = new THREE.Vector3();
    return raycaster.ray.intersectPlane(planeY0, out) ? out : null;
  }
  const SEL_MAX = 400;
  const SEL_COLOR = 0xffe066;
  const SEL_COLOR_MULTI = 0x38bdf8;
  function objectFor(kind, id) {
    for (let i = 0; i < pickables.length; i++) {
      const u = pickables[i] && pickables[i].userData; if (!u) continue;
      if (kind === 'node') { if (u.nodeId === id) return pickables[i]; continue; }
      if (kind === 'furniture') { if (u.furnId === id) return pickables[i]; continue; }
      if (kind === 'rect') { if (u.rectId === id) return pickables[i]; continue; }
      if (kind === 'text') { if (u.textId === id) return pickables[i]; continue; }
      if (kind === 'image') { if (u.imageId === id) return pickables[i]; continue; }
      if (kind === 'edge') { if (u.edgeId === id) return pickables[i]; continue; }
    }
    return null;
  }
  function pickableItems(excludeEdges) {
    const seen = Object.create(null), out = [];
    for (let i = 0; i < pickables.length; i++) {
      const u = pickables[i] && pickables[i].userData; if (!u) continue;
      let kind = null, id = null;
      if (u.furnId) { kind = 'furniture'; id = u.furnId; }
      else if (u.rectId) { kind = 'rect'; id = u.rectId; }
      else if (u.textId) { kind = 'text'; id = u.textId; }
      else if (u.imageId) { kind = 'image'; id = u.imageId; }
      else if (u.edgeId) { kind = 'edge'; id = u.edgeId; }
      else if (u.nodeId) { kind = 'node'; id = u.nodeId; }
      if (!kind || (excludeEdges && kind === 'edge')) continue;
      const k = selKeyOf(kind, id); if (seen[k]) continue; seen[k] = 1;
      out.push({ kind: kind, id: id, obj: pickables[i] });
    }
    return out;
  }
  function clearSelHalos() {
    while (selHalos.length) { const h = selHalos.pop(); if (h.parent) h.parent.remove(h); if (h.geometry) h.geometry.dispose(); if (h.material) h.material.dispose(); }
  }
  function clearPrimaryHalo() {
    if (!selBox) return;
    if (selBox.parent) selBox.parent.remove(selBox);
    if (selBox.geometry) selBox.geometry.dispose();
    if (selBox.material) selBox.material.dispose();
    selBox = null;
  }
  function applySelectionVisuals() {
    clearPrimaryHalo(); clearSelHalos();
    if (!scene || !selection.length) return;
    const root = contentRoot() || scene;
    for (let i = 0; i < selection.length; i++) {
      const s = selection[i], o = objectFor(s.kind, s.id); if (!o) continue;
      const primary = (i === selection.length - 1);
      const h = new THREE.BoxHelper(o, primary ? SEL_COLOR : SEL_COLOR_MULTI);
      root.add(h);
      if (primary) selBox = h; else selHalos.push(h);
    }
  }
  function renderInspect() {
    if (!inspectEl) return;
    if (selection.length > 1) { showMultiInspect(); return; }
    if (!selection.length) { inspectEl.style.display = 'none'; return; }
    const s = selection[0];
    if (s.kind === 'furniture') showFurnInspect(s.id);
    else if (s.kind === 'rect' || s.kind === 'text' || s.kind === 'image') showPrimInspect(s.kind, s.id);
    else if (s.kind === 'edge') showEdgeInspect(s.id);
    else showInspect(s.id);
  }
  function setSelection(list) {
    selection = (Array.isArray(list) ? list : []).slice(0, SEL_MAX);
    const last = selection.length ? selection[selection.length - 1] : null;
    selectedId = last ? last.id : null;
    selectedKind = last ? last.kind : null;
    groupDelArmed = 0;
    applySelectionVisuals();
    renderInspect();
    sendSelectionPresence();
    announceSelection();
  }
  function selectionName(kind, id) {
    try {
      if (kind === 'node') { const nd = getVar('NODE_DATA'); const n = nd && nd[id]; if (n && n.name) return String(n.name); }
      else if (kind === 'rect' || kind === 'text' || kind === 'image') {
        const it = primItem(kind, id);
        if (it) return String(it.content || it.label || it.name || id);
      } else if (kind === 'edge') {
        const ed = getVar('EDGE_DATA'); const e = Array.isArray(ed) ? ed.find(function (x) { return x && x.id === id; }) : null;
        if (e) return String(e.label || (e.from + ' to ' + e.to));
      }
    } catch (e) {}
    return String(id);
  }
  function announceSelection() {
    if (!srEl) return;
    if (!selection.length) { announce('Selection cleared'); return; }
    if (selection.length === 1) { announce('Selected: ' + selectionName(selectedKind, selectedId) + ', ' + (selectedKind || 'object')); return; }
    const s = selSummary(selection);
    announce(s.n + ' selected: ' + s.detail + '. Primary: ' + selectionName(selectedKind, selectedId) + '.');
  }
  function selectItem(kind, id) { setSelection([{ kind: kind, id: id }]); }
  function toggleSelect(kind, id) { setSelection(selToggle(selection, kind, id)); }
  function selRemoveItem(kind, id) { const i = selIndexOf(selection, kind, id); if (i >= 0) { const l = selection.slice(); l.splice(i, 1); setSelection(l); } }
  function selectAllPickables() {
    const items = pickableItems(false).map(function (x) { return { kind: x.kind, id: x.id }; });
    if (!items.length) { guardToast('Nothing to select on this tab.'); return; }
    const capped = items.length > SEL_MAX;
    setSelection(items);
    guardToast('▣ ' + selection.length + ' selected' + (capped ? ' (capped at ' + SEL_MAX + ')' : ''));
  }
  let _presenceSig = null;
  function sendSelectionPresence() {
    try {
      const api = window.__collab3d; if (!api || typeof api.send !== 'function') return;
      const me = api.me && api.me(); if (!me || !me.id) return;
      const ids = [];
      for (let i = 0; i < selection.length && ids.length < 50; i++) if (selection[i].kind === 'node') ids.push(String(selection[i].id));
      const sig = ids.join(',');
      if (sig === _presenceSig) return;
      _presenceSig = sig;
      const tabs = getVar('documentTabs'), idx = num(getVar('currentTabIndex'), 0) | 0;
      const nm = (Array.isArray(tabs) && tabs[idx] && tabs[idx].name) || 'Main';
      api.send('presence', { userId: me.id, selectedNodes: ids, editingNode: null, currentTab: nm });
    } catch (e) {  }
  }
  let groupDelArmed = 0;
  function showMultiInspect() {
    const s = selSummary(selection);
    inspectEl.textContent = '';
    const t = document.createElement('div'); t.style.cssText = 'font-weight:700;font-size:14px;color:#fbbf24;margin-bottom:6px'; t.textContent = s.text; inspectEl.appendChild(t);
    if (s.detail) { const d = document.createElement('div'); d.style.cssText = 'color:#94a3b8'; d.textContent = s.detail; inspectEl.appendChild(d); }
    let lockedN = 0; for (let i = 0; i < selection.length; i++) if (isLocked(selection[i].kind, selection[i].id)) lockedN++;
    if (lockedN) { const w = document.createElement('div'); w.style.cssText = 'color:#fca5a5'; w.textContent = '🔒 ' + lockedN + ' locked, skipped by group move / delete'; inspectEl.appendChild(w); }
    const h = document.createElement('div'); h.style.cssText = 'color:#94a3b8;margin-top:4px';
    h.textContent = (moveArmed ? 'Drag any member to move them all' : 'Press M to arm Move, then drag') + ' · Shift+click adds/removes · Esc clears';
    inspectEl.appendChild(h);
    const n2 = document.createElement('div'); n2.style.cssText = 'color:#64748b'; n2.textContent = 'Select a single object to open its edit book.'; inspectEl.appendChild(n2);
    const del = document.createElement('button');
    del.style.cssText = 'margin:8px 6px 0 0;padding:5px 12px;border:none;border-radius:6px;background:#b91c1c;color:#fff;font-weight:700;cursor:pointer;font:12px system-ui';
    del.textContent = '🗑 Delete ' + selection.length;
    del.onclick = function () {
      if (isViewOnly()) { editBlocked(null, null); return; }
      if (!groupDelArmed) { groupDelArmed = Date.now(); del.textContent = '⚠ Confirm delete ' + selection.length; setTimeout(function () { if (groupDelArmed) { groupDelArmed = 0; try { del.textContent = '🗑 Delete ' + selection.length; } catch (e) {} } }, 2500); return; }
      groupDelArmed = 0; deleteSelection();
    };
    inspectEl.appendChild(del);
    const dsl = document.createElement('button');
    dsl.style.cssText = 'margin:8px 0 0 0;padding:5px 12px;border:none;border-radius:6px;background:#334155;color:#e2e8f0;font-weight:700;cursor:pointer;font:12px system-ui';
    dsl.textContent = '✕ Deselect';
    dsl.onclick = function () { setSelection([]); };
    inspectEl.appendChild(dsl);
    inspectEl.style.display = 'block';
  }
  function showEdgeInspect(id) {
    const ed = getVar('EDGE_DATA') || {}; const nd = getVar('NODE_DATA') || {};
    const e = ((ed.list) || []).find((x) => x && x.id === id); if (!e) return;
    inspectEl.textContent = '';
    const t = document.createElement('div'); t.style.cssText = 'font-weight:700;font-size:14px;color:#7dd3c8;margin-bottom:6px';
    t.textContent = 'connection'; inspectEl.appendChild(t);
    const from = (nd[e.from] && nd[e.from].name) || e.from, to = (nd[e.to] && nd[e.to].name) || e.to;
    const r = document.createElement('div'); r.style.cssText = 'color:#94a3b8'; r.textContent = from + ' → ' + to + (scene3d.buried && scene3d.buried[id] ? '  · on floor' : ''); inspectEl.appendChild(r);
    if (e.groupId) { const gr = document.createElement('div'); gr.style.cssText = 'color:#94a3b8'; gr.textContent = 'Group: ' + e.groupId; inspectEl.appendChild(gr); }
    inspectEl.appendChild(editBtn('edge', id));
    inspectEl.appendChild(delBtn('edge', id));
    inspectEl.style.display = 'block';
  }
  function showPrimInspect(kind, id) {
    const list = ((getVar(kind === 'rect' ? 'RECT_DATA' : kind === 'text' ? 'TEXT_DATA' : 'IMAGE_DATA') || {}).list) || [];
    const it = list.find((x) => x && x.id === id); if (!it) return;
    inspectEl.textContent = '';
    const label = kind === 'rect' ? (it.lineStyle === 'wall' ? 'wall' : 'zone') : kind;
    const t = document.createElement('div'); t.style.cssText = 'font-weight:700;font-size:14px;color:#93c5fd;margin-bottom:6px'; t.textContent = label + (kind === 'text' ? (': ' + String(it.content || '').slice(0, 18)) : ''); inspectEl.appendChild(t);
    const h = document.createElement('div'); h.style.cssText = 'color:#94a3b8'; h.textContent = it.locked ? '🔒 Locked, unlock in 2D to move/edit' : 'Drag to move · Edit ✏ · Delete'; inspectEl.appendChild(h);
    if (it.groupId) { const gr = document.createElement('div'); gr.style.cssText = 'color:#94a3b8'; gr.textContent = 'Group: ' + it.groupId; inspectEl.appendChild(gr); }
    inspectEl.appendChild(editBtn(kind, id));
    inspectEl.appendChild(delBtn(kind, id));
    inspectEl.style.display = 'block';
  }
  function deselect() { setSelection([]); }
  function showFurnInspect(id) {
    const f = scene3d.furniture.find((x) => x.id === id); if (!f) return;
    inspectEl.textContent = '';
    const t = document.createElement('div'); t.style.cssText = 'font-weight:700;font-size:14px;color:#c4b5fd;margin-bottom:6px'; t.textContent = (f.kind || 'item') + ' (furniture)'; inspectEl.appendChild(t);
    const h = document.createElement('div'); h.style.cssText = 'color:#94a3b8'; h.textContent = 'Drag to move · Delete to remove'; inspectEl.appendChild(h);
    inspectEl.appendChild(editBtn('furniture', id));
    inspectEl.appendChild(delBtn('furniture', id));
    inspectEl.style.display = 'block';
  }
  function showInspect(id) {
    const nd = getVar('NODE_DATA') || {};
    const n = nd[id]; if (!n) return;
    inspectEl.textContent = '';
    const title = document.createElement('div');
    title.style.cssText = 'font-weight:700;font-size:14px;color:#7dd3c8;margin-bottom:6px';
    title.textContent = n.name || id;
    inspectEl.appendChild(title);
    const rows = [['IP', n.ip], ['Role', n.role], ['Shape', n.shape], ['Layer', n.layer],
      n.groupId ? ['Group', n.groupId] : null,
      n.locked ? ['Locked', '🔒 yes, unlock in 2D to move/edit'] : null,
      ['Tags', Array.isArray(n.tags) ? n.tags.join(', ') : n.tags],
      isTrue(n.isRack) ? ['Rack', (n.rackCapacity || '?') + 'U'] : null,
      n.assignedRack ? ['In rack', (nd[n.assignedRack] && nd[n.assignedRack].name) || n.assignedRack] : null,
      n.assignedRack ? ['U position', n.rackUnit + ' (' + (n.uHeight || 1) + 'U)'] : null];
    rows.forEach((r) => {
      if (!r || r[1] == null || r[1] === '') return;
      const row = document.createElement('div');
      const k = document.createElement('span'); k.style.cssText = 'color:#94a3b8'; k.textContent = r[0] + ': ';
      const v = document.createElement('span'); v.textContent = String(r[1]);
      row.appendChild(k); row.appendChild(v); inspectEl.appendChild(row);
    });
    inspectEl.appendChild(editBtn('node', id));
    inspectEl.appendChild(delBtn('node', id));
    inspectEl.style.display = 'block';
  }

  let hudEl = null, hudBody = null, hudBtn = null;
  const HUD_EDGE_DEFAULT = 'you can edit me too';
  const HUD_ZONE_DEFAULT = 'Coverage Zone';
  const HUD_LABEL_MAX = 200;
  function ensureHud() {
    if (hudEl) return;
    hudEl = document.createElement('div');
    hudEl.id = 'threed-legend';
    hudEl.style.cssText = 'position:absolute;left:14px;top:56px;z-index:5;width:252px;max-height:calc(100% - 210px);overflow-y:auto;display:none;color:#e2e8f0;font:12px/1.5 system-ui,sans-serif;background:rgba(15,23,42,.94);border:1px solid #334155;border-radius:10px;padding:10px 12px';
    const hdr = document.createElement('div');
    hdr.style.cssText = 'display:flex;justify-content:space-between;align-items:center;font-weight:700;color:#7dd3c8;margin-bottom:6px';
    const ht = document.createElement('span'); ht.textContent = '🗂 Legend & Layers'; hdr.appendChild(ht);
    const x = document.createElement('span'); x.textContent = '✕'; x.style.cssText = 'cursor:pointer;color:#64748b'; x.onclick = function () { hudEl.style.display = 'none'; }; hdr.appendChild(x);
    hudEl.appendChild(hdr);
    hudBody = document.createElement('div'); hudEl.appendChild(hudBody);
    overlay.appendChild(hudEl);
  }
  function toggleHud() {
    ensureHud();
    const show = hudEl.style.display !== 'block';
    hudEl.style.display = show ? 'block' : 'none';
    if (show) renderHud();
  }
  function hudSection(title, parent) {
    const h = document.createElement('div');
    h.style.cssText = 'margin:10px 0 4px;font:700 11px system-ui;letter-spacing:.04em;text-transform:uppercase;color:#94a3b8;border-top:1px solid #334155;padding-top:7px';
    h.textContent = title; parent.appendChild(h);
    const b = document.createElement('div'); parent.appendChild(b); return b;
  }
  function hudNote(txt, parent) {
    const d = document.createElement('div'); d.style.cssText = 'font-size:10.5px;line-height:1.4;color:#64748b;margin:5px 0 2px'; d.textContent = txt; parent.appendChild(d); return d;
  }
  function hudRow(parent, swatchColor, control, text) {
    const row = document.createElement('label'); row.style.cssText = 'display:flex;align-items:center;gap:7px;margin:4px 0';
    if (swatchColor) { const s = document.createElement('span'); s.style.cssText = 'flex:0 0 auto;width:14px;height:14px;border-radius:3px;border:1px solid #475569;background:' + swatchColor; row.appendChild(s); }
    if (control) row.appendChild(control);
    if (text != null) { const t = document.createElement('span'); t.style.cssText = 'flex:1 1 auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap'; t.textContent = text; row.appendChild(t); }
    parent.appendChild(row); return row;
  }
  function hudLabelInput(value, placeholder, onCommit) {
    const i = document.createElement('input'); i.type = 'text'; i.value = value == null ? '' : value;
    i.placeholder = placeholder || '';
    i.style.cssText = 'flex:1 1 auto;min-width:0;padding:3px 6px;border:1px solid #334155;border-radius:4px;background:#0f172a;color:#e2e8f0;font:12px system-ui';
    bookTrack(i);
    i.addEventListener('change', onCommit);
    i.addEventListener('blur', onCommit);
    i.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') { ev.preventDefault(); i.blur(); } });
    return i;
  }
  function hudCommitLegend(name, color, input) {
    if (!bookChanged(input)) return;
    if (editBlocked(null)) { input.value = input.__book0; return; }
    const m = getVar(name); if (!m || typeof m !== 'object') return;
    const v = String(input.value == null ? '' : input.value).trim().slice(0, HUD_LABEL_MAX) || (name === 'EDGE_LEGEND' ? HUD_EDGE_DEFAULT : HUD_ZONE_DEFAULT);
    m[color] = v;
    setVar(name, m);
    input.value = v; bookTrack(input);
  }
  function hudSetLayer(n, on) {
    const cb = document.getElementById('layer-' + n);
    const apply = getVar('applyLayerFilter');
    if (!cb || typeof apply !== 'function') { guardToast('Layer filtering is not available in this document.'); return false; }
    cb.checked = !!on;
    try { apply(); } catch (e) {}
    if (active) buildScene();
    return true;
  }
  function renderHud() {
    if (!hudEl || !hudBody) return;
    const ae = document.activeElement;
    if (ae && ae.tagName === 'INPUT' && ae.type === 'text' && hudEl.contains(ae)) return;
    hudBody.textContent = '';
    const nd = getVar('NODE_DATA') || {};
    const ro = isViewOnly();

    const act = activeLayerList();
    const on = act ? new Set(act) : null;
    const counts = { layer1: 0, layer2: 0, layer3: 0, layer4: 0 };
    for (const id in nd) { const n = nd[id] || {}; let L = n.layer || 'layer1'; if (LAYER_ALIAS[L]) L = LAYER_ALIAS[L]; if (counts[L] !== undefined) counts[L]++; }
    const ls = hudSection('Layers', hudBody);
    LAYER_IDS.forEach(function (L, i) {
      const cb = document.createElement('input'); cb.type = 'checkbox';
      cb.checked = on ? on.has(L) : true;
      cb.disabled = !on || !document.getElementById('layer-' + (i + 1));
      cb.style.cssText = 'flex:0 0 auto;margin:0';
      cb.addEventListener('change', function () { hudSetLayer(i + 1, cb.checked); });
      const nameEl = document.getElementById('layer-' + (i + 1) + '-label');
      const nm = (nameEl && nameEl.textContent.trim()) || ('Layer ' + (i + 1));
      hudRow(ls, null, cb, nm + '  (' + counts[L] + ')');
    });
    hudNote('Hidden layers are dimmed to 25 %, not removed, the same as 2D, and they stay selectable. Layer visibility is local to you: it is never saved or shared.', ls);

    const eMap = getVar('EDGE_LEGEND') || {};
    const el = ((getVar('EDGE_DATA') || {}).list) || [];
    const eSeen = Object.create(null), eColors = [];
    el.forEach(function (e) { const c = e && e.color; if (c && !eSeen[c]) { eSeen[c] = 1; eColors.push(c); } });
    const lg = hudSection('Line legend', hudBody);
    if (!eColors.length) hudNote('No coloured connections yet.', lg);
    eColors.forEach(function (c) {
      const inp = hudLabelInput(eMap[c] == null ? '' : eMap[c], HUD_EDGE_DEFAULT, function () { hudCommitLegend('EDGE_LEGEND', c, inp); });
      inp.disabled = ro;
      hudRow(lg, c, inp, null);
    });

    const zMap = getVar('ZONE_LEGEND') || {};
    const zSeen = Object.create(null), zColors = [];
    for (const id in nd) { const n = nd[id] || {}; const c = n.fovColor; if (c && isTrue(n.fovEnabled) && hasCoverageZone(n.shape) && !zSeen[c]) { zSeen[c] = 1; zColors.push(c); } }
    const zg = hudSection('Zone legend', hudBody);
    if (!zColors.length) hudNote('No coverage zones yet.', zg);
    zColors.forEach(function (c) {
      const inp = hudLabelInput(zMap[c] == null ? '' : zMap[c], HUD_ZONE_DEFAULT, function () { hudCommitLegend('ZONE_LEGEND', c, inp); });
      inp.disabled = ro;
      hudRow(zg, c, inp, null);
    });
    hudNote(ro ? 'View Only is on, legend labels are read only.' : 'Legend labels are shared. The 2D legend picks up a rename on its next render.', zg);
  }

  let bookEl = null, bookBody = null, bookTitle = null, bookSave = null;
  function ensureBook() {
    if (bookEl) return;
    bookEl = document.createElement('div');
    bookEl.id = 'threed-book';
    bookEl.setAttribute('role', 'dialog');
    bookEl.setAttribute('aria-modal', 'true');
    bookEl.setAttribute('aria-labelledby', 'threed-book-title');
    bookEl.addEventListener('keydown', onBookKey);
    bookEl.style.cssText = 'position:absolute;right:14px;top:14px;bottom:88px;width:310px;z-index:6;display:none;flex-direction:column;background:linear-gradient(#f5ecd6,#e9dbb8);border:2px solid #b9a06a;border-radius:10px;box-shadow:0 12px 40px rgba(0,0,0,.6);font:13px/1.4 Georgia,\'Times New Roman\',serif;color:#2a2417';
    const hdr = document.createElement('div');
    hdr.style.cssText = 'padding:10px 14px;border-bottom:1px solid #d3bf8f;font-weight:700;font-size:15px;color:#5a4a2a;display:flex;justify-content:space-between;align-items:center;flex:0 0 auto';
    bookTitle = document.createElement('span'); bookTitle.id = 'threed-book-title'; bookTitle.textContent = '📖 Edit'; hdr.appendChild(bookTitle);
    const x = document.createElement('button'); x.type = 'button'; x.textContent = '✕';
    x.setAttribute('aria-label', 'Close the editor');
    x.style.cssText = 'cursor:pointer;color:#8a7a5a;font-family:system-ui;background:none;border:none;font-size:15px;line-height:1'
      + (COARSE_POINTER ? ';min-width:44px;min-height:44px' : '');
    x.onclick = closeBook; hdr.appendChild(x);
    bookEl.appendChild(hdr);
    bookBody = document.createElement('div'); bookBody.style.cssText = 'padding:6px 14px;overflow-y:auto;flex:1 1 auto'; bookEl.appendChild(bookBody);
    const ft = document.createElement('div');
    ft.style.cssText = 'padding:10px 14px;border-top:1px solid #d3bf8f;display:flex;gap:8px;justify-content:flex-end;flex:0 0 auto';
    const cancel = document.createElement('button'); cancel.textContent = 'Cancel'; cancel.style.cssText = 'padding:6px 14px;border:1px solid #b9a06a;border-radius:6px;background:#e9dbb8;color:#5a4a2a;cursor:pointer;font-family:system-ui'; cancel.onclick = closeBook;
    bookSave = document.createElement('button'); bookSave.textContent = 'Save'; bookSave.style.cssText = 'padding:6px 18px;border:none;border-radius:6px;background:#6b8e23;color:#fff;font-weight:700;cursor:pointer;font-family:system-ui';
    ft.appendChild(cancel); ft.appendChild(bookSave); bookEl.appendChild(ft);
    overlay.appendChild(bookEl);
  }
  let bookReturnFocus = null;
  const BOOK_FOCUSABLE = 'button, [href], input, select, textarea, summary, [tabindex]:not([tabindex="-1"])';
  function bookFocusables() {
    if (!bookEl) return [];
    const all = bookEl.querySelectorAll(BOOK_FOCUSABLE);
    const out = [];
    for (let i = 0; i < all.length; i++) {
      const el = all[i];
      if (el.disabled) continue;
      if (el.offsetParent === null && el !== bookEl) continue;
      out.push(el);
    }
    return out;
  }
  function onBookKey(e) {
    if (!bookEl || bookEl.style.display !== 'flex') return;
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closeBook(); return; }
    if (e.key !== 'Tab') return;
    const items = bookFocusables();
    if (!items.length) return;
    let cur = -1;
    for (let i = 0; i < items.length; i++) if (items[i] === document.activeElement) { cur = i; break; }
    const next = focusTrapNext(items.length, cur, e.shiftKey);
    if (cur === -1 || (e.shiftKey && cur === 0) || (!e.shiftKey && cur === items.length - 1)) {
      e.preventDefault(); e.stopPropagation();
      if (next >= 0 && items[next]) items[next].focus();
    }
  }
  function showBook() {
    if (!bookEl) return;
    bookReturnFocus = (document.activeElement && document.activeElement !== document.body) ? document.activeElement : canvas;
    bookEl.style.display = 'flex';
    const items = bookFocusables();
    try { (items[0] || bookEl).focus(); } catch (e) {}
    announce((bookTitle ? bookTitle.textContent : 'Editor') + ' dialog opened. Press Escape to close.');
  }
  function closeBook() {
    if (!bookEl) return;
    const wasOpen = bookEl.style.display === 'flex';
    bookEl.style.display = 'none';
    if (!wasOpen) return;
    const back = bookReturnFocus; bookReturnFocus = null;
    try { if (back && back.isConnected !== false && typeof back.focus === 'function') back.focus(); else if (canvas) canvas.focus(); } catch (e) {}
    announce('Editor closed.');
  }
  function bookField(label, el, parent) {
    const row = document.createElement('label'); row.style.cssText = 'display:block;margin:7px 0';
    const l = document.createElement('div'); l.style.cssText = 'font-size:11px;color:#7c6a44;margin-bottom:2px;font-weight:700;font-family:system-ui'; l.textContent = label;
    row.appendChild(l); row.appendChild(el); (parent || bookBody).appendChild(row); return el;
  }
  function bookGroup(label, open) {
    const d = document.createElement('details'); d.open = !!open;
    d.style.cssText = 'margin:8px 0;border:1px solid #d3bf8f;border-radius:7px;background:rgba(255,253,245,.5)';
    const s = document.createElement('summary');
    s.style.cssText = 'padding:6px 10px;cursor:pointer;font:700 12px system-ui;color:#5a4a2a;letter-spacing:.02em;user-select:none';
    s.textContent = label; d.appendChild(s);
    const body = document.createElement('div'); body.style.cssText = 'padding:0 10px 8px'; d.appendChild(body);
    bookBody.appendChild(d); return { el: d, body: body };
  }
  function bookNote(txt, parent) {
    const d = document.createElement('div'); d.style.cssText = 'font-size:11px;color:#7c6a44;margin:2px 0 7px;line-height:1.35';
    d.textContent = txt; (parent || bookBody).appendChild(d); return d;
  }
  function bookBtn(txt, parent) {
    const b = document.createElement('button'); b.type = 'button'; b.textContent = txt;
    b.style.cssText = 'padding:5px 10px;border:1px solid #b9a06a;border-radius:5px;background:#e9dbb8;color:#5a4a2a;cursor:pointer;font:600 12px system-ui;margin:2px 0 7px';
    (parent || bookBody).appendChild(b); return b;
  }
  function bookTrack(el) { el.__book0 = el.type === 'checkbox' ? el.checked : el.value; return el; }
  function bookChanged(el) { return !!el && (el.type === 'checkbox' ? el.checked !== el.__book0 : el.value !== el.__book0); }
  function bookApply(obj, key, el, co, keepBlank) {
    if (!bookChanged(el)) return;
    if (el.type === 'checkbox') { obj[key] = el.checked; return; }
    if (el.value === '' && !keepBlank) { delete obj[key]; return; }
    obj[key] = co ? co(el.value) : el.value;
  }
  function bookApplyNum(obj, key, el, co) { if (bookChanged(el) && el.value !== '') obj[key] = co(el.value); }
  const bookInt = (lo, hi, fb) => (v) => clamp(Math.round(num(v, fb)), lo, hi);
  const BOOK_INP = 'width:100%;padding:5px 7px;border:1px solid #cbb78f;border-radius:5px;background:#fffdf5;color:#2a2417;font:13px system-ui;box-sizing:border-box';
  function bookInput(type, value) {
    const i = document.createElement('input'); i.type = type;
    if (type === 'checkbox') { i.checked = !!value; i.style.cssText = 'transform:scale(1.3);margin-top:3px'; }
    else if (type === 'color') { i.value = value || '#000000'; i.style.cssText = 'width:52px;height:30px;border:1px solid #cbb78f;border-radius:5px;background:#fffdf5;cursor:pointer'; }
    else { i.value = value == null ? '' : value; i.style.cssText = BOOK_INP; }
    return i;
  }
  function bookSelect(options, value) {
    const s = document.createElement('select'); s.style.cssText = BOOK_INP;
    options.forEach((o) => { const val = Array.isArray(o) ? o[0] : o, lab = Array.isArray(o) ? o[1] : o; const opt = document.createElement('option'); opt.value = val; opt.textContent = lab; if (val === value) opt.selected = true; s.appendChild(opt); });
    return s;
  }
  function bookTextarea(value) { const t = document.createElement('textarea'); t.rows = 3; t.value = value || ''; t.style.cssText = BOOK_INP + ';resize:vertical'; return t; }
  function notesToText(arr) { return Array.isArray(arr) ? arr.map((x) => (typeof x === 'string' ? x : (x && x.content) || '')).join('\n') : ''; }
  function notesFromText(v) { return String(v == null ? '' : v).split('\n').map((s) => s.trim()).filter(Boolean); }
  function openNodeBook(id) {
    const nd = getVar('NODE_DATA'); if (!nd || !nd[id]) return;
    const n = nd[id], isRack = isTrue(n.isRack);
    const ps = getVar('PAGE_STATE') || {};
    const styles = getVar('savedStyles') || {};
    const stA = styles[id] && styles[id].all, stAll = stA && typeof stA === 'object' ? stA : {};
    const stRes = bookResolveStyles(styles[id]);
    const sv0 = (k, dflt) => (stAll[k] !== undefined ? stAll[k] : stRes[k] !== undefined ? stRes[k] : dflt);
    const ping = n.ping || {};
    const cd = coverageDefaults(n.shape);
    ensureBook(); bookBody.textContent = ''; bookTitle.textContent = isRack ? '📖 Edit rack' : '📖 Edit node';
    const f = {}, T = bookTrack;

    const gId = bookGroup('Identity', true).body;
    f.name = T(bookField('Name', bookInput('text', n.name), gId));
    f.ip = T(bookField('IP / address (the node subtitle in 2D)', bookInput('text', n.ip), gId));
    f.mac = T(bookField('MAC', bookInput('text', n.mac), gId));
    f.role = T(bookField('Role', bookInput('text', n.role), gId));
    f.cat = bookField('Icon category', bookSelect(BOOK_CATEGORY_OPTS, bookFindCategory(n.shape)), gId);
    f.shape = bookField('Shape', bookSelect([], ''), gId);
    function fillShapes(cat, keep) {
      const list = (BOOK_SHAPE_CATEGORIES[cat] || BOOK_SHAPE_CATEGORIES.basic).slice();
      if (keep && !list.some((o) => o[0] === keep)) list.unshift([keep, keep + ' (current)']);
      f.shape.textContent = '';
      list.forEach((o) => { const el = document.createElement('option'); el.value = o[0]; el.textContent = o[1]; f.shape.appendChild(el); });
      f.shape.value = keep && list.some((o) => o[0] === keep) ? keep : list[0][0];
    }
    fillShapes(f.cat.value, n.shape); T(f.shape);
    f.cat.onchange = function () { fillShapes(this.value, f.shape.value); syncCoverage(); };
    f.shape.onchange = syncCoverage;
    f.layer = T(bookField('Layer', bookSelect(BOOK_LAYERS, n.layer || 'layer1'), gId));
    if (isRack) f.rackCap = T(bookField('Rack capacity (U)', bookSelect(BOOK_RACK_CAPS, String(n.rackCapacity || '42')), gId));
    f.tags = T(bookField('Tags (comma separated)', bookInput('text', (Array.isArray(n.tags) ? n.tags.filter((t) => typeof t === 'string') : []).join(', ')), gId));
    const iconTags = (Array.isArray(n.tags) ? n.tags : []).filter((t) => t && typeof t === 'object');
    if (iconTags.length) {
      bookNote('Icon tags (kept on save; ✕ removes)', gId);
      const row = document.createElement('div'); row.style.cssText = 'display:flex;flex-wrap:wrap;gap:5px;margin:0 0 7px'; gId.appendChild(row);
      iconTags.slice().forEach((tg) => {
        const b = document.createElement('span');
        b.style.cssText = 'display:inline-flex;align-items:center;gap:5px;padding:3px 7px;border:1px solid #cbb78f;border-radius:5px;background:#fffdf5;font:12px system-ui;color:#5a4a2a';
        b.textContent = String(tg.name || '?') + ' (' + String(tg.library || '?') + ')';
        const x = document.createElement('span'); x.textContent = '✕'; x.style.cssText = 'cursor:pointer;color:#a05a3c;font-weight:700';
        x.onclick = function () { const i = iconTags.indexOf(tg); if (i > -1) iconTags.splice(i, 1); b.remove(); };
        b.appendChild(x); row.appendChild(b);
      });
    }
    f.notes = T(bookField('Notes (one per line)', bookTextarea(Array.isArray(n.notes) ? n.notes.map((x) => (typeof x === 'string' ? x : (x && x.content) || '')).join('\n') : ''), gId));

    const gAp = bookGroup('Appearance', true).body;
    f.fill = T(bookField('Fill colour', bookInput('color', sv0('circleColor', ps.nodeFill || '#1e293b')), gAp));
    f.border = T(bookField('Border colour', bookInput('color', sv0('circleBorder', ps.nodeStroke || '#475569')), gAp));
    const cache = getVar('iconCache') || {};
    const curIcon = stAll.icon && stAll.icon.library && stAll.icon.name ? stAll.icon : null;
    const iconOpts = [['', '(none, use the shape)']];
    Object.keys(cache).forEach((k) => {
      const lib = BOOK_ICON_LIBS.filter((L) => k.indexOf(L + '-') === 0).sort((a, b) => b.length - a.length)[0];
      if (!lib) return; const nm = k.slice(lib.length + 1); if (!nm) return;
      const v = lib + '/' + nm; if (!iconOpts.some((o) => o[0] === v)) iconOpts.push([v, nm + '  (' + lib + ')']);
    });
    const curIconV = curIcon ? curIcon.library + '/' + curIcon.name : '';
    if (curIconV && !iconOpts.some((o) => o[0] === curIconV)) iconOpts.splice(1, 0, [curIconV, curIcon.name + '  (' + curIcon.library + ', current)']);
    f.icon = T(bookField('Web icon (already loaded in this map)', bookSelect(iconOpts, curIconV), gAp));
    f.iconCustom = T(bookField('…or type library/name', bookInput('text', ''), gAp));
    bookNote('Libraries: ' + BOOK_ICON_LIBS.join(', ') + ', e.g. selfhst/plex. Typing here wins over the picker.', gAp);

    const gTx = bookGroup('Title & subtitle', false).body;
    f.titleColor = T(bookField('Title colour', bookInput('color', sv0('titleColor', ps.nodeTitle || '#e2e8f0')), gTx));
    f.titleFont = T(bookField('Title font', bookSelect(BOOK_FONTS, sv0('titleFont', '')), gTx));
    f.titleSize = T(bookField('Title size (blank = auto)', bookInput('number', stAll.titleSize != null ? stAll.titleSize : ''), gTx));
    f.titleOX = T(bookField('Title offset X', bookInput('number', stAll.titleOffsetX || 0), gTx));
    f.titleOY = T(bookField('Title offset Y', bookInput('number', stAll.titleOffsetY || 0), gTx));
    f.subColor = T(bookField('Subtitle colour', bookInput('color', sv0('subColor', ps.nodeSub || '#94a3b8')), gTx));
    f.subFont = T(bookField('Subtitle font', bookSelect(BOOK_FONTS, sv0('subFont', '')), gTx));
    f.subSize = T(bookField('Subtitle size (blank = auto)', bookInput('number', stAll.subSize != null ? stAll.subSize : ''), gTx));
    f.subOX = T(bookField('Subtitle offset X', bookInput('number', stAll.subOffsetX || 0), gTx));
    f.subOY = T(bookField('Subtitle offset Y', bookInput('number', stAll.subOffsetY || 0), gTx));
    bookNote('The subtitle text is the IP / address field under Identity.', gTx);

    const gPg = bookGroup('Status monitoring', !!ping.enabled).body;
    f.ping = T(bookField('Status monitoring (ping)', bookInput('checkbox', ping.enabled), gPg));
    f.proto = T(bookField('Ping protocol', bookSelect(BOOK_PING_PROTOS, ping.protocol || 'http'), gPg));
    f.pingUrl = T(bookField('Custom URL (protocol = custom)', bookInput('text', ping.customUrl || ''), gPg));
    f.pingTo = T(bookField('Timeout (ms)', bookInput('number', ping.timeout || 3000), gPg));
    bookNote('Status: ' + (ping.enabled ? (ping.status || 'unknown') : 'monitoring off'), gPg);
    if (typeof getVar('checkNodeStatus') === 'function') {
      const cb = bookBtn('Check status now', gPg);
      cb.onclick = function () { const fn = getVar('checkNodeStatus'); if (typeof fn === 'function') { try { fn(id); } catch (e) {} } };
    }

    const secFov = bookGroup('Coverage (FOV)', isTrue(n.fovEnabled));
    const gFv = secFov.body;
    f.fov = T(bookField('Show coverage zone', bookInput('checkbox', n.fovEnabled), gFv));
    f.fovA = T(bookField('Angle (10 to 360°)', bookInput('number', n.fovAngle || cd.angle), gFv));
    f.fovD = T(bookField('Distance (50 to 500)', bookInput('number', n.fovDistance || cd.distance), gFv));
    f.fovInner = T(bookField('Inner radius (0 to 200)', bookInput('number', n.fovInnerRadius || 0), gFv));
    f.fovRot = T(bookField('Zone rotation (0 to 360°)', bookInput('number', n.fovRotation || 0), gFv));
    f.fovColor = T(bookField('Fill colour', bookInput('color', n.fovColor || '#f59e0b'), gFv));
    f.fovOp = T(bookField('Fill opacity (5 to 80%)', bookInput('number', n.fovOpacity || 20), gFv));
    f.fovGrad = T(bookField('Gradient (fade toward edge, 2D)', bookInput('checkbox', n.fovGradient), gFv));
    f.fovBC = T(bookField('Border colour', bookInput('color', n.fovBorderColor || '#f59e0b'), gFv));
    f.fovBW = T(bookField('Border width (0 to 10)', bookInput('number', n.fovBorderWidth !== undefined ? n.fovBorderWidth : 2), gFv));
    f.fovBS = T(bookField('Border style', bookSelect(BOOK_FOV_BORDER_STYLES, n.fovBorderStyle || 'solid'), gFv));
    f.fovBO = T(bookField('Border opacity (0 to 100%)', bookInput('number', n.fovBorderOpacity !== undefined ? n.fovBorderOpacity : 100), gFv));
    f.fovAnim = T(bookField('Animate', bookInput('checkbox', n.fovAnimate), gFv));
    f.fovAnimT = T(bookField('Animation type', bookSelect(BOOK_FOV_ANIMS, n.fovAnimationType || cd.animationType), gFv));
    f.fovSweep = T(bookField('Sweep (30 to 360°)', bookInput('number', n.fovSweep || 120), gFv));
    f.fovSpeed = T(bookField('Speed (1 to 60 s)', bookInput('number', n.fovSpeed || 4), gFv));
    bookNote('3D draws the cone, inner radius, colour, opacity and the animations. Gradient and border width/style/opacity are 2D only.', gFv);

    const secLbl = bookGroup('Coverage label', false);
    const gLb = secLbl.body;
    f.fovLbl = T(bookField('Label text', bookInput('text', n.fovLabel || ''), gLb));
    f.fovLP = T(bookField('Label position', bookSelect(BOOK_FOV_LABEL_POS, n.fovLabelPosition || 'center'), gLb));
    f.fovLS = T(bookField('Label size (8 to 32px)', bookInput('number', n.fovLabelSize || 14), gLb));
    f.fovLC = T(bookField('Label colour', bookInput('color', n.fovLabelColor || '#ffffff'), gLb));
    f.fovLB = T(bookField('Label bold', bookInput('checkbox', n.fovLabelBold), gLb));
    f.fovLBg = T(bookField('Label background', bookInput('checkbox', n.fovLabelBg), gLb));
    f.fovLBgC = T(bookField('Label background colour', bookInput('color', n.fovLabelBgColor || '#000000'), gLb));
    f.fovLOX = T(bookField('Label offset X (−200 to 200)', bookInput('number', n.fovLabelOffsetX || 0), gLb));
    f.fovLOY = T(bookField('Label offset Y (−200 to 200)', bookInput('number', n.fovLabelOffsetY || 0), gLb));
    bookNote('3D billboards the label at the node using its colour and offsets; position/size/bold/background are 2D only.', gLb);

    const fovHint = bookNote('', gFv);
    function syncCoverage() {
      const ok = hasCoverageZone(f.shape.value);
      secFov.el.style.opacity = secLbl.el.style.opacity = ok ? '1' : '.55';
      fovHint.textContent = ok ? '' : 'This shape has no coverage zone in 2D, the cone is not drawn until you pick a camera / sensor / wireless shape.';
      fovHint.style.display = ok ? 'none' : '';
    }
    syncCoverage();

    const gPl = bookGroup('Placement', true).body;
    f.elev = T(bookField('Elevation (height off floor)', bookInput('number', (scene3d.heights || {})[id] || 0), gPl));
    f.rot = T(bookField('Rotation (°)', bookInput('number', n.rotation || 0), gPl));
    f.trail = T(bookField('Motion trail', bookInput('checkbox', n.trailEnabled !== false), gPl));
    if (!isRack) {
      const sizes0 = getVar('savedSizes') || {};
      f.size = T(bookField('Size', bookInput('number', sizes0[id] || 55), gPl));
      const rackOpts = [['', '(none)']].concat(Object.keys(nd).filter((k) => k !== id && isTrue(nd[k].isRack)).map((k) => [k, nd[k].name || k]));
      const hostOpts = [['', '(none)']].concat(Object.keys(nd).filter((k) => k !== id && !isTrue(nd[k].isRack)).map((k) => [k, nd[k].name || k]));
      f.rack = T(bookField('Mounted in rack', bookSelect(rackOpts, n.assignedRack || ''), gPl));
      f.rackUnit = T(bookField('Rack U position', bookInput('number', n.rackUnit || ''), gPl));
      f.uHeight = T(bookField('U height (slots)', bookInput('number', n.uHeight || '1'), gPl));
      f.host = T(bookField('Hosted on', bookSelect(hostOpts, n.hostedOn || ''), gPl));
    }
    bookSave.onclick = function () {
      const cur = getVar('NODE_DATA'); if (!cur || !cur[id]) { closeBook(); return; }
      const node = cur[id];
      const push = getVar('pushUndo'); if (typeof push === 'function') { try { push('edit node (3D)'); } catch (e) {} }
      node.name = f.name.value; node.ip = f.ip.value; node.mac = f.mac.value; node.role = f.role.value; node.layer = f.layer.value;
      bookApply(node, 'shape', f.shape, null, true);
      if (isRack && f.rackCap) node.rackCapacity = f.rackCap.value;
      node.tags = f.tags.value.split(',').map((t) => t.trim()).filter(Boolean).concat(iconTags);
      node.notes = f.notes.value.split('\n').map((s) => s.trim()).filter(Boolean);
      const pg = Object.assign({ protocol: 'http', customUrl: '', timeout: 3000, status: 'unknown', lastCheck: null }, node.ping || {}, { enabled: f.ping.checked, protocol: f.proto.value });
      bookApply(pg, 'customUrl', f.pingUrl, (v) => v.trim(), true);
      bookApply(pg, 'timeout', f.pingTo, bookInt(1000, 10000, 3000));
      node.ping = pg;
      const wasFov = isTrue(node.fovEnabled);
      bookApply(node, 'fovEnabled', f.fov);
      if (!wasFov && f.fov.checked && !node.fovColor) node.fovColor = f.fovColor.value || '#f59e0b';
      const cdS = coverageDefaults(node.shape);
      bookApply(node, 'fovAngle', f.fovA, bookInt(10, 360, cdS.angle));
      bookApply(node, 'fovDistance', f.fovD, bookInt(50, 500, cdS.distance));
      bookApply(node, 'fovInnerRadius', f.fovInner, bookInt(0, 200, 0));
      bookApply(node, 'fovRotation', f.fovRot, bookInt(0, 360, 0));
      bookApply(node, 'fovColor', f.fovColor);
      bookApply(node, 'fovOpacity', f.fovOp, bookInt(5, 80, 20));
      bookApply(node, 'fovGradient', f.fovGrad);
      bookApply(node, 'fovBorderColor', f.fovBC);
      bookApply(node, 'fovBorderWidth', f.fovBW, bookInt(0, 10, 2));
      bookApply(node, 'fovBorderStyle', f.fovBS);
      bookApply(node, 'fovBorderOpacity', f.fovBO, bookInt(0, 100, 100));
      bookApply(node, 'fovAnimate', f.fovAnim);
      bookApply(node, 'fovAnimationType', f.fovAnimT);
      bookApply(node, 'fovSweep', f.fovSweep, bookInt(30, 360, 120));
      bookApply(node, 'fovSpeed', f.fovSpeed, bookInt(1, 60, 4));
      bookApply(node, 'fovLabel', f.fovLbl, null, true);
      bookApply(node, 'fovLabelPosition', f.fovLP);
      bookApply(node, 'fovLabelSize', f.fovLS, bookInt(8, 32, 14));
      bookApply(node, 'fovLabelColor', f.fovLC);
      bookApply(node, 'fovLabelBold', f.fovLB);
      bookApply(node, 'fovLabelBg', f.fovLBg);
      bookApply(node, 'fovLabelBgColor', f.fovLBgC);
      bookApply(node, 'fovLabelOffsetX', f.fovLOX, bookInt(-200, 200, 0));
      bookApply(node, 'fovLabelOffsetY', f.fovLOY, bookInt(-200, 200, 0));
      bookApply(node, 'rotation', f.rot, bookInt(-360, 360, 0));
      bookApply(node, 'trailEnabled', f.trail);
      if (!isRack) {
        if (f.size) { const sz = getVar('savedSizes') || {}; sz[id] = clamp(num(f.size.value, 55), 8, 400); setVar('savedSizes', sz); }
        { const rv = f.rack.value; node.assignedRack = (rv && cur[rv] && isTrue(cur[rv].isRack)) ? rv : ''; }
        if (!node.assignedRack) { const spx = getVar('savedPositions') || {}; if (!spx[id]) { const or = spx[n.assignedRack]; spx[id] = or ? { x: Math.round(clamp(or.x + 160, PAD, WORLD_W - PAD)), y: or.y } : { x: 2000, y: 1500 }; setVar('savedPositions', spx); } }
        node.rackUnit = f.rackUnit.value === '' ? '' : String(Math.max(1, Math.round(num(f.rackUnit.value, 1))));
        node.uHeight = f.uHeight.value === '' ? '1' : String(Math.max(1, Math.round(num(f.uHeight.value, 1))));
        node.hostedOn = f.host.value;
      }
      const styleEls = [f.fill, f.border, f.titleColor, f.titleFont, f.titleSize, f.titleOX, f.titleOY, f.subColor, f.subFont, f.subSize, f.subOX, f.subOY, f.icon, f.iconCustom];
      if (styleEls.some((el) => bookChanged(el))) {
        const sv = getVar('savedStyles') || {};
        const all = bookStyleScope(sv, id);
        bookApply(all, 'circleColor', f.fill);
        bookApply(all, 'circleBorder', f.border);
        bookApply(all, 'titleColor', f.titleColor);
        bookApply(all, 'titleFont', f.titleFont);
        bookApply(all, 'titleSize', f.titleSize, bookInt(8, 100, 18));
        bookApply(all, 'titleOffsetX', f.titleOX, bookInt(-100, 100, 0));
        bookApply(all, 'titleOffsetY', f.titleOY, bookInt(-100, 100, 0));
        bookApply(all, 'subColor', f.subColor);
        bookApply(all, 'subFont', f.subFont);
        bookApply(all, 'subSize', f.subSize, bookInt(6, 80, 13));
        bookApply(all, 'subOffsetX', f.subOX, bookInt(-100, 100, 0));
        bookApply(all, 'subOffsetY', f.subOY, bookInt(-100, 100, 0));
        const typed = f.iconCustom.value.trim();
        if (bookChanged(f.iconCustom) && typed) {
          const cut = typed.indexOf('/');
          const lib = cut > 0 ? typed.slice(0, cut).trim() : '', nm = cut > 0 ? typed.slice(cut + 1).trim() : '';
          if (lib && nm) all.icon = { library: lib, name: nm };
        } else if (bookChanged(f.icon)) {
          const cut = f.icon.value.indexOf('/');
          if (cut > 0) all.icon = { library: f.icon.value.slice(0, cut), name: f.icon.value.slice(cut + 1) };
          else delete all.icon;
        }
        setVar('savedStyles', sv);
      }
      const elevV = clamp(num(f.elev.value, 0), 0, MAX_ELEVATION);
      scene3d.heights = scene3d.heights || {};
      if (elevV) scene3d.heights[id] = elevV; else delete scene3d.heights[id];
      if (sceneReady) { scheduleSave(); broadcastFurn({ op: 'height', id: id, y: elevV }); }
      setVar('NODE_DATA', cur);
      const forge = getVar('forgeTheTopology') || window.forgeTheTopology; if (typeof forge === 'function') { try { forge(); } catch (e) {} }
      closeBook(); buildScene();
    };
    showBook();
  }
  function openFurnBook(id) {
    const fi = scene3d.furniture.find((x) => x.id === id); if (!fi) return;
    ensureBook(); bookBody.textContent = ''; bookTitle.textContent = '📖 Edit furniture';
    const f = {};
    f.kind = bookField('Kind', bookSelect(['table', 'shelf', 'lamp', 'wall', 'plant', 'frame', 'model'], fi.kind));
    f.scale = bookField('Scale (0.2 to 6)', bookInput('number', fi.scale || 1));
    f.rot = bookField('Rotation (°)', bookInput('number', Math.round((fi.rotY || 0) * 180 / Math.PI)));
    f.color = bookField('Colour', bookInput('color', fi.color || '#8b5e3c'));
    let pendingImage = fi.image || null, pendingModel = fi.model || null;
    if (fi.kind === 'frame') {
      const up = bookField('Image', bookInput('file'));
      up.accept = 'image/*';
      const status = document.createElement('div'); status.style.cssText = 'font-size:11px;color:#7c6a44;margin:-4px 0 6px'; status.textContent = fi.image ? 'image set ✓' : 'no image yet'; bookBody.appendChild(status);
      up.addEventListener('change', function () {
        const file = up.files && up.files[0]; if (!file) return;
        if (file.size > 3 * 1024 * 1024) { status.textContent = 'too large (max 3 MB)'; return; }
        status.textContent = 'uploading…';
        fetch('/api/room/' + ROOM_ID + '/asset', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': file.type || 'application/octet-stream', 'x-csrf-token': window.CSRF_TOKEN || '' }, body: file })
          .then(function (r) { return r.ok ? r.json() : r.json().then(function (e) { throw new Error(e.error || 'upload failed'); }); })
          .then(function (j) { pendingImage = j.hash; status.textContent = 'uploaded ✓'; })
          .catch(function (e) { status.textContent = 'error: ' + e.message; });
      });
    }
    if (fi.kind === 'model') {
      const up = bookField('3D model (.glb)', bookInput('file'));
      up.accept = '.glb,model/gltf-binary';
      const status = document.createElement('div'); status.style.cssText = 'font-size:11px;color:#7c6a44;margin:-4px 0 6px'; status.textContent = fi.model ? 'model set ✓' : 'no model yet'; bookBody.appendChild(status);
      up.addEventListener('change', function () {
        const file = up.files && up.files[0]; if (!file) return;
        if (file.size > 12 * 1024 * 1024) { status.textContent = 'too large (max 12 MB)'; return; }
        status.textContent = 'uploading…';
        fetch('/api/room/' + ROOM_ID + '/asset', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'model/gltf-binary', 'x-csrf-token': window.CSRF_TOKEN || '' }, body: file })
          .then(function (r) { return r.ok ? r.json() : r.json().then(function (e) { throw new Error(e.error || 'upload failed'); }); })
          .then(function (j) { pendingModel = j.hash; status.textContent = 'uploaded ✓ (Save to apply)'; })
          .catch(function (e) { status.textContent = 'error: ' + e.message; });
      });
    }
    bookSave.onclick = function () {
      if (!sceneReady) { closeBook(); return; }
      const cur = scene3d.furniture.find((x) => x.id === fi.id); if (!cur) { closeBook(); return; }
      cur.kind = FURN_KINDS.has(f.kind.value) ? f.kind.value : cur.kind;
      cur.scale = clamp(num(f.scale.value, 1), 0.2, 6);
      cur.rotY = wrapAngle(num(f.rot.value, 0) * Math.PI / 180);
      cur.color = f.color.value;
      if (pendingImage && HEX64_RE.test(pendingImage)) cur.image = pendingImage;
      if (pendingModel && HEX64_RE.test(pendingModel)) cur.model = pendingModel;
      scheduleSave(); closeBook(); buildScene(); broadcastFurn({ op: 'update', item: cur });
    };
    showBook();
  }
  function openRectBook(id) {
    const rd = getVar('RECT_DATA'); const r0 = rd && Array.isArray(rd.list) && rd.list.find((x) => x && x.id === id); if (!r0) return;
    const isWall = r0.lineStyle === 'wall';
    ensureBook(); bookBody.textContent = ''; bookTitle.textContent = '📖 Edit ' + (isWall ? 'wall' : 'zone');
    const f = {}, T = bookTrack;
    const gSh = bookGroup('Shape', true).body;
    f.lineStyle = T(bookField('Type', bookSelect([['wall', 'Wall'], ['solid', 'Zone (solid border)'], ['dashed', 'Zone (dashed)'], ['dotted', 'Zone (dotted)']], r0.lineStyle || 'solid'), gSh));
    f.style = T(bookField('Fill', bookSelect([['filled', 'Filled'], ['outlined', 'Outlined']], r0.style || 'filled'), gSh));
    f.width = T(bookField('Width', bookInput('number', Math.round(num(r0.width, 400))), gSh));
    f.height = T(bookField('Height', bookInput('number', Math.round(num(r0.height, 300))), gSh));
    f.rot = T(bookField('Rotation (°)', bookInput('number', num(r0.rotation, 0)), gSh));
    f.wallH = T(bookField('Wall height (3D only, walls)', bookInput('number', num((scene3d.wallHeights || {})[id], WALL_HEIGHT_3D)), gSh));

    const gAp = bookGroup('Appearance', true).body;
    f.color = T(bookField('Colour', bookInput('color', r0.color || '#f97316'), gAp));
    f.border = T(bookField('Border colour', bookInput('color', r0.borderColor || r0.color || '#f97316'), gAp));
    f.borderW = T(bookField('Border width (0 to 20)', bookInput('number', r0.borderWidth !== undefined ? r0.borderWidth : 2), gAp));
    f.fillOpacity = T(bookField('Fill opacity (0 to 1)', bookInput('number', r0.fillOpacity !== undefined ? r0.fillOpacity : (isWall ? 0.5 : 0.3)), gAp));
    bookNote('Border width widens the 3D outline once it exceeds the 2D default of 2; a dashed/dotted zone border keeps its dash pattern instead. 0 hides the border, exactly as in 2D.', gAp);

    const gNt = bookGroup('Notes', false).body;
    f.notes = T(bookField('Notes (one per line)', bookTextarea(notesToText(r0.notes)), gNt));
    bookSave.onclick = function () {
      const cur = getVar('RECT_DATA'); const r = cur && Array.isArray(cur.list) && cur.list.find((x) => x && x.id === id); if (!r) { closeBook(); return; }
      const push = getVar('pushUndo'); if (typeof push === 'function') { try { push('edit rect (3D)'); } catch (e) {} }
      bookApply(r, 'lineStyle', f.lineStyle); bookApply(r, 'style', f.style); bookApply(r, 'color', f.color); bookApply(r, 'borderColor', f.border);
      bookApply(r, 'borderWidth', f.borderW, bookInt(0, 20, 2));
      bookApply(r, 'fillOpacity', f.fillOpacity, (v) => clamp(num(v, 0.3), 0, 1));
      bookApplyNum(r, 'width', f.width, (v) => Math.max(1, Math.round(num(v, 400))));
      bookApplyNum(r, 'height', f.height, (v) => Math.max(1, Math.round(num(v, 300))));
      bookApply(r, 'rotation', f.rot, bookInt(-360, 360, 0));
      if (bookChanged(f.notes)) r.notes = notesFromText(f.notes.value);
      if (bookChanged(f.wallH) && f.wallH.value !== '') {
        scene3d.wallHeights = scene3d.wallHeights || {}; const wh = clamp(num(f.wallH.value, WALL_HEIGHT_3D), MIN_WALL_HEIGHT, MAX_WALL_HEIGHT);
        if (wh !== WALL_HEIGHT_3D) scene3d.wallHeights[id] = wh; else delete scene3d.wallHeights[id];
        if (sceneReady) { scheduleSave(); broadcastFurn({ op: 'wallh', id: id, h: (wh !== WALL_HEIGHT_3D ? wh : 0) }); }
      }
      setVar('RECT_DATA', cur);
      const forge = getVar('forgeTheTopology') || window.forgeTheTopology; if (typeof forge === 'function') { try { forge(); } catch (e) {} }
      closeBook(); buildScene();
    };
    showBook();
  }
  function openTextBook(id) {
    const td = getVar('TEXT_DATA'); const t0 = td && Array.isArray(td.list) && td.list.find((x) => x && x.id === id); if (!t0) return;
    ensureBook(); bookBody.textContent = ''; bookTitle.textContent = '📖 Edit text';
    const f = {}, T = bookTrack;
    const gTx = bookGroup('Text', true).body;
    f.content = T(bookField('Text (one line per row)', bookTextarea(t0.content || ''), gTx));
    f.fontSize = T(bookField('Font size (8 to 200)', bookInput('number', num(t0.fontSize, 18)), gTx));
    f.color = T(bookField('Colour', bookInput('color', t0.color || '#e2e8f0'), gTx));
    const wCur = String(t0.fontWeight == null || t0.fontWeight === '' ? 'normal' : t0.fontWeight);
    const wOpts = [['normal', 'Normal'], ['bold', 'Bold'], ['600', 'Semi Bold'], ['300', 'Light']];
    if (!wOpts.some((o) => o[0] === wCur)) wOpts.push([wCur, wCur]);
    f.weight = T(bookField('Font weight', bookSelect(wOpts, wCur), gTx));
    f.italic = T(bookField('Italic', bookInput('checkbox', t0.fontStyle === 'italic'), gTx));
    f.align = T(bookField('Align', bookSelect([['start', 'Left'], ['middle', 'Centre'], ['end', 'Right']], t0.textAlign || 'start'), gTx));
    f.deco = T(bookField('Decoration', bookSelect([['none', 'None'], ['underline', 'Underline'], ['line-through', 'Strike through']], t0.textDecoration || 'none'), gTx));

    const gAp = bookGroup('Appearance', true).body;
    f.bg = T(bookField('Background', bookInput('checkbox', !!t0.bgEnabled), gAp));
    f.bgColor = T(bookField('Background colour', bookInput('color', t0.bgColor || '#000000'), gAp));
    f.opacity = T(bookField('Opacity (0 to 1)', bookInput('number', t0.opacity != null ? t0.opacity : 1), gAp));
    f.rot = T(bookField('Rotation (°)', bookInput('number', num(t0.rotation, 0)), gAp));
    bookNote('Rotation round trips to 2D but is not applied in 3D, a billboard always faces the viewer.', gAp);
    bookSave.onclick = function () {
      const cur = getVar('TEXT_DATA'); const t = cur && Array.isArray(cur.list) && cur.list.find((x) => x && x.id === id); if (!t) { closeBook(); return; }
      const push = getVar('pushUndo'); if (typeof push === 'function') { try { push('edit text (3D)'); } catch (e) {} }
      bookApply(t, 'content', f.content, null, true);
      bookApplyNum(t, 'fontSize', f.fontSize, bookInt(8, 200, 18));
      bookApply(t, 'color', f.color);
      bookApply(t, 'fontWeight', f.weight);
      if (bookChanged(f.italic)) t.fontStyle = f.italic.checked ? 'italic' : 'normal';
      bookApply(t, 'textAlign', f.align);
      bookApply(t, 'textDecoration', f.deco);
      bookApply(t, 'bgEnabled', f.bg);
      bookApply(t, 'bgColor', f.bgColor);
      bookApply(t, 'opacity', f.opacity, (v) => clamp(num(v, 1), 0, 1));
      bookApply(t, 'rotation', f.rot, (v) => clamp(Math.round(num(v, 0)), -360, 360));
      setVar('TEXT_DATA', cur);
      const forge = getVar('forgeTheTopology') || window.forgeTheTopology; if (typeof forge === 'function') { try { forge(); } catch (e) {} }
      closeBook(); buildScene();
    };
    showBook();
  }
  function openImageBook(id) {
    const idd = getVar('IMAGE_DATA'); const im0 = idd && Array.isArray(idd.list) && idd.list.find((x) => x && x.id === id); if (!im0) return;
    ensureBook(); bookBody.textContent = ''; bookTitle.textContent = '📖 Edit image';
    const f = {}, T = bookTrack;
    f.name = T(bookField('Name', bookInput('text', im0.name || '')));
    f.opacity = T(bookField('Opacity (10 to 100%)', bookInput('number', Math.round(num(im0.opacity, 1) * 100))));
    f.size = T(bookField('Size (20 to 200% of original)', bookInput('number', im0.baseWidth ? Math.round(num(im0.width, im0.baseWidth) / num(im0.baseWidth, 1) * 100) : 100)));
    f.border = T(bookField('Border', bookSelect([['none', 'None'], ['thin', 'Thin'], ['medium', 'Medium'], ['thick', 'Thick']], im0.border || 'none')));
    f.shadow = T(bookField('Shadow', bookSelect([['none', 'None'], ['small', 'Small'], ['medium', 'Medium'], ['large', 'Large']], im0.shadow || 'none')));
    f.notes = T(bookField('Notes (one per line)', bookTextarea(notesToText(im0.notes))));
    bookNote('Size rescales from the original upload, exactly like the 2D slider. Drag the image in 3D to move it.');
    bookSave.onclick = function () {
      const cur = getVar('IMAGE_DATA'); const im = cur && Array.isArray(cur.list) && cur.list.find((x) => x && x.id === id); if (!im) { closeBook(); return; }
      const push = getVar('pushUndo'); if (typeof push === 'function') { try { push('edit image (3D)'); } catch (e) {} }
      bookApply(im, 'name', f.name, null, true);
      bookApply(im, 'opacity', f.opacity, (v) => clamp(Math.round(num(v, 100)), 10, 100) / 100);
      bookApply(im, 'border', f.border);
      bookApply(im, 'shadow', f.shadow);
      if (bookChanged(f.size) && f.size.value !== '') {
        const scale = clamp(Math.round(num(f.size.value, 100)), 20, 200) / 100;
        const bw = im.baseWidth || im.width, bh = im.baseHeight || im.height;
        if (!im.baseWidth) im.baseWidth = im.width;
        if (!im.baseHeight) im.baseHeight = im.height;
        im.width = Math.round(num(bw, 200) * scale); im.height = Math.round(num(bh, 200) * scale);
      }
      if (bookChanged(f.notes)) im.notes = notesFromText(f.notes.value);
      setVar('IMAGE_DATA', cur);
      const forge = getVar('forgeTheTopology') || window.forgeTheTopology; if (typeof forge === 'function') { try { forge(); } catch (e) {} }
      closeBook(); buildScene();
    };
    showBook();
  }
  function openEdgeBook(id) {
    const ed = getVar('EDGE_DATA'); const e0 = ed && Array.isArray(ed.list) && ed.list.find((x) => x && x.id === id); if (!e0) return;
    ensureBook(); bookBody.textContent = ''; bookTitle.textContent = '📖 Edit connection';
    const f = {}, T = bookTrack;
    const gLn = bookGroup('Line', true).body;
    f.color = T(bookField('Colour', bookInput('color', e0.color || '#64748b'), gLn));
    f.width = T(bookField('Width (1 to 20)', bookInput('number', num(e0.width, 4)), gLn));
    f.routing = T(bookField('Routing', bookSelect([['curved', 'Curved'], ['orthogonal', 'Orthogonal'], ['straight', 'Straight']], e0.routing || 'curved'), gLn));
    f.direction = T(bookField('Direction / arrows', bookSelect([['none', 'None'], ['forward', 'Forward →'], ['backward', 'Backward ←'], ['both', 'Both ↔']], e0.direction || 'none'), gLn));
    f.lineStyle = T(bookField('Line style', bookSelect([['solid', 'Solid'], ['dashed', 'Dashed'], ['dotted', 'Dotted'], ['wall', 'Wall']], e0.lineStyle || 'solid'), gLn));
    f.buried = T(bookField('On the floor (3D cable-tray)', bookInput('checkbox', !!(scene3d.buried && scene3d.buried[id])), gLn));
    const wpN = Array.isArray(e0.waypoints) ? e0.waypoints.length : 0;
    const wpBtn = bookBtn('Clear waypoints (' + wpN + ')', gLn);
    wpBtn.disabled = wpN === 0; if (!wpN) wpBtn.style.opacity = '.5';
    wpBtn.onclick = function () {
      if (editBlocked('edge', id)) return;
      const cur = getVar('EDGE_DATA'); const e = cur && Array.isArray(cur.list) && cur.list.find((x) => x && x.id === id);
      if (!e || !Array.isArray(e.waypoints) || !e.waypoints.length) return;
      const push = getVar('pushUndo'); if (typeof push === 'function') { try { push('clear waypoints (3D)'); } catch (x) {} }
      e.waypoints = []; setVar('EDGE_DATA', cur);
      const forge = getVar('forgeTheTopology') || window.forgeTheTopology; if (typeof forge === 'function') { try { forge(); } catch (x) {} }
      wpBtn.textContent = 'Clear waypoints (0)'; wpBtn.disabled = true; wpBtn.style.opacity = '.5';
      buildScene();
    };
    bookNote('Clearing waypoints applies immediately, exactly as the 2D button does, Cancel will not undo it.', gLn);

    const gAn = bookGroup('Flow animation', e0.animate === true).body;
    f.animate = T(bookField('Animate flow', bookInput('checkbox', e0.animate === true), gAn));
    f.animStyle = T(bookField('Flow style', bookSelect([['', 'Default (page setting)'], ['arrows', 'Flowing arrows'], ['dots', 'Dot arrows']], e0.animationStyle || ''), gAn));
    f.animSpeed = T(bookField('Flow speed', bookSelect([['', 'Default (page setting)'], ['0.5', 'Very fast'], ['1', 'Fast'], ['1.5', 'Normal'], ['2.5', 'Slow'], ['4', 'Very slow']], e0.animationSpeed == null ? '' : String(e0.animationSpeed)), gAn));
    bookNote('Flow markers only appear when the connection has arrows (Direction ≠ None), same rule as 2D.', gAn);

    const gPt = bookGroup('Ports & notes', !!(e0.fromPort || e0.toPort)).body;
    f.fromPort = T(bookField('From port', bookInput('text', e0.fromPort || ''), gPt));
    f.toPort = T(bookField('To port', bookInput('text', e0.toPort || ''), gPt));
    bookNote((((getVar('PAGE_STATE') || {}).showPortLabels) ? 'Port labels are shown' : 'Port labels are hidden') + ', toggled by "Show Port Labels" in the 2D settings panel.', gPt);
    f.notes = T(bookField('Notes (one per line)', bookTextarea(notesToText(e0.notes)), gPt));
    bookSave.onclick = function () {
      const cur = getVar('EDGE_DATA'); const e = cur && Array.isArray(cur.list) && cur.list.find((x) => x && x.id === id); if (!e) { closeBook(); return; }
      const push = getVar('pushUndo'); if (typeof push === 'function') { try { push('edit edge (3D)'); } catch (x) {} }
      bookApply(e, 'color', f.color);
      bookApplyNum(e, 'width', f.width, bookInt(1, 20, 4));
      bookApply(e, 'routing', f.routing); bookApply(e, 'direction', f.direction); bookApply(e, 'lineStyle', f.lineStyle);
      bookApply(e, 'animate', f.animate);
      bookApply(e, 'animationStyle', f.animStyle, null, true);
      bookApply(e, 'animationSpeed', f.animSpeed, null, true);
      bookApply(e, 'fromPort', f.fromPort, (v) => v.trim(), true);
      bookApply(e, 'toPort', f.toPort, (v) => v.trim(), true);
      if (bookChanged(f.notes)) e.notes = notesFromText(f.notes.value);
      setVar('EDGE_DATA', cur);
      const forge = getVar('forgeTheTopology') || window.forgeTheTopology; if (typeof forge === 'function') { try { forge(); } catch (x) {} }
      if (bookChanged(f.buried)) {
        scene3d.buried = scene3d.buried || {}; const bury = f.buried.checked;
        if (bury) scene3d.buried[id] = 1; else delete scene3d.buried[id];
        if (sceneReady) { scheduleSave(); broadcastFurn({ op: 'bury', id: id, buried: bury }); }
      }
      closeBook(); buildScene();
    };
    showBook();
  }
  function deleteEdgeIn3D(id) {
    if (editBlocked('edge', id)) return;
    const hadBuried = !!(scene3d.buried && scene3d.buried[id]);
    const push = getVar('pushUndo'); if (typeof push === 'function') { try { push('delete edge (3D)'); } catch (e) {} }
    if (!deleteEdgeData(id)) return;
    if (hadBuried && sceneReady) scheduleSave();
    forge2D();
    selRemoveItem('edge', id);
    buildScene();
  }
  function openBookFor(kind, id) {
    if (selection.length > 1) { guardToast('📕 Select a single object to open its edit book.'); return false; }
    if (editBlocked(kind, id)) return false;
    if (kind === 'furniture') openFurnBook(id); else if (kind === 'rect') openRectBook(id); else if (kind === 'text') openTextBook(id); else if (kind === 'image') openImageBook(id); else if (kind === 'edge') openEdgeBook(id); else openNodeBook(id);
    return true;
  }
  function editBtn(kind, id) {
    const b = document.createElement('button');
    b.textContent = '✏️ Edit';
    b.style.cssText = 'margin:8px 6px 0 0;padding:5px 12px;border:none;border-radius:6px;background:#7c3aed;color:#fff;font-weight:700;cursor:pointer;font:12px system-ui';
    b.onclick = () => openBookFor(kind, id);
    return b;
  }
  function rackAtWorld(wxp, wyp, skip) {
    const nd = getVar('NODE_DATA') || {}, sp = getVar('savedPositions') || {};
    let best = null, bestD = 260;
    Object.keys(nd).forEach((k) => { if (k === skip || !nd[k] || !isTrue(nd[k].isRack)) return; const p = sp[k]; if (!p) return; const d = Math.hypot(p.x - wxp, p.y - wyp); if (d < bestD) { bestD = d; best = k; } });
    return best;
  }
  function nextFreeUnit(rackId) {
    const nd = getVar('NODE_DATA') || {}, cap = parseInt(nd[rackId] && nd[rackId].rackCapacity, 10) || 42, used = {};
    Object.keys(nd).forEach((k) => { if (nd[k] && nd[k].assignedRack === rackId) { const u = parseInt(nd[k].rackUnit, 10) || 1, uh = Math.max(1, parseInt(nd[k].uHeight, 10) || 1); for (let i = 0; i < uh; i++) used[u + i] = 1; } });
    for (let u = 1; u <= cap; u++) { if (!used[u]) return u; }
    return 1;
  }
  function deleteNodeData(id, keepChildren) {
    const nd = getVar('NODE_DATA'); if (!nd || !nd[id]) return false;
    const sp = getVar('savedPositions') || {}, sz = getVar('savedSizes') || {}, st = getVar('savedStyles') || {}, ed = getVar('EDGE_DATA') || { list: [] };
    const strip = (nid) => { if (ed.list) ed.list = ed.list.filter((e) => e && e.from !== nid && e.to !== nid); delete nd[nid]; delete sp[nid]; delete sz[nid]; delete st[nid]; if (scene3d.heights) delete scene3d.heights[nid]; };
    if (isTrue(nd[id].isRack)) {
      const kids = Object.keys(nd).filter((k) => nd[k] && nd[k].assignedRack === id);
      if (keepChildren) {
        const rp = sp[id] || { x: 2000, y: 1500 };
        kids.forEach((k, i) => { nd[k].assignedRack = ''; const a = (i / Math.max(1, kids.length)) * Math.PI * 2; sp[k] = { x: Math.round(clamp(rp.x + Math.cos(a) * 190, PAD, WORLD_W - PAD)), y: Math.round(clamp(rp.y + Math.sin(a) * 190, PAD, WORLD_D - PAD)) }; if (sz[k] == null) sz[k] = 55; });
      } else { kids.forEach((k) => strip(k)); }
    }
    strip(id);
    Object.keys(nd).forEach((k) => { if (nd[k] && nd[k].hostedOn === id) nd[k].hostedOn = ''; });
    setVar('NODE_DATA', nd); setVar('savedPositions', sp); setVar('savedSizes', sz); setVar('savedStyles', st); setVar('EDGE_DATA', ed);
    return true;
  }
  function deleteNodeIn3D(id, keepChildren) {
    if (editBlocked('node', id)) return;
    const nd0 = getVar('NODE_DATA'); if (!nd0 || !nd0[id]) return;
    const push = getVar('pushUndo'); if (typeof push === 'function') { try { push('delete node (3D)'); } catch (e) {} }
    if (!deleteNodeData(id, keepChildren)) return;
    forge2D();
    selRemoveItem('node', id);
    if (sceneReady) scheduleSave();
    buildScene();
  }
  function forge2D() { const f = getVar('forgeTheTopology') || window.forgeTheTopology; if (typeof f === 'function') { try { f(); } catch (e) {} } }
  function deleteFurnData(id) {
    const before = scene3d.furniture.length;
    scene3d.furniture = scene3d.furniture.filter((x) => x.id !== id);
    return scene3d.furniture.length !== before;
  }
  function deleteFurnIn3D(id) {
    if (!sceneReady) return;
    if (editBlocked('furniture', id)) return;
    if (!deleteFurnData(id)) return;
    selRemoveItem('furniture', id);
    scheduleSave(); buildScene(); broadcastFurn({ op: 'del', id: id });
  }
  function deletePrimData(kind, id) {
    const varName = kind === 'rect' ? 'RECT_DATA' : kind === 'text' ? 'TEXT_DATA' : 'IMAGE_DATA';
    const d = getVar(varName); if (!d || !Array.isArray(d.list)) return false;
    const before = d.list.length;
    d.list = d.list.filter((x) => !(x && x.id === id)); setVar(varName, d);
    return d.list.length !== before;
  }
  function deletePrimIn3D(kind, id) {
    if (editBlocked(kind, id)) return;
    const push = getVar('pushUndo'); if (typeof push === 'function') { try { push('delete ' + kind + ' (3D)'); } catch (e) {} }
    if (!deletePrimData(kind, id)) return;
    forge2D();
    selRemoveItem(kind, id);
    buildScene();
  }
  function deleteEdgeData(id) {
    const ed = getVar('EDGE_DATA'); if (!ed || !Array.isArray(ed.list)) return false;
    const before = ed.list.length;
    ed.list = ed.list.filter((x) => !(x && x.id === id)); setVar('EDGE_DATA', ed);
    if (ed.list.length === before) return false;
    if (scene3d.buried && scene3d.buried[id]) delete scene3d.buried[id];
    return true;
  }
  function deleteSelection() {
    if (isViewOnly()) { editBlocked(null, null); return; }
    if (!selection.length) return;
    const doable = [], locked = [];
    for (let i = 0; i < selection.length; i++) {
      const s = selection[i];
      if (isLocked(s.kind, s.id)) locked.push(s); else doable.push(s);
    }
    if (!doable.length) { guardToast('🔒 Every selected object is locked, unlock in 2D first.'); return; }
    let keepKids = false;
    {
      const ndR = getVar('NODE_DATA') || {};
      const selNode = Object.create(null);
      for (const s of doable) if (s.kind === 'node') selNode[s.id] = 1;
      let kidN = 0;
      for (const s of doable) {
        if (s.kind !== 'node' || !ndR[s.id] || !isTrue(ndR[s.id].isRack)) continue;
        for (const k in ndR) if (ndR[k] && ndR[k].assignedRack === s.id && !selNode[k]) kidN++;
      }
      if (kidN) {
        keepKids = !window.confirm('The selected rack(s) hold ' + kidN + ' mounted node(s) that are NOT selected.\n\nOK  = delete those nodes too.\nCancel = delete only the rack(s), their nodes drop to the floor.');
      }
    }
    const has2D = doable.some(function (s) { return s.kind !== 'furniture'; });
    if (has2D) { const push = getVar('pushUndo'); if (typeof push === 'function') { try { push('delete ' + doable.length + ' objects (3D)'); } catch (e) {} } }
    let furnDeleted = 0, twoDDeleted = 0, any2D = false;
    for (const s of doable) if (s.kind === 'edge') { if (deleteEdgeData(s.id)) { twoDDeleted++; any2D = true; } }
    for (const s of doable) if (s.kind === 'rect' || s.kind === 'text' || s.kind === 'image') { if (deletePrimData(s.kind, s.id)) { twoDDeleted++; any2D = true; } }
    for (const s of doable) if (s.kind === 'node') { if (deleteNodeData(s.id, keepKids)) { twoDDeleted++; any2D = true; } }
    if (sceneReady) for (const s of doable) if (s.kind === 'furniture') { if (deleteFurnData(s.id)) { furnDeleted++; broadcastFurn({ op: 'del', id: s.id }); } }
    if (any2D) forge2D();
    if ((furnDeleted || any2D) && sceneReady) scheduleSave();
    const total = selection.length, done = twoDDeleted + furnDeleted;
    setSelection(locked.slice());
    buildScene();
    guardToast('🗑 Deleted ' + done + ' of ' + total + (locked.length ? ' · ' + locked.length + ' locked, skipped' : '') + (furnDeleted ? ' · furniture deletions cannot be undone' : ''));
  }
  function delBtn(kind, id) {
    const b = document.createElement('button');
    b.textContent = '🗑 Delete';
    b.style.cssText = 'margin-top:8px;padding:5px 12px;border:none;border-radius:6px;background:#b91c1c;color:#fff;font-weight:700;cursor:pointer;font:12px system-ui';
    let armed = false;
    b.onclick = () => {
      if (editBlocked(kind, id)) { armed = false; b.textContent = '🗑 Delete'; return; }
      if (!armed) { armed = true; b.textContent = '⚠ Confirm delete'; setTimeout(() => { armed = false; b.textContent = '🗑 Delete'; }, 2500); return; }
      if (kind === 'furniture') { deleteFurnIn3D(id); closeBook(); return; }
      if (kind === 'rect' || kind === 'text' || kind === 'image') { deletePrimIn3D(kind, id); closeBook(); return; }
      if (kind === 'edge') { deleteEdgeIn3D(id); closeBook(); return; }
      const nd = getVar('NODE_DATA') || {};
      const kids = (nd[id] && isTrue(nd[id].isRack)) ? Object.keys(nd).filter((k) => nd[k] && nd[k].assignedRack === id) : [];
      const keep = kids.length ? !window.confirm('This rack holds ' + kids.length + ' node(s).\n\nOK  = delete the rack AND its nodes.\nCancel = delete only the rack, its nodes drop to the floor.') : false;
      deleteNodeIn3D(id, keep);
      closeBook();
    };
    return b;
  }

  function rackUnderPointer(ndc, excludeId) {
    if (!ndc) return null;
    raycaster.setFromCamera(ndc, camera);
    const hits = raycaster.intersectObjects(pickables, true), nd = getVar('NODE_DATA') || {};
    for (let i = 0; i < hits.length; i++) {
      let o = hits[i].object; while (o && !(o.userData && (o.userData.nodeId || o.userData.furnId))) o = o.parent;
      if (o && o.userData.nodeId && o.userData.nodeId !== excludeId && nd[o.userData.nodeId] && isTrue(nd[o.userData.nodeId].isRack)) return o.userData.nodeId;
    }
    return null;
  }
  function beginGroupDrag(anchorKind, anchorId) {
    if (selection.length < 2) return null;
    if (selIndexOf(selection, anchorKind, anchorId) < 0) return null;
    if (isViewOnly()) return null;
    const out = [], skipped = [];
    for (let i = 0; i < selection.length; i++) {
      const s = selection[i];
      if (s.kind === 'edge') { skipped.push(s); continue; }
      if (isLocked(s.kind, s.id)) { skipped.push(s); continue; }
      const o = objectFor(s.kind, s.id); if (!o) continue;
      out.push({ kind: s.kind, id: s.id, obj: o, ox: o.position.x, oy: o.position.y, oz: o.position.z });
    }
    if (out.length < 2) return null;
    if (skipped.length) guardToast('🔒 ' + skipped.length + ' selected item(s) skipped, locked or a connection.');
    return out;
  }
  function moveGroupBy(dx, dz) {
    if (!dragGroup) return;
    for (let i = 0; i < dragGroup.length; i++) { const g = dragGroup[i]; g.obj.position.set(g.ox + dx, g.oy, g.oz + dz); }
    applySelectionHalosUpdate();
  }
  function applySelectionHalosUpdate() {
    if (selBox) selBox.update();
    for (let i = 0; i < selHalos.length; i++) selHalos[i].update();
  }
  function commitGroupDrag() {
    const grp = dragGroup; dragGroup = null;
    if (!grp || !grp.length) return;
    const anchor = grp[0];
    const raw = groupDelta({ x: anchor.ox, z: anchor.oz }, { x: anchor.obj.position.x, z: anchor.obj.position.z });
    const canvasItems = [];
    const sp = getVar('savedPositions') || {};
    for (let i = 0; i < grp.length; i++) {
      const g = grp[i];
      let p = null;
      if (g.kind === 'node') { const q = sp[g.id]; if (q) p = { x: num(q.x, 0), z: num(q.y, 0) }; }
      else if (g.kind === 'furniture') { const f = scene3d.furniture.find((x) => x.id === g.id); if (f) p = { x: num(f.x, 0), z: num(f.z, 0) }; }
      else { const it = primItem(g.kind, g.id); if (it) p = primAnchor(g.kind, it); }
      if (p) canvasItems.push({ kind: g.kind, id: g.id, x: p.x, z: p.z, base: p });
    }
    const d = clampGroupDelta({ dx: raw.dx, dz: raw.dz }, canvasItems, PAD, WORLD_W - PAD, PAD, WORLD_D - PAD);
    if (!canvasItems.length || (Math.abs(d.dx) < 0.5 && Math.abs(d.dz) < 0.5)) { buildScene(); return; }
    const has2D = canvasItems.some(function (x) { return x.kind !== 'furniture'; });
    if (has2D) { const push = getVar('pushUndo'); if (typeof push === 'function') { try { push('move ' + canvasItems.length + ' objects (3D)'); } catch (e) {} } }
    const moves = []; let any2D = false;
    for (let i = 0; i < canvasItems.length; i++) {
      const it = canvasItems[i];
      const nx = Math.round(clamp(it.base.x + d.dx, Math.min(PAD, it.base.x), Math.max(WORLD_W - PAD, it.base.x)));
      const nz = Math.round(clamp(it.base.z + d.dz, Math.min(PAD, it.base.z), Math.max(WORLD_D - PAD, it.base.z)));
      if (it.kind === 'node') { sp[it.id] = { x: nx, y: nz }; any2D = true; }
      else if (it.kind === 'furniture') { const f = scene3d.furniture.find((x) => x.id === it.id); if (f) { f.x = nx; f.z = nz; moves.push({ id: f.id, x: nx, z: nz }); } }
      else { const o = primItem(it.kind, it.id); if (o) { primSetAnchor(it.kind, o, nx, nz); any2D = true; } }
    }
    if (any2D) { setVar('savedPositions', sp); primFlush(); forge2D(); }
    if (moves.length) { if (sceneReady) scheduleSave(); broadcastFurnMoves(moves); }
    buildScene();
  }
  function primList(kind) { return getVar(kind === 'rect' ? 'RECT_DATA' : kind === 'text' ? 'TEXT_DATA' : 'IMAGE_DATA'); }
  function primItem(kind, id) { const d = primList(kind); return (d && Array.isArray(d.list)) ? d.list.find((x) => x && x.id === id) : null; }
  function primAnchor(kind, it) {
    if (kind === 'text') return { x: num(it.x, 0), z: num(it.y, 0) };
    return { x: num(it.x, 0) + num(it.width, 0) / 2, z: num(it.y, 0) + num(it.height, 0) / 2 };
  }
  function primSetAnchor(kind, it, cx, cz) {
    if (kind === 'text') { it.x = cx; it.y = cz; return; }
    it.x = Math.round(cx - num(it.width, 0) / 2); it.y = Math.round(cz - num(it.height, 0) / 2);
  }
  function primFlush() { ['rect', 'text', 'image'].forEach(function (k) { const d = primList(k); if (d) setVar(k === 'rect' ? 'RECT_DATA' : k === 'text' ? 'TEXT_DATA' : 'IMAGE_DATA', d); }); }

  function commitDrag(mountRackHint) {
    if (dragGroup) { commitGroupDrag(); return; }
    if (!dragId || !dragObj) return;
    const keep = dragId, keepKind = dragKind;
    if (dragKind === 'edge') { buildScene(); const oe = pickables.find((m) => m.userData.edgeId === keep); if (oe) selectItem('edge', keep, oe); return; }
    if (editBlocked(keepKind, keep)) {
      buildScene();
      const ob = pickables.find((m) => m.userData.nodeId === keep || m.userData.furnId === keep || m.userData.rectId === keep || m.userData.textId === keep || m.userData.imageId === keep);
      if (ob) selectItem(keepKind, keep, ob);
      return;
    }
    const wxp0 = Math.round(clamp(wx(dragObj.position.x), PAD, WORLD_W - PAD)), wyp0 = Math.round(clamp(wy(dragObj.position.z), PAD, WORLD_D - PAD));
    if (dragKind === 'rect' || dragKind === 'text' || dragKind === 'image') {
      const varName = dragKind === 'rect' ? 'RECT_DATA' : dragKind === 'text' ? 'TEXT_DATA' : 'IMAGE_DATA';
      const d = getVar(varName); const it = d && Array.isArray(d.list) && d.list.find((x) => x && x.id === dragId);
      if (it) {
        const push = getVar('pushUndo'); if (typeof push === 'function') { try { push('move ' + dragKind + ' (3D)'); } catch (e) {} }
        if (dragKind === 'text') { it.x = wxp0; it.y = wyp0; }
        else { const w = num(it.width, 0), h = num(it.height, 0); it.x = Math.round(wxp0 - w / 2); it.y = Math.round(wyp0 - h / 2); }
        setVar(varName, d);
        const forge = getVar('forgeTheTopology') || window.forgeTheTopology; if (typeof forge === 'function') { try { forge(); } catch (e) {} }
      }
      buildScene();
      const o2 = pickables.find((m) => m.userData.rectId === keep || m.userData.textId === keep || m.userData.imageId === keep);
      if (o2) selectItem(keepKind, keep, o2);
      return;
    }
    if (dragKind === 'furniture') {
      if (!sceneReady) { buildScene(); return; }
      const f = scene3d.furniture.find((x) => x.id === dragId);
      if (f) { f.x = Math.round(clamp(wx(dragObj.position.x), PAD, WORLD_W - PAD)); f.z = Math.round(clamp(wy(dragObj.position.z), PAD, WORLD_D - PAD)); scheduleSave(); broadcastFurn({ op: 'move', id: f.id, x: f.x, z: f.z }); }
    } else {
      const nd = getVar('NODE_DATA') || {}, sp = getVar('savedPositions') || {};
      const node = nd[dragId] || {};
      const wxp = Math.round(clamp(wx(dragObj.position.x), PAD, WORLD_W - PAD)), wyp = Math.round(clamp(wy(dragObj.position.z), PAD, WORLD_D - PAD));
      const rackId = isTrue(node.isRack) ? null : (mountRackHint || rackAtWorld(wxp, wyp, dragId));
      if (rackId && rackId !== dragId) {
        node.assignedRack = rackId; node.rackUnit = String(nextFreeUnit(rackId)); if (!node.uHeight) node.uHeight = '1';
        setVar('NODE_DATA', nd);
      } else {
        sp[dragId] = { x: wxp, y: wyp }; setVar('savedPositions', sp);
      }
      const forge = getVar('forgeTheTopology') || window.forgeTheTopology;
      if (typeof forge === 'function') { try { forge(); } catch (e) {} }
    }
    buildScene();
    const obj = pickables.find((m) => m.userData.nodeId === keep || m.userData.furnId === keep);
    if (obj) selectItem(keepKind, keep, obj);
  }

  const avatars = {};
  function avatarHeadGeometry(shape) {
    switch (shape) {
      case 'sphere': return new THREE.SphereGeometry(32, 16, 12);
      case 'cone': return new THREE.ConeGeometry(34, 60, 6);
      case 'cylinder': return new THREE.CylinderGeometry(30, 30, 55, 14);
      case 'octahedron': return new THREE.OctahedronGeometry(38);
      case 'wedge': return new THREE.CylinderGeometry(0.0001, 42, 56, 4);
      default: return new THREE.BoxGeometry(55, 55, 55);
    }
  }
  function makeAvatar(color, userId) {
    const g = new THREE.Group();
    const c = new THREE.Color(color || '#4fd1c5');
    const shape = avatarShapeName(userId);
    g.userData.avatarShape = shape;
    const body = new THREE.Mesh(new THREE.BoxGeometry(70, 150, 45), new THREE.MeshStandardMaterial({ color: c, roughness: 0.6 }));
    body.position.y = 75; g.add(body);
    const headMat = new THREE.MeshStandardMaterial({ color: c.clone().offsetHSL(0, 0, 0.12), roughness: 0.5 });
    const head = new THREE.Mesh(avatarHeadGeometry(shape), headMat);
    head.position.y = 185; g.add(head);
    const badge = new THREE.Mesh(avatarHeadGeometry(shape), new THREE.MeshStandardMaterial({ color: 0xf8fafc, roughness: 0.4 }));
    badge.scale.setScalar(0.28); badge.position.set(0, 110, 24); g.add(badge);
    const nose = new THREE.Mesh(new THREE.BoxGeometry(14, 14, 26), new THREE.MeshStandardMaterial({ color: 0x111827 }));
    nose.position.set(0, 150, 30); g.add(nose);
    return g;
  }
  const OP_WIRE_LIMIT = 1024;
  let _opGuardWarnedAt = 0;
  function broadcastFurn(op) {
    const api = window.__collab3d; if (!api || !api.send) return;
    const me = api.me && api.me(); if (!me || !me.id) return;
    if (op && typeof op === 'object' && op.tk === undefined) op.tk = tabKey();
    if (op && op.op !== 'scale' && op.op !== 'wire' && op.op !== 'mvb') logLocalOp(op.tk, op);
    sendFurnOp(op);
  }
  function opWireBytes(op) {
    const api = window.__collab3d; const me = api && api.me && api.me();
    try {
      const s = JSON.stringify({ type: 'cursor', userId: (me && me.id) || '', d3: 1, furnOp: op });
      return (typeof TextEncoder === 'function') ? new TextEncoder().encode(s).length : s.length;
    } catch (e) { return OP_WIRE_LIMIT + 1; }
  }
  function sendFurnOp(op) {
    const api = window.__collab3d; if (!api || !api.send) return;
    const me = api.me && api.me(); if (!me || !me.id) return;
    if (op && typeof op === 'object' && op.tk === undefined) op.tk = tabKey();
    const payload = { userId: me.id, d3: 1, furnOp: op };
    const bytes = opWireBytes(op);
    if (bytes > OP_WIRE_LIMIT) {
      const now = Date.now();
      if (now - _opGuardWarnedAt > 4000) { _opGuardWarnedAt = now; guardToast('📡 Change too large to sync live, saved; collaborators will see it on their next refresh.'); }
      try { console.warn('[3d] furnOp ' + bytes + 'B exceeds the ' + OP_WIRE_LIMIT + 'B op-channel cap — save-only', op && op.op); } catch (e) {}
      scheduleSave();
      return;
    }
    try { api.send('cursor', payload); } catch (e) {}
  }

  '@collab-3d-furnop-retry-helpers:start';
  const FURNOP_RETRY_MIN_MS = 50;
  const FURNOP_RETRY_MAX_MS = 5000;
  const FURNOP_RETRY_MAX = 3;
  function furnOpRetryKey(op) {
    if (!op || typeof op !== 'object') return null;
    const verb = op.op == null ? '' : String(op.op);
    if (!verb) return null;
    return verb + '|' + (op.id == null ? '' : String(op.id)) + '|' + (op.tk == null ? '' : String(op.tk));
  }
  function furnOpRetryAllowed(attempt, max) {
    const m = Math.floor(Number(max));
    const lim = Number.isFinite(m) && m > 0 ? m : FURNOP_RETRY_MAX;
    const a = Math.floor(Number(attempt));
    if (!Number.isFinite(a) || a < 0) return false;
    return a < lim;
  }
  function furnOpRetryDelay(retryAfterMs, attempt, opts) {
    const o = opts || {};
    const lo = Number.isFinite(Number(o.min)) && Number(o.min) > 0 ? Number(o.min) : FURNOP_RETRY_MIN_MS;
    const hi = Number.isFinite(Number(o.max)) && Number(o.max) > 0 ? Number(o.max) : FURNOP_RETRY_MAX_MS;
    const raw = Number(retryAfterMs);
    const base = Number.isFinite(raw) && raw > 0 ? raw : lo;
    const a = Math.floor(Number(attempt));
    const n = Number.isFinite(a) && a > 0 ? Math.min(a, 20) : 0;
    const d = base * Math.pow(2, n);
    if (!Number.isFinite(d)) return hi;
    return Math.min(hi, Math.max(lo, d));
  }
  '@collab-3d-furnop-retry-helpers:end';
  const furnOpRetryCount = new Map();
  const furnOpRetryTimers = new Set();
  function onFurnOpDropped(ev) {
    if (!active) return;
    const d = ev && ev.detail;
    if (!d || d.channel !== 'furnOp') return;
    const op = d.op;
    const key = furnOpRetryKey(op);
    if (!key) return;
    const attempt = furnOpRetryCount.get(key) || 0;
    if (!furnOpRetryAllowed(attempt, FURNOP_RETRY_MAX)) {
      furnOpRetryCount.delete(key);
      scheduleSave();
      return;
    }
    furnOpRetryCount.set(key, attempt + 1);
    const delay = furnOpRetryDelay(d.retryAfterMs, attempt, null);
    const t = setTimeout(function () {
      furnOpRetryTimers.delete(t);
      if (!active) return;
      try { sendFurnOp(op); } catch (e) {}
    }, delay);
    furnOpRetryTimers.add(t);
  }
  function clearFurnOpRetries() {
    furnOpRetryTimers.forEach(function (t) { try { clearTimeout(t); } catch (e) {} });
    furnOpRetryTimers.clear(); furnOpRetryCount.clear();
  }

  function broadcastFurnMoves(moves) {
    if (!moves || !moves.length) return;
    const tk = tabKey();
    for (let i = 0; i < moves.length; i++) logLocalOp(tk, { op: 'move', id: moves[i].id, x: moves[i].x, z: moves[i].z, tk: tk });
    let chunk = [];
    const flush = function () { if (chunk.length) { sendFurnOp({ op: 'mvb', items: chunk, tk: tk }); chunk = []; } };
    for (let i = 0; i < moves.length; i++) {
      chunk.push(moves[i]);
      if (chunk.length > 1 && opWireBytes({ op: 'mvb', items: chunk, tk: tk }) > OP_WIRE_LIMIT) { chunk.pop(); flush(); chunk.push(moves[i]); }
    }
    flush();
  }
  const pendingFurnOps = [];
  function applyFurnOp(op) {
    if (!op || !op.op) return;
    if (!sceneReady) { pendingFurnOps.push(op); if (pendingFurnOps.length > 800) pendingFurnOps.shift(); return; }
    const curTab = tabKey();
    const key = (typeof op.tk === 'string' && op.tk) ? op.tk.slice(0, 64).replace(TAB_KEY_RE, '_') : curTab;
    if (op.op === 'scale') {
      scene3d.mpu = clamp(num(op.mpu, 0), 0, 1);
      refreshScaleBtn(); deferrableRebuild(); scheduleReconcile(curTab); return;
    }
    if (op.op === 'wire') {
      scene3d.wireMode = clamp(op.wireMode | 0, 0, WIRE_MODES.length - 1);
      refreshWireBtn(); deferrableRebuild(); scheduleReconcile(curTab); return;
    }
    const B = bucketFor(key);
    if (!B) return;
    const vis = (key === curTab);
    const rebuild = () => { if (vis) deferrableRebuild(); };
    const save = () => scheduleReconcile(key);
    if (op.op === 'add') {
      const it = sanitizeFurnItem(op.item);
      if (it && !B.furniture.some((f) => f.id === it.id) && B.furniture.length < MAX_FURNITURE) { B.furniture.push(it); rebuild(); save(); }
    } else if (op.op === 'move') {
      const f = B.furniture.find((x) => x.id === op.id);
      if (f) { f.x = clamp(Math.round(num(op.x, f.x)), 0, WORLD_W); f.z = clamp(Math.round(num(op.z, f.z)), 0, WORLD_D); rebuild(); save(); }
    } else if (op.op === 'mvb') {
      const items = Array.isArray(op.items) ? op.items.slice(0, SEL_MAX) : [];
      let any = false;
      for (let i = 0; i < items.length; i++) {
        const m = items[i]; if (!m || typeof m.id !== 'string') continue;
        const f = B.furniture.find((x) => x.id === m.id);
        if (f) { f.x = clamp(Math.round(num(m.x, f.x)), 0, WORLD_W); f.z = clamp(Math.round(num(m.z, f.z)), 0, WORLD_D); any = true; }
      }
      if (any) { rebuild(); save(); }
    } else if (op.op === 'update') {
      const it = sanitizeFurnItem(op.item);
      if (it) { const idx = B.furniture.findIndex((x) => x.id === it.id); if (idx >= 0) { B.furniture[idx] = it; rebuild(); save(); } }
    } else if (op.op === 'height') {
      const y = clamp(num(op.y, 0), 0, MAX_ELEVATION);
      if (y) B.heights[op.id] = y; else delete B.heights[op.id];
      rebuild(); save();
    } else if (op.op === 'bury') {
      if (op.buried) B.buried[op.id] = 1; else delete B.buried[op.id];
      rebuild(); save();
    } else if (op.op === 'wallh') {
      const h = clamp(num(op.h, 0), 0, MAX_WALL_HEIGHT);
      if (h) B.wallHeights[op.id] = h; else delete B.wallHeights[op.id];
      rebuild(); save();
    } else if (op.op === 'del') {
      const before = B.furniture.length;
      B.furniture = B.furniture.filter((x) => x.id !== op.id);
      if (B.furniture.length !== before) { if (vis) selRemoveItem('furniture', op.id); rebuild(); save(); }
    }
  }
  function onNetMessage(msg) {
    if (!msg) return;
    const me = window.__collab3d && window.__collab3d.me && window.__collab3d.me();
    if (msg.type === 'leave' && msg.userId && avatars[msg.userId]) { if (scene) scene.remove(avatars[msg.userId].grp); disposeObject3D(avatars[msg.userId].grp); delete avatars[msg.userId]; return; }
    if (msg.type === 'cursor' && msg.furnOp) { if (!me || msg.userId !== me.id) applyFurnOp(msg.furnOp); return; }
    if (msg.type !== 'cursor' || !msg.d3 || !msg.userId) return;
    if (me && msg.userId === me.id) return;
    let a = avatars[msg.userId];
    if (!a) {
      const u = window.__collab3d.getUser(msg.userId);
      const grp = makeAvatar(u && u.color, msg.userId);
      const tag = textSprite(((u && u.name) || 'user') + ' (' + grp.userData.avatarShape + ')', (u && u.color) || '#e2e8f0');
      tag.position.set(0, 250, 0); grp.add(tag);
      if (scene) scene.add(grp);
      a = avatars[msg.userId] = { grp: grp, tx: sx(msg.x), ty: msg.z3d || 0, tz: sz(msg.y), yaw: msg.yaw3d || 0, seen: performance.now() };
      grp.position.set(a.tx, 0, a.tz);
    }
    a.tx = sx(msg.x); a.tz = sz(msg.y); a.yaw = msg.yaw3d || 0; a.seen = performance.now();
  }
  function updateAvatars() {
    for (const id in avatars) {
      const a = avatars[id];
      if (performance.now() - a.seen > 8000) { scene.remove(a.grp); disposeObject3D(a.grp); delete avatars[id]; continue; }
      if (reduceMotion()) { a.grp.position.x = a.tx; a.grp.position.z = a.tz; }
      else {
        a.grp.position.x += (a.tx - a.grp.position.x) * 0.18;
        a.grp.position.z += (a.tz - a.grp.position.z) * 0.18;
      }
      a.grp.rotation.y = a.yaw;
    }
  }
  let lastPoseAt = 0, lastPoseKey = '';
  const _poseEuler = new THREE.Euler();
  function sendPose(now) {
    const api = window.__collab3d; if (!api || !api.send) return;
    const me = api.me && api.me(); if (!me || !me.id) return;
    if (now - lastPoseAt < 120) return;
    let gx, gz, yaw, hy;
    if (renderer && renderer.xr && renderer.xr.isPresenting) {
      const k = vrScale() || 1;
      gx = camera.position.x / k; gz = camera.position.z / k; hy = camera.position.y / k;
      _poseEuler.setFromQuaternion(camera.quaternion, 'YXZ');
      yaw = _poseEuler.y;
    }
    else if (mode === 'walk') { gx = walkPos.x; gz = walkPos.z; yaw = walkYaw; hy = walkPos.y; }
    else { gx = target.x; gz = target.z; yaw = theta; hy = 100; }
    if (!Number.isFinite(gx) || !Number.isFinite(gz) || !Number.isFinite(hy) || !Number.isFinite(yaw)) return;
    const key = Math.round(gx) + ',' + Math.round(gz) + ',' + yaw.toFixed(2) + ',' + Math.round(hy);
    if (key === lastPoseKey && now - lastPoseAt < 1000) return;
    lastPoseAt = now; lastPoseKey = key;
    api.send('cursor', { userId: me.id, x: wx(gx), y: wy(gz), isCanvasCoords: true, d3: 1, z3d: hy, yaw3d: yaw });
  }

  function hexColor(v, fb) { try { return new THREE.Color(v || fb); } catch (e) { return new THREE.Color(fb); } }

  let theme = {};
  function readTheme() {
    const ps = getVar('PAGE_STATE') || {};
    return {
      nodeFill: ps.nodeFill, nodeStroke: ps.nodeStroke,
      nodeTitle: ps.nodeTitle, nodeSub: ps.nodeSub,
      nodeTitleSize: ps.nodeTitleSize, nodeSubSize: ps.nodeSubSize, nodeFont: ps.nodeFont,
      defaultEdge: ps.defaultEdge, groupIndicator: ps.groupIndicator,
    };
  }
  function nodeColor(id, node, styles, res) {
    const c = (res || bookResolveStyles(styles && styles[id])).circleColor;
    if (c) return hexColor(c, '#3b82f6');
    if (theme.nodeFill) return hexColor(theme.nodeFill, '#3b82f6');
    return isTrue(node.isRack) ? hexColor('#1f2937', '#1f2937') : hexColor('#3b82f6', '#3b82f6');
  }

  const LAYER_FADE = 0.25;
  const LAYER_IDS = ['layer1', 'layer2', 'layer3', 'layer4'];
  const LAYER_ALIAS = { physical: 'layer1', logical: 'layer2', security: 'layer3', application: 'layer4' };
  function activeLayerList() { const a = getVar('activeLayers'); return Array.isArray(a) ? a : null; }
  function makeLayerFilter(ND) {
    const fn = getVar('isNodeVisible');
    if (typeof fn === 'function') return function (id) { try { return fn(id) !== false; } catch (e) { return true; } };
    const arr = activeLayerList();
    if (!arr) return function () { return true; };
    const set = new Set(arr);
    return function (id) {
      const n = ND && ND[id]; if (!n) return false;
      let L = n.layer || 'layer1'; if (LAYER_ALIAS[L]) L = LAYER_ALIAS[L];
      return set.has(L);
    };
  }
  function fadeForLayer(o) {
    if (!o || !o.traverse) return o;
    o.traverse(function (c) {
      const m = c.material; if (!m) return;
      const list = Array.isArray(m) ? m : [m];
      for (let i = 0; i < list.length; i++) {
        const mm = list[i]; if (!mm || mm.__layerFaded) continue;
        mm.__layerFaded = true; mm.transparent = true; mm.depthWrite = false;
        mm.opacity = (mm.opacity === undefined ? 1 : mm.opacity) * LAYER_FADE;
      }
    });
    return o;
  }

  const GROUP_DASH = 5, GROUP_GAP = 5, GROUP_Y = 2.6;
  function groupColor() { return hexColor(theme.groupIndicator, '#4fd1c5'); }
  function dashedLoop(pts) {
    const l = new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), new THREE.LineDashedMaterial({ color: groupColor(), dashSize: GROUP_DASH, gapSize: GROUP_GAP }));
    l.computeLineDistances();
    return l;
  }
  function groupRing(r) { const p = []; for (let i = 0; i <= 48; i++) { const a = (i / 48) * Math.PI * 2; p.push(new THREE.Vector3(Math.cos(a) * r, 0, Math.sin(a) * r)); } return dashedLoop(p); }
  function groupBox(hw, hd) { return dashedLoop([new THREE.Vector3(-hw, 0, -hd), new THREE.Vector3(hw, 0, -hd), new THREE.Vector3(hw, 0, hd), new THREE.Vector3(-hw, 0, hd), new THREE.Vector3(-hw, 0, -hd)]); }

  const NODE_H0 = 0.62;
  const NODE_TRIM = '#475569';
  const NODE_DARK = '#1e293b';
  const NODE_LED = '#4ade80';
  const NODE_LED2 = '#facc15';
  const _star = (n, ro, ri, a0) => { const o = []; for (let i = 0; i < n * 2; i++) { const a = (Math.PI / n) * i + a0; const q = i % 2 === 0 ? ro : ri; o.push([Math.cos(a) * q, Math.sin(a) * q]); } return o; };
  const P_STAR = _star(5, 1, 0.45, -Math.PI / 2);
  const P_TSTAR = _star(5, 0.9, 0.4, -Math.PI / 2);
  const P_TRI = [[0, -1.8], [1, 0.9], [-1, 0.9]];
  const P_CROSS = [[-.35, -1], [.35, -1], [.35, -.35], [1, -.35], [1, .35], [.35, .35], [.35, 1], [-.35, 1], [-.35, .35], [-1, .35], [-1, -.35], [-.35, -.35]];
  const P_PARA = [[-.6, -.6], [1.2, -.6], [.6, .6], [-1.2, .6]];
  const P_TRAP = [[-.6, -.6], [.6, -.6], [1, .6], [-1, .6]];
  const P_SHIELD = [[0, -1], [.85, -.5], [.85, .2], [.56, .75], [0, 1], [-.56, .75], [-.85, .2], [-.85, -.5]];
  const NODE_FORMS = {
    circle: { b: { k: 'p', r: 1, sg: 24, h: NODE_H0 } },
    square: { b: { k: 'b', w: 2, d: 2, h: NODE_H0 } },
    rectangle: { b: { k: 'b', w: 2.8, d: 1.6, h: NODE_H0 } },
    triangle: { b: { k: 'y', pts: P_TRI, h: NODE_H0 } },
    hexagon: { b: { k: 'p', r: 1, sg: 6, h: 0.7 } },
    diamond: { b: { k: 'p', r: 1, sg: 4, h: 0.7 } },
    star: { b: { k: 'y', pts: P_STAR, h: 0.55 } },
    'stop-sign': { b: { k: 'p', r: 1, sg: 8, h: NODE_H0, ry: 22.5 } },
    octagon: { b: { k: 'p', r: 1, sg: 8, h: NODE_H0, ry: 22.5 } },
    pentagon: { b: { k: 'p', r: 1, sg: 5, h: NODE_H0, ry: 180 } },
    cross: { b: { k: 'y', pts: P_CROSS, h: 0.55 } },
    'rounded-square': { b: { k: 'q', w: 1.6, d: 1.6, r: 0.4, h: NODE_H0 } },
    pill: { b: { k: 'q', w: 2.4, d: 1, r: 0.5, h: NODE_H0 } },
    parallelogram: { b: { k: 'y', pts: P_PARA, h: NODE_H0 } },
    trapezoid: { b: { k: 'y', pts: P_TRAP, h: NODE_H0 } },
    server: { b: { k: 'b', w: 2.4, d: 1.2, h: 0.9 }, t: [{ k: 'b', w: 1.9, h: 0.5, d: 0.06, p: [0, 0.45, -0.62], c: NODE_DARK }, { k: 's', r: 0.1, p: [0.95, 0.62, -0.62], c: NODE_LED }] },
    pc: { b: { k: 'b', w: 1.8, d: 0.3, h: 1.2, p: [0, 0.9, 0] }, t: [{ k: 'b', w: 1.5, h: 0.9, d: 0.06, p: [0, 0.9, -0.18], c: NODE_DARK }, { k: 'b', w: 0.6, h: 0.3, d: 0.6, p: [0, 0.15, 0], c: 'T' }] },
    laptop: { b: { k: 'b', w: 1.8, d: 1.2, h: 0.12 }, t: [{ k: 'b', w: 1.8, h: 1, d: 0.1, p: [0, 0.5, 0.58], rx: -18, c: 'T' }] },
    phone: { b: { k: 'b', w: 0.75, d: 0.18, h: 1.5 }, t: [{ k: 'b', w: 0.6, h: 1.15, d: 0.05, p: [0, 0.78, -0.11], c: NODE_DARK }] },
    printer: { b: { k: 'b', w: 1.6, d: 1.3, h: 0.85 }, t: [{ k: 'b', w: 1.3, h: 0.06, d: 0.5, p: [0, 0.9, -0.5], c: 'T' }, { k: 'b', w: 0.5, h: 0.16, d: 0.05, p: [-0.45, 0.55, -0.67], c: NODE_DARK }] },
    pi: { b: { k: 'b', w: 1.7, d: 1.15, h: 0.1 }, t: [{ k: 'b', w: 0.5, h: 0.14, d: 0.5, p: [-0.2, 0.17, 0.1], c: NODE_DARK }, { k: 'b', w: 1.2, h: 0.1, d: 0.12, p: [0, 0.15, -0.45], c: 'T' }] },
    sensor: { b: { k: 'p', r: 0.7, sg: 16, h: 0.5 }, t: [{ k: 'b', w: 0.06, h: 0.55, d: 0.06, p: [0, 0.77, 0], c: 'T' }, { k: 's', r: 0.12, p: [0, 1.08, 0], c: 'T' }] },
    router: { b: { k: 'b', w: 2.2, d: 1.2, h: 0.5 }, t: [{ k: 'b', w: 0.1, h: 0.7, d: 0.1, p: [-0.7, 0.85, -0.1], c: 'T', rep: 2, dx: 1.4 }, { k: 'b', w: 1.4, h: 0.05, d: 0.05, p: [0, 0.3, -0.61], c: NODE_LED }] },
    switch: { b: { k: 'b', w: 2.8, d: 1, h: 0.42 }, t: [{ k: 'b', w: 2.4, h: 0.28, d: 0.06, p: [0, 0.21, -0.52], c: NODE_DARK }] },
    firewall: { b: { k: 'b', w: 2, d: 0.5, h: 1.4 }, t: [{ k: 'b', w: 1.94, h: 0.06, d: 0.54, p: [0, 0.47, 0], c: 'T', rep: 2, dy: 0.46 }] },
    'access-point': { b: { k: 'p', r: 1, sg: 20, h: 0.28 }, t: [{ k: 's', r: 0.55, sys: 0.5, p: [0, 0.28, 0] }, { k: 's', r: 0.09, p: [0, 0.58, 0], c: NODE_LED }] },
    'load-balancer': { b: { k: 'b', w: 1.8, d: 1.2, h: 0.8 }, t: [{ k: 'b', w: 0.12, h: 0.1, d: 0.9, p: [-0.6, 0.85, 0], c: 'T', rep: 3, dx: 0.6 }] },
    gateway: { b: { k: 'b', w: 1.9, d: 0.5, h: 1.3 }, t: [{ k: 'b', w: 0.9, h: 0.9, d: 0.55, p: [0, 0.45, 0], c: NODE_DARK }] },
    vpn: { b: { k: 'p', r: 0.8, sg: 16, h: 2, ax: 'x' }, t: [{ k: 'p', r: 0.55, sg: 16, h: 0.12, ax: 'x', p: [-1.02, 0.8, 0], c: NODE_DARK }] },
    nas: { b: { k: 'b', w: 1.4, d: 1.2, h: 1.4 }, t: [{ k: 'b', w: 1.2, h: 0.16, d: 0.06, p: [0, 0.4, -0.62], c: NODE_DARK, rep: 3, dy: 0.38 }] },
    cloud: { b: { k: 's', r: 0.85, sys: 0.72, p: [0, 0.65, 0] }, t: [{ k: 's', r: 0.6, sys: 0.72, p: [-0.85, 0.48, 0] }, { k: 's', r: 0.55, sys: 0.72, p: [0.9, 0.45, 0] }] },
    database: { b: { k: 'p', r: 0.95, sg: 18, h: 1.3 }, t: [{ k: 'p', r: 0.99, sg: 18, h: 0.06, p: [0, 0.45, 0], c: 'T', rep: 2, dy: 0.42 }] },
    docker: { b: { k: 'b', w: 2.2, d: 1.1, h: 0.5 }, t: [{ k: 'b', w: 0.45, h: 0.4, d: 0.5, p: [-0.55, 0.7, 0], c: 'T', rep: 3, dx: 0.55 }] },
    container: { b: { k: 'b', w: 2, d: 1, h: 1 }, t: [{ k: 'b', w: 0.08, h: 0.9, d: 1.02, p: [-0.6, 0.5, 0], c: 'T', rep: 3, dx: 0.6 }] },
    vm: { b: { k: 'b', w: 1.9, d: 1.2, h: 1.2 }, t: [{ k: 'b', w: 1, h: 0.7, d: 1.24, p: [0, 0.6, 0], c: 'T' }] },
    kubernetes: { b: { k: 'p', r: 1, sg: 7, h: 0.75 }, t: [{ k: 'p', r: 0.35, sg: 7, h: 0.85, p: [0, 0.42, 0], c: 'T' }] },
    api: { b: { k: 't', r: 0.8, tb: 0.26 }, t: [{ k: 's', r: 0.3, p: [0, 0.32, 0], c: 'T' }] },
    queue: { b: { k: 'b', w: 0.6, d: 1, h: 0.7, p: [-0.78, 0.35, 0] }, t: [{ k: 'b', w: 0.6, h: 0.7, d: 1, p: [0, 0.35, 0], rep: 2, dx: 0.78 }] },
    lambda: { b: { k: 'p', rt: 0, rb: 1, sg: 4, h: 1.4, ry: 45 } },
    bucket: { b: { k: 'p', rt: 1, rb: 0.68, sg: 18, h: 1 }, t: [{ k: 'p', r: 1.04, sg: 18, h: 0.08, p: [0, 0.96, 0], c: 'T' }] },
    shield: { b: { k: 'y', pts: P_SHIELD, h: 0.7 } },
    camera: { b: { k: 'b', w: 1.4, d: 0.8, h: 0.7, p: [0.1, 0.55, 0] }, t: [{ k: 'p', r: 0.3, sg: 14, h: 0.35, ax: 'z', p: [0.1, 0.55, -0.55], c: NODE_DARK }, { k: 'b', w: 0.22, h: 1.1, d: 0.22, p: [-0.95, 0.55, 0], c: 'T' }] },
    monitor: { b: { k: 'b', w: 2, d: 0.2, h: 1.3, p: [0, 0.95, 0] }, t: [{ k: 'b', w: 1.7, h: 1, d: 0.06, p: [0, 0.95, -0.13], c: NODE_DARK }, { k: 'b', w: 0.6, h: 0.3, d: 0.6, p: [0, 0.15, 0], c: 'T' }] },
    thermostat: { b: { k: 'p', r: 0.85, sg: 22, h: 0.5 }, t: [{ k: 'p', r: 0.55, sg: 22, h: 0.12, p: [0, 0.52, 0], c: 'T' }] },
    doorbell: { b: { k: 'q', w: 0.8, d: 0.5, r: 0.24, h: 1.2 }, t: [{ k: 's', r: 0.16, p: [0, 0.85, -0.26], c: 'T' }] },
    'smart-lock': { b: { k: 'b', w: 1, d: 0.5, h: 0.9 }, t: [{ k: 't', r: 0.33, tb: 0.1, rx: 0, p: [0, 0.95, 0], c: 'T' }] },
    'smart-bulb': { b: { k: 's', r: 0.72, p: [0, 0.95, 0] }, t: [{ k: 'p', r: 0.32, sg: 14, h: 0.4, p: [0, 0.2, 0], c: 'T' }] },
    'smart-plug': { b: { k: 'b', w: 0.95, d: 0.6, h: 1 }, t: [{ k: 'b', w: 0.1, h: 0.1, d: 0.35, p: [-0.2, 0.6, -0.42], c: 'T', rep: 2, dx: 0.4 }] },
    'smart-speaker': { b: { k: 'p', r: 0.7, sg: 20, h: 1.5 }, t: [{ k: 't', r: 0.5, tb: 0.08, p: [0, 1.52, 0], c: 'T' }] },
    'smart-tv': { b: { k: 'b', w: 2.6, d: 0.16, h: 1.5, p: [0, 1.05, 0] }, t: [{ k: 'b', w: 2.3, h: 1.2, d: 0.05, p: [0, 1.05, -0.11], c: NODE_DARK }, { k: 'b', w: 0.8, h: 0.3, d: 0.5, p: [0, 0.15, 0], c: 'T' }] },
    hub: { b: { k: 'p', r: 0.95, sg: 22, h: 0.55 }, t: [{ k: 't', r: 0.62, tb: 0.1, p: [0, 0.58, 0], c: 'T' }] },
    'smoke-detector': { b: { k: 'p', r: 1, sg: 20, h: 0.32 }, t: [{ k: 's', r: 0.4, sys: 0.45, p: [0, 0.32, 0], c: 'T' }, { k: 's', r: 0.08, p: [0.45, 0.34, 0], c: NODE_LED }] },
    'motion-sensor': { b: { k: 'p', r: 0.9, sg: 3, h: 0.8, ry: 180 }, t: [{ k: 's', r: 0.3, sys: 0.6, p: [0, 0.82, -0.2], c: NODE_DARK }] },
    garage: { b: { k: 'b', w: 2.2, d: 0.35, h: 1.2 }, t: [{ k: 'b', w: 2.12, h: 0.06, d: 0.39, p: [0, 0.3, 0], c: 'T', rep: 3, dy: 0.32 }] },
    sprinkler: { b: { k: 'p', r: 0.42, sg: 14, h: 0.6 }, t: [{ k: 'p', rt: 0.95, rb: 0.06, sg: 16, h: 0.5, p: [0, 0.85, 0], c: 'T' }] },
    vacuum: { b: { k: 'p', r: 1, sg: 24, h: 0.4 }, t: [{ k: 't', r: 0.95, tb: 0.1, p: [0, 0.12, 0], c: NODE_DARK }, { k: 's', r: 0.14, p: [0, 0.44, 0], c: 'T' }] },
    'basketball-ball': { b: { k: 's', r: 1, p: [0, 1, 0] }, t: [{ k: 't', r: 1, tb: 0.045, p: [0, 1, 0], c: 'T' }, { k: 't', r: 1, tb: 0.045, rx: 0, p: [0, 1, 0], c: 'T' }] },
    'football-ball': { b: { k: 's', r: 1, sxs: 1.3, sys: 0.7, szs: 0.7, p: [0, 0.7, 0] }, t: [{ k: 'b', w: 0.5, h: 0.06, d: 0.06, p: [0, 0.72, 0], c: 'T' }] },
    'soccer-ball': { b: { k: 's', r: 0.95, p: [0, 0.95, 0] }, t: [{ k: 'p', r: 0.3, sg: 5, h: 0.06, p: [0, 1.88, 0], c: NODE_DARK }] },
    'hockey-puck': { b: { k: 'p', r: 1, sg: 24, h: 0.35 } },
    'baseball-ball': { b: { k: 's', r: 0.85, p: [0, 0.85, 0] }, t: [{ k: 't', r: 0.86, tb: 0.04, rx: 0, p: [0, 0.85, 0], c: 'T' }] },
    'tennis-ball': { b: { k: 's', r: 0.85, p: [0, 0.85, 0] }, t: [{ k: 't', r: 0.86, tb: 0.05, rz: 90, p: [0, 0.85, 0], c: 'T' }] },
    volleyball: { b: { k: 's', r: 0.95, p: [0, 0.95, 0] }, t: [{ k: 't', r: 0.96, tb: 0.05, p: [0, 0.95, 0], c: 'T' }] },
    'rugby-ball': { b: { k: 's', r: 1, sxs: 1.45, sys: 0.78, szs: 0.78, p: [0, 0.78, 0] }, t: [{ k: 'b', w: 1.6, h: 0.05, d: 0.05, p: [0, 0.8, 0], c: 'T' }] },
    'golf-ball': { b: { k: 's', r: 0.55, p: [0, 0.9, 0] }, t: [{ k: 'p', rt: 0.14, rb: 0.06, sg: 10, h: 0.4, p: [0, 0.2, 0], c: 'T' }] },
    frisbee: { b: { k: 'p', rt: 1.05, rb: 0.9, sg: 24, h: 0.22 }, t: [{ k: 't', r: 1, tb: 0.07, p: [0, 0.2, 0], c: 'T' }] },
    'cricket-ball': { b: { k: 's', r: 0.85, p: [0, 0.85, 0] }, t: [{ k: 't', r: 0.86, tb: 0.05, p: [0, 0.85, 0], c: 'T' }] },
    'lacrosse-stick': { b: { k: 'b', w: 0.16, d: 1.8, h: 0.16, p: [0, 0.25, 0.3] }, t: [{ k: 't', r: 0.4, tb: 0.1, p: [0, 0.25, -0.8], c: 'T' }] },
    'golf-flag': { b: { k: 'p', r: 0.07, sg: 8, h: 2.2 }, t: [{ k: 'b', w: 0.75, h: 0.45, d: 0.05, p: [0.42, 1.95, 0], c: 'T' }] },
    'tactical-x': { b: { k: 'b', w: 1.98, d: 0.3, h: 0.4, ry: 45 }, t: [{ k: 'b', w: 1.98, h: 0.4, d: 0.3, ry: -45, p: [0, 0.2, 0] }] },
    'tactical-o': { b: { k: 't', r: 0.7, tb: 0.15 } },
    'tactical-star': { b: { k: 'y', pts: P_TSTAR, h: 0.5 } },
    'patch-panel': { b: { k: 'b', w: 2.6, d: 0.9, h: 0.42 }, t: [{ k: 'b', w: 2.3, h: 0.2, d: 0.06, p: [0, 0.21, -0.47], c: NODE_DARK }] },
    ups: { b: { k: 'b', w: 2, d: 1, h: 1.1 }, t: [{ k: 'b', w: 0.7, h: 0.3, d: 0.06, p: [-0.5, 0.75, -0.52], c: NODE_DARK }, { k: 's', r: 0.1, p: [0.7, 0.75, -0.52], c: NODE_LED }] },
    pdu: { b: { k: 'b', w: 2.8, d: 0.5, h: 0.34 }, t: [{ k: 'p', r: 0.09, sg: 10, h: 0.06, ax: 'z', p: [-0.8, 0.17, -0.27], c: NODE_DARK, rep: 3, dx: 0.8 }] },
    'rack-shelf': { b: { k: 'b', w: 2.6, d: 1.2, h: 0.16 }, t: [{ k: 'b', w: 2.6, h: 0.22, d: 0.08, p: [0, 0.16, -0.56], c: 'T' }] },
    'blank-panel': { b: { k: 'b', w: 2.6, d: 0.3, h: 0.5 } },
    'cable-management': { b: { k: 'b', w: 2.6, d: 0.6, h: 0.5 }, t: [{ k: 't', r: 0.2, tb: 0.06, rx: 0, p: [-0.9, 0.52, 0], c: 'T', rep: 3, dx: 0.9 }] },
    kvm: { b: { k: 'b', w: 2.2, d: 1, h: 0.5 }, t: [{ k: 'b', w: 0.9, h: 0.3, d: 0.06, p: [-0.4, 0.28, -0.52], c: NODE_DARK }, { k: 's', r: 0.08, p: [0.75, 0.3, -0.52], c: NODE_LED2 }] },
  };
  const NODE_SHAPE_ALIAS = {
    desktop: 'pc', mobile: 'phone', wifi: 'access-point', storage: 'nas', modem: 'gateway', tunnel: 'vpn',
    virtual: 'vm', k8s: 'kubernetes', security: 'shield', cctv: 'camera', whale: 'docker', capsule: 'pill',
    plus: 'cross', sbc: 'pi', raspberry: 'pi', endpoint: 'api', message: 'queue', function: 'lambda',
    s3: 'bucket', iot: 'sensor', dashboard: 'monitor',
  };
  function extrudePoly(pts, depth, s) {
    const sh = new THREE.Shape();
    for (let i = 0; i < pts.length; i++) { const x = pts[i][0] * s, y = -pts[i][1] * s; if (i === 0) sh.moveTo(x, y); else sh.lineTo(x, y); }
    sh.closePath();
    const g = new THREE.ExtrudeGeometry(sh, { depth: depth, bevelEnabled: false, curveSegments: 4 });
    g.rotateX(-Math.PI / 2);
    return g;
  }
  function extrudeRRect(w, d, r, depth) {
    const hw = w / 2, hd = d / 2, q = Math.min(r, hw, hd), sh = new THREE.Shape();
    sh.moveTo(-hw + q, -hd);
    sh.lineTo(hw - q, -hd); sh.quadraticCurveTo(hw, -hd, hw, -hd + q);
    sh.lineTo(hw, hd - q); sh.quadraticCurveTo(hw, hd, hw - q, hd);
    sh.lineTo(-hw + q, hd); sh.quadraticCurveTo(-hw, hd, -hw, hd - q);
    sh.lineTo(-hw, -hd + q); sh.quadraticCurveTo(-hw, -hd, -hw + q, -hd);
    const g = new THREE.ExtrudeGeometry(sh, { depth: depth, bevelEnabled: false, curveSegments: 3 });
    g.rotateX(-Math.PI / 2);
    return g;
  }
  function nodePartGeo(o, s) {
    const k = o.k;
    if (k === 'b') return new THREE.BoxGeometry((o.w || 1) * s, (o.h || 1) * s, (o.d || 1) * s);
    if (k === 's') return new THREE.SphereGeometry((o.r || 1) * s, 14, 10);
    if (k === 't') return new THREE.TorusGeometry((o.r || 1) * s, (o.tb || 0.15) * s, 8, 20);
    if (k === 'y') return extrudePoly(o.pts, (o.h === undefined ? NODE_H0 : o.h) * s, s);
    if (k === 'q') return extrudeRRect((o.w || 1) * s, (o.d || 1) * s, (o.r || 0.2) * s, (o.h === undefined ? NODE_H0 : o.h) * s);
    const rt = (o.rt !== undefined ? o.rt : o.r !== undefined ? o.r : 1) * s;
    const rb = (o.rb !== undefined ? o.rb : o.r !== undefined ? o.r : 1) * s;
    return new THREE.CylinderGeometry(rt, rb, (o.h === undefined ? NODE_H0 : o.h) * s, o.sg || 24);
  }
  function nodePartY(o) {
    if (o.p && o.p[1] !== undefined) return o.p[1];
    if (o.k === 'b') return (o.h || 1) / 2;
    if (o.k === 's') return (o.r || 1) * (o.sys !== undefined ? o.sys : 1);
    if (o.k === 't') return (o.tb || 0.15);
    if (o.k === 'y' || o.k === 'q') return 0;
    if (o.ax === 'x' || o.ax === 'z') return (o.rb !== undefined ? o.rb : o.r !== undefined ? o.r : 1);
    return (o.h === undefined ? NODE_H0 : o.h) / 2;
  }
  function buildNodeShape(shape, s, bodyMat, trimHex) {
    const dk = devModelsOn ? deviceModelKey(shape, NODE_SHAPE_ALIAS) : null;
    const devForm = dk ? DEVICE_MODELS[dk] : null;
    if (devForm) _devModelCount++;
    const form = devForm || NODE_FORMS[NODE_SHAPE_ALIAS[shape] || shape] || NODE_FORMS.circle;
    const g = new THREE.Group();
    const matCache = {};
    const matFor = (c) => {
      if (!c) return bodyMat;
      if (matCache[c]) return matCache[c];
      const hex = c === 'T' ? (trimHex || NODE_TRIM) : c;
      const m = new THREE.MeshStandardMaterial({ color: hexColor(hex, NODE_TRIM), roughness: 0.55, metalness: 0.15 });
      if (c === NODE_LED || c === NODE_LED2) { m.emissive = hexColor(hex, NODE_TRIM); m.emissiveIntensity = 0.55; }
      matCache[c] = m; return m;
    };
    const add = (o) => {
      if (!o) return;
      const reps = clamp(o.rep || 1, 1, 4), geo = nodePartGeo(o, s), mat = matFor(o.c);
      const x0 = (o.p ? (o.p[0] || 0) : 0), y0 = nodePartY(o), z0 = (o.p ? (o.p[2] || 0) : 0);
      for (let i = 0; i < reps; i++) {
        const m = new THREE.Mesh(geo, mat);
        m.position.set((x0 + i * (o.dx || 0)) * s, (y0 + i * (o.dy || 0)) * s, z0 * s);
        if (o.k === 't') m.rotation.x = -Math.PI / 2;
        else if (o.k === 'p' && o.ax === 'x') m.rotation.z = Math.PI / 2;
        else if (o.k === 'p' && o.ax === 'z') m.rotation.x = Math.PI / 2;
        if (o.rx !== undefined) m.rotation.x = rad(o.rx);
        if (o.ry !== undefined) m.rotation.y = rad(o.ry);
        if (o.rz !== undefined) m.rotation.z = rad(o.rz);
        if (o.sxs || o.sys || o.szs) m.scale.set(o.sxs || 1, o.sys || 1, o.szs || 1);
        g.add(m);
      }
    };
    add(form.b); (form.t || []).forEach(add);
    if (devForm) mergeSameMaterial(g);
    g.updateMatrixWorld(true);
    let top = NODE_H0 * s;
    try { const bb = new THREE.Box3().setFromObject(g); if (Number.isFinite(bb.max.y)) top = Math.max(4, bb.max.y); } catch (e) {}
    return { g: g, top: top };
  }

  const ICON_PX = 128;
  const ICON_TEX_MAX = 96;
  const iconTexCache = {};
  let _iconUsed = null;
  function iconSvgFor(lib, name) {
    const c = getVar('iconCache');
    if (!c || typeof c !== 'object') return null;
    const v = c[lib + '-' + name];
    return (typeof v === 'string' && v.indexOf('<svg') !== -1) ? v : null;
  }
  function iconDataUri(svg, fill, stroke, tint) {
    let out = svg;
    try {
      const doc = new DOMParser().parseFromString(svg, 'image/svg+xml');
      const el = doc.querySelector('svg');
      if (el && !doc.querySelector('parsererror')) {
        if (!el.getAttribute('viewBox')) {
          const w0 = parseFloat(el.getAttribute('width')) || 24, h0 = parseFloat(el.getAttribute('height')) || 24;
          el.setAttribute('viewBox', '0 0 ' + w0 + ' ' + h0);
        }
        el.setAttribute('width', ICON_PX); el.setAttribute('height', ICON_PX);
        el.setAttribute('preserveAspectRatio', 'xMidYMid meet');
        if (tint) el.setAttribute('color', tint);
        if (fill || stroke) {
          const shapes = doc.querySelectorAll('path,circle,rect,polygon,ellipse,line,polyline');
          for (let i = 0; i < shapes.length; i++) {
            if (fill) shapes[i].setAttribute('fill', fill);
            if (stroke) shapes[i].setAttribute('stroke', stroke);
          }
          if (fill) el.setAttribute('fill', fill);
        }
        out = new XMLSerializer().serializeToString(el);
      }
    } catch (e) {}
    return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(out);
  }
  function getIconTexture(lib, name, fill, stroke, tint) {
    const key = lib + '-' + name + '|' + (fill || '') + '|' + (stroke || '') + '|' + (tint || '');
    if (_iconUsed) _iconUsed.add(key);
    const c = iconTexCache[key];
    if (c && c !== 'loading' && c !== 'error') return c;
    if (c) return null;
    const svg = iconSvgFor(lib, name); if (!svg) return null;
    if (Object.keys(iconTexCache).length >= ICON_TEX_MAX) return null;
    iconTexCache[key] = 'loading';
    const img = new Image();
    img.onload = function () {
      if (iconTexCache[key] !== 'loading') return;
      try {
        const cv = document.createElement('canvas'); cv.width = cv.height = ICON_PX;
        cv.getContext('2d').drawImage(img, 0, 0, ICON_PX, ICON_PX);
        const tex = new THREE.CanvasTexture(cv);
        tex.minFilter = THREE.LinearFilter;
        tex.__shared = true;
        if ('colorSpace' in tex) tex.colorSpace = THREE.SRGBColorSpace;
        iconTexCache[key] = tex;
        if (active) buildScene();
      } catch (e) { iconTexCache[key] = 'error'; }
    };
    img.onerror = function () { iconTexCache[key] = 'error'; };
    img.src = iconDataUri(svg, fill, stroke, tint);
    return null;
  }
  function pruneIconTexCache(used) {
    for (const k in iconTexCache) {
      if (used && used.has(k)) continue;
      const v = iconTexCache[k];
      if (v && v.dispose) { try { v.dispose(); } catch (e) {} }
      delete iconTexCache[k];
    }
  }
  function clearIconTexCache() { pruneIconTexCache(null); }

  '@collab-3d-devmodel-helpers:start';
  const DEVICE_MODEL_KEYS = ['server', 'router', 'switch', 'firewall', 'workstation', 'laptop', 'phone',
    'printer', 'camera', 'access-point', 'nas', 'cloud'];
  const DEVICE_MODEL_OF = {
    server: 'server', router: 'router', switch: 'switch', firewall: 'firewall',
    pc: 'workstation', monitor: 'workstation', laptop: 'laptop', phone: 'phone', printer: 'printer',
    camera: 'camera', 'access-point': 'access-point', nas: 'nas', cloud: 'cloud',
    gateway: 'router',
  };
  function deviceModelKey(shape, alias) {
    const s = String(shape == null ? '' : shape);
    const canon = (alias && Object.prototype.hasOwnProperty.call(alias, s)) ? alias[s] : s;
    return Object.prototype.hasOwnProperty.call(DEVICE_MODEL_OF, canon) ? DEVICE_MODEL_OF[canon] : null;
  }
  const EMBLEM_BUCKET = 16, EMBLEM_BUCKET_MIN = 16, EMBLEM_BUCKET_MAX = 256;
  function iconSizeBucket(size) {
    const n = Number(size);
    if (!Number.isFinite(n) || n <= 0) return EMBLEM_BUCKET_MIN;
    const b = Math.ceil(n / EMBLEM_BUCKET) * EMBLEM_BUCKET;
    return Math.min(EMBLEM_BUCKET_MAX, Math.max(EMBLEM_BUCKET_MIN, b));
  }
  function emblemGeoKey(lib, name, bucket) { return String(lib) + '-' + String(name) + '|' + bucket; }
  const EMBLEM_PATH_MAX = 400;
  const EMBLEM_MAX_PER_SCENE = 300;
  function emblemDecision(paths, built, enabled, opts) {
    const o = opts || {};
    const maxPaths = o.maxPaths === undefined ? EMBLEM_PATH_MAX : o.maxPaths;
    const maxScene = o.maxPerScene === undefined ? EMBLEM_MAX_PER_SCENE : o.maxPerScene;
    if (!enabled) return { use: false, reason: 'off' };
    if (!(Number(built) < maxScene)) return { use: false, reason: 'scene-cap' };
    if (paths === null || paths === undefined) return { use: true, reason: 'ok' };
    const p = Number(paths);
    if (!Number.isFinite(p) || p <= 0) return { use: false, reason: 'empty' };
    if (p > maxPaths) return { use: false, reason: 'path-cap' };
    return { use: true, reason: 'ok' };
  }
  '@collab-3d-devmodel-helpers:end';

  const EMBLEM_DEPTH = 0.15;
  const EMBLEM_GEO_MAX = 96;
  const EMBLEM_SVG_MAX = 65536;
  const EMBLEM_POINT_MAX = 5000;
  const emblemGeoCache = {};
  const emblemMatCache = {};
  let _emblemUsed = null;
  let _emblemCount = 0;
  let _emblemFallback = 0;
  let _devModelCount = 0;
  let _svgLoaderP = null, _svgMod = null, _svgLoaderInst = null;
  function getSVGLoader() {
    if (!_svgLoaderP) {
      _svgLoaderP = import('/vendor/three/addons/loaders/SVGLoader.js').then(function (m) {
        _svgMod = m;
        if (active) buildScene();
        return m;
      }).catch(function () { _svgMod = null; return null; });
    }
    return _svgLoaderP;
  }
  let _bguP = null, _bguMod = null;
  function getBGU() {
    if (!_bguP) {
      _bguP = import('/vendor/three/addons/utils/BufferGeometryUtils.js').then(function (m) {
        _bguMod = m;
        if (active) buildScene();
        return m;
      }).catch(function () { _bguMod = null; return null; });
    }
    return _bguP;
  }
  function getEmblemGeometry(lib, name, bucket) {
    const key = emblemGeoKey(lib, name, bucket);
    if (_emblemUsed) _emblemUsed.add(key);
    const c = emblemGeoCache[key];
    if (c && c !== 'loading' && c !== 'error') return c;
    if (c === 'error') return null;
    if (!_svgMod) { getSVGLoader(); return null; }
    const svg = iconSvgFor(lib, name);
    if (!svg) return null;
    if (svg.length > EMBLEM_SVG_MAX) { emblemGeoCache[key] = 'error'; return null; }
    if (Object.keys(emblemGeoCache).length >= EMBLEM_GEO_MAX) return null;
    let geo = null;
    try {
      if (!_svgLoaderInst) _svgLoaderInst = new _svgMod.SVGLoader();
      const data = _svgLoaderInst.parse(svg);
      const paths = (data && data.paths) || [];
      if (!emblemDecision(paths.length, 0, true).use) { emblemGeoCache[key] = 'error'; return null; }
      const shapes = [];
      for (let i = 0; i < paths.length && shapes.length <= EMBLEM_PATH_MAX; i++) {
        const sh = (typeof paths[i].toShapes === 'function') ? paths[i].toShapes() : _svgMod.SVGLoader.createShapes(paths[i]);
        for (let j = 0; j < sh.length; j++) shapes.push(sh[j]);
      }
      if (!shapes.length) { emblemGeoCache[key] = 'error'; return null; }
      let pts = 0;
      for (let i = 0; i < shapes.length; i++) {
        const sc = shapes[i].curves, holes = shapes[i].holes || [];
        pts += (sc ? sc.length : 0) * 5;
        for (let j = 0; j < holes.length; j++) { const hc = holes[j].curves; pts += (hc ? hc.length : 0) * 5; }
      }
      if (pts > EMBLEM_POINT_MAX) { emblemGeoCache[key] = 'error'; return null; }
      const target = bucket * 1.6;
      const depth = Math.max(1, target * EMBLEM_DEPTH);
      geo = new THREE.ExtrudeGeometry(shapes, { depth: depth, bevelEnabled: false, curveSegments: 4 });
      geo.scale(1, -1, 1);
      geo.computeBoundingBox();
      const bb = geo.boundingBox;
      const w = bb.max.x - bb.min.x, h = bb.max.y - bb.min.y;
      if (!(w > 0) || !(h > 0)) { geo.dispose(); emblemGeoCache[key] = 'error'; return null; }
      geo.translate(-(bb.min.x + w / 2), -(bb.min.y + h / 2), -depth / 2);
      geo.scale(target / Math.max(w, h), target / Math.max(w, h), 1);
      geo.computeVertexNormals();
      geo.__shared = true;
    } catch (e) {
      if (geo) { try { geo.dispose(); } catch (e2) {} }
      emblemGeoCache[key] = 'error'; return null;
    }
    emblemGeoCache[key] = geo;
    return geo;
  }
  function emblemMaterial(fillHex, strokeHex) {
    const key = (fillHex || '') + '|' + (strokeHex || '');
    if (emblemMatCache[key]) return emblemMatCache[key];
    const m = new THREE.MeshStandardMaterial({
      color: hexColor(fillHex || strokeHex || NODE_TRIM, NODE_TRIM),
      roughness: 0.45, metalness: 0.2, side: THREE.DoubleSide,
    });
    emblemMatCache[key] = m;
    return m;
  }
  function pruneEmblemCache(used) {
    for (const k in emblemGeoCache) {
      if (used && used.has(k)) continue;
      const v = emblemGeoCache[k];
      if (v && v.dispose) { try { v.dispose(); } catch (e) {} }
      delete emblemGeoCache[k];
    }
  }
  function clearEmblemCache() {
    pruneEmblemCache(null);
    for (const k in emblemMatCache) { try { emblemMatCache[k].dispose(); } catch (e) {} delete emblemMatCache[k]; }
  }
  function buildIconEmblem(lib, name, size, fillHex, strokeHex) {
    const gate = emblemDecision(null, _emblemCount, icon3dOn);
    if (!gate.use) return null;
    const bucket = iconSizeBucket(size);
    const geo = getEmblemGeometry(lib, name, bucket);
    if (!geo) return null;
    const m = new THREE.Mesh(geo, emblemMaterial(fillHex, strokeHex));
    const k = (size * 1.6) / (bucket * 1.6);
    m.scale.set(k, k, k);
    m.userData.__modelClone = true;
    _emblemCount++;
    return m;
  }

  const DEVICE_MODELS = {
    server: { b: { k: 'b', w: 2, d: 1.5, h: 2.4 }, t: [
      { k: 'b', w: 1.7, h: 0.16, d: 0.06, p: [0, 0.4, -0.78], c: NODE_DARK, rep: 4, dy: 0.5 },
      { k: 'b', w: 1.7, h: 0.05, d: 0.05, p: [0, 0.3, -0.79], c: 'T' },
      { k: 's', r: 0.09, p: [0.75, 2.2, -0.78], c: NODE_LED }, { k: 's', r: 0.09, p: [0.5, 2.2, -0.78], c: NODE_LED2 } ] },
    router: { b: { k: 'b', w: 2.4, d: 1.4, h: 0.45 }, t: [
      { k: 'p', r: 0.07, sg: 8, h: 0.9, p: [-0.85, 0.85, 0.3], c: 'T', rep: 3, dx: 0.85 },
      { k: 's', r: 0.08, p: [-0.85, 1.32, 0.3], c: 'T', rep: 3, dx: 0.85 },
      { k: 'b', w: 0.1, h: 0.06, d: 0.06, p: [-0.6, 0.2, -0.71], c: NODE_LED, rep: 4, dx: 0.4 } ] },
    switch: { b: { k: 'b', w: 3, d: 1.1, h: 0.36 }, t: [
      { k: 'b', w: 2.7, h: 0.22, d: 0.06, p: [0, 0.18, -0.56], c: NODE_DARK },
      { k: 'b', w: 0.14, h: 0.12, d: 0.05, p: [-1.15, 0.18, -0.6], c: NODE_LED, rep: 4, dx: 0.33 },
      { k: 'b', w: 0.14, h: 0.12, d: 0.05, p: [0.2, 0.18, -0.6], c: NODE_LED2, rep: 4, dx: 0.33 } ] },
    firewall: { b: { k: 'b', w: 2, d: 0.7, h: 1.7 }, t: [
      { k: 'b', w: 1.94, h: 0.05, d: 0.74, p: [0, 0.42, 0], c: 'T', rep: 3, dy: 0.55 },
      { k: 'y', pts: P_SHIELD, h: 0.08, rx: 90, p: [0, 1.05, -0.4], c: 'T', sxs: 0.55, szs: 0.55 },
      { k: 's', r: 0.08, p: [0.8, 1.6, -0.38], c: NODE_LED } ] },
    workstation: { b: { k: 'b', w: 2, d: 0.18, h: 1.25, p: [0, 1.05, -0.1] }, t: [
      { k: 'b', w: 1.72, h: 0.98, d: 0.05, p: [0, 1.05, -0.21], c: NODE_DARK },
      { k: 'p', r: 0.12, sg: 10, h: 0.42, p: [0, 0.21, -0.1], c: 'T' },
      { k: 'b', w: 0.85, h: 0.06, d: 0.5, p: [0, 0.03, -0.1], c: 'T' },
      { k: 'b', w: 0.45, h: 0.95, d: 0.7, p: [1.35, 0.48, 0.15], c: 'T' } ] },
    laptop: { b: { k: 'b', w: 2, d: 1.35, h: 0.11 }, t: [
      { k: 'b', w: 2, h: 1.2, d: 0.08, p: [0, 0.62, 0.68], rx: -16, c: 'T' },
      { k: 'b', w: 1.76, h: 1, d: 0.04, p: [0, 0.62, 0.62], rx: -16, c: NODE_DARK },
      { k: 'b', w: 1.3, h: 0.02, d: 0.55, p: [0, 0.12, -0.1], c: NODE_DARK },
      { k: 'b', w: 0.5, h: 0.02, d: 0.3, p: [0, 0.13, -0.5], c: 'T' } ] },
    phone: { b: { k: 'b', w: 0.8, d: 0.18, h: 1.6, p: [0, 0.8, 0] }, t: [
      { k: 'b', w: 0.66, h: 1.2, d: 0.03, p: [0, 0.8, -0.1], c: NODE_DARK },
      { k: 'p', r: 0.07, sg: 12, h: 0.02, ax: 'z', p: [0, 0.15, -0.1], c: 'T' },
      { k: 's', r: 0.05, p: [0, 1.45, 0.1], c: NODE_DARK } ] },
    printer: { b: { k: 'b', w: 1.8, d: 1.4, h: 0.95 }, t: [
      { k: 'b', w: 1.5, h: 0.05, d: 0.6, p: [0, 1.05, 0.35], rx: -22, c: 'T' },
      { k: 'b', w: 1.4, h: 0.09, d: 0.06, p: [0, 0.62, -0.72], c: NODE_DARK },
      { k: 'b', w: 0.4, h: 0.16, d: 0.04, p: [-0.55, 0.85, -0.72], c: NODE_DARK },
      { k: 's', r: 0.07, p: [0.6, 0.86, -0.72], c: NODE_LED } ] },
    camera: { b: { k: 'p', r: 0.42, sg: 18, h: 1.3, ax: 'z', p: [0, 0.95, 0] }, t: [
      { k: 'p', r: 0.34, sg: 18, h: 0.18, ax: 'z', p: [0, 0.95, -0.72], c: NODE_DARK },
      { k: 's', r: 0.2, p: [0, 0.95, -0.8], c: NODE_DARK },
      { k: 'p', r: 0.09, sg: 10, h: 0.75, p: [0, 0.35, 0.45], c: 'T', rz: 0, rx: 28 },
      { k: 'p', r: 0.34, sg: 14, h: 0.08, p: [0, 0.04, 0.62], c: 'T' },
      { k: 's', r: 0.06, p: [0.3, 1.25, -0.6], c: NODE_LED } ] },
    'access-point': { b: { k: 'p', r: 1.05, sg: 24, h: 0.22 }, t: [
      { k: 's', r: 0.6, sys: 0.45, p: [0, 0.22, 0], c: 'T' },
      { k: 't', r: 0.78, tb: 0.05, p: [0, 0.23, 0], c: NODE_LED },
      { k: 'p', r: 0.05, sg: 8, h: 0.5, p: [-0.75, 0.47, 0.35], c: 'T', rep: 2, dx: 1.5 } ] },
    nas: { b: { k: 'b', w: 1.5, d: 1.4, h: 1.7 }, t: [
      { k: 'b', w: 1.26, h: 0.3, d: 0.06, p: [0, 0.3, -0.72], c: NODE_DARK, rep: 4, dy: 0.38 },
      { k: 's', r: 0.06, p: [0.52, 0.3, -0.76], c: NODE_LED, rep: 4, dy: 0.38 },
      { k: 'b', w: 1.5, h: 0.06, d: 1.4, p: [0, 1.67, 0], c: 'T' } ] },
    cloud: { b: { k: 's', r: 0.9, sys: 0.78, p: [0, 0.85, 0] }, t: [
      { k: 's', r: 0.62, sys: 0.78, p: [-0.95, 0.65, 0.1] }, { k: 's', r: 0.58, sys: 0.78, p: [1, 0.62, -0.1] },
      { k: 's', r: 0.46, sys: 0.78, p: [0.35, 0.95, 0.45] }, { k: 's', r: 0.42, sys: 0.78, p: [-0.4, 0.9, -0.45] } ] },
  };
  function mergeSameMaterial(g) {
    if (!_bguMod || typeof _bguMod.mergeGeometries !== 'function') return g;
    const byMat = new Map();
    g.children.slice().forEach(function (m) {
      if (!m.isMesh || !m.geometry || !m.geometry.isBufferGeometry) return;
      const bucket = { mat: m.material, idx: !!m.geometry.index };
      let hit = null;
      byMat.forEach(function (v, k) { if (!hit && k.mat === bucket.mat && k.idx === bucket.idx) hit = k; });
      const arr = hit ? byMat.get(hit) : []; arr.push(m); byMat.set(hit || bucket, arr);
    });
    byMat.forEach(function (list, k) {
      if (list.length < 2) return;
      const mat = k.mat;
      const baked = [], srcGeos = new Set();
      list.forEach(function (m) { m.updateMatrix(); const c = m.geometry.clone(); c.applyMatrix4(m.matrix); baked.push(c); srcGeos.add(m.geometry); });
      let merged = null;
      try { merged = _bguMod.mergeGeometries(baked, false); } catch (e) { merged = null; }
      baked.forEach(function (c) { try { c.dispose(); } catch (e) {} });
      if (!merged) return;
      list.forEach(function (m) { g.remove(m); });
      srcGeos.forEach(function (x) { try { x.dispose(); } catch (e) {} });
      g.add(new THREE.Mesh(merged, mat));
    });
    return g;
  }

  const NODE_LABEL_SCALE = 1.35;
  const NODE_LABEL_MAXW = 512, NODE_LABEL_MAXH = 224, NODE_LABEL_CHARS = 26;
  const FONT_STRIP_RE = /[^A-Za-z0-9 ,._'"-]/g;
  function safeFontFamily(f, fb) {
    const v = String(f == null ? '' : f).replace(FONT_STRIP_RE, '').trim().slice(0, 80);
    return v || fb;
  }
  function nodeSubtitle(node) { const v = node && node.ip; return (v && v !== '0.0.0.0') ? String(v) : ''; }
  function nodeLabelSprite(name, sub, st, r) {
    const tSize = clamp(num(st.titleSize, 0) || num(theme.nodeTitleSize, 0) || r * 0.33, 6, 100);
    const sSize = clamp(num(st.subSize, 0) || num(theme.nodeSubSize, 0) || r * 0.24, 5, 80);
    const ss = clamp(28 / tSize, 1, 2);
    const tPx = tSize * ss, sPx = sSize * ss;
    const tFam = safeFontFamily(st.titleFont || theme.nodeFont, 'system-ui,sans-serif');
    const sFam = safeFontFamily(st.subFont || theme.nodeFont, 'system-ui,sans-serif');
    const meas = document.createElement('canvas').getContext('2d');
    const rows = [];
    const tTxt = String(name == null ? '' : name).slice(0, NODE_LABEL_CHARS);
    const tFont = '600 ' + tPx + 'px ' + tFam;
    meas.font = tFont;
    rows.push({ t: tTxt, f: tFont, c: st.titleColor || theme.nodeTitle || '#e2e8f0', w: meas.measureText(tTxt).width, h: tPx, x: clamp(num(st.titleOffsetX, 0), -100, 100) * ss, y: tPx / 2 + clamp(num(st.titleOffsetY, 0), -100, 100) * ss });
    if (sub) {
      const sTxt = String(sub).slice(0, NODE_LABEL_CHARS), sFont = sPx + 'px ' + sFam;
      meas.font = sFont;
      rows.push({ t: sTxt, f: sFont, c: st.subColor || theme.nodeSub || '#94a3b8', w: meas.measureText(sTxt).width, h: sPx, x: clamp(num(st.subOffsetX, 0), -100, 100) * ss, y: tPx + tPx * 0.28 + sPx / 2 + clamp(num(st.subOffsetY, 0), -100, 100) * ss });
    }
    const pad = Math.round(tPx * 0.35);
    let minY = Infinity, maxY = -Infinity, halfW = 8;
    rows.forEach((q) => { minY = Math.min(minY, q.y - q.h * 0.62); maxY = Math.max(maxY, q.y + q.h * 0.62); halfW = Math.max(halfW, Math.abs(q.x) + q.w / 2); });
    const cw = clamp(Math.ceil(halfW * 2 + pad * 2), 32, NODE_LABEL_MAXW);
    const ch = clamp(Math.ceil(maxY - minY + pad * 2), 24, NODE_LABEL_MAXH);
    const cv = document.createElement('canvas'); cv.width = cw; cv.height = ch;
    const g = cv.getContext('2d');
    g.fillStyle = 'rgba(0,0,0,0.55)'; g.fillRect(0, 0, cw, ch);
    g.textAlign = 'center'; g.textBaseline = 'middle';
    rows.forEach((q) => { g.font = q.f; g.fillStyle = q.c; g.fillText(q.t, cw / 2 + q.x, q.y - minY + pad); });
    const tex = new THREE.CanvasTexture(cv); tex.minFilter = THREE.LinearFilter;
    const spr = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, depthTest: false, transparent: true }));
    const k = NODE_LABEL_SCALE / ss;
    spr.scale.set(cw * k, ch * k, 1);
    return spr;
  }
  function textSprite(txt, color) {
    const c = document.createElement('canvas'); c.width = 256; c.height = 64;
    const g = c.getContext('2d');
    g.font = '28px system-ui,sans-serif'; g.textAlign = 'center'; g.textBaseline = 'middle';
    g.fillStyle = 'rgba(0,0,0,0.55)'; g.fillRect(0, 0, 256, 64);
    g.fillStyle = color || '#e2e8f0'; g.fillText(String(txt || '').slice(0, 22), 128, 32);
    const tex = new THREE.CanvasTexture(c); tex.minFilter = THREE.LinearFilter;
    const spr = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, depthTest: false, transparent: true }));
    spr.scale.set(220, 55, 1); return spr;
  }
  let _lockTex = null;
  function lockTexture() {
    if (_lockTex) return _lockTex;
    const c = document.createElement('canvas'); c.width = 64; c.height = 64;
    const g = c.getContext('2d');
    g.font = '46px system-ui,"Segoe UI Emoji","Noto Color Emoji",sans-serif'; g.textAlign = 'center'; g.textBaseline = 'middle';
    g.fillText('🔒', 32, 35);
    _lockTex = new THREE.CanvasTexture(c); _lockTex.minFilter = THREE.LinearFilter; _lockTex.__shared = true;
    return _lockTex;
  }
  function addLockBadge(x, y, z, size) {
    const s = clamp(num(size, 44), 22, 130);
    const spr = new THREE.Sprite(new THREE.SpriteMaterial({ map: lockTexture(), transparent: true, depthTest: false }));
    spr.scale.set(s, s, 1); spr.position.set(x, y, z); scene.add(spr);
    return spr;
  }
  function buildTextItem(t) {
    const content = String(t.content == null ? '' : t.content);
    const lines = content.split('\n');
    const fs = clamp(num(t.fontSize, 18), 6, 200);
    const wv = String(t.fontWeight == null ? '' : t.fontWeight).trim();
    const weight = (/^(bold|bolder|lighter|[1-9]00)$/.test(wv)) ? wv + ' ' : '';
    const style = t.fontStyle === 'italic' ? 'italic ' : '';
    const font = style + weight + fs + 'px system-ui,sans-serif';
    const pad = Math.round(fs * 0.45), lineH = Math.round(fs * 1.25);
    const meas = document.createElement('canvas').getContext('2d'); meas.font = font;
    let maxW = 1; for (let i = 0; i < lines.length; i++) maxW = Math.max(maxW, meas.measureText(lines[i] || ' ').width);
    const cw = Math.min(4096, Math.ceil(maxW + pad * 2)), ch = Math.min(4096, Math.ceil(lineH * lines.length + pad * 2));
    const c = document.createElement('canvas'); c.width = cw; c.height = ch;
    const g = c.getContext('2d'); g.font = font; g.textBaseline = 'middle';
    if (isTrue(t.bgEnabled)) { g.globalAlpha = 0.7; g.fillStyle = t.bgColor || '#000000'; g.fillRect(0, 0, cw, ch); g.globalAlpha = 1; }
    g.fillStyle = t.color || '#e2e8f0';
    const align = t.textAlign === 'middle' ? 'center' : (t.textAlign === 'end' ? 'right' : 'left');
    g.textAlign = align;
    const tx = align === 'center' ? cw / 2 : (align === 'right' ? cw - pad : pad);
    const deco = (t.textDecoration === 'underline' || t.textDecoration === 'line-through') ? t.textDecoration : null;
    const ruleH = Math.max(1, Math.round(fs / 14));
    for (let i = 0; i < lines.length; i++) {
      const ly = pad + lineH * (i + 0.5);
      g.fillText(lines[i], tx, ly);
      if (deco && lines[i]) {
        const lw = g.measureText(lines[i]).width;
        const x0 = align === 'center' ? tx - lw / 2 : (align === 'right' ? tx - lw : tx);
        g.fillRect(x0, Math.round(deco === 'underline' ? ly + fs * 0.42 : ly - ruleH / 2), lw, ruleH);
      }
    }
    const tex = new THREE.CanvasTexture(c); tex.minFilter = THREE.LinearFilter;
    if ('colorSpace' in tex) tex.colorSpace = THREE.SRGBColorSpace;
    const op = t.opacity != null ? clamp(num(t.opacity, 1), 0, 1) : 1;
    const spr = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, opacity: op, depthTest: false }));
    const k = TEXT_WORLD_SCALE; spr.scale.set(cw * k, ch * k, 1);
    return spr;
  }
  function rectBorderWidth(r) { return clamp(Math.round(num(r && r.borderWidth !== undefined ? r.borderWidth : 2, 2)), 0, 20); }
  function addStrokeRing(parent, w, d, bw, y, color, ox, oz, ty) {
    const mat = new THREE.MeshBasicMaterial({ color: color, side: THREE.DoubleSide });
    const t = ty || 1.2, x0 = ox || 0, z0 = oz || 0, side = Math.max(0.1, d - bw);
    const put = (gw, gd, px, pz) => { const m = new THREE.Mesh(new THREE.BoxGeometry(gw, t, gd), mat); m.position.set(x0 + px, y, z0 + pz); parent.add(m); };
    put(w + bw, bw, 0, -d / 2); put(w + bw, bw, 0, d / 2);
    put(bw, side, -w / 2, 0); put(bw, side, w / 2, 0);
  }
  function buildRectWall(r) {
    const w = clamp(Math.abs(num(r.width, 0)), 1, WORLD_W * 3), d = clamp(Math.abs(num(r.height, 0)), 1, WORLD_D * 3);
    const cx = sx(num(r.x, 0) + num(r.width, 0) / 2), cz = sz(num(r.y, 0) + num(r.height, 0) / 2);
    const col = hexColor(r.color, '#94a3b8');
    const bw = rectBorderWidth(r);
    const trim = (bw > 0 && r.borderColor && r.borderColor !== r.color) ? hexColor(r.borderColor, '#94a3b8') : null;
    const op = clamp(r.fillOpacity !== undefined ? num(r.fillOpacity, 0.5) : 0.5, 0.06, 1);
    const H = clamp(num((scene3d.wallHeights || {})[r.id], WALL_HEIGHT_3D), MIN_WALL_HEIGHT, MAX_WALL_HEIGHT);
    const g = new THREE.Group(); g.position.set(cx, 0, cz); g.rotation.y = -rad(r.rotation);
    const mkMat = () => new THREE.MeshStandardMaterial({ color: col, roughness: 1, metalness: 0.02, transparent: op < 1, opacity: op });
    const seg = (sw, sd, ox, oz) => {
      const geo = new THREE.BoxGeometry(sw, H, sd);
      const m = new THREE.Mesh(geo, mkMat()); m.position.set(ox, H / 2, oz); g.add(m);
      if (trim) {
        const e = new THREE.LineSegments(new THREE.EdgesGeometry(geo), new THREE.LineBasicMaterial({ color: trim })); e.position.set(ox, H / 2, oz); g.add(e);
        if (bw > 2) addStrokeRing(g, sw, sd, bw, H + 0.7, trim, ox, oz);
      }
    };
    if (r.style === 'outlined') {
      const th = WALL_THICK_3D;
      seg(w, th, 0, -d / 2); seg(w, th, 0, d / 2);
      seg(th, Math.max(1, d - th), -w / 2, 0); seg(th, Math.max(1, d - th), w / 2, 0);
    } else {
      seg(w, d, 0, 0);
    }
    if (r.groupId) { const gi = groupBox(w / 2 + 4, d / 2 + 4); gi.position.y = 0.9; g.add(gi); }
    g.__gx = cx; g.__gz = cz; g.__hw = w / 2; g.__hd = d / 2; g.__topY = H;
    return g;
  }
  function buildRectZone(r) {
    const w = clamp(Math.abs(num(r.width, 0)), 1, WORLD_W * 3), d = clamp(Math.abs(num(r.height, 0)), 1, WORLD_D * 3);
    const cx = sx(num(r.x, 0) + num(r.width, 0) / 2), cz = sz(num(r.y, 0) + num(r.height, 0) / 2);
    const g = new THREE.Group(); g.position.set(cx, 1, cz); g.rotation.y = -rad(r.rotation);
    const hw = w / 2, hd = d / 2;
    const dash = r.lineStyle === 'dashed' ? [10, 5] : (r.lineStyle === 'dotted' ? [2, 4] : null);
    const bcol = hexColor(r.borderColor || r.color, '#f97316');
    const by = 0.4;
    const bw = rectBorderWidth(r);
    if (bw > 0) {
      const pts = [new THREE.Vector3(-hw, by, -hd), new THREE.Vector3(hw, by, -hd), new THREE.Vector3(hw, by, hd), new THREE.Vector3(-hw, by, hd), new THREE.Vector3(-hw, by, -hd)];
      const border = new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts),
        dash ? new THREE.LineDashedMaterial({ color: bcol, dashSize: dash[0], gapSize: dash[1] }) : new THREE.LineBasicMaterial({ color: bcol }));
      if (dash) border.computeLineDistances();
      g.add(border);
      if (bw > 2 && !dash) addStrokeRing(g, w, d, bw, by, bcol, 0, 0, 0.6);
    }
    if (r.style !== 'outlined') {
      const op = clamp(r.fillOpacity != null ? num(r.fillOpacity, 0.16) : 0.16, 0.02, 0.9);
      const m = new THREE.Mesh(new THREE.PlaneGeometry(w, d), new THREE.MeshBasicMaterial({ color: hexColor(r.color, '#f97316'), transparent: true, opacity: op, side: THREE.DoubleSide, depthWrite: false }));
      m.rotation.x = -Math.PI / 2; g.add(m);
    } else if (bw <= 0) {
      const ghost = new THREE.Mesh(new THREE.PlaneGeometry(w, d), new THREE.MeshBasicMaterial({ transparent: true, opacity: 0, depthWrite: false, side: THREE.DoubleSide }));
      ghost.rotation.x = -Math.PI / 2; g.add(ghost);
    }
    if (r.groupId) { const gi = groupBox(hw + 4, hd + 4); gi.position.y = 0.9; g.add(gi); }
    g.__gx = cx; g.__gz = cz; g.__hw = hw; g.__hd = hd; g.__topY = 6;
    return g;
  }
  function buildRack(node, pos, mounted, ND, styles) {
    const cap = parseInt(node.rackCapacity, 10) || 42, H = cap * RACK_PER_U;
    const g = new THREE.Group(); g.position.set(sx(pos.x), 0, sz(pos.y)); g.userData.nodeId = node.__id;
    const body = new THREE.Mesh(new THREE.BoxGeometry(RACK_WIDTH_3D, H, RACK_DEPTH_3D),
      new THREE.MeshStandardMaterial({ color: 0x0f172a, roughness: 0.85, metalness: 0.15, transparent: true, opacity: 0.35 }));
    body.position.y = H / 2; g.add(body);
    const edges = new THREE.LineSegments(new THREE.EdgesGeometry(new THREE.BoxGeometry(RACK_WIDTH_3D, H, RACK_DEPTH_3D)), new THREE.LineBasicMaterial({ color: 0x4fd1c5 }));
    edges.position.y = H / 2; g.add(edges);
    const SLOT_W = RACK_WIDTH_3D * 0.84, SLOT_D = RACK_DEPTH_3D * 0.7;
    mounted.forEach((id) => {
      const d = ND[id] || {}, u = parseInt(d.rackUnit, 10) || 1, uh = Math.max(1, parseInt(d.uHeight, 10) || 1), dh = uh * RACK_PER_U * 0.9;
      const slotY = (u - 1) * RACK_PER_U + dh / 2;
      const dst = bookResolveStyles(styles && styles[id]);
      const dCol = nodeColor(id, d, styles, dst);
      const dPing = (d.ping && d.ping.enabled) ? PING_COLORS[d.ping.status] : null;
      const dMat = new THREE.MeshStandardMaterial({ color: dPing ? hexColor(dPing) : dCol, roughness: 0.55, metalness: 0.2 });
      let placed = null;
      if (devModelsOn && deviceModelKey(d.shape, NODE_SHAPE_ALIAS)) {
        try {
          const built = buildNodeShape(d.shape, 1, dMat, dst.circleBorder || theme.nodeStroke);
          const bb = new THREE.Box3().setFromObject(built.g);
          const bw = bb.max.x - bb.min.x, bh = bb.max.y - bb.min.y, bd = bb.max.z - bb.min.z;
          if (Number.isFinite(bw) && bw > 0 && Number.isFinite(bh) && bh > 0 && Number.isFinite(bd) && bd > 0) {
            const k = Math.min(SLOT_W / bw, dh / bh, SLOT_D / bd);
            built.g.scale.setScalar(k);
            const cx = (bb.min.x + bb.max.x) / 2 * k, cy = (bb.min.y + bb.max.y) / 2 * k, cz = (bb.min.z + bb.max.z) / 2 * k;
            built.g.position.set(-cx, slotY - cy, RACK_DEPTH_3D * 0.06 - cz);
            g.add(built.g); placed = built.g;
          } else {
            built.g.traverse(function (c) { if (c.geometry) c.geometry.dispose(); });
          }
        } catch (e) { placed = null; }
      }
      if (!placed) {
        const box = new THREE.Mesh(new THREE.BoxGeometry(SLOT_W, dh, SLOT_D), dMat);
        box.position.set(0, slotY, RACK_DEPTH_3D * 0.06); g.add(box);
      }
      if (dPing && fxAllowed() && (d.ping.status === 'offline' || d.ping.status === 'checking')) { dMat.emissive = hexColor(dPing); anims.ping.push({ mat: dMat, status: d.ping.status }); }
      const lbl = textSprite(d.name || id, '#dbeafe'); lbl.scale.set(150, 38, 1); lbl.position.set(RACK_WIDTH_3D * 0.7, slotY, 0); g.add(lbl);
    });
    const rst = Object.assign({ titleColor: theme.nodeTitle || '#4fd1c5' }, bookResolveStyles(styles && styles[node.__id]));
    const cl = nodeLabelSprite((node.name || 'Rack') + '  (' + cap + 'U)', nodeSubtitle(node), rst, 55);
    cl.position.set(0, H + 46 + cl.scale.y / 2, 0); g.add(cl);
    return { group: g, topY: H };
  }
  function buildFovGroup(node) {
    const cd = coverageDefaults(node.shape);
    const dist = clamp(Number(node.fovDistance) || cd.distance, 1, 6000), ang = clamp(Number(node.fovAngle) || cd.angle, 1, 360);
    const innerR = clamp(Number(node.fovInnerRadius) || 0, 0, Math.max(0, dist - 1));
    const g = new THREE.Group();
    const coneMat = new THREE.MeshBasicMaterial({ color: hexColor(node.fovColor, '#f59e0b'), transparent: true, opacity: clamp((Number(node.fovOpacity) || 20) / 100, 0.05, 0.85), side: THREE.DoubleSide, depthWrite: false });
    const coneGeo = innerR > 0
      ? new THREE.RingGeometry(innerR, dist, 48, 1, -rad(ang) / 2, rad(ang))
      : new THREE.CircleGeometry(dist, 48, -rad(ang) / 2, rad(ang));
    const cone = new THREE.Mesh(coneGeo, coneMat);
    cone.rotation.x = -Math.PI / 2; cone.rotation.z = rad(node.fovRotation); g.add(cone);
    let anim = null;
    const type = node.fovAnimationType || cd.animationType;
    if (isTrue(node.fovAnimate) && fxAllowed() && isAnimationAllowed(node.shape, type)) {
      const speed = Math.max(0.2, Number(node.fovSpeed) || 4);
      anim = { group: g, cone: cone, type: type, speed: speed, sweep: Number(node.fovSweep) || 120, baseOpacity: coneMat.opacity, fade: 1, rings: [] };
      if (type === 'rings') {
        const inner = innerR || 10, rc = hexColor(node.fovBorderColor || node.fovColor, '#f59e0b');
        for (let i = 1; i <= 3; i++) {
          const pts = []; for (let k = 0; k <= 40; k++) { const th = (k / 40) * Math.PI * 2; pts.push(new THREE.Vector3(Math.cos(th), 0, Math.sin(th))); }
          const ring = new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), new THREE.LineBasicMaterial({ color: rc, transparent: true, opacity: 0 }));
          g.add(ring); anim.rings.push({ mesh: ring, inner: inner, dist: dist, delay: (i - 1) / 3 });
        }
      }
    }
    return { group: g, anim: anim };
  }
  function animateFov(a, t) {
    const phase = (t / safePeriod(a.speed)) % 1;
    if (a.type === 'sweep') { a.group.rotation.y = -rad(a.sweep * (1 - Math.cos(phase * Math.PI * 2)) / 2); }
    else if (a.type === 'spin') { a.group.rotation.y = -phase * Math.PI * 2; }
    else if (a.type === 'pulse') { const tri = (1 - Math.cos(phase * Math.PI * 2)) / 2; const s = 1 + 0.1 * tri; a.group.scale.set(s, s, s); a.cone.material.opacity = a.baseOpacity * a.fade * (1 - 0.3 * tri); }
    else if (a.type === 'rings') { a.rings.forEach((r) => { const rp = ((phase - r.delay) % 1 + 1) % 1; const rad3 = r.inner + (r.dist - r.inner) * rp; r.mesh.scale.set(rad3, 1, rad3); r.mesh.material.opacity = 0.8 * a.fade * (1 - rp); }); }
  }
  function animateFlow(a, t) {
    const base = t / safePeriod(a.dur);
    for (let i = 0; i < a.markers.length; i++) {
      const m = a.markers[i]; let u = base * m.sign + m.phase; u = ((u % 1) + 1) % 1;
      a.curve.getPointAt(u, m.mesh.position);
      if (m.arrow) { const tan = a.curve.getTangentAt(u).multiplyScalar(m.sign); if (tan.lengthSq() > 1e-9) m.mesh.quaternion.setFromUnitVectors(UP_Y, tan.normalize()); }
    }
  }
  function animatePing(a, t) { const p = Math.sin(t * (a.status === 'checking' ? 6 : 3)) * 0.5 + 0.5; a.mat.emissiveIntensity = 0.12 + 0.5 * p; }
  const UP_Y = new THREE.Vector3(0, 1, 0);
  const SEL_STATIC_OPACITY = 0.85;
  function setSelOpacity(o) {
    if (selBox && selBox.material) { selBox.material.transparent = true; selBox.material.opacity = o; }
    for (let i = 0; i < selHalos.length; i++) { const m = selHalos[i].material; if (m) { m.transparent = true; m.opacity = o; } }
  }
  function applyStaticAnimPose() {
    for (let i = 0; i < anims.fov.length; i++) {
      const a = anims.fov[i];
      try {
        a.group.rotation.y = 0; a.group.scale.set(1, 1, 1);
        if (a.cone && a.cone.material) a.cone.material.opacity = a.baseOpacity * a.fade;
        if (a.rings) a.rings.forEach(function (r) { const mid = r.inner + (r.dist - r.inner) * 0.6; r.mesh.scale.set(mid, 1, mid); r.mesh.material.opacity = 0.35 * a.fade; });
      } catch (e) {}
    }
    for (let i = 0; i < anims.flow.length; i++) {
      const a = anims.flow[i];
      try { for (let j = 0; j < a.markers.length; j++) { const m = a.markers[j]; a.curve.getPointAt(((m.phase % 1) + 1) % 1, m.mesh.position); } } catch (e) {}
    }
    for (let i = 0; i < anims.ping.length; i++) { try { anims.ping[i].mat.emissiveIntensity = 0.38; } catch (e) {} }
  }
  function updateAnimations(now) {
    if (!fxAllowed()) return;
    if (reduceMotion()) {
      if (!_rmStatic) { _rmStatic = true; applyStaticAnimPose(); }
      setSelOpacity(SEL_STATIC_OPACITY);
      return;
    }
    _rmStatic = false;
    const t = now / 1000;
    for (let i = 0; i < anims.fov.length; i++) animateFov(anims.fov[i], t);
    for (let i = 0; i < anims.flow.length; i++) animateFlow(anims.flow[i], t);
    for (let i = 0; i < anims.ping.length; i++) animatePing(anims.ping[i], t);
    setSelOpacity(0.55 + 0.45 * Math.sin(t * 5));
  }
  function edgeShouldFlow(e) {
    if (!connectionsAnimAllowed()) return false;
    const ps = getVar('PAGE_STATE') || {}; const dir = e.direction || 'none';
    if (dir === 'none') return false;
    if (!((ps.animateConnections && e.animate !== false) || e.animate === true)) return false;
    const ad = ps.animationDirection || 'all';
    return ad === 'all' || ad === dir;
  }
  function addEdgeFlow(e, pts3, radius) {
    const ps = getVar('PAGE_STATE') || {};
    const style = e.animationStyle || ps.animationStyle || 'arrows';
    const dur = Math.max(0.3, parseFloat(e.animationSpeed) || Number(ps.animationSpeed) || 1.5);
    const dir = e.direction || 'none';
    const curve = pts3.length === 2 ? new THREE.LineCurve3(pts3[0], pts3[1]) : new THREE.CatmullRomCurve3(pts3, false, 'centripetal', 0.5);
    const mat = new THREE.MeshBasicMaterial({ color: hexColor(e.color || theme.defaultEdge, '#94a3b8') });
    const geo = style === 'dots' ? new THREE.SphereGeometry(Math.max(4, radius * 1.7), 8, 8) : new THREE.ConeGeometry(Math.max(6, radius * 1.9), Math.max(16, radius * 4.5), 8);
    const flow = { curve: curve, dur: dur, markers: [] }, count = 3, signs = [];
    if (dir === 'forward' || dir === 'both') signs.push(1);
    if (dir === 'backward' || dir === 'both') signs.push(-1);
    signs.forEach((sign) => { for (let i = 0; i < count; i++) { const mk = new THREE.Mesh(geo, mat); wireAdd(mk); flow.markers.push({ mesh: mk, sign: sign, phase: (sign > 0 ? i : i + 0.5) / count, arrow: style !== 'dots' }); } });
    anims.flow.push(flow);
  }

  const imgTexCache = {};
  let _imgUsed = null;
  function getImgTexture(src) {
    if (_imgUsed) _imgUsed.add(src);
    if (imgTexCache[src]) return imgTexCache[src];
    const tex = new THREE.TextureLoader().load(src, undefined, undefined, function () {});
    if ('colorSpace' in tex) tex.colorSpace = THREE.SRGBColorSpace;
    imgTexCache[src] = tex; return tex;
  }
  function pruneImgTexCache(used) {
    for (const k in imgTexCache) { if (!used || !used.has(k)) { try { imgTexCache[k].dispose(); } catch (e) {} delete imgTexCache[k]; } }
  }
  function clearImgTexCache() { for (const k in imgTexCache) { try { imgTexCache[k].dispose(); } catch (e) {} delete imgTexCache[k]; } }
  function disposeMaterial(m) {
    if (!m) return;
    (Array.isArray(m) ? m : [m]).forEach(function (x) { if (x.map && x.map.isCanvasTexture && !x.map.__shared) x.map.dispose(); x.dispose(); });
  }
  function disposeObject3D(o) { if (o && o.traverse) o.traverse(function (c) { if (c.userData && c.userData.__modelClone) return; if (c.geometry) c.geometry.dispose(); if (c.material) disposeMaterial(c.material); }); }
  function disposeOldScene() {
    if (!scene) return;
    const keep = [];
    for (const id in avatars) keep.push(avatars[id].grp);
    for (let i = 0; i < xrObjects.length; i++) keep.push(xrObjects[i]);
    if (wireRoot) keep.push(wireRoot);
    keep.forEach(function (o) { if (o.parent) o.parent.remove(o); });
    scene.children.slice().forEach(function (c) { disposeObject3D(c); });
  }

  const modelCache = {};
  function getModel(hash) {
    const c = modelCache[hash];
    if (c && c !== 'loading' && c !== 'error') return c;
    if (c) return null;
    modelCache[hash] = 'loading';
    getGLTFLoader().then(function (loader) {
      loader.load('/api/asset/' + hash, function (gltf) { modelCache[hash] = gltf.scene; if (active) buildScene(); }, undefined, function () { modelCache[hash] = 'error'; });
    }).catch(function () { modelCache[hash] = 'error'; });
    return null;
  }
  function clearModelCache() { for (const k in modelCache) { const m = modelCache[k]; if (m && m.traverse) disposeObject3D(m); delete modelCache[k]; } }

  function buildFurniture(f) {
    const g = new THREE.Group();
    g.position.set(sx(clamp(num(f.x, WORLD_W / 2), 0, WORLD_W)), clamp(num(f.y, 0), -200, MAX_ELEVATION), sz(clamp(num(f.z, WORLD_D / 2), 0, WORLD_D))); g.rotation.y = wrapAngle(f.rotY);
    const s = clamp(num(f.scale, 1), 0.2, 6), col = hexColor(f.color, '#8b5e3c');
    const mat = () => new THREE.MeshStandardMaterial({ color: col, roughness: 0.7, metalness: 0.05 });
    if (f.kind === 'table') {
      const top = new THREE.Mesh(new THREE.BoxGeometry(160 * s, 12 * s, 90 * s), mat()); top.position.y = 75 * s; g.add(top);
      [[-70, -38], [70, -38], [-70, 38], [70, 38]].forEach((p) => { const leg = new THREE.Mesh(new THREE.BoxGeometry(10 * s, 75 * s, 10 * s), mat()); leg.position.set(p[0] * s, 37 * s, p[1] * s); g.add(leg); });
    } else if (f.kind === 'shelf') {
      const w = 140 * s, d = 40 * s;
      for (let i = 0; i < 4; i++) { const sh = new THREE.Mesh(new THREE.BoxGeometry(w, 8 * s, d), mat()); sh.position.y = (i * 60 + 10) * s; g.add(sh); }
      [-w / 2, w / 2].forEach((x) => { const side = new THREE.Mesh(new THREE.BoxGeometry(8 * s, 200 * s, d), mat()); side.position.set(x, 100 * s, 0); g.add(side); });
    } else if (f.kind === 'lamp') {
      g.add(new THREE.Mesh(new THREE.CylinderGeometry(20 * s, 26 * s, 10 * s, 16), mat()));
      const pole = new THREE.Mesh(new THREE.CylinderGeometry(4 * s, 4 * s, 150 * s, 8), mat()); pole.position.y = 80 * s; g.add(pole);
      const shade = new THREE.Mesh(new THREE.ConeGeometry(35 * s, 40 * s, 20, 1, true), new THREE.MeshStandardMaterial({ color: hexColor(f.color, '#fde68a'), emissive: hexColor(f.color, '#fbbf24'), emissiveIntensity: 0.8, side: THREE.DoubleSide })); shade.position.y = 170 * s; g.add(shade);
    } else if (f.kind === 'wall') {
      const wall = new THREE.Mesh(new THREE.BoxGeometry(300 * s, 180 * s, 14 * s), new THREE.MeshStandardMaterial({ color: hexColor(f.color, '#94a3b8'), roughness: 1 })); wall.position.y = 90 * s; g.add(wall);
    } else if (f.kind === 'plant') {
      const pot = new THREE.Mesh(new THREE.CylinderGeometry(22 * s, 16 * s, 30 * s, 14), new THREE.MeshStandardMaterial({ color: 0x7c4a2d })); pot.position.y = 15 * s; g.add(pot);
      const fol = new THREE.Mesh(new THREE.IcosahedronGeometry(40 * s, 0), new THREE.MeshStandardMaterial({ color: 0x3f6f3f, flatShading: true })); fol.position.y = 70 * s; g.add(fol);
    } else if (f.kind === 'frame') {
      const w = 150 * s, h = 105 * s, cy = h / 2 + 30 * s;
      const border = new THREE.Mesh(new THREE.BoxGeometry(w + 16 * s, h + 16 * s, 9 * s), new THREE.MeshStandardMaterial({ color: hexColor(f.color, '#5b4636'), roughness: 0.55 }));
      border.position.y = cy; g.add(border);
      const tex = (f.image && HEX64_RE.test(f.image)) ? getImgTexture('/api/asset/' + f.image) : null;
      const faceMat = tex ? new THREE.MeshBasicMaterial({ map: tex, side: THREE.DoubleSide }) : new THREE.MeshStandardMaterial({ color: 0x9aa7b4, roughness: 0.9 });
      const face = new THREE.Mesh(new THREE.PlaneGeometry(w, h), faceMat); face.position.set(0, cy, 5.2 * s); g.add(face);
      const face2 = new THREE.Mesh(new THREE.PlaneGeometry(w, h), faceMat); face2.rotation.y = Math.PI; face2.position.set(0, cy, -5.2 * s); g.add(face2);
      const post = new THREE.Mesh(new THREE.CylinderGeometry(4 * s, 4 * s, 30 * s, 8), mat()); post.position.y = 15 * s; g.add(post);
    } else if (f.kind === 'model') {
      const src = (f.model && HEX64_RE.test(f.model)) ? getModel(f.model) : null;
      if (src) {
        const inst = src.clone(true);
        inst.traverse(function (c) { c.userData.__modelClone = true; if (c.isMesh) c.frustumCulled = false; });
        const box = new THREE.Box3().setFromObject(inst), sz3 = new THREE.Vector3(); box.getSize(sz3);
        const maxd = Math.max(sz3.x, sz3.y, sz3.z) || 1, norm = (110 * s) / maxd;
        inst.scale.setScalar(norm);
        const b2 = new THREE.Box3().setFromObject(inst); inst.position.y = -b2.min.y;
        g.add(inst);
      } else {
        const ph = new THREE.Mesh(new THREE.BoxGeometry(70 * s, 70 * s, 70 * s), new THREE.MeshStandardMaterial({ color: col, roughness: 0.7, wireframe: !!(f.model && HEX64_RE.test(f.model)) }));
        ph.position.y = 35 * s; g.add(ph);
      }
    } else {
      const box = new THREE.Mesh(new THREE.BoxGeometry(60 * s, 60 * s, 60 * s), mat()); box.position.y = 30 * s; g.add(box);
    }
    g.userData.furnId = f.id;
    return g;
  }
  function sanitizeFurnItem(f) {
    if (!f || typeof f !== 'object' || !FURN_KINDS.has(f.kind)) return null;
    const item = {
      id: (typeof f.id === 'string' && f.id) ? f.id.slice(0, 80) : ('f-' + Date.now() + '-' + Math.floor(Math.random() * 1e4)),
      kind: f.kind,
      x: clamp(Math.round(num(f.x, WORLD_W / 2)), 0, WORLD_W),
      z: clamp(Math.round(num(f.z, WORLD_D / 2)), 0, WORLD_D),
      y: clamp(num(f.y, 0), -200, MAX_ELEVATION),
      rotY: wrapAngle(f.rotY),
      scale: clamp(num(f.scale, 1), 0.2, 6)
    };
    if (typeof f.color === 'string' && /^#?[0-9a-zA-Z]{1,20}$/.test(f.color)) item.color = f.color;
    if (typeof f.image === 'string' && HEX64_RE.test(f.image)) item.image = f.image;
    if (typeof f.model === 'string' && HEX64_RE.test(f.model)) item.model = f.model;
    return item;
  }
  function sanitizeFurnList(arr) {
    if (!Array.isArray(arr)) return [];
    const out = [];
    for (let i = 0; i < arr.length && out.length < MAX_FURNITURE; i++) { const s = sanitizeFurnItem(arr[i]); if (s) out.push(s); }
    return out;
  }
  function placeFurniture(kind, fp) {
    if (!sceneReady || scene3d.furniture.length >= MAX_FURNITURE) return;
    const f = { id: 'f-' + Date.now() + '-' + Math.floor(Math.random() * 1e4), kind: kind, x: clamp(Math.round(wx(fp.x)), 0, WORLD_W), z: clamp(Math.round(wy(fp.z)), 0, WORLD_D), y: 0, rotY: 0, scale: 1 };
    scene3d.furniture.push(f); scheduleSave(); buildScene(); broadcastFurn({ op: 'add', item: f });
  }
  function placeItem(item, fp) {
    if (!item) return;
    if (editBlocked(item.place)) return;
    if (item.place === 'furniture') { placeFurniture(item.furnKind, fp); return; }
    if (item.place === 'node' || item.place === 'rack') { createNodeAt(fp, item.place === 'rack'); return; }
    if (item.place === 'rect') { createRectAt(fp, item.rectKind); return; }
    if (item.place === 'text') { createTextAt(fp); return; }
    if (item.place === 'image') { createImageAt(fp); return; }
  }
  function encodeImage2D(img, w, h) {
    try {
      const c = document.createElement('canvas'); c.width = w; c.height = h;
      const ctx = c.getContext('2d'); if (!ctx) return null;
      ctx.drawImage(img, 0, 0, w, h);
      let hasTransparency = false;
      try { const d = ctx.getImageData(0, 0, w, h).data; for (let i = 3; i < d.length; i += 4) { if (d[i] < 255) { hasTransparency = true; break; } } } catch (e) { hasTransparency = true; }
      const webp = c.toDataURL('image/webp', 0.8);
      if (webp.startsWith('data:image/webp')) return webp;
      return hasTransparency ? c.toDataURL('image/png') : c.toDataURL('image/jpeg', 0.8);
    } catch (e) { return null; }
  }
  function createImageAt(fp) {
    const id0 = getVar('IMAGE_DATA');
    if (!id0 || !Array.isArray(id0.list)) return;
    if (id0.list.length >= MAX_CANVAS_IMAGES) { guardToast('🖼 Image limit reached (' + MAX_CANVAS_IMAGES + ' per room), delete one first.'); return; }
    const cx = Math.round(clamp(wx(fp.x), PAD, WORLD_W - PAD)), cy = Math.round(clamp(wy(fp.z), PAD, WORLD_D - PAD));
    const inp = document.createElement('input'); inp.type = 'file'; inp.accept = 'image/*';
    inp.addEventListener('change', function () {
      const file = inp.files && inp.files[0]; if (!file) return;
      if (file.size > 5 * 1024 * 1024) { guardToast('🖼 That file is over 5 MB, pick a smaller one.'); return; }
      const reader = new FileReader();
      reader.onload = function (ev) {
        const src = ev.target.result, img = new Image();
        img.onload = function () {
          const iw = img.width || 200, ih = img.height || 200;
          const sc = Math.min(1, MAX_IMAGE_SIZE / Math.max(iw, ih));
          const w = Math.max(1, Math.round(iw * sc)), h = Math.max(1, Math.round(ih * sc));
          const idd = getVar('IMAGE_DATA'); if (!idd || !Array.isArray(idd.list)) return;
          if (idd.list.length >= MAX_CANVAS_IMAGES) { guardToast('🖼 Image limit reached (' + MAX_CANVAS_IMAGES + ' per room), delete one first.'); return; }
          const stored = encodeImage2D(img, w, h) || src;
          const push = getVar('pushUndo'); if (typeof push === 'function') { try { push('add image (3D)'); } catch (e) {} }
          idd.list.push({ id: 'img-' + Date.now(), name: file.name || 'image', x: Math.round(clamp(cx - w / 2, 0, WORLD_W - w)), y: Math.round(clamp(cy - h / 2, 0, WORLD_D - h)), width: w, height: h, src: stored, opacity: 1, border: 'none', shadow: 'none', notes: [], baseWidth: w, baseHeight: h });
          setVar('IMAGE_DATA', idd);
          const forge = getVar('forgeTheTopology') || window.forgeTheTopology; if (typeof forge === 'function') { try { forge(); } catch (e) {} }
          buildScene();
        };
        img.src = src;
      };
      reader.readAsDataURL(file);
    });
    inp.click();
  }
  function createRectAt(fp, kind) {
    const rd = getVar('RECT_DATA');
    if (!rd || typeof rd !== 'object' || !Array.isArray(rd.list)) return;
    const isWall = kind === 'wall';
    const push = getVar('pushUndo'); if (typeof push === 'function') { try { push(isWall ? 'add wall (3D)' : 'add zone (3D)'); } catch (e) {} }
    const cx = Math.round(clamp(wx(fp.x), PAD, WORLD_W - PAD)), cy = Math.round(clamp(wy(fp.z), PAD, WORLD_D - PAD));
    const W = isWall ? 480 : 520, H = isWall ? 40 : 400;
    rd.list.push({
      id: 'rect-' + Date.now() + '-' + Math.floor(Math.random() * 1e4),
      x: Math.round(clamp(cx - W / 2, 0, WORLD_W - W)), y: Math.round(clamp(cy - H / 2, 0, WORLD_D - H)),
      width: W, height: H,
      color: isWall ? '#94a3b8' : '#f97316',
      style: 'filled', lineStyle: isWall ? 'wall' : 'solid',
      fillOpacity: isWall ? 0.5 : 0.3, borderColor: '', borderWidth: 2, rotation: 0, notes: []
    });
    setVar('RECT_DATA', rd);
    const forge = getVar('forgeTheTopology') || window.forgeTheTopology; if (typeof forge === 'function') { try { forge(); } catch (e) {} }
    buildScene();
  }
  function createTextAt(fp) {
    const td = getVar('TEXT_DATA');
    if (!td || typeof td !== 'object' || !Array.isArray(td.list)) return;
    const push = getVar('pushUndo'); if (typeof push === 'function') { try { push('add text (3D)'); } catch (e) {} }
    td.list.push({
      id: 'text-' + Date.now(),
      x: Math.round(clamp(wx(fp.x), PAD, WORLD_W - PAD)), y: Math.round(clamp(wy(fp.z), PAD, WORLD_D - PAD)),
      content: 'Text', fontSize: 18, color: '#e2e8f0', fontWeight: 'normal', fontStyle: 'normal',
      textAlign: 'start', textDecoration: 'none', bgColor: '#000000', bgEnabled: false, opacity: 1, rotation: 0
    });
    setVar('TEXT_DATA', td);
    const forge = getVar('forgeTheTopology') || window.forgeTheTopology; if (typeof forge === 'function') { try { forge(); } catch (e) {} }
    buildScene();
  }
  function createNodeAt(fp, isRack) {
    const nd = getVar('NODE_DATA'), sp = getVar('savedPositions');
    if (!nd || typeof nd !== 'object' || !sp || typeof sp !== 'object') return;
    const sz = getVar('savedSizes') || {};
    const push = getVar('pushUndo'); if (typeof push === 'function') { try { push(isRack ? 'add rack (3D)' : 'add node (3D)'); } catch (e) {} }
    const base = isRack ? 'rack' : 'node';
    let id = base, n = 1; while (nd[id]) id = base + '-' + (n++);
    const node = { shape: 'circle', name: id, ip: '', role: isRack ? 'Rack' : '', tags: [], notes: [], mac: '', rackUnit: '', uHeight: '1', layer: 'layer1', assignedRack: '', hostedOn: '', locked: false, groupId: null };
    if (isRack) { node.isRack = true; node.rackCapacity = '42'; }
    nd[id] = node;
    sp[id] = { x: Math.round(clamp(wx(fp.x), PAD, WORLD_W - PAD)), y: Math.round(clamp(wy(fp.z), PAD, WORLD_D - PAD)) };
    sz[id] = 55;
    setVar('NODE_DATA', nd); setVar('savedPositions', sp); setVar('savedSizes', sz);
    const forge = getVar('forgeTheTopology') || window.forgeTheTopology;
    if (typeof forge === 'function') { try { forge(); } catch (e) {} }
    buildScene();
    const obj = pickables.find((m) => m.userData.nodeId === id); if (obj) selectItem('node', id, obj);
    openNodeBook(id);
  }
  let saveTimer = null;
  let sceneReady = false;
  function scheduleSave() {
    markTabDirty(tabKey());
    if (reloadRequired) return;
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(function () { saveTimer = null; saveScene3d(false); }, 600);
  }
  const RECONCILE_MS = 15000;
  let reconcileTimer = null;
  function scheduleReconcile(key) {
    markTabDirty(key);
    if (reloadRequired || reconcileTimer || saveTimer) return;
    reconcileTimer = setTimeout(function () { reconcileTimer = null; saveScene3d(false); }, RECONCILE_MS);
  }
  function cancelReconcile() { if (reconcileTimer) { clearTimeout(reconcileTimer); reconcileTimer = null; } }
  function flushSave(unloading) { if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; saveScene3d(!!unloading); } }

  const SAVE_RETRY_DELAYS = [800, 2000, 5000, 12000];
  let saveRetryTimer = null, saveRetryAt = 0, saveInFlight = false, saveDirtyDuringFlight = false;
  function cancelSaveRetry() { if (saveRetryTimer) { clearTimeout(saveRetryTimer); saveRetryTimer = null; } saveRetryAt = 0; }
  function scheduleSaveRetry(reason, minDelay) {
    if (saveRetryAt >= SAVE_RETRY_DELAYS.length) { showSaveError(reason); return; }
    let d = SAVE_RETRY_DELAYS[saveRetryAt++];
    const md = Number(minDelay);
    if (Number.isFinite(md) && md > d) d = Math.min(md + 500, 90000);
    showSaveWarning('⏳ 3D save failed (' + reason + '), retrying in ' + Math.round(d / 1000) + 's…');
    if (saveRetryTimer) clearTimeout(saveRetryTimer);
    saveRetryTimer = setTimeout(function () { saveRetryTimer = null; saveScene3d(false); }, d);
  }
  function sceneBody() {
    const active = tabKey();
    const tabs = {};
    const push = function (k) {
      const b = scene3d.tabs[k];
      if (!b || Object.prototype.hasOwnProperty.call(tabs, k)) return;
      tabs[k] = { furniture: b.furniture, heights: b.heights, buried: b.buried, wallHeights: b.wallHeights, rev: tabRev(k) };
    };
    dirtyTabs.forEach(push);
    push(active);
    return { sent: Object.keys(tabs), tabIdx: currentTabIdentity(), body: JSON.stringify({ version: 2, rev: sceneRev, mpu: scene3d.mpu, wireMode: scene3d.wireMode, tabs: tabs }) };
  }
  function saveScene3d(unloading) {
    if (!ROOM_ID || !sceneReady) return;
    if (reloadRequired) return;
    if (saveInFlight && !unloading) { saveDirtyDuringFlight = true; return; }
    const built = sceneBody();
    const sent = built.sent, carrierTab = built.tabIdx;
    for (let i = 0; i < sent.length; i++) dirtyTabs.delete(sent[i]);
    const carried = Object.create(null);
    for (let i = 0; i < sent.length; i++) { carried[sent[i]] = localOps[sent[i]] || []; localOps[sent[i]] = []; }
    const opts = { method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'x-csrf-token': window.CSRF_TOKEN || '' }, body: built.body };
    if (unloading) opts.keepalive = true;
    const p = fetch('/api/room/' + ROOM_ID + '/scene3d', opts);
    if (unloading) { p.catch(function () {}); return; }
    saveInFlight = true;
    p.then(function (r) {
      if (!r.ok) {
        const e = new Error('HTTP ' + r.status); e.status = r.status;
        const ra = Number(r.headers && r.headers.get ? r.headers.get('retry-after') : 0);
        e.retryAfterMs = (Number.isFinite(ra) && ra > 0) ? Math.min(ra, 90) * 1000 : 0;
        throw e;
      }
      return r.json();
    }).then(function (j) {
      saveInFlight = false; cancelSaveRetry(); clearSaveError();
      const conflicts = (j && Array.isArray(j.conflicts)) ? j.conflicts : [];
      if (j && typeof j.rev === 'number') sceneRev = j.rev;
      if (j && j.tabs && typeof j.tabs === 'object') {
        for (const k in j.tabs) { const r = j.tabs[k]; if (r && typeof r.rev === 'number') tabRevs[k] = r.rev | 0; }
      }
      if (j && j.truncated) {
        showSaveWarning('⚠ 3D scene is over the size limit, '
          + ((j.droppedFurniture | 0) + (j.droppedMapKeys | 0)) + ' item(s) were not saved.'
          + droppedByTabDetail(j.droppedByTab));
      }
      if (j && j.code) writeSceneCarrier(j.code, false, carrierTab);
      if (conflicts.length) refetchTabs(conflicts, carried);
      if (saveDirtyDuringFlight) { saveDirtyDuringFlight = false; scheduleSave(); }
    }).catch(function (e) {
      saveInFlight = false; saveDirtyDuringFlight = false;
      for (let i = 0; i < sent.length; i++) dirtyTabs.add(sent[i]);
      for (let i = 0; i < sent.length; i++) { const k = sent[i]; localOps[k] = carried[k].concat(localOps[k] || []); }
      const st = e && e.status;
      if (st === 409) { reloadRequired = true; cancelSaveRetry(); cancelReconcile(); if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; } showReloadRequired(); return; }
      if (st === 400 || st === 413) { showSaveError('rejected by server (HTTP ' + st + ')'); return; }
      scheduleSaveRetry(st === 429 ? 'rate limited' : (st ? 'HTTP ' + st : 'network error'), e && e.retryAfterMs);
    });
  }
  let pendingConflictRebuild = false;
  function refetchTabs(keys, carried) {
    if (!ROOM_ID || !keys || !keys.length) return;
    fetch('/api/room/' + ROOM_ID + '/scene3d', { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) {
        if (!sceneReady) return;
        const raw = (d && d.tabs && typeof d.tabs === 'object' && !Array.isArray(d.tabs)) ? d.tabs : null;
        if (!raw) return;
        const cur = tabKey();
        let touchedActive = false, rebased = false;
        for (let i = 0; i < keys.length; i++) {
          const k = keys[i];
          if (!Object.prototype.hasOwnProperty.call(raw, k)) continue;
          scene3d.tabs[k] = readBucket(raw[k]);
          tabRevs[k] = (raw[k] && typeof raw[k].rev === 'number') ? (raw[k].rev | 0) : 0;
          dirtyTabs.delete(k);
          const log = carried && carried[k] ? carried[k] : null;
          if (log && log.length) {
            for (let j = 0; j < log.length; j++) { try { applyFurnOp(log[j]); } catch (x) {} }
            const merged = log.concat(localOps[k] || []);
            localOps[k] = merged.length > MAX_LOCAL_OPS ? merged.slice(merged.length - MAX_LOCAL_OPS) : merged;
            markTabDirty(k); rebased = true;
          }
          if (k === cur) touchedActive = true;
        }
        if (typeof d.rev === 'number') sceneRev = d.rev;
        if (rebased) scheduleSave();
        if (!touchedActive) return;
        if (dragId || dragGroup) { pendingConflictRebuild = true; return; }
        buildScene();
      })
      .catch(function () {  });
  }
  let pendingPeerRebuild = false;
  function deferrableRebuild() { if (dragId || dragGroup) { pendingPeerRebuild = true; return; } buildScene(); }
  function flushConflictRebuild() {
    if (dragId || dragGroup) return;
    if (!pendingConflictRebuild && !pendingPeerRebuild) return;
    pendingConflictRebuild = false; pendingPeerRebuild = false;
    buildScene();
  }
  function showReloadRequired() {
    const e = saveBanner(); if (!e) return;
    e.style.background = '#7f1d1d'; e.style.color = '#fecaca'; e.style.cursor = 'pointer';
    e.textContent = '⚠ This room’s 3D scene was upgraded by another client, reload the page to keep editing. Changes are no longer being saved.';
    e.onclick = function () { try { location.reload(); } catch (x) {} };
  }
  let ourSceneCode = null, pendingCarrier = null;
  function currentTabIdentity() {
    try {
      const tabs = getVar('documentTabs'); const i = num(getVar('currentTabIndex'), 0) | 0;
      const t = (Array.isArray(tabs) && tabs[i]) ? tabs[i] : null;
      return { idx: i, id: (t && typeof t.id === 'string') ? t.id : null };
    } catch (e) { return { idx: 0, id: null }; }
  }
  function writeSceneCarrier(code, force, carrier) {
    if (!code || !/^[A-Za-z0-9_-]{1,64}$/.test(code)) return;
    ourSceneCode = code;
    try {
      const tabs = getVar('documentTabs');
      if (!Array.isArray(tabs)) return;
      let i;
      if (carrier) {
        i = carrier.id ? tabs.findIndex(function (t) { return t && t.id === carrier.id; }) : -1;
        if (i < 0 && !carrier.id && tabs[carrier.idx]) i = carrier.idx;
        if (i < 0) return;
      } else {
        i = num(getVar('currentTabIndex'), 0) | 0;
      }
      if (!tabs[i]) return;
      const cur = tabs[i].threeDRoom;
      if (cur === '3d:' + code) return;
      const m = (typeof cur === 'string') && cur.match(/^3d:([A-Za-z0-9_-]{1,64})$/);
      if (m && m[1] !== code && !force) {
        if (pendingCarrier !== m[1]) {
          pendingCarrier = m[1];
          try { console.warn('[3d] tab carries a foreign scene code', m[1], '— not overwriting with', code); } catch (e2) {}
          showCarrierPrompt(m[1]);
        }
        return;
      }
      tabs[i].threeDRoom = '3d:' + code; setVar('documentTabs', tabs);
    } catch (e) {}
  }
  function readBucket(src) {
    const b = emptyBucket();
    b.furniture = sanitizeFurnList(src && src.furniture);
    b.heights = (src && src.heights && typeof src.heights === 'object' && !Array.isArray(src.heights)) ? src.heights : {};
    b.buried = (src && src.buried && typeof src.buried === 'object' && !Array.isArray(src.buried)) ? src.buried : {};
    b.wallHeights = (src && src.wallHeights && typeof src.wallHeights === 'object' && !Array.isArray(src.wallHeights)) ? src.wallHeights : {};
    return b;
  }
  function bucketEmpty(b) {
    return !b || (!b.furniture.length && !Object.keys(b.heights).length && !Object.keys(b.buried).length && !Object.keys(b.wallHeights).length);
  }
  function loadScene3d(cb) {
    if (!ROOM_ID) { sceneReady = true; if (cb) cb(); return; }
    fetch('/api/room/' + ROOM_ID + '/scene3d', { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) {
        scene3d.mpu = (d && typeof d.mpu === 'number' && d.mpu >= 0 && d.mpu <= 1) ? d.mpu : 0;
        scene3d.wireMode = (d && Number.isInteger(d.wireMode) && d.wireMode >= 0 && d.wireMode <= 2) ? d.wireMode : 0;
        const fresh = Object.create(null);
        const freshRevs = Object.create(null);
        let migrated = false, migratedTargets = [];
        const rawTabs = (d && d.tabs && typeof d.tabs === 'object' && !Array.isArray(d.tabs)) ? d.tabs : null;
        if (rawTabs) {
          const rawKeys = Object.keys(rawTabs);
          for (let i = 0, n = 0; i < rawKeys.length && n < MAX_SCENE_TABS; i++) {
            const raw = rawKeys[i];
            const k = String(raw).slice(0, 64).replace(TAB_KEY_RE, '_');
            if (!k || k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
            if (Object.prototype.hasOwnProperty.call(fresh, k)) continue;
            fresh[k] = readBucket(rawTabs[raw]); n++;
            freshRevs[k] = (rawTabs[raw] && typeof rawTabs[raw].rev === 'number') ? (rawTabs[raw].rev | 0) : 0;
          }
        } else if (d && (Array.isArray(d.furniture) || d.heights || d.buried || d.wallHeights)) {
          fresh[LEGACY_TAB_KEY] = readBucket(d); freshRevs[LEGACY_TAB_KEY] = 0;
        }
        const key = tabKey();
        const canAdopt = function (k) { return !Object.prototype.hasOwnProperty.call(fresh, k) || bucketEmpty(fresh[k]); };
        if (Object.prototype.hasOwnProperty.call(fresh, LEGACY_TAB_KEY) && !bucketEmpty(fresh[LEGACY_TAB_KEY])) {
          const target = canAdopt('main') ? 'main' : (canAdopt(key) ? key : null);
          if (target) {
            fresh[target] = fresh[LEGACY_TAB_KEY];
            freshRevs[target] = freshRevs[target] || 0;
            fresh[LEGACY_TAB_KEY] = emptyBucket();
            migrated = true; migratedTargets = [target, LEGACY_TAB_KEY];
          }
        } else if (Object.prototype.hasOwnProperty.call(fresh, LEGACY_TAB_KEY)) {
          delete fresh[LEGACY_TAB_KEY]; delete freshRevs[LEGACY_TAB_KEY];
        }
        if (!Object.prototype.hasOwnProperty.call(fresh, key)) { fresh[key] = emptyBucket(); freshRevs[key] = 0; }
        scene3d.tabs = fresh;
        for (const k in tabRevs) delete tabRevs[k];
        for (const k in freshRevs) tabRevs[k] = freshRevs[k] | 0;
        dirtyTabs.clear(); clearLocalOps(); cancelReconcile(); reloadRequired = false;
        sceneRev = (d && typeof d.rev === 'number') ? (d.rev | 0) : 0;
        if (d && d.code) { ourSceneCode = d.code; }
        sceneReady = true; clearLoadError(); cancelSaveRetry(); clearSaveError(); refreshScaleBtn(); refreshWireBtn();
        if (d && d.code) writeSceneCarrier(d.code);
        if (migrated) { for (let i = 0; i < migratedTargets.length; i++) markTabDirty(migratedTargets[i]); scheduleSave(); }
        if (pendingFurnOps.length) { const q = pendingFurnOps.splice(0); q.forEach((op) => applyFurnOp(op)); }
        if (cb) cb();
      })
      .catch(function () {
        sceneReady = false; showLoadError();
        if (cb) cb();
      });
  }
  function showCarrierPrompt(code) {
    if (!overlay || !active) return;
    let e = document.getElementById('threed-carrier-prompt');
    if (e) e.remove();
    e = document.createElement('div');
    e.id = 'threed-carrier-prompt';
    e.style.cssText = 'position:absolute;left:50%;top:16px;transform:translateX(-50%);z-index:8;max-width:70%;background:#1e3a5f;color:#dbeafe;font:12px/1.5 system-ui,sans-serif;padding:10px 14px;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,.5);display:flex;gap:10px;align-items:center;flex-wrap:wrap';
    const t = document.createElement('span');
    t.textContent = '📦 This tab was imported with its own 3D scene. Load it into this tab?';
    e.appendChild(t);
    const load = mkBtn('Load it', '#2563eb', '#fff', function () { e.remove(); adoptCarrier(code); });
    const keep = mkBtn('Keep this room\'s', '#334155', '#e2e8f0', function () {
      e.remove(); pendingCarrier = null;
      if (ourSceneCode) writeSceneCarrier(ourSceneCode, true);
    });
    load.style.cssText += ';padding:4px 10px;font-size:12px'; keep.style.cssText += ';padding:4px 10px;font-size:12px';
    e.appendChild(load); e.appendChild(keep);
    overlay.appendChild(e);
  }
  function adoptCarrier(code) {
    if (!ROOM_ID || !code || !/^[A-Za-z0-9_-]{1,64}$/.test(code)) return;
    fetch('/api/room/' + ROOM_ID + '/scene3d/by-code/' + encodeURIComponent(code), { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) {
        if (!sceneReady) return;
        const key = tabKey();
        const tabs = (d && d.tabs && typeof d.tabs === 'object' && !Array.isArray(d.tabs)) ? d.tabs : null;
        let src = null;
        if (tabs) {
          if (Object.prototype.hasOwnProperty.call(tabs, key)) src = tabs[key];
          else if (Object.prototype.hasOwnProperty.call(tabs, LEGACY_TAB_KEY)) src = tabs[LEGACY_TAB_KEY];
          else { const ks = Object.keys(tabs); src = ks.length ? tabs[ks[0]] : null; }
        } else src = d;
        if (!src) { guardToast('📦 That scene code holds nothing to import.'); return; }
        scene3d.tabs[key] = readBucket(src);
        markTabDirty(key);
        pendingCarrier = null;
        buildScene(); scheduleSave();
        guardToast('📦 Imported 3D scene loaded into this tab.');
      })
      .catch(function () { guardToast('📦 Could not load that scene code.'); });
  }
  function showLoadError() {
    if (!overlay) return;
    let e = document.getElementById('threed-load-err');
    if (!e) {
      e = document.createElement('div');
      e.id = 'threed-load-err';
      e.setAttribute('role', 'alert');
      e.setAttribute('aria-live', 'assertive');
      e.style.cssText = 'position:absolute;left:50%;top:16px;transform:translateX(-50%);z-index:3;background:#7f1d1d;color:#fecaca;font:12px/1.4 system-ui,sans-serif;padding:8px 14px;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,.5);cursor:pointer;display:flex;align-items:center;gap:10px';
      const msg = document.createElement('span');
      msg.textContent = '⚠ Could not load saved furniture, editing disabled.';
      e.appendChild(msg);
      const retry = document.createElement('button');
      retry.type = 'button'; retry.textContent = 'Retry';
      retry.setAttribute('aria-label', 'Retry loading the saved 3D scene');
      retry.style.cssText = 'padding:4px 10px;border:1px solid #fecaca;border-radius:6px;background:transparent;color:#fecaca;font:600 12px system-ui;cursor:pointer'
        + (COARSE_POINTER ? ';min-height:44px;min-width:44px' : '');
      e.appendChild(retry);
      e.addEventListener('click', function () { e.remove(); loadScene3d(function () { if (active) buildScene(); }); });
      overlay.appendChild(e);
    } else { e.style.display = 'block'; }
  }
  function clearLoadError() { const e = document.getElementById('threed-load-err'); if (e) e.remove(); }
  function saveBanner() {
    if (!overlay) return null;
    let e = document.getElementById('threed-save-err');
    if (!e) {
      e = document.createElement('div');
      e.id = 'threed-save-err';
      e.setAttribute('role', 'alert');
      e.setAttribute('aria-live', 'assertive');
      e.style.cssText = 'position:absolute;left:50%;top:52px;transform:translateX(-50%);z-index:8;max-width:70%;text-align:center;font:12px/1.4 system-ui,sans-serif;padding:8px 14px;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,.5)';
      overlay.appendChild(e);
    }
    e.style.display = 'block';
    return e;
  }
  function showSaveWarning(msg) {
    const e = saveBanner(); if (!e) return;
    e.style.background = '#78350f'; e.style.color = '#fde68a'; e.style.cursor = 'default';
    e.onclick = null; e.textContent = msg;
  }
  function showSaveError(reason) {
    const e = saveBanner(); if (!e) return;
    e.style.background = '#7f1d1d'; e.style.color = '#fecaca'; e.style.cursor = 'pointer';
    e.textContent = '⚠ 3D changes could NOT be saved (' + reason + '). ';
    const retry = document.createElement('button');
    retry.type = 'button'; retry.textContent = 'Retry save';
    retry.setAttribute('aria-label', 'Retry saving the 3D scene');
    retry.style.cssText = 'padding:4px 10px;border:1px solid #fecaca;border-radius:6px;background:transparent;color:#fecaca;font:600 12px system-ui;cursor:pointer'
      + (COARSE_POINTER ? ';min-height:44px;min-width:44px' : '');
    e.appendChild(retry);
    e.onclick = function () { cancelSaveRetry(); clearSaveError(); saveScene3d(false); };
  }
  function clearSaveError() { const e = document.getElementById('threed-save-err'); if (e) { e.onclick = null; e.remove(); } }

  const nodeCenters = {};
  let cbox = null;
  function grow(x, z) { if (!Number.isFinite(x) || !Number.isFinite(z)) return; if (!cbox) cbox = { a: x, b: x, c: z, d: z }; else { cbox.a = Math.min(cbox.a, x); cbox.b = Math.max(cbox.b, x); cbox.c = Math.min(cbox.c, z); cbox.d = Math.max(cbox.d, z); } }
  function addStem(x, z, top) { const m = new THREE.Mesh(new THREE.CylinderGeometry(3, 3, top, 8), new THREE.MeshStandardMaterial({ color: 0x475569, roughness: 0.85 })); m.position.set(x, top / 2, z); scene.add(m); return m; }
  let _skyTex = null, _shadowTex = null, _imgShadowTex = null;
  function skyTexture() {
    if (_skyTex) return _skyTex;
    const c = document.createElement('canvas'); c.width = 8; c.height = 256; const ctx = c.getContext('2d');
    const g = ctx.createLinearGradient(0, 0, 0, 256);
    g.addColorStop(0, '#2f6fc7'); g.addColorStop(0.5, '#6ea8e0'); g.addColorStop(0.82, '#a9cdec'); g.addColorStop(1, '#d7e7f5');
    ctx.fillStyle = g; ctx.fillRect(0, 0, 8, 256);
    _skyTex = new THREE.CanvasTexture(c); if (THREE.SRGBColorSpace) _skyTex.colorSpace = THREE.SRGBColorSpace;
    return _skyTex;
  }
  function shadowTexture() {
    if (_shadowTex) return _shadowTex;
    const c = document.createElement('canvas'); c.width = c.height = 64; const ctx = c.getContext('2d');
    const g = ctx.createRadialGradient(32, 32, 2, 32, 32, 31);
    g.addColorStop(0, 'rgba(0,0,0,0.42)'); g.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = g; ctx.fillRect(0, 0, 64, 64);
    _shadowTex = new THREE.CanvasTexture(c); _shadowTex.__shared = true;
    return _shadowTex;
  }
  function imageShadowTexture() {
    if (_imgShadowTex) return _imgShadowTex;
    const c = document.createElement('canvas'); c.width = c.height = 64; const g = c.getContext('2d');
    try { g.filter = 'blur(5px)'; } catch (e) {}
    g.fillStyle = 'rgba(0,0,0,0.5)'; g.fillRect(10, 10, 44, 44);
    try { g.filter = 'none'; } catch (e) {}
    _imgShadowTex = new THREE.CanvasTexture(c); _imgShadowTex.minFilter = THREE.LinearFilter; _imgShadowTex.__shared = true;
    return _imgShadowTex;
  }
  function addShadowBlob(x, z, radius) {
    const m = new THREE.Mesh(new THREE.PlaneGeometry(radius * 2, radius * 2), new THREE.MeshBasicMaterial({ map: shadowTexture(), transparent: true, depthWrite: false }));
    m.rotation.x = -Math.PI / 2; m.position.set(x, 1.4, z); m.renderOrder = -1; scene.add(m);
    return m;
  }

  const FLOOR_MARK_Y = 2.2, FLOOR_TINT_Y = 1.0;
  function floorTint2D(x, y, w, h, colorHex) {
    const m = new THREE.Mesh(new THREE.PlaneGeometry(w, h), new THREE.MeshStandardMaterial({ color: hexColor(colorHex, '#3f6f3f'), roughness: 0.97 }));
    m.rotation.x = -Math.PI / 2; m.position.set(sx(x + w / 2), FLOOR_TINT_Y, sz(y + h / 2)); scene.add(m); return m;
  }
  function floorLine2D(x1, y1, x2, y2, colorHex, mat) {
    const g = new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(sx(x1), FLOOR_MARK_Y, sz(y1)), new THREE.Vector3(sx(x2), FLOOR_MARK_Y, sz(y2))]);
    scene.add(new THREE.Line(g, mat || new THREE.LineBasicMaterial({ color: hexColor(colorHex, '#ffffff') })));
  }
  function floorRect2D(x, y, w, h, colorHex, mat) {
    const p = [[x, y], [x + w, y], [x + w, y + h], [x, y + h], [x, y]].map((q) => new THREE.Vector3(sx(q[0]), FLOOR_MARK_Y, sz(q[1])));
    scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(p), mat || new THREE.LineBasicMaterial({ color: hexColor(colorHex, '#ffffff') })));
  }
  function floorArc2D(cx, cy, r, a0, a1, colorHex, mat) {
    const s = (a0 == null ? 0 : a0), e = (a1 == null ? Math.PI * 2 : a1), n = Math.max(8, Math.round(Math.abs(e - s) / (Math.PI * 2) * 64)), pts = [];
    for (let i = 0; i <= n; i++) { const a = s + (e - s) * (i / n); pts.push(new THREE.Vector3(sx(cx + Math.cos(a) * r), FLOOR_MARK_Y, sz(cy + Math.sin(a) * r))); }
    scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(pts), mat || new THREE.LineBasicMaterial({ color: hexColor(colorHex, '#ffffff') })));
  }
  function floorDot2D(cx, cy, r, colorHex) {
    const m = new THREE.Mesh(new THREE.CircleGeometry(r, 12), new THREE.MeshBasicMaterial({ color: hexColor(colorHex, '#ffffff'), side: THREE.DoubleSide }));
    m.rotation.x = -Math.PI / 2; m.position.set(sx(cx), FLOOR_MARK_Y, sz(cy)); scene.add(m);
  }
  function buildFloorTemplate(template) {
    const pad = PAD, w = WORLD_W - 2 * pad, h = WORLD_D - 2 * pad, cx = WORLD_W / 2, cy = WORLD_D / 2;
    const min = Math.min, gridCol = ((getVar('PAGE_STATE') || {}).canvasGrid) || '#475569';
    if (template === 'basketball') {
      const courtW = min(w * 0.9, h * 0.9 * 1.88), courtH = courtW / 1.88, courtX = cx - courtW / 2, courtY = cy - courtH / 2, L = '#f8f4ec';
      floorTint2D(courtX, courtY, courtW, courtH, '#b5813f'); floorRect2D(courtX, courtY, courtW, courtH, L);
      floorArc2D(cx, cy, courtH * 0.12, null, null, L); floorLine2D(cx, courtY, cx, courtY + courtH, L);
      const keyW = courtW * 0.19, keyH = courtH * 0.38, ftR = keyH * 0.32, arcR = courtH * 0.48;
      floorRect2D(courtX, cy - keyH / 2, keyW, keyH, L); floorRect2D(courtX + courtW - keyW, cy - keyH / 2, keyW, keyH, L);
      floorArc2D(courtX + keyW, cy, ftR, null, null, L); floorArc2D(courtX + courtW - keyW, cy, ftR, null, null, L);
      const lx = courtX + courtW * 0.055, rx = courtX + courtW * 0.945;
      floorLine2D(courtX, courtY + courtH * 0.06, lx, cy - arcR, L); floorLine2D(courtX, courtY + courtH * 0.94, lx, cy + arcR, L); floorArc2D(lx, cy, arcR, -Math.PI / 2, Math.PI / 2, L);
      floorLine2D(courtX + courtW, courtY + courtH * 0.06, rx, cy - arcR, L); floorLine2D(courtX + courtW, courtY + courtH * 0.94, rx, cy + arcR, L); floorArc2D(rx, cy, arcR, Math.PI / 2, Math.PI * 1.5, L);
      return true;
    }
    if (template === 'tennis') {
      const courtW = min(w * 0.9, h * 0.9 * 2.17), courtH = courtW / 2.17, courtX = cx - courtW / 2, courtY = cy - courtH / 2, ins = courtH * 0.125, L = '#ffffff';
      floorTint2D(courtX, courtY, courtW, courtH, '#2d6a9f'); floorRect2D(courtX, courtY, courtW, courtH, L);
      floorRect2D(courtX, courtY + ins, courtW, courtH - 2 * ins, L); floorLine2D(cx, courtY, cx, courtY + courtH, L);
      const sW = courtW * 0.27, sH = (courtH - 2 * ins) / 2;
      floorRect2D(cx - sW, courtY + ins, sW, sH, L); floorRect2D(cx, courtY + ins, sW, sH, L); floorRect2D(cx - sW, cy, sW, sH, L); floorRect2D(cx, cy, sW, sH, L);
      floorLine2D(cx - sW, cy, cx + sW, cy, L); floorLine2D(courtX, cy - 10, courtX, cy + 10, L); floorLine2D(courtX + courtW, cy - 10, courtX + courtW, cy + 10, L);
      return true;
    }
    if (template === 'hockey') {
      const rinkW = min(w * 0.9, h * 0.9 * 2.35), rinkH = rinkW / 2.35, rinkX = cx - rinkW / 2, rinkY = cy - rinkH / 2, red = '#cc3333', blue = '#3366cc';
      floorTint2D(rinkX, rinkY, rinkW, rinkH, '#e8f0fb'); floorRect2D(rinkX, rinkY, rinkW, rinkH, '#9aa7b8');
      floorLine2D(cx, rinkY, cx, rinkY + rinkH, red);
      floorLine2D(cx - rinkW * 0.25, rinkY, cx - rinkW * 0.25, rinkY + rinkH, blue); floorLine2D(cx + rinkW * 0.25, rinkY, cx + rinkW * 0.25, rinkY + rinkH, blue);
      floorArc2D(cx, cy, rinkH * 0.18, null, null, blue);
      [[0.15, -0.25], [0.15, 0.25], [0.85, -0.25], [0.85, 0.25]].forEach((f) => floorArc2D(rinkX + rinkW * f[0], cy + rinkH * f[1], rinkH * 0.18, null, null, red));
      const cr = rinkH * 0.08; floorArc2D(rinkX + rinkW * 0.045, cy, cr, -Math.PI / 2, Math.PI / 2, red); floorArc2D(rinkX + rinkW * 0.955, cy, cr, Math.PI / 2, Math.PI * 1.5, red);
      return true;
    }
    if (template === 'soccer') {
      const pW = min(w * 0.9, h * 0.9 * 1.54), pH = pW / 1.54, pX = cx - pW / 2, pY = cy - pH / 2, L = '#f0fff0';
      floorTint2D(pX, pY, pW, pH, '#3f7d3f'); floorRect2D(pX, pY, pW, pH, L); floorLine2D(cx, pY, cx, pY + pH, L); floorArc2D(cx, cy, pH * 0.14, null, null, L);
      const penW = pW * 0.157, penH = pH * 0.62, gW = penW * 0.35, gH = penH * 0.45;
      floorRect2D(pX, cy - penH / 2, penW, penH, L); floorRect2D(pX + pW - penW, cy - penH / 2, penW, penH, L);
      floorRect2D(pX, cy - gH / 2, gW, gH, L); floorRect2D(pX + pW - gW, cy - gH / 2, gW, gH, L);
      return true;
    }
    if (template === 'football') {
      const fW = min(w * 0.9, h * 0.9 * 2.25), fH = fW / 2.25, fX = cx - fW / 2, fY = cy - fH / 2, L = '#f5f5f5', ez = fW / 12, play = fW - 2 * ez;
      floorTint2D(fX, fY, fW, fH, '#356b34'); floorRect2D(fX, fY, fW, fH, L);
      floorRect2D(fX, fY, ez, fH, L); floorRect2D(fX + fW - ez, fY, ez, fH, L);
      for (let i = 1; i <= 9; i++) { const x = fX + ez + play * i / 10; floorLine2D(x, fY, x, fY + fH, i === 5 ? '#ffe066' : L); }
      const hy1 = fY + fH * 0.3, hy2 = fY + fH * 0.7; for (let i = 0; i <= 100; i += 10) { const x = fX + ez + play * i / 100; floorLine2D(x - 5, hy1, x + 5, hy1, L); floorLine2D(x - 5, hy2, x + 5, hy2, L); }
      return true;
    }
    if (template === 'baseball') {
      const dS = min(w * 0.7, h * 0.7), bX = cx, bY = cy + dS * 0.3, bd = dS * 0.35, L = '#eaddc6';
      const home = [bX, bY], first = [bX + bd, bY - bd], second = [bX, bY - 2 * bd], third = [bX - bd, bY - bd];
      floorTint2D(pad, pad, w, h, '#3f7d3f');
      floorLine2D(home[0], home[1], first[0], first[1], L); floorLine2D(first[0], first[1], second[0], second[1], L); floorLine2D(second[0], second[1], third[0], third[1], L); floorLine2D(third[0], third[1], home[0], home[1], L);
      [home, first, second, third].forEach((b, i) => floorDot2D(b[0], b[1], i === 0 ? 22 : 18, L));
      floorDot2D(bX, bY - bd * 0.67, 30, '#b07a4a');
      const oR = dS * 0.6; floorArc2D(bX, bY, oR, Math.PI * 1.12, Math.PI * 1.88, L);
      const fl = dS * 0.8; floorLine2D(bX, bY, bX - fl, bY - fl * 0.7, L); floorLine2D(bX, bY, bX + fl, bY - fl * 0.7, L);
      return true;
    }
    if (template === 'blueprint') {
      floorTint2D(pad, pad, w, h, '#12355b');
      const step = 200; for (let x = pad; x <= WORLD_W - pad + 1; x += step) floorLine2D(x, pad, x, WORLD_D - pad, '#9fc7ff'); for (let y = pad; y <= WORLD_D - pad + 1; y += step) floorLine2D(pad, y, WORLD_W - pad, y, '#9fc7ff');
      floorRect2D(pad, pad, w, h, '#ffffff'); return true;
    }
    if (template === 'dots') {
      const step = Math.max(240, (((getVar('PAGE_STATE') || {}).canvasGridSize) || 50) * 4);
      for (let x = pad; x <= WORLD_W - pad + 1; x += step) for (let y = pad; y <= WORLD_D - pad + 1; y += step) floorDot2D(x, y, 6, gridCol);
      return false;
    }
    return false;
  }

  const edgeRoutingOf = (e) => (e && e.routing) || 'curved';
  function edgePairInfo(edges) {
    const count = {}, seen = {}, out = new Map();
    const keyOf = (e) => (e.from < e.to ? e.from + '||' + e.to : e.to + '||' + e.from);
    for (const e of edges) { if (!e || e.type === 'custom' || !e.from || !e.to) continue; const k = keyOf(e); count[k] = (count[k] || 0) + 1; }
    for (const e of edges) { if (!e || e.type === 'custom' || !e.from || !e.to) continue; const k = keyOf(e); const i = seen[k] || 0; out.set(e, { pairIndex: i, pairTotal: count[k] }); seen[k] = i + 1; }
    return out;
  }
  function orthoLegSegs(prev, curr, offset) {
    const dx = curr.x - prev.x, dy = curr.y - prev.y;
    if (Math.abs(dx) > Math.abs(dy)) { const midX = prev.x + dx / 2 + offset; return [[prev.x, prev.y, midX, prev.y], [midX, prev.y, midX, curr.y], [midX, curr.y, curr.x, curr.y]]; }
    const midY = prev.y + dy / 2 + offset; return [[prev.x, prev.y, prev.x, midY], [prev.x, midY, curr.x, midY], [curr.x, midY, curr.x, curr.y]];
  }
  function computeOrthoGaps(edges, positions, pairInfo) {
    const segs = [];
    edges.forEach((edge, edgeIndex) => {
      if (!edge || edge.type === 'custom' || edgeRoutingOf(edge) !== 'orthogonal') return;
      const p1 = positions[edge.from], p2 = positions[edge.to]; if (!p1 || !p2) return;
      const wps = Array.isArray(edge.waypoints) ? edge.waypoints : [];
      const info = pairInfo.get(edge) || { pairIndex: 0, pairTotal: 1 };
      const offset = (info.pairIndex - (info.pairTotal - 1) / 2) * 40;
      const pts = wps.length ? [p1].concat(wps, [p2]) : [p1, p2];
      for (let i = 1; i < pts.length; i++) { const off = wps.length ? 0 : offset; orthoLegSegs(pts[i - 1], pts[i], off).forEach((s) => segs.push({ edgeId: edge.id, x1: s[0], y1: s[1], x2: s[2], y2: s[3], idx: edgeIndex })); }
    });
    const gaps = {};
    if (segs.length > 1400) return gaps;
    for (let i = 0; i < segs.length; i++) for (let j = i + 1; j < segs.length; j++) {
      const s1 = segs[i], s2 = segs[j]; if (s1.edgeId === s2.edgeId) continue;
      const s1H = Math.abs(s1.y1 - s1.y2) < 1, s2H = Math.abs(s2.y1 - s2.y2) < 1; if (s1H === s2H) continue;
      const h = s1H ? s1 : s2, v = s1H ? s2 : s1, hY = h.y1, vX = v.x1;
      if (vX > Math.min(h.x1, h.x2) && vX < Math.max(h.x1, h.x2) && hY > Math.min(v.y1, v.y2) && hY < Math.max(v.y1, v.y2)) {
        const ge = s1.idx > s2.idx ? s1.edgeId : s2.edgeId; (gaps[ge] = gaps[ge] || []).push({ x: vX, y: hY });
      }
    }
    return gaps;
  }
  function orthoSubpaths(start, segList, gaps) {
    const GAP = 10, subs = []; let cur = [{ x: start.x, y: start.y }];
    segList.forEach((seg) => {
      const isH = Math.abs(seg[1] - seg[3]) < 1;
      const segGaps = gaps.filter((g) => isH
        ? (Math.abs(g.y - seg[1]) < 1 && g.x > Math.min(seg[0], seg[2]) + GAP && g.x < Math.max(seg[0], seg[2]) - GAP)
        : (Math.abs(g.x - seg[0]) < 1 && g.y > Math.min(seg[1], seg[3]) + GAP && g.y < Math.max(seg[1], seg[3]) - GAP)
      ).sort((a, b) => isH ? (seg[2] > seg[0] ? a.x - b.x : b.x - a.x) : (seg[3] > seg[1] ? a.y - b.y : b.y - a.y));
      let cy = seg[1], cx = seg[0];
      segGaps.forEach((g) => {
        if (isH) { cur.push({ x: g.x - GAP, y: cy }); subs.push(cur); cur = [{ x: g.x + GAP, y: cy }]; cx = g.x + GAP; }
        else { cur.push({ x: cx, y: g.y - GAP }); subs.push(cur); cur = [{ x: cx, y: g.y + GAP }]; cy = g.y + GAP; }
      });
      cur.push({ x: seg[2], y: seg[3] });
    });
    subs.push(cur); return subs;
  }
  function sampleQuad(P0, C, P1, n, out) {
    for (let i = 1; i <= n; i++) { const t = i / n, u = 1 - t; out.push({ x: u * u * P0.x + 2 * u * t * C.x + t * t * P1.x, y: u * u * P0.y + 2 * u * t * C.y + t * t * P1.y }); }
  }
  function buildEdgePath2D(edge, positions, pairInfo, orthoGaps) {
    const p1 = positions[edge.from], p2 = positions[edge.to]; if (!p1 || !p2) return [];
    const routing = edgeRoutingOf(edge);
    const wps = Array.isArray(edge.waypoints) ? edge.waypoints : [];
    const info = pairInfo.get(edge) || { pairIndex: 0, pairTotal: 1 };
    const offset = (info.pairIndex - (info.pairTotal - 1) / 2) * 40;
    const gaps = (orthoGaps && orthoGaps[edge.id]) || [];
    if (wps.length > 0) {
      const all = [p1].concat(wps, [p2]);
      if (routing === 'straight') return [all.map((p) => ({ x: p.x, y: p.y }))];
      if (routing === 'orthogonal') { const segs = []; for (let i = 1; i < all.length; i++) orthoLegSegs(all[i - 1], all[i], 0).forEach((s) => segs.push(s)); return orthoSubpaths(all[0], segs, gaps); }
      const out = [{ x: all[0].x, y: all[0].y }];
      if (all.length === 3) { sampleQuad(all[0], all[1], all[2], 16, out); return [out]; }
      let prevC = null, start = all[0];
      for (let i = 1; i < all.length - 1; i++) {
        const curr = all[i], next = all[i + 1], end = { x: (curr.x + next.x) / 2, y: (curr.y + next.y) / 2 };
        const C = (i === 1) ? { x: curr.x, y: curr.y } : { x: 2 * start.x - prevC.x, y: 2 * start.y - prevC.y };
        sampleQuad(start, C, end, 12, out); prevC = C; start = end;
      }
      const secondLast = all[all.length - 2], last = all[all.length - 1];
      sampleQuad(start, { x: secondLast.x, y: secondLast.y }, { x: last.x, y: last.y }, 12, out);
      return [out];
    }
    if (routing === 'straight') return [[{ x: p1.x, y: p1.y }, { x: p2.x, y: p2.y }]];
    if (routing === 'orthogonal') return orthoSubpaths(p1, orthoLegSegs(p1, p2, offset), gaps);
    const midX = (p1.x + p2.x) / 2, midY = (p1.y + p2.y) / 2, dx = p2.x - p1.x, dy = p2.y - p1.y;
    const len = Math.sqrt(dx * dx + dy * dy) || 1, oa = info.pairTotal > 1 ? offset : 0;
    const C = { x: midX + (-dy / len) * oa, y: midY + (dx / len) * oa };
    const out = [{ x: p1.x, y: p1.y }]; sampleQuad(p1, C, p2, 18, out); return [out];
  }
  let wireRoot = null;
  const wireCache = Object.create(null);
  let wireCur = null;
  let wireStats = { rebuilt: 0, reused: 0, removed: 0 };
  function wireAdd(o) { (wireCur || wireRoot || scene).add(o); }
  function contentRoot() { if (!scene) return null; for (let i = 0; i < scene.children.length; i++) if (scene.children[i].name === '__vrworld') return scene.children[i]; return scene; }
  function disposeWireLayer() {
    for (const k in wireCache) delete wireCache[k];
    if (!wireRoot) return;
    for (let i = pickables.length - 1; i >= 0; i--) { const u = pickables[i] && pickables[i].userData; if (u && u.edgeId) pickables.splice(i, 1); }
    if (wireRoot.parent) wireRoot.parent.remove(wireRoot);
    disposeObject3D(wireRoot); wireRoot = null; wireCur = null;
  }
  function disposeEdgeEntry(key) {
    const en = wireCache[key]; if (!en) return;
    for (let i = 0; i < en.picks.length; i++) { const at = pickables.indexOf(en.picks[i]); if (at >= 0) pickables.splice(at, 1); }
    if (en.grp) { if (en.grp.parent) en.grp.parent.remove(en.grp); disposeObject3D(en.grp); }
    delete wireCache[key];
  }
  function addWireSubpath(sub, y, radius, mat, edgeId, dash) {
    const pts = [];
    for (let i = 0; i < sub.length; i++) { const P = new THREE.Vector3(sx(sub[i].x), y, sz(sub[i].y)); if (!pts.length || pts[pts.length - 1].distanceToSquared(P) > 1) pts.push(P); }
    if (pts.length < 2) return null;
    let obj;
    if (dash) {
      const src = pts.length === 2 ? new THREE.LineCurve3(pts[0], pts[1]) : new THREE.CatmullRomCurve3(pts, false, 'centripetal', 0.5);
      const lp = src.getPoints(clamp(pts.length * 6, 6, 160));
      obj = new THREE.Line(new THREE.BufferGeometry().setFromPoints(lp), new THREE.LineDashedMaterial({ color: mat.color, dashSize: dash[0], gapSize: dash[1], transparent: mat.transparent, opacity: mat.opacity }));
      obj.computeLineDistances();
    } else {
      const curve = pts.length === 2 ? new THREE.LineCurve3(pts[0], pts[1]) : new THREE.CatmullRomCurve3(pts, false, 'centripetal', 0.5);
      obj = new THREE.Mesh(new THREE.TubeGeometry(curve, clamp(pts.length * 8, 8, 240), radius, 6, false), mat);
    }
    if (edgeId) { obj.userData.edgeId = edgeId; pickables.push(obj); } wireAdd(obj); return pts;
  }
  function addArrowCone(tip, from, radius, mat, edgeId) {
    const dir = new THREE.Vector3().subVectors(tip, from); const L = dir.length(); if (L < 1) return; dir.multiplyScalar(1 / L);
    const h = Math.max(20, radius * 5), r = Math.max(8, radius * 2.4);
    const cone = new THREE.Mesh(new THREE.ConeGeometry(r, h, 10), mat);
    cone.position.copy(tip).addScaledVector(dir, -h / 2);
    cone.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), dir); if (edgeId) { cone.userData.edgeId = edgeId; pickables.push(cone); } wireAdd(cone);
  }

  function ptsSig(arr) {
    if (!Array.isArray(arr) || !arr.length) return '';
    let s = '';
    for (let i = 0; i < arr.length; i++) { const p = arr[i]; if (!p) { s += '~'; continue; } s += (Math.round(num(p.x, 0) * 10) / 10) + ',' + (Math.round(num(p.y, 0) * 10) / 10) + ';'; }
    return s;
  }
  function edgeInputSig(e, g, positions, pairInfo, orthoGaps, flowing, buried) {
    const p1 = positions[e.from], p2 = positions[e.to];
    const info = pairInfo.get(e) || { pairIndex: 0, pairTotal: 1 };
    return g + '|' + (e.type || '') + '|' + (e.from || '') + '>' + (e.to || '')
      + '|' + (p1 ? (Math.round(num(p1.x, 0) * 10) / 10) + ',' + (Math.round(num(p1.y, 0) * 10) / 10) : '-')
      + '|' + (p2 ? (Math.round(num(p2.x, 0) * 10) / 10) + ',' + (Math.round(num(p2.y, 0) * 10) / 10) : '-')
      + '|' + (nodeCenters[e.from] ? 1 : 0) + (nodeCenters[e.to] ? 1 : 0)
      + '|' + edgeRoutingOf(e) + '|' + ptsSig(e.waypoints) + '|' + ptsSig(e.points)
      + '|' + info.pairIndex + '/' + info.pairTotal
      + '|' + ptsSig((orthoGaps && orthoGaps[e.id]) || null)
      + '|' + (e.color || '') + '|' + num(e.width, 4) + '|' + (e.lineStyle || '') + '|' + (e.direction || '')
      + '|' + (e.groupId || '') + '|' + (e.fromPort || '') + '|' + (e.toPort || '')
      + '|' + (buried ? 1 : 0) + '|' + (flowing ? 1 : 0)
      + '|' + (e.animationStyle || '') + '|' + (e.animationSpeed == null ? '' : e.animationSpeed);
  }
  function buildEdgeLayer(positions, edgeList, full) {
    if (!wireRoot) wireRoot = new THREE.Group();
    { const root = contentRoot() || scene; if (wireRoot.parent !== root) { if (wireRoot.parent) wireRoot.parent.remove(wireRoot); root.add(wireRoot); } }
    anims.flow.length = 0;
    for (let i = pickables.length - 1; i >= 0; i--) { const u = pickables[i] && pickables[i].userData; if (u && u.edgeId) pickables.splice(i, 1); }
    wireStats = { rebuilt: 0, reused: 0, removed: 0 };
    const seenKeys = Object.create(null);
    const pairInfo = edgePairInfo(edgeList);
    const orthoGaps = computeOrthoGaps(edgeList, positions, pairInfo);
    const wdef = wireModeDef();
    const portsOn = !!((getVar('PAGE_STATE') || {}).showPortLabels);
    const c = { wires: 0, walls: 0, ports: 0, groups: 0 };
    const gsig = (theme.defaultEdge || '') + '|' + (portsOn ? 1 : 0) + '|' + wdef.id + '|' + wdef.y + '|' + (wdef.hidden ? 1 : 0)
      + '|' + (wdef.floor ? 1 : 0) + '|' + (fxAllowed() ? 1 : 0) + '|' + scene3d.mpu;
    edgeList.forEach((e, ei) => {
      if (!e) return;
      let ekey = (e.id != null && e.id !== '') ? ('e:' + e.id) : ('i:' + ei);
      if (seenKeys[ekey]) ekey = ekey + '#' + ei;
      seenKeys[ekey] = 1;
      const isHidden = !!(e.from && e.to && wdef.hidden);
      const buriedE = !!(scene3d.buried && scene3d.buried[e.id]);
      const flowingE = !!(e.from && e.to) && fxAllowed() && edgeShouldFlow(e);
      const sig = edgeInputSig(e, gsig, positions, pairInfo, orthoGaps, flowingE, buriedE) + '|' + (isHidden ? 'H' : '');
      const prev = wireCache[ekey];
      if (prev && prev.sig === sig) {
        wireStats.reused++;
        for (let q = 0; q < prev.picks.length; q++) pickables.push(prev.picks[q]);
        for (let q = 0; q < prev.flows.length; q++) anims.flow.push(prev.flows[q]);
        c.wires += prev.counts.wires; c.walls += prev.counts.walls; c.ports += prev.counts.ports; c.groups += prev.counts.groups;
        if (full) for (let q = 0; q < prev.grows.length; q++) grow(prev.grows[q][0], prev.grows[q][1]);
        if (prev.grp.parent !== wireRoot) wireRoot.add(prev.grp);
        return;
      }
      if (prev) disposeEdgeEntry(ekey);
      wireStats.rebuilt++;
      const entry = { sig: sig, grp: new THREE.Group(), picks: [], flows: [], counts: { wires: 0, walls: 0, ports: 0, groups: 0 }, grows: [] };
      wireCache[ekey] = entry;
      wireRoot.add(entry.grp);
      wireCur = entry.grp;
      const pick0 = pickables.length, flow0 = anims.flow.length;
      const c0 = { wires: c.wires, walls: c.walls, ports: c.ports, groups: c.groups };
      const growHere = entry.grows;
      try { buildOneEdge(e, positions, pairInfo, orthoGaps, wdef, portsOn, c, full, growHere); }
      finally { wireCur = null; }
      entry.picks = pickables.slice(pick0);
      entry.flows = anims.flow.slice(flow0);
      entry.counts = { wires: c.wires - c0.wires, walls: c.walls - c0.walls, ports: c.ports - c0.ports, groups: c.groups - c0.groups };
    });
    for (const k in wireCache) if (!seenKeys[k]) { disposeEdgeEntry(k); wireStats.removed++; }
    return c;
  }
  function buildOneEdge(e, positions, pairInfo, orthoGaps, wdef, portsOn, c, full, growHere) {
    {
      const eCol = e.color || theme.defaultEdge;
      if (e.type === 'custom' && e.points && e.points.length > 1) {
        const isWall = e.lineStyle === 'wall';
        for (let i = 0; i < e.points.length - 1; i++) {
          const a = e.points[i], b = e.points[i + 1];
          if (isWall) {
            const ax = sx(a.x), az = sz(a.y), bx = sx(b.x), bz = sz(b.y), len = Math.hypot(bx - ax, bz - az); if (len < 1) continue;
            const seg = new THREE.Mesh(new THREE.BoxGeometry(len, WALL_HEIGHT_3D, WALL_THICK_3D), new THREE.MeshStandardMaterial({ color: hexColor(eCol, '#94a3b8'), roughness: 1 }));
            seg.position.set((ax + bx) / 2, WALL_HEIGHT_3D / 2, (az + bz) / 2); seg.rotation.y = -Math.atan2(bz - az, bx - ax); wireAdd(seg); c.walls++; growHere.push([ax, az], [bx, bz]); if (full) { grow(ax, az); grow(bx, bz); }
          } else {
            wireAdd(new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(sx(a.x), 3, sz(a.y)), new THREE.Vector3(sx(b.x), 3, sz(b.y))]), new THREE.LineBasicMaterial({ color: hexColor(eCol, '#64748b') })));
          }
        }
        if (e.groupId) {
          let x0 = Infinity, z0 = Infinity, x1 = -Infinity, z1 = -Infinity;
          e.points.forEach((q) => { if (!q) return; x0 = Math.min(x0, q.x); x1 = Math.max(x1, q.x); z0 = Math.min(z0, q.y); z1 = Math.max(z1, q.y); });
          if (Number.isFinite(x0) && Number.isFinite(z0)) {
            const gi = groupBox((x1 - x0) / 2 + 8, (z1 - z0) / 2 + 8);
            gi.position.set(sx((x0 + x1) / 2), GROUP_Y, sz((z0 + z1) / 2)); wireAdd(gi); c.groups++;
          }
        }
        return;
      }
      if (!e.from || !e.to) return;
      if (!nodeCenters[e.from] || !nodeCenters[e.to]) return;
      if (wdef.hidden) return;
      const buried = !!(scene3d.buried && scene3d.buried[e.id]);
      const wireY = buried ? WIRE_MODES[1].y : wdef.y, floorLike = buried || wdef.floor;
      const subs = buildEdgePath2D(e, positions, pairInfo, orthoGaps); if (!subs.length) return;
      const flowing = fxAllowed() && edgeShouldFlow(e);
      const mat = new THREE.MeshStandardMaterial({ color: hexColor(eCol, '#64748b'), roughness: 0.5, metalness: 0.2, transparent: flowing, opacity: flowing ? 0.35 : 1 });
      const radius = clamp(num(e.width, 4) * (floorLike ? 0.9 : 0.6), 1.2, 14);
      const dash = e.lineStyle === 'dashed' ? [12, 8] : (e.lineStyle === 'dotted' ? [2, 6] : null);
      let firstPts = null, lastPts = null; const all3 = [];
      subs.forEach((sub) => { const pts = addWireSubpath(sub, wireY, radius, mat, e.id, dash); if (pts) { if (!firstPts) firstPts = pts; lastPts = pts; for (let q = 0; q < pts.length; q++) if (!all3.length || all3[all3.length - 1].distanceToSquared(pts[q]) > 1) all3.push(pts[q]); } });
      const dir = e.direction || 'none';
      if ((dir === 'forward' || dir === 'both') && lastPts) addArrowCone(lastPts[lastPts.length - 1], lastPts[lastPts.length - 2], radius, mat, e.id);
      if ((dir === 'backward' || dir === 'both') && firstPts) addArrowCone(firstPts[0], firstPts[1], radius, mat, e.id);
      if (flowing && all3.length >= 2) addEdgeFlow(e, all3, radius);
      if (portsOn && (e.fromPort || e.toPort) && all3.length >= 2) {
        const at = (t) => all3[clamp(Math.round((all3.length - 1) * t), 0, all3.length - 1)];
        const put = (txt, t) => { const p = at(t), s = textSprite(txt, '#e2e8f0'); s.scale.set(132, 33, 1); s.position.set(p.x, p.y + 34, p.z); wireAdd(s); c.ports++; };
        if (e.fromPort) put(e.fromPort, 0.14);
        if (e.toPort) put(e.toPort, 0.86);
      }
      c.wires++;
    }
  }

  function buildScene() {
    disposeOldScene();
    followReset();
    theme = readTheme();
    _imgUsed = new Set();
    _iconUsed = new Set();
    _emblemUsed = new Set(); _emblemCount = 0; _emblemFallback = 0; _devModelCount = 0;
    _rmStatic = false;
    if (devModelsOn && !_bguMod) getBGU();
    scene = new THREE.Scene();
    scene.background = skyTexture();
    scene.fog = new THREE.Fog(0xbcd6ee, 5000, 17000);
    pickables.length = 0; for (const k in nodeCenters) delete nodeCenters[k]; cbox = null;
    if (selBox) selBox = null; selHalos.length = 0;
    for (const id in avatars) { scene.add(avatars[id].grp); }
    if (renderer && renderer.xr && renderer.xr.isPresenting) xrObjects.forEach(function (o) { scene.add(o); });

    const FLOOR_SPAN = 2.4, FLOOR_W = WORLD_W * FLOOR_SPAN, FLOOR_D = WORLD_D * FLOOR_SPAN, FLOOR_MAX = Math.max(FLOOR_W, FLOOR_D);
    const floor = new THREE.Mesh(new THREE.PlaneGeometry(FLOOR_W, FLOOR_D), new THREE.MeshStandardMaterial({ color: 0x59657a, roughness: 0.96, metalness: 0.0 }));
    floor.rotation.x = -Math.PI / 2; scene.add(floor);
    const grid = new THREE.GridHelper(FLOOR_MAX, Math.round(FLOOR_MAX / 200), 0x93a7bb, 0x74879a);
    grid.material.transparent = true; grid.material.opacity = 0.5; grid.position.y = 0.6; scene.add(grid);
    { const ps = getVar('PAGE_STATE') || {}; let tpl = ps.canvasTemplate || 'grid';
      if (ps.mappingMode === 'mindmap') tpl = 'none'; else if (ps.mappingMode === 'floorplan') tpl = 'blueprint';
      try { buildFloorTemplate(tpl); } catch (e) {} }
    if (scene3d.mpu > 0) {
      const upm = 1 / scene3d.mpu;
      const divs = Math.max(2, Math.min(1000, Math.round(WORLD_W / upm)));
      const mgrid = new THREE.GridHelper(WORLD_W, divs, 0xffffff, 0xdcecfa);
      mgrid.material.transparent = true; mgrid.material.opacity = 0.16; mgrid.position.y = 1.0; scene.add(mgrid);
      const hh = Math.max(20, 1.8 * upm), rad = Math.max(4, 0.28 * upm);
      const refG = THREE.CapsuleGeometry ? new THREE.CapsuleGeometry(rad, Math.max(1, hh - 2 * rad), 4, 8) : new THREE.CylinderGeometry(rad, rad, hh, 10);
      const ref = new THREE.Mesh(refG, new THREE.MeshStandardMaterial({ color: 0x22c55e, roughness: 0.7 }));
      ref.position.set(sx(180), hh / 2, sz(180)); scene.add(ref);
      const rl = textSprite('1.8 m', '#bbf7d0'); rl.position.set(sx(180), hh + Math.max(30, rad * 3), sz(180)); scene.add(rl);
    }
    scene.add(new THREE.HemisphereLight(0xcfe6ff, 0x4a5360, LIGHT.hemi));
    scene.add(new THREE.AmbientLight(0xffffff, LIGHT.ambient));
    const sun = new THREE.DirectionalLight(0xfff2dc, LIGHT.sun); sun.position.set(1800, 3200, 1400); scene.add(sun);

    const ND = getVar('NODE_DATA') || {}, positions = getVar('savedPositions') || {}, sizes = getVar('savedSizes') || {}, styles = getVar('savedStyles') || {};
    const mountedByRack = {};
    Object.keys(ND).forEach((id) => { const ar = ND[id] && ND[id].assignedRack; if (ar && ND[ar] && isTrue(ND[ar].isRack)) (mountedByRack[ar] = mountedByRack[ar] || []).push(id); });

    let nNodes = 0, nRacks = 0, nFov = 0, nWalls = 0, nZones = 0, nText = 0, nIcons = 0, nHidden = 0, nGroups = 0;
    anims.fov.length = 0; anims.flow.length = 0; anims.ping.length = 0;
    const layerVisible = makeLayerFilter(ND);
    const heights = scene3d.heights || {};
    let prunedH = false; for (const hk in heights) { if (!ND[hk]) { delete heights[hk]; prunedH = true; } }
    if (prunedH && sceneReady) scheduleSave();
    Object.keys(ND).forEach((id) => {
      const p = positions[id]; if (!p) return;
      const node = ND[id] || {};
      if (node.assignedRack && ND[node.assignedRack] && isTrue(ND[node.assignedRack].isRack)) return;
      grow(sx(p.x), sz(p.y));
      const dim = []; let nodeFovAnim = null;
      dim.push(addShadowBlob(sx(p.x), sz(p.y), isTrue(node.isRack) ? RACK_WIDTH_3D * 0.62 : (Number(sizes[id]) || 55) * 1.3));
      const elev = clamp(num(heights[id], 0), 0, MAX_ELEVATION);
      if (elev > 1) dim.push(addStem(sx(p.x), sz(p.y), elev));
      if (isTrue(node.isRack)) {
        node.__id = id;
        const r = buildRack(node, p, mountedByRack[id] || [], ND, styles);
        r.group.position.y = elev;
        r.group.rotation.y = -rad(node.rotation);
        scene.add(r.group); pickables.push(r.group); dim.push(r.group);
        if (node.locked) dim.push(addLockBadge(sx(p.x) + RACK_WIDTH_3D * 0.62, elev + r.topY + 46, sz(p.y), 60));
        if (node.groupId) { const gi = groupRing(RACK_WIDTH_3D * 0.62 + 4); gi.position.set(sx(p.x), elev + GROUP_Y, sz(p.y)); scene.add(gi); dim.push(gi); nGroups++; }
        nodeCenters[id] = new THREE.Vector3(sx(p.x), elev + r.topY * 0.5, sz(p.y)); nRacks++;
      } else {
        const size = Number(sizes[id]) || 55;
        const st = bookResolveStyles(styles[id]);
        const ping = node.ping || {}, pingHex = ping.enabled ? PING_COLORS[ping.status] : null;
        const baseCol = nodeColor(id, node, styles, st);
        const mat = new THREE.MeshStandardMaterial({ color: pingHex ? hexColor(pingHex) : baseCol, roughness: 0.6, metalness: 0.12 });
        const body = buildNodeShape(node.shape, size, mat, st.circleBorder || theme.nodeStroke);
        const h = body.top;
        body.g.position.set(sx(p.x), elev, sz(p.y));
        body.g.rotation.y = -rad(node.rotation);
        body.g.userData.nodeId = id; scene.add(body.g); pickables.push(body.g); dim.push(body.g);
        if (pingHex && fxAllowed() && (ping.status === 'offline' || ping.status === 'checking')) { mat.emissive = hexColor(pingHex); anims.ping.push({ mat: mat, status: ping.status }); }
        nodeCenters[id] = new THREE.Vector3(sx(p.x), elev + h, sz(p.y));
        let iconTop = h;
        const ic = st.icon;
        if (ic && ic.library && ic.name) {
          const tint = st.circleColor || ('#' + baseCol.getHexString());
          const emb = buildIconEmblem(String(ic.library), String(ic.name), size, st.circleColor || tint, st.circleBorder || null);
          const itex = emb ? null : getIconTexture(String(ic.library), String(ic.name), st.circleColor || null, st.circleBorder || null, tint);
          if (emb) {
            const esz = size * 1.6;
            emb.position.set(0, h + esz * 0.55, 0);
            body.g.add(emb);
            iconTop = h + esz; nIcons++;
          } else if (itex) {
            if (icon3dOn) _emblemFallback++;
            const isz = size * 1.9;
            const isp = new THREE.Sprite(new THREE.SpriteMaterial({ map: itex, transparent: true }));
            isp.scale.set(isz, isz, 1); isp.position.set(0, h + isz * 0.5, 0); body.g.add(isp);
            iconTop = h + isz; nIcons++;
          }
        }
        const label = nodeLabelSprite(node.name || id, nodeSubtitle(node), st, size);
        label.position.set(sx(p.x), elev + iconTop + 16 + label.scale.y / 2, sz(p.y)); scene.add(label); nNodes++; dim.push(label);
        if (node.locked) dim.push(addLockBadge(sx(p.x) + size * 0.85, elev + h + 26, sz(p.y), size * 0.8));
        if (node.groupId) { const gi = groupRing(size + 4); gi.position.set(sx(p.x), elev + GROUP_Y, sz(p.y)); scene.add(gi); dim.push(gi); nGroups++; }
      }
      if (isTrue(node.fovEnabled) && hasCoverageZone(node.shape) && isZoneAllowed(node.shape)) {
        const fv = buildFovGroup(node);
        const holder = new THREE.Group();
        holder.position.set(sx(p.x), elev + 2, sz(p.y)); holder.rotation.y = -rad(node.rotation);
        holder.add(fv.group); scene.add(holder); dim.push(holder);
        if (fv.anim) { anims.fov.push(fv.anim); nodeFovAnim = fv.anim; } nFov++;
        if (node.fovLabel) {
          const fl = textSprite(node.fovLabel, node.fovLabelColor || '#ffffff');
          fl.position.set(Number(node.fovLabelOffsetX) || 0, 24, Number(node.fovLabelOffsetY) || 0);
          holder.add(fl);
        }
      }
      if (!layerVisible(id)) {
        nHidden++;
        for (let q = 0; q < dim.length; q++) fadeForLayer(dim[q]);
        if (nodeFovAnim) nodeFovAnim.fade = LAYER_FADE;
      }
      followNodes.push({ id: id, bx: sx(p.x), bz: sz(p.y), objs: dim, base: null });
    });

    const ED = getVar('EDGE_DATA') || {};
    const edgeList = (ED && ED.list) || [];
    const ec = buildEdgeLayer(positions, edgeList, true);
    const nWires = ec.wires, nPorts = ec.ports; nWalls += ec.walls; nGroups += ec.groups;

    const RD = getVar('RECT_DATA') || {};
    ((RD.list) || []).forEach((r) => {
      if (!r || !num(r.width, 0) || !num(r.height, 0)) return;
      const g = (r.lineStyle === 'wall') ? buildRectWall(r) : buildRectZone(r);
      g.userData.rectId = r.id; scene.add(g); pickables.push(g); if (r.lineStyle === 'wall') nWalls++; else nZones++;
      followRects.push({ id: r.id, o: g, w: Math.abs(num(r.width, 0)), h: Math.abs(num(r.height, 0)) });
      if (r.groupId) nGroups++;
      if (r.locked) addLockBadge(g.__gx, g.position.y + (g.__topY || 0) + 34, g.__gz, 52);
      grow(g.__gx - g.__hw, g.__gz - g.__hd); grow(g.__gx + g.__hw, g.__gz + g.__hd);
    });
    const TD = getVar('TEXT_DATA') || {};
    ((TD.list) || []).forEach((t) => {
      if (!t || t.content == null || t.content === '') return;
      const s = buildTextItem(t); s.position.set(sx(num(t.x, WORLD_W / 2)), 90, sz(num(t.y, WORLD_D / 2))); s.userData.textId = t.id; scene.add(s); pickables.push(s);
      followTexts.push({ id: t.id, o: s });

      if (t.locked) addLockBadge(s.position.x + s.scale.x / 2 + 28, 90 + s.scale.y / 2, s.position.z, 46);
      if (t.groupId) { const gi = groupBox(54, 24); gi.position.set(s.position.x, GROUP_Y, s.position.z); scene.add(gi); nGroups++; }
      grow(sx(num(t.x, WORLD_W / 2)), sz(num(t.y, WORLD_D / 2))); nText++;
    });
    const ID = getVar('IMAGE_DATA') || {};
    ((ID.list) || []).forEach((img) => {
      if (!img || !img.src) return; const w = img.width || 200, h = img.height || 200;
      const cxI = sx(img.x + w / 2), czI = sz(img.y + h / 2);
      const shN = IMG_SHADOW_PX[img.shadow] || 0;
      if (shN) {
        const sm = new THREE.Mesh(new THREE.PlaneGeometry(w + shN * 2, h + shN * 2), new THREE.MeshBasicMaterial({ map: imageShadowTexture(), transparent: true, depthWrite: false }));
        sm.rotation.x = -Math.PI / 2; sm.position.set(cxI + shN / 2, 1.15, czI + shN / 2); sm.renderOrder = -1; scene.add(sm);
      }
      const tex = getImgTexture(img.src);
      const m = new THREE.Mesh(new THREE.PlaneGeometry(w, h), new THREE.MeshBasicMaterial({ map: tex, transparent: true, opacity: img.opacity != null ? img.opacity : 1, side: THREE.DoubleSide }));
      m.rotation.x = -Math.PI / 2; m.position.set(cxI, 1.5, czI); m.userData.imageId = img.id; scene.add(m); pickables.push(m); grow(sx(img.x), sz(img.y));
      const bwI = IMG_BORDER_PX[img.border] || 0;
      if (bwI) { const bg = new THREE.Group(); bg.position.set(cxI, 1.9, czI); scene.add(bg); addStrokeRing(bg, w, h, bwI, 0, 0xffffff, 0, 0, 0.5); }
    });

    const bMat = new THREE.MeshStandardMaterial({ color: 0x334155, roughness: 1, transparent: true, opacity: 0.3 }), wH = 120, t = 8;
    [[WORLD_W, t, 0, -WORLD_D / 2], [WORLD_W, t, 0, WORLD_D / 2], [t, WORLD_D, -WORLD_W / 2, 0], [t, WORLD_D, WORLD_W / 2, 0]]
      .forEach((a) => { const m = new THREE.Mesh(new THREE.BoxGeometry(a[0], wH, a[1]), bMat); m.position.set(a[2], wH / 2, a[3]); scene.add(m); });

    let nFurn = 0;
    (scene3d.furniture || []).forEach((f) => { if (!f || !f.kind) return; const g = buildFurniture(f); scene.add(g); pickables.push(g); grow(sx(f.x), sz(f.z)); addShadowBlob(sx(f.x), sz(f.z), 60 * (num(f.scale, 1) || 1)); nFurn++; });

    lastBuild = { hidden: nHidden, groups: nGroups, fov: nFov };
    if (canvas) canvas.setAttribute('aria-label', '3D topology view: ' + nNodes + ' nodes, ' + nRacks + ' racks, ' + nWires + ' connections, ' + nWalls + ' walls, ' + nZones + ' zones, ' + nText + ' text labels, ' + nFurn + ' furniture. Arrow keys orbit, plus and minus zoom, Tab cycles selection, Enter opens the editor for the selection.');
    if (statEl) statEl.textContent = nNodes + ' nodes' + (nIcons ? ' (' + nIcons + ' icons)' : '') + ' · ' + nRacks + ' racks · ' + nWires + ' wires' + (nPorts ? ' (' + nPorts + ' ports)' : '') + ' · ' + nFov + ' coverage · ' + nWalls + ' walls · ' + nZones + ' zones · ' + nText + ' text · ' + nFurn + ' furniture' + (nHidden ? ' · ' + nHidden + ' layer-hidden' : '') + (nGroups ? ' · ' + nGroups + ' grouped' : '');
    if (hudEl && hudEl.style.display === 'block') renderHud();
    if (selection.length) {
      const alive = selection.filter(function (s) { return !!objectFor(s.kind, s.id); });
      if (alive.length !== selection.length) {
        selection = alive;
        const last = selection.length ? selection[selection.length - 1] : null;
        selectedId = last ? last.id : null; selectedKind = last ? last.kind : null;
        renderInspect();
      }
      applySelectionVisuals();
    }
    { let pr = false; const rIds = {}; ((RD.list) || []).forEach((x) => { if (x) rIds[x.id] = 1; }); const eIds = {}; edgeList.forEach((x) => { if (x) eIds[x.id] = 1; });
      const B = activeBucket();
      for (const k in B.wallHeights) if (!rIds[k]) { delete B.wallHeights[k]; pr = true; }
      for (const k in B.buried) if (!eIds[k]) { delete B.buried[k]; pr = true; }
      if (pr && sceneReady) scheduleSave(); }
    if (_envTex) { scene.environment = _envTex; scene.environmentIntensity = LIGHT.env; }
    if (renderPass) { renderPass.scene = scene; renderPass.camera = camera; }
    applyVRWorldScale();
    pruneImgTexCache(_imgUsed); _imgUsed = null;
    pruneIconTexCache(_iconUsed); _iconUsed = null;
    pruneEmblemCache(_emblemUsed); _emblemUsed = null;
    lastTopoSig = topoSig();
    followStruct = followStructSig(); followMove = null; followWire = followWireSig(positions, edgeList);
    pendingPeerRebuild = false; pendingConflictRebuild = false;
  }

  let lastTopoSig = null, lastTopoCheckAt = 0, lastRecSyncAt = 0;
  let lastBuild = { hidden: 0, groups: 0, fov: 0 };
  function topoSig() {
    try {
      const nd = getVar('NODE_DATA') || {}, sp = getVar('savedPositions') || {}, sz = getVar('savedSizes') || {}, st = getVar('savedStyles') || {}, ed = getVar('EDGE_DATA') || {};
      let h = 5381, budget = 120000;
      const _tk = tabKey();
      const mix = (v) => { const s = '' + (v == null ? '' : v); for (let i = 0; i < s.length && budget > 0; i++, budget--) h = ((h << 5) + h + s.charCodeAt(i)) | 0; h = (((h << 5) + h) ^ 0x9e37) | 0; };
      mix('tk'); mix(_tk);
      const keys = Object.keys(nd); mix(keys.length);
      for (let k = 0; k < keys.length && budget > 0; k++) {
        const id = keys[k], n = nd[id] || {}, p = sp[id] || {}, sty = bookResolveStyles(st[id]);
        mix(id); mix(n.name); mix(n.shape); mix(n.ip); mix(n.role); mix(n.layer); mix(n.isRack ? 1 : 0); mix(n.rackCapacity); mix(n.assignedRack); mix(n.rackUnit);
        mix(n.fovEnabled ? 1 : 0); mix(n.fovAngle); mix(n.fovDistance); mix(n.fovRotation); mix(p.x); mix(p.y); mix(sz[id]); mix(sty.circleColor); mix(sty.circleBorder);
        mix(n.fovAnimate ? 1 : 0); mix(n.fovAnimationType); mix(n.fovSpeed); mix(n.ping && n.ping.enabled ? 1 : 0); mix(n.ping && n.ping.status);
        mix(n.fovColor); mix(n.fovOpacity); mix(n.fovInnerRadius); mix(n.fovBorderColor); mix(n.fovSweep);
        mix(n.fovLabel); mix(n.fovLabelColor); mix(n.fovLabelOffsetX); mix(n.fovLabelOffsetY); mix(sty.titleColor);
        mix(n.locked ? 1 : 0);
        mix(n.groupId);
        mix(n.rotation);
        mix(sty.titleFont); mix(sty.titleSize); mix(sty.titleOffsetX); mix(sty.titleOffsetY);
        mix(sty.subColor); mix(sty.subFont); mix(sty.subSize); mix(sty.subOffsetX); mix(sty.subOffsetY);
        mix(sty.icon && (sty.icon.library + '/' + sty.icon.name));
      }
      { const icc = getVar('iconCache'); mix('ic'); mix(icc && typeof icc === 'object' ? Object.keys(icc).length : 0); }
      const el = (ed && ed.list) || []; mix('e'); mix(el.length);
      for (let e = 0; e < el.length && budget > 0; e++) { const g = el[e] || {}; mix(g.from); mix(g.to); mix(g.id); mix(g.routing); mix(g.lineStyle); mix(g.direction); mix(g.width); mix(g.color); mix(g.animate ? 1 : 0); mix(g.animationStyle); mix(g.animationSpeed); mix(g.fromPort); mix(g.toPort); mix(g.groupId); const wp = g.waypoints || []; mix(wp.length); for (let w = 0; w < wp.length && budget > 0; w++) { mix(wp[w] && wp[w].x); mix(wp[w] && wp[w].y); } }
      const ps = getVar('PAGE_STATE') || {}; mix('p'); mix(ps.animateConnections ? 1 : 0); mix(ps.animationStyle); mix(ps.animationSpeed); mix(ps.animationDirection);
      mix(ps.canvasTemplate); mix(ps.mappingMode); mix(ps.canvasGrid); mix(ps.canvasGridSize);
      mix(ps.showPortLabels ? 1 : 0);
      mix('nf'); mix(ps.nodeFill); mix('ns'); mix(ps.nodeStroke); mix('nt'); mix(ps.nodeTitle); mix('nb'); mix(ps.nodeSub);
      mix('nz'); mix(ps.nodeTitleSize); mix('bz'); mix(ps.nodeSubSize); mix('nn'); mix(ps.nodeFont); mix('de'); mix(ps.defaultEdge); mix('gi'); mix(ps.groupIndicator);
      { const as = getVar('ANIM_SETTINGS') || {}; const at = as.animTypes || {}, ac = as.animCategories || {}, zc = as.zoneCategories || {};
        mix('a'); mix(as.masterAnim === false ? 0 : 1); mix(as.masterZones === false ? 0 : 1);
        ['sweep', 'pulse', 'rings', 'spin', 'connections'].forEach((k) => mix(at[k] ? 1 : 0));
        ['camera', 'doorbell', 'motion', 'smoke', 'wifi', 'sensor', 'sprinkler', 'connections'].forEach((k) => mix(ac[k] ? 1 : 0));
        ['camera', 'doorbell', 'motion', 'smoke', 'wifi', 'sensor', 'sprinkler'].forEach((k) => mix(zc[k] ? 1 : 0)); }
      const rl = ((getVar('RECT_DATA') || {}).list) || []; mix('r'); mix(rl.length);
      for (let r = 0; r < rl.length && budget > 0; r++) { const g = rl[r] || {}; mix(g.id); mix(g.x); mix(g.y); mix(g.width); mix(g.height); mix(g.lineStyle); mix(g.style); mix(g.color); mix(g.rotation); mix(g.fillOpacity); mix(g.borderColor); mix(g.borderWidth); mix(g.locked ? 1 : 0); mix(g.groupId); }
      const tl = ((getVar('TEXT_DATA') || {}).list) || []; mix('t'); mix(tl.length);
      for (let t = 0; t < tl.length && budget > 0; t++) { const g = tl[t] || {}; mix(g.id); mix(g.x); mix(g.y); mix(g.content); mix(g.fontSize); mix(g.color); mix(g.bgEnabled ? 1 : 0); mix(g.fontWeight); mix(g.fontStyle); mix(g.textAlign); mix(g.textDecoration); mix(g.bgColor); mix(g.opacity); mix(g.locked ? 1 : 0); mix(g.groupId); }
      const il = ((getVar('IMAGE_DATA') || {}).list) || []; mix('i'); mix(il.length);
      for (let m = 0; m < il.length && budget > 0; m++) { const g = il[m] || {}; mix(g.id); mix(g.x); mix(g.y); mix(g.width); mix(g.height); mix(g.opacity); mix(g.border); mix(g.shadow); }
      return h;
    } catch (e) { return lastTopoSig; }
  }

  const TRAIL_Y = 7;
  const TRAIL_OPACITY = 0.6;
  const REC_SPEEDS = ['0.5', '1', '2', '4'];
  const TRAIL_STYLES = ['solid', 'dashed', 'dots'];
  const REC_HANDLES = ['startRecording', 'stopRecording', 'playRecording', 'pauseRecording', 'seekRecording', 'startStepRecording', 'stopStepRecording', 'captureStepFrame', 'selectRecording'];
  const FOLLOW_BUDGET_MS = 16;
  let followNodes = [], followTexts = [], followRects = [];
  let followStruct = null, followMove = null, followWire = null, followHoldUntil = 0, followPending = false;
  let followSteps = 0, wireRebuilds = 0, wasPlaying = false, trailDirty = true;
  let followCostEma = 0, followNextAt = 0;
  let trailRoot = null, trailCount = 0;

  function recState() { const r = getVar('RECORDING_STATE'); return (r && typeof r === 'object') ? r : null; }
  function recFn(n) { const f = getVar(n); return typeof f === 'function' ? f : undefined; }
  function recCall(n, arg) {
    const f = recFn(n);
    if (!f) { guardToast('🎬 The recording controls are not available in this document.'); return false; }
    try { if (arg === undefined) f(); else f(arg); return true; }
    catch (e) { guardToast('🎬 The 2D recorder refused that action (' + ((e && e.message) || e) + ').'); return false; }
  }
  function recFmtTime(ms) { const s = Math.floor(num(ms, 0) / 1000), m = Math.floor(s / 60); return m + ':' + String(s % 60).padStart(2, '0'); }

  function followReset() { followNodes = []; followTexts = []; followRects = []; followStruct = null; followMove = null; followWire = null; trailRoot = null; trailCount = 0; followCostEma = 0; followNextAt = 0; }
  function followStructSig() {
    let s = 17; const add = (v) => { s = (Math.imul(s, 31) + (v | 0)) | 0; };
    const nd = getVar('NODE_DATA') || {}, keys = Object.keys(nd);
    add(keys.length);
    for (let i = 0; i < keys.length; i++) { const k = keys[i]; for (let c = 0; c < k.length; c++) add(k.charCodeAt(c)); }
    add((((getVar('EDGE_DATA') || {}).list) || []).length);
    add((((getVar('RECT_DATA') || {}).list) || []).length);
    add((((getVar('TEXT_DATA') || {}).list) || []).length);
    add((((getVar('IMAGE_DATA') || {}).list) || []).length);
    add(followNodes.length); add(followRects.length); add(followTexts.length);
    return s;
  }
  function followMoveSig(positions, rl, tl, ed) {
    let s = 5; const add = (v) => { s = (Math.imul(s, 31) + ((num(v, 0) * 8) | 0)) | 0; };
    for (let i = 0; i < followNodes.length; i++) { const p = positions[followNodes[i].id]; if (!p) { s = (Math.imul(s, 31) + 1) | 0; continue; } add(p.x); add(p.y); }
    for (let i = 0; i < rl.length; i++) { const r = rl[i] || {}; add(r.x); add(r.y); add(r.width); add(r.height); add(r.rotation); }
    for (let i = 0; i < tl.length; i++) { const t = tl[i] || {}; add(t.x); add(t.y); }
    for (let i = 0; i < ed.length; i++) { const w = (ed[i] && ed[i].waypoints) || []; s = (Math.imul(s, 31) + w.length) | 0; for (let q = 0; q < w.length; q++) { add(w[q] && w[q].x); add(w[q] && w[q].y); } }
    return s;
  }
  function followWireSig(positions, ed) {
    let s = 11; const add = (v) => { s = (Math.imul(s, 31) + ((num(v, 0) * 8) | 0)) | 0; };
    for (let i = 0; i < followNodes.length; i++) { const p = positions[followNodes[i].id]; if (!p) { s = (Math.imul(s, 31) + 1) | 0; continue; } add(p.x); add(p.y); }
    for (let i = 0; i < ed.length; i++) { const w = (ed[i] && ed[i].waypoints) || []; s = (Math.imul(s, 31) + w.length) | 0; for (let q = 0; q < w.length; q++) { add(w[q] && w[q].x); add(w[q] && w[q].y); } }
    return s;
  }
  function reattachSelBox() { if (scene) applySelectionVisuals(); }
  function playbackFollow(force) {
    if (!scene) return false;
    const t0 = performance.now();
    if (!force && followNextAt && t0 < followNextAt) return true;
    if (followStructSig() !== followStruct) { buildScene(); return false; }
    const positions = getVar('savedPositions') || {};
    const rl = (((getVar('RECT_DATA') || {}).list) || []), tl = (((getVar('TEXT_DATA') || {}).list) || []);
    const ed = (((getVar('EDGE_DATA') || {}).list) || []);
    const mv = followMoveSig(positions, rl, tl, ed);
    if (mv !== followMove) {
      followMove = mv; followSteps++;
      for (let i = 0; i < followNodes.length; i++) {
        const f = followNodes[i], p = positions[f.id]; if (!p) continue;
        if (!f.base) { const b = []; for (let q = 0; q < f.objs.length; q++) { const o = f.objs[q]; if (o && o.position) b.push({ o: o, x: o.position.x, y: o.position.y, z: o.position.z }); } f.base = b; }
        const nx = sx(num(p.x, 0)), nz = sz(num(p.y, 0)), dx = nx - f.bx, dz = nz - f.bz;
        for (let q = 0; q < f.base.length; q++) { const b = f.base[q]; b.o.position.set(b.x + dx, b.y, b.z + dz); }
        const c = nodeCenters[f.id]; if (c) { c.x = nx; c.z = nz; }
      }
      if (followRects.length) {
        const byId = Object.create(null); for (let i = 0; i < rl.length; i++) if (rl[i]) byId[rl[i].id] = rl[i];
        for (let i = 0; i < followRects.length; i++) {
          const f = followRects[i], r = byId[f.id];
          if (!r || Math.abs(num(r.width, 0)) !== f.w || Math.abs(num(r.height, 0)) !== f.h) { buildScene(); return false; }
          const cx = sx(num(r.x, 0) + num(r.width, 0) / 2), cz = sz(num(r.y, 0) + num(r.height, 0) / 2);
          f.o.position.x = cx; f.o.position.z = cz; f.o.rotation.y = -rad(r.rotation); f.o.__gx = cx; f.o.__gz = cz;
        }
      }
      if (followTexts.length) {
        const byId = Object.create(null); for (let i = 0; i < tl.length; i++) if (tl[i]) byId[tl[i].id] = tl[i];
        for (let i = 0; i < followTexts.length; i++) { const f = followTexts[i], t = byId[f.id]; if (!t) continue; f.o.position.x = sx(num(t.x, WORLD_W / 2)); f.o.position.z = sz(num(t.y, WORLD_D / 2)); }
      }
      const ws = followWireSig(positions, ed);
      if (ws !== followWire) {
        followWire = ws;
        buildEdgeLayer(positions, ed, false); wireRebuilds++;
        if (selectedId) reattachSelBox();
      } else if (selBox) selBox.update();
      trailDirty = true;
      const cost = performance.now() - t0;
      followCostEma = followCostEma ? followCostEma * 0.7 + cost * 0.3 : cost;
      followNextAt = followCostEma > FOLLOW_BUDGET_MS ? performance.now() + followCostEma * 2 : 0;
    }
    if (trailDirty) { trailDirty = false; buildTrailLayer(); }
    return true;
  }

  function disposeTrailLayer() { if (!trailRoot) return; if (trailRoot.parent) trailRoot.parent.remove(trailRoot); disposeObject3D(trailRoot); trailRoot = null; trailCount = 0; }
  function trailColor(id, styles) {
    const st = styles && styles[id];
    return hexColor((st && st.stroke) || (st && bookResolveStyles(st).circleBorder) || theme.nodeStroke || '#475569', '#475569');
  }
  function buildTrailLayer() {
    disposeTrailLayer();
    if (!scene) return;
    if (reduceMotion()) return;
    const rs = recState(); if (!rs || !rs.isPlaying) return;
    const ps = getVar('PAGE_STATE') || {}; if (!ps.motionTrailsEnabled) return;
    const hist = rs.trailHistory; if (!hist || typeof hist !== 'object') return;
    const ids = Object.keys(hist); if (!ids.length) return;
    const ND = getVar('NODE_DATA') || {}, styles = getVar('savedStyles') || {}, sizes = getVar('savedSizes') || {};
    const heights = scene3d.heights || {};
    const style = TRAIL_STYLES.indexOf(ps.motionTrailStyle) !== -1 ? ps.motionTrailStyle : 'solid';
    const arrow = ps.motionTrailArrow !== false;
    const root = new THREE.Group(); let n = 0;
    for (let i = 0; i < ids.length; i++) {
      const id = ids[i], node = ND[id];
      if (!node || node.trailEnabled === false) continue;
      const trail = hist[id]; if (!Array.isArray(trail) || trail.length < 2) continue;
      const size = Number(sizes[id]) || 55;
      const col = trailColor(id, styles);
      const y = TRAIL_Y + clamp(num(heights[id], 0), 0, MAX_ELEVATION);
      const pts = []; for (let q = 0; q < trail.length; q++) { const p = trail[q]; if (p) pts.push(new THREE.Vector3(sx(num(p.x, 0)), y, sz(num(p.y, 0)))); }
      if (pts.length < 2) continue;
      if (style === 'dots') {
        const B = Math.min(4, pts.length);
        for (let b = 0; b < B; b++) {
          const lo = Math.floor(b * pts.length / B), hi = Math.floor((b + 1) * pts.length / B);
          if (hi <= lo) continue;
          const f = (b + 1) / B;
          const g = new THREE.BufferGeometry().setFromPoints(pts.slice(lo, hi));
          root.add(new THREE.Points(g, new THREE.PointsMaterial({ color: col, size: (3 + f * 4) * 2, sizeAttenuation: true, transparent: true, opacity: f * 0.7, depthWrite: false })));
        }
      } else {
        const g = new THREE.BufferGeometry().setFromPoints(pts);
        const m = style === 'dashed'
          ? new THREE.LineDashedMaterial({ color: col, dashSize: 8, gapSize: 4, transparent: true, opacity: TRAIL_OPACITY })
          : new THREE.LineBasicMaterial({ color: col, transparent: true, opacity: TRAIL_OPACITY });
        const l = new THREE.Line(g, m); if (style === 'dashed') l.computeLineDistances(); root.add(l);
      }
      if (arrow) {
        const last = pts[pts.length - 1], prev = pts[pts.length - 2];
        const d = new THREE.Vector3(last.x - prev.x, 0, last.z - prev.z); const L = d.length();
        if (L > 1e-3) {
          d.multiplyScalar(1 / L);
          const aS = Math.max(12, size * 0.26);
          const cone = new THREE.Mesh(new THREE.ConeGeometry(aS * 0.7, aS * 1.8, 8), new THREE.MeshBasicMaterial({ color: col, transparent: true, opacity: 0.8 }));
          cone.position.copy(last).addScaledVector(d, size / 2 + 5 + aS * 0.9);
          cone.quaternion.setFromUnitVectors(UP_Y, d);
          root.add(cone);
        }
      }
      n++;
    }
    if (!n) { disposeObject3D(root); return; }
    contentRoot().add(root); trailRoot = root; trailCount = n;
  }

  let recEl = null, recBody = null, recBtn = null, recListSig = null;
  let rcRecord, rcStep, rcFrame, rcPlay, rcPause, rcStop, rcScrub, rcTime, rcSpeed, rcLoop, rcStatus, rcSel;
  let rcTrailOn, rcTrailStyle, rcTrailLen, rcTrailLenVal, rcTrailArrow;
  const REC_BTN_CSS = 'flex:0 0 auto;padding:5px 9px;background:#1e293b;color:#e2e8f0;border:1px solid #334155;border-radius:6px;font:600 12px system-ui;cursor:pointer';
  function recButton(txt, title, on) {
    const b = document.createElement('button'); b.type = 'button'; b.textContent = txt; b.title = title || txt;
    b.style.cssText = REC_BTN_CSS; b.addEventListener('click', on); return b;
  }
  function recRow(parent) { const d = document.createElement('div'); d.style.cssText = 'display:flex;align-items:center;gap:6px;margin:5px 0;flex-wrap:wrap'; parent.appendChild(d); return d; }
  function recLabel(txt) { const s = document.createElement('span'); s.style.cssText = 'flex:0 0 auto;color:#94a3b8'; s.textContent = txt; return s; }
  function ensureRecPanel() {
    if (recEl) return;
    recEl = document.createElement('div');
    recEl.id = 'threed-recorder';
    recEl.style.cssText = 'position:absolute;top:56px;z-index:5;width:264px;max-width:calc(100% - 28px);max-height:calc(100% - 210px);overflow-y:auto;display:none;color:#e2e8f0;font:12px/1.5 system-ui,sans-serif;background:rgba(15,23,42,.94);border:1px solid #334155;border-radius:10px;padding:10px 12px';
    const hdr = document.createElement('div');
    hdr.style.cssText = 'display:flex;justify-content:space-between;align-items:center;font-weight:700;color:#7dd3c8;margin-bottom:6px';
    const ht = document.createElement('span'); ht.textContent = '🎬 Recording'; hdr.appendChild(ht);
    const x = document.createElement('span'); x.textContent = '✕'; x.style.cssText = 'cursor:pointer;color:#64748b'; x.onclick = function () { recEl.style.display = 'none'; }; hdr.appendChild(x);
    recEl.appendChild(hdr);
    recBody = document.createElement('div'); recEl.appendChild(recBody);
    overlay.appendChild(recEl);
    buildRecPanel();
  }
  function buildRecPanel() {
    const tr = hudSection('Transport', recBody);
    const r1 = recRow(tr);
    rcRecord = recButton('● Rec', 'Start / stop a 10 fps recording', recToggleRecord); r1.appendChild(rcRecord);
    rcStep = recButton('●+ Step', 'Start / end a step by step recording', recToggleStep); r1.appendChild(rcStep);
    rcFrame = recButton('＋ Frame', 'Capture one step frame', function () { recCall('captureStepFrame'); syncRecPanel(); }); r1.appendChild(rcFrame);
    const r2 = recRow(tr);
    rcPlay = recButton('▶ Play', 'Play the selected recording', recPlay); r2.appendChild(rcPlay);
    rcPause = recButton('⏸ Pause', 'Pause playback', recPause); r2.appendChild(rcPause);
    rcStop = recButton('■ Stop', 'Stop recording / playback', recStop); r2.appendChild(rcStop);
    const r3 = recRow(tr);
    rcScrub = document.createElement('input'); rcScrub.type = 'range'; rcScrub.min = '0'; rcScrub.max = '100'; rcScrub.step = '0.5'; rcScrub.value = '0';
    rcScrub.title = 'Playback position'; rcScrub.style.cssText = 'flex:1 1 auto;min-width:0;cursor:pointer';
    rcScrub.addEventListener('input', function () { recSeek(parseFloat(rcScrub.value)); });
    r3.appendChild(rcScrub);
    rcTime = document.createElement('span'); rcTime.style.cssText = 'flex:0 0 auto;min-width:62px;text-align:right;color:#94a3b8;font-variant-numeric:tabular-nums'; rcTime.textContent = '0:00';
    r3.appendChild(rcTime);
    const r4 = recRow(tr);
    r4.appendChild(recLabel('Speed'));
    rcSpeed = document.createElement('select'); rcSpeed.style.cssText = 'flex:0 0 auto;padding:3px 5px;border:1px solid #334155;border-radius:4px;background:#0f172a;color:#e2e8f0;font:12px system-ui';
    REC_SPEEDS.forEach(function (v) { const o = document.createElement('option'); o.value = v; o.textContent = v + '×'; rcSpeed.appendChild(o); });
    rcSpeed.addEventListener('change', function () { recSetSpeed(rcSpeed.value); });
    r4.appendChild(rcSpeed);
    const ll = document.createElement('label'); ll.style.cssText = 'display:flex;align-items:center;gap:5px;margin-left:auto;cursor:pointer';
    rcLoop = document.createElement('input'); rcLoop.type = 'checkbox'; rcLoop.style.cssText = 'margin:0';
    rcLoop.addEventListener('change', function () { recSetLoop(rcLoop.checked); });
    ll.appendChild(rcLoop); ll.appendChild(recLabel('Loop')); r4.appendChild(ll);
    rcStatus = hudNote('', tr);

    const rl = hudSection('Recordings', recBody);
    rcSel = document.createElement('select'); rcSel.style.cssText = 'width:100%;padding:4px 6px;border:1px solid #334155;border-radius:4px;background:#0f172a;color:#e2e8f0;font:12px system-ui';
    rcSel.addEventListener('change', function () { recSelect(rcSel.value); syncRecPanel(); });
    rl.appendChild(rcSel);
    hudNote('Recordings live only in this browser tab: they are never saved to the room and never sent to collaborators. Playing one DOES move the real nodes, and that movement is shared.', rl);

    const tl = hudSection('Motion trails', recBody);
    const t1 = recRow(tl);
    rcTrailOn = document.createElement('input'); rcTrailOn.type = 'checkbox'; rcTrailOn.style.cssText = 'margin:0';
    rcTrailOn.addEventListener('change', function () { if (!recSetTrail({ motionTrailsEnabled: rcTrailOn.checked }, !rcTrailOn.checked, !rcTrailOn.checked)) syncRecPanel(); });
    const t1l = document.createElement('label'); t1l.style.cssText = 'display:flex;align-items:center;gap:5px;cursor:pointer';
    t1l.appendChild(rcTrailOn); t1l.appendChild(recLabel('Show trails')); t1.appendChild(t1l);
    rcTrailArrow = document.createElement('input'); rcTrailArrow.type = 'checkbox'; rcTrailArrow.style.cssText = 'margin:0';
    rcTrailArrow.addEventListener('change', function () { if (!recSetTrail({ motionTrailArrow: rcTrailArrow.checked }, false, true)) syncRecPanel(); });
    const t2l = document.createElement('label'); t2l.style.cssText = 'display:flex;align-items:center;gap:5px;margin-left:auto;cursor:pointer';
    t2l.appendChild(rcTrailArrow); t2l.appendChild(recLabel('Arrow')); t1.appendChild(t2l);
    const t2 = recRow(tl);
    t2.appendChild(recLabel('Style'));
    rcTrailStyle = document.createElement('select'); rcTrailStyle.style.cssText = 'flex:1 1 auto;min-width:0;padding:3px 5px;border:1px solid #334155;border-radius:4px;background:#0f172a;color:#e2e8f0;font:12px system-ui';
    TRAIL_STYLES.forEach(function (v) { const o = document.createElement('option'); o.value = v; o.textContent = v; rcTrailStyle.appendChild(o); });
    rcTrailStyle.addEventListener('change', function () { if (!recSetTrail({ motionTrailStyle: rcTrailStyle.value }, false, true)) syncRecPanel(); });
    t2.appendChild(rcTrailStyle);
    const t3 = recRow(tl);
    t3.appendChild(recLabel('Length'));
    rcTrailLen = document.createElement('input'); rcTrailLen.type = 'range'; rcTrailLen.min = '2'; rcTrailLen.max = '20'; rcTrailLen.step = '1';
    rcTrailLen.style.cssText = 'flex:1 1 auto;min-width:0;cursor:pointer';
    rcTrailLen.addEventListener('input', function () { rcTrailLenVal.textContent = rcTrailLen.value; if (!recSetTrail({ motionTrailLength: parseInt(rcTrailLen.value, 10) }, false, false)) syncRecPanel(); });
    t3.appendChild(rcTrailLen);
    rcTrailLenVal = document.createElement('span'); rcTrailLenVal.style.cssText = 'flex:0 0 auto;min-width:20px;text-align:right;color:#94a3b8'; t3.appendChild(rcTrailLenVal);
    hudNote('Trails are drawn only while a recording is playing, and a node whose "Motion trail" box is off in its book is skipped.', tl);
  }
  function placeRecPanel() {
    const w = (overlay && overlay.clientWidth) || window.innerWidth || 1280;
    recEl.style.left = w >= 620 ? '278px' : '14px';
  }
  function toggleRecPanel() {
    if (!overlay) return false;
    ensureRecPanel();
    const show = recEl.style.display !== 'block';
    recEl.style.display = show ? 'block' : 'none';
    if (show) { placeRecPanel(); syncRecPanel(); }
    return show;
  }
  function syncRecPanel() {
    if (!recEl || recEl.style.display !== 'block') return;
    const rs = recState(), ae = document.activeElement;
    const has = !!rs, cur = rs && rs.currentRecording, frames = (cur && cur.frames) || [];
    const playable = frames.length >= 2;
    rcRecord.textContent = (rs && rs.isRecording) ? '■ End rec' : '● Rec';
    rcRecord.disabled = !has || !!(rs && (rs.isPlaying || rs.isPaused || rs.isStepRecording));
    rcStep.textContent = (rs && rs.isStepRecording) ? '■ End steps' : '●+ Step';
    rcStep.disabled = !has || !!(rs && (rs.isRecording || rs.isPlaying || rs.isPaused));
    rcFrame.disabled = !has || !(rs && rs.isStepRecording);
    rcPlay.textContent = (rs && rs.isPaused) ? '▶ Resume' : '▶ Play';
    rcPlay.disabled = !has || !playable || !!(rs && rs.isPlaying);
    rcPause.disabled = !has || !(rs && rs.isPlaying);
    rcStop.disabled = !has || !(rs && (rs.isRecording || rs.isPlaying));
    rcScrub.disabled = !has || !playable;
    rcSpeed.disabled = !has; rcLoop.disabled = !has;
    if (has && playable && ae !== rcScrub) rcScrub.value = String(clamp((rs.playbackIndex / Math.max(1, frames.length - 1)) * 100, 0, 100));
    const at = frames[clamp(rs ? (rs.playbackIndex | 0) : 0, 0, Math.max(0, frames.length - 1))];
    rcTime.textContent = playable ? (recFmtTime(at && at.time) + ' / ' + recFmtTime(cur.duration)) : '0:00';
    if (has && ae !== rcSpeed) { const sv = String(num(rs.playbackSpeed, 1)); rcSpeed.value = REC_SPEEDS.indexOf(sv) !== -1 ? sv : '1'; }
    if (has && ae !== rcLoop) rcLoop.checked = !!rs.loopPlayback;
    rcStatus.textContent = !has ? 'RECORDING_STATE is not on the bridge in this document, the transport is inert.'
      : rs.isRecording ? 'Recording: ' + (rs.frames || []).length + ' frames captured.'
      : rs.isStepRecording ? 'Step recording, ' + (rs.stepCount | 0) + ' frames. Move things in 2D or 3D, then ＋ Frame.'
      : rs.isPlaying ? 'Playing frame ' + (rs.playbackIndex | 0) + ' / ' + Math.max(0, frames.length - 1) + '.'
      : rs.isPaused ? 'Paused. ▶ Resume, then ■ to stop (this is how 2D works too).'
      : playable ? frames.length + ' frames ready.' : 'No recording selected, ● Rec, or ●+ Step.';
    const list = (rs && Array.isArray(rs.recordings)) ? rs.recordings : [];
    let sig = list.length + '|'; for (let i = 0; i < list.length; i++) { const r = list[i] || {}; sig += r.id + '~' + (r.name || '') + '~' + ((r.frames || []).length) + ','; }
    if (sig !== recListSig) {
      recListSig = sig; rcSel.textContent = '';
      if (!list.length) { const o = document.createElement('option'); o.value = ''; o.textContent = 'No recordings yet'; rcSel.appendChild(o); }
      list.forEach(function (r) { const o = document.createElement('option'); o.value = r.id; o.textContent = (r.name || r.id) + '  (' + ((r.frames || []).length) + 'f, ' + recFmtTime(r.duration) + ')'; rcSel.appendChild(o); });
    }
    rcSel.disabled = !list.length;
    if (ae !== rcSel) rcSel.value = (cur && cur.id) || '';
    const ps = getVar('PAGE_STATE') || {};
    if (ae !== rcTrailOn) rcTrailOn.checked = !!ps.motionTrailsEnabled;
    if (ae !== rcTrailArrow) rcTrailArrow.checked = ps.motionTrailArrow !== false;
    if (ae !== rcTrailStyle) rcTrailStyle.value = TRAIL_STYLES.indexOf(ps.motionTrailStyle) !== -1 ? ps.motionTrailStyle : 'solid';
    if (ae !== rcTrailLen) rcTrailLen.value = String(clamp(Math.round(num(ps.motionTrailLength, 8)), 2, 20));
    rcTrailLenVal.textContent = rcTrailLen.value;
  }

  function recToggleRecord() { const rs = recState(); if (!rs) { guardToast('🎬 Recording is not available in this document.'); return; } recCall(rs.isRecording ? 'stopRecording' : 'startRecording'); trailDirty = true; followPending = true; syncRecPanel(); }
  function recToggleStep() { const rs = recState(); if (!rs) { guardToast('🎬 Recording is not available in this document.'); return; } recCall(rs.isStepRecording ? 'stopStepRecording' : 'startStepRecording'); syncRecPanel(); }
  function recPlay() {
    const rs = recState(); if (!rs) { guardToast('🎬 Recording is not available in this document.'); return; }
    if (editBlocked(null)) return;
    const cur = rs.currentRecording;
    if (!cur || !(cur.frames || []).length || cur.frames.length < 2) { guardToast('🎬 Nothing to play, record something first, or pick a recording from the list.'); return; }
    recCall('playRecording'); trailDirty = true; followPending = true; syncRecPanel();
  }
  function recPause() { recCall('pauseRecording'); followPending = true; syncRecPanel(); }
  function recStop() { recCall('stopRecording'); disposeTrailLayer(); trailDirty = true; followPending = true; syncRecPanel(); }
  function recSeek(pct) {
    const rs = recState(); if (!rs) return;
    if (editBlocked(null)) { syncRecPanel(); return; }
    if (!rs.currentRecording) { guardToast('🎬 No recording selected.'); syncRecPanel(); return; }
    recCall('seekRecording', clamp(num(pct, 0), 0, 100));
    followPending = true; trailDirty = true;
    followHoldUntil = performance.now() + 700;
  }
  function recSelect(id) {
    const rs = recState(); if (!rs) return false;
    const f = recFn('selectRecording');
    if (f) { try { f(id); return true; } catch (e) {} }
    const list = Array.isArray(rs.recordings) ? rs.recordings : [];
    rs.currentRecording = list.filter(function (r) { return r && r.id === id; })[0] || null;
    return true;
  }
  function recSetSpeed(v) {
    const rs = recState(); if (!rs) return;
    const n = clamp(num(v, 1), 0.1, 16); rs.playbackSpeed = n;
    const el = document.getElementById('playback-speed'); if (el && REC_SPEEDS.indexOf(String(n)) !== -1) el.value = String(n);
    syncRecPanel();
  }
  function recSetLoop(on) {
    const rs = recState(); if (!rs) return;
    rs.loopPlayback = !!on;
    const el = document.getElementById('loop-playback'); if (el) el.checked = !!on;
    syncRecPanel();
  }
  function recSetTrail(patch, clearHistory, forge) {
    if (editBlocked(null)) return false;
    setVar('PAGE_STATE', patch);
    if (clearHistory) { const rs = recState(); if (rs) rs.trailHistory = {}; }
    if (forge) { const f = getVar('forgeTheTopology') || window.forgeTheTopology; if (typeof f === 'function') { try { f(); } catch (e) {} } }
    trailDirty = true; followPending = true;
    return true;
  }
  function recInfo() {
    const rs = recState(), ps = getVar('PAGE_STATE') || {}, cur = rs && rs.currentRecording;
    return {
      bridged: !!rs,
      handles: REC_HANDLES.filter(function (n) { return !!recFn(n); }).length,
      isRecording: !!(rs && rs.isRecording), isPlaying: !!(rs && rs.isPlaying), isPaused: !!(rs && rs.isPaused), isStepRecording: !!(rs && rs.isStepRecording),
      recordings: (rs && Array.isArray(rs.recordings)) ? rs.recordings.length : 0,
      current: cur ? { id: cur.id, frames: (cur.frames || []).length, duration: cur.duration | 0 } : null,
      index: rs ? (rs.playbackIndex | 0) : 0, speed: rs ? num(rs.playbackSpeed, 1) : null, loop: !!(rs && rs.loopPlayback),
      capturing: (rs && Array.isArray(rs.frames)) ? rs.frames.length : 0, steps: rs ? (rs.stepCount | 0) : 0,
      trails: { enabled: !!ps.motionTrailsEnabled, style: ps.motionTrailStyle || 'solid', length: num(ps.motionTrailLength, 8), arrow: ps.motionTrailArrow !== false,
        buffered: (rs && rs.trailHistory && typeof rs.trailHistory === 'object') ? Object.keys(rs.trailHistory).length : 0, drawn: trailCount },
      follow: { nodes: followNodes.length, rects: followRects.length, texts: followTexts.length, steps: followSteps, wireRebuilds: wireRebuilds,
        costMs: +followCostEma.toFixed(2), throttled: followNextAt > 0, holdingPoll: performance.now() < followHoldUntil },
      panelOpen: !!(recEl && recEl.style.display === 'block')
    };
  }

  let camGoal = null;
  function fitCamera(animate) {
    let g;
    if (cbox) { const cx = (cbox.a + cbox.b) / 2, cz = (cbox.c + cbox.d) / 2, ext = Math.max(cbox.b - cbox.a, cbox.d - cbox.c, 400); g = { tx: cx, ty: 60, tz: cz, radius: clamp(ext * 1.15, 400, 9000), theta: Math.PI * 0.25, phi: Math.PI * 0.34 }; }
    else g = { tx: 0, ty: 40, tz: 0, radius: 2600, theta: Math.PI * 0.25, phi: Math.PI * 0.34 };
    if (animate) { camGoal = g; }
    else { target.set(g.tx, g.ty, g.tz); radius = g.radius; theta = g.theta; phi = g.phi; camGoal = null; }
  }
  function stepCameraGoal() {
    if (!camGoal || mode !== 'orbit') return;
    if (reduceMotion()) {
      target.set(camGoal.tx, camGoal.ty, camGoal.tz); radius = camGoal.radius; theta = camGoal.theta; phi = camGoal.phi; camGoal = null;
      return;
    }
    const k = 0.12;
    target.x += (camGoal.tx - target.x) * k; target.y += (camGoal.ty - target.y) * k; target.z += (camGoal.tz - target.z) * k;
    radius += (camGoal.radius - radius) * k; theta += (camGoal.theta - theta) * k; phi += (camGoal.phi - phi) * k;
    if (Math.abs(camGoal.radius - radius) < 2 && Math.abs(camGoal.tx - target.x) < 2 && Math.abs(camGoal.tz - target.z) < 2 && Math.abs(camGoal.theta - theta) < 0.005) {
      target.set(camGoal.tx, camGoal.ty, camGoal.tz); radius = camGoal.radius; theta = camGoal.theta; phi = camGoal.phi; camGoal = null;
    }
  }

  function drawMarquee(cx, cy) {
    if (!overlay || !marqScreen) return;
    if (!marqEl) {
      marqEl = document.createElement('div');
      marqEl.id = 'threed-marquee';
      marqEl.style.cssText = 'position:fixed;z-index:8;border:1px dashed #38bdf8;background:rgba(56,189,248,.14);pointer-events:none;display:none';
      overlay.appendChild(marqEl);
    }
    const x0 = Math.min(marqScreen.x, cx), y0 = Math.min(marqScreen.y, cy);
    marqEl.style.left = x0 + 'px'; marqEl.style.top = y0 + 'px';
    marqEl.style.width = Math.abs(cx - marqScreen.x) + 'px'; marqEl.style.height = Math.abs(cy - marqScreen.y) + 'px';
    marqEl.style.display = 'block';
  }
  function hideMarquee() { if (marqEl) marqEl.style.display = 'none'; marqStart = null; marqEnd = null; marqScreen = null; }
  function finishMarquee() {
    const a = marqStart, b = marqEnd;
    hideMarquee();
    if (!a || !b) return;
    const rect = marqueeRectOf(a, b);
    if (marqueeArea(rect) < 16) return;
    const cands = [], v = new THREE.Vector3();
    const items = pickableItems(true);
    for (let i = 0; i < items.length; i++) { items[i].obj.getWorldPosition(v); cands.push({ kind: items[i].kind, id: items[i].id, x: v.x, z: v.z }); }
    const hits = marqueeHits(rect, cands);
    if (!hits.length) { guardToast('▢ Nothing inside the box.'); return; }
    setSelection(selUnion(selection, hits));
    guardToast('▣ ' + selection.length + ' selected');
  }
  function marqueeRectOf(a, b) { return marqueeRect({ x: a.x, z: a.z }, { x: b.x, z: b.z }); }

  const ptrs = new Map();
  let gestStart = null;
  let gestDist0 = 0, gestRadius0 = 0, gestCentroid0 = null, gestTarget0 = null, gestKind = null;
  let multiTouch = false;
  let lpTimer = null, lpDown = null;
  let lookDragging = false;
  function clearLongPress() { if (lpTimer) { clearTimeout(lpTimer); lpTimer = null; } lpDown = null; }
  function ptrList() {
    const out = [];
    ptrs.forEach(function (p, id) { out.push({ id: id, x: p.x, y: p.y }); });
    return out;
  }
  function abandonSinglePointer() {
    const wasDragging = !!(dragId || dragGroup);
    clearLongPress(); hideMarquee();
    placeCandidate = false; dragId = null; dragObj = null; dragKind = null; dragGroup = null; dragAnchor = null; orbiting = false; dragMoved = false;
    if (wasDragging && active) buildScene();
  }
  function beginGesture() {
    const l = ptrList(); if (l.length !== 2) return;
    gestStart = [{ id: l[0].id, x: l[0].x, y: l[0].y }, { id: l[1].id, x: l[1].x, y: l[1].y }];
    gestDist0 = touchDist(gestStart[0], gestStart[1]);
    gestCentroid0 = touchCentroid(gestStart);
    gestRadius0 = radius; gestTarget0 = { x: target.x, z: target.z };
    gestKind = null; multiTouch = true; camGoal = null;
  }
  function endGesture() { gestStart = null; gestKind = null; gestCentroid0 = null; gestTarget0 = null; }
  function updateGesture() {
    if (!gestStart) return;
    const now = [];
    for (let i = 0; i < gestStart.length; i++) { const p = ptrs.get(gestStart[i].id); if (!p) return; now.push({ id: gestStart[i].id, x: p.x, y: p.y }); }
    if (!gestKind) { const k = classifyGesture(gestStart, now, null); if (k === 'pinch' || k === 'pan') gestKind = k; }
    if (gestKind === 'pinch') { radius = pinchDolly(gestRadius0, gestDist0, touchDist(now[0], now[1]), 120, 12000); return; }
    if (gestKind === 'pan') {
      const c = touchCentroid(now);
      const dxPx = c.x - gestCentroid0.x, dyPx = c.y - gestCentroid0.y;
      const k = radius / Math.max(1, (overlay && overlay.clientHeight) || window.innerHeight || 720);
      const fX = Math.sin(theta), fZ = Math.cos(theta), rX = Math.cos(theta), rZ = -Math.sin(theta);
      target.x = gestTarget0.x - (rX * dxPx + fX * dyPx) * k;
      target.z = gestTarget0.z - (rZ * dxPx + fZ * dyPx) * k;
    }
  }

  function bindControls() {
    canvas.addEventListener('contextmenu', (e) => { if (active) e.preventDefault(); });
    canvas.addEventListener('pointerdown', (e) => {
      const rightBtn = (e.button === 2);
      try { canvas.focus({ preventScroll: true }); } catch (x) { try { canvas.focus(); } catch (y) {} }
      ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (ptrs.size >= 2) {
        abandonSinglePointer();
        if (ptrs.size === 2) beginGesture();
        else endGesture();
        return;
      }
      if (mode === 'walk') {
        if (freeLook) {
          lookDragging = true; lastX = e.clientX; lastY = e.clientY;
          try { canvas.setPointerCapture(e.pointerId); } catch (x) {}
          if (rightBtn) { const held = heldItem(); if (held) { const fp = floorPoint(new THREE.Vector2(0, 0)); if (fp) placeItem(held, fp); } return; }
          const pf = pick(new THREE.Vector2(0, 0));
          if (pf) { if (e.shiftKey) toggleSelect(pf.kind, pf.id); else selectItem(pf.kind, pf.id); } else if (!e.shiftKey) deselect();
          return;
        }
        if (document.pointerLockElement !== canvas) { canvas.requestPointerLock(); return; }
        if (rightBtn) { const held = heldItem(); if (held) { const fp = floorPoint(new THREE.Vector2(0, 0)); if (fp) placeItem(held, fp); } return; }
        const p = pick(new THREE.Vector2(0, 0));
        if (p) { if (e.shiftKey) toggleSelect(p.kind, p.id); else selectItem(p.kind, p.id); } else if (!e.shiftKey) deselect();
        return;
      }
      camGoal = null;
      try { canvas.setPointerCapture(e.pointerId); } catch (x) {}
      lastX = downX = e.clientX; lastY = downY = e.clientY; dragMoved = false;
      multiTouch = false;
      clearLongPress();
      if (e.pointerType === 'touch' && !rightBtn) {
        lpDown = { x: e.clientX, y: e.clientY, at: performance.now() };
        lpTimer = setTimeout(function () {
          lpTimer = null;
          if (!active || multiTouch || dragMoved || !lpDown) return;
          if (selection.length !== 1 || !selectedId) return;
          dragId = null; dragObj = null; dragKind = null; dragGroup = null; dragAnchor = null; orbiting = false; placeCandidate = false;
          if (openBookFor(selectedKind, selectedId)) announce('Editor opened for ' + selectionName(selectedKind, selectedId));
        }, LONG_PRESS_MS);
      }
      if (rightBtn) {
        if (heldItem()) { placeCandidate = true; orbiting = true; dragId = null; dragObj = null; dragKind = null; return; }
        orbiting = true; dragId = null; dragObj = null; dragKind = null; return;
      }
      const p = pick(ndcFrom(e));
      if (p) {
        if (e.shiftKey) { toggleSelect(p.kind, p.id); orbiting = false; dragId = null; dragObj = null; dragKind = null; return; }
        const inSet = selIndexOf(selection, p.kind, p.id) >= 0 && selection.length > 1;
        if (!inSet) selectItem(p.kind, p.id);
        if (moveArmed) {
          dragId = p.id; dragKind = p.kind; dragObj = p.obj;
          dragGroup = inSet ? beginGroupDrag(p.kind, p.id) : null;
          if (dragGroup) { dragAnchor = floorPoint(ndcFrom(e)); if (!dragAnchor) { dragGroup = null; } }
        } else orbiting = true;
      } else {
        dragId = null; dragObj = null; dragKind = null; dragGroup = null;
        if (e.shiftKey) { marqStart = floorPoint(ndcFrom(e)); marqScreen = { x: e.clientX, y: e.clientY }; marqEnd = marqStart; orbiting = !marqStart; }
        else { orbiting = true; deselect(); }
      }
    });
    canvas.addEventListener('pointermove', (e) => {
      if (ptrs.has(e.pointerId)) ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (ptrs.size >= 2) { if (ptrs.size === 2) updateGesture(); return; }
      if (multiTouch) return;
      if (mode === 'walk') {
        if (freeLook) { if (lookDragging) { walkYaw -= (e.clientX - lastX) * 0.0045; walkPitch = clamp(walkPitch - (e.clientY - lastY) * 0.0045, -1.4, 1.4); lastX = e.clientX; lastY = e.clientY; } }
        else if (document.pointerLockElement === canvas) { walkYaw -= e.movementX * 0.0026; walkPitch = clamp(walkPitch - e.movementY * 0.0026, -1.4, 1.4); }
        return;
      }
      if (lpDown && touchDist(lpDown, { x: e.clientX, y: e.clientY }) > TOUCH_SLOP) clearLongPress();
      if (Math.abs(e.clientX - downX) + Math.abs(e.clientY - downY) > 4) { dragMoved = true; placeCandidate = false; }
      if (marqStart) { const fp = floorPoint(ndcFrom(e)); if (fp) marqEnd = fp; drawMarquee(e.clientX, e.clientY); return; }
      if (dragGroup && dragAnchor) {
        const fp = floorPoint(ndcFrom(e));
        if (fp) moveGroupBy(fp.x - dragAnchor.x, fp.z - dragAnchor.z);
      } else if (dragId && dragKind !== 'edge') {
        const fp = floorPoint(ndcFrom(e));
        if (fp && dragObj) { dragObj.position.x = fp.x; dragObj.position.z = fp.z; applySelectionHalosUpdate(); }
      } else if (orbiting || dragKind === 'edge') {
        theta -= (e.clientX - lastX) * 0.005; phi = clamp(phi - (e.clientY - lastY) * 0.005, 0.08, Math.PI * 0.49); lastX = e.clientX; lastY = e.clientY;
      }
    });
    canvas.addEventListener('pointerup', (e) => {
      try { canvas.releasePointerCapture(e.pointerId); } catch (x) {}
      ptrs.delete(e.pointerId);
      clearLongPress();
      lookDragging = false;
      if (gestStart) endGesture();
      if (multiTouch) {
        if (ptrs.size === 0) multiTouch = false;
        placeCandidate = false; dragId = null; dragObj = null; dragKind = null; dragGroup = null; dragAnchor = null; orbiting = false;
        return;
      }
      if (marqStart) { finishMarquee(); placeCandidate = false; dragId = null; dragObj = null; dragKind = null; dragGroup = null; dragAnchor = null; orbiting = false; return; }
      if (placeCandidate && !dragMoved) { const held = heldItem(); if (held) { const fp = floorPoint(ndcFrom(e)); if (fp) placeItem(held, fp); } }
      else if (dragGroup) { if (dragMoved) commitDrag(null); else dragGroup = null; }
      else if (dragId) { if (dragMoved && dragKind !== 'edge') commitDrag(dragKind === 'node' ? rackUnderPointer(ndcFrom(e), dragId) : null); else selectItem(dragKind, dragId); }
      placeCandidate = false; dragId = null; dragObj = null; dragKind = null; dragGroup = null; dragAnchor = null; orbiting = false;
      flushConflictRebuild();
    });
    canvas.addEventListener('pointercancel', (e) => {
      try { canvas.releasePointerCapture(e.pointerId); } catch (x) {}
      ptrs.delete(e.pointerId);
      clearLongPress();
      lookDragging = false;
      if (gestStart) endGesture();
      if (ptrs.size === 0) multiTouch = false;
      const wasDragging = !!(dragId || dragGroup);
      hideMarquee();
      placeCandidate = false; dragId = null; dragObj = null; dragKind = null; dragGroup = null; dragAnchor = null; orbiting = false; dragMoved = false;
      if (wasDragging && active) buildScene();
      flushConflictRebuild();
    });
    canvas.addEventListener('wheel', (e) => {
      if (mode === 'walk') { e.preventDefault(); cycleHotbar(Math.sign(e.deltaY)); return; }
      if (mode === 'orbit') { e.preventDefault(); camGoal = null; radius = clamp(radius * (1 + Math.sign(e.deltaY) * 0.08), 120, 12000); }
    }, { passive: false });
    canvas.addEventListener('dblclick', (e) => {
      if (mode !== 'orbit') return;
      const p = pick(ndcFrom(e)); if (!p || !p.obj) return;
      const c = new THREE.Vector3(); p.obj.getWorldPosition(c);
      camGoal = { tx: c.x, ty: c.y + 40, tz: c.z, radius: clamp(radius, 300, 1100), theta: theta, phi: phi };
    });
    window.addEventListener('keydown', onKey, true); window.addEventListener('keyup', onKey, true);
    document.addEventListener('pointerlockchange', () => { if (!freeLook && mode === 'walk' && document.pointerLockElement !== canvas) setMode('orbit'); });
  }
  function onKey(e) {
    if (!active) return;
    const tgt = e.target;
    const inBook = !!(bookEl && bookEl.style.display === 'flex');
    if (tgt) {
      const tn = tgt.tagName;
      if (tn === 'INPUT' || tn === 'TEXTAREA' || tgt.isContentEditable) return;
      if (tn === 'SELECT') { e.stopPropagation(); if (inBook) onBookKey(e); return; }
      if (tn === 'BUTTON' || tn === 'SUMMARY' || tn === 'A' || (tgt.getAttribute && tgt.getAttribute('role') === 'button')) {
        if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar' || e.key === 'Tab') { e.stopPropagation(); if (inBook) onBookKey(e); return; }
      }
    }
    if (inBook) {
      e.stopPropagation();
      if (e.type === 'keydown' && e.key === 'Escape') { e.preventDefault(); closeBook(); }
      else onBookKey(e);
      return;
    }
    e.stopPropagation();
    if (e.type === 'keydown' && (e.key === 'a' || e.key === 'A') && (e.ctrlKey || e.metaKey)) {
      e.preventDefault(); selectAllPickables(); return;
    }
    if (e.type === 'keydown' && e.key === 'Escape') {
      if (marqStart) { hideMarquee(); e.preventDefault(); return; }
      if (selection.length) { deselect(); e.preventDefault(); return; }
      closeBook(); e.preventDefault(); return;
    }
    if (e.type === 'keydown' && (e.key === 'Delete' || e.key === 'Backspace')) {
      e.preventDefault();
      if (selection.length > 1) {
        if (!keyDelArmed || Date.now() - keyDelArmed > 2500) { keyDelArmed = Date.now(); guardToast('⚠ Press Delete again to remove ' + selection.length + ' objects.'); return; }
        keyDelArmed = 0; deleteSelection(); return;
      }
      keyDelArmed = 0;
      if (sceneReady && selectedKind === 'furniture' && selectedId) deleteFurnIn3D(selectedId);
      else if (selectedId && (selectedKind === 'rect' || selectedKind === 'text' || selectedKind === 'image')) deletePrimIn3D(selectedKind, selectedId);
      else if (selectedId && selectedKind === 'edge') deleteEdgeIn3D(selectedId);
      return;
    }
    if (e.type === 'keydown' && (e.key === 'ArrowLeft' || e.key === 'ArrowRight' || e.key === 'ArrowUp' || e.key === 'ArrowDown')) {
      e.preventDefault(); camGoal = null;
      const step = e.shiftKey ? 0.02 : 0.08;
      if (mode === 'walk') {
        if (e.key === 'ArrowLeft') walkYaw += step; else if (e.key === 'ArrowRight') walkYaw -= step;
        else walkPitch = clamp(walkPitch + (e.key === 'ArrowUp' ? step : -step), -1.4, 1.4);
      } else {
        if (e.key === 'ArrowLeft') theta += step; else if (e.key === 'ArrowRight') theta -= step;
        else phi = clamp(phi + (e.key === 'ArrowUp' ? -step : step), 0.08, Math.PI * 0.49);
      }
      return;
    }
    if (e.type === 'keydown' && (e.key === '+' || e.key === '=' || e.key === '-' || e.key === '_' || e.code === 'NumpadAdd' || e.code === 'NumpadSubtract')) {
      e.preventDefault(); camGoal = null;
      const inToward = (e.key === '+' || e.key === '=' || e.code === 'NumpadAdd');
      radius = clamp(radius * (inToward ? 0.92 : 1.08), 120, 12000);
      return;
    }
    if (e.type === 'keydown' && e.key === 'Tab') {
      e.preventDefault();
      const items = pickableItems(false);
      if (!items.length) { announce('Nothing to select in this scene'); return; }
      let cur = -1;
      for (let i = 0; i < items.length; i++) if (items[i].kind === selectedKind && items[i].id === selectedId) { cur = i; break; }
      const nx = focusTrapNext(items.length, cur, e.shiftKey);
      const it = items[nx];
      if (it) { selectItem(it.kind, it.id); announce('Item ' + (nx + 1) + ' of ' + items.length); }
      return;
    }
    if (e.type === 'keydown' && e.key === 'Enter') {
      e.preventDefault();
      if (selection.length === 1 && selectedId != null) { if (!openBookFor(selectedKind, selectedId)) announce('This object cannot be edited here'); }
      else if (selection.length > 1) announce('Select a single object to open its editor');
      else announce('Nothing selected');
      return;
    }
    if (e.type === 'keydown') {
      if (e.key === 'e' || e.key === 'E' || e.key === 'i' || e.key === 'I') { toggleInventory(); e.preventDefault(); return; }
      if (e.key === 'q' || e.key === 'Q') { dropHeld(); e.preventDefault(); return; }
      if (e.key === 'l' || e.key === 'L') { toggleHud(); e.preventDefault(); return; }
      if (e.key === 'r' || e.key === 'R') { toggleRecPanel(); e.preventDefault(); return; }
      if (e.key === 'm' || e.key === 'M') { toggleMove(); e.preventDefault(); return; }
      if (e.key >= '1' && e.key <= '9') { selectHotbar((+e.key) - 1); e.preventDefault(); return; }
    }
    const k = e.key.toLowerCase();
    if ('wasd'.indexOf(k) !== -1) { keys[k] = e.type === 'keydown'; if (active) e.preventDefault(); }
    if (e.key === ' ' || e.code === 'Space') {
      const down = e.type === 'keydown';
      if (active) e.preventDefault();
      if (down && !keys[' ']) {
        const now = performance.now();
        if (now - lastSpaceAt < DOUBLE_TAP_MS) { walkFlying = !walkFlying; walkVelY = 0; lastSpaceAt = 0; guardToast(walkFlying ? '✈️ Flying, double tap Space to walk' : '🚶 Walking, double tap Space to fly'); }
        else { lastSpaceAt = now; if (mode === 'walk' && !walkFlying && walkFly <= 0) walkVelY = JUMP_SPEED; }
      }
      keys[' '] = down;
    }
    keys['shift'] = !!e.shiftKey;
    keys['ctrl'] = !!e.ctrlKey;
  }

  function resize() {
    if (!renderer || (renderer.xr && renderer.xr.isPresenting)) return;
    const w = overlay.clientWidth || window.innerWidth || 1280;
    const h = overlay.clientHeight || window.innerHeight || 720;
    if (w <= 0 || h <= 0) return;
    renderer.setSize(w, h, false); camera.aspect = w / h; camera.updateProjectionMatrix();
    if (composer) composer.setSize(w, h);
    if (recEl && recEl.style.display === 'block') placeRecPanel();
  }
  let gpPrevButtons = {};
  const padMove = { fwd: 0, rgt: 0, up: 0 };
  function pollGamepad(dt) {
    padMove.fwd = padMove.rgt = padMove.up = 0;
    if (!navigator.getGamepads) return;
    let gp = null; const pads = navigator.getGamepads();
    for (let i = 0; i < pads.length; i++) { if (pads[i] && pads[i].connected) { gp = pads[i]; break; } }
    if (!gp) return;
    const ax = gp.axes || [], dz = (v) => (Math.abs(v) < 0.16 ? 0 : v);
    const lx = dz(ax[0] || 0), ly = dz(ax[1] || 0), rx = dz(ax[2] || 0), ry = dz(ax[3] || 0);
    const btn = (i) => !!(gp.buttons[i] && gp.buttons[i].pressed);
    const val = (i) => (gp.buttons[i] ? gp.buttons[i].value || (gp.buttons[i].pressed ? 1 : 0) : 0);
    const edge = (i) => { const p = btn(i); const was = gpPrevButtons[i]; gpPrevButtons[i] = p; return p && !was; };
    if (lx || ly || rx || ry) camGoal = null;
    const fwd = -ly, rgt = lx, lt = val(6), rt = val(7);
    const d = num(dt, 1 / 60);
    if (mode === 'walk') {
      padMove.fwd = fwd; padMove.rgt = rgt;
      padMove.up = (Math.abs(rt) > 0.1 || Math.abs(lt) > 0.1) ? clamp(rt - lt, -1, 1) : 0;
      walkYaw -= rx * 3.0 * d; walkPitch = clamp(walkPitch - ry * 2.7 * d, -1.4, 1.4);
    } else {
      const s = radius * 1.2 * d, fX = Math.sin(theta), fZ = Math.cos(theta), rX = Math.cos(theta), rZ = -Math.sin(theta);
      target.x += (-fwd * fX + rgt * rX) * s; target.z += (-fwd * fZ + rgt * rZ) * s;
      theta -= rx * 2.7 * d; phi = clamp(phi - ry * 1.8 * d, 0.08, Math.PI * 0.49);
      if (lt > 0.1 || rt > 0.1) { camGoal = null; radius = clamp(radius * (1 + (lt - rt) * 1.8 * d), 120, 12000); }
    }
    if (edge(0)) { const held = heldItem(), fp = floorPoint(new THREE.Vector2(0, 0)); if (held && fp) placeItem(held, fp); else { const p = pick(new THREE.Vector2(0, 0)); if (p) selectItem(p.kind, p.id, p.obj); else deselect(); } }
    if (edge(3)) toggleMode();
    if (edge(4)) selectHotbar((hotbarSel + HOTBAR_SLOTS - 1) % HOTBAR_SLOTS);
    if (edge(5)) selectHotbar((hotbarSel + 1) % HOTBAR_SLOTS);
    if (edge(2)) toggleInventory();
  }

  let xrBtn = null, xrSession = null;
  function initXRButton() {
    if (!xrBtn || !navigator.xr || !navigator.xr.isSessionSupported) return;
    navigator.xr.isSessionSupported('immersive-vr').then(function (ok) { if (xrBtn) xrBtn.style.display = ok ? '' : 'none'; }).catch(function () {});
  }
  let xrRequestPending = false;
  function toggleVR() {
    if (!navigator.xr || !renderer) return;
    if (xrSession) { try { xrSession.end(); } catch (e) {} return; }
    if (xrRequestPending) { if (statEl) statEl.textContent = 'VR: waiting for the headset to confirm. Put it on to continue.'; return; }
    xrRequestPending = true;
    if (statEl) statEl.textContent = 'VR: starting, put on the headset.';
    navigator.xr.requestSession('immersive-vr', { optionalFeatures: ['local-floor', 'bounded-floor'] })
      .then(function (session) {
        xrRequestPending = false;
        xrSession = session;
        session.addEventListener('end', onXRSessionEnd);
        renderer.xr.enabled = true;
        try { renderer.xr.setReferenceSpaceType('local-floor'); } catch (e) {}
        return renderer.xr.setSession(session);
      })
      .then(function () {
        if (xrBtn) xrBtn.textContent = '🥽 Exit VR';
        setupXRInput();
        xrOffset.x = xrOffset.y = xrOffset.z = 0;
        try { xrBaseRefSpace = renderer.xr.getReferenceSpace(); } catch (e) { xrBaseRefSpace = null; }
        if (scene) xrObjects.forEach(function (o) { scene.add(o); });
        buildScene(); recenterVR();
      })
      .catch(function (e) { xrRequestPending = false; xrSession = null; try { renderer.xr.enabled = false; } catch (x) {} if (statEl) statEl.textContent = 'VR unavailable: ' + (e && e.message || e); });
  }
  function onXRSessionEnd() {
    xrSession = null; try { renderer.xr.enabled = false; } catch (e) {}
    xrObjects.forEach(function (o) { if (o.parent) o.parent.remove(o); });
    teleporting[0] = teleporting[1] = false; if (teleportMarker) teleportMarker.visible = false;
    if (xrBtn) xrBtn.textContent = '🥽 VR';
    if (active) { buildScene(); fitCamera(false); }
  }
  function recenterVR() {
    if (!renderer || !renderer.xr || !renderer.xr.isPresenting || !scene) return;
    scene.updateMatrixWorld(true);
    var box = new THREE.Box3(), any = false;
    scene.traverse(function (o) { if (o.userData && (o.userData.nodeId || o.userData.furnId)) { box.expandByObject(o); any = true; } });
    if (!any) return;
    var c = box.getCenter(new THREE.Vector3()), sz = box.getSize(new THREE.Vector3());
    var back = Math.max(1.2, Math.min(8, Math.max(sz.x, sz.z) * 0.6 + 1));
    xrOffset.x = -c.x; xrOffset.z = -(c.z + back); xrOffset.y = 0; applyXROffset();
  }

  const xrControllers = [], xrGrips = [], xrHands = [], xrObjects = [];
  let xrInputReady = false, xrBaseRefSpace = null; const xrOffset = { x: 0, y: 0, z: 0 };
  const teleporting = [false, false]; let teleportMarker = null;
  let _handDotGeo = null, _handDotMat = null;
  function makeHandModel(handedness) {
    const g = new THREE.Group();
    const skin = new THREE.MeshStandardMaterial({ color: 0xe8b48c, roughness: 0.85, metalness: 0.0 });
    const palm = new THREE.Mesh(new THREE.BoxGeometry(0.085, 0.032, 0.10), skin); palm.position.set(0, 0, 0.015); g.add(palm);
    const knuck = new THREE.Mesh(new THREE.BoxGeometry(0.085, 0.03, 0.028), skin); knuck.position.set(0, 0.001, -0.05); g.add(knuck);
    for (let k = 0; k < 4; k++) {
      const fg = new THREE.Group();
      const p1 = new THREE.Mesh(new THREE.BoxGeometry(0.018, 0.02, 0.05), skin); p1.position.z = -0.03; fg.add(p1);
      const p2 = new THREE.Mesh(new THREE.BoxGeometry(0.017, 0.019, 0.042), skin); p2.position.set(0, -0.018, -0.066); p2.rotation.x = -0.85; fg.add(p2);
      fg.position.set(-0.031 + k * 0.021, 0.004, -0.06); g.add(fg);
    }
    const th = new THREE.Group();
    const t1 = new THREE.Mesh(new THREE.BoxGeometry(0.022, 0.022, 0.05), skin); t1.position.z = -0.022; th.add(t1);
    th.position.set(0.05, 0.006, 0.012); th.rotation.set(0.25, 0.7, 0); g.add(th);
    if (handedness === 'left') g.scale.x = -1;
    return g;
  }
  function attachHandModel(idx, handedness) {
    const grip = xrGrips[idx]; if (!grip || grip.userData.handModel) return;
    const hand = handedness === 'left' ? 'left' : 'right';
    const hm = makeHandModel(hand); grip.add(hm); grip.userData.handModel = hm; grip.userData.hand = hand;
    loadHandGLB(hand, grip);
  }
  let _gltfLoaderP = null;
  function getGLTFLoader() { if (!_gltfLoaderP) _gltfLoaderP = import('/vendor/three/addons/loaders/GLTFLoader.js').then(function (m) { return new m.GLTFLoader(); }); return _gltfLoaderP; }
  const HAND_GLB = { left: 'https://cdn.jsdelivr.net/npm/@webxr-input-profiles/assets@1.0/dist/profiles/generic-hand/left.glb', right: 'https://cdn.jsdelivr.net/npm/@webxr-input-profiles/assets@1.0/dist/profiles/generic-hand/right.glb' };
  function loadHandGLB(hand, grip) {
    getGLTFLoader().then(function (loader) {
      loader.load(HAND_GLB[hand] || HAND_GLB.right, function (gltf) {
        if (!grip || grip.userData.hand !== hand || grip.userData.handIsGLB) return;
        const model = gltf.scene; model.traverse(function (o) { if (o.isMesh) o.frustumCulled = false; });
        const old = grip.userData.handModel; if (old) { grip.remove(old); disposeObject3D(old); }
        grip.add(model); grip.userData.handModel = model; grip.userData.handIsGLB = true;
      }, undefined, function () {  });
    }).catch(function () {  });
  }
  function detachHandModel(idx) {
    const grip = xrGrips[idx]; if (!grip || !grip.userData.handModel) return;
    grip.remove(grip.userData.handModel); disposeObject3D(grip.userData.handModel);
    grip.userData.handModel = null; grip.userData.hand = null; grip.userData.handIsGLB = false;
  }
  function setupXRInput() {
    if (xrInputReady || !renderer) return; xrInputReady = true;
    _handDotGeo = new THREE.SphereGeometry(0.008, 6, 6); _handDotMat = new THREE.MeshStandardMaterial({ color: 0xffe0bd, roughness: 0.7 });
    for (let i = 0; i < 2; i++) {
      const ctrl = renderer.xr.getController(i); ctrl.userData.idx = i;
      ctrl.addEventListener('selectstart', function () { onXRSelect(ctrl); });
      ctrl.addEventListener('squeezestart', function () { teleporting[ctrl.userData.idx] = true; });
      ctrl.addEventListener('squeezeend', function () { endTeleport(ctrl); });
      ctrl.addEventListener('connected', function (e) { ctrl.userData.src = e.data; attachHandModel(ctrl.userData.idx, e.data && e.data.handedness); });
      ctrl.addEventListener('disconnected', function () { ctrl.userData.src = null; detachHandModel(ctrl.userData.idx); });
      const ray = new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0, 0, 0), new THREE.Vector3(0, 0, -1)]), new THREE.LineBasicMaterial({ color: 0x4fd1c5 }));
      ray.scale.z = 60; ray.name = 'ray'; ctrl.add(ray); xrControllers.push(ctrl); xrObjects.push(ctrl);
      const grip = renderer.xr.getControllerGrip(i); xrGrips.push(grip); xrObjects.push(grip);
      const hand = renderer.xr.getHand(i); xrHands.push(hand); xrObjects.push(hand);
    }
    teleportMarker = new THREE.Mesh(new THREE.RingGeometry(0.3, 0.5, 24), new THREE.MeshBasicMaterial({ color: 0x4fd1c5, transparent: true, opacity: 0.8, side: THREE.DoubleSide }));
    teleportMarker.rotation.x = -Math.PI / 2; teleportMarker.visible = false; xrObjects.push(teleportMarker);
  }
  function ensureHandJoints(hand) {
    if (!hand || !hand.joints) return;
    for (const name in hand.joints) { const j = hand.joints[name]; if (j && !j.userData.__dot) { j.userData.__dot = true; j.add(new THREE.Mesh(_handDotGeo, _handDotMat)); } }
  }
  function xrRaycast(ctrl) {
    const m = new THREE.Matrix4().extractRotation(ctrl.matrixWorld);
    raycaster.ray.origin.setFromMatrixPosition(ctrl.matrixWorld);
    raycaster.ray.direction.set(0, 0, -1).applyMatrix4(m).normalize();
    let picked = null; const hits = raycaster.intersectObjects(pickables, true);
    if (hits.length) {
      let o = hits[0].object;
      while (o && !(o.userData && (o.userData.nodeId || o.userData.furnId || o.userData.rectId || o.userData.textId || o.userData.imageId || o.userData.edgeId))) o = o.parent;
      if (o) {
        const u = o.userData;
        if (u.furnId) picked = { kind: 'furniture', id: u.furnId, obj: o };
        else if (u.rectId) picked = { kind: 'rect', id: u.rectId, obj: o };
        else if (u.textId) picked = { kind: 'text', id: u.textId, obj: o };
        else if (u.imageId) picked = { kind: 'image', id: u.imageId, obj: o };
        else if (u.edgeId) picked = { kind: 'edge', id: u.edgeId, obj: o };
        else picked = { kind: 'node', id: u.nodeId, obj: o };
      }
    }
    const fp = new THREE.Vector3(); const floor = raycaster.ray.intersectPlane(planeY0, fp) ? fp : null;
    return { hit: picked, floor: floor };
  }
  function vrScale() { return (renderer && renderer.xr && renderer.xr.isPresenting) ? (scene3d.mpu > 0 ? scene3d.mpu : VR_DEFAULT_SCALE) : 1; }
  function onXRSelect(ctrl) {
    const r = xrRaycast(ctrl); const held = heldItem();
    if (held && r.floor) { const k = vrScale(); placeItem(held, { x: r.floor.x / k, z: r.floor.z / k }); return; }
    if (r.hit) selectItem(r.hit.kind, r.hit.id, r.hit.obj); else deselect();
  }
  function endTeleport(ctrl) {
    const i = ctrl.userData.idx; if (!teleporting[i]) return; teleporting[i] = false;
    if (teleportMarker) teleportMarker.visible = false;
    const r = xrRaycast(ctrl); if (r.floor) teleportTo(r.floor);
  }
  function applyXROffset() { if (!xrBaseRefSpace || typeof XRRigidTransform === 'undefined') return; try { renderer.xr.setReferenceSpace(xrBaseRefSpace.getOffsetReferenceSpace(new XRRigidTransform({ x: xrOffset.x, y: xrOffset.y, z: xrOffset.z }))); } catch (e) {} }
  function teleportTo(p) { xrOffset.x = -p.x; xrOffset.z = -p.z; applyXROffset(); }
  const XR_MOVE_MPS = 3;
  let xrLocoLastT = 0;
  function xrSmoothLocomotion() {
    const nowT = performance.now();
    const dt = xrLocoLastT ? Math.min(0.1, (nowT - xrLocoLastT) / 1000) : 0;
    xrLocoLastT = nowT;
    let mx = 0, mz = 0;
    for (let i = 0; i < xrControllers.length; i++) { const src = xrControllers[i].userData.src; const ax = src && src.gamepad && src.gamepad.axes; if (!ax) continue; const sx2 = ax[2] != null ? ax[2] : (ax[0] || 0), sy2 = ax[3] != null ? ax[3] : (ax[1] || 0); if (Math.abs(sx2) > 0.2) mx += sx2; if (Math.abs(sy2) > 0.2) mz += sy2; }
    mx = Math.max(-1, Math.min(1, mx)); mz = Math.max(-1, Math.min(1, mz));
    if ((!mx && !mz) || !dt) return;
    const cam = renderer.xr.getCamera(); const dir = new THREE.Vector3(); cam.getWorldDirection(dir); dir.y = 0; if (dir.lengthSq() < 1e-6) return; dir.normalize();
    const right = new THREE.Vector3(-dir.z, 0, dir.x), speed = XR_MOVE_MPS * dt;
    const dx = (dir.x * (-mz) + right.x * mx) * speed, dz = (dir.z * (-mz) + right.z * mx) * speed;
    xrOffset.x -= dx; xrOffset.z -= dz; applyXROffset();
  }
  function updateXR() {
    for (let i = 0; i < xrHands.length; i++) ensureHandJoints(xrHands[i]);
    let show = false;
    for (let i = 0; i < xrControllers.length; i++) { if (teleporting[i]) { const r = xrRaycast(xrControllers[i]); if (r.floor && teleportMarker) { teleportMarker.position.set(r.floor.x, 0.05, r.floor.z); show = true; } } }
    if (teleportMarker) teleportMarker.visible = show;
    xrSmoothLocomotion();
  }

  const VR_DEFAULT_SCALE = 0.01;
  function applyVRWorldScale() {
    if (!renderer || !renderer.xr || !renderer.xr.isPresenting || !scene) return;
    const K = scene3d.mpu > 0 ? scene3d.mpu : VR_DEFAULT_SCALE;
    const world = new THREE.Group(); world.name = '__vrworld'; world.scale.setScalar(K);
    scene.children.slice().forEach(function (c) {
      if (c === world || c.isLight || xrObjects.indexOf(c) !== -1) return;
      world.add(c);
    });
    scene.add(world);
  }

  let composer = null, bloomPass = null, renderPass = null, _envTex = null;
  function initPostFX() {
    if (!renderer) return;
    if (!_envTex) {
      import('/vendor/three/addons/environments/RoomEnvironment.js').then(function (m) {
        try { const pg = new THREE.PMREMGenerator(renderer); _envTex = pg.fromScene(new m.RoomEnvironment(), 0.04).texture; pg.dispose(); if (active && scene) { scene.environment = _envTex; scene.environmentIntensity = LIGHT.env; } } catch (e) {}
      }).catch(function () {});
    }
    if (!composer) {
      Promise.all([
        import('/vendor/three/addons/postprocessing/EffectComposer.js'),
        import('/vendor/three/addons/postprocessing/RenderPass.js'),
        import('/vendor/three/addons/postprocessing/UnrealBloomPass.js'),
        import('/vendor/three/addons/postprocessing/OutputPass.js')
      ]).then(function (mods) {
        try {
          const w = (overlay && overlay.clientWidth) || 1280, h = (overlay && overlay.clientHeight) || 720;
          const c = new mods[0].EffectComposer(renderer);
          renderPass = new mods[1].RenderPass(scene, camera); c.addPass(renderPass);
          bloomPass = new mods[2].UnrealBloomPass(new THREE.Vector2(w, h), LIGHT.bloomStrength, LIGHT.bloomRadius, LIGHT.bloomThreshold); c.addPass(bloomPass);
          c.addPass(new mods[3].OutputPass()); c.setSize(w, h);
          composer = c;
          applyLook();
        } catch (e) { composer = null; }
      }).catch(function () { composer = null; });
    }
  }

  function loop() {
    if (!active) return;
    frame++;
    const now = performance.now();
    const dt = Math.min(0.05, Math.max(0.001, (now - (lastFrameAt || now - 16)) / 1000));
    lastFrameAt = now;
    const inXR = !!(renderer.xr && renderer.xr.isPresenting);
    if (!inXR) { pollGamepad(dt); applyKeys(dt); stepCameraGoal(); (mode === 'walk' ? updateCameraWalk : updateCameraOrbit)(); }
    else updateXR();
    const rsNow = recState(), playing = !!(rsNow && rsNow.isPlaying);
    if (playing !== wasPlaying) { wasPlaying = playing; trailDirty = true; if (!playing) { disposeTrailLayer(); followPending = true; } }
    if ((playing || followPending) && !dragId) {
      const forced = followPending; followPending = false;
      if (playbackFollow(forced) && playing) followHoldUntil = now + 450;
    }
    if (recEl && recEl.style.display === 'block' && now - lastRecSyncAt > 180) { lastRecSyncAt = now; syncRecPanel(); }
    updateAnimations(now);
    updateAvatars();
    sendPose(now);
    if (now - lastTopoCheckAt > 500 && !dragId && now >= followHoldUntil) {
      lastTopoCheckAt = now;
      flushConflictRebuild();

      const sig = topoSig();
      if (lastTopoSig !== null && sig !== lastTopoSig) buildScene();
      else if (lastTopoSig === null) lastTopoSig = sig;
    }
    if (!inXR && fxOn && composer) { try { composer.render(); } catch (e) { renderer.render(scene, camera); } }
    else renderer.render(scene, camera);
  }
  let _prevSuppressWelcome = false;
  function enter3D() {
    if (active) return;
    if (!overlay) makeOverlay();
    overlay.style.display = 'block'; active = true;
    _prevSuppressWelcome = window.__collabSuppressWelcome;
    window.__collabSuppressWelcome = true;
    { const wm = document.getElementById('welcome-modal'); if (wm) wm.classList.remove('active'); }
    if (!renderer) {
      try { renderer = new THREE.WebGLRenderer({ canvas, antialias: true }); }
      catch (e) {
        renderer = null; overlay.style.display = 'none'; active = false;
        window.__collabSuppressWelcome = _prevSuppressWelcome;
        try { alert('3D view needs WebGL, which is unavailable in this browser.'); } catch (x) {}
        return;
      }
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75));
      if (THREE.ACESFilmicToneMapping !== undefined) renderer.toneMapping = THREE.ACESFilmicToneMapping;
      renderer.toneMappingExposure = LIGHT.exposure;
      camera = new THREE.PerspectiveCamera(60, 1, 1, 40000);
      bindControls(); window.addEventListener('resize', resize);
      window.addEventListener('pagehide', function () { flushSave(true); });
      document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'hidden') flushSave(false); });
    }
    window.__collab3dOnMessage = onNetMessage;
    for (const id in avatars) { if (scene) scene.remove(avatars[id].grp); disposeObject3D(avatars[id].grp); delete avatars[id]; }
    mode = 'orbit'; hotbarSel = HOTBAR_SLOTS - 1; renderHotbar(); sceneReady = false; pendingFurnOps.length = 0; camGoal = null; gpPrevButtons = {}; if (modeBtn) modeBtn.textContent = '🚶 Walk';
    cancelSaveRetry(); clearSaveError(); saveInFlight = false; saveDirtyDuringFlight = false; pendingCarrier = null;
    cancelReconcile(); dirtyTabs.clear(); clearLocalOps(); reloadRequired = false; pendingConflictRebuild = false; pendingPeerRebuild = false; sceneRev = 0;
    selection = []; selHalos.length = 0; selBox = null; selectedId = null; selectedKind = null; _presenceSig = null;
    for (const k in tabRevs) delete tabRevs[k];
    { const cp = document.getElementById('threed-carrier-prompt'); if (cp) cp.remove(); }
    clearLongPress(); endGesture(); ptrs.clear(); multiTouch = false; lookDragging = false; _rmStatic = false;
    clearFurnOpRetries();
    window.addEventListener('collab:furnop-dropped', onFurnOpDropped);
    buildScene(); fitCamera(false); resize(); renderer.setAnimationLoop(loop);
    try { canvas.focus({ preventScroll: true }); } catch (e) { try { canvas.focus(); } catch (x) {} }
    announce(COARSE_POINTER
      ? '3D view opened in touch viewer mode. One finger orbits, two fingers pinch to zoom or drag to pan, tap selects, press and hold opens the editor.'
      : '3D view opened. Arrow keys orbit, plus and minus zoom, Tab cycles the selection, Enter opens its editor, Escape clears it.');
    initXRButton();
    initPostFX();
    loadScene3d(function () { if (active) buildScene(); });
  }
  function exit3D() {
    flushSave(false);
    active = false; if (renderer) renderer.setAnimationLoop(null); rafId = null;
    window.__collabSuppressWelcome = _prevSuppressWelcome;
    if (xrSession) { try { xrSession.end(); } catch (e) {} }
    if (document.pointerLockElement === canvas) document.exitPointerLock();
    clearLongPress(); endGesture(); ptrs.clear(); multiTouch = false; lookDragging = false;
    window.removeEventListener('collab:furnop-dropped', onFurnOpDropped);
    clearFurnOpRetries();
    closeBook();
    hideMarquee(); dragGroup = null; dragAnchor = null; keyDelArmed = 0;
    dragId = null; dragObj = null; dragKind = null; dragMoved = false; orbiting = false; placeCandidate = false;
    pendingPeerRebuild = false; pendingConflictRebuild = false;
    setSelection([]);
    window.__collab3dOnMessage = null;
    if (overlay) overlay.style.display = 'none';
    cancelAnnounce();
    try { const b = document.getElementById('enter-3d-btn'); if (b) b.focus(); } catch (e) {}
    for (const k in keys) keys[k] = false;
    for (const id in avatars) { if (scene) scene.remove(avatars[id].grp); disposeObject3D(avatars[id].grp); delete avatars[id]; }
    followReset(); wasPlaying = false; followPending = false; followHoldUntil = 0; trailDirty = true;
    disposeWireLayer();
    clearImgTexCache();
    clearIconTexCache();
    clearModelCache();
    clearEmblemCache();
  }

  window.__collab3dInfo = function () {
    const f0 = anims.fov[0], m0 = anims.flow[0] && anims.flow[0].markers[0];
    return {
      active: active, mode: mode, selectedId: selectedId, selectedKind: selectedKind,
      selection: selection.map(function (s) { return { kind: s.kind, id: s.id }; }),
      selectionCounts: selCounts(selection),
      halos: (selBox ? 1 : 0) + selHalos.length,
      dragging: !!(dragId || dragGroup), dragGroup: dragGroup ? dragGroup.length : 0,
      marquee: !!marqStart,
      pendingPeerRebuild: pendingPeerRebuild,
      wireCache: { entries: Object.keys(wireCache).length, rebuilt: wireStats.rebuilt, reused: wireStats.reused, removed: wireStats.removed },
      avatars: Object.keys(avatars).length, pickables: pickables.length,
      a11y: {
        coarsePointer: COARSE_POINTER, touchViewer: COARSE_POINTER,
        reduceMotion: reduceMotion(), rmOverride: rmOverride, rmMedia: rmMediaMatches, rmStatic: _rmStatic,
        freeLook: freeLook, pointerLocked: document.pointerLockElement === canvas,
        activePointers: ptrs.size, gesture: gestKind, multiTouch: multiTouch,
        canvasFocusable: !!(canvas && canvas.tabIndex >= 0),
        liveRegion: !!srEl, srText: srEl ? srEl.textContent : null,
        bookModal: !!(bookEl && bookEl.getAttribute('aria-modal') === 'true'),
        bookFocusables: (bookEl && bookEl.style.display === 'flex') ? bookFocusables().length : 0,
      },
      avatarShapes: (function () { const m = {}; for (const id in avatars) { const s = avatars[id].grp.userData.avatarShape || '?'; m[s] = (m[s] || 0) + 1; } return { byShape: m, distinct: Object.keys(m).length }; })(),
      sceneChildren: scene ? scene.children.length : 0,
      sceneObjects: (function () { let n = 0; if (scene) scene.traverse(function () { n++; }); return n; })(),
      inspectVisible: inspectEl ? inspectEl.style.display === 'block' : false,
      tabKey: tabKey(),
      sceneTabs: Object.keys(scene3d.tabs).map(function (k) {
        const b = scene3d.tabs[k];
        return { key: k, rev: tabRev(k), dirty: dirtyTabs.has(k), furniture: b.furniture.length, heights: Object.keys(b.heights).length, buried: Object.keys(b.buried).length, wallHeights: Object.keys(b.wallHeights).length };
      }),
      sceneRev: sceneRev, reloadRequired: reloadRequired, reconcilePending: !!reconcileTimer,
      saveRetries: saveRetryAt, pendingCarrier: pendingCarrier,
      fxOn: fxOn, wireMode: scene3d.wireMode,
      devModels: { on: devModelsOn, built: _devModelCount, merger: !!_bguMod },
      emblems: { on: icon3dOn, built: _emblemCount, fellBackToSprite: _emblemFallback, cached: Object.keys(emblemGeoCache).length, mats: Object.keys(emblemMatCache).length, loader: !!_svgMod },
      cam: { tx: Math.round(target.x), tz: Math.round(target.z), theta: +theta.toFixed(3), radius: Math.round(radius), wx: Math.round(walkPos.x), wz: Math.round(walkPos.z) },
      xrButtonShown: !!(xrBtn && xrBtn.style.display !== 'none'), xrPresenting: !!(renderer && renderer.xr && renderer.xr.isPresenting), xrOffset: { x: Math.round(xrOffset.x * 100) / 100, y: Math.round(xrOffset.y * 100) / 100, z: Math.round(xrOffset.z * 100) / 100 }, xrTeleporting: teleporting.slice(), xrTeleportMarker: !!(teleportMarker && teleportMarker.visible), xrControllers: xrControllers.map(function (c) { return c.userData.src ? (c.userData.src.handedness || 'unknown') : null; }),
      postFX: { composer: !!composer, bloom: !!bloomPass, env: !!_envTex, sceneHasEnv: !!(scene && scene.environment) },
      controls: { moveArmed: moveArmed, flying: walkFlying, grounded: walkFly <= 0, walkY: Math.round(walkPos.y), velY: Math.round(walkVelY) },
      anims: { fov: anims.fov.length, flow: anims.flow.length, ping: anims.ping.length },
      fovRotY: f0 ? +f0.group.rotation.y.toFixed(4) : null,
      fovScale: f0 ? +f0.group.scale.x.toFixed(4) : null,
      flowPos: m0 ? m0.mesh.position.toArray().map((n) => Math.round(n)) : null,
      camAnimating: !!camGoal,
      bookOpen: !!(bookEl && bookEl.style.display === 'flex'),
      viewOnly: isViewOnly(), lastGuard: lastGuard,
      layers: { active: activeLayerList(), hidden: lastBuild.hidden, bridged: typeof getVar('isNodeVisible') === 'function' },
      groups: lastBuild.groups,
      recording: recInfo(),
      theme: theme,
      anim: { master: animSettings().masterAnim !== false, zones: animSettings().masterZones !== false, connections: connectionsAnimAllowed(), fov: lastBuild.fov },
      legendOpen: !!(hudEl && hudEl.style.display === 'block')
    };
  };
  window.__collab3dSetLayer = function (n, on) { try { hudSetLayer(n, on); return activeLayerList(); } catch (e) { return String(e && e.message || e); } };
  window.__collab3dLegend = function () { try { ensureHud(); return { edge: getVar('EDGE_LEGEND'), zone: getVar('ZONE_LEGEND') }; } catch (e) { return String(e && e.message || e); } };
  window.__collab3dOpenBook = function (kind, id) { try { return openBookFor(kind, id); } catch (e) { return String(e && e.message || e); } };
  window.__collab3dSelect = function (action, arg) {
    try {
      switch (action) {
        case 'set': setSelection(Array.isArray(arg) ? arg : []); break;
        case 'toggle': toggleSelect(arg && arg.kind, arg && arg.id); break;
        case 'all': selectAllPickables(); break;
        case 'clear': setSelection([]); break;
        case 'marquee': {
          const r = marqueeRect({ x: num(arg && arg.x0, 0), z: num(arg && arg.z0, 0) }, { x: num(arg && arg.x1, 0), z: num(arg && arg.z1, 0) });
          const v = new THREE.Vector3(), cands = [], items = pickableItems(true);
          for (let i = 0; i < items.length; i++) { items[i].obj.getWorldPosition(v); cands.push({ kind: items[i].kind, id: items[i].id, x: v.x, z: v.z }); }
          setSelection(selUnion(selection, marqueeHits(r, cands)));
          break;
        }
        case 'delete': deleteSelection(); break;
        case 'move': {
          const g = beginGroupDrag(selection.length ? selection[0].kind : null, selection.length ? selection[0].id : null);
          if (!g) return 'no group drag (need 2+ movable members, Move need not be armed here)';
          dragGroup = g; moveGroupBy(num(arg && arg.dx, 0), num(arg && arg.dz, 0)); commitGroupDrag();
          break;
        }
        default: return 'unknown action: ' + action;
      }
      return { selection: selection.map(function (s) { return { kind: s.kind, id: s.id }; }), halos: (selBox ? 1 : 0) + selHalos.length, counts: selCounts(selection) };
    } catch (e) { return String((e && e.message) || e); }
  };
  window.__collab3dLook = function (patch) {
    if (patch && typeof patch === 'object') { for (const k in patch) if (k in LIGHT && Number.isFinite(Number(patch[k]))) LIGHT[k] = Number(patch[k]); applyLook(); if (active) buildScene(); }
    return Object.assign({}, LIGHT);
  };
  window.__collab3dRec = function (action, arg) {
    try {
      switch (action) {
        case undefined: case null: case '': case 'info': break;
        case 'panel': toggleRecPanel(); break;
        case 'record': recToggleRecord(); break;
        case 'step': recToggleStep(); break;
        case 'frame': recCall('captureStepFrame'); syncRecPanel(); break;
        case 'play': recPlay(); break;
        case 'pause': recPause(); break;
        case 'stop': recStop(); break;
        case 'seek': recSeek(arg); break;
        case 'select': recSelect(String(arg)); syncRecPanel(); break;
        case 'speed': recSetSpeed(arg); break;
        case 'loop': recSetLoop(!!arg); break;
        case 'trails': recSetTrail(arg || {}, !!(arg && arg.motionTrailsEnabled === false), true); syncRecPanel(); break;
        case 'follow': followPending = false; if (active) playbackFollow(true); break;
        case 'traillayer': trailDirty = false; buildTrailLayer(); break;
        case 'where': { const f = followNodes.filter(function (x) { return x.id === String(arg); })[0], c = nodeCenters[String(arg)];
          return { id: String(arg), objs: f ? f.objs.length : 0,
            at: (f && f.objs[0] && f.objs[0].position) ? [Math.round(f.objs[0].position.x), Math.round(f.objs[0].position.z)] : null,
            centre: c ? [Math.round(c.x), Math.round(c.z)] : null,
            base: f ? [Math.round(f.bx), Math.round(f.bz)] : null }; }
        default: return 'unknown action: ' + action;
      }
      return recInfo();
    } catch (e) { return String((e && e.message) || e); }
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', makeButton);
  else makeButton();
})();
