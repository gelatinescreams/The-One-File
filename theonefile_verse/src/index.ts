import { readFileSync, writeFileSync, existsSync, mkdirSync, unlinkSync, readdirSync } from "fs";
import { join } from "path";

const PORT = parseInt(process.env.PORT || "10101");
const DATA_DIR = process.env.DATA_DIR || "./data";
const ROOMS_DIR = join(DATA_DIR, "rooms");
const ADMIN_CONFIG_PATH = join(DATA_DIR, "admin.json");
const SETTINGS_PATH = join(DATA_DIR, "settings.json");

const ENV_UPDATE_INTERVAL = parseInt(process.env.UPDATE_INTERVAL || "0");
const ENV_SKIP_UPDATE = process.env.SKIP_UPDATE === "true";
const ENV_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

interface AdminConfig {
  passwordHash: string;
  createdAt: string;
}

interface InstanceSettings {
  instancePasswordEnabled: boolean;
  instancePasswordHash: string | null;
  updateIntervalHours: number;
  skipUpdates: boolean;
  allowPublicRoomCreation: boolean;
  maxRoomsPerInstance: number;
  defaultDestructMode: "time" | "empty" | "never";
  defaultDestructHours: number;
  forcedTheme: "user" | "dark" | "light";
}

const defaultSettings: InstanceSettings = {
  instancePasswordEnabled: false,
  instancePasswordHash: null,
  updateIntervalHours: 0,
  skipUpdates: false,
  allowPublicRoomCreation: true,
  maxRoomsPerInstance: 0,
  defaultDestructMode: "time",
  defaultDestructHours: 24,
  forcedTheme: "user"
};

function loadSettings(): InstanceSettings {
  if (!existsSync(SETTINGS_PATH)) return { ...defaultSettings };
  try {
    const saved = JSON.parse(readFileSync(SETTINGS_PATH, "utf-8"));
    return { ...defaultSettings, ...saved };
  } catch { return { ...defaultSettings }; }
}

function saveSettings(settings: InstanceSettings): void {
  writeFileSync(SETTINGS_PATH, JSON.stringify(settings, null, 2));
}

let instanceSettings = loadSettings();

if (ENV_SKIP_UPDATE) instanceSettings.skipUpdates = true;
if (ENV_UPDATE_INTERVAL > 0) instanceSettings.updateIntervalHours = ENV_UPDATE_INTERVAL;

function loadAdminConfig(): AdminConfig | null {
  if (!existsSync(ADMIN_CONFIG_PATH)) return null;
  try { return JSON.parse(readFileSync(ADMIN_CONFIG_PATH, "utf-8")); } catch { return null; }
}

function saveAdminConfig(config: AdminConfig): void {
  writeFileSync(ADMIN_CONFIG_PATH, JSON.stringify(config, null, 2));
}

function isAdminConfigured(): boolean {
  return !!ENV_ADMIN_PASSWORD || loadAdminConfig() !== null;
}

async function verifyAdminPassword(password: string): Promise<boolean> {
  if (ENV_ADMIN_PASSWORD) return password === ENV_ADMIN_PASSWORD;
  const config = loadAdminConfig();
  if (!config) return false;
  return await verifyPassword(password, config.passwordHash);
}

async function verifyInstancePassword(password: string): Promise<boolean> {
  if (!instanceSettings.instancePasswordEnabled || !instanceSettings.instancePasswordHash) return true;
  return await verifyPassword(password, instanceSettings.instancePasswordHash);
}

function isInstanceLocked(): boolean {
  return instanceSettings.instancePasswordEnabled && !!instanceSettings.instancePasswordHash;
}

const ADMIN_TOKENS = new Set<string>();
const INSTANCE_TOKENS = new Set<string>();

function generateAdminToken(): string {
  const token = crypto.randomUUID();
  ADMIN_TOKENS.add(token);
  return token;
}

function validateAdminToken(token: string): boolean {
  return ADMIN_TOKENS.has(token);
}

function getTokenFromRequest(req: Request): string | null {
  const cookie = req.headers.get("cookie") || "";
  const match = cookie.match(/collab_token=([^;]+)/);
  if (match) return match[1];
  const auth = req.headers.get("authorization") || "";
  if (auth.startsWith("Bearer ")) return auth.slice(7);
  return null;
}

function isAdminRoute(path: string): boolean {
  return path === "/" || path === "/index.html" || path.startsWith("/s/") || 
         path.startsWith("/ws/") || path.startsWith("/api/room");
}

const setupPageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Setup - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .setup-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:450px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    .subtitle{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    .warning{background:rgba(201,162,39,0.1);border:1px solid rgba(201,162,39,0.3);border-radius:8px;padding:12px;margin-bottom:24px;font-size:13px;color:#c9a227}
    label{display:block;font-size:14px;color:var(--text-soft);margin-bottom:6px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
    button:hover{background:var(--accent-hover)}
    button:disabled{background:var(--border);cursor:not-allowed}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    .strength{height:4px;background:var(--border);border-radius:2px;margin-bottom:16px;overflow:hidden}
    .strength-bar{height:100%;transition:all 0.3s;width:0%}
    .strength-weak{background:#ef4444;width:33%}
    .strength-medium{background:#c9a227;width:66%}
    .strength-strong{background:#22c55e;width:100%}
  </style>
</head>
<body>
  <div class="setup-box">
    <h1>Welcome to The One File Collab</h1>
    <p class="subtitle">Set up your admin password to get started</p>
    <div class="warning">This password protects your admin panel. Store it safely - there's no recovery option except deleting data/admin.json</div>
    <div class="error" id="error"></div>
    <form id="setup-form">
      <label for="password">Admin Password</label>
      <input type="password" id="password" placeholder="Enter a strong password" autofocus>
      <div class="strength"><div class="strength-bar" id="strength-bar"></div></div>
      <label for="confirm">Confirm Password</label>
      <input type="password" id="confirm" placeholder="Confirm your password">
      <button type="submit" id="submit-btn" disabled>Create Admin Account</button>
    </form>
  </div>
  <script>
    (function(){document.documentElement.setAttribute('data-theme',localStorage.getItem('theme')||'dark')})();
    const pwd=document.getElementById('password'),confirm=document.getElementById('confirm'),bar=document.getElementById('strength-bar'),btn=document.getElementById('submit-btn'),error=document.getElementById('error');
    function checkStrength(p){if(p.length<6)return 0;let s=0;if(p.length>=8)s++;if(p.length>=12)s++;if(/[a-z]/.test(p)&&/[A-Z]/.test(p))s++;if(/[0-9]/.test(p))s++;if(/[^a-zA-Z0-9]/.test(p))s++;return Math.min(s,3)}
    function updateUI(){const s=checkStrength(pwd.value);bar.className='strength-bar';if(s===1)bar.classList.add('strength-weak');else if(s===2)bar.classList.add('strength-medium');else if(s>=3)bar.classList.add('strength-strong');btn.disabled=pwd.value.length<6||pwd.value!==confirm.value}
    pwd.addEventListener('input',updateUI);confirm.addEventListener('input',updateUI);
    document.getElementById('setup-form').addEventListener('submit',async(e)=>{
      e.preventDefault();if(pwd.value!==confirm.value){error.textContent='Passwords do not match';error.classList.add('active');return}
      if(pwd.value.length<6){error.textContent='Password must be at least 6 characters';error.classList.add('active');return}
      try{const res=await fetch('/api/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pwd.value})});
        if(res.ok)window.location.href='/';else{const d=await res.json();error.textContent=d.error||'Setup failed';error.classList.add('active')}
      }catch{error.textContent='Connection error';error.classList.add('active')}
    });
  </script>
</body>
</html>`;

const loginPageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
  </style>
</head>
<body>
  <div class="login-box">
    <h1>The One File Collab</h1>
    <p>This instance requires a password</p>
    <div class="error" id="error">Invalid password</div>
    <form id="login-form">
      <input type="password" id="password" placeholder="Enter password" autofocus>
      <button type="submit">Login</button>
    </form>
  </div>
  <script>
    (function(){let f=null;function g(){if(f&&f!=='user')return f;return localStorage.getItem('theme')||'dark'}function s(t){document.documentElement.setAttribute('data-theme',t)}s(g());fetch('/api/theme').then(r=>r.json()).then(d=>{if(d.forcedTheme&&d.forcedTheme!=='user'){f=d.forcedTheme;s(f)}}).catch(()=>{})})();
    document.getElementById('login-form').addEventListener('submit',async(e)=>{
      e.preventDefault();
      const password=document.getElementById('password').value;
      try{
        const res=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});
        if(res.ok)window.location.reload();
        else{document.getElementById('error').classList.add('active');document.getElementById('password').value=''}
      }catch{document.getElementById('error').textContent='Connection error';document.getElementById('error').classList.add('active')}
    });
  </script>
</body>
</html>`;

const instanceLoginPageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
  </style>
</head>
<body>
  <div class="login-box">
    <h1>The One File Collab</h1>
    <p>This instance requires a password to access</p>
    <div class="error" id="error">Invalid password</div>
    <form id="login-form">
      <input type="password" id="password" placeholder="Enter password" autofocus>
      <button type="submit">Access</button>
    </form>
  </div>
  <script>
    (function(){let f=null;function g(){if(f&&f!=='user')return f;return localStorage.getItem('theme')||'dark'}function s(t){document.documentElement.setAttribute('data-theme',t)}s(g());fetch('/api/theme').then(r=>r.json()).then(d=>{if(d.forcedTheme&&d.forcedTheme!=='user'){f=d.forcedTheme;s(f)}}).catch(()=>{})})();
    document.getElementById('login-form').addEventListener('submit',async(e)=>{
      e.preventDefault();
      try{
        const res=await fetch('/api/instance-login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('password').value})});
        if(res.ok)window.location.reload();
        else{document.getElementById('error').classList.add('active');document.getElementById('password').value=''}
      }catch{document.getElementById('error').textContent='Connection error';document.getElementById('error').classList.add('active')}
    });
  </script>
</body>
</html>`;

const adminDashboardHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{
      --bg:#0d0d0d;
      --bg-alt:#1a1a1a;
      --surface:#242424;
      --border:#333;
      --text:#e8e8e8;
      --text-soft:#999;
      --accent:#c9a227;
      --accent-hover:#d4b23a;
      --accent-bg:rgba(201,162,39,0.1);
      --accent-bg-hover:rgba(201,162,39,0.15);
    }
    [data-theme="light"]{
      --bg:#f5f3ef;
      --bg-alt:#eae7e0;
      --surface:#fff;
      --border:#d4d0c8;
      --text:#1a1a1a;
      --text-soft:#666;
      --accent:#996b1f;
      --accent-hover:#7a5518;
      --accent-bg:rgba(153,107,31,0.1);
      --accent-bg-hover:rgba(153,107,31,0.15);
    }
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:20px;padding-bottom:80px}
    .container{max-width:1200px;margin:0 auto}
    header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:12px}
    h1{font-size:24px;display:flex;align-items:center;gap:12px}
    .header-actions{display:flex;gap:8px;flex-wrap:wrap}
    .theme-toggle{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;cursor:pointer;font-size:14px}
    .theme-toggle:hover{background:var(--bg-alt)}
    .btn{padding:10px 20px;border-radius:8px;font-size:14px;font-weight:500;cursor:pointer;border:none;transition:all 0.15s;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:6px}
    .btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{background:var(--accent-hover)}
    .btn-secondary{background:var(--surface);color:var(--text);border:1px solid var(--border)}.btn-secondary:hover{background:var(--bg-alt)}
    .btn-danger{background:#dc2626;color:white}.btn-danger:hover{background:#b91c1c}
    .btn-success{background:#22c55e;color:white}.btn-success:hover{background:#16a34a}
    .btn-sm{padding:6px 12px;font-size:12px}
    .btn:disabled{opacity:0.5;cursor:not-allowed}
    .tabs{display:flex;gap:4px;margin-bottom:24px;border-bottom:1px solid var(--border);padding-bottom:0}
    .tab{padding:12px 20px;background:transparent;border:none;color:var(--text-soft);font-size:14px;font-weight:500;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px}
    .tab:hover{color:var(--text)}
    .tab.active{color:var(--accent);border-bottom-color:var(--accent)}
    .tab-content{display:none}
    .tab-content.active{display:block}
    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}
    .stat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px}
    .stat-value{font-size:28px;font-weight:700;color:var(--accent)}
    .stat-label{font-size:13px;color:var(--text-soft);margin-top:4px}
    .section-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:12px}
    .section-title{font-size:18px;font-weight:600;display:flex;align-items:center;gap:8px}
    .bulk-actions{display:none;gap:8px;align-items:center;flex-wrap:wrap}
    .bulk-actions.active{display:flex}
    .selected-count{font-size:13px;color:var(--text-soft);padding:6px 12px;background:var(--surface);border-radius:6px}
    .room-list{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden}
    .room-header{display:grid;grid-template-columns:40px 1fr 100px 100px 80px 140px;padding:12px 16px;background:var(--bg-alt);font-size:12px;font-weight:600;color:var(--text-soft);text-transform:uppercase;gap:8px;align-items:center}
    .room-row{display:grid;grid-template-columns:40px 1fr 100px 100px 80px 140px;padding:12px 16px;border-bottom:1px solid var(--border);align-items:center;gap:8px;transition:background 0.15s}
    .room-row:last-child{border-bottom:none}
    .room-row:hover{background:var(--accent-bg)}
    .room-row.selected{background:var(--accent-bg-hover)}
    .room-checkbox{width:20px;height:20px;cursor:pointer;accent-color:var(--accent)}
    .room-id{font-family:monospace;font-size:11px;color:var(--text-soft);word-break:break-all}
    .room-name{font-weight:500;font-size:14px}
    .badge{display:inline-block;padding:4px 8px;border-radius:12px;font-size:11px;font-weight:500}
    .badge-green{background:rgba(34,197,94,0.15);color:#22c55e}
    .badge-yellow{background:rgba(201,162,39,0.15);color:#c9a227}
    .badge-gray{background:rgba(100,116,139,0.15);color:#94a3b8}
    .room-actions{display:flex;gap:6px;flex-wrap:wrap}
    .empty-state{text-align:center;padding:60px 20px;color:var(--text-soft)}
    .empty-state h3{font-size:18px;margin-bottom:8px;color:var(--text)}
    .settings-section{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:16px}
    .settings-section h3{font-size:16px;font-weight:600;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--border)}
    .setting-row{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:12px}
    .setting-row:last-child{border-bottom:none}
    .setting-info{flex:1;min-width:200px}
    .setting-label{font-size:14px;font-weight:500;margin-bottom:4px}
    .setting-desc{font-size:12px;color:var(--text-soft)}
    .setting-control{display:flex;align-items:center;gap:8px}
    .toggle{position:relative;width:48px;height:26px;background:var(--border);border-radius:13px;cursor:pointer;transition:background 0.2s}
    .toggle.active{background:var(--accent)}
    .toggle::after{content:'';position:absolute;top:3px;left:3px;width:20px;height:20px;background:var(--text);border-radius:50%;transition:transform 0.2s}
    .toggle.active::after{transform:translateX(22px)}
    input[type="text"],input[type="password"],input[type="number"],select{padding:10px 12px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:14px;min-width:120px}
    input:focus,select:focus{outline:none;border-color:var(--accent)}
    .modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:1000;align-items:center;justify-content:center;padding:20px}
    .modal-overlay.active{display:flex}
    .modal{background:var(--surface);border:1px solid var(--border);border-radius:16px;width:100%;max-width:500px}
    .modal-header{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid var(--border)}
    .modal-header h3{font-size:18px}
    .modal-close{background:none;border:none;color:var(--text-soft);font-size:24px;cursor:pointer;padding:4px}
    .modal-body{padding:20px}
    .info-row{display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:8px}
    .info-row:last-child{border-bottom:none}
    .info-label{color:var(--text-soft);font-size:14px}
    .info-value{font-weight:500;font-size:14px;word-break:break-all}
    .status-msg{padding:12px;border-radius:8px;margin-bottom:16px;font-size:14px}
    .status-msg.success{background:rgba(34,197,94,0.15);color:#22c55e}
    .status-msg.error{background:rgba(239,68,68,0.15);color:#ef4444}
    @media(max-width:900px){.room-header,.room-row{grid-template-columns:32px 1fr 80px 100px}.room-header>*:nth-child(4),.room-header>*:nth-child(5),.room-row>*:nth-child(4),.room-row>*:nth-child(5){display:none}}
    @media(max-width:600px){body{padding:12px;padding-bottom:80px}header{flex-direction:column;align-items:flex-start}h1{font-size:20px}.stats{grid-template-columns:repeat(2,1fr);gap:8px}.stat-card{padding:12px}.stat-value{font-size:22px}.stat-label{font-size:11px}.room-header,.room-row{grid-template-columns:32px 1fr 90px}.room-header>*:nth-child(3),.room-header>*:nth-child(4),.room-header>*:nth-child(5),.room-row>*:nth-child(3),.room-row>*:nth-child(4),.room-row>*:nth-child(5){display:none}.room-actions{justify-content:flex-end}.btn{padding:8px 12px;font-size:12px}.btn-sm{padding:6px 10px;font-size:11px}.section-header{flex-direction:column;align-items:flex-start}.bulk-actions{width:100%;justify-content:flex-start}.tabs{overflow-x:auto}.setting-row{flex-direction:column;align-items:flex-start}.setting-control{width:100%}}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Admin Dashboard</h1>
      <div class="header-actions">
        <button class="theme-toggle" id="theme-toggle" onclick="toggleTheme()"><span id="theme-icon"></span></button>
        <a href="/" class="btn btn-secondary">Back to App</a>
        <button class="btn btn-secondary" onclick="logout()">Logout</button>
      </div>
    </header>
    <div class="tabs">
      <button class="tab active" onclick="showTab('rooms')">Rooms</button>
      <button class="tab" onclick="showTab('settings')">Settings</button>
    </div>
    <div id="tab-rooms" class="tab-content active">
      <div class="stats" id="stats"></div>
      <div class="section-header">
        <h2 class="section-title">All Rooms</h2>
        <div class="bulk-actions" id="bulk-actions">
          <span class="selected-count" id="selected-count">0 selected</span>
          <button class="btn btn-danger btn-sm" onclick="deleteSelected()">Delete Selected</button>
          <button class="btn btn-secondary btn-sm" onclick="clearSelection()">Clear</button>
        </div>
      </div>
      <div class="room-list" id="room-list"></div>
    </div>
    <div id="tab-settings" class="tab-content">
      <div id="settings-status"></div>
      <div class="settings-section">
        <h3>Instance Access</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Password Lock</div><div class="setting-desc">Require password to access the entire instance</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-instance-lock" onclick="toggleSetting('instancePasswordEnabled')"></div></div>
        </div>
        <div class="setting-row" id="instance-pwd-row" style="display:none">
          <div class="setting-info"><div class="setting-label">Instance Password</div><div class="setting-desc" id="instance-pwd-status">Set a password for instance access</div></div>
          <div class="setting-control"><input type="password" id="instance-password" placeholder="New password"><button class="btn btn-sm btn-primary" onclick="setInstancePassword()">Set</button></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>TheOneFile Source</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Source Mode</div><div class="setting-desc">Choose where to load TheOneFile from</div></div>
          <div class="setting-control">
            <select id="source-mode" onchange="changeSourceMode()"><option value="github">GitHub (Auto-Update)</option><option value="local">Local (Manual Upload)</option></select>
          </div>
        </div>
        <div class="setting-row" id="github-settings">
          <div class="setting-info"><div class="setting-label">Update Interval</div><div class="setting-desc">Hours between auto-updates (0 = manual only)</div></div>
          <div class="setting-control"><input type="number" id="update-interval" min="0" max="168" style="width:80px"><button class="btn btn-sm btn-primary" onclick="saveUpdateInterval()">Save</button></div>
        </div>
        <div class="setting-row" id="github-update-row">
          <div class="setting-info"><div class="setting-label">Fetch from GitHub</div><div class="setting-desc">Download latest version now</div></div>
          <div class="setting-control"><button class="btn btn-sm btn-success" id="update-btn" onclick="triggerUpdate()">Update Now</button></div>
        </div>
        <div class="setting-row" id="upload-row" style="display:none">
          <div class="setting-info"><div class="setting-label">Upload Local File</div><div class="setting-desc" id="upload-status">Upload your own TheOneFile HTML</div></div>
          <div class="setting-control">
            <input type="file" id="upload-file" accept=".html" style="display:none" onchange="uploadFile()">
            <button class="btn btn-sm btn-primary" onclick="document.getElementById('upload-file').click()">Choose File</button>
          </div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Current File</div><div class="setting-desc" id="current-file-info">Loading...</div></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Appearance</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Theme</div><div class="setting-desc">Force a theme for all users or let them choose</div></div>
          <div class="setting-control">
            <select id="forced-theme" onchange="saveForcedTheme()"><option value="user">User Choice</option><option value="dark">Force Dark</option><option value="light">Force Light</option></select>
          </div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Room Defaults</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Default Self-Destruct</div><div class="setting-desc">Default expiration for new rooms</div></div>
          <div class="setting-control">
            <select id="default-destruct-mode"><option value="time">After time</option><option value="empty">When empty</option><option value="never">Never</option></select>
            <input type="number" id="default-destruct-hours" min="1" max="720" style="width:70px">
            <span style="color:#8892a0;font-size:12px">hours</span>
          </div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Max Rooms</div><div class="setting-desc">Maximum rooms allowed (0 = unlimited)</div></div>
          <div class="setting-control"><input type="number" id="max-rooms" min="0" max="1000" style="width:80px"></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Public Room Creation</div><div class="setting-desc">Allow anyone to create rooms</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-public-rooms" onclick="toggleSetting('allowPublicRoomCreation')"></div></div>
        </div>
        <div style="margin-top:16px"><button class="btn btn-primary" onclick="saveRoomDefaults()">Save Room Settings</button></div>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="room-modal">
    <div class="modal">
      <div class="modal-header"><h3 id="modal-title">Room Details</h3><button class="modal-close" onclick="closeModal()">&times;</button></div>
      <div class="modal-body" id="modal-body"></div>
    </div>
  </div>
  <script>
    let forcedTheme=null;
    function getTheme(){if(forcedTheme&&forcedTheme!=='user')return forcedTheme;return localStorage.getItem('theme')||'dark'}
    function setTheme(theme){if(!forcedTheme||forcedTheme==='user')localStorage.setItem('theme',theme);document.documentElement.setAttribute('data-theme',theme);document.getElementById('theme-icon').textContent=theme==='dark'?'\\u2600':'\\u263E'}
    function toggleTheme(){if(forcedTheme&&forcedTheme!=='user')return;setTheme(getTheme()==='dark'?'light':'dark')}
    function updateThemeToggleVisibility(){const btn=document.getElementById('theme-toggle');if(forcedTheme&&forcedTheme!=='user')btn.style.display='none';else btn.style.display='block'}
    setTheme(getTheme());
    fetch('/api/theme').then(r=>r.json()).then(data=>{if(data.forcedTheme&&data.forcedTheme!=='user'){forcedTheme=data.forcedTheme;setTheme(forcedTheme)}updateThemeToggleVisibility()}).catch(()=>updateThemeToggleVisibility());
    let rooms=[],selected=new Set(),settings={};
    function showTab(name){document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));document.querySelector('.tab-content#tab-'+name).classList.add('active');document.querySelector('.tab[onclick*="'+name+'"]').classList.add('active');if(name==='settings')loadSettings()}
    async function loadData(){try{const res=await fetch('/api/admin/rooms');if(!res.ok){if(res.status===401)window.location.href='/admin/login';return}rooms=await res.json();renderStats();renderRooms();updateBulkUI()}catch(e){console.error(e)}}
    async function loadSettings(){try{const res=await fetch('/api/admin/settings');if(!res.ok)return;settings=await res.json();renderSettings()}catch(e){console.error(e)}}
    function renderSettings(){
      document.getElementById('toggle-instance-lock').classList.toggle('active',settings.instancePasswordEnabled);
      document.getElementById('toggle-public-rooms').classList.toggle('active',settings.allowPublicRoomCreation);
      document.getElementById('update-interval').value=settings.updateIntervalHours||0;
      document.getElementById('default-destruct-mode').value=settings.defaultDestructMode||'time';
      document.getElementById('default-destruct-hours').value=settings.defaultDestructHours||24;
      document.getElementById('max-rooms').value=settings.maxRoomsPerInstance||0;
      document.getElementById('forced-theme').value=settings.forcedTheme||'user';
      document.getElementById('instance-pwd-row').style.display=settings.instancePasswordEnabled?'flex':'none';
      document.getElementById('instance-pwd-status').textContent=settings.instancePasswordSet?'Password is set':'No password set';
      if(settings.envAdminPasswordSet){document.getElementById('toggle-instance-lock').style.opacity='0.5';document.getElementById('toggle-instance-lock').onclick=null}
      updateSourceUI();
    }
    async function saveForcedTheme(){
      const val=document.getElementById('forced-theme').value;
      await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({forcedTheme:val})});
      showStatus('Theme setting saved','success');
    }
    async function toggleSetting(key){
      if(key==='instancePasswordEnabled'&&settings.envAdminPasswordSet)return;
      settings[key]=!settings[key];
      renderSettings();
      await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({[key]:settings[key]})});
      showStatus('Setting updated','success');
    }
    async function setInstancePassword(){
      const pwd=document.getElementById('instance-password').value;
      if(pwd.length<4){showStatus('Password must be at least 4 characters','error');return}
      await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({instancePassword:pwd})});
      document.getElementById('instance-password').value='';
      showStatus('Password updated','success');
      loadSettings();
    }
    async function saveUpdateInterval(){
      const val=parseInt(document.getElementById('update-interval').value)||0;
      await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({updateIntervalHours:val})});
      showStatus('Update interval saved','success');
    }
    async function triggerUpdate(){
      const btn=document.getElementById('update-btn');btn.disabled=true;btn.textContent='Updating...';
      try{const res=await fetch('/api/admin/update',{method:'POST'});const data=await res.json();
        if(data.success){showStatus('Updated successfully ('+Math.round(data.size/1024)+'KB)','success');loadSettings()}
        else showStatus(data.error||'Update failed','error');
      }catch{showStatus('Update failed','error')}
      btn.disabled=false;btn.textContent='Update Now';
    }
    async function changeSourceMode(){
      const mode=document.getElementById('source-mode').value;
      try{
        const res=await fetch('/api/admin/source-mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode})});
        const data=await res.json();
        if(data.success){
          showStatus('Source mode changed to '+mode,'success');
          loadSettings();
        }else{showStatus(data.error||'Failed to change mode','error')}
      }catch{showStatus('Failed to change mode','error')}
    }
    async function uploadFile(){
      const input=document.getElementById('upload-file');
      if(!input.files||!input.files[0])return;
      const file=input.files[0];
      const formData=new FormData();
      formData.append('file',file);
      try{
        const res=await fetch('/api/admin/upload-html',{method:'POST',body:formData});
        const data=await res.json();
        if(data.success){
          showStatus('Uploaded successfully ('+Math.round(data.size/1024)+'KB) - '+data.edition+' edition','success');
          loadSettings();
        }else{showStatus(data.error||'Upload failed','error')}
      }catch{showStatus('Upload failed','error')}
      input.value='';
    }
    function updateSourceUI(){
      const isLocal=settings.skipUpdates;
      document.getElementById('source-mode').value=isLocal?'local':'github';
      document.getElementById('github-settings').style.display=isLocal?'none':'flex';
      document.getElementById('github-update-row').style.display=isLocal?'none':'flex';
      document.getElementById('upload-row').style.display=isLocal?'flex':'none';
      const sizeKB=settings.currentFileSize?Math.round(settings.currentFileSize/1024):0;
      const edition=settings.currentFileEdition||'unknown';
      const source=isLocal?'Local upload':'GitHub';
      document.getElementById('current-file-info').textContent=sizeKB+'KB - '+edition+' edition ('+source+')';
    }
    async function saveRoomDefaults(){
      await fetch('/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
        defaultDestructMode:document.getElementById('default-destruct-mode').value,
        defaultDestructHours:parseInt(document.getElementById('default-destruct-hours').value)||24,
        maxRoomsPerInstance:parseInt(document.getElementById('max-rooms').value)||0
      })});
      showStatus('Room defaults saved','success');
    }
    function showStatus(msg,type){
      const el=document.getElementById('settings-status');
      el.innerHTML='<div class="status-msg '+type+'">'+msg+'</div>';
      setTimeout(()=>el.innerHTML='',3000);
    }
    function renderStats(){const active=rooms.filter(r=>r.connectedUsers>0).length;const withPwd=rooms.filter(r=>r.hasPassword).length;document.getElementById('stats').innerHTML='<div class="stat-card"><div class="stat-value">'+rooms.length+'</div><div class="stat-label">Total Rooms</div></div><div class="stat-card"><div class="stat-value">'+active+'</div><div class="stat-label">Active</div></div><div class="stat-card"><div class="stat-value">'+withPwd+'</div><div class="stat-label">Protected</div></div><div class="stat-card"><div class="stat-value">'+rooms.reduce((a,r)=>a+r.connectedUsers,0)+'</div><div class="stat-label">Users Online</div></div>'}
    function renderRooms(){if(rooms.length===0){document.getElementById('room-list').innerHTML='<div class="empty-state"><h3>No rooms yet</h3><p>Rooms will appear here when created</p></div>';return}let html='<div class="room-header"><input type="checkbox" class="room-checkbox" onchange="toggleAll(this.checked)" '+(selected.size===rooms.length&&rooms.length>0?'checked':'')+'><span>Room</span><span>Users</span><span>Created</span><span>Password</span><span>Actions</span></div>';rooms.forEach(r=>{const created=new Date(r.created).toLocaleDateString();const users=r.connectedUsers>0?'<span class="badge badge-green">'+r.connectedUsers+'</span>':'<span class="badge badge-gray">0</span>';const pwd=r.hasPassword?'<span class="badge badge-yellow">Yes</span>':'<span class="badge badge-gray">No</span>';const isSelected=selected.has(r.id);html+='<div class="room-row'+(isSelected?' selected':'')+'"><input type="checkbox" class="room-checkbox" '+(isSelected?'checked':'')+' onchange="toggleSelect(\\''+r.id+'\\',this.checked)"><div><div class="room-name">Room</div><div class="room-id">'+r.id+'</div></div><div>'+users+'</div><div>'+created+'</div><div>'+pwd+'</div><div class="room-actions"><button class="btn btn-secondary btn-sm" onclick="viewRoom(\\''+r.id+'\\')">View</button><button class="btn btn-primary btn-sm" onclick="joinRoom(\\''+r.id+'\\')">Join</button><button class="btn btn-danger btn-sm" onclick="deleteRoom(\\''+r.id+'\\')">Del</button></div></div>'});document.getElementById('room-list').innerHTML=html}
    function toggleSelect(id,checked){if(checked)selected.add(id);else selected.delete(id);updateBulkUI();renderRooms()}
    function toggleAll(checked){if(checked)rooms.forEach(r=>selected.add(r.id));else selected.clear();updateBulkUI();renderRooms()}
    function clearSelection(){selected.clear();updateBulkUI();renderRooms()}
    function updateBulkUI(){const bulk=document.getElementById('bulk-actions');const count=document.getElementById('selected-count');if(selected.size>0){bulk.classList.add('active');count.textContent=selected.size+' selected'}else{bulk.classList.remove('active')}}
    async function deleteSelected(){if(selected.size===0)return;if(!confirm('Delete '+selected.size+' room(s) permanently?'))return;for(const id of selected){try{await fetch('/api/admin/rooms/'+id,{method:'DELETE'})}catch{}}selected.clear();loadData()}
    function viewRoom(id){const room=rooms.find(r=>r.id===id);if(!room)return;let destruct='Never';if(room.destruct.mode==='time'){const h=room.destruct.value/3600000;destruct=h<1?Math.round(h*60)+' min':h<24?h+' hours':Math.round(h/24)+' days'}else if(room.destruct.mode==='empty')destruct='When empty';document.getElementById('modal-title').textContent='Room Details';document.getElementById('modal-body').innerHTML='<div class="info-row"><span class="info-label">Room ID</span><span class="info-value" style="font-family:monospace;font-size:12px">'+room.id+'</span></div><div class="info-row"><span class="info-label">Created</span><span class="info-value">'+new Date(room.created).toLocaleString()+'</span></div><div class="info-row"><span class="info-label">Last Activity</span><span class="info-value">'+new Date(room.lastActivity).toLocaleString()+'</span></div><div class="info-row"><span class="info-label">Connected Users</span><span class="info-value">'+room.connectedUsers+'</span></div><div class="info-row"><span class="info-label">Password Protected</span><span class="info-value">'+(room.hasPassword?'Yes':'No')+'</span></div><div class="info-row"><span class="info-label">Self-Destruct</span><span class="info-value">'+destruct+'</span></div><div style="margin-top:20px;display:flex;gap:12px;flex-wrap:wrap"><button class="btn btn-primary" onclick="joinRoom(\\''+room.id+'\\');closeModal()">Join Room</button><button class="btn btn-danger" onclick="deleteRoom(\\''+room.id+'\\');closeModal()">Delete Room</button></div>';document.getElementById('room-modal').classList.add('active')}
    function closeModal(){document.getElementById('room-modal').classList.remove('active')}
    function joinRoom(id){window.open('/s/'+id,'_blank')}
    async function deleteRoom(id){if(!confirm('Delete this room permanently?'))return;try{const res=await fetch('/api/admin/rooms/'+id,{method:'DELETE'});if(res.ok){selected.delete(id);loadData()}else alert('Failed to delete room')}catch{alert('Error deleting room')}}
    async function logout(){await fetch('/api/logout',{method:'POST'});window.location.href='/'}
    document.getElementById('room-modal').addEventListener('click',e=>{if(e.target.id==='room-modal')closeModal()});
    loadData();setInterval(loadData,10000);
  </script>
</body>
</html>`;

const adminLoginHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    .back-link{text-align:center;margin-top:20px}
    .back-link a{color:var(--accent);text-decoration:none;font-size:14px}
  </style>
</head>
<body>
  <div class="login-box">
    <h1>Admin Login</h1>
    <p>Enter your admin password</p>
    <div class="error" id="error">Invalid password</div>
    <form id="login-form">
      <input type="password" id="password" placeholder="Admin password" autofocus>
      <button type="submit">Login</button>
    </form>
    <div class="back-link"><a href="/">Back to App</a></div>
  </div>
  <script>
    (function(){let f=null;function g(){if(f&&f!=='user')return f;return localStorage.getItem('theme')||'dark'}function s(t){document.documentElement.setAttribute('data-theme',t)}s(g());fetch('/api/theme').then(r=>r.json()).then(d=>{if(d.forcedTheme&&d.forcedTheme!=='user'){f=d.forcedTheme;s(f)}}).catch(()=>{})})();
    document.getElementById('login-form').addEventListener('submit',async(e)=>{
      e.preventDefault();
      try{
        const res=await fetch('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('password').value})});
        if(res.ok)window.location.href='/admin';
        else{document.getElementById('error').classList.add('active');document.getElementById('password').value=''}
      }catch{document.getElementById('error').textContent='Connection error';document.getElementById('error').classList.add('active')}
    });
  </script>
</body>
</html>`;

if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
if (!existsSync(ROOMS_DIR)) mkdirSync(ROOMS_DIR, { recursive: true });

interface Room {
  id: string;
  created: string;
  lastActivity: string;
  creatorId: string;
  passwordHash: string | null;
  destruct: { mode: "time" | "empty" | "never"; value: number };
  topology: any;
}

interface RoomMeta {
  connectedUsers: number;
  destructTimer?: Timer;
}

const roomMeta: Map<string, RoomMeta> = new Map();
const roomConnections: Map<string, Set<any>> = new Map();
const roomUsers: Map<string, Map<string, any>> = new Map();
const roomUsedNames: Map<string, Map<string, string>> = new Map();

async function hashPassword(password: string): Promise<string> {
  return await Bun.password.hash(password, {
    algorithm: "argon2id",
    memoryCost: 65536,
    timeCost: 2
  });
}

async function verifyPassword(password: string, hash: string): Promise<boolean> {
  if (hash.startsWith('$argon2')) {
    return await Bun.password.verify(password, hash);
  }
  const encoder = new TextEncoder();
  const data = encoder.encode(password + "theonefile-collab-salt-v1");
  const legacyHash = await crypto.subtle.digest("SHA-256", data);
  return Buffer.from(legacyHash).toString("hex") === hash;
}

function getRoomPath(id: string): string {
  return join(ROOMS_DIR, `${id}.json`);
}

function loadRoom(id: string): Room | null {
  const path = getRoomPath(id);
  if (!existsSync(path)) return null;
  try { return JSON.parse(readFileSync(path, "utf-8")); } catch { return null; }
}

function saveRoom(room: Room): void {
  writeFileSync(getRoomPath(room.id), JSON.stringify(room, null, 2));
}

function deleteRoom(id: string): boolean {
  const path = getRoomPath(id);
  if (!existsSync(path)) return false;
  try { unlinkSync(path); roomMeta.delete(id); return true; } catch { return false; }
}

function scheduleDestruction(roomId: string, delayMs: number): void {
  const meta = roomMeta.get(roomId) || { connectedUsers: 0 };
  if (meta.destructTimer) clearTimeout(meta.destructTimer);
  meta.destructTimer = setTimeout(() => {
    const room = loadRoom(roomId);
    if (room && room.destruct.mode === "time") {
      console.log(`[Room] ${roomId} self-destructed`);
      deleteRoom(roomId);
    }
  }, delayMs);
  roomMeta.set(roomId, meta);
}

function resetDestructionTimer(roomId: string): void {
  const room = loadRoom(roomId);
  if (room && room.destruct.mode === "time") {
    scheduleDestruction(roomId, room.destruct.value);
  }
}

let theOneFileHtml = "";
const theOneFilePath = join(process.cwd(), "public", "theonefile.html");
const GITHUB_RAW_URL = "https://raw.githubusercontent.com/gelatinescreams/The-One-File/main/theonefile-networkening.html";

interface ValidationResult {
  valid: boolean;
  error?: string;
  edition?: string;
}

function validateTheOneFileHtml(html: string): ValidationResult {
  if (!html || html.length < 1000) {
    return { valid: false, error: "File too small to be valid" };
  }
  if (!html.trim().startsWith("<!DOCTYPE html>") && !html.trim().startsWith("<html")) {
    return { valid: false, error: "Not a valid HTML file" };
  }
  const hasHeaderComment = html.includes("The One File") && html.includes("There can be only one");
  if (!hasHeaderComment) {
    return { valid: false, error: "Missing The One File header comment" };
  }
  const hasLangJson = html.includes('id="lang-json"');
  if (!hasLangJson) {
    return { valid: false, error: "Missing language system (lang-json)" };
  }
  const hasTopologyState = html.includes('id="topology-state"');
  if (!hasTopologyState) {
    return { valid: false, error: "Missing topology state element" };
  }
  let edition = "core";
  if (html.includes("The Networkening") || html.includes("networkening")) {
    edition = "networkening";
  }
  const hasCoreVars = html.includes("NODE_DATA") && html.includes("EDGE_DATA") && html.includes("savedPositions");
  if (!hasCoreVars) {
    return { valid: false, error: "Missing core topology variables" };
  }
  return { valid: true, edition };
}

async function fetchLatestFromGitHub(): Promise<boolean> {
  try {
    console.log("[Update] Fetching from GitHub...");
    const res = await fetch(GITHUB_RAW_URL);
    if (!res.ok) return false;
    const html = await res.text();
    writeFileSync(theOneFilePath, html);
    theOneFileHtml = html;
    console.log(`[Update] Downloaded (${(html.length / 1024).toFixed(1)}KB)`);
    return true;
  } catch { return false; }
}

let updateTimer: Timer | null = null;

function restartUpdateTimer(): void {
  if (updateTimer) clearInterval(updateTimer);
  updateTimer = null;
  if (instanceSettings.updateIntervalHours > 0 && !instanceSettings.skipUpdates) {
    updateTimer = setInterval(() => { fetchLatestFromGitHub(); }, instanceSettings.updateIntervalHours * 60 * 60 * 1000);
    console.log(`[Update] Auto-update every ${instanceSettings.updateIntervalHours} hours`);
  }
}

if (instanceSettings.skipUpdates) {
  if (existsSync(theOneFilePath)) {
    theOneFileHtml = readFileSync(theOneFilePath, "utf-8");
    console.log("[Update] Using local file (updates disabled)");
  }
} else {
  await fetchLatestFromGitHub();
  if (!theOneFileHtml && existsSync(theOneFilePath)) {
    theOneFileHtml = readFileSync(theOneFilePath, "utf-8");
    console.log("[Update] Using cached file");
  }
}

restartUpdateTimer();

const server = Bun.serve({
  port: PORT,
  async fetch(req, server) {
    const url = new URL(req.url);
    const path = url.pathname;
    
    if (path.match(/^\/ws\/[\w-]+$/)) {
      const roomId = path.split("/")[2];
      const room = loadRoom(roomId);
      if (!room) return new Response("Room not found", { status: 404 });
	  
      if (ENV_ADMIN_PASSWORD || isInstanceLocked()) {
        const token = getTokenFromRequest(req);
        if (!token || !INSTANCE_TOKENS.has(token)) return new Response("Unauthorized", { status: 401 });
      }
      const upgraded = server.upgrade(req, { data: { roomId } });
      if (upgraded) return undefined;
      return new Response("WebSocket upgrade failed", { status: 400 });
    }
    
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };
    
    if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

        if (!isAdminConfigured() && (path === "/" || path === "/index.html")) {
      return new Response(setupPageHtml, { headers: { "Content-Type": "text/html" } });
    }

    if (path === "/api/setup" && req.method === "POST") {
      if (isAdminConfigured()) {
        return Response.json({ error: "Admin already configured" }, { status: 400, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        if (!body.password || body.password.length < 6) {
          return Response.json({ error: "Password must be at least 6 characters" }, { status: 400, headers: corsHeaders });
        }
        const config: AdminConfig = {
          passwordHash: await hashPassword(body.password),
          createdAt: new Date().toISOString()
        };
        saveAdminConfig(config);
        const token = generateAdminToken();
        return new Response(JSON.stringify({ success: true }), {
          headers: { ...corsHeaders, "Content-Type": "application/json",
            "Set-Cookie": `collab_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800` }
        });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/admin") {
      const token = getTokenFromRequest(req);
      if (!token || !validateAdminToken(token)) {
        return Response.redirect(new URL("/admin/login", req.url).toString(), 302);
      }
      return new Response(adminDashboardHtml, { headers: { "Content-Type": "text/html" } });
    }

    if (path === "/admin/login") {
      if (!isAdminConfigured()) {
        return Response.redirect(new URL("/", req.url).toString(), 302);
      }
      return new Response(adminLoginHtml, { headers: { "Content-Type": "text/html" } });
    }

    if (path === "/api/admin/login" && req.method === "POST") {
      if (!isAdminConfigured()) {
        return Response.json({ error: "Admin not configured" }, { status: 400, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        if (await verifyAdminPassword(body.password)) {
          const token = generateAdminToken();
          return new Response(JSON.stringify({ success: true }), {
            headers: { ...corsHeaders, "Content-Type": "application/json",
              "Set-Cookie": `collab_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800` }
          });
        }
        return Response.json({ error: "Invalid password" }, { status: 403, headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/api/admin/rooms" && req.method === "GET") {
      const token = getTokenFromRequest(req);
      if (!token || !validateAdminToken(token)) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const rooms: any[] = [];
      readdirSync(ROOMS_DIR).forEach(file => {
        if (file.endsWith(".json")) {
          const room = loadRoom(file.replace(".json", ""));
          if (room) {
            const meta = roomMeta.get(room.id);
            rooms.push({
              id: room.id,
              created: room.created,
              lastActivity: room.lastActivity,
              hasPassword: !!room.passwordHash,
              destruct: room.destruct,
              connectedUsers: meta?.connectedUsers || 0
            });
          }
        }
      });
      rooms.sort((a, b) => new Date(b.created).getTime() - new Date(a.created).getTime());
      return Response.json(rooms, { headers: corsHeaders });
    }

    if (path.match(/^\/api\/admin\/rooms\/[\w-]+$/) && req.method === "DELETE") {
      const token = getTokenFromRequest(req);
      if (!token || !validateAdminToken(token)) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const id = path.split("/")[4];
      if (deleteRoom(id)) {
        return Response.json({ deleted: true }, { headers: corsHeaders });
      }
      return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });
    }

    if (path === "/api/logout" && req.method === "POST") {
      const token = getTokenFromRequest(req);
      if (token) ADMIN_TOKENS.delete(token);
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json",
          "Set-Cookie": `collab_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0` }
      });
    }

    if ((ENV_ADMIN_PASSWORD || isInstanceLocked()) && isAdminRoute(path)) {
      const token = getTokenFromRequest(req);
      const hasInstanceAccess = token && (INSTANCE_TOKENS.has(token) || ADMIN_TOKENS.has(token));
      if (!hasInstanceAccess) {
        if (path === "/" || path === "/index.html" || path.startsWith("/s/")) {
          return new Response(instanceLoginPageHtml, { headers: { "Content-Type": "text/html" } });
        }
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
    }

    if (path === "/api/instance-login" && req.method === "POST") {
      if (!ENV_ADMIN_PASSWORD && !isInstanceLocked()) {
        return Response.json({ error: "Instance not locked" }, { status: 400, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        let valid = false;
        if (ENV_ADMIN_PASSWORD) {
          valid = body.password === ENV_ADMIN_PASSWORD;
        } else {
          valid = await verifyInstancePassword(body.password);
        }
        if (valid) {
          const token = crypto.randomUUID();
          INSTANCE_TOKENS.add(token);
          return new Response(JSON.stringify({ success: true }), {
            headers: { ...corsHeaders, "Content-Type": "application/json",
              "Set-Cookie": `collab_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800` }
          });
        }
        return Response.json({ error: "Invalid password" }, { status: 403, headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/api/admin/settings" && req.method === "GET") {
      const token = getTokenFromRequest(req);
      if (!token || !validateAdminToken(token)) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      const { instancePasswordHash, ...safeSettings } = instanceSettings;
      const fileValidation = validateTheOneFileHtml(theOneFileHtml);
      return Response.json({
        ...safeSettings,
        instancePasswordSet: !!instancePasswordHash,
        envAdminPasswordSet: !!ENV_ADMIN_PASSWORD,
        currentFileSize: theOneFileHtml.length,
        currentFileEdition: fileValidation.valid ? fileValidation.edition : "invalid"
      }, { headers: corsHeaders });
    }

    if (path === "/api/admin/settings" && req.method === "POST") {
      const token = getTokenFromRequest(req);
      if (!token || !validateAdminToken(token)) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();

        if (typeof body.instancePasswordEnabled === "boolean") {
          instanceSettings.instancePasswordEnabled = body.instancePasswordEnabled;
        }
        if (body.instancePassword !== undefined) {
          if (body.instancePassword === "") {
            instanceSettings.instancePasswordHash = null;
          } else if (body.instancePassword.length >= 4) {
            instanceSettings.instancePasswordHash = await hashPassword(body.instancePassword);
          }
        }
        if (typeof body.updateIntervalHours === "number") {
          instanceSettings.updateIntervalHours = Math.max(0, body.updateIntervalHours);
          restartUpdateTimer();
        }
        if (typeof body.skipUpdates === "boolean") {
          instanceSettings.skipUpdates = body.skipUpdates;
        }
        if (typeof body.allowPublicRoomCreation === "boolean") {
          instanceSettings.allowPublicRoomCreation = body.allowPublicRoomCreation;
        }
        if (typeof body.maxRoomsPerInstance === "number") {
          instanceSettings.maxRoomsPerInstance = Math.max(0, body.maxRoomsPerInstance);
        }
        if (body.defaultDestructMode && ["time", "empty", "never"].includes(body.defaultDestructMode)) {
          instanceSettings.defaultDestructMode = body.defaultDestructMode;
        }
        if (typeof body.defaultDestructHours === "number") {
          instanceSettings.defaultDestructHours = Math.max(1, body.defaultDestructHours);
        }
        if (body.forcedTheme && ["user", "dark", "light"].includes(body.forcedTheme)) {
          instanceSettings.forcedTheme = body.forcedTheme;
        }

        saveSettings(instanceSettings);
        return Response.json({ success: true }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }

    if (path === "/api/admin/update" && req.method === "POST") {
      const token = getTokenFromRequest(req);
      if (!token || !validateAdminToken(token)) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      if (instanceSettings.skipUpdates) {
        return Response.json({ error: "Updates disabled" }, { status: 400, headers: corsHeaders });
      }
      const success = await fetchLatestFromGitHub();
      return Response.json({ success, size: theOneFileHtml.length }, { headers: corsHeaders });
    }

    if (path === "/api/admin/upload-html" && req.method === "POST") {
      const token = getTokenFromRequest(req);
      if (!token || !validateAdminToken(token)) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const formData = await req.formData();
        const file = formData.get("file") as File | null;
        if (!file) {
          return Response.json({ error: "No file provided" }, { status: 400, headers: corsHeaders });
        }
        const html = await file.text();
        const validationResult = validateTheOneFileHtml(html);
        if (!validationResult.valid) {
          return Response.json({ error: validationResult.error }, { status: 400, headers: corsHeaders });
        }
        writeFileSync(theOneFilePath, html);
        theOneFileHtml = html;
        instanceSettings.skipUpdates = true;
        saveSettings(instanceSettings);
        if (updateTimer) { clearInterval(updateTimer); updateTimer = null; }
        console.log(`[Upload] Admin uploaded local file (${(html.length / 1024).toFixed(1)}KB) - ${validationResult.edition}`);
        return Response.json({ success: true, size: html.length, edition: validationResult.edition }, { headers: corsHeaders });
      } catch (e) {
        return Response.json({ error: "Failed to process upload" }, { status: 500, headers: corsHeaders });
      }
    }

    if (path === "/api/admin/source-mode" && req.method === "POST") {
      const token = getTokenFromRequest(req);
      if (!token || !validateAdminToken(token)) {
        return Response.json({ error: "Unauthorized" }, { status: 401, headers: corsHeaders });
      }
      try {
        const body = await req.json();
        if (body.mode === "github") {
          instanceSettings.skipUpdates = false;
          saveSettings(instanceSettings);
          await fetchLatestFromGitHub();
          restartUpdateTimer();
          return Response.json({ success: true, mode: "github", size: theOneFileHtml.length }, { headers: corsHeaders });
        } else if (body.mode === "local") {
          instanceSettings.skipUpdates = true;
          saveSettings(instanceSettings);
          if (updateTimer) { clearInterval(updateTimer); updateTimer = null; }
          return Response.json({ success: true, mode: "local" }, { headers: corsHeaders });
        }
        return Response.json({ error: "Invalid mode" }, { status: 400, headers: corsHeaders });
      } catch {
        return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders });
      }
    }

    if (path === "/api/theme" && req.method === "GET") {
      return Response.json({ forcedTheme: instanceSettings.forcedTheme }, { headers: corsHeaders });
    }

    if (path === "/api/room" && req.method === "POST") {
      try {
        const body = await req.json();
        const id = crypto.randomUUID();
        const room: Room = {
          id,
          created: new Date().toISOString(),
          lastActivity: new Date().toISOString(),
          creatorId: body.creatorId || "",
          passwordHash: body.password ? await hashPassword(body.password) : null,
          destruct: { mode: body.destructMode || "time", value: body.destructValue || 86400000 },
          topology: body.topology || null
        };
        saveRoom(room);
        if (room.destruct.mode === "time") scheduleDestruction(id, room.destruct.value);
        return Response.json({ id, url: `/s/${id}`, hasPassword: !!room.passwordHash }, { headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }
    
    if (path.match(/^\/api\/room\/[\w-]+\/verify$/) && req.method === "POST") {
      const id = path.split("/")[3];
      const room = loadRoom(id);
      if (!room) return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });
      if (!room.passwordHash) return Response.json({ valid: true }, { headers: corsHeaders });
      try {
        const body = await req.json();
        return Response.json({ valid: await verifyPassword(body.password || "", room.passwordHash) }, { headers: corsHeaders });
      } catch { return Response.json({ valid: false }, { headers: corsHeaders }); }
    }
    
    if (path.match(/^\/api\/room\/[\w-]+$/) && req.method === "DELETE") {
      const id = path.split("/")[3];
      const room = loadRoom(id);
      if (!room) return Response.json({ error: "Room not found" }, { status: 404, headers: corsHeaders });
      try {
        const body = await req.json();
        if (body.creatorId && body.creatorId === room.creatorId) {
          deleteRoom(id);
          return Response.json({ deleted: true }, { headers: corsHeaders });
        }
        return Response.json({ error: "Only room creator can delete" }, { status: 403, headers: corsHeaders });
      } catch { return Response.json({ error: "Invalid request" }, { status: 400, headers: corsHeaders }); }
    }
    
    if (path.match(/^\/api\/room\/[\w-]+\/exists$/) && req.method === "GET") {
      const id = path.split("/")[3];
      const room = loadRoom(id);
      if (!room) return Response.json({ exists: false }, { headers: corsHeaders });
      return Response.json({ 
        exists: true, hasPassword: !!room.passwordHash, created: room.created, destruct: room.destruct 
      }, { headers: corsHeaders });
    }
    
    if (path === "/api/refresh" && req.method === "POST") {
      if (instanceSettings.skipUpdates) return Response.json({ error: "Updates disabled" }, { status: 400, headers: corsHeaders });
      const success = await fetchLatestFromGitHub();
      return Response.json({ success, size: theOneFileHtml.length }, { headers: corsHeaders });
    }
    
    if (path.match(/^\/s\/[\w-]+$/)) {
      const id = path.split("/")[2];
      const room = loadRoom(id);
      if (!room) return new Response("Room not found", { status: 404 });
      if (!theOneFileHtml) return new Response("TheOneFile not loaded", { status: 500 });

      const autosaveBlockerScript = `<script>
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
})();
</` + `script>`;

      const exposureScript = `<script>
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
            case 'PAGE_STATE': return typeof PAGE_STATE !== 'undefined' ? PAGE_STATE : {};
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
            default: return false;
          }
        } catch(e) { return false; }
      };
    }
  }, 50);
})();
</` + `script>`;

      let injectedHtml = theOneFileHtml.replace('<head>', '<head>' + autosaveBlockerScript);
      injectedHtml = injectedHtml.replace('</head>', exposureScript + '</head>');

      const saveHookScript = `<script>
(function(){
  var pendingHtmlBlobs = new Map();
  var origCreateObjectURL = URL.createObjectURL;
  var origRevokeObjectURL = URL.revokeObjectURL;

  URL.createObjectURL = function(blob) {
    var url = origCreateObjectURL.apply(URL, arguments);
    if (blob && blob.type && blob.type.indexOf('text/html') !== -1) {
      pendingHtmlBlobs.set(url, blob);
    }
    return url;
  };

  URL.revokeObjectURL = function(url) {
    pendingHtmlBlobs.delete(url);
    return origRevokeObjectURL.apply(URL, arguments);
  };

  document.addEventListener('click', function(e) {
    var anchor = e.target;
    if (!anchor.download) {
      anchor = e.target.closest ? e.target.closest('a[download]') : null;
    }
    if (!anchor || !anchor.download || !anchor.href) return;
    if (!anchor.download.endsWith('.html')) return;
    if (!anchor.href.startsWith('blob:')) return;
    if (typeof window.__collabStripHTML !== 'function') return;

    var blob = pendingHtmlBlobs.get(anchor.href);
    if (!blob) return;

    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    var reader = new FileReader();
    reader.onload = function() {
      var cleanHtml = window.__collabStripHTML(reader.result);
      var cleanBlob = new Blob([cleanHtml], {type: 'text/html'});
      var cleanUrl = origCreateObjectURL.call(URL, cleanBlob);
      var a = document.createElement('a');
      a.href = cleanUrl;
      a.download = anchor.download;
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      setTimeout(function() {
        document.body.removeChild(a);
        origRevokeObjectURL.call(URL, cleanUrl);
      }, 100);
    };
    reader.readAsText(blob);
  }, true);
})();
</` + `script>`;

      const token = getTokenFromRequest(req);
      const isAdmin = token ? validateAdminToken(token) : false;

      const configScript = `<script>
window.ROOM_ID = "${id}";
window.ROOM_HAS_PASSWORD = ${!!room.passwordHash && !isAdmin};
window.ROOM_CREATOR_ID = "${room.creatorId}";
window.WS_URL = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + "/ws/${id}";
window.ROOM_IS_ADMIN = ${isAdmin};
window.ROOM_IS_CREATOR = (function(){
  var uid = localStorage.getItem('collab-user-${id}');
  return uid && uid === "${room.creatorId}";
})();
</` + `script>
<link rel="stylesheet" href="/collab.css">
<script src="/collab.js"></` + `script>
${saveHookScript}
</body>`;
      
      injectedHtml = injectedHtml.replace(/<\/body>\s*<\/html>\s*$/i, configScript + "\n</html>");
      
      return new Response(injectedHtml, { headers: { "Content-Type": "text/html" } });
    }
    
    if (path === "/" || path === "/index.html") {
      const file = Bun.file(join(process.cwd(), "public", "index.html"));
      if (await file.exists()) return new Response(file, { headers: { "Content-Type": "text/html" } });
    }
    
    if (path === "/collab.js") {
      const file = Bun.file(join(process.cwd(), "public", "collab.js"));
      if (await file.exists()) return new Response(file, { headers: { "Content-Type": "application/javascript" } });
    }
    
    if (path === "/collab.css") {
      const file = Bun.file(join(process.cwd(), "public", "collab.css"));
      if (await file.exists()) return new Response(file, { headers: { "Content-Type": "text/css" } });
    }
    
    if (path === "/favicon.ico") {
      return new Response(null, { status: 204 });
    }
    
    return new Response("Not found", { status: 404 });
  },
  websocket: {
    open(ws) {
      const roomId = (ws.data as any)?.roomId;
      if (!roomId) return;
      if (!roomConnections.has(roomId)) roomConnections.set(roomId, new Set());
      roomConnections.get(roomId)!.add(ws);
      if (!roomUsers.has(roomId)) roomUsers.set(roomId, new Map());
      ws.subscribe(roomId);
      const meta = roomMeta.get(roomId) || { connectedUsers: 0 };
      meta.connectedUsers++;
      if (meta.destructTimer) { clearTimeout(meta.destructTimer); meta.destructTimer = undefined; }
      roomMeta.set(roomId, meta);
    },
    message(ws, message) {
      const roomId = (ws.data as any)?.roomId;
      if (!roomId) return;
      let msg;
      try { msg = JSON.parse(message.toString()); } catch { return; }
      
      if (msg.type === 'join' && msg.user) {
        const userId = msg.user.id;
        const userName = msg.user.name?.toLowerCase().trim();
        const users = roomUsers.get(roomId)!;

        if (!roomUsedNames.has(roomId)) roomUsedNames.set(roomId, new Map());
        const usedNames = roomUsedNames.get(roomId)!;

        const existingUser = users.get(userId);
        const isNameChange = existingUser && existingUser.name?.toLowerCase().trim() !== userName;
        const isNewUser = !existingUser;

        if (userName && (isNewUser || isNameChange)) {
          const nameOwner = usedNames.get(userName);
          if (nameOwner && nameOwner !== userId) {
            ws.send(JSON.stringify({ type: 'name-rejected', reason: 'Name already taken in this room' }));
            return;
          }
          if (isNameChange && existingUser?.name) {
            usedNames.delete(existingUser.name.toLowerCase().trim());
          }
          usedNames.set(userName, userId);
        }

        (ws.data as any).userId = userId;
        users.delete(userId);
        users.set(userId, msg.user);
        const existingUsers = Array.from(users.values()).filter(u => u.id !== userId);
        if (existingUsers.length > 0) ws.send(JSON.stringify({ type: 'users', users: existingUsers }));

        if (isNewUser) {
          const room = loadRoom(roomId);
          if (room && room.topology) {
            ws.send(JSON.stringify({ type: 'initial-state', state: room.topology }));
          } else {
            ws.send(JSON.stringify({ type: 'initial-state', state: null }));
          }
        }

        const connections = roomConnections.get(roomId);
        if (connections) {
          const joinMsg = JSON.stringify(msg);
          connections.forEach(client => { if (client !== ws && client.readyState === 1) client.send(joinMsg); });
        }
      } else if (msg.type === 'presence') {
        const users = roomUsers.get(roomId);
        if (users && msg.userId) {
          const user = users.get(msg.userId);
          if (user) { user.selectedNodes = msg.selectedNodes; user.editingNode = msg.editingNode; }
        }
        ws.publish(roomId, message);
      } else if (msg.type === 'state') {
        ws.publish(roomId, message);
        if (msg.state) {
          const room = loadRoom(roomId);
          if (room) { room.topology = msg.state; room.lastActivity = new Date().toISOString(); saveRoom(room); }
        }
      } else {
        ws.publish(roomId, message);
      }
      resetDestructionTimer(roomId);
    },
    close(ws) {
      const roomId = (ws.data as any)?.roomId;
      const userId = (ws.data as any)?.userId;
      if (!roomId) return;
      const connections = roomConnections.get(roomId);
      if (connections) {
        connections.delete(ws);
        if (connections.size === 0) roomConnections.delete(roomId);
      }
      if (userId) {
        const users = roomUsers.get(roomId);
        if (users) {
          users.delete(userId);
          if (connections && connections.size > 0) {
            const leaveMsg = JSON.stringify({ type: 'leave', userId });
            connections.forEach(client => { if (client.readyState === 1) client.send(leaveMsg); });
          }
          if (users.size === 0) roomUsers.delete(roomId);
        }
      }
      ws.unsubscribe(roomId);
      const meta = roomMeta.get(roomId);
      if (meta) {
        meta.connectedUsers = Math.max(0, meta.connectedUsers - 1);
        if (meta.connectedUsers === 0) {
          const room = loadRoom(roomId);
          if (room) {
            if (room.destruct.mode === "empty") { deleteRoom(roomId); }
            else if (room.destruct.mode === "time") { scheduleDestruction(roomId, room.destruct.value); }
          }
        }
      }
    }
  }
});

console.log(`TheOneFile Collab running on http://localhost:${PORT}`);
if (ENV_ADMIN_PASSWORD) console.log(`Instance password lock: ENV`);
else if (isInstanceLocked()) console.log(`Instance password lock: Settings`);
if (instanceSettings.skipUpdates) console.log(`Auto-updates: Disabled`);
else if (instanceSettings.updateIntervalHours > 0) console.log(`Auto-updates: Every ${instanceSettings.updateIntervalHours}h`);
console.log(`Admin: ${isAdminConfigured() ? 'Configured' : 'Not set up'} | Rooms: ${readdirSync(ROOMS_DIR).filter(f => f.endsWith('.json')).length}`);

readdirSync(ROOMS_DIR).forEach(file => {
  if (file.endsWith(".json")) {
    const roomId = file.replace(".json", "");
    const room = loadRoom(roomId);
    if (room && room.destruct.mode === "time") {
      const elapsed = Date.now() - new Date(room.lastActivity).getTime();
      const remaining = room.destruct.value - elapsed;
      if (remaining <= 0) { deleteRoom(roomId); }
      else { scheduleDestruction(roomId, remaining); }
    }
  }
});
