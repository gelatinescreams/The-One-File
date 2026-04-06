export const setupPageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Setup - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    button,a{-webkit-tap-highlight-color:transparent}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;padding-left:max(20px,env(safe-area-inset-left,20px));padding-right:max(20px,env(safe-area-inset-right,20px));padding-bottom:max(20px,env(safe-area-inset-bottom,20px))}
    .setup-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:450px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    .subtitle{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    .info{background:rgba(201,162,39,0.1);border:1px solid rgba(201,162,39,0.3);border-radius:8px;padding:12px;margin-bottom:24px;font-size:13px;color:#c9a227}
    label{display:block;font-size:14px;color:var(--text-soft);margin-bottom:6px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
    button:hover{background:var(--accent-hover)}
    button:disabled{background:var(--border);cursor:not-allowed}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    .oidc-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:var(--bg);border:1px solid var(--border);margin-bottom:12px}
    .oidc-btn:hover{background:var(--bg-alt)}
    .divider{display:flex;align-items:center;gap:12px;margin:24px 0;color:var(--text-soft);font-size:12px}
    .divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}
    @media(max-width:640px){.setup-box,.login-box,.box{padding:24px}}
    @media(max-width:380px){.setup-box,.login-box,.box{padding:20px 16px}}
  </style>
</head>
<body data-page="setup">
  <div class="setup-box">
    <h1>Welcome to The One File Collab</h1>
    <p class="subtitle">Create your admin account to get started</p>
    <div class="info">The first user created becomes the administrator.</div>
    <div class="error" id="error"></div>
    <div id="oidc-buttons"></div>
    <div class="divider" id="divider" style="display:none">or continue with email</div>
    <form id="setup-form" novalidate>
      <label for="email">Email</label>
      <input type="email" id="email" placeholder="admin@example.com" autocomplete="email" autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" placeholder="At least 8 characters" autocomplete="new-password">
      <label for="confirm">Confirm Password</label>
      <input type="password" id="confirm" placeholder="Confirm your password" autocomplete="new-password">
      <button type="submit" id="submit-btn">Create Admin Account</button>
    </form>
  </div>
  <script src="/admin-auth.js"></script>
  <script src="/admin-pages.js"></script>
</body>
</html>`;

export const migrationPageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Migrate Admin - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    button,a{-webkit-tap-highlight-color:transparent}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;padding-left:max(20px,env(safe-area-inset-left,20px));padding-right:max(20px,env(safe-area-inset-right,20px));padding-bottom:max(20px,env(safe-area-inset-bottom,20px))}
    .setup-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:450px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    .subtitle{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    .info{background:rgba(201,162,39,0.1);border:1px solid rgba(201,162,39,0.3);border-radius:8px;padding:12px;margin-bottom:24px;font-size:13px;color:#c9a227}
    label{display:block;font-size:14px;color:var(--text-soft);margin-bottom:6px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    @media(max-width:640px){.setup-box,.login-box,.box{padding:24px}}
    @media(max-width:380px){.setup-box,.login-box,.box{padding:20px 16px}}
  </style>
</head>
<body data-page="migration">
  <div class="setup-box">
    <h1>Migrate to User Account</h1>
    <p class="subtitle">Convert your admin password to a user account</p>
    <div class="info">Enter your current admin password and a new email to create your admin user account. This is a one time migration.</div>
    <div class="error" id="error"></div>
    <form id="migrate-form" novalidate>
      <label for="old-password">Current Admin Password</label>
      <input type="password" id="old-password" placeholder="Your existing admin password" autocomplete="current-password" autofocus>
      <label for="email">Email for Admin Account</label>
      <input type="email" id="email" placeholder="admin@example.com" autocomplete="email">
      <label for="new-password">New Password (optional)</label>
      <input type="password" id="new-password" placeholder="Leave blank to keep current password" autocomplete="new-password">
      <button type="submit">Migrate Account</button>
    </form>
  </div>
  <script src="/admin-auth.js"></script>
  <script src="/admin-pages.js"></script>
</body>
</html>`;

export const loginPageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    button,a{-webkit-tap-highlight-color:transparent}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;padding-left:max(20px,env(safe-area-inset-left,20px));padding-right:max(20px,env(safe-area-inset-right,20px));padding-bottom:max(20px,env(safe-area-inset-bottom,20px))}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    @media(max-width:640px){.setup-box,.login-box,.box{padding:24px}}
    @media(max-width:380px){.setup-box,.login-box,.box{padding:20px 16px}}
  </style>
</head>
<body data-page="login">
  <div class="login-box">
    <h1>The One File Collab</h1>
    <p>This instance requires a password</p>
    <div class="error" id="error">Invalid password</div>
    <form id="login-form" novalidate>
      <input type="password" id="password" placeholder="Enter password" autofocus>
      <button type="submit">Login</button>
    </form>
  </div>
  <script src="/admin-auth.js"></script>
  <script src="/admin-pages.js"></script>
</body>
</html>`;

export const instanceLoginPageHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    button,a{-webkit-tap-highlight-color:transparent}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;padding-left:max(20px,env(safe-area-inset-left,20px));padding-right:max(20px,env(safe-area-inset-right,20px));padding-bottom:max(20px,env(safe-area-inset-bottom,20px))}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    @media(max-width:640px){.setup-box,.login-box,.box{padding:24px}}
    @media(max-width:380px){.setup-box,.login-box,.box{padding:20px 16px}}
  </style>
</head>
<body data-page="instance-login">
  <div class="login-box">
    <h1>The One File Collab</h1>
    <p>This instance requires a password to access</p>
    <div class="error" id="error">Invalid password</div>
    <form id="login-form" novalidate>
      <input type="password" id="password" placeholder="Enter password" autofocus>
      <button type="submit">Access</button>
    </form>
  </div>
  <script src="/admin-auth.js"></script>
  <script src="/admin-pages.js"></script>
</body>
</html>`;

export const userLoginHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    button,a{-webkit-tap-highlight-color:transparent}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;padding-left:max(20px,env(safe-area-inset-left,20px));padding-right:max(20px,env(safe-area-inset-right,20px));padding-bottom:max(20px,env(safe-area-inset-bottom,20px))}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    label{display:block;font-size:14px;color:var(--text-soft);margin-bottom:6px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    .success{color:#22c55e;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .success.active{display:block}
    .links{text-align:center;margin-top:20px;font-size:14px}
    .links a{color:var(--accent);text-decoration:none}
    .links a:hover{text-decoration:underline}
    .oidc-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:var(--bg);border:1px solid var(--border);margin-bottom:12px}
    .oidc-btn:hover{background:var(--bg-alt)}
    .divider{display:flex;align-items:center;gap:12px;margin:24px 0;color:var(--text-soft);font-size:12px}
    .divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}
    @media(max-width:640px){.setup-box,.login-box,.box{padding:24px}}
    @media(max-width:380px){.setup-box,.login-box,.box{padding:20px 16px}}
  </style>
</head>
<body data-page="user-login">
  <div class="login-box">
    <h1>Welcome Back</h1>
    <p>Sign in to your account</p>
    <div class="error" id="error"></div>
    <div id="oidc-buttons"></div>
    <div class="divider" id="divider" style="display:none">or continue with email</div>
    <form id="login-form" novalidate>
      <label for="email">Email</label>
      <input type="email" id="email" placeholder="you@example.com" autocomplete="email" autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" placeholder="Your password" autocomplete="current-password">
      <button type="submit">Sign In</button>
    </form>
    <div class="links">
      <a href="/auth/forgot-password">Forgot password?</a>
      <span style="margin:0 8px;color:var(--text-soft)">|</span>
      <a href="/auth/register">Create account</a>
    </div>
  </div>
  <script src="/admin-auth.js"></script>
  <script src="/admin-pages.js"></script>
</body>
</html>`;

export const userRegisterHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    button,a{-webkit-tap-highlight-color:transparent}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;padding-left:max(20px,env(safe-area-inset-left,20px));padding-right:max(20px,env(safe-area-inset-right,20px));padding-bottom:max(20px,env(safe-area-inset-bottom,20px))}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    label{display:block;font-size:14px;color:var(--text-soft);margin-bottom:6px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    .success{color:#22c55e;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .success.active{display:block}
    .links{text-align:center;margin-top:20px;font-size:14px}
    .links a{color:var(--accent);text-decoration:none}
    .links a:hover{text-decoration:underline}
    .oidc-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:var(--bg);border:1px solid var(--border);margin-bottom:12px}
    .oidc-btn:hover{background:var(--bg-alt)}
    .divider{display:flex;align-items:center;gap:12px;margin:24px 0;color:var(--text-soft);font-size:12px}
    .divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}
    .password-hint{font-size:12px;color:var(--text-soft);margin-top:-12px;margin-bottom:16px}
    .password-strength{height:4px;border-radius:2px;margin-top:-12px;margin-bottom:8px;background:var(--border);overflow:hidden}
    .password-strength-bar{height:100%;transition:all 0.3s;width:0%}
    .password-strength-bar.weak{width:33%;background:#ef4444}
    .password-strength-bar.medium{width:66%;background:#f59e0b}
    .password-strength-bar.strong{width:100%;background:#22c55e}
    .password-strength-text{font-size:11px;margin-top:-4px;margin-bottom:12px;transition:color 0.3s}
    .password-strength-text.weak{color:#ef4444}
    .password-strength-text.medium{color:#f59e0b}
    .password-strength-text.strong{color:#22c55e}
    @media(max-width:640px){.setup-box,.login-box,.box{padding:24px}}
    @media(max-width:380px){.setup-box,.login-box,.box{padding:20px 16px}}
  </style>
</head>
<body data-page="user-register">
  <div class="login-box">
    <h1>Create Account</h1>
    <p>Join The One File Collab</p>
    <div class="error" id="error"></div>
    <div class="success" id="success"></div>
    <div id="oidc-buttons"></div>
    <div class="divider" id="divider" style="display:none">or register with email</div>
    <form id="register-form" novalidate>
      <label for="email">Email</label>
      <input type="email" id="email" placeholder="you@example.com" autocomplete="email" autofocus>
      <label for="displayName">Display Name</label>
      <input type="text" id="displayName" placeholder="Your name" autocomplete="name">
      <label for="password">Password</label>
      <input type="password" id="password" placeholder="Create a password" autocomplete="new-password">
      <div class="password-strength"><div class="password-strength-bar" id="strength-bar"></div></div>
      <div class="password-strength-text" id="strength-text"></div>
      <label for="confirmPassword">Confirm Password</label>
      <input type="password" id="confirmPassword" placeholder="Confirm your password" autocomplete="new-password">
      <button type="submit">Create Account</button>
    </form>
    <div class="links">
      Already have an account? <a href="/auth/login">Sign in</a>
    </div>
  </div>
  <script src="/admin-auth.js"></script>
  <script src="/admin-pages.js"></script>
</body>
</html>`;

export const userForgotPasswordHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Forgot Password - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    button,a{-webkit-tap-highlight-color:transparent}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;padding-left:max(20px,env(safe-area-inset-left,20px));padding-right:max(20px,env(safe-area-inset-right,20px));padding-bottom:max(20px,env(safe-area-inset-bottom,20px))}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    label{display:block;font-size:14px;color:var(--text-soft);margin-bottom:6px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    .success{color:#22c55e;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .success.active{display:block}
    .links{text-align:center;margin-top:20px;font-size:14px}
    .links a{color:var(--accent);text-decoration:none}
    .links a:hover{text-decoration:underline}
    @media(max-width:640px){.setup-box,.login-box,.box{padding:24px}}
    @media(max-width:380px){.setup-box,.login-box,.box{padding:20px 16px}}
  </style>
</head>
<body data-page="user-forgot-password">
  <div class="login-box">
    <h1>Reset Password</h1>
    <p>Enter your email to receive a reset link</p>
    <div class="error" id="error"></div>
    <div class="success" id="success"></div>
    <form id="forgot-form" novalidate>
      <label for="email">Email</label>
      <input type="email" id="email" placeholder="you@example.com" autocomplete="email" autofocus>
      <button type="submit">Send Reset Link</button>
    </form>
    <div class="links">
      <a href="/auth/login">Back to login</a>
    </div>
  </div>
  <script src="/admin-auth.js"></script>
  <script src="/admin-pages.js"></script>
</body>
</html>`;

export const adminDashboardHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    button,a,.btn,.tab,.toggle,.room-checkbox,.modal-close{-webkit-tap-highlight-color:transparent}
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
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:20px;padding-left:max(20px,env(safe-area-inset-left,20px));padding-right:max(20px,env(safe-area-inset-right,20px));padding-bottom:max(80px,calc(80px + env(safe-area-inset-bottom,0px)))}
    .container{max-width:1200px;margin:0 auto}
    header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;padding-bottom:20px;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:12px}
    h1{font-size:24px;display:flex;align-items:center;gap:12px}
    .header-actions{display:flex;gap:8px;flex-wrap:wrap}
    .theme-toggle{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;cursor:pointer;font-size:14px}
    .theme-toggle:hover{background:var(--bg-alt)}
    .btn{padding:10px 20px;border-radius:8px;font-size:14px;font-weight:500;cursor:pointer;border:none;transition:all 0.15s;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:44px}
    .btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{background:var(--accent-hover)}
    .btn-secondary{background:var(--surface);color:var(--text);border:1px solid var(--border)}.btn-secondary:hover{background:var(--bg-alt)}
    .btn-danger{background:#dc2626;color:white}.btn-danger:hover{background:#b91c1c}
    .btn-success{background:#22c55e;color:white}.btn-success:hover{background:#16a34a}
    .btn-sm{padding:8px 12px;font-size:12px;min-height:44px}
    .btn:disabled{opacity:0.5;cursor:not-allowed}
    .tabs{display:flex;gap:4px;margin-bottom:24px;border-bottom:1px solid var(--border);padding-bottom:0}
    .tab{padding:12px 20px;background:transparent;border:none;color:var(--text-soft);font-size:14px;font-weight:500;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;min-height:44px}
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
    .room-header{display:grid;grid-template-columns:40px 1fr 80px 100px 80px 200px;padding:12px 16px;background:var(--bg-alt);font-size:12px;font-weight:600;color:var(--text-soft);text-transform:uppercase;gap:8px;align-items:center}
    .room-row{display:grid;grid-template-columns:40px 1fr 80px 100px 80px 200px;padding:12px 16px;border-bottom:1px solid var(--border);align-items:center;gap:8px;transition:background 0.15s}
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
    .room-actions{display:flex;gap:6px;flex-wrap:nowrap}
    #user-list .room-header,#user-list .room-row{grid-template-columns:1fr 100px 120px 100px 140px}
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
    .toggle::before{content:'';position:absolute;top:-9px;left:-4px;right:-4px;bottom:-9px}
    input[type="text"],input[type="password"],input[type="number"],input[type="email"],select{padding:10px 12px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;min-width:120px;min-height:44px}
    input:focus,select:focus{outline:none;border-color:var(--accent)}
    .modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:1000;align-items:center;justify-content:center;padding:20px;padding-bottom:max(20px,env(safe-area-inset-bottom,20px))}
    .modal-overlay.active{display:flex}
    .modal{background:var(--surface);border:1px solid var(--border);border-radius:16px;width:100%;max-width:500px}
    .modal-header{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;border-bottom:1px solid var(--border)}
    .modal-header h3{font-size:18px}
    .modal-close{background:none;border:none;color:var(--text-soft);font-size:24px;cursor:pointer;padding:4px;min-width:44px;min-height:44px;display:flex;align-items:center;justify-content:center}
    .modal-body{padding:20px}
    .info-row{display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--border);flex-wrap:wrap;gap:8px}
    .info-row:last-child{border-bottom:none}
    .info-label{color:var(--text-soft);font-size:14px}
    .info-value{font-weight:500;font-size:14px;word-break:break-all}
    .status-msg{padding:12px;border-radius:8px;margin-bottom:16px;font-size:14px}
    .status-msg.success{background:rgba(34,197,94,0.15);color:#22c55e}
    .status-msg.error{background:rgba(239,68,68,0.15);color:#ef4444}
    .tabs,#email-log-list,#activity-log-list,#audit-log-list{-webkit-overflow-scrolling:touch;scrollbar-width:none}
    .tabs::-webkit-scrollbar{display:none}
    @media(max-width:900px){.tabs{overflow-x:auto;-webkit-overflow-scrolling:touch}.room-header,.room-row{grid-template-columns:32px 1fr 80px 170px}.room-header>*:nth-child(4),.room-header>*:nth-child(5),.room-row>*:nth-child(4),.room-row>*:nth-child(5){display:none}#user-list .room-header,#user-list .room-row{grid-template-columns:1fr 80px 100px}#user-list .room-header>*:nth-child(3),#user-list .room-header>*:nth-child(4),#user-list .room-row>*:nth-child(3),#user-list .room-row>*:nth-child(4){display:none}}
    @media(max-width:640px){body{padding:12px;padding-left:max(12px,env(safe-area-inset-left,12px));padding-right:max(12px,env(safe-area-inset-right,12px));padding-bottom:max(80px,calc(80px + env(safe-area-inset-bottom,0px)))}header{flex-direction:column;align-items:flex-start}h1{font-size:20px}.stats{grid-template-columns:repeat(2,1fr);gap:8px}.stat-card{padding:12px}.stat-value{font-size:22px}.stat-label{font-size:11px}.room-header,.room-row{grid-template-columns:32px 1fr 140px}.room-header>*:nth-child(3),.room-header>*:nth-child(4),.room-header>*:nth-child(5),.room-row>*:nth-child(3),.room-row>*:nth-child(4),.room-row>*:nth-child(5){display:none}#user-list .room-header,#user-list .room-row{grid-template-columns:1fr 100px}#user-list .room-header>*:nth-child(2),#user-list .room-header>*:nth-child(3),#user-list .room-header>*:nth-child(4),#user-list .room-row>*:nth-child(2),#user-list .room-row>*:nth-child(3),#user-list .room-row>*:nth-child(4){display:none}.room-actions{justify-content:flex-end}.btn{padding:8px 12px;font-size:12px;min-height:44px}.btn-sm{padding:6px 10px;font-size:11px;min-height:44px}.section-header{flex-direction:column;align-items:flex-start}.bulk-actions{width:100%;justify-content:flex-start}.tabs{overflow-x:auto;-webkit-overflow-scrolling:touch;scrollbar-width:none}.tabs::-webkit-scrollbar{display:none}.tab{padding:12px 16px;white-space:nowrap;min-height:44px}.setting-row{flex-direction:column;align-items:flex-start}.setting-control{width:100%}.setting-control input,.setting-control select{width:100%;max-width:none}}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Admin Dashboard</h1>
      <div class="header-actions">
        <button class="theme-toggle" id="theme-toggle" data-action="toggleTheme"><span id="theme-icon"></span></button>
        <a href="/" class="btn btn-secondary">Back to App</a>
        <button class="btn btn-secondary" data-action="logout">Logout</button>
      </div>
    </header>
    <div class="tabs">
      <button class="tab active" data-action="showTab" data-tab="rooms">Rooms</button>
      <button class="tab" data-action="showTab" data-tab="users">Users</button>
      <button class="tab" data-action="showTab" data-tab="auth">Authentication</button>
      <button class="tab" data-action="showTab" data-tab="settings">Settings</button>
      <button class="tab" data-action="showTab" data-tab="logs">Logs</button>
      <button class="tab" data-action="showTab" data-tab="backups">Backups</button>
      <button class="tab" data-action="showTab" data-tab="apikeys">API Keys</button>
    </div>
    <div id="tab-rooms" class="tab-content active">
      <div class="stats" id="stats"></div>
      <div class="section-header">
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          <h2 class="section-title">All Rooms</h2>
          <input type="text" id="room-search" placeholder="Search rooms..." style="padding:8px 12px;width:100%;max-width:200px" data-action="searchRooms">
        </div>
        <div class="bulk-actions" id="bulk-actions">
          <span class="selected-count" id="selected-count">0 selected</span>
          <button class="btn btn-danger btn-sm" data-action="deleteSelected">Delete Selected</button>
          <button class="btn btn-secondary btn-sm" data-action="clearSelection">Clear</button>
        </div>
      </div>
      <div class="room-list" id="room-list"></div>
    </div>
    <div id="tab-users" class="tab-content">
      <div class="section-header">
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          <h2 class="section-title">User Management</h2>
          <input type="text" id="user-search" placeholder="Search users..." style="padding:8px 12px;width:100%;max-width:200px" data-action="searchUsers">
        </div>
        <button class="btn btn-primary" data-action="showCreateUser">Create User</button>
      </div>
      <div class="room-list" id="user-list"></div>
    </div>
    <div id="tab-auth" class="tab-content">
      <div id="auth-status"></div>
      <div class="settings-section">
        <h3>Authentication Mode</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Default Auth Mode</div><div class="setting-desc">How users can access the system</div></div>
          <div class="setting-control">
            <select id="auth-mode" data-action="saveAuthSettings">
              <option value="open">Open (Anyone can register)</option>
              <option value="registration">Registration Required</option>
              <option value="oidc_only">OIDC Only</option>
              <option value="invite_only">Invite Only</option>
              <option value="closed">Closed (No new users)</option>
            </select>
          </div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Require Email Verification</div><div class="setting-desc">Users must verify email before accessing</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-require-email-verify" data-action="toggleAuthSetting" data-setting="requireEmailVerification"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Allow Magic Link Login</div><div class="setting-desc">Users can login via email link</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-magic-link" data-action="toggleAuthSetting" data-setting="allowMagicLinkLogin"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Match OIDC Emails</div><div class="setting-desc">Auto link OIDC accounts with matching email. <span style="color:#f59e0b">Only enable with trusted providers</span></div></div>
          <div class="setting-control"><div class="toggle" id="toggle-oidc-email-match" data-action="toggleAuthSetting" data-setting="oidcEmailMatching"></div></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Security</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Production Mode</div><div class="setting-desc">Enable HTTPS secure cookies. <span style="color:#ef4444">Required for production</span></div></div>
          <div class="setting-control"><div class="toggle" id="toggle-production-mode" data-action="toggleAuthSetting" data-setting="productionMode"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">ID Token Max Age (hours)</div><div class="setting-desc">Maximum age for OIDC ID tokens before they are considered too old</div></div>
          <div class="setting-control"><input type="number" id="input-id-token-max-age" min="1" max="168" style="width:80px;padding:8px;border:1px solid #374151;border-radius:4px;background:#1f2937;color:#fff" data-action="updateAuthNumber" data-setting="idTokenMaxAgeHours"></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Email Rate Limit Window (seconds)</div><div class="setting-desc">Time window for email rate limiting</div></div>
          <div class="setting-control"><input type="number" id="input-email-rate-window" min="60" max="3600" style="width:80px;padding:8px;border:1px solid #374151;border-radius:4px;background:#1f2937;color:#fff" data-action="updateAuthNumber" data-setting="emailRateLimitWindowSeconds"></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Email Rate Limit Max Attempts</div><div class="setting-desc">Maximum email requests per address within window</div></div>
          <div class="setting-control"><input type="number" id="input-email-rate-max" min="1" max="20" style="width:80px;padding:8px;border:1px solid #374151;border-radius:4px;background:#1f2937;color:#fff" data-action="updateAuthNumber" data-setting="emailRateLimitMaxAttempts"></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Guest Access</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Allow Guest Room Creation</div><div class="setting-desc">Unregistered users can create rooms</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-guest-room-create" data-action="toggleAuthSetting" data-setting="allowGuestRoomCreation"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Allow Guest Room Join</div><div class="setting-desc">Unregistered users can join rooms</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-guest-room-join" data-action="toggleAuthSetting" data-setting="allowGuestRoomJoin"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Room Creator Guest Setting</div><div class="setting-desc">Let room creators choose guest access per room</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-room-creator-guest" data-action="toggleAuthSetting" data-setting="allowRoomCreatorGuestSetting"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Share Button</div><div class="setting-desc">Show share button in rooms</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-share-button" data-action="toggleAuthSetting" data-setting="shareButtonEnabled"></div></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>OIDC Providers</h3>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <p style="color:var(--text-soft);font-size:13px">Configure OpenID Connect providers for SSO</p>
          <button class="btn btn-primary btn-sm" data-action="showAddOidcProvider">Add Provider</button>
        </div>
        <div id="oidc-provider-list"></div>
      </div>
      <div class="settings-section">
        <h3>SMTP Configuration</h3>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <p style="color:var(--text-soft);font-size:13px">Configure email delivery for verification and notifications</p>
          <button class="btn btn-primary btn-sm" data-action="showAddSmtpConfig">Add SMTP</button>
        </div>
        <div id="smtp-config-list"></div>
      </div>
      <div class="settings-section">
        <h3>Email Templates</h3>
        <div id="email-template-list"></div>
      </div>
      <div class="settings-section">
        <h3>Email Logs</h3>
        <div style="margin-bottom:12px;display:flex;gap:12px;align-items:center"><input type="text" id="email-log-search" placeholder="Filter by email..." style="width:100%;max-width:250px" data-action="loadEmailLogs"><button class="btn btn-sm btn-secondary" data-action="clearEmailLogs">Clear All</button></div>
        <div id="email-log-list" style="max-height:300px;overflow-y:auto"></div>
      </div>
    </div>
    <div id="tab-settings" class="tab-content">
      <div id="settings-status"></div>
      <div class="settings-section">
        <h3>Instance Access</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Password Lock</div><div class="setting-desc">Require password to access the entire instance</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-instance-lock" data-action="toggleSetting" data-setting="instancePasswordEnabled"></div></div>
        </div>
        <div class="setting-row" id="instance-pwd-row" style="display:none">
          <div class="setting-info"><div class="setting-label">Instance Password</div><div class="setting-desc" id="instance-pwd-status">Set a password for instance access</div></div>
          <div class="setting-control"><input type="password" id="instance-password" placeholder="New password"><button class="btn btn-sm btn-primary" data-action="setInstancePassword">Set</button></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Admin Panel Path</div><div class="setting-desc">Custom URL path for the admin panel (default: admin)</div></div>
          <div class="setting-control"><span style="color:#8892a0;font-size:12px">/</span><input type="text" id="admin-path" placeholder="admin" style="width:100%;max-width:150px" pattern="[a-zA-Z0-9_-]+"><button class="btn btn-sm btn-primary" data-action="saveAdminPath">Save</button></div>
        </div>
        <div class="setting-row" id="admin-path-info" style="display:none">
          <div class="setting-info"><div class="setting-label"></div><div class="setting-desc" id="admin-path-current" style="color:#4ade80">Current path: /admin</div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Show Admin Link</div><div class="setting-desc">Show admin panel link in the landing page footer</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-show-admin-link" data-action="toggleSetting" data-setting="showAdminLink"></div></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>TheOneFile Source</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Source Mode</div><div class="setting-desc">Choose where to load TheOneFile from</div></div>
          <div class="setting-control">
            <select id="source-mode" data-action="changeSourceMode"><option value="github">GitHub (Auto Update)</option><option value="local">Local (Manual Upload)</option></select>
          </div>
        </div>
        <div class="setting-row" id="github-settings">
          <div class="setting-info"><div class="setting-label">Update Interval</div><div class="setting-desc">Hours between auto updates (0 = manual only)</div></div>
          <div class="setting-control"><input type="number" id="update-interval" min="0" max="168" style="width:80px"><button class="btn btn-sm btn-primary" data-action="saveUpdateInterval">Save</button></div>
        </div>
        <div class="setting-row" id="upload-row" style="display:none">
          <div class="setting-info"><div class="setting-label">Upload Local File</div><div class="setting-desc" id="upload-status">Upload your own TheOneFile HTML</div></div>
          <div class="setting-control">
            <input type="file" id="upload-file" accept=".html" style="display:none" data-action="uploadFile">
            <button class="btn btn-sm btn-primary" data-action="uploadFileClick">Choose File</button>
          </div>
        </div>
        <div style="padding:12px;background:var(--card-bg,#1a1f2e);border-radius:8px;margin-top:8px;">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
            <div>
              <span id="current-version-badge" style="font-size:18px;font-weight:700;color:var(--accent,#f0b429);"></span>
              <span id="current-edition-badge" style="font-size:12px;color:#8892a0;margin-left:8px;"></span>
            </div>
            <span id="version-status-badge" style="font-size:11px;padding:3px 8px;border-radius:4px;font-weight:600;"></span>
          </div>
          <div style="font-size:12px;color:#8892a0;margin-bottom:10px;">
            <span id="last-update-info"></span>
            <span id="file-size-info" style="margin-left:12px;"></span>
          </div>
          <div id="github-update-row" style="display:flex;gap:8px;">
            <button class="btn btn-sm btn-success" id="update-btn" data-action="triggerUpdate">Update Now</button>
            <button class="btn btn-sm" id="check-update-btn" data-action="checkForUpdates" style="background:#2a3040;color:#c8cdd5;">Check for Updates</button>
            <a href="https://github.com/gelatinescreams/The-One-File/releases" target="_blank" rel="noopener" style="font-size:12px;color:var(--accent,#f0b429);align-self:center;margin-left:auto;text-decoration:none;">Changelog</a>
          </div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Appearance</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Theme</div><div class="setting-desc">Force a theme for all users or let them choose</div></div>
          <div class="setting-control">
            <select id="forced-theme" data-action="saveForcedTheme"><option value="user">User Choice</option><option value="dark">Force Dark</option><option value="light">Force Light</option></select>
          </div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Room Defaults</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Default Self Destruct</div><div class="setting-desc">Default expiration for new rooms</div></div>
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
          <div class="setting-info"><div class="setting-label">Default Room Theme</div><div class="setting-desc">Theme preset for new rooms (from loaded file)</div></div>
          <div class="setting-control"><select id="default-room-theme"><option value="">Default (from file)</option></select></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Public Room Creation</div><div class="setting-desc">Allow anyone to create rooms</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-public-rooms" data-action="toggleSetting" data-setting="allowPublicRoomCreation"></div></div>
        </div>
        <div style="margin-top:16px"><button class="btn btn-primary" data-action="saveRoomDefaults">Save Room Settings</button></div>
      </div>
      <div class="settings-section">
        <h3>Rate Limiting</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Enable Rate Limiting</div><div class="setting-desc">Protect against brute force attacks</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-rate-limit" data-action="toggleSetting" data-setting="rateLimitEnabled"></div></div>
        </div>
        <div class="setting-row" id="rate-limit-options">
          <div class="setting-info"><div class="setting-label">Limit Settings</div><div class="setting-desc">Max attempts per time window</div></div>
          <div class="setting-control">
            <input type="number" id="rate-limit-attempts" min="1" max="100" style="width:60px">
            <span style="color:#8892a0;font-size:12px">attempts per</span>
            <input type="number" id="rate-limit-window" min="10" max="3600" style="width:70px">
            <span style="color:#8892a0;font-size:12px">seconds</span>
          </div>
        </div>
        <div style="margin-top:16px"><button class="btn btn-primary" data-action="saveRateLimitSettings">Save Rate Limit Settings</button></div>
      </div>
      <div class="settings-section">
        <h3>Collaboration Features</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Chat</div><div class="setting-desc">Enable chat in rooms</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-chat" data-action="toggleSetting" data-setting="chatEnabled"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Cursor Sharing</div><div class="setting-desc">Show other users cursors</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-cursor" data-action="toggleSetting" data-setting="cursorSharingEnabled"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Name Changes</div><div class="setting-desc">Allow users to change name after joining</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-namechange" data-action="toggleSetting" data-setting="nameChangeEnabled"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Welcome Modal</div><div class="setting-desc">Always show welcome setup when joining rooms</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-welcome-modal" data-action="toggleSetting" data-setting="forceWelcomeModal"></div></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Network Probing</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Server-Side Probing</div><div class="setting-desc">Enable real ICMP/TCP/HTTP/DNS probes from server</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-probe" data-action="toggleSetting" data-setting="probeEnabled"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Network Discovery</div><div class="setting-desc">Allow subnet scanning to discover hosts</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-discovery" data-action="toggleSetting" data-setting="discoveryEnabled"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Discovery Admin Only</div><div class="setting-desc">Restrict network discovery to admin users</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-discovery-admin" data-action="toggleSetting" data-setting="discoveryAdminOnly"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Allow Public Ranges</div><div class="setting-desc">Allow scanning non-private (public) IP ranges</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-discovery-public" data-action="toggleSetting" data-setting="discoveryAllowPublicRanges"></div></div>
        </div>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Max Scan Size</div><div class="setting-desc">Minimum CIDR prefix (larger = smaller range)</div></div>
          <div class="setting-control">
            <span style="color:#8892a0;font-size:12px">/</span>
            <input type="number" id="discovery-max-prefix" min="20" max="32" style="width:60px">
            <button class="btn btn-sm btn-primary" data-action="saveDiscoveryPrefix">Save</button>
          </div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Webhooks</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Enable Webhooks</div><div class="setting-desc">Send notifications for events</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-webhook" data-action="toggleSetting" data-setting="webhookEnabled"></div></div>
        </div>
        <div class="setting-row" id="webhook-url-row">
          <div class="setting-info"><div class="setting-label">Webhook URL</div><div class="setting-desc">POST endpoint for notifications</div></div>
          <div class="setting-control"><input type="text" id="webhook-url" placeholder="https://..." style="width:100%;max-width:250px"><button class="btn btn-sm btn-primary" data-action="saveWebhookUrl">Save</button></div>
        </div>
      </div>
      <div class="settings-section">
        <h3>Automatic Backups</h3>
        <div class="setting-row">
          <div class="setting-info"><div class="setting-label">Enable Auto Backup</div><div class="setting-desc">Automatically backup data</div></div>
          <div class="setting-control"><div class="toggle" id="toggle-backup" data-action="toggleSetting" data-setting="backupEnabled"></div></div>
        </div>
        <div class="setting-row" id="backup-options">
          <div class="setting-info"><div class="setting-label">Backup Settings</div><div class="setting-desc">Interval and retention</div></div>
          <div class="setting-control">
            <span style="color:#8892a0;font-size:12px">Every</span>
            <input type="number" id="backup-interval" min="1" max="168" style="width:60px">
            <span style="color:#8892a0;font-size:12px">hours, keep</span>
            <input type="number" id="backup-retention" min="1" max="100" style="width:60px">
            <span style="color:#8892a0;font-size:12px">backups</span>
          </div>
        </div>
        <div style="margin-top:16px"><button class="btn btn-primary" data-action="saveBackupSettings">Save Backup Settings</button></div>
      </div>
    </div>
    <div id="tab-logs" class="tab-content">
      <div class="settings-section">
        <h3>Activity Log</h3>
        <div style="margin-bottom:12px;display:flex;gap:12px;align-items:center"><input type="text" id="activity-search" placeholder="Filter by room ID..." style="width:100%;max-width:250px" data-action="loadActivityLogs"><button class="btn btn-sm btn-secondary" data-action="clearActivityLogs">Clear All</button></div>
        <div id="activity-log-list" style="max-height:400px;overflow-y:auto"></div>
      </div>
      <div class="settings-section">
        <h3>Audit Log</h3>
        <div style="margin-bottom:12px;display:flex;gap:12px;align-items:center"><input type="text" id="audit-search" placeholder="Search..." style="width:100%;max-width:250px" data-action="loadAuditLogs"><button class="btn btn-sm btn-secondary" data-action="clearAuditLogs">Clear All</button></div>
        <div id="audit-log-list" style="max-height:400px;overflow-y:auto"></div>
      </div>
    </div>
    <div id="tab-backups" class="tab-content">
      <div class="settings-section">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <h3 style="margin:0;border:none;padding:0">Backups</h3>
          <div style="display:flex;gap:8px">
            <button class="btn btn-primary btn-sm" data-action="createBackup">Create Backup</button>
            <button class="btn btn-secondary btn-sm" data-action="exportAll">Export All</button>
          </div>
        </div>
        <div id="backup-list"></div>
      </div>
    </div>
    <div id="tab-apikeys" class="tab-content">
      <div class="settings-section">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <h3 style="margin:0;border:none;padding:0">API Keys</h3>
          <button class="btn btn-primary btn-sm" data-action="showCreateApiKey">Create API Key</button>
        </div>
        <div id="apikey-list"></div>
        <div id="new-key-display" style="display:none;margin-top:16px;padding:16px;background:var(--bg);border-radius:8px">
          <p style="margin-bottom:8px;font-weight:500">New API Key Created</p>
          <p style="font-size:12px;color:var(--text-soft);margin-bottom:8px">Copy this key now. It will not be shown again.</p>
          <code id="new-key-value" style="display:block;padding:12px;background:var(--surface);border-radius:4px;word-break:break-all;font-size:12px"></code>
        </div>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="room-modal">
    <div class="modal">
      <div class="modal-header"><h3 id="modal-title">Room Details</h3><button class="modal-close" data-action="closeModal">&times;</button></div>
      <div class="modal-body" id="modal-body"></div>
    </div>
  </div>
  <div class="modal-overlay" id="apikey-modal">
    <div class="modal">
      <div class="modal-header"><h3>Create API Key</h3><button class="modal-close" data-action="closeApiKeyModal">&times;</button></div>
      <div class="modal-body">
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Name</label><input type="text" id="apikey-name" placeholder="My API Key" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Expires In (days, 0=never)</label><input type="number" id="apikey-expires" value="0" min="0" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Permissions</label>
          <label style="display:flex;align-items:center;gap:8px;margin:8px 0"><input type="checkbox" id="perm-read" checked> Read rooms</label>
          <label style="display:flex;align-items:center;gap:8px;margin:8px 0"><input type="checkbox" id="perm-write"> Write rooms</label>
          <label style="display:flex;align-items:center;gap:8px;margin:8px 0"><input type="checkbox" id="perm-admin"> Admin access</label>
        </div>
        <button class="btn btn-primary" data-action="createApiKey" style="width:100%">Create Key</button>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="user-modal">
    <div class="modal">
      <div class="modal-header"><h3>Create User</h3><button class="modal-close" data-action="closeUserModal">&times;</button></div>
      <div class="modal-body">
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Email</label><input type="email" id="user-email" placeholder="user@example.com" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Display Name</label><input type="text" id="user-displayname" placeholder="John Doe" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Password (leave blank for invite email)</label><input type="password" id="user-password" placeholder="Optional" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Role</label>
          <select id="user-role" style="width:100%"><option value="user">User</option><option value="admin">Admin</option></select>
        </div>
        <button class="btn btn-primary" data-action="createUser" style="width:100%">Create User</button>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="edit-user-modal">
    <div class="modal">
      <div class="modal-header"><h3>Edit User</h3><button class="modal-close" data-action="closeEditUserModal">&times;</button></div>
      <div class="modal-body">
        <input type="hidden" id="edit-user-id">
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Email</label><input type="email" id="edit-user-email" style="width:100%;background:var(--bg-alt)" readonly></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Display Name</label><input type="text" id="edit-user-displayname" placeholder="Display Name" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">New Password (leave blank to keep current)</label><input type="password" id="edit-user-password" placeholder="Optional" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Role</label>
          <select id="edit-user-role" style="width:100%"><option value="user">User</option><option value="admin">Admin</option></select>
        </div>
        <div style="margin-bottom:16px">
          <label style="display:flex;align-items:center;gap:8px"><input type="checkbox" id="edit-user-active"> Active</label>
          <label style="display:flex;align-items:center;gap:8px;margin-top:8px"><input type="checkbox" id="edit-user-verified"> Email Verified</label>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-secondary" data-action="resetUserPassword" style="flex:1">Send Password Reset</button>
          <button class="btn btn-primary" data-action="saveUserEdit" style="flex:1">Save</button>
        </div>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="oidc-modal">
    <div class="modal" style="max-width:550px">
      <div class="modal-header"><h3 id="oidc-modal-title">Add OIDC Provider</h3><button class="modal-close" data-action="closeOidcModal">&times;</button></div>
      <div class="modal-body">
        <input type="hidden" id="oidc-edit-id">
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Name</label><input type="text" id="oidc-name" placeholder="My Provider" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Provider Type</label>
          <select id="oidc-type" style="width:100%"><option value="generic">Generic OIDC</option><option value="authentik">Authentik</option><option value="keycloak">Keycloak</option><option value="auth0">Auth0</option><option value="okta">Okta</option></select>
        </div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Client ID</label><input type="text" id="oidc-client-id" placeholder="client-id" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Client Secret</label><input type="password" id="oidc-client-secret" placeholder="client-secret" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Issuer URL</label><input type="text" id="oidc-issuer" placeholder="https://auth.example.com" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Authorization URL</label><input type="text" id="oidc-auth-url" placeholder="https://auth.example.com/authorize" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Token URL</label><input type="text" id="oidc-token-url" placeholder="https://auth.example.com/token" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Userinfo URL</label><input type="text" id="oidc-userinfo-url" placeholder="https://auth.example.com/userinfo" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Scopes</label><input type="text" id="oidc-scopes" value="openid email profile" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:flex;align-items:center;gap:8px"><input type="checkbox" id="oidc-active" checked> Active</label></div>
        <button class="btn btn-primary" data-action="saveOidcProvider" style="width:100%">Save Provider</button>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="smtp-modal">
    <div class="modal" style="max-width:550px">
      <div class="modal-header"><h3 id="smtp-modal-title">Add SMTP Configuration</h3><button class="modal-close" data-action="closeSmtpModal">&times;</button></div>
      <div class="modal-body">
        <input type="hidden" id="smtp-edit-id">
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Name</label><input type="text" id="smtp-name" placeholder="Primary SMTP" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Host</label><input type="text" id="smtp-host" placeholder="smtp.example.com" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Port</label><input type="number" id="smtp-port" value="587" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Security Mode</label>
          <select id="smtp-secure-mode" style="width:100%"><option value="starttls">STARTTLS (587)</option><option value="tls">TLS/SSL (465)</option><option value="none">None (25)</option></select>
        </div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Username</label><input type="text" id="smtp-username" placeholder="user@example.com" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Password</label><input type="password" id="smtp-password" placeholder="password" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">From Email</label><input type="email" id="smtp-from-email" placeholder="noreply@example.com" style="width:100%"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">From Name</label><input type="text" id="smtp-from-name" placeholder="TheOneFile_Verse" style="width:100%"></div>
        <div style="margin-bottom:16px">
          <label style="display:flex;align-items:center;gap:8px"><input type="checkbox" id="smtp-default"> Set as default</label>
          <label style="display:flex;align-items:center;gap:8px;margin-top:8px"><input type="checkbox" id="smtp-active" checked> Active</label>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-secondary" data-action="testSmtpConfig" style="flex:1">Test</button>
          <button class="btn btn-primary" data-action="saveSmtpConfig" style="flex:1">Save</button>
        </div>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="template-modal">
    <div class="modal" style="max-width:900px;max-height:90vh;display:flex;flex-direction:column">
      <div class="modal-header"><h3 id="template-modal-title">Edit Email Template</h3><button class="modal-close" data-action="closeTemplateModal">&times;</button></div>
      <div class="modal-body" style="flex:1;overflow:auto;display:flex;flex-direction:column">
        <input type="hidden" id="template-edit-id">
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Template Name</label><input type="text" id="template-name" readonly style="width:100%;background:var(--bg-alt)"></div>
        <div style="margin-bottom:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Subject</label><input type="text" id="template-subject" placeholder="Email subject with {{variables}}" style="width:100%"></div>
        <div style="margin-bottom:8px;display:flex;justify-content:space-between;align-items:center">
          <label style="font-size:14px">HTML Body</label>
          <div style="display:flex;gap:4px">
            <button class="btn btn-sm btn-secondary" data-action="insertTemplateVar" data-varname="displayName">{{displayName}}</button>
            <button class="btn btn-sm btn-secondary" data-action="insertTemplateVar" data-varname="actionUrl">{{actionUrl}}</button>
            <button class="btn btn-sm btn-secondary" data-action="insertTemplateVar" data-varname="appName">{{appName}}</button>
            <button class="btn btn-sm btn-secondary" data-action="toggleTemplateView">Toggle HTML/Preview</button>
          </div>
        </div>
        <div style="flex:1;min-height:300px;position:relative">
          <div id="template-editor-toolbar" style="background:var(--bg-alt);border:1px solid var(--border);border-bottom:none;border-radius:8px 8px 0 0;padding:8px;display:flex;gap:4px;flex-wrap:wrap">
            <button type="button" class="btn btn-sm btn-secondary" data-action="execCmd" data-cmd="bold" title="Bold"><b>B</b></button>
            <button type="button" class="btn btn-sm btn-secondary" data-action="execCmd" data-cmd="italic" title="Italic"><i>I</i></button>
            <button type="button" class="btn btn-sm btn-secondary" data-action="execCmd" data-cmd="underline" title="Underline"><u>U</u></button>
            <span style="border-left:1px solid var(--border);margin:0 4px"></span>
            <button type="button" class="btn btn-sm btn-secondary" data-action="execCmd" data-cmd="justifyLeft" title="Align Left">&#8676;</button>
            <button type="button" class="btn btn-sm btn-secondary" data-action="execCmd" data-cmd="justifyCenter" title="Center">&#8596;</button>
            <button type="button" class="btn btn-sm btn-secondary" data-action="execCmd" data-cmd="justifyRight" title="Align Right">&#8677;</button>
            <span style="border-left:1px solid var(--border);margin:0 4px"></span>
            <button type="button" class="btn btn-sm btn-secondary" data-action="execCmd" data-cmd="insertUnorderedList" title="Bullet List">&#8226;</button>
            <button type="button" class="btn btn-sm btn-secondary" data-action="execCmd" data-cmd="insertOrderedList" title="Numbered List">1.</button>
            <span style="border-left:1px solid var(--border);margin:0 4px"></span>
            <select data-action="execCmdArg" data-cmd="formatBlock" style="padding:4px 8px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px">
              <option value="">Heading</option>
              <option value="h1">Heading 1</option>
              <option value="h2">Heading 2</option>
              <option value="h3">Heading 3</option>
              <option value="p">Paragraph</option>
            </select>
            <select data-action="execCmdArg" data-cmd="fontSize" style="padding:4px 8px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px">
              <option value="">Size</option>
              <option value="1">Small</option>
              <option value="3">Normal</option>
              <option value="5">Large</option>
              <option value="7">Huge</option>
            </select>
            <input type="color" id="template-color" data-action="templateColor" title="Text Color" style="width:30px;height:26px;padding:0;border:1px solid var(--border);border-radius:4px;cursor:pointer">
            <span style="border-left:1px solid var(--border);margin:0 4px"></span>
            <button type="button" class="btn btn-sm btn-secondary" data-action="insertLink" title="Insert Link">&#128279;</button>
            <button type="button" class="btn btn-sm btn-secondary" data-action="insertImage" title="Insert Image">&#128247;</button>
            <button type="button" class="btn btn-sm btn-secondary" data-action="insertButton" title="Insert Button">&#9634; Btn</button>
          </div>
          <div id="template-editor" contenteditable="true" style="flex:1;min-height:250px;background:var(--surface);border:1px solid var(--border);border-radius:0 0 8px 8px;padding:16px;overflow-y:auto;font-family:system-ui;line-height:1.6"></div>
          <textarea id="template-html-source" style="display:none;width:100%;min-height:300px;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;font-family:monospace;font-size:13px;color:var(--text);resize:vertical"></textarea>
        </div>
        <div style="margin-top:16px"><label style="display:block;margin-bottom:4px;font-size:14px">Plain Text Body (fallback)</label><textarea id="template-text" placeholder="Plain text version for email clients that don't support HTML" style="width:100%;height:100px;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px;font-family:monospace;font-size:13px;color:var(--text);resize:vertical"></textarea></div>
        <div style="margin-top:16px;display:flex;gap:8px;justify-content:flex-end">
          <button class="btn btn-secondary" data-action="previewTemplate">Preview</button>
          <button class="btn btn-primary" data-action="saveTemplate">Save Template</button>
        </div>
      </div>
    </div>
  </div>
  <div class="modal-overlay" id="template-preview-modal">
    <div class="modal" style="max-width:700px;max-height:80vh">
      <div class="modal-header"><h3>Email Preview</h3><button class="modal-close" data-action="closeTemplatePreview">&times;</button></div>
      <div class="modal-body" style="padding:0">
        <div style="padding:12px 16px;background:var(--bg-alt);border-bottom:1px solid var(--border)">
          <div style="font-size:12px;color:var(--text-soft)">Subject:</div>
          <div id="preview-subject" style="font-weight:500"></div>
        </div>
        <iframe id="preview-frame" style="width:100%;height:400px;border:none;background:#fff"></iframe>
      </div>
    </div>
  </div>
  <script type="application/json" id="page-data">{"adminPath":"ADMIN_PATH_PLACEHOLDER"}</script>
  <script src="/admin-dashboard.js"></script>
</body>
</html>`;

export const adminLoginHtml = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login - The One File Collab</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    button,a{-webkit-tap-highlight-color:transparent}
    :root{--bg:#0d0d0d;--bg-alt:#1a1a1a;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    [data-theme="light"]{--bg:#f5f3ef;--bg-alt:#eae7e0;--surface:#fff;--border:#d4d0c8;--text:#1a1a1a;--text-soft:#666;--accent:#996b1f;--accent-hover:#7a5518}
    body{font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;padding-left:max(20px,env(safe-area-inset-left,20px));padding-right:max(20px,env(safe-area-inset-right,20px));padding-bottom:max(20px,env(safe-area-inset-bottom,20px))}
    .login-box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    label{display:block;font-size:14px;color:var(--text-soft);margin-bottom:6px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer;margin-top:8px}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    .back-link{text-align:center;margin-top:20px}
    .back-link a{color:var(--accent);text-decoration:none;font-size:14px}
    .oidc-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:var(--bg);border:1px solid var(--border);margin-bottom:12px}
    .oidc-btn:hover{background:var(--bg-alt)}
    .divider{display:flex;align-items:center;gap:12px;margin:24px 0;color:var(--text-soft);font-size:12px}
    .divider::before,.divider::after{content:'';flex:1;height:1px;background:var(--border)}
    @media(max-width:640px){.setup-box,.login-box,.box{padding:24px}}
    @media(max-width:380px){.setup-box,.login-box,.box{padding:20px 16px}}
  </style>
</head>
<body data-page="admin-login">
  <div class="login-box">
    <h1>Admin Login</h1>
    <p>Sign in with your admin account</p>
    <div class="error" id="error"></div>
    <div id="oidc-buttons"></div>
    <div class="divider" id="divider" style="display:none">or continue with email</div>
    <form id="login-form" novalidate>
      <label for="email">Email</label>
      <input type="email" id="email" placeholder="admin@example.com" autocomplete="email" autofocus>
      <label for="password">Password</label>
      <input type="password" id="password" placeholder="Your password" autocomplete="current-password">
      <button type="submit">Login</button>
    </form>
    <div class="back-link"><a href="/">Back to App</a></div>
  </div>
  <script type="application/json" id="page-data">{"adminPath":"ADMIN_PATH_PLACEHOLDER"}</script>
  <script src="/admin-auth.js"></script>
  <script src="/admin-pages.js"></script>
</body>
</html>`;

export function getPasswordResetHtml(token: string): string {
  const safePageData = JSON.stringify({ token }).replace(/</g, '\\u003c');
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Password - TheOneFile_Verse</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    button,a{-webkit-tap-highlight-color:transparent}
    :root{--bg:#0d0d0d;--surface:#242424;--border:#333;--text:#e8e8e8;--text-soft:#999;--accent:#c9a227;--accent-hover:#d4b23a}
    body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;padding-left:max(20px,env(safe-area-inset-left,20px));padding-right:max(20px,env(safe-area-inset-right,20px));padding-bottom:max(20px,env(safe-area-inset-bottom,20px))}
    .box{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:40px;width:100%;max-width:400px}
    h1{font-size:24px;margin-bottom:8px;text-align:center}
    p{color:var(--text-soft);font-size:14px;text-align:center;margin-bottom:32px}
    input{width:100%;padding:14px 16px;background:var(--bg);border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:16px;margin-bottom:16px;outline:none}
    input:focus{border-color:var(--accent)}
    button{width:100%;padding:14px;background:var(--accent);border:none;border-radius:8px;color:white;font-size:16px;font-weight:600;cursor:pointer}
    button:hover{background:var(--accent-hover)}
    .error{color:#ef4444;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .error.active{display:block}
    .success{color:#22c55e;font-size:14px;text-align:center;margin-bottom:16px;display:none}
    .success.active{display:block}
    @media(max-width:640px){.setup-box,.login-box,.box{padding:24px}}
    @media(max-width:380px){.setup-box,.login-box,.box{padding:20px 16px}}
  </style>
</head>
<body data-page="password-reset">
  <div class="box">
    <h1>Reset Password</h1>
    <p>Enter your new password</p>
    <div class="error" id="error"></div>
    <div class="success" id="success">Password reset successfully! <a href="/" style="color:var(--accent)">Go to home</a></div>
    <form id="form" novalidate>
      <input type="password" id="password" placeholder="New password (min 8 characters)" minlength="8" required autocomplete="new-password">
      <input type="password" id="confirm" placeholder="Confirm password" required autocomplete="new-password">
      <button type="submit">Reset Password</button>
    </form>
  </div>
  <script type="application/json" id="page-data">${safePageData}</script>
  <script src="/admin-auth.js"></script>
  <script src="/admin-pages.js"></script>
</body>
</html>`;
}
