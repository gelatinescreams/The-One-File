(function() {
  'use strict';

  var pageData = JSON.parse(
    (document.getElementById('page-data') || {}).textContent || '{}'
  );
  var page = document.body.dataset.page;

  if (page === 'setup') {
    window.__authRenderOidcProviders('oidc-buttons', 'divider', '');
    document.getElementById('setup-form').addEventListener('submit', async function(e) {
      e.preventDefault();
      var error = document.getElementById('error');
      error.classList.remove('active');
      var email = document.getElementById('email').value;
      var pwd = document.getElementById('password').value;
      var confirmVal = document.getElementById('confirm').value;
      if (!email || !email.includes('@')) { error.textContent = 'Please enter a valid email'; error.classList.add('active'); return; }
      if (pwd.length < 8) { error.textContent = 'Password must be at least 8 characters'; error.classList.add('active'); return; }
      if (pwd !== confirmVal) { error.textContent = 'Passwords do not match'; error.classList.add('active'); return; }
      try {
        var res = await fetch('/api/setup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email, password: pwd }) });
        var d = await res.json();
        if (res.ok && d.success) { window.location.href = '/admin'; }
        else { error.textContent = d.error || 'Setup failed'; error.classList.add('active'); }
      } catch(ex) { error.textContent = 'Connection error'; error.classList.add('active'); }
    });
  }

  else if (page === 'migration') {
    document.getElementById('migrate-form').addEventListener('submit', async function(e) {
      e.preventDefault();
      var oldPwd = document.getElementById('old-password');
      var email = document.getElementById('email');
      var newPwd = document.getElementById('new-password');
      var error = document.getElementById('error');
      error.classList.remove('active');
      if (!oldPwd.value) { error.textContent = 'Please enter your current admin password'; error.classList.add('active'); return; }
      if (!email.value || !email.value.includes('@')) { error.textContent = 'Please enter a valid email'; error.classList.add('active'); return; }
      try {
        var res = await fetch('/api/admin/migrate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ oldPassword: oldPwd.value, email: email.value, newPassword: newPwd.value || null }) });
        var d = await res.json();
        if (res.ok && d.success) { window.location.href = '/admin'; }
        else { error.textContent = d.error || 'Migration failed'; error.classList.add('active'); }
      } catch(ex) { error.textContent = 'Connection error'; error.classList.add('active'); }
    });
  }

  else if (page === 'login') {
    document.getElementById('login-form').addEventListener('submit', async function(e) {
      e.preventDefault();
      var password = document.getElementById('password').value;
      try {
        var res = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: password }) });
        if (res.ok) window.location.reload();
        else { document.getElementById('error').classList.add('active'); document.getElementById('password').value = ''; }
      } catch(ex) { document.getElementById('error').textContent = 'Connection error'; document.getElementById('error').classList.add('active'); }
    });
  }

  else if (page === 'instance-login') {
    document.getElementById('login-form').addEventListener('submit', async function(e) {
      e.preventDefault();
      try {
        var res = await fetch('/api/instance-login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: document.getElementById('password').value }) });
        if (res.ok) window.location.reload();
        else { document.getElementById('error').classList.add('active'); document.getElementById('password').value = ''; }
      } catch(ex) { document.getElementById('error').textContent = 'Connection error'; document.getElementById('error').classList.add('active'); }
    });
  }

  else if (page === 'user-login') {
    var csrfToken = '';
    var pendingToken = null;
    window.__authCsrfRefresh().then(function() { csrfToken = window.__authCsrfToken; });
    window.__authRenderOidcProviders('oidc-buttons', 'divider', '');
    document.getElementById('login-form').addEventListener('submit', async function(e) {
      e.preventDefault();
      var error = document.getElementById('error');
      error.classList.remove('active');
      if (pendingToken) {
        var code = document.getElementById('2fa-code').value.trim();
        if (!code) { error.textContent = 'Please enter your 2FA code'; error.classList.add('active'); return; }
        try {
          var res = await fetch('/api/auth/2fa/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pendingToken: pendingToken, code: code }) });
          var d = await res.json();
          if (res.ok && d.success) { var redirect = new URLSearchParams(window.location.search).get('redirect') || '/'; window.location.href = redirect; }
          else { error.textContent = d.error || 'Invalid code'; error.classList.add('active'); }
        } catch(ex) { error.textContent = 'Connection error'; error.classList.add('active'); }
        return;
      }
      var email = document.getElementById('email').value;
      var password = document.getElementById('password').value;
      if (!email || !email.includes('@')) { error.textContent = 'Please enter a valid email'; error.classList.add('active'); return; }
      if (!password) { error.textContent = 'Please enter your password'; error.classList.add('active'); return; }
      try {
        var res = await fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email, password: password, csrfToken: csrfToken }) });
        var d = await res.json();
        if (d.requires2FA) {
          pendingToken = d.pendingToken;
          document.getElementById('login-form').innerHTML = '<label for="2fa-code">Authentication Code</label><input type="text" id="2fa-code" placeholder="000000" maxlength="8" autocomplete="one-time-code" inputmode="numeric" style="text-align:center;font-size:24px;letter-spacing:8px" autofocus><button type="submit">Verify</button>';
          document.querySelector('h1').textContent = 'Two Factor Authentication';
          document.querySelector('p').textContent = 'Enter the 6 digit code from your authenticator app';
          return;
        }
        if (res.ok && d.success) { var redirect = new URLSearchParams(window.location.search).get('redirect') || '/'; window.location.href = redirect; }
        else { error.textContent = d.error || 'Invalid credentials'; error.classList.add('active'); document.getElementById('password').value = ''; fetch('/api/auth/csrf').then(function(r) { return r.json(); }).then(function(c) { csrfToken = c.token; }).catch(function() {}); }
      } catch(ex) { error.textContent = 'Connection error'; error.classList.add('active'); }
    });
  }

  else if (page === 'user-register') {
    var csrfToken = '';
    window.__authCsrfRefresh().then(function() { csrfToken = window.__authCsrfToken; });
    window.__authRenderOidcProviders('oidc-buttons', 'divider', '');

    function checkPasswordStrength(pwd) {
      if (!pwd) return { strength: '', text: '' };
      var score = 0;
      if (pwd.length >= 8) score++;
      if (pwd.length >= 12) score++;
      if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) score++;
      if (/[0-9]/.test(pwd)) score++;
      if (/[^a-zA-Z0-9]/.test(pwd)) score++;
      if (score <= 2) return { strength: 'weak', text: 'Weak: Add more characters, numbers, or symbols' };
      if (score <= 3) return { strength: 'medium', text: 'Medium: Getting better, add more variety' };
      return { strength: 'strong', text: 'Strong password' };
    }

    document.getElementById('password').addEventListener('input', function(e) {
      var result = checkPasswordStrength(e.target.value);
      var bar = document.getElementById('strength-bar');
      var txt = document.getElementById('strength-text');
      bar.className = 'password-strength-bar' + (result.strength ? ' ' + result.strength : '');
      txt.className = 'password-strength-text' + (result.strength ? ' ' + result.strength : '');
      txt.textContent = result.text;
    });

    document.getElementById('register-form').addEventListener('submit', async function(e) {
      e.preventDefault();
      var error = document.getElementById('error');
      var success = document.getElementById('success');
      error.classList.remove('active'); success.classList.remove('active');
      var email = document.getElementById('email').value;
      var displayName = document.getElementById('displayName').value;
      var password = document.getElementById('password').value;
      var confirmPassword = document.getElementById('confirmPassword').value;
      if (!email || !email.includes('@')) { error.textContent = 'Please enter a valid email'; error.classList.add('active'); return; }
      if (!password) { error.textContent = 'Please enter a password'; error.classList.add('active'); return; }
      if (password !== confirmPassword) { error.textContent = 'Passwords do not match'; error.classList.add('active'); return; }
      try {
        var res = await fetch('/api/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email, password: password, displayName: displayName || null, csrfToken: csrfToken }) });
        var d = await res.json();
        if (res.ok) {
          if (d.requiresVerification) { success.textContent = 'Account created! Please check your email to verify your account.'; success.classList.add('active'); document.getElementById('register-form').reset(); }
          else { window.location.href = '/'; }
        } else { error.textContent = d.error || 'Registration failed'; error.classList.add('active'); fetch('/api/auth/csrf').then(function(r) { return r.json(); }).then(function(c) { csrfToken = c.token; }).catch(function() {}); }
      } catch(ex) { error.textContent = 'Connection error'; error.classList.add('active'); }
    });
  }

  else if (page === 'user-forgot-password') {
    document.getElementById('forgot-form').addEventListener('submit', async function(e) {
      e.preventDefault();
      var error = document.getElementById('error');
      var success = document.getElementById('success');
      error.classList.remove('active'); success.classList.remove('active');
      var email = document.getElementById('email').value;
      if (!email || !email.includes('@')) { error.textContent = 'Please enter a valid email'; error.classList.add('active'); return; }
      try {
        var res = await fetch('/api/auth/forgot-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email }) });
        var d = await res.json();
        if (res.ok) { success.textContent = 'If an account exists with this email, a reset link has been sent.'; success.classList.add('active'); document.getElementById('email').value = ''; }
        else { error.textContent = d.error || 'Failed to send reset email'; error.classList.add('active'); }
      } catch(ex) { error.textContent = 'Connection error'; error.classList.add('active'); }
    });
  }

  else if (page === 'admin-login') {
    var adminPath = pageData.adminPath || 'admin';
    window.__authRenderOidcProviders('oidc-buttons', 'divider', '?redirect=/' + adminPath);
    var pendingToken = null;
    document.getElementById('login-form').addEventListener('submit', async function(e) {
      e.preventDefault();
      var error = document.getElementById('error');
      error.classList.remove('active');
      if (pendingToken) {
        var code = document.getElementById('2fa-code').value.trim();
        if (!code) { error.textContent = 'Please enter your 2FA code'; error.classList.add('active'); return; }
        try {
          var res = await fetch('/api/auth/2fa/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pendingToken: pendingToken, code: code }) });
          var d = await res.json();
          if (res.ok && d.success) { window.location.href = '/' + adminPath; }
          else { error.textContent = d.error || 'Invalid code'; error.classList.add('active'); }
        } catch(ex) { error.textContent = 'Connection error'; error.classList.add('active'); }
        return;
      }
      var email = document.getElementById('email').value;
      var password = document.getElementById('password').value;
      if (!email || !email.includes('@')) { error.textContent = 'Please enter a valid email'; error.classList.add('active'); return; }
      if (!password) { error.textContent = 'Please enter your password'; error.classList.add('active'); return; }
      try {
        var res = await fetch('/api/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email, password: password }) });
        var d = await res.json();
        if (d.requires2FA) {
          pendingToken = d.pendingToken;
          document.getElementById('login-form').innerHTML = '<label for="2fa-code">Authentication Code</label><input type="text" id="2fa-code" placeholder="000000" maxlength="8" autocomplete="one-time-code" inputmode="numeric" style="text-align:center;font-size:24px;letter-spacing:8px" autofocus><button type="submit">Verify</button>';
          document.querySelector('h1').textContent = 'Two Factor Authentication';
          document.querySelector('p').textContent = 'Enter the 6 digit code from your authenticator app';
          return;
        }
        if (res.ok && d.success) { window.location.href = '/' + adminPath; }
        else { error.textContent = d.error || 'Invalid credentials'; error.classList.add('active'); document.getElementById('password').value = ''; }
      } catch(ex) { error.textContent = 'Connection error'; error.classList.add('active'); }
    });
  }

  else if (page === 'password-reset') {
    document.getElementById('form').addEventListener('submit', async function(e) {
      e.preventDefault();
      var pw = document.getElementById('password').value;
      var confirmVal = document.getElementById('confirm').value;
      var err = document.getElementById('error');
      err.classList.remove('active');
      if (pw !== confirmVal) { err.textContent = 'Passwords do not match'; err.classList.add('active'); return; }
      if (pw.length < 8) { err.textContent = 'Password must be at least 8 characters'; err.classList.add('active'); return; }
      try {
        var csrfRes = await fetch('/api/auth/csrf');
        var csrfData = await csrfRes.json();
        var res = await fetch('/api/auth/reset-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: pageData.token, password: pw, csrfToken: csrfData.token }) });
        var data = await res.json();
        if (data.success) { document.getElementById('form').style.display = 'none'; document.getElementById('success').classList.add('active'); }
        else { err.textContent = data.error || 'Failed to reset password'; err.classList.add('active'); }
      } catch(ex) { err.textContent = 'Connection error'; err.classList.add('active'); }
    });
  }
})();
