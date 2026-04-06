(function() {
  'use strict';

  function withFormLoading(form, fn) {
    return async function(e) {
      e.preventDefault();
      var btn = form.querySelector('button[type="submit"], button:not([type])');
      if (btn) btn.disabled = true;
      try { await fn.call(this, e); }
      finally { if (btn) btn.disabled = false; }
    };
  }

  var pageData = JSON.parse(
    (document.getElementById('page-data') || {}).textContent || '{}'
  );
  var page = document.body.dataset.page;

  function build2FAForm(form) {
    while (form.firstChild) form.removeChild(form.firstChild);
    var label = document.createElement('label');
    label.setAttribute('for', '2fa-code');
    label.textContent = 'Authentication Code';
    var input = document.createElement('input');
    input.type = 'text';
    input.id = '2fa-code';
    input.placeholder = '000000';
    input.maxLength = 8;
    input.autocomplete = 'one-time-code';
    input.inputMode = 'numeric';
    input.setAttribute('style', 'text-align:center;font-size:24px;letter-spacing:8px');
    input.autofocus = true;
    var btn = document.createElement('button');
    btn.type = 'submit';
    btn.textContent = 'Verify';
    form.appendChild(label);
    form.appendChild(input);
    form.appendChild(btn);
  }

  if (page === 'setup') {
    window.__authRenderOidcProviders('oidc-buttons', 'divider', '');
    var setupForm = document.getElementById('setup-form');
    setupForm.addEventListener('submit', withFormLoading(setupForm, async function() {
      var error = document.getElementById('error');
      error.classList.remove('active');
      var email = document.getElementById('email').value;
      var pwd = document.getElementById('password').value;
      var confirmVal = document.getElementById('confirm').value;
      if (!email || !email.includes('@')) { error.textContent = 'Please enter a valid email'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
      if (pwd.length < 8) { error.textContent = 'Password must be at least 8 characters'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
      if (pwd !== confirmVal) { error.textContent = 'Passwords do not match'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
      try {
        var res = await fetch('/api/setup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email, password: pwd }) });
        var d = await res.json();
        if (res.ok && d.success) { window.location.href = '/' + (pageData.adminPath || 'admin'); }
        else { error.textContent = d.error || 'Setup failed'; error.setAttribute('role', 'alert'); error.classList.add('active'); }
      } catch(ex) { error.textContent = 'Connection error'; error.setAttribute('role', 'alert'); error.classList.add('active'); }
    }));
  }

  else if (page === 'migration') {
    var migrateForm = document.getElementById('migrate-form');
    migrateForm.addEventListener('submit', withFormLoading(migrateForm, async function() {
      var oldPwd = document.getElementById('old-password');
      var email = document.getElementById('email');
      var newPwd = document.getElementById('new-password');
      var error = document.getElementById('error');
      error.classList.remove('active');
      if (!oldPwd.value) { error.textContent = 'Please enter your current admin password'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
      if (!email.value || !email.value.includes('@')) { error.textContent = 'Please enter a valid email'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
      try {
        var res = await fetch('/api/admin/migrate', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ oldPassword: oldPwd.value, email: email.value, newPassword: newPwd.value || null }) });
        var d = await res.json();
        if (res.ok && d.success) { window.location.href = '/' + (pageData.adminPath || 'admin'); }
        else { error.textContent = d.error || 'Migration failed'; error.setAttribute('role', 'alert'); error.classList.add('active'); }
      } catch(ex) { error.textContent = 'Connection error'; error.setAttribute('role', 'alert'); error.classList.add('active'); }
    }));
  }

  else if (page === 'login') {
    var loginForm = document.getElementById('login-form');
    loginForm.addEventListener('submit', withFormLoading(loginForm, async function() {
      var password = document.getElementById('password').value;
      try {
        var res = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: password }) });
        if (res.ok) window.location.reload();
        else { document.getElementById('error').setAttribute('role', 'alert'); document.getElementById('error').classList.add('active'); document.getElementById('password').value = ''; }
      } catch(ex) { document.getElementById('error').textContent = 'Connection error'; document.getElementById('error').setAttribute('role', 'alert'); document.getElementById('error').classList.add('active'); }
    }));
  }

  else if (page === 'instance-login') {
    var instanceForm = document.getElementById('login-form');
    instanceForm.addEventListener('submit', withFormLoading(instanceForm, async function() {
      try {
        var res = await fetch('/api/instance-login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: document.getElementById('password').value }) });
        if (res.ok) window.location.reload();
        else { document.getElementById('error').setAttribute('role', 'alert'); document.getElementById('error').classList.add('active'); document.getElementById('password').value = ''; }
      } catch(ex) { document.getElementById('error').textContent = 'Connection error'; document.getElementById('error').setAttribute('role', 'alert'); document.getElementById('error').classList.add('active'); }
    }));
  }

  else if (page === 'user-login') {
    var csrfToken = '';
    var pendingToken = null;
    window.__authCsrfRefresh().then(function() { csrfToken = window.__authCsrfToken; });
    window.__authRenderOidcProviders('oidc-buttons', 'divider', '');
    var userLoginForm = document.getElementById('login-form');
    userLoginForm.addEventListener('submit', withFormLoading(userLoginForm, async function() {
      var error = document.getElementById('error');
      error.classList.remove('active');
      if (pendingToken) {
        var code = document.getElementById('2fa-code').value.trim();
        if (!code) { error.textContent = 'Please enter your 2FA code'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
        try {
          var res = await fetch('/api/auth/2fa/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pendingToken: pendingToken, code: code }) });
          var d = await res.json();
          if (res.ok && d.success) { var redirect = new URLSearchParams(window.location.search).get('redirect') || '/'; if (redirect.startsWith('/') && !redirect.startsWith('//')) { window.location.href = redirect; } else { window.location.href = '/'; } }
          else { error.textContent = d.error || 'Invalid code'; error.setAttribute('role', 'alert'); error.classList.add('active'); }
        } catch(ex) { error.textContent = 'Connection error'; error.setAttribute('role', 'alert'); error.classList.add('active'); }
        return;
      }
      var email = document.getElementById('email').value;
      var password = document.getElementById('password').value;
      if (!email || !email.includes('@')) { error.textContent = 'Please enter a valid email'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
      if (!password) { error.textContent = 'Please enter your password'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
      try {
        var res = await fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email, password: password, csrfToken: csrfToken }) });
        var d = await res.json();
        if (d.requires2FA) {
          pendingToken = d.pendingToken;
          build2FAForm(userLoginForm);
          document.querySelector('h1').textContent = 'Two Factor Authentication';
          document.querySelector('p').textContent = 'Enter the 6 digit code from your authenticator app';
          return;
        }
        if (res.ok && d.success) { var redirect = new URLSearchParams(window.location.search).get('redirect') || '/'; if (redirect.startsWith('/') && !redirect.startsWith('//')) { window.location.href = redirect; } else { window.location.href = '/'; } }
        else { error.textContent = d.error || 'Invalid credentials'; error.setAttribute('role', 'alert'); error.classList.add('active'); document.getElementById('password').value = ''; fetch('/api/auth/csrf').then(function(r) { return r.json(); }).then(function(c) { csrfToken = c.token; }).catch(function() {}); }
      } catch(ex) { error.textContent = 'Connection error'; error.setAttribute('role', 'alert'); error.classList.add('active'); }
    }));
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

    var registerForm = document.getElementById('register-form');
    registerForm.addEventListener('submit', withFormLoading(registerForm, async function() {
      var error = document.getElementById('error');
      var success = document.getElementById('success');
      error.classList.remove('active'); success.classList.remove('active');
      var email = document.getElementById('email').value;
      var displayName = document.getElementById('displayName').value;
      var password = document.getElementById('password').value;
      var confirmPassword = document.getElementById('confirmPassword').value;
      if (!email || !email.includes('@')) { error.textContent = 'Please enter a valid email'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
      if (!password) { error.textContent = 'Please enter a password'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
      if (password !== confirmPassword) { error.textContent = 'Passwords do not match'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
      try {
        var res = await fetch('/api/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email, password: password, displayName: displayName || null, csrfToken: csrfToken }) });
        var d = await res.json();
        if (res.ok) {
          if (d.requiresVerification) { success.textContent = 'Account created! Please check your email to verify your account.'; success.classList.add('active'); registerForm.reset(); }
          else { window.location.href = '/'; }
        } else { error.textContent = d.error || 'Registration failed'; error.setAttribute('role', 'alert'); error.classList.add('active'); fetch('/api/auth/csrf').then(function(r) { return r.json(); }).then(function(c) { csrfToken = c.token; }).catch(function() {}); }
      } catch(ex) { error.textContent = 'Connection error'; error.setAttribute('role', 'alert'); error.classList.add('active'); }
    }));
  }

  else if (page === 'user-forgot-password') {
    var forgotForm = document.getElementById('forgot-form');
    forgotForm.addEventListener('submit', withFormLoading(forgotForm, async function() {
      var error = document.getElementById('error');
      var success = document.getElementById('success');
      error.classList.remove('active'); success.classList.remove('active');
      var email = document.getElementById('email').value;
      if (!email || !email.includes('@')) { error.textContent = 'Please enter a valid email'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
      try {
        var res = await fetch('/api/auth/forgot-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email }) });
        var d = await res.json();
        if (res.ok) { success.textContent = 'If an account exists with this email, a reset link has been sent.'; success.classList.add('active'); document.getElementById('email').value = ''; }
        else { error.textContent = d.error || 'Failed to send reset email'; error.setAttribute('role', 'alert'); error.classList.add('active'); }
      } catch(ex) { error.textContent = 'Connection error'; error.setAttribute('role', 'alert'); error.classList.add('active'); }
    }));
  }

  else if (page === 'admin-login') {
    var adminPath = pageData.adminPath || 'admin';
    window.__authRenderOidcProviders('oidc-buttons', 'divider', '?redirect=/' + adminPath);
    var pendingToken = null;
    var adminLoginForm = document.getElementById('login-form');
    adminLoginForm.addEventListener('submit', withFormLoading(adminLoginForm, async function() {
      var error = document.getElementById('error');
      error.classList.remove('active');
      if (pendingToken) {
        var code = document.getElementById('2fa-code').value.trim();
        if (!code) { error.textContent = 'Please enter your 2FA code'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
        try {
          var res = await fetch('/api/auth/2fa/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pendingToken: pendingToken, code: code }) });
          var d = await res.json();
          if (res.ok && d.success) { window.location.href = '/' + adminPath; }
          else { error.textContent = d.error || 'Invalid code'; error.setAttribute('role', 'alert'); error.classList.add('active'); }
        } catch(ex) { error.textContent = 'Connection error'; error.setAttribute('role', 'alert'); error.classList.add('active'); }
        return;
      }
      var email = document.getElementById('email').value;
      var password = document.getElementById('password').value;
      if (!email || !email.includes('@')) { error.textContent = 'Please enter a valid email'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
      if (!password) { error.textContent = 'Please enter your password'; error.setAttribute('role', 'alert'); error.classList.add('active'); return; }
      try {
        var res = await fetch('/api/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: email, password: password }) });
        var d = await res.json();
        if (d.requires2FA) {
          pendingToken = d.pendingToken;
          build2FAForm(adminLoginForm);
          document.querySelector('h1').textContent = 'Two Factor Authentication';
          document.querySelector('p').textContent = 'Enter the 6 digit code from your authenticator app';
          return;
        }
        if (res.ok && d.success) { window.location.href = '/' + adminPath; }
        else { error.textContent = d.error || 'Invalid credentials'; error.setAttribute('role', 'alert'); error.classList.add('active'); document.getElementById('password').value = ''; }
      } catch(ex) { error.textContent = 'Connection error'; error.setAttribute('role', 'alert'); error.classList.add('active'); }
    }));
  }

  else if (page === 'password-reset') {
    var resetForm = document.getElementById('form');
    resetForm.addEventListener('submit', withFormLoading(resetForm, async function() {
      var pw = document.getElementById('password').value;
      var confirmVal = document.getElementById('confirm').value;
      var err = document.getElementById('error');
      err.classList.remove('active');
      if (pw !== confirmVal) { err.textContent = 'Passwords do not match'; err.setAttribute('role', 'alert'); err.classList.add('active'); return; }
      if (pw.length < 8) { err.textContent = 'Password must be at least 8 characters'; err.setAttribute('role', 'alert'); err.classList.add('active'); return; }
      try {
        var csrfRes = await fetch('/api/auth/csrf');
        var csrfData = await csrfRes.json();
        var res = await fetch('/api/auth/reset-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: pageData.token, password: pw, csrfToken: csrfData.token }) });
        var data = await res.json();
        if (data.success) { resetForm.style.display = 'none'; document.getElementById('success').classList.add('active'); }
        else { err.textContent = data.error || 'Failed to reset password'; err.setAttribute('role', 'alert'); err.classList.add('active'); }
      } catch(ex) { err.textContent = 'Connection error'; err.setAttribute('role', 'alert'); err.classList.add('active'); }
    }));
  }
})();
