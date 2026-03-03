(function() {
  'use strict';

  var forcedTheme = null;

  function getTheme() {
    if (forcedTheme && forcedTheme !== 'user') return forcedTheme;
    return localStorage.getItem('theme') || 'dark';
  }

  function setTheme(t) {
    document.documentElement.setAttribute('data-theme', t);
  }

  setTheme(getTheme());

  fetch('/api/theme').then(function(r) {
    return r.json();
  }).then(function(d) {
    if (d.forcedTheme && d.forcedTheme !== 'user') {
      forcedTheme = d.forcedTheme;
      setTheme(forcedTheme);
    }
  }).catch(function() {});

  window.__authCsrfToken = '';
  window.__authCsrfRefresh = function() {
    return fetch('/api/auth/csrf').then(function(r) {
      return r.json();
    }).then(function(d) {
      window.__authCsrfToken = d.token;
    }).catch(function() {});
  };

  window.__authRenderOidcProviders = function(containerId, dividerId, redirectSuffix) {
    fetch('/api/auth/providers').then(function(r) {
      return r.json();
    }).then(function(providers) {
      if (providers.length > 0) {
        var divider = document.getElementById(dividerId);
        if (divider) divider.style.display = 'flex';
        var container = document.getElementById(containerId);
        providers.forEach(function(p) {
          var btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'oidc-btn';
          if (p.iconUrl && (p.iconUrl.startsWith('http://') || p.iconUrl.startsWith('https://'))) {
            var img = document.createElement('img');
            img.src = p.iconUrl;
            img.width = 20;
            img.height = 20;
            btn.appendChild(img);
          }
          btn.appendChild(document.createTextNode(' Continue with ' + (p.name || '')));
          btn.addEventListener('click', function() {
            window.location.href = '/api/auth/oidc/' + p.id + '/login' + (redirectSuffix || '');
          });
          container.appendChild(btn);
        });
      }
    }).catch(function() {});
  };
})();
