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
