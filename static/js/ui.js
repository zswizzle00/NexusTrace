// Shared result-page behavior: a copy button on every raw-data block.
(function () {
  'use strict';

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    // Plain-HTTP LAN access has no Clipboard API.
    var area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    var ok = document.execCommand('copy');
    document.body.removeChild(area);
    return ok ? Promise.resolve() : Promise.reject(new Error('copy failed'));
  }

  function addCopyButtons() {
    document.querySelectorAll('details.nt-raw').forEach(function (block) {
      var pre = block.querySelector('pre');
      if (!pre || block.querySelector('.nt-raw__copy')) return;
      var button = document.createElement('button');
      button.type = 'button';
      button.className = 'nt-raw__copy';
      button.textContent = 'Copy';
      button.setAttribute('aria-label', 'Copy raw data');
      button.addEventListener('click', function () {
        copyText(pre.textContent).then(function () {
          button.textContent = 'Copied';
        }, function () {
          button.textContent = 'Copy failed';
        });
        setTimeout(function () { button.textContent = 'Copy'; }, 1500);
      });
      block.insertBefore(button, pre);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', addCopyButtons);
  } else {
    addCopyButtons();
  }
})();
