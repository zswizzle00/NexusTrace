// Header behavior: the Tools and account menus are <details> elements, so they open
// without script; this closes them on an outside click, on Escape, and when another
// one opens. "/" focuses the header search, as on most search-first tools.
(function () {
  'use strict';

  function menus() {
    return document.querySelectorAll('.nt-header details.nt-menu');
  }

  function closeAll(except) {
    menus().forEach(function (menu) {
      if (menu !== except) menu.removeAttribute('open');
    });
  }

  // Full-height pages (CyberChef) sit below the header, whose height changes when the
  // search box wraps onto its own row on narrow screens.
  function publishHeaderHeight() {
    var header = document.querySelector('.nt-header');
    if (header) {
      document.documentElement.style.setProperty('--header-height', header.offsetHeight + 'px');
    }
  }
  publishHeaderHeight();
  window.addEventListener('resize', publishHeaderHeight);

  document.addEventListener('toggle', function (event) {
    var menu = event.target;
    if (menu.matches && menu.matches('details.nt-menu') && menu.open) closeAll(menu);
  }, true);

  document.addEventListener('click', function (event) {
    if (!event.target.closest('details.nt-menu')) closeAll(null);
  });

  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') {
      var open = document.querySelector('.nt-header details.nt-menu[open]');
      if (open) {
        open.removeAttribute('open');
        open.querySelector('summary').focus();
      }
      return;
    }
    if (event.key !== '/' || event.ctrlKey || event.metaKey || event.altKey) return;
    var target = event.target;
    var typing = target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName);
    var box = document.getElementById('nt-omnibox');
    if (box && !typing) {
      event.preventDefault();
      box.focus();
    }
  });
})();
