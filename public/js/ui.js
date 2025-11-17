// ui.js - shared UI interactivity (hamburger nav, etc.)

(function () {
  function initNavToggle() {
    var toggle = document.querySelector('[data-nav-toggle]');
    var mobileNav = document.querySelector('[data-nav-mobile]');
    if (!toggle || !mobileNav) return;

    toggle.addEventListener('click', function () {
      var isOpen = mobileNav.getAttribute('data-open') === 'true';
      mobileNav.setAttribute('data-open', String(!isOpen));
      toggle.setAttribute('aria-expanded', String(!isOpen));
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    initNavToggle();
  });
})();
