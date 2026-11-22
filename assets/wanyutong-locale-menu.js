(function () {
  'use strict';

  function bindDisclosure(menu) {
    var summary = menu.querySelector('summary');
    var options = menu.querySelector('[data-wyt-disclosure-options], .wyt-language-options');

    function fitOptions() {
      if (!menu.open) return;
      options.style.removeProperty('--wyt-menu-shift');
      var bounds = options.getBoundingClientRect();
      var gutter = 8;
      var viewportRight = document.documentElement.clientWidth - gutter;
      var shift = Math.max(0, gutter - bounds.left) - Math.max(0, bounds.right - viewportRight);
      if (shift) options.style.setProperty('--wyt-menu-shift', shift + 'px');
    }

    menu.addEventListener('toggle', function () {
      if (!menu.open) return;
      document.querySelectorAll('details.wyt-language[open], details.wyt-theme[open]').forEach(function (other) {
        if (other !== menu) other.open = false;
      });
      fitOptions();
    });
    window.addEventListener('resize', fitOptions, { passive: true });
    document.addEventListener('pointerdown', function (event) {
      if (menu.open && !menu.contains(event.target)) menu.open = false;
    });
    menu.addEventListener('keydown', function (event) {
      if (menu.open && event.key === 'Escape') {
        event.preventDefault();
        menu.open = false;
        summary.focus();
      }
    });
  }

  function addThemeMenu() {
    var legacy = document.querySelector('#themeToggle, #join-theme-toggle, #article-theme-switch, #theme-button');
    if (!legacy) return;

    var labels = {
      'zh-Hant': ['明暗模式', '開燈（亮色）', '關燈（暗色）'],
      'zh-Hans': ['明暗模式', '开灯（亮色）', '关灯（暗色）'],
      en: ['Appearance', 'Lights on', 'Lights off'],
      ja: ['画面の明るさ', '点灯（ライト）', '消灯（ダーク）'],
      ko: ['화면 모드', '불 켜기 (밝게)', '불 끄기 (어둡게)'],
      id: ['Tampilan', 'Nyalakan lampu', 'Matikan lampu']
    };
    var copy = labels[document.documentElement.lang] || labels['zh-Hant'];
    var menu = document.createElement('details');
    menu.className = 'wyt-theme';

    var summary = document.createElement('summary');
    summary.title = copy[0];
    var cord = document.createElement('span');
    cord.className = 'wyt-theme-cord';
    cord.setAttribute('aria-hidden', 'true');
    summary.appendChild(cord);
    menu.appendChild(summary);

    var options = document.createElement('div');
    options.className = 'wyt-theme-options';
    options.setAttribute('data-wyt-disclosure-options', '');
    menu.appendChild(options);

    function currentMode() {
      return document.documentElement.classList.contains('light') ? 'light' : 'dark';
    }

    var modes = ['light', 'dark'];
    var buttons = modes.map(function (mode, index) {
      var button = document.createElement('button');
      button.type = 'button';
      button.textContent = copy[index + 1];
      button.setAttribute('data-wyt-theme-mode', mode);
      button.addEventListener('click', function () {
        if (currentMode() !== mode) legacy.click();
        syncTheme();
        menu.open = false;
        summary.focus();
      });
      options.appendChild(button);
      return button;
    });

    function syncTheme() {
      var active = currentMode();
      summary.setAttribute('aria-label', copy[0] + ' · ' + copy[modes.indexOf(active) + 1]);
      buttons.forEach(function (button, index) {
        button.setAttribute('aria-pressed', active === modes[index] ? 'true' : 'false');
      });
    }

    legacy.before(menu);
    legacy.setAttribute('data-wyt-theme-legacy', '');
    legacy.hidden = true;
    syncTheme();
    menu.addEventListener('toggle', function () { if (menu.open) syncTheme(); });
    bindDisclosure(menu);

    // Tapping and keyboard activation still use native disclosure behavior.
    var pullStart = null;
    var suppressClick = false;
    summary.addEventListener('pointerdown', function (event) {
      if (!event.isPrimary || event.button !== 0) return;
      pullStart = event.clientY;
      suppressClick = false;
      summary.setPointerCapture(event.pointerId);
    });
    summary.addEventListener('pointerup', function (event) {
      if (pullStart !== null && event.clientY - pullStart >= 10) {
        menu.open = true;
        suppressClick = true;
      }
      pullStart = null;
    });
    summary.addEventListener('pointercancel', function () { pullStart = null; });
    summary.addEventListener('click', function (event) {
      if (suppressClick && event.detail > 0) event.preventDefault();
      suppressClick = false;
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    var languageMenu = document.querySelector('details.wyt-language');
    if (languageMenu) bindDisclosure(languageMenu);
    addThemeMenu();
  });
})();
