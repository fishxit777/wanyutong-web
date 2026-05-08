(function () {
  'use strict';

  var TOP_FLAG = 'wyt-force-top';
  var userScrollIntent = false;
  var topTimers = [];
  var topFrames = [];

  if ('scrollRestoration' in window.history) {
    window.history.scrollRestoration = 'manual';
  }

  function hasAnchor() {
    return window.location.hash && window.location.hash.length > 1;
  }

  function clearTopQueue() {
    while (topTimers.length) {
      window.clearTimeout(topTimers.pop());
    }
    while (topFrames.length) {
      window.cancelAnimationFrame(topFrames.pop());
    }
  }

  function queueTopTimer(delay, force) {
    var id = window.setTimeout(function () {
      var index = topTimers.indexOf(id);
      if (index !== -1) topTimers.splice(index, 1);
      goTop(force);
    }, delay);
    topTimers.push(id);
  }

  function queueTopFrame(force) {
    var id = window.requestAnimationFrame(function () {
      var index = topFrames.indexOf(id);
      if (index !== -1) topFrames.splice(index, 1);
      goTop(force);
    });
    topFrames.push(id);
  }

  function goTop(force) {
    if (!force && hasAnchor()) return;
    if (!force && userScrollIntent) return;
    var root = document.documentElement;
    var body = document.body;
    var rootScrollBehavior = root ? root.style.scrollBehavior : '';
    var bodyScrollBehavior = body ? body.style.scrollBehavior : '';
    var rootOverflowAnchor = root ? root.style.overflowAnchor : '';
    var bodyOverflowAnchor = body ? body.style.overflowAnchor : '';

    if (root) {
      root.style.scrollBehavior = 'auto';
      root.style.overflowAnchor = 'none';
    }
    if (body) {
      body.style.scrollBehavior = 'auto';
      body.style.overflowAnchor = 'none';
    }

    try {
      window.scrollTo({ top: 0, left: 0, behavior: 'instant' });
    } catch (e) {
      window.scrollTo(0, 0);
    }
    if (document.documentElement) {
      document.documentElement.scrollTop = 0;
      document.documentElement.scrollLeft = 0;
    }
    if (document.body) {
      document.body.scrollTop = 0;
      document.body.scrollLeft = 0;
    }
    if (document.scrollingElement) {
      document.scrollingElement.scrollTop = 0;
      document.scrollingElement.scrollLeft = 0;
    }

    window.setTimeout(function () {
      if (root) {
        root.style.scrollBehavior = rootScrollBehavior;
        root.style.overflowAnchor = rootOverflowAnchor;
      }
      if (body) {
        body.style.scrollBehavior = bodyScrollBehavior;
        body.style.overflowAnchor = bodyOverflowAnchor;
      }
    }, 120);
  }

  function goTopSoon(force) {
    clearTopQueue();
    goTop(force);
    queueTopFrame(force);
    queueTopTimer(80, force);
  }

  function markUserScrollIntent(event) {
    if (event && event.type === 'keydown') {
      var keys = ['ArrowDown', 'ArrowUp', 'PageDown', 'PageUp', 'Home', 'End', ' '];
      if (keys.indexOf(event.key) === -1) return;
    }
    userScrollIntent = true;
    clearTopQueue();
  }

  window.addEventListener('wheel', markUserScrollIntent, { passive: true });
  window.addEventListener('touchmove', markUserScrollIntent, { passive: true });
  window.addEventListener('keydown', markUserScrollIntent, true);

  window.wanyuGoTop = goTopSoon;

  function getCurrentLang() {
    try {
      var stored = window.localStorage.getItem('wyt-lang');
      if (stored === 'en' || stored === 'zh') return stored;
    } catch (e) {}

    if ((document.documentElement.lang || '').toLowerCase().indexOf('en') === 0) return 'en';

    var btnEn = document.getElementById('btn-en');
    if (btnEn && btnEn.classList.contains('active')) return 'en';

    return 'zh';
  }

  function setLocalizedText(element, zhText, enText, lang) {
    if (!element) return;
    element.setAttribute('data-zh', zhText);
    element.setAttribute('data-en', enText);
    element.textContent = lang === 'en' ? enText : zhText;
  }

  function syncChromeText(lang) {
    var activeLang = lang === 'en' ? 'en' : 'zh';

    setLocalizedText(
      document.querySelector('.brand'),
      '萬語通',
      'WanyuTong',
      activeLang
    );

    var btnZh = document.getElementById('btn-zh');
    var btnEn = document.getElementById('btn-en');
    if (btnZh) {
      btnZh.textContent = activeLang === 'en' ? 'ZH' : '繁中';
      btnZh.classList.toggle('active', activeLang === 'zh');
    }
    if (btnEn) {
      btnEn.textContent = 'EN';
      btnEn.classList.toggle('active', activeLang === 'en');
    }

    var footerInfo = document.querySelector('footer div[data-zh], footer div:first-child');
    if (footerInfo && /©|萬語通|WanyuTong|LINE|Email/.test(footerInfo.textContent)) {
      setLocalizedText(
        footerInfo,
        '© 2026 萬語通 · LINE: fishxit · Email: bao58881@gmail.com',
        '© 2026 WanyuTong · LINE: fishxit · Email: bao58881@gmail.com',
        activeLang
      );
    }
  }

  window.wanyuSyncChromeText = syncChromeText;

  function markNextPageTop() {
    try { window.sessionStorage.setItem(TOP_FLAG, '1'); } catch (e) {}
  }

  function shouldResetFromNavigation() {
    try {
      var nav = window.performance && window.performance.getEntriesByType
        ? window.performance.getEntriesByType('navigation')[0]
        : null;
      return !nav || nav.type === 'reload' || nav.type === 'navigate' || nav.type === 'back_forward';
    } catch (e) {
      return true;
    }
  }

  window.addEventListener('pageshow', function (event) {
    var forced = false;
    try {
      forced = window.sessionStorage.getItem(TOP_FLAG) === '1';
      if (forced) window.sessionStorage.removeItem(TOP_FLAG);
    } catch (e) {}

    syncChromeText(getCurrentLang());

    if (forced || event.persisted || shouldResetFromNavigation()) {
      goTopSoon(forced);
    }
  });

  window.addEventListener('load', function () {
    syncChromeText(getCurrentLang());
    if (shouldResetFromNavigation()) {
      goTopSoon(false);
    }
  });

  window.addEventListener('beforeunload', function () {
    markNextPageTop();
  });

  document.addEventListener('DOMContentLoaded', function () {
    syncChromeText(getCurrentLang());
    goTopSoon(false);

    ['setLang', 'toggleTheme'].forEach(function (name) {
      var original = window[name];
      if (typeof original !== 'function' || original.__wytTopWrapped) return;
      window[name] = function () {
        var result = original.apply(this, arguments);
        if (name === 'setLang') {
          syncChromeText(arguments[0] || getCurrentLang());
        } else {
          syncChromeText(getCurrentLang());
        }
        goTopSoon(true);
        return result;
      };
      window[name].__wytTopWrapped = true;
    });

    document.addEventListener('click', function (event) {
      var target = event.target;
      if (!target || !target.closest) return;

      var langControl = target.closest('[onclick*="setLang"], .lang-toggle button, .lang-btn');
      var historyControl = target.closest('[onclick*="history.back"], [onclick*="history.forward"], .history-nav button, .history-nav-btn');
      var pageLink = target.closest('a[href]');

      if (langControl) {
        goTopSoon(true);
        return;
      }

      if (historyControl) {
        markNextPageTop();
        goTopSoon(true);
        return;
      }

      if (pageLink) {
        var href = pageLink.getAttribute('href') || '';
        var isSamePageAnchor = href.charAt(0) === '#';
        var isArticleOrSitePage = /\.html(?:$|[?#])/.test(href) || href === './' || href === '/wanyutong-web/' || href === 'index.html';

        if (!isSamePageAnchor && isArticleOrSitePage) {
          markNextPageTop();
        }
      }
    }, true);

    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('./sw.js').catch(function () {});
    }
  });
})();
