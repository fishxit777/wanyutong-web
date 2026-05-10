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

  function ensureLanguageLayoutStyle() {
    if (document.getElementById('wyt-language-layout-fix')) return;

    var style = document.createElement('style');
    style.id = 'wyt-language-layout-fix';
    style.textContent = [
      'nav{justify-content:flex-start!important;gap:clamp(.55rem,1vw,1.25rem)!important;padding:0 clamp(1rem,3vw,3rem)!important}',
      '.nav-brand,.brand{flex:0 0 auto!important;white-space:nowrap!important;letter-spacing:.02em!important;gap:.38rem!important}',
      '.nav-brand-sub:empty{display:none!important}',
      '.nav-quick-links{display:flex;align-items:center;gap:.55rem;flex:0 0 auto}',
      '.nav-links{flex:1 1 auto!important;min-width:0!important;justify-content:center!important;gap:clamp(.75rem,1.25vw,1.55rem)!important;margin:0!important;padding:0!important}',
      '.nav-links a{white-space:nowrap!important;display:inline-flex!important;align-items:center!important;letter-spacing:.045em!important}',
      '.nav-cta{flex:0 0 auto!important;white-space:nowrap!important;display:inline-flex!important;align-items:center!important;justify-content:center!important;padding:.38em .9em!important;letter-spacing:.04em!important;line-height:1.1!important}',
      '.nav-actions{display:flex!important;align-items:center!important;gap:.45rem!important;flex:0 0 auto!important;margin-left:auto!important}',
      '@media(max-width:1280px){.nav-quick-links{display:none!important}.nav-links{gap:.85rem!important}.nav-links a{font-size:.72rem!important;letter-spacing:.035em!important}}',
      '@media(max-width:1050px){nav{padding:0 4vw!important;gap:.5rem!important}.nav-blog-pill,.nav-quick-links{display:none!important}.nav-links{display:none!important;flex-direction:column;position:absolute;top:58px;left:0;right:0;background:var(--bg2);border-bottom:1px solid var(--border);padding:1rem 5vw;gap:1rem}.nav-links.open{display:flex!important}.hamburger{display:flex!important;flex-shrink:0!important}}'
    ].join('\n');
    document.head.appendChild(style);
  }

  function ensureNavStructure() {
    var nav = document.querySelector('nav');
    if (!nav) return;

    var brand = document.querySelector('.nav-brand');
    if (brand && !brand.querySelector('.nav-brand-main')) {
      brand.innerHTML = '<span class="nav-dot"></span><span class="nav-brand-main"></span><span class="nav-brand-sub"></span>';
    }

    if (!document.querySelector('.nav-quick-links')) {
      var blog = document.querySelector('a[href="blog.html"].nav-blog-pill');
      var faq = document.querySelector('a[href="faq.html"].nav-blog-pill');
      if (blog && faq && blog.parentNode) {
        var quickLinks = document.createElement('div');
        quickLinks.className = 'nav-quick-links';
        blog.parentNode.insertBefore(quickLinks, blog);
        quickLinks.appendChild(blog);
        quickLinks.appendChild(faq);
      }
    }

    if (!document.querySelector('.nav-actions')) {
      var langToggle = document.querySelector('.lang-toggle');
      if (langToggle && langToggle.parentNode) {
        var actions = document.createElement('div');
        actions.className = 'nav-actions';
        langToggle.parentNode.insertBefore(actions, langToggle);
        actions.appendChild(langToggle);

        var themeToggle = document.getElementById('themeToggle');
        if (themeToggle) actions.appendChild(themeToggle);

        var hamburger = document.getElementById('hamburger');
        if (hamburger) actions.appendChild(hamburger);
      }
    }
  }

  function syncNavLabels(activeLang) {
    var labels = activeLang === 'en'
      ? {
        '#features': 'Features',
        '#industries': 'Use Cases',
        '#compare': 'Engine',
        '#vs-competitors': 'Compare',
        '#referral': 'Referral',
        '#pricing': 'Pricing',
        '#howto': 'Start',
        '#terms': 'Terms'
      }
      : {
        '#features': '為何選我',
        '#industries': '適用產業',
        '#compare': '引擎差異',
        '#vs-competitors': '競品比較',
        '#referral': '推薦優惠',
        '#pricing': '收費方案',
        '#howto': '如何開始',
        '#terms': '條款'
      };

    Object.keys(labels).forEach(function (href) {
      var link = document.querySelector('.nav-links a[href="' + href + '"]');
      if (link) link.textContent = labels[href];
    });

    var cta = document.querySelector('.nav-links .nav-cta');
    if (cta) cta.textContent = activeLang === 'en' ? 'Try Free' : '免費體驗';

    var blog = document.querySelector('a[href="blog.html"].nav-blog-pill');
    if (blog) blog.textContent = activeLang === 'en' ? 'Blog' : '📝 部落格';

    var faq = document.querySelector('a[href="faq.html"].nav-blog-pill');
    if (faq) faq.textContent = activeLang === 'en' ? 'FAQ' : '❓ 常見問題';
  }

  function syncFooterLinks(activeLang) {
    var footerLinks = document.querySelectorAll('.footer-links a');
    if (!footerLinks.length) return;

    var labels = activeLang === 'en'
      ? ['Blog', 'FAQ', 'Pricing', 'Terms', 'Contact']
      : ['部落格', '常見問題', '收費方案', '使用條款', '聯繫客服'];

    footerLinks.forEach(function (link, index) {
      if (labels[index]) link.textContent = labels[index];
    });
  }

  function syncChromeText(lang) {
    var activeLang = lang === 'en' ? 'en' : 'zh';

    ensureLanguageLayoutStyle();
    ensureNavStructure();

    setLocalizedText(
      document.querySelector('.brand'),
      '萬語通',
      'WanyuTong',
      activeLang
    );

    var brandMain = document.querySelector('.nav-brand-main');
    var brandSub = document.querySelector('.nav-brand-sub');
    if (brandMain) brandMain.textContent = activeLang === 'en' ? 'WanyuTong' : '萬語通';
    if (brandSub) brandSub.textContent = activeLang === 'en' ? '' : 'WanyuTong';

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

    syncNavLabels(activeLang);
    syncFooterLinks(activeLang);
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
