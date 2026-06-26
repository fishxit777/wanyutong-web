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
      '.nav-brand,.brand{display:inline-flex!important;align-items:center!important;flex:0 0 auto!important;white-space:nowrap!important;letter-spacing:.02em!important;gap:.5rem!important;text-decoration:none!important}',
      '.brand-logo{width:42px!important;height:42px!important;border-radius:50%!important;object-fit:cover!important;flex:0 0 42px!important;border:2px solid rgba(255,255,255,.14)!important;box-shadow:0 0 0 1px rgba(255,115,30,.35),0 0 22px rgba(255,115,30,.22),0 0 28px rgba(6,199,85,.14)!important}',
      '.brand-copy,.brand-text{display:inline-flex!important;align-items:baseline!important;gap:.32rem!important;min-width:0!important}',
      '.brand-main,.nav-brand-main{line-height:1!important}',
      '.nav-brand-sub:empty{display:none!important}',
      '.nav-quick-links{display:flex;align-items:center;gap:.55rem;flex:0 0 auto}',
      '.nav-links{flex:1 1 auto!important;min-width:0!important;justify-content:center!important;gap:clamp(.75rem,1.25vw,1.55rem)!important;margin:0!important;padding:0!important}',
      '.nav-links a{white-space:nowrap!important;display:inline-flex!important;align-items:center!important;letter-spacing:.045em!important}',
      '.nav-cta{flex:0 0 auto!important;white-space:nowrap!important;display:inline-flex!important;align-items:center!important;justify-content:center!important;padding:.38em .9em!important;letter-spacing:.04em!important;line-height:1.1!important}',
      '.nav-actions{display:flex!important;align-items:center!important;gap:.45rem!important;flex:0 0 auto!important;margin-left:auto!important}',
      '.hamburger,.blog-hamburger{width:34px!important;min-width:34px!important;height:34px!important;padding:6px!important;border:0!important;background:transparent!important;align-items:center!important;justify-content:center!important;flex-direction:column!important;gap:4px!important}',
      '.hamburger span,.blog-hamburger span{display:block!important;width:20px!important;height:2px!important;flex:0 0 2px!important;border-radius:2px!important;background:var(--text)!important}',
      '@media(max-width:1450px){.nav-quick-links{display:none!important}.nav-links{gap:.85rem!important}.nav-links a{font-size:.72rem!important;letter-spacing:.035em!important}}',
      '@media(max-width:1450px){nav{padding:0 4vw!important;gap:.5rem!important}.nav-blog-pill,.nav-quick-links{display:none!important}.nav-links,.nav-links-blog{display:none!important;flex-direction:column!important;position:absolute!important;top:58px!important;left:0!important;right:0!important;background:var(--bg2)!important;border-bottom:1px solid var(--border)!important;padding:1rem 5vw!important;gap:1rem!important;z-index:220!important}.nav-links.open,.nav-links-blog.open{display:flex!important}.hamburger,.blog-hamburger{display:flex!important;flex-shrink:0!important}}',
      '@media(max-width:600px){nav{height:56px!important;min-height:56px!important;padding:0 .7rem!important;gap:.35rem!important}.nav-brand,.brand{min-width:0!important;max-width:calc(100vw - 150px)!important;font-size:clamp(.92rem,5vw,1.05rem)!important;overflow:hidden!important}.brand-logo{width:34px!important;height:34px!important;flex-basis:34px!important}.nav-brand-main,.brand-main,.brand-text{overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important}.nav-brand-sub{display:none!important}.nav-actions{gap:.25rem!important;margin-left:auto!important;min-width:0!important}.lang-toggle{font-size:.62rem!important;flex:0 0 auto!important}.lang-btn,.lang-toggle button{min-width:auto!important;padding:3px 7px!important;height:24px!important}.theme-toggle{width:34px!important;min-width:34px!important;height:24px!important}.theme-toggle-knob{width:14px!important;height:14px!important}.hamburger,.blog-hamburger{width:32px!important;min-width:32px!important;height:32px!important;padding:6px!important}}',
      '@media(max-width:380px){.nav-brand,.brand{max-width:calc(100vw - 138px)!important}.nav-actions{gap:.18rem!important}.theme-toggle{display:none!important}}',
      '@media(max-width:600px){.hero-grid,.hero-text,.hero-actions,.hero-mockup{min-width:0!important;max-width:100%!important;width:100%!important}.bot-chat-glow{display:none!important}.stats-strip{grid-template-columns:1fr!important}.stat-item{width:auto!important;min-width:0!important}.compare-wrap{width:100%!important;max-width:100%!important;overflow:visible!important}#compare .compare-table,#vs-competitors .compare-table{min-width:0!important;width:100%!important;display:block!important;border:0!important;background:transparent!important}#compare .compare-table thead,#vs-competitors .compare-table thead{display:none!important}#compare .compare-table tbody,#vs-competitors .compare-table tbody{display:grid!important;gap:.75rem!important}#compare .compare-table tr,#vs-competitors .compare-table tr{display:block!important;border:1px solid var(--border)!important;border-radius:10px!important;overflow:hidden!important;background:rgba(12,17,26,.92)!important}#compare .compare-table td,#vs-competitors .compare-table td{display:block!important;width:100%!important;text-align:left!important;padding:.78rem .95rem!important;border-top:1px solid rgba(114,139,176,.14)!important;line-height:1.55!important}#compare .compare-table td:first-child,#vs-competitors .compare-table td:first-child{border-top:0!important;background:rgba(255,255,255,.045)!important;color:var(--white)!important;font-weight:800!important}#compare .compare-table td:not(:first-child)::before,#vs-competitors .compare-table td:not(:first-child)::before{content:attr(data-label);display:block;margin-bottom:.32rem;color:#7f91b0;font-family:"DM Mono",monospace;font-size:.66rem;letter-spacing:.07em;text-transform:uppercase}}'
    ].join('\n');
    document.head.appendChild(style);
  }

  function ensureNavStructure() {
    var nav = document.querySelector('nav');
    if (!nav) return;

    var brand = document.querySelector('.nav-brand');
    if (brand && (!brand.querySelector('.nav-brand-main') || !brand.querySelector('.brand-logo'))) {
      brand.innerHTML = '<img class="brand-logo" src="assets/wanyutong-logo.jpg" alt="萬語通 Globe Talk AI Translation 標誌"><span class="brand-copy"><span class="nav-brand-main"></span><span class="nav-brand-sub"></span></span>';
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
        'features.html': 'Features',
        'industries.html': 'Use Cases',
        'engine.html': 'Engine',
        'compare.html': 'Compare',
        'pricing.html': 'Pricing',
        'start.html': 'Start',
        'terms.html': 'Terms'
      }
      : {
        'features.html': '為何選我',
        'industries.html': '適用產業',
        'engine.html': '引擎差異',
        'compare.html': '競品比較',
        'pricing.html': '收費方案',
        'start.html': '如何開始',
        'terms.html': '條款'
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
      ? {
        'index.html': 'Official Site',
        'features.html': 'Why Us',
        'pricing.html': 'Pricing',
        'blog.html': 'Blog',
        'faq.html': 'FAQ',
        'terms.html': 'Terms',
        'privacy.html': 'Privacy',
        'contact.html': 'Contact'
      }
      : {
        'index.html': '官網',
        'features.html': '為何選我',
        'pricing.html': '收費方案',
        'blog.html': '部落格',
        'faq.html': '常見問題',
        'terms.html': '使用條款',
        'privacy.html': '隱私權政策',
        'contact.html': '聯絡方式'
      };

    footerLinks.forEach(function (link) {
      var href = link.getAttribute('href') || '';
      if (labels[href]) link.textContent = labels[href];
    });
  }

  function syncChromeText(lang) {
    var activeLang = lang === 'en' ? 'en' : 'zh';

    ensureLanguageLayoutStyle();
    ensureNavStructure();

    var simpleBrand = document.querySelector('.brand');
    if (simpleBrand) {
      simpleBrand.setAttribute('data-zh', '萬語通');
      simpleBrand.setAttribute('data-en', 'WanyuTong');
      if (!simpleBrand.querySelector('.brand-logo') || !simpleBrand.querySelector('.brand-main')) {
        simpleBrand.innerHTML = '<img class="brand-logo" src="assets/wanyutong-logo.jpg" alt="萬語通 Globe Talk AI Translation 標誌"><span class="brand-main"></span>';
      }
      var simpleBrandMain = simpleBrand.querySelector('.brand-main');
      if (simpleBrandMain) simpleBrandMain.textContent = activeLang === 'en' ? 'WanyuTong' : '萬語通';
    }

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
    var footerText = footerInfo ? footerInfo.textContent : '';
    if (footerInfo && (footerText.indexOf('客服') !== -1 || footerText.indexOf('表單') !== -1 || footerText.indexOf('WanyuTong') !== -1 || footerText.indexOf('LINE') !== -1 || footerText.indexOf('Email') !== -1)) {
      footerInfo.innerHTML = activeLang === 'en' ? '© 2026 WanyuTong · <a class="support-form-link" href="https://forms.gle/rKatiHrCmh5wpCov8" target="_blank" rel="noopener">GOOGLE Support Form</a> · Email: bao58881@gmail.com' : '© 2026 萬語通 · <a class="support-form-link" href="https://forms.gle/rKatiHrCmh5wpCov8" target="_blank" rel="noopener">GOOGLE 客服表單</a> · Email：bao58881@gmail.com';
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
