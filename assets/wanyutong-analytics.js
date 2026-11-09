(function () {
  'use strict';

  // One controller per document: a second script load or a bfcache restore
  // must not count another page view or attach another click listener.
  if (window.__wytAnalyticsV2Started) return;
  window.__wytAnalyticsV2Started = true;

  var ENDPOINT = 'https://one1stars-line-bot.onrender.com/track/event';
  var PAGES = [
    'index', 'about', 'blog', 'blog-foreign-worker-communication',
    'blog-free-paid-plans', 'blog-group-translation-checklist',
    'blog-image-ocr-translation', 'blog-language-settings',
    'blog-line-bot-first-setup', 'blog-line-group-translation',
    'blog-translation-quality-checklist', 'card', 'compare', 'contact',
    'editorial', 'engine', 'faq', 'features', 'industries', 'join',
    'pricing', 'privacy', 'start', 'terms'
  ];

  function excluded() {
    try {
      if (window.localStorage.getItem('wyt-admin') === '1') return true;
    } catch (error) {
      // Private browsing or disabled storage must not affect navigation.
    }
    return false;
  }

  function currentPage() {
    var location = window.location;
    if (location.protocol !== 'https:') return null;
    var path = location.pathname;
    if (location.hostname === 'fishxit777.github.io') {
      if (path.indexOf('/wanyutong-web/') !== 0) return null;
      path = path.slice('/wanyutong-web'.length);
    } else if (location.hostname !== 'wanyutong.tw' && location.hostname !== 'www.wanyutong.tw') {
      return null;
    }
    if (path === '/' || path === '/index.html') return 'index';
    if (!/^\/[a-z0-9-]+\.html$/.test(path)) return null;
    var page = path.slice(1, -5);
    return PAGES.indexOf(page) === -1 ? null : page;
  }

  function originOnly(value) {
    try {
      var url = new URL(value);
      if ((url.protocol === 'https:' || url.protocol === 'http:') && !url.username && !url.password) {
        return url.origin;
      }
    } catch (error) {}
    return '';
  }

  function eventId() {
    var crypto = window.crypto;
    if (!crypto) return null;
    if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    if (typeof crypto.getRandomValues !== 'function') return null;
    var bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    var hex = Array.prototype.map.call(bytes, function (n) { return ('0' + n.toString(16)).slice(-2); }).join('');
    return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
  }

  var page = currentPage();
  if (!page || excluded()) return;
  var robots = document.querySelectorAll('meta[name="robots"]');
  for (var i = 0; i < robots.length; i++) {
    if (/\bnoindex\b/i.test(robots[i].getAttribute('content') || '')) return;
  }

  function send(type) {
    if (excluded()) return;
    try {
      var id = eventId();
      if (!id) return;
      var body = JSON.stringify({
        version: 2, event_id: id, event_type: type,
        page: page, referrer: originOnly(document.referrer)
      });
      // The document's origin-only referrer policy also bounds Beacon's
      // Referer header. Neither transport sends page queries or link URLs.
      try {
        if (typeof window.navigator.sendBeacon === 'function' &&
            window.navigator.sendBeacon(ENDPOINT, new Blob([body], { type: 'text/plain;charset=UTF-8' }))) return;
      } catch (error) {}
      if (typeof window.fetch === 'function') {
        var pending = window.fetch(ENDPOINT, {
          method: 'POST', mode: 'cors', credentials: 'omit', cache: 'no-store',
          keepalive: true, referrerPolicy: 'no-referrer',
          headers: { 'Content-Type': 'text/plain;charset=UTF-8' }, body: body
        });
        if (pending && typeof pending.catch === 'function') pending.catch(function () {});
      }
    } catch (error) {
      // Analytics is best effort. Never delay, cancel or replace LINE navigation.
    }
  }

  function isLineJoin(anchor) {
    try {
      var url = new URL(anchor.getAttribute('href'), window.location.href);
      return url.protocol === 'https:' && url.hostname === 'line.me' &&
        !url.username && !url.password && !url.port &&
        /^\/(?:R\/)?ti\/p\/@969wpxno\/?$/.test(url.pathname);
    } catch (error) { return false; }
  }

  function handleClick(event) {
    if (event.defaultPrevented || event.isTrusted === false) return;
    if (event.type === 'auxclick' ? event.button !== 1 : (event.button !== undefined && event.button !== 0)) return;
    var target = event.target;
    if (target && typeof target.closest !== 'function') target = target.parentElement;
    var anchor = target && typeof target.closest === 'function' ? target.closest('a[href]') : null;
    if (anchor && isLineJoin(anchor)) send('line_click');
  }

  function start() {
    send('page_view');
    document.addEventListener('click', handleClick);
    document.addEventListener('auxclick', handleClick);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})();
