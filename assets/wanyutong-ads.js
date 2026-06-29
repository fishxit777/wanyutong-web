(function () {
  "use strict";

  var cfg = window.WANYUTONG_ADS || {};
  var publisherId = String(cfg.publisherId || "").trim();
  var hasPublisher = /^ca-pub-\d{16}$/.test(publisherId);
  var mode = String(cfg.mode || "content_ads_only");
  var testMode = cfg.testMode === true;
  var fullPath = window.location.pathname || "/";
  var path = fullPath.split("/").pop() || "index.html";

  function list(value) {
    return Array.isArray(value) ? value : [];
  }

  function matchesAny(items) {
    return items.some(function (item) {
      return item && (path.indexOf(item) !== -1 || fullPath.indexOf(item) !== -1);
    });
  }

  function log(message) {
    if (cfg.debug && window.console) console.info("[WanyuTong Ads] " + message);
  }

  function hideAllSlots() {
    document.querySelectorAll("[data-wyt-ad]").forEach(function (slot) {
      slot.hidden = true;
      slot.setAttribute("aria-hidden", "true");
      slot.setAttribute("data-wyt-ad-state", "hidden");
    });
  }

  function canLoadAds() {
    if (mode !== "content_ads_only") return false;
    if (cfg.enabled !== true || !hasPublisher) return false;
    if (matchesAny(list(cfg.excludedPaths))) return false;
    var enabledPaths = list(cfg.enabledPaths);
    return enabledPaths.length === 0 || matchesAny(enabledPaths);
  }

  function loadAdSense() {
    if (document.querySelector("script[data-wyt-adsense]")) return;
    var script = document.createElement("script");
    script.async = true;
    script.src = "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=" + encodeURIComponent(publisherId);
    script.crossOrigin = "anonymous";
    script.setAttribute("data-wyt-adsense", "true");
    document.head.appendChild(script);
  }

  function mountSlots() {
    var slots = cfg.slots || {};
    document.querySelectorAll("[data-wyt-ad]").forEach(function (slot) {
      var slotKey = slot.getAttribute("data-wyt-ad");
      var adSlot = String(slots[slotKey] || "").trim();
      if (!/^\d+$/.test(adSlot)) {
        slot.hidden = true;
        slot.setAttribute("aria-hidden", "true");
        slot.setAttribute("data-wyt-ad-state", "missing-slot");
        return;
      }
      slot.hidden = false;
      slot.removeAttribute("aria-hidden");
      slot.setAttribute("data-wyt-ad-state", "mounted");
      slot.innerHTML = [
        '<ins class="adsbygoogle"',
        ' style="display:block"',
        ' data-ad-client="' + publisherId + '"',
        ' data-ad-slot="' + adSlot + '"',
        ' data-ad-format="auto"',
        ' data-full-width-responsive="true"',
        (testMode ? ' data-adtest="on"' : ''),
        '></ins>'
      ].join("");
      try {
        (window.adsbygoogle = window.adsbygoogle || []).push({});
      } catch (err) {
        log("slot push skipped: " + err.message);
      }
    });
  }

  window.wytAds = {
    enabled: canLoadAds(),
    mode: mode,
    path: path,
    publisherId: hasPublisher ? publisherId : "",
    status: function () {
      return {
        enabled: canLoadAds(),
        mode: mode,
        path: path,
        fullPath: fullPath,
        hasPublisher: hasPublisher,
        slots: Object.assign({}, cfg.slots || {})
      };
    },
    refresh: function () {
      if (!canLoadAds()) {
        hideAllSlots();
        return false;
      }
      loadAdSense();
      mountSlots();
      return true;
    }
  };

  document.addEventListener("DOMContentLoaded", function () {
    if (!window.wytAds.refresh()) {
      log("disabled, missing publisher ID, or excluded path: " + path);
    }
  });
})();
