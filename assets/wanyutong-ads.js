(function () {
  "use strict";

  var cfg = window.WANYUTONG_ADS || {};
  var publisherId = String(cfg.publisherId || "").trim();
  var hasPublisher = /^ca-pub-\d{16}$/.test(publisherId);
  var path = (window.location.pathname || "").split("/").pop() || "index.html";

  function list(value) {
    return Array.isArray(value) ? value : [];
  }

  function matchesAny(items) {
    return items.some(function (item) {
      return item && path.indexOf(item) !== -1;
    });
  }

  function log(message) {
    if (cfg.debug && window.console) console.info("[WanyuTong Ads] " + message);
  }

  function hideAllSlots() {
    document.querySelectorAll("[data-wyt-ad]").forEach(function (slot) {
      slot.hidden = true;
      slot.setAttribute("aria-hidden", "true");
    });
  }

  function canLoadAds() {
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
        return;
      }
      slot.hidden = false;
      slot.removeAttribute("aria-hidden");
      slot.innerHTML = [
        '<ins class="adsbygoogle"',
        ' style="display:block"',
        ' data-ad-client="' + publisherId + '"',
        ' data-ad-slot="' + adSlot + '"',
        ' data-ad-format="auto"',
        ' data-full-width-responsive="true"></ins>'
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
    publisherId: hasPublisher ? publisherId : "",
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
