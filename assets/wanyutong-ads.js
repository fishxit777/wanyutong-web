(function () {
  "use strict";

  // A second inclusion must reuse the first controller, not enqueue more ads.
  if (window.wytAds && window.wytAds.version === "20260907-reviewed-content-v1") return;

  var cfg = window.WANYUTONG_ADS || {};
  var publisherId = String(cfg.publisherId || "").trim();
  var hasPublisher = /^ca-pub-\d{16}$/.test(publisherId);
  var mode = String(cfg.mode || "content_ads_only");
  var mountedSlots = new WeakSet();
  var reviewedPaths = [
    "blog-foreign-worker-communication.html",
    "blog-free-paid-plans.html",
    "blog-group-translation-checklist.html",
    "blog-image-ocr-checklist.html",
    "blog-image-ocr-translation.html",
    "blog-language-settings.html",
    "blog-line-bot-first-setup.html",
    "blog-line-group-translation.html",
    "blog-translation-quality-checklist.html"
  ];

  function list(value) {
    return Array.isArray(value) ? value : [];
  }

  function pageName() {
    return (window.location.pathname || "/").slice(1);
  }

  function hideSlot(slot, state) {
    slot.hidden = true;
    slot.setAttribute("aria-hidden", "true");
    slot.setAttribute("data-wyt-ad-state", state);
  }

  function hideAllSlots(state) {
    document.querySelectorAll("[data-wyt-ad]").forEach(function (slot) {
      hideSlot(slot, state || "hidden");
    });
  }

  function canLoadAds() {
    // These are release checklist gates, not a CMP, geo lookup, or a substitute
    // for the real approval and regional consent requirements.
    if (cfg.enabled !== true || cfg.approvalConfirmed !== true || cfg.consentReady !== true) return false;
    if (mode !== "content_ads_only" || !hasPublisher) return false;
    if (window.location.protocol !== "https:" || window.location.hostname !== "wanyutong.tw") return false;
    if (window.location.search || window.location.hash) return false;
    var path = pageName();
    if (reviewedPaths.indexOf(path) === -1) return false;
    if (list(cfg.enabledPaths).indexOf(path) === -1) return false;
    if (list(cfg.excludedPaths).some(function (item) { return item === path || item === "/" + path; })) return false;
    if (Array.prototype.some.call(document.querySelectorAll('meta[name="robots"]'), function (meta) {
      return /\bnoindex\b/i.test(meta.getAttribute("content") || "");
    })) return false;
    return true;
  }

  function existingLoader() {
    var scripts = document.querySelectorAll("script[src]");
    var found = false;
    for (var i = 0; i < scripts.length; i += 1) {
      var src = scripts[i].getAttribute("src") || "";
      var url;
      try { url = new URL(src, window.location.href); } catch (err) { continue; }
      if (url.hostname !== "pagead2.googlesyndication.com" || url.pathname !== "/pagead/js/adsbygoogle.js") continue;
      if (url.protocol !== "https:" || url.searchParams.get("client") !== publisherId) return "conflict";
      found = true;
    }
    return found ? "present" : "absent";
  }

  function loadAdSense() {
    var state = existingLoader();
    if (state === "conflict") return false;
    if (state === "present") return true;
    var script = document.createElement("script");
    script.async = true;
    script.src = "https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=" + encodeURIComponent(publisherId);
    script.crossOrigin = "anonymous";
    script.setAttribute("data-wyt-adsense", "true");
    document.head.appendChild(script);
    return true;
  }

  function eligibleSlots() {
    var slots = cfg.slots || {};
    var eligible = [];
    document.querySelectorAll("[data-wyt-ad]").forEach(function (slot) {
      if (mountedSlots.has(slot)) return;
      var slotKey = slot.getAttribute("data-wyt-ad");
      var adSlot = Object.prototype.hasOwnProperty.call(slots, slotKey) ? String(slots[slotKey] || "").trim() : "";
      if (!/^\d{1,20}$/.test(adSlot)) {
        hideSlot(slot, "missing-slot");
        return;
      }
      eligible.push({ element: slot, id: adSlot });
    });
    return eligible;
  }

  function mountSlots(slots) {
    slots.forEach(function (entry) {
      var slot = entry.element;
      // Mark before push: reentrancy or a provider error must not duplicate it.
      mountedSlots.add(slot);
      var ad = document.createElement("ins");
      ad.className = "adsbygoogle";
      ad.style.display = "block";
      ad.setAttribute("data-ad-client", publisherId);
      ad.setAttribute("data-ad-slot", entry.id);
      ad.setAttribute("data-ad-format", "auto");
      ad.setAttribute("data-full-width-responsive", "true");
      if (cfg.testMode === true) ad.setAttribute("data-adtest", "on");
      slot.appendChild(ad);
      slot.hidden = false;
      slot.removeAttribute("aria-hidden");
      slot.setAttribute("data-wyt-ad-state", "mounted");
      try {
        (window.adsbygoogle = window.adsbygoogle || []).push({});
      } catch (err) {
        hideSlot(slot, "provider-error");
      }
    });
  }

  window.wytAds = {
    version: "20260907-reviewed-content-v1",
    status: function () {
      return { enabled: canLoadAds(), mode: mode, path: pageName(), hasPublisher: hasPublisher };
    },
    refresh: function () {
      if (!canLoadAds()) {
        hideAllSlots("disabled");
        return false;
      }
      var slots = eligibleSlots();
      // A verification tag and ads.txt are sufficient for ownership checks;
      // blank ad-unit configuration must never cause a third-party request.
      if (slots.length === 0) return false;
      if (!loadAdSense()) {
        hideAllSlots("loader-conflict");
        return false;
      }
      mountSlots(slots);
      return true;
    }
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { window.wytAds.refresh(); }, { once: true });
  } else {
    window.wytAds.refresh();
  }
})();
