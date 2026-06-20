// cernis-web-harness beacon (phase 1 stub)
// Confirms JS ran and posts a minimal readiness ping. Phase 3 extends this
// with mouse/scroll/keypress cadence + honeypot dwell measurements.
(function () {
  try {
    var t0 = performance.now();
    var payload = {
      type: "ready",
      t: t0,
      ua: navigator.userAgent,
      screen: { w: screen.width, h: screen.height },
      tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
      cookies: document.cookie ? document.cookie.length : 0,
      dom: document.body ? document.body.children.length : 0,
    };
    var send = function (data) {
      try {
        if (navigator.sendBeacon) {
          var blob = new Blob([JSON.stringify(data)], { type: "application/json" });
          navigator.sendBeacon("/__beacon", blob);
        } else {
          fetch("/__beacon", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data),
            keepalive: true,
          });
        }
      } catch (e) {}
    };
    send(payload);
    var loaded = false;
    var onReady = function () {
      if (loaded) return;
      loaded = true;
      send({
        type: "loaded",
        t: performance.now(),
        ttfi_candidate: t0,
        dom: document.body ? document.body.children.length : 0,
      });
    };
    if (document.readyState === "complete" || document.readyState === "interactive") {
      setTimeout(onReady, 0);
    } else {
      document.addEventListener("DOMContentLoaded", onReady);
    }
  } catch (e) {
    /* swallow */
  }
})();
