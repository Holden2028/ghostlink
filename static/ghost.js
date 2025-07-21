// static/ghost.js
(function() {
  const API_ENDPOINT = "/track"; // Call your Flask /track endpoint
  const SESSION_KEY = (function() {
    try {
      if (window.crypto && crypto.getRandomValues) {
        const arr = new Uint8Array(16);
        crypto.getRandomValues(arr);
        return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
      }
    } catch(e) {}
    return Math.random().toString(36).substr(2) + Date.now();
  })();

  function getFingerprint() {
    return {
      ua: navigator.userAgent,
      lang: navigator.language,
      platform: navigator.platform,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      width: window.innerWidth,
      height: window.innerHeight,
      dpr: window.devicePixelRatio,
      plugins: (navigator.plugins ? Array.from(navigator.plugins).map(p=>p.name).join(',') : ''),
    };
  }

  function isHeadless() {
    if (navigator.webdriver) return true;
    if (/HeadlessChrome/.test(navigator.userAgent)) return true;
    if (navigator.plugins && navigator.plugins.length === 0) return true;
    try {
      if (window.outerWidth === 0 || window.outerHeight === 0) return true;
    } catch(e) {}
    return false;
  }

  function checkCookieSupport() {
    try {
      document.cookie = 'ghost_cookie=1; path=/';
      return document.cookie.indexOf('ghost_cookie=1') !== -1;
    } catch(e) { return false; }
  }

  function reportToServer(extra={}) {
    const data = Object.assign({
      session_key: SESSION_KEY,
      url: window.location.href,
      referrer: document.referrer,
      is_headless: isHeadless(),
      cookie_enabled: checkCookieSupport(),
      ...getFingerprint(),
      ...extra
    });
    setTimeout(() => {
      fetch(API_ENDPOINT, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(data)
      });
    }, 50);
  }

  function addHoneyTrap() {
    const trap = document.createElement('a');
    trap.href = '/honeypot';
    trap.style.display = 'none';
    trap.textContent = 'Invisible Bot Trap';
    document.body.appendChild(trap);
  }

  window.addEventListener('DOMContentLoaded', function() {
    reportToServer();
    addHoneyTrap();
  });
})();