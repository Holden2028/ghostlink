(function () {
    const endpoint = 'https://ghostwall.onrender.com/track';
    const data = {
        user_agent: navigator.userAgent,
        url: window.location.href,
        referrer: document.referrer,
        timestamp: new Date().toISOString()
    };

    fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    }).catch(err => {
        console.warn('GhostWall tracking failed', err);
    });
})();
