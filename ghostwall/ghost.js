(function() {
  const API_URL = "https://yourapi.com/check";  // Change to your API URL
  const API_KEY = "CLIENT_SITE_API_KEY";        // Client’s assigned API key

  // Prepare visitor data
  const visitorData = {
    api_key: API_KEY,
    user_agent: navigator.userAgent || "",
    language: navigator.language || "",
    platform: navigator.platform || "",
    // Add more fields if you want, like timezone, screen resolution, etc.
  };

  // Send visitor info asynchronously (fire-and-forget)
  fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(visitorData),
    keepalive: true // allows send during page unload
  }).catch(() => {
    // Fail silently, no blocking of page load
  });
})();