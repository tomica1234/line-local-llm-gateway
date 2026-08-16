const startedAt = Date.now();
const tabSessionId = crypto.randomUUID();

function searchQuery(url) {
  const candidates = ["q", "query", "p", "keyword", "search_query"];
  for (const key of candidates) {
    const value = url.searchParams.get(key);
    if (value) return value.slice(0, 2000);
  }
  return null;
}

function referrerDomain() {
  if (!document.referrer) return null;
  try { return new URL(document.referrer).hostname; } catch { return null; }
}

async function capture() {
  if (document.visibilityState !== "visible") return;
  if (browser.extension?.inIncognitoContext !== true) return;
  const url = new URL(location.href);
  await browser.runtime.sendMessage({
    type: "activity_event",
    event: {
      timestamp: new Date().toISOString(),
      browser: "safari",
      private_mode: true,
      url: url.href,
      page_title: document.title.slice(0, 2000),
      search_query: searchQuery(url),
      referrer_domain: referrerDomain(),
      estimated_dwell_time: Math.max(0, (Date.now() - startedAt) / 1000),
      tab_session_id: tabSessionId,
    },
  });
}

const interval = setInterval(() => capture().catch(() => {}), 15000);
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") capture().catch(() => {});
});
window.addEventListener("pagehide", () => {
  clearInterval(interval);
  capture().catch(() => {});
});
