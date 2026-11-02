const PIPELINE_URL = "http://127.0.0.1:8000/api/pipeline/event";
const recentlyCheckedUrls = new Map();
const CHECKED_URL_TTL_MS = 10_000;

function rememberCheckedUrl(url) {
  const now = Date.now();
  for (const [checkedUrl, timestamp] of recentlyCheckedUrls) {
    if (now - timestamp > CHECKED_URL_TTL_MS) recentlyCheckedUrls.delete(checkedUrl);
  }
  recentlyCheckedUrls.set(url, now);
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "GUARD_CHECK_LINK" || typeof message.url !== "string") {
    return false;
  }

  console.log("[Guard AI SW] message received", message.url);
  fetch(PIPELINE_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "link", value: message.url, source: "extension" })
  })
    .then(async (response) => {
      if (!response.ok) throw new Error(`Guard AI returned HTTP ${response.status}`);
      return response.json();
    })
    .then((data) => {
      const informer = Array.isArray(data.steps)
        ? data.steps.find((step) => step?.name === "Informer")?.result
        : null;
      console.log("[Guard AI SW] pipeline action", data.action);
      if (data.action === "allow" || data.action === "warn") rememberCheckedUrl(message.url);
      sendResponse({
        ok: true,
        action: data.action,
        english: informer?.english || "",
        telugu: informer?.telugu || ""
      });
    })
    .catch((error) => {
      console.error("[Guard AI SW] pipeline error", error);
      sendResponse({ ok: false });
    });

  return true;
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;

  let target;
  try {
    target = new URL(details.url);
  } catch {
    return;
  }
  if (target.protocol !== "http:" && target.protocol !== "https:") return;
  if (target.hostname === "127.0.0.1" || target.hostname === "localhost") return;

  const url = details.url;
  const now = Date.now();
  for (const [checkedUrl, timestamp] of recentlyCheckedUrls) {
    if (now - timestamp > CHECKED_URL_TTL_MS) recentlyCheckedUrls.delete(checkedUrl);
  }
  if (recentlyCheckedUrls.has(url)) {
    console.log("[Guard AI SW] skipped, already checked", url);
    return;
  }
  console.log("[Guard AI] checking URL", url);
  fetch(PIPELINE_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "link", value: url, source: "extension" })
  })
    .then(async (response) => {
      if (!response.ok) throw new Error(`Guard AI returned HTTP ${response.status}`);
      return response.json();
    })
    .then((data) => {
      const informer = Array.isArray(data.steps)
        ? data.steps.find((step) => step?.name === "Informer")?.result
        : null;
      const action = data.action;
      console.log("[Guard AI] decision", action, "for", url);
      if (action !== "block") return;

      const blockUrl = chrome.runtime.getURL("block.html")
        + "?u=" + encodeURIComponent(url)
        + "&english=" + encodeURIComponent(informer?.english || "")
        + "&telugu=" + encodeURIComponent(informer?.telugu || "");
      chrome.tabs.update(details.tabId, { url: blockUrl });
    })
    .catch((error) => {
      console.log("[Guard AI] decision backend-unavailable for", url, error);
    });
});
