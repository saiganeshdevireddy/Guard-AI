const PIPELINE_URL = "http://127.0.0.1:8000/api/pipeline/event";

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "GUARD_CHECK_LINK" || typeof message.url !== "string") {
    return false;
  }

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
      sendResponse({
        ok: true,
        action: data.action,
        english: informer?.english || "",
        telugu: informer?.telugu || ""
      });
    })
    .catch(() => sendResponse({ ok: false }));

  return true;
});
