(() => {
  if (window.__guardAiLinkProtectionInstalled) return;
  window.__guardAiLinkProtectionInstalled = true;

  function speak(english, telugu) {
    if (!("speechSynthesis" in window)) return;
    window.speechSynthesis.cancel();
    for (const [text, lang] of [[english, "en-IN"], [telugu, "te-IN"]]) {
      if (!text) continue;
      const utterance = new SpeechSynthesisUtterance(text);
      utterance.lang = lang;
      window.speechSynthesis.speak(utterance);
    }
  }

  function showDecision({ title, message, english, telugu, color, buttons }) {
    document.getElementById("guard-ai-link-overlay")?.remove();
    const host = document.createElement("div");
    host.id = "guard-ai-link-overlay";
    host.style.cssText = "all:initial;position:fixed;inset:0;z-index:2147483647";
    const shadow = host.attachShadow({ mode: "closed" });
    const fullScreen = color === "#b91c1c";
    const panel = document.createElement("section");
    panel.setAttribute("role", "alertdialog");
    panel.setAttribute("aria-modal", "true");
    panel.style.cssText = `box-sizing:border-box;${fullScreen ? "min-height:100vh;" : ""}width:100%;padding:24px;background:${color};color:white;font:16px/1.5 system-ui,sans-serif;box-shadow:0 4px 24px #0008;${fullScreen ? "display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center;" : ""}`;

    const heading = document.createElement("h2");
    heading.textContent = title;
    heading.style.cssText = "margin:0 0 12px;font-size:24px";
    panel.append(heading);
    if (message) {
      const status = document.createElement("p");
      status.textContent = message;
      status.style.cssText = "font-weight:700";
      panel.append(status);
    }
    for (const text of [english, telugu]) {
      if (!text) continue;
      const paragraph = document.createElement("p");
      paragraph.textContent = text;
      paragraph.style.cssText = "max-width:760px;margin:8px 0";
      panel.append(paragraph);
    }

    const controls = document.createElement("div");
    controls.style.cssText = "display:flex;gap:12px;margin-top:18px;flex-wrap:wrap;justify-content:center";
    for (const button of buttons) {
      const element = document.createElement("button");
      element.type = "button";
      element.textContent = button.label;
      element.style.cssText = "border:0;border-radius:6px;padding:12px 18px;font:600 16px system-ui;cursor:pointer;color:#111;background:#fff";
      element.addEventListener("click", () => {
        host.remove();
        button.onClick();
      }, { once: true });
      controls.append(element);
    }
    panel.append(controls);
    shadow.append(panel);
    (document.body || document.documentElement).append(host);
    controls.querySelector("button")?.focus();
  }

  function navigate(anchor, url, targetTab) {
    if (targetTab && !targetTab.closed) {
      targetTab.location.replace(url);
      return;
    }
    if (anchor.target === "_top" && window.top !== window) {
      window.top.location.assign(url);
    } else if (anchor.target && anchor.target !== "_self") {
      window.open(url, anchor.target, "noopener");
    } else {
      window.location.assign(url);
    }
  }

  document.addEventListener("click", (event) => {
    if (event.defaultPrevented || (event.button !== 0 && event.button !== 1)) return;
    const anchor = event.composedPath().find((node) => node instanceof HTMLAnchorElement);
    if (!anchor || !anchor.href || anchor.hasAttribute("download")) return;
    const url = anchor.href;
    if (!/^https?:/i.test(url)) return;

    // Preserve the user's original click gesture for links that open a new tab.
    const opensNewContext = anchor.target === "_blank" || (event.ctrlKey || event.metaKey || event.shiftKey || event.button === 1);
    const pendingTab = opensNewContext ? window.open("about:blank", "_blank") : null;
    event.preventDefault();
    event.stopImmediatePropagation();

    chrome.runtime.sendMessage({ type: "GUARD_CHECK_LINK", url }, (result) => {
      if (chrome.runtime.lastError || !result?.ok) {
        pendingTab?.close();
        showDecision({
          title: "Guard AI",
          message: "Guard AI backend not running",
          english: "Guard AI could not check this link. Choose whether to continue.",
          telugu: "గార్డ్ ఏఐ ఈ లింక్‌ను తనిఖీ చేయలేకపోయింది. కొనసాగించాలా వద్దా ఎంచుకోండి.",
          color: "#4b5563",
          buttons: [
            { label: "Continue anyway", onClick: () => navigate(anchor, url) },
            { label: "Go back", onClick: () => {} }
          ]
        });
        return;
      }

      const english = result.english || "";
      const telugu = result.telugu || "";
      speak(english, telugu);
      if (result.action === "block") {
        pendingTab?.close();
        showDecision({
          title: "Dangerous link blocked",
          english,
          telugu,
          color: "#b91c1c",
          buttons: [{ label: "Go back", onClick: () => {} }]
        });
      } else if (result.action === "warn") {
        pendingTab?.close();
        showDecision({
          title: "Guard AI warning",
          english,
          telugu,
          color: "#ca8a04",
          buttons: [{ label: "Continue anyway", onClick: () => navigate(anchor, url) }]
        });
      } else if (result.action === "allow") {
        navigate(anchor, url, pendingTab);
      } else {
        pendingTab?.close();
        showDecision({
          title: "Guard AI",
          message: "Guard AI backend not running",
          english: "Guard AI returned an unknown decision. Choose whether to continue.",
          telugu: "గార్డ్ ఏఐ నిర్ణయం అందుబాటులో లేదు. కొనసాగించాలా వద్దా ఎంచుకోండి.",
          color: "#4b5563",
          buttons: [
            { label: "Continue anyway", onClick: () => navigate(anchor, url) },
            { label: "Go back", onClick: () => {} }
          ]
        });
      }
    });
  }, true);
})();
