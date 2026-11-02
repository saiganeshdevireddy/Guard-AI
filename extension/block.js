const parameters = new URLSearchParams(window.location.search);
document.getElementById("english-warning").textContent = parameters.get("english")
  || "Guard AI blocked this dangerous link.";
document.getElementById("telugu-warning").textContent = parameters.get("telugu")
  || "గార్డ్ ఏఐ ఈ ప్రమాదకరమైన లింక్‌ను బ్లాక్ చేసింది.";
document.getElementById("blocked-url").textContent = parameters.get("u") || "Unknown URL";
document.getElementById("go-back").addEventListener("click", () => {
  if (window.history.length > 1) window.history.back();
  else window.location.href = "https://www.google.com";
});
