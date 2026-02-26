async function getActiveTab() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function prettyLabel(label) {
  if (label === "danger") return "Danger";
  if (label === "sus") return "Suspicious";
  return "Safe";
}

async function load() {
  const tab = await getActiveTab();
  if (!tab?.id) return;

  document.getElementById("site").textContent = tab.url || "(no url)";

  const key = `tab:${tab.id}`;
  const data = (await browser.storage.local.get(key))[key];

  if (!data) {
    document.getElementById("score").textContent = "--";
    document.getElementById("label").textContent = "Unknown";
    document.getElementById("reason").textContent =
      "No data yet. Refresh after the page finishes loading.";
    document.getElementById("raw").textContent = "";
    return;
  }

  document.getElementById("score").textContent =
    data.score == null ? "--" : String(data.score);

  document.getElementById("label").textContent =
    data.label ? prettyLabel(data.label) : "Unknown";

  // ✅ show useful reason/errors
  const reason = data.reason || "";
  const err = data.error ? `\n${data.error}` : "";
  document.getElementById("reason").textContent = (reason + err).trim() || "—";

  document.getElementById("raw").textContent =
    data.raw ? JSON.stringify(data.raw, null, 2) : "";
}

document.getElementById("refresh").addEventListener("click", load);
load();