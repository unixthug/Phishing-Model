async function getActiveTab() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  return tab;
}

function prettyLabel(label) {
  if (label === "danger") return "Danger";
  if (label === "sus") return "Suspicious";
  return "Safe";
}

function renderLoading(tabUrl) {
  document.getElementById("site").textContent = tabUrl || "Loading…";
  document.getElementById("score").textContent = "--";
  document.getElementById("label").textContent = "Unknown";
  document.getElementById("reason").textContent = "Loading…";
  document.getElementById("raw").textContent = "";
}

async function readAndRender(tabId, tabUrl) {
  document.getElementById("site").textContent = tabUrl || "(no url)";
  const key = `tab:${tabId}`;
  const data = (await browser.storage.local.get(key))[key];

  if (!data) {
    document.getElementById("score").textContent = "--";
    document.getElementById("label").textContent = "Unknown";
    document.getElementById("reason").textContent =
      "No data yet. If this is a single-page app, hit Refresh once.";
    document.getElementById("raw").textContent = "";
    return;
  }

  document.getElementById("score").textContent =
    data.score == null ? "--" : String(data.score);

  document.getElementById("label").textContent =
    data.label ? prettyLabel(data.label) : "Unknown";

  const reason = data.reason || "";
  const err = data.error ? `\n${data.error}` : "";
  document.getElementById("reason").textContent = (reason + err).trim() || "—";

  document.getElementById("raw").textContent =
    data.raw ? JSON.stringify(data.raw, null, 2) : "";
}

async function forceScoreNow(tabId) {
  // Ask background to score immediately
  try {
    await browser.runtime.sendMessage({ type: "SCORE_TAB_NOW", tabId });
  } catch {
    // ignore
  }
}

async function load({ force = false } = {}) {
  const tab = await getActiveTab();
  if (!tab?.id) return;

  renderLoading(tab.url);

  if (force) {
    await forceScoreNow(tab.id);
  }

  // Give background a moment to write storage after scoring
  await new Promise(r => setTimeout(r, 250));
  await readAndRender(tab.id, tab.url);
}

document.getElementById("refresh").addEventListener("click", () => load({ force: true }));

document.getElementById("openOptions").addEventListener("click", async () => {
  await browser.runtime.openOptionsPage();
  window.close();
});

// On popup open, force score once so user doesn't have to press Refresh.
load({ force: true });