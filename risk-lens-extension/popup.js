function safeHostname(url) {
  try {
    const u = new URL(url);
    return u.hostname || url;
  } catch {
    return url || "";
  }
}

async function getActiveTab() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  return tabs[0];
}

function setRingProgress(score) {
  const ring = document.getElementById("ringFill");
  const r = 90;
  const C = 2 * Math.PI * r;

  ring.style.transition = "stroke-dasharray 260ms ease";

  if (score == null || !Number.isFinite(Number(score))) {
    ring.style.strokeDasharray = `0 ${C}`;
    return;
  }

  const s = Math.max(0, Math.min(100, Number(score)));
  const filled = (s / 100) * C;
  ring.style.strokeDasharray = `${filled} ${C}`;
}

function renderReasons(entry) {
  const list = document.getElementById("reasons");
  list.innerHTML = "";

  // Your background.js stores top reasons in `explanations` already
  const reasons =
    Array.isArray(entry?.explanations) ? entry.explanations :
    Array.isArray(entry?.raw?.reasons) ? entry.raw.reasons :
    Array.isArray(entry?.raw?.why_flagged) ? entry.raw.why_flagged :
    Array.isArray(entry?.raw?.explanations) ? entry.raw.explanations :
    [];

  if (!reasons.length) {
    const li = document.createElement("li");
    li.textContent = "No explanation data available.";
    list.appendChild(li);
    return;
  }

  for (const r of reasons.slice(0, 8)) {
    const li = document.createElement("li");
    li.textContent = String(r);
    list.appendChild(li);
  }
}

function renderRaw(entry) {
  const box = document.getElementById("rawJson");
  const raw = entry?.raw ?? {};

  if (typeof raw === "string") {
    box.textContent = raw;
    return;
  }

  try {
    box.textContent = JSON.stringify(raw, null, 2);
  } catch {
    box.textContent = String(raw);
  }
}

function setAdvancedFields(entry) {
  const verdict = entry?.raw?.verdict ?? entry?.verdict ?? "—";
  const prob = entry?.raw?.prob_phishing ?? entry?.prob_phishing ?? "—";

  document.getElementById("verdict").textContent = verdict == null ? "—" : String(verdict);
  document.getElementById("prob").textContent = prob == null ? "—" : String(prob);

  renderReasons(entry);
  renderRaw(entry);
}

async function loadScore() {
  const tab = await getActiveTab();
  if (!tab?.id) return;

  const key = `tab:${tab.id}`;
  const data = await browser.storage.local.get(key);
  const entry = data[key];

  const url = entry?.url || tab.url || "";
  document.getElementById("host").textContent = url ? safeHostname(url) : "—";

  if (!entry) {
    document.getElementById("score").textContent = "--";
    document.getElementById("status").textContent = "Loading…";
    setRingProgress(null);

    document.getElementById("verdict").textContent = "—";
    document.getElementById("prob").textContent = "—";
    document.getElementById("reasons").innerHTML = "";
    document.getElementById("rawJson").textContent = "{}";

    // Ask background to score immediately (your background.js supports this)
    await browser.runtime.sendMessage({ type: "SCORE_TAB_NOW", tabId: tab.id });
    return;
  }

  const score = entry.score != null ? Number(entry.score) : null;

  document.getElementById("score").textContent =
    score != null && Number.isFinite(score) ? `${Math.round(score)}` : "--";

  const label = entry.label ? String(entry.label).toUpperCase() : "UNKNOWN";

  document.getElementById("status").textContent =
    score != null && Number.isFinite(score) ? `${label} • ${Math.round(score)}/100` : label;

  setRingProgress(score);
  setAdvancedFields(entry);
}

/* Buttons */
document.getElementById("settingsBtn").addEventListener("click", async () => {
  await browser.runtime.openOptionsPage();
});

document.getElementById("siteBtn").addEventListener("click", async () => {
  await browser.tabs.create({ url: "https://eli-69.github.io/Risklens.github.io/" });
});

document.getElementById("darkModeBtn").addEventListener("click", async () => {
  const body = document.body;
  const isLight = body.classList.toggle("light-mode");
  await browser.storage.local.set({ popupLightMode: isLight });
});

/* Advanced toggle */
document.getElementById("advToggle").addEventListener("click", async () => {
  const panel = document.getElementById("advPanel");
  const btn = document.getElementById("advToggle");

  const open = panel.classList.toggle("open");
  btn.setAttribute("aria-expanded", open ? "true" : "false");

  // swap chevron character
  const chev = btn.querySelector(".chev");
  if (chev) chev.textContent = open ? "▴" : "▾";

  await browser.storage.local.set({ popupAdvancedOpen: open });
});

(async () => {
  const saved = await browser.storage.local.get({
    popupLightMode: false,
    popupAdvancedOpen: false
  });

  if (saved.popupLightMode) document.body.classList.add("light-mode");
  if (saved.popupAdvancedOpen) {
    document.getElementById("advPanel").classList.add("open");
    const btn = document.getElementById("advToggle");
    btn.setAttribute("aria-expanded", "true");
    const chev = btn.querySelector(".chev");
    if (chev) chev.textContent = "▴";
  }

  await loadScore();

  // Live updates while popup is open
  browser.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (Object.keys(changes).some((k) => k.startsWith("tab:"))) {
      loadScore().catch(() => {});
    }
  });
})();