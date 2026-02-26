const ICONS = {
  safe: "icons/safe.png",
  sus: "icons/sus.png",
  danger: "icons/danger.png",
};

function scoreToLabel(score0to100) {
  // Change these thresholds however you want
  if (score0to100 >= 70) return "danger";
  if (score0to100 >= 40) return "sus";
  return "safe";
}

async function fetchModelScore(urlString) {
  // ignore non-http(s)
  let u;
  try { u = new URL(urlString); } catch {
    return { score: null, label: "safe", reason: "Invalid URL" };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { score: null, label: "safe", reason: "Not a web page" };
  }

  // 2s timeout so the extension never “hangs”
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 2000);

  try {
    const res = await fetch("http://127.0.0.1:8000/score", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlString }),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`API error ${res.status}`);

    const json = await res.json();

    // Prefer a 0-100 score if your API returns it.
    // If only prob_phishing exists (0..1), convert to 0..100:
    let score = null;
    if (json.score != null) score = Number(json.score);
    else if (json.prob_phishing != null) score = Number(json.prob_phishing) * 100;

    if (!Number.isFinite(score)) {
      return { score: null, label: "safe", reason: "Bad model response", raw: json };
    }

    const label = scoreToLabel(score);

    return {
      score: Math.round(score * 10) / 10, // 1 decimal
      label,
      reason: json.verdict ? `Model: ${json.verdict}` : "Model result",
      raw: json,
    };
  } catch (e) {
    return {
      score: null,
      label: "safe",
      reason: "Model API unreachable (is it running?)",
      error: String(e),
    };
  } finally {
    clearTimeout(t);
  }
}

async function setStateForTab(tabId, url) {
  const result = await fetchModelScore(url);

  // store per-tab so popup can read it
  await browser.storage.session.set({
    [`tab:${tabId}`]: {
      tabId,
      url,
      ...result,
      updatedAt: Date.now(),
    },
  });

  // set per-tab icon
  await browser.browserAction.setIcon({
    tabId,
    path: ICONS[result.label] || ICONS.safe,
  });

  // tooltip title
  const title =
    result.score == null
      ? "RiskLens"
      : `RiskLens: ${result.score}/100 (${result.label})`;

  await browser.browserAction.setTitle({ tabId, title });
}

// when a tab loads
browser.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (!tab?.url) return;
  await setStateForTab(tabId, tab.url);
});

// when switching tabs
browser.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await browser.tabs.get(tabId);
  if (!tab?.url) return;
  await setStateForTab(tabId, tab.url);
});