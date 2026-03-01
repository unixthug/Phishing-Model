// RiskLens background.js (Firefox MV2)

const ICONS = {
  safe: "icons/safe.png",
  sus: "icons/sus.png",
  danger: "icons/danger.png",
};

function scoreToLabel(score0to100) {
  if (score0to100 >= 70) return "danger";
  if (score0to100 >= 40) return "sus";
  return "safe";
}

// Your Render API
const API_URL = "https://risklens-api-9e7l.onrender.com/score";

const DEFAULTS = {
  blockingEnabled: true,
  dangerThreshold: 70,
  bypassDurationMinutes: 60, // 0 = Always
  cacheTtlMinutes: 30,
  apiKey: ""
};

let settings = { ...DEFAULTS };

// allowlist: url -> expiresAtMs (0 = never)
let allowlist = {};

// hostCache: hostname -> { score,label,verdict,raw,reason,error,updatedAtMs }
let hostCache = {};

function now() { return Date.now(); }
function isHttpUrl(url) { return url.startsWith("http://") || url.startsWith("https://"); }
function hostnameOf(urlString) { try { return new URL(urlString).hostname; } catch { return null; } }

async function loadState() {
  const s = await browser.storage.local.get(DEFAULTS);
  settings = { ...DEFAULTS, ...s };

  const a = await browser.storage.local.get({ allowlist: {} });
  allowlist = a.allowlist || {};

  const c = await browser.storage.local.get({ hostCache: {} });
  hostCache = c.hostCache || {};
}

function buildExplanation(raw) {
  if (!raw) return [];

  const reasons = [];

  // You can expand this later
  if (raw?.features) {
    const f = raw.features;

    if (f.has_ip) reasons.push("Uses IP address instead of domain");
    if (f.punycode) reasons.push("Uses encoded domain (possible spoofing)");
    if (f.shortener) reasons.push("Uses URL shortener");
    if (f.susp_words_host || f.susp_words_path_query)
      reasons.push("Contains suspicious keywords");
    if (f.entropy_url > 4) reasons.push("Unusual/random-looking URL");
    if (f.longest_digit_run > 5) reasons.push("Long digit sequences in URL");
  }

  return reasons.slice(0, 3); // keep it clean
}

browser.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;

  if (changes.blockingEnabled) settings.blockingEnabled = !!changes.blockingEnabled.newValue;
  if (changes.dangerThreshold) settings.dangerThreshold = Number(changes.dangerThreshold.newValue);
  if (changes.bypassDurationMinutes) settings.bypassDurationMinutes = Number(changes.bypassDurationMinutes.newValue);
  if (changes.cacheTtlMinutes) settings.cacheTtlMinutes = Number(changes.cacheTtlMinutes.newValue);

  if (changes.apiKey) {
    settings.apiKey = String(changes.apiKey.newValue || "");

    // 🔥 CLEAR CACHE when API key changes
    hostCache = {};
    browser.storage.local.set({ hostCache: {} });
  }

  if (changes.allowlist) allowlist = changes.allowlist.newValue || {};
  if (changes.hostCache) hostCache = changes.hostCache.newValue || {};
});

function getCachedForHost(host) {
  const entry = hostCache[host];
  if (!entry) return null;

  const ttlMs = Number(settings.cacheTtlMinutes) * 60_000;
  if (typeof entry.updatedAtMs === "number" && entry.updatedAtMs + ttlMs > now()) return entry;

  delete hostCache[host];
  saveHostCache().catch(() => {});
  return null;
}

/* ------------------------------ Model scoring -------------------------------- */

async function fetchModelScore(urlString) {
  let u;
  try { u = new URL(urlString); } catch {
    return { score: null, label: "safe", reason: "Invalid URL" };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { score: null, label: "safe", reason: "Not a web page" };
  }

  // ✅ ALWAYS pull key at request time (prevents startup race)
  const { apiKey } = await browser.storage.local.get({ apiKey: "" });

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 20000);

  try {
    const headers = { "Content-Type": "application/json" };
    if (apiKey) headers["x-api-key"] = apiKey;

    const res = await fetch(API_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ url: urlString }),
      signal: controller.signal,
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`API error ${res.status} ${text}`.trim());
    }

    const json = await res.json();

    let score = null;
    if (json.score != null) score = Number(json.score);
    else if (json.prob_phishing != null) score = Number(json.prob_phishing) * 100;

    if (!Number.isFinite(score)) {
      return { score: null, label: "safe", reason: "Bad model response", raw: json };
    }

    const label = scoreToLabel(score);

    return {
      score: Math.round(score * 10) / 10,
      label,
      reason: json.verdict ? `Model: ${json.verdict}` : "Model result",
      raw: json,
    };
  } catch (e) {
    return {
      score: null,
      label: "safe",
      reason: "API call failed",
      error: String(e),
    };
  } finally {
    clearTimeout(t);
  }
}

async function scoreAndCacheHost(urlString) {
  const host = hostnameOf(urlString);
  if (!host) return null;

  const cached = getCachedForHost(host);
  if (cached) return cached;

  const r = await fetchModelScore(urlString);

  // DO NOT CACHE failures
  if (r.score == null) {
  return {
    score: null,
    label: r.label,
    verdict: r.raw?.verdict,
    raw: r.raw,
    reason: r.reason || "",
    error: r.error || "",
    updatedAtMs: now(),
  };
}

  const entry = {
    score: r.score,
    label: r.label,
    verdict: r.raw?.verdict,
    raw: r.raw,
    reason: r.reason || "",
    error: r.error || "",
    updatedAtMs: now(),
  };
  if (entry.score != null) {
    hostCache[host] = entry;
    await saveHostCache();
  }

  return entry;
}

/* --------------------------- Per-tab UI (icons) ------------------------------ */

async function setStateForTab(tabId, url) {
  const hostEntry = await scoreAndCacheHost(url);
  const explanations = buildExplanation(hostEntry?.raw);
  await browser.storage.local.set({
    [`tab:${tabId}`]: {
      tabId,
      url,
      ...result,
      explanations, // ✅ ADD THIS
      updatedAt: now(),
    },
  });

  const result =
    hostEntry?.score == null
      ? {
          score: null,
          label: hostEntry?.label || "safe",
          reason: hostEntry?.reason || "No score",
          raw: hostEntry?.raw,
          error: hostEntry?.error,
        }
      : {
          score: hostEntry.score,
          label: hostEntry.label,
          reason: hostEntry.verdict ? `Model: ${hostEntry.verdict}` : "Model result",
          raw: hostEntry.raw,
        };

  await browser.storage.local.set({
    [`tab:${tabId}`]: { tabId, url, ...result, updatedAt: now() },
  });

  await browser.browserAction.setIcon({
    tabId,
    path: ICONS[result.label] || ICONS.safe,
  });

  const title =
    result.score == null ? "RiskLens" : `RiskLens: ${result.score}/100 (${result.label})`;

  await browser.browserAction.setTitle({ tabId, title });
}

browser.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (!tab?.url || !isHttpUrl(tab.url)) return;
  await setStateForTab(tabId, tab.url);
});

browser.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await browser.tabs.get(tabId);
  if (!tab?.url || !isHttpUrl(tab.url)) return;
  await setStateForTab(tabId, tab.url);
});

browser.tabs.onRemoved.addListener((tabId) => {
  browser.storage.local.remove(`tab:${tabId}`).catch(() => {});
});

/* ------------------------ Warning page + allow bypass ------------------------- */

browser.runtime.onMessage.addListener(async (msg) => {
  // Popup asks background to score the active tab immediately
  if (msg?.type === "SCORE_TAB_NOW" && Number.isFinite(msg.tabId)) {
    const tab = await browser.tabs.get(msg.tabId);
    if (tab?.url && tab.id != null) {
      if (tab.url.startsWith("http://") || tab.url.startsWith("https://")) {
        await setStateForTab(tab.id, tab.url);
      }
    }
    return;
  }

  // warning.html sends this when the user clicks "Continue Anyway".
  if (msg?.type === "ALLOW_ONCE" && typeof msg.url === "string") {
    const minutes = Number(settings.bypassDurationMinutes);

    if (!Number.isFinite(minutes) || minutes < 0) {
      allowlist[msg.url] = now() + DEFAULTS.bypassDurationMinutes * 60_000;
    } else if (minutes === 0) {
      allowlist[msg.url] = 0;
    } else {
      allowlist[msg.url] = now() + minutes * 60_000;
    }
    await saveAllowlist();
    return;
  }
});

/* --------------------------- Blocking / redirecting --------------------------- */

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    try {
      if (!settings.blockingEnabled) return {};
      if (details.type !== "main_frame") return {};

      const url = details.url;
      if (!isHttpUrl(url)) return {};

      const warningPrefix = browser.runtime.getURL("warning.html");
      if (url.startsWith(warningPrefix)) return {};

      if (isAllowlisted(url)) return {};

      const host = hostnameOf(url);
      if (!host) return {};

      const cached = getCachedForHost(host);
      if (!cached || cached.score == null) return {};

      const isDanger = Number(cached.score) >= Number(settings.dangerThreshold);
      if (!isDanger) return {};

      const redirect = browser.runtime.getURL(
        `warning.html?target=${encodeURIComponent(url)}&score=${encodeURIComponent(
          cached.score
        )}&verdict=${encodeURIComponent(cached.verdict || "")}`
      );

      return { redirectUrl: redirect };
    } catch {
      return {};
    }
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);

loadState().catch(() => {});