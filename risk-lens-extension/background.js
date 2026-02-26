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

// ✅ Your Render API
const API_URL = "https://risklens-api-9e7l.onrender.com/score";
const API_KEY = "32d4c8bbd3de7a77c2704bf4a28afa68";

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

// Load persisted state
async function loadState() {
  const s = await browser.storage.local.get(DEFAULTS);
  settings = { ...DEFAULTS, ...s };

  const a = await browser.storage.local.get({ allowlist: {} });
  allowlist = a.allowlist || {};

  const c = await browser.storage.local.get({ hostCache: {} });
  hostCache = c.hostCache || {};
}

// Keep in-memory copies updated
browser.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;

  if (changes.blockingEnabled) settings.blockingEnabled = !!changes.blockingEnabled.newValue;
  if (changes.dangerThreshold) settings.dangerThreshold = Number(changes.dangerThreshold.newValue);
  if (changes.bypassDurationMinutes) settings.bypassDurationMinutes = Number(changes.bypassDurationMinutes.newValue);
  if (changes.cacheTtlMinutes) settings.cacheTtlMinutes = Number(changes.cacheTtlMinutes.newValue);

  if (changes.allowlist) allowlist = changes.allowlist.newValue || {};
  if (changes.hostCache) hostCache = changes.hostCache.newValue || {};
});

async function saveAllowlist() {
  await browser.storage.local.set({ allowlist });
}
async function saveHostCache() {
  await browser.storage.local.set({ hostCache });
}

function isAllowlisted(urlString) {
  const exp = allowlist[urlString];
  if (exp === 0) return true;
  if (typeof exp === "number" && exp > now()) return true;

  if (typeof exp === "number" && exp !== 0 && exp <= now()) {
    delete allowlist[urlString];
    saveAllowlist().catch(() => {});
  }
  return false;
}

function getCachedForHost(host) {
  const entry = hostCache[host];
  if (!entry) return null;

  const ttlMs = Number(settings.cacheTtlMinutes) * 60_000;
  if (typeof entry.updatedAtMs === "number" && entry.updatedAtMs + ttlMs > now()) return entry;

  delete hostCache[host];
  saveHostCache().catch(() => {});
  return null;
}

async function fetchModelScore(urlString) {
  let u;
  try { u = new URL(urlString); } catch {
    return { score: null, label: "safe", reason: "Invalid URL" };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { score: null, label: "safe", reason: "Not a web page" };
  }

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 20000);

  try {
    const headers = { "Content-Type": "application/json" };
    if (settings.apiKey) headers["x-api-key"] = settings.apiKey;

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
      raw: json
    };
  } catch (e) {
    return {
      score: null,
      label: "safe",
      reason: "RiskLens API unreachable (or waking up)",
      error: String(e)
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

  // ✅ IMPORTANT: keep reason/error so popup can show real failures
  const entry = {
    score: r.score,
    label: r.label,
    verdict: r.raw?.verdict,
    raw: r.raw,
    reason: r.reason || "",
    error: r.error || "",
    updatedAtMs: now()
  };

  hostCache[host] = entry;
  await saveHostCache();
  return entry;
}

async function setStateForTab(tabId, url) {
  const hostEntry = await scoreAndCacheHost(url);

  const result =
    hostEntry?.score == null
      ? {
          score: null,
          label: hostEntry?.label || "safe",
          reason: hostEntry?.reason || "No score",
          raw: hostEntry?.raw,
          error: hostEntry?.error
        }
      : {
          score: hostEntry.score,
          label: hostEntry.label,
          reason: hostEntry.verdict ? `Model: ${hostEntry.verdict}` : "Model result",
          raw: hostEntry.raw
        };

  await browser.storage.local.set({
    [`tab:${tabId}`]: {
      tabId,
      url,
      ...result,
      updatedAt: now()
    }
  });

  await browser.browserAction.setIcon({
    tabId,
    path: ICONS[result.label] || ICONS.safe
  });

  const title =
    result.score == null ? "RiskLens" : `RiskLens: ${result.score}/100 (${result.label})`;

  await browser.browserAction.setTitle({ tabId, title });
}

// Update on load
browser.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (!tab?.url || !isHttpUrl(tab.url)) return;
  await setStateForTab(tabId, tab.url);
});

// Update when switching tabs
browser.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await browser.tabs.get(tabId);
  if (!tab?.url || !isHttpUrl(tab.url)) return;
  await setStateForTab(tabId, tab.url);
});

// Cleanup per-tab storage
browser.tabs.onRemoved.addListener((tabId) => {
  browser.storage.local.remove(`tab:${tabId}`).catch(() => {});
});

// Continue anyway handler
browser.runtime.onMessage.addListener(async (msg) => {
  if (msg?.type === "ALLOW_ONCE" && typeof msg.url === "string") {
    const minutes = Number(settings.bypassDurationMinutes);

    if (!Number.isFinite(minutes) || minutes < 0) {
      allowlist[msg.url] = now() + DEFAULTS.bypassDurationMinutes * 60_000;
    } else if (minutes === 0) {
      allowlist[msg.url] = 0; // never expires
    } else {
      allowlist[msg.url] = now() + minutes * 60_000;
    }
    await saveAllowlist();
  }
});

// Redirect known-dangerous cached hosts (avoids blocking everything)
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