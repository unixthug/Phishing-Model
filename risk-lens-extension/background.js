// RiskLens background.js (Firefox MV2)
//
// What this does:
// - Calls your hosted API (/score) to get a 0–100 score (or prob_phishing -> score).
// - Sets the toolbar icon per-tab (safe / sus / danger).
// - If "blockingEnabled" is ON and a URL is known-dangerous (cached), it redirects the tab
//   to warning.html (an interstitial).
// - "Continue anyway" sends ALLOW_ONCE to bypass blocking for a configurable duration.
//
// Notes / limitations:
// - To *truly* block a never-before-seen URL BEFORE it loads, you'd need a precomputed
//   score (cache) or accept gating/redirecting unknown sites to a "checking" page.
//   This implementation blocks based on cached verdicts (fast + practical UX).

/* ----------------------------- Icons + thresholds ----------------------------- */

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

/* ------------------------------- API config --------------------------------- */

// TODO: replace with your real Render endpoint:
const API_URL = "https://YOUR-RENDER-SERVICE.onrender.com/score";

// If you are NOT using a key, leave as "".
// If you set RISKLENS_API_KEY on the server, set the same value here.
const API_KEY = "";

/* ------------------------------ Settings model ------------------------------- */

const DEFAULTS = {
  blockingEnabled: true,
  dangerThreshold: 70,         // score >= this triggers warning redirect
  bypassDurationMinutes: 60,   // dropdown default (1 hour); 0 means "Always"
  cacheTtlMinutes: 30,         // how long to trust cached scores per-host
};

let settings = { ...DEFAULTS };

// allowlist: key -> expiresAtMs (0 means never expires)
let allowlist = {};

// cache: hostname -> { score, label, verdict, updatedAtMs, raw }
let hostCache = {};

// Load everything once at startup, and keep in-memory copies updated.
async function loadState() {
  const s = await browser.storage.local.get(DEFAULTS);
  settings = { ...DEFAULTS, ...s };

  const a = await browser.storage.local.get({ allowlist: {} });
  allowlist = a.allowlist || {};

  const c = await browser.storage.local.get({ hostCache: {} });
  hostCache = c.hostCache || {};
}

browser.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;

  if (changes.blockingEnabled) settings.blockingEnabled = !!changes.blockingEnabled.newValue;
  if (changes.dangerThreshold) settings.dangerThreshold = Number(changes.dangerThreshold.newValue);
  if (changes.bypassDurationMinutes) settings.bypassDurationMinutes = Number(changes.bypassDurationMinutes.newValue);

  if (changes.allowlist) allowlist = changes.allowlist.newValue || {};
  if (changes.hostCache) hostCache = changes.hostCache.newValue || {};
});

// Persist helpers (keep memory + disk in sync)
async function saveAllowlist() {
  await browser.storage.local.set({ allowlist });
}
async function saveHostCache() {
  await browser.storage.local.set({ hostCache });
}

function now() {
  return Date.now();
}

function isHttpUrl(url) {
  return url.startsWith("http://") || url.startsWith("https://");
}

function hostnameOf(urlString) {
  try {
    return new URL(urlString).hostname;
  } catch {
    return null;
  }
}

function isAllowlisted(urlString) {
  const exp = allowlist[urlString];
  if (exp === 0) return true;          // never expires
  if (typeof exp === "number" && exp > now()) return true;

  // expired -> clean up
  if (typeof exp === "number" && exp !== 0 && exp <= now()) {
    delete allowlist[urlString];
    // fire-and-forget cleanup
    saveAllowlist().catch(() => {});
  }
  return false;
}

function getCachedForHost(host) {
  const entry = hostCache[host];
  if (!entry) return null;

  const ttlMs = settings.cacheTtlMinutes * 60_000;
  if (typeof entry.updatedAtMs === "number" && entry.updatedAtMs + ttlMs > now()) return entry;

  // expired -> cleanup
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

  // Render cold-start can be slow; 20s is safer for first hit.
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), 20000);

  try {
    const headers = { "Content-Type": "application/json" };
    if (API_KEY) headers["X-API-Key"] = API_KEY;

    const res = await fetch(API_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ url: urlString }),
      signal: controller.signal,
    });

    if (!res.ok) throw new Error(`API error ${res.status}`);

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
      reason: "RiskLens API unreachable (or waking up)",
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
  const entry = {
    score: r.score,
    label: r.label,
    verdict: r.raw?.verdict,
    raw: r.raw,
    updatedAtMs: now(),
  };

  hostCache[host] = entry;
  await saveHostCache();

  return entry;
}

/* --------------------------- Per-tab UI (icons) ------------------------------ */

async function setStateForTab(tabId, url) {
  // We score and cache by host, but we still show per-tab info in session storage for the popup.
  const hostEntry = await scoreAndCacheHost(url);

  const result = hostEntry?.score == null
    ? { score: null, label: "safe", reason: "No score", raw: hostEntry?.raw }
    : {
        score: hostEntry.score,
        label: hostEntry.label,
        reason: hostEntry.verdict ? `Model: ${hostEntry.verdict}` : "Model result",
        raw: hostEntry.raw,
      };

  await browser.storage.session.set({
    [`tab:${tabId}`]: {
      tabId,
      url,
      ...result,
      updatedAt: now(),
    },
  });

  await browser.browserAction.setIcon({
    tabId,
    path: ICONS[result.label] || ICONS.safe,
  });

  const title =
    result.score == null
      ? "RiskLens"
      : `RiskLens: ${result.score}/100 (${result.label})`;

  await browser.browserAction.setTitle({ tabId, title });
}

// On page load completion, score/caches and update icon.
browser.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (!tab?.url) return;
  if (!isHttpUrl(tab.url)) return;
  await setStateForTab(tabId, tab.url);
});

// When switching tabs, refresh state/icon.
browser.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await browser.tabs.get(tabId);
  if (!tab?.url) return;
  if (!isHttpUrl(tab.url)) return;
  await setStateForTab(tabId, tab.url);
});

/* ------------------------ Warning page + allow bypass ------------------------- */

// warning.html sends this when the user clicks "Continue Anyway".
browser.runtime.onMessage.addListener(async (msg) => {
  if (msg?.type === "ALLOW_ONCE" && typeof msg.url === "string") {
    const minutes = Number(settings.bypassDurationMinutes);

    if (!Number.isFinite(minutes) || minutes < 0) {
      allowlist[msg.url] = now() + DEFAULTS.bypassDurationMinutes * 60_000;
    } else if (minutes === 0) {
      // "Always"
      allowlist[msg.url] = 0;
    } else {
      allowlist[msg.url] = now() + minutes * 60_000;
    }
    await saveAllowlist();
  }

  // Optional: warning page can ask for a score explicitly.
  // msg: { type: "SCORE_URL", url: "https://..." }
  if (msg?.type === "SCORE_URL" && typeof msg.url === "string") {
    const entry = await scoreAndCacheHost(msg.url);
    return entry || null;
  }
});

/* --------------------------- Blocking / redirecting --------------------------- */

// We only redirect when:
// - blockingEnabled is ON
// - URL is http(s)
// - URL not allowlisted
// - host is cached as dangerous (score >= dangerThreshold)
// This avoids blocking *all* unknown sites, while still preventing revisits to known-dangerous hosts.

browser.webRequest.onBeforeRequest.addListener(
  (details) => {
    try {
      if (!settings.blockingEnabled) return {};

      if (details.type !== "main_frame") return {};
      const url = details.url;
      if (!isHttpUrl(url)) return {};

      // Don't block our own warning page
      const warningPrefix = browser.runtime.getURL("warning.html");
      if (url.startsWith(warningPrefix)) return {};

      // Allow bypass
      if (isAllowlisted(url)) return {};

      const host = hostnameOf(url);
      if (!host) return {};

      const cached = getCachedForHost(host);
      if (!cached || cached.score == null) return {}; // not known-dangerous yet

      const isDanger = Number(cached.score) >= Number(settings.dangerThreshold);
      if (!isDanger) return {};

      const redirect = browser.runtime.getURL(
        `warning.html?target=${encodeURIComponent(url)}&score=${encodeURIComponent(cached.score)}&verdict=${encodeURIComponent(cached.verdict || "")}`
      );

      return { redirectUrl: redirect };
    } catch {
      return {};
    }
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);

/* --------------------------------- Startup ---------------------------------- */

loadState().catch(() => {});