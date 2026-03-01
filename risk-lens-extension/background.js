/* ============================== RiskLens Background ============================== */

const DEFAULTS = {
  apiBaseUrl: "https://risklens-api-9e7l.onrender.com",
  blockingEnabled: true,
  dangerThreshold: 70,
  cacheTtlMinutes: 10,
  bypassDurationMinutes: 60
};

let settings = { ...DEFAULTS };

// allowlistHosts: hostname -> expiresAtMs (0 = never)
let allowlistHosts = {};

// hostCache: hostname -> { score,label,verdict,raw,reason,error,updatedAtMs }
let hostCache = {};

function now() { return Date.now(); }
function isHttpUrl(url) { return url.startsWith("http://") || url.startsWith("https://"); }
function hostnameOf(urlString) { try { return new URL(urlString).hostname; } catch { return null; } }

async function saveHostCache() {
  await browser.storage.local.set({ hostCache });
}

async function saveAllowlist() {
  await browser.storage.local.set({ allowlistHosts });
}

function isAllowlisted(url) {
  const host = hostnameOf(url);
  if (!host) return false;

  const expiresAt = allowlistHosts[host];
  if (expiresAt == null) return false;

  if (expiresAt === 0) return true; // never expires

  if (typeof expiresAt === "number" && expiresAt > now()) return true;

  // expired -> cleanup
  delete allowlistHosts[host];
  saveAllowlist().catch(() => {});
  return false;
}

async function loadState() {
  const s = await browser.storage.local.get(DEFAULTS);
  settings = { ...DEFAULTS, ...s };

  const a = await browser.storage.local.get({ allowlistHosts: {}, allowlist: {} });
  // backward compat: migrate old exact-URL allowlist -> hostname allowlist
  allowlistHosts = a.allowlistHosts || {};
  if (!Object.keys(allowlistHosts).length && a.allowlist && typeof a.allowlist === "object") {
    for (const [url, exp] of Object.entries(a.allowlist)) {
      const h = hostnameOf(url);
      if (h) allowlistHosts[h] = exp;
    }
    await browser.storage.local.set({ allowlistHosts });
  }

  const c = await browser.storage.local.get({ hostCache: {} });
  hostCache = c.hostCache || {};
}

function scoreToLabel(score) {
  if (score == null) return "safe";
  const s = Number(score);
  if (!Number.isFinite(s)) return "safe";
  if (s >= 70) return "danger";
  if (s >= 40) return "suspicious";
  return "safe";
}

const ICONS = {
  safe: {
    16: "icons/safe-16.png",
    32: "icons/safe-32.png"
  },
  suspicious: {
    16: "icons/suspicious-16.png",
    32: "icons/suspicious-32.png"
  },
  danger: {
    16: "icons/danger-16.png",
    32: "icons/danger-32.png"
  }
};

function pickTopReasons(raw) {
  if (!raw) return [];
  const reasons = raw.reasons || raw.why_flagged || raw.explanations;
  if (Array.isArray(reasons)) return reasons.slice(0, 3);

  // If backend ever returns a dict of feature->importance, show top 3
  if (reasons && typeof reasons === "object") {
    const entries = Object.entries(reasons)
      .map(([k, v]) => ({ k, v: Number(v) }))
      .filter((x) => Number.isFinite(x.v))
      .sort((a, b) => b.v - a.v)
      .slice(0, 3)
      .map((x) => `${x.k}: ${x.v}`);
    return entries;
  }

  return [];
}

browser.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;

  if (changes.blockingEnabled) settings.blockingEnabled = !!changes.blockingEnabled.newValue;
  if (changes.dangerThreshold) settings.dangerThreshold = Number(changes.dangerThreshold.newValue);
  if (changes.bypassDurationMinutes) settings.bypassDurationMinutes = Number(changes.bypassDurationMinutes.newValue);
  if (changes.cacheTtlMinutes) settings.cacheTtlMinutes = Number(changes.cacheTtlMinutes.newValue);

  if (changes.allowlistHosts) allowlistHosts = changes.allowlistHosts.newValue || {};
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
  if (!["http:", "https:"].includes(u.protocol)) {
    return { score: null, label: "safe", reason: "Unsupported URL scheme" };
  }

  // No per-user API key (public API)
  const headers = { "Content-Type": "application/json" };

  const apiBase = (settings.apiBaseUrl || DEFAULTS.apiBaseUrl).replace(/\/+$/, "");
  const endpoint = `${apiBase}/score`;

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify({ url: urlString })
    });

    const text = await res.text();
    let data = null;
    try { data = JSON.parse(text); } catch {}

    if (!res.ok) {
      const msg =
        (data && (data.detail || data.error)) ||
        `API error (${res.status})`;
      return { score: null, label: "safe", reason: msg, raw: data || text };
    }

    const prob = data?.prob_phishing;
    const score = data?.score != null ? Number(data.score) :
      (Number.isFinite(Number(prob)) ? Math.round(Number(prob) * 100) : null);

    const label = scoreToLabel(score);
    const verdict = data?.verdict || null;

    return {
      score,
      label,
      verdict,
      reason: verdict ? `Model: ${verdict}` : "Model result",
      raw: data
    };
  } catch (e) {
    return { score: null, label: "safe", reason: "Network error", error: String(e) };
  }
}

/* ------------------------------ Tab state -------------------------------- */

async function setStateForTab(tabId, url) {
  const host = hostnameOf(url);
  if (!host) return;

  const cached = getCachedForHost(host);
  let hostEntry = cached;

  if (!cached) {
    const result = await fetchModelScore(url);
    hostEntry = {
      score: result.score,
      label: result.label,
      verdict: result.verdict,
      raw: result.raw || null,
      reason: result.reason || null,
      error: result.error || null,
      updatedAtMs: now()
    };
    hostCache[host] = hostEntry;
    await saveHostCache();
  }

  const explanations = pickTopReasons(hostEntry.raw);

  const result =
    hostEntry.error
      ? { score: null, label: "safe", reason: hostEntry.reason || "Error", error: hostEntry.error, raw: hostEntry.raw }
      : {
          score: hostEntry.score,
          label: hostEntry.label,
          reason: hostEntry.verdict ? `Model: ${hostEntry.verdict}` : "Model result",
          raw: hostEntry.raw,
        };

  await browser.storage.local.set({
    [`tab:${tabId}`]: { tabId, url, ...result, explanations, updatedAt: now() },
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
  if (msg?.type === "ALLOW_ONCE") {
    const targetUrl = typeof msg.url === "string" ? msg.url : "";
    const host = typeof msg.host === "string" ? msg.host : hostnameOf(targetUrl);
    if (!host) return;

    const minutes = Number(settings.bypassDurationMinutes);

    let expiresAt;
    if (!Number.isFinite(minutes) || minutes < 0) {
      expiresAt = now() + DEFAULTS.bypassDurationMinutes * 60_000;
    } else if (minutes === 0) {
      expiresAt = 0; // always
    } else {
      expiresAt = now() + minutes * 60_000;
    }

    allowlistHosts[host] = expiresAt;
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
          String(cached.score)
        )}&verdict=${encodeURIComponent(String(cached.verdict || ""))}`
      );

      return { redirectUrl: redirect };
    } catch {
      return {};
    }
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);

/* ------------------------------- Init -------------------------------- */

loadState().catch(() => {});