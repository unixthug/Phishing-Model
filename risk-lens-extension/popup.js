let showAdvanced = false;

function scoreToClass(score) {
  if (score >= 70) return "danger";
  if (score >= 40) return "sus";
  return "safe";
}

function timeAgo(ts) {
  if (!ts) return "--";
  const diff = Math.floor((Date.now() - ts) / 1000);

  if (diff < 5) return "just now";
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

async function getActiveTab() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  return tab;
}

// Smooth count-up animation
function animateScore(el, target) {
  let current = 0;
  const duration = 400;
  const stepTime = 16;
  const steps = duration / stepTime;
  const increment = target / steps;

  const interval = setInterval(() => {
    current += increment;

    if (current >= target) {
      current = target;
      clearInterval(interval);
    }

    el.textContent = `${Math.round(current)}/100`;
  }, stepTime);
}

async function loadData() {
  const tab = await getActiveTab();
  if (!tab?.id) return;

  const key = `tab:${tab.id}`;
  const data = (await browser.storage.local.get(key))[key];

  const scoreEl = document.getElementById("scoreText");
  const labelEl = document.getElementById("labelText");
  const metaEl = document.getElementById("meta");
  const bar = document.getElementById("barFill");

  if (data?.score != null) {
    const score = Math.round(data.score);

    // Animate score
    animateScore(scoreEl, score);

    const cls = scoreToClass(score);

    scoreEl.className = cls;
    labelEl.className = cls;

    labelEl.textContent = data.label;

    // Animate bar
    bar.style.width = `${score}%`;
    bar.className = `${cls}-bg`;
  } else {
    scoreEl.textContent = "--";
    labelEl.textContent = "No score";
    bar.style.width = "0%";
  }

  const age = timeAgo(data?.updatedAt);
  const isFresh = age === "just now" || age.includes("s");
  metaEl.textContent = `${isFresh ? "⚡ fresh" : "🕒 cached"} • ${age}`;

  document.getElementById("reason").textContent = data?.reason || "";
  document.getElementById("error").textContent = data?.error || "";
  document.getElementById("rawJson").textContent =
    data?.raw ? JSON.stringify(data.raw, null, 2) : "";

  // Explanations (Why flagged)
  const list = document.getElementById("explanations");
  list.innerHTML = "";
  (data?.explanations || []).forEach((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    list.appendChild(li);
  });
}

function updateView() {
  const adv = document.getElementById("advancedView");
  const btn = document.getElementById("toggleAdvanced");

  if (showAdvanced) {
    adv.style.display = "block";
    btn.textContent = "Hide Advanced";
  } else {
    adv.style.display = "none";
    btn.textContent = "Show Advanced";
  }
}

async function init() {
  const { showAdvancedView } = await browser.storage.local.get({
    showAdvancedView: false,
  });

  showAdvanced = showAdvancedView;

  updateView();
  await loadData();
}

// Refresh
document.getElementById("refreshBtn").addEventListener("click", async () => {
  const tab = await getActiveTab();
  if (!tab?.id) return;

  const btn = document.getElementById("refreshBtn");
  btn.disabled = true;
  btn.textContent = "Refreshing...";

  // background.js listens for SCORE_TAB_NOW
  await browser.runtime.sendMessage({
    type: "SCORE_TAB_NOW",
    tabId: tab.id,
  });

  // give background a moment to store tab state
  setTimeout(async () => {
    await loadData();
    btn.disabled = false;
    btn.textContent = "Refresh Score";
  }, 700);
});

// Toggle advanced
document.getElementById("toggleAdvanced").addEventListener("click", async () => {
  showAdvanced = !showAdvanced;

  await browser.storage.local.set({
    showAdvancedView: showAdvanced,
  });

document.getElementById("openOptions").addEventListener("click", async () => {
  if (browser?.runtime?.openOptionsPage) {
    await browser.runtime.openOptionsPage();
  } else {
    await browser.tabs.create({ url: browser.runtime.getURL("options.html") });
  }
});

  updateView();
});

init();