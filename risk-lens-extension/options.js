const DEFAULTS = {
  blockingEnabled: true,
  dangerThreshold: 70,
  bypassDurationMinutes: 60
};

async function load() {
  const cfg = await browser.storage.local.get(DEFAULTS);
  document.getElementById("blockingEnabled").checked = !!cfg.blockingEnabled;
  document.getElementById("dangerThreshold").value = String(cfg.dangerThreshold);
  document.getElementById("bypassDuration").value = String(cfg.bypassDurationMinutes);
}

async function save() {
  const blockingEnabled = document.getElementById("blockingEnabled").checked;
  const dangerThreshold = Number(document.getElementById("dangerThreshold").value);
  const bypassDurationMinutes = Number(document.getElementById("bypassDuration").value);

  await browser.storage.local.set({
    blockingEnabled,
    dangerThreshold: Number.isFinite(dangerThreshold) ? dangerThreshold : DEFAULTS.dangerThreshold,
    bypassDurationMinutes: Number.isFinite(bypassDurationMinutes) ? bypassDurationMinutes : DEFAULTS.bypassDurationMinutes
  });

  const status = document.getElementById("status");
  status.textContent = "Saved.";
  setTimeout(() => status.textContent = "", 1200);
}

document.getElementById("saveBtn").addEventListener("click", save);

load();