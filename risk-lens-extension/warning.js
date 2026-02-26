function qp(name) {
  const u = new URL(location.href);
  return u.searchParams.get(name);
}

(async () => {
  const target = qp("target") || "";
  const score = qp("score");
  const verdict = qp("verdict");

  document.getElementById("target").textContent = target;
  document.getElementById("details").textContent =
    `Score: ${score ?? "?"} / 100` + (verdict ? ` • Verdict: ${verdict}` : "");

  // Load current setting
  const cfg = await browser.storage.local.get({ blockingEnabled: true });
  document.getElementById("disable").checked = !cfg.blockingEnabled;

  document.getElementById("disable").addEventListener("change", async (e) => {
    await browser.storage.local.set({ blockingEnabled: !e.target.checked });
  });

  document.getElementById("back").addEventListener("click", async () => {
    // Go back if possible, otherwise open a safe page
    history.length > 1 ? history.back() : (location.href = "about:blank");
  });

  document.getElementById("continue").addEventListener("click", async () => {
    // Tell background to allow this exact URL once (short TTL)
    await browser.runtime.sendMessage({ type: "ALLOW_ONCE", url: target });
    // Now navigate there
    location.href = target;
  });
})();