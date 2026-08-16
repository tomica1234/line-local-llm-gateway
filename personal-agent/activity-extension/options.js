async function load() {
  const settings = await browser.storage.local.get(["coreUrl", "activityToken", "paused"]);
  document.querySelector("#core-url").value = settings.coreUrl || "";
  document.querySelector("#activity-token").value = settings.activityToken || "";
  document.querySelector("#paused").checked = Boolean(settings.paused);
}

document.querySelector("#settings").addEventListener("submit", async (event) => {
  event.preventDefault();
  await browser.storage.local.set({
    coreUrl: document.querySelector("#core-url").value.replace(/\/$/, ""),
    activityToken: document.querySelector("#activity-token").value,
    paused: document.querySelector("#paused").checked,
  });
  await browser.runtime.sendMessage({ type: "flush_now" });
  document.querySelector("#status").textContent = "保存しました。";
});

load();
