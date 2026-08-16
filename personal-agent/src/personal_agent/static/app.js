const state = {
  tasks: [],
  continuationTaskId: null,
  passkeyAuthenticated: false,
  chatBusy: false,
};

const $ = (selector) => document.querySelector(selector);
const adminHeaders = () => {
  const token = $("#admin-token")?.value || "";
  return token ? { "X-Admin-Token": token } : {};
};
const hasAdminAccess = () => Boolean($("#admin-token")?.value || state.passkeyAuthenticated);
const escapeHtml = (value) => String(value)
  .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;").replaceAll("'", "&#039;");

async function api(path, options = {}) {
  const { headers = {}, ...requestOptions } = options;
  const response = await fetch(path, {
    ...requestOptions,
    headers: { "Content-Type": "application/json", ...headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `HTTP ${response.status}`);
  }
  return response.json();
}

function decodeBase64Url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64Url(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function decodeRequestOptions(options) {
  return {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((item) => ({
      ...item, id: decodeBase64Url(item.id),
    })),
  };
}

function decodeCreationOptions(options) {
  return {
    ...options,
    challenge: decodeBase64Url(options.challenge),
    user: { ...options.user, id: decodeBase64Url(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((item) => ({
      ...item, id: decodeBase64Url(item.id),
    })),
  };
}

function serializeCredential(credential) {
  if (!credential) throw new Error("Passkey操作がキャンセルされました。");
  const response = {
    clientDataJSON: encodeBase64Url(credential.response.clientDataJSON),
  };
  if (credential.response.attestationObject) {
    response.attestationObject = encodeBase64Url(credential.response.attestationObject);
    response.transports = credential.response.getTransports?.() || [];
  } else {
    response.authenticatorData = encodeBase64Url(credential.response.authenticatorData);
    response.signature = encodeBase64Url(credential.response.signature);
    response.userHandle = credential.response.userHandle ? encodeBase64Url(credential.response.userHandle) : null;
  }
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults(),
    response,
  };
}

async function loadPasskeyStatus() {
  const status = await api("/api/webauthn/status");
  state.passkeyAuthenticated = status.authenticated;
  const supported = Boolean(window.PublicKeyCredential && navigator.credentials);
  const statusNode = $("#passkey-status");
  const login = $("#passkey-login");
  const logout = $("#passkey-logout");
  const register = $("#passkey-register-form");
  login.hidden = !status.configured || !supported || status.authenticated || status.credential_count === 0;
  logout.hidden = !status.authenticated;
  register.hidden = !status.configured || !supported;
  if (!status.configured) {
    statusNode.textContent = "HTTPSのRP ID/Originが未設定です。iPhone連携はまだ無効です。";
  } else if (!supported) {
    statusNode.textContent = "このBrowserはWebAuthn Passkeyに対応していません。";
  } else if (status.authenticated) {
    statusNode.textContent = `Passkeyでサインイン済み · ${status.credential_count}台登録`;
  } else if (status.credential_count) {
    statusNode.textContent = `${status.credential_count}台登録済み · Face IDでサインインできます。`;
  } else {
    statusNode.textContent = "初回だけAdmin Tokenを入力し、このiPhoneのFace IDを登録してください。";
  }
  const list = $("#passkey-list");
  if (!status.configured || !hasAdminAccess()) {
    list.replaceChildren();
    return status;
  }
  const credentials = await api("/api/webauthn/credentials", { headers: adminHeaders() });
  list.innerHTML = credentials.length ? credentials.map((item) =>
    `<article class="usage-row"><strong>${escapeHtml(item.label)}</strong><span>${item.backed_up ? "synced/backup" : "single-device"}</span><small>${escapeHtml(item.device_type)} · ${new Date(item.created_at).toLocaleString("ja-JP")}</small><button class="danger" data-revoke-passkey="${escapeHtml(item.credential_id)}" type="button">失効</button></article>`
  ).join("") : '<p class="muted">Passkeyはまだ登録されていません。</p>';
  list.querySelectorAll("[data-revoke-passkey]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (!state.passkeyAuthenticated) await loginWithPasskey();
      if (!confirm("このPasskeyを失効しますか？ 最後の1本は失効できません。")) return;
      await api(`/api/webauthn/credentials/${encodeURIComponent(button.dataset.revokePasskey)}`, {
        method: "DELETE",
      });
      await loadPasskeyStatus();
    });
  });
  return status;
}

async function registerPasskey(event) {
  event.preventDefault();
  const status = await api("/api/webauthn/status");
  if (status.credential_count === 0 && !$("#admin-token").value) {
    return alert("初回登録にはAdmin Tokenが必要です。");
  }
  if (status.credential_count > 0 && !state.passkeyAuthenticated) {
    await loginWithPasskey();
  }
  const start = await api("/api/webauthn/register/options", {
    method: "POST",
    headers: adminHeaders(),
    body: JSON.stringify({ label: $("#passkey-label").value.trim() }),
  });
  const credential = await navigator.credentials.create({ publicKey: decodeCreationOptions(start.public_key) });
  await api("/api/webauthn/register/verify", {
    method: "POST",
    headers: adminHeaders(),
    body: JSON.stringify({ challenge_id: start.challenge_id, credential: serializeCredential(credential) }),
  });
  $("#admin-token").value = "";
  await loadPasskeyStatus();
  alert("Passkeyを登録しました。続けてFace IDでサインインしてください。");
}

async function loginWithPasskey() {
  const start = await api("/api/webauthn/login/options", { method: "POST", body: "{}" });
  const credential = await navigator.credentials.get({ publicKey: decodeRequestOptions(start.public_key) });
  await api("/api/webauthn/login/verify", {
    method: "POST",
    body: JSON.stringify({ challenge_id: start.challenge_id, credential: serializeCredential(credential) }),
  });
  await loadPasskeyStatus();
  await refreshPrimaryData();
  return true;
}

async function logoutPasskey() {
  await api("/api/webauthn/logout", { method: "POST", body: "{}" });
  state.passkeyAuthenticated = false;
  location.reload();
}

function activateTab(name) {
  document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((panel) => panel.classList.toggle("active", panel.id === name));
  history.replaceState(null, "", `#${name}`);
}

document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => activateTab(tab.dataset.tab)));

function appendMessage(role, text, meta = "") {
  const article = document.createElement("article");
  article.className = `message ${role}`;
  article.innerHTML = `${role === "agent" ? '<span class="avatar">PA</span>' : ""}<div><p>${escapeHtml(text)}</p>${meta ? `<small>${escapeHtml(meta)}</small>` : ""}</div>`;
  $("#messages").append(article);
  article.scrollIntoView({ behavior: "smooth", block: "end" });
  return article;
}

function updateMessage(article, text, meta, status = "") {
  article.classList.toggle("pending", status === "pending");
  article.classList.toggle("failed", status === "failed");
  article.querySelector("p").textContent = text;
  let detail = article.querySelector("small");
  if (!detail) {
    detail = document.createElement("small");
    article.querySelector("div").append(detail);
  }
  detail.className = status === "pending" ? "processing-meta" : "";
  detail.textContent = meta;
  article.scrollIntoView({ behavior: "smooth", block: "end" });
}

function setChatBusy(busy, elapsedSeconds = 0) {
  state.chatBusy = busy;
  const form = $("#chat-form");
  const send = $("#send");
  form.setAttribute("aria-busy", String(busy));
  send.disabled = busy;
  send.textContent = busy ? "処理中…" : "送信";
  const dot = $("#health-dot");
  if (busy) {
    dot.classList.remove("ok", "error");
    dot.classList.add("busy");
    $("#health-text").textContent = `Chat処理中 · ${elapsedSeconds}秒`;
  } else {
    dot.classList.remove("busy");
  }
}

$("#prompt").addEventListener("input", (event) => {
  event.target.style.height = "auto";
  event.target.style.height = `${Math.min(event.target.scrollHeight, 180)}px`;
});

$("#prompt").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    $("#chat-form").requestSubmit();
  }
});

$("#chat-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = $("#prompt");
  const text = input.value.trim();
  if (!text) return;
  appendMessage("user", text, state.continuationTaskId ? `継続: ${state.continuationTaskId.slice(0, 8)}` : "Web");
  input.value = "";
  input.style.height = "auto";
  const startedAt = performance.now();
  const pending = appendMessage("agent", "送信済み。Agentが処理しています…", "処理中 · 0秒");
  updateMessage(pending, "送信済み。Agentが処理しています…", "処理中 · 0秒", "pending");
  setChatBusy(true, 0);
  const progressTimer = window.setInterval(() => {
    const elapsed = Math.floor((performance.now() - startedAt) / 1000);
    const message = elapsed >= 10
      ? "まだ処理中です。ローカルQwenの応答には時間がかかることがあります…"
      : "送信済み。Agentが処理しています…";
    updateMessage(pending, message, `処理中 · ${elapsed}秒`, "pending");
    setChatBusy(true, elapsed);
  }, 1000);
  try {
    const response = await api("/api/messages", {
      method: "POST",
      body: JSON.stringify({
        text,
        source: "web",
        conversation_id: "pwa-primary",
        task_id: state.continuationTaskId,
        dry_run: $("#dry-run").checked,
      }),
    });
    const elapsed = (performance.now() - startedAt) / 1000;
    updateMessage(
      pending,
      response.text,
      `${response.state} · ${response.route} · ${response.task_id.slice(0, 8)} · ${elapsed.toFixed(1)}秒`,
    );
    clearContinuation();
    await loadTasks();
  } catch (error) {
    const elapsed = (performance.now() - startedAt) / 1000;
    updateMessage(
      pending,
      `処理に失敗しました: ${error.message}\n入力内容を戻しました。もう一度「送信」を押せます。`,
      `FAILED · ${elapsed.toFixed(1)}秒`,
      "failed",
    );
    input.value = text;
    input.dispatchEvent(new Event("input"));
  } finally {
    window.clearInterval(progressTimer);
    setChatBusy(false);
    await loadHealth();
    input.focus();
  }
});

function setContinuation(taskId) {
  state.continuationTaskId = taskId;
  $("#continuation-id").textContent = taskId.slice(0, 8);
  $("#continuation").classList.remove("hidden");
  activateTab("chat");
  $("#prompt").focus();
}

function clearContinuation() {
  state.continuationTaskId = null;
  $("#continuation").classList.add("hidden");
}
$("#clear-continuation").addEventListener("click", clearContinuation);

async function loadHealth() {
  try {
    await api("/api/health");
    if (state.chatBusy) return;
    $("#health-dot").classList.remove("busy", "error");
    $("#health-dot").classList.add("ok");
    $("#health-text").textContent = "Local · Online";
  } catch {
    if (state.chatBusy) return;
    $("#health-dot").classList.remove("ok", "busy");
    $("#health-dot").classList.add("error");
    $("#health-text").textContent = "Offline";
  }
}

function actionVisible(action, taskState) {
  const terminal = ["COMPLETED", "FAILED", "CANCELLED"].includes(taskState);
  if (action === "continue") return !["COMPLETED", "CANCELLED"].includes(taskState);
  if (action === "pause") return !terminal && taskState !== "PAUSED";
  if (action === "resume") return ["PAUSED", "FAILED", "WAITING_EXTERNAL"].includes(taskState);
  if (action === "cancel") return taskState !== "COMPLETED" && taskState !== "CANCELLED";
  return true;
}

async function loadTasks() {
  const tasks = await api("/api/tasks");
  state.tasks = tasks;
  $("#task-count").textContent = tasks.filter((task) => !["COMPLETED", "FAILED", "CANCELLED"].includes(task.state)).length;
  const list = $("#task-list");
  list.replaceChildren();
  for (const task of tasks) {
    const node = $("#task-template").content.cloneNode(true);
    node.querySelector(".task-state").textContent = task.state;
    node.querySelector("time").textContent = new Date(task.updated_at).toLocaleString("ja-JP", { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" });
    node.querySelector("h3").textContent = task.goal;
    node.querySelector(".task-meta").textContent = `${task.source} · ${task.route || "pending"} · ${task.risk_level} · ${task.task_id.slice(0, 8)}`;
    node.querySelector(".task-open").addEventListener("click", () => showTask(task.task_id));
    node.querySelectorAll("[data-action]").forEach((button) => {
      const action = button.dataset.action;
      button.hidden = !actionVisible(action, task.state);
      button.addEventListener("click", () => runTaskAction(task.task_id, action));
    });
    list.append(node);
  }
  if (!tasks.length) list.innerHTML = '<p class="muted">Taskはまだありません。</p>';
}

function renderMemory(memory) {
  const article = document.createElement("article");
  article.className = "memory-card";
  article.innerHTML = `<span class="task-state">${escapeHtml(memory.kind)}</span><p>${escapeHtml(memory.statement)}</p><small>confidence ${Number(memory.confidence).toFixed(2)} · ${new Date(memory.updated_at).toLocaleString("ja-JP")}</small><div class="card-actions"><button data-edit type="button">編集</button><button data-delete type="button">忘れる</button></div>`;
  article.querySelector("[data-edit]").addEventListener("click", () => editMemory(memory));
  article.querySelector("[data-delete]").addEventListener("click", () => deleteMemory(memory));
  return article;
}

async function loadMemory() {
  const [memories, events] = await Promise.all([api("/api/memories"), api("/api/events?limit=30")]);
  const memoryList = $("#memory-list");
  memoryList.replaceChildren(...memories.map(renderMemory));
  if (!memories.length) memoryList.innerHTML = '<p class="muted">Long-term Memoryはまだありません。</p>';
  const eventList = $("#event-list");
  eventList.replaceChildren();
  for (const event of events) {
    const article = document.createElement("article");
    article.className = "event-card";
    article.innerHTML = `<span class="event-source">${escapeHtml(event.source)} · ${escapeHtml(event.event_type)}</span><p>${escapeHtml(event.content || "[本文保持なし]")}</p><small>${new Date(event.timestamp).toLocaleString("ja-JP")}${event.redacted ? " · redacted" : ""}</small>`;
    eventList.append(article);
  }
  if (!events.length) eventList.innerHTML = '<p class="muted">Eventはまだありません。</p>';
}

$("#memory-create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/memories", {
      method: "POST",
      body: JSON.stringify({
        statement: $("#memory-statement").value.trim(),
        kind: $("#memory-kind").value,
        confidence: 1,
      }),
    });
    $("#memory-statement").value = "";
    await loadMemory();
  } catch (error) { alert(error.message); }
});

$("#memory-search-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const query = $("#memory-search").value.trim();
    const hits = await api(`/api/search?q=${encodeURIComponent(query)}&limit=30`);
    const results = $("#search-results");
    results.classList.remove("hidden");
    results.innerHTML = hits.length ? hits.map((hit) => `<article class="search-hit"><small>${escapeHtml(hit.record_type)} · ${escapeHtml(hit.source)}</small><p>${escapeHtml(hit.text)}</p></article>`).join("") : '<p class="muted">一致する記録はありません。</p>';
  } catch (error) { alert(error.message); }
});

async function editMemory(memory) {
  const statement = prompt("Memoryを修正", memory.statement);
  if (!statement || statement === memory.statement) return;
  try {
    await api(`/api/memories/${memory.memory_id}`, {
      method: "PATCH",
      body: JSON.stringify({ statement }),
    });
    await loadMemory();
  } catch (error) { alert(error.message); }
}

async function deleteMemory(memory) {
  if (!confirm(`「${memory.statement}」を忘れますか？`)) return;
  try {
    await api(`/api/memories/${memory.memory_id}`, { method: "DELETE" });
    await loadMemory();
  } catch (error) { alert(error.message); }
}

$("#refresh-memory").addEventListener("click", () => loadMemory().catch((error) => alert(error.message)));

async function runTaskAction(taskId, action) {
  if (action === "continue") return setContinuation(taskId);
  try {
    const result = await api(`/api/tasks/${taskId}/${action}`, { method: "POST", body: "{}" });
    if (action === "resume" && result.text) appendMessage("agent", result.text, `${result.state} · resumed`);
    await loadTasks();
  } catch (error) {
    alert(error.message);
  }
}

async function showTask(taskId) {
  const detail = await api(`/api/tasks/${taskId}`);
  const task = detail.task;
  $("#task-detail").innerHTML = `
    <p><span class="task-state">${escapeHtml(task.state)}</span></p>
    <h3>${escapeHtml(task.goal)}</h3>
    <p class="muted"><code>${escapeHtml(task.task_id)}</code><br>${escapeHtml(task.source)} · ${escapeHtml(task.route || "pending")} · ${escapeHtml(task.risk_level)}</p>
    <h3>Timeline</h3>
    <div class="timeline">${detail.events.map((event) => `<article><strong>${escapeHtml(event.event_type)}</strong><p>${escapeHtml(event.state || "")}</p><time>${new Date(event.created_at).toLocaleString("ja-JP")}</time></article>`).join("")}</div>
    <h3>Result & Evidence</h3>
    <pre class="evidence">${escapeHtml(JSON.stringify(task.result || {}, null, 2))}</pre>`;
  $("#task-dialog").showModal();
}

$("#close-dialog").addEventListener("click", () => $("#task-dialog").close());
$("#refresh-tasks").addEventListener("click", () => loadTasks().catch((error) => alert(error.message)));

const lockLabels = {
  global_pause: ["Global Pause", "新しいTask実行を停止"],
  finance_lock: ["Finance Lock", "購入・送金を拒否"],
  browser_lock: ["Browser Lock", "Browser操作を拒否"],
  secret_lock: ["Secret Lock", "Credential利用を拒否"],
};

async function loadLocks() {
  const locks = await api("/api/system/locks");
  const list = $("#lock-list");
  list.replaceChildren();
  for (const [name, metadata] of Object.entries(locks)) {
    const row = document.createElement("article");
    row.className = "lock-row";
    const [label, description] = lockLabels[name];
    row.innerHTML = `<div><strong>${label}</strong><small>${description}</small></div><button class="switch ${metadata.value ? "on" : ""}" aria-label="${label} 切り替え"></button>`;
    row.querySelector("button").addEventListener("click", () => updateLock(name, !metadata.value));
    list.append(row);
  }
}

async function pollNotification() {
  try {
    const notification = await api("/api/notifications/claim", {
      method: "POST",
      body: JSON.stringify({ source: "web", conversation_id: "pwa-primary" }),
    });
    if (!notification) return;
    appendMessage("agent", notification.text, "Scheduler");
    if ("Notification" in window) {
      if (Notification.permission === "default") await Notification.requestPermission();
      if (Notification.permission === "granted") new Notification("Personal Agent", { body: notification.text });
    }
    await api(`/api/notifications/${notification.notification_id}/ack`, { method: "POST", body: "{}" });
  } catch (error) {
    console.debug("Notification poll failed", error);
  }
}

async function updateLock(name, enabled) {
  if (!hasAdminAccess()) return alert("Admin Tokenを入力するか、Face IDでサインインしてください。");
  try {
    await api(`/api/system/locks/${name}`, {
      method: "PUT",
      headers: adminHeaders(),
      body: JSON.stringify({ enabled }),
    });
    await loadLocks();
  } catch (error) {
    alert(error.message);
  }
}

async function loadPending() {
  if (!hasAdminAccess()) return alert("Admin Tokenを入力するか、Face IDでサインインしてください。");
  const headers = adminHeaders();
  const approvalList = $("#approval-list");
  const authList = $("#auth-session-list");
  try {
    const [approvals, sessions] = await Promise.all([
      api("/api/approvals?state=pending", { headers }),
      api("/api/auth/sessions", { headers }).catch(() => []),
    ]);
    approvalList.replaceChildren();
    for (const approval of approvals) {
      const row = document.createElement("article");
      row.className = "pending-row";
      row.innerHTML = `<div><span class="task-state">${escapeHtml(approval.risk_level)}</span><strong>${escapeHtml(approval.tool_name)}</strong><p>${escapeHtml(approval.reason)}</p><small>${escapeHtml(JSON.stringify(approval.input_summary))}</small></div><div class="card-actions"><button data-approve type="button">承認</button><button data-deny class="danger" type="button">拒否</button></div>`;
      if (["R4", "R5"].includes(approval.risk_level)) row.querySelector("[data-approve]").textContent = "Face IDで承認";
      row.querySelector("[data-approve]").addEventListener("click", () => decideApproval(approval, true));
      row.querySelector("[data-deny]").addEventListener("click", () => decideApproval(approval, false));
      approvalList.append(row);
    }
    if (!approvals.length) approvalList.innerHTML = '<p class="muted">承認待ちはありません。</p>';

    const pendingAuth = sessions.filter((session) => session.state === "WAITING_OTP");
    authList.replaceChildren();
    for (const session of pendingAuth) {
      const row = document.createElement("article");
      row.className = "pending-row";
      row.innerHTML = `<div><span class="task-state">OTP</span><strong>${escapeHtml(session.origin)}</strong><p>${escapeHtml(session.account_label || "Account未指定")} · ${escapeHtml(session.factor || "OTP")}</p><small>期限 ${new Date(session.expires_at).toLocaleString("ja-JP")}</small></div><form class="otp-form"><input inputmode="numeric" autocomplete="one-time-code" pattern="[0-9A-Za-z -]{4,20}" maxlength="20" placeholder="認証コード" required><button type="submit">送信</button></form>`;
      row.querySelector("form").addEventListener("submit", (event) => submitOtp(event, session));
      authList.append(row);
    }
    if (!pendingAuth.length) authList.innerHTML = '<p class="muted">OTP待ちはありません。</p>';
  } catch (error) {
    approvalList.innerHTML = `<p class="muted">${escapeHtml(error.message)}</p>`;
    authList.replaceChildren();
  }
}

async function decideApproval(approval, approved) {
  const approvalId = approval.approval_id;
  if (approved && !confirm("表示されたActionを1回だけ実行することを承認しますか？")) return;
  try {
    let result;
    if (approved && ["R4", "R5"].includes(approval.risk_level)) {
      if (!state.passkeyAuthenticated) await loginWithPasskey();
      const options = await api(`/api/approvals/${encodeURIComponent(approvalId)}/webauthn/options`, {
        method: "POST", headers: adminHeaders(), body: "{}",
      });
      const credential = await navigator.credentials.get({ publicKey: decodeRequestOptions(options.public_key) });
      result = await api(`/api/approvals/${encodeURIComponent(approvalId)}/webauthn/verify`, {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({ challenge_id: options.challenge_id, credential: serializeCredential(credential) }),
      });
    } else {
      result = await api(`/api/approvals/${encodeURIComponent(approvalId)}/decision`, {
        method: "POST", headers: adminHeaders(), body: JSON.stringify({ approved }),
      });
    }
    if (result.task_response?.text) appendMessage("agent", result.task_response.text, `${result.task_response.state} · approval`);
    await Promise.all([loadPending(), loadTasks()]);
  } catch (error) { alert(error.message); }
}

async function submitOtp(event, session) {
  event.preventDefault();
  const input = event.currentTarget.querySelector("input");
  const code = input.value;
  input.value = "";
  try {
    const result = await api(`/api/auth/${encodeURIComponent(session.profile)}/otp`, {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify({ auth_session_id: session.auth_session_id, code }),
    });
    if (result.task_response?.text) appendMessage("agent", result.task_response.text, `${result.task_response.state} · auth resumed`);
    await Promise.all([loadPending(), loadTasks()]);
  } catch (error) { alert(error.message); }
}

$("#refresh-pending").addEventListener("click", loadPending);

async function loadSecrets() {
  if (!hasAdminAccess()) return alert("Admin Tokenを入力するか、Face IDでサインインしてください。");
  const headers = adminHeaders();
  const secretList = $("#secret-list");
  const usageList = $("#secret-usage-list");
  try {
    const [secrets, usage] = await Promise.all([
      api("/api/secrets", { headers }),
      api("/api/secrets/usage", { headers }),
    ]);
    secretList.replaceChildren();
    for (const credential of secrets) {
      const row = document.createElement("article");
      row.className = "pending-row";
      row.innerHTML = `<div><span class="task-state">${escapeHtml(credential.kind)}</span><strong>${escapeHtml(credential.credential_id)}</strong><p>${escapeHtml(credential.account_label)} · ${escapeHtml(credential.allowed_origins.join(", "))}</p><small>${credential.enabled ? "enabled" : "disabled"} · ${escapeHtml(credential.allowed_actions.join(", "))}</small></div><div class="card-actions"></div>`;
      if (credential.enabled) {
        const disable = document.createElement("button");
        disable.className = "danger";
        disable.type = "button";
        disable.textContent = "失効";
        disable.addEventListener("click", () => disableSecret(credential.credential_id));
        row.querySelector(".card-actions").append(disable);
      }
      secretList.append(row);
    }
    if (!secrets.length) secretList.innerHTML = '<p class="muted">Credentialは登録されていません。</p>';
    usageList.innerHTML = usage.length ? usage.slice(0, 30).map((item) => `<article class="usage-row"><strong>${escapeHtml(item.credential_id)}</strong><span>${escapeHtml(item.action)} · ${escapeHtml(item.result)}</span><small>${escapeHtml(item.origin)} · ${new Date(item.created_at).toLocaleString("ja-JP")}</small></article>`).join("") : '<p class="muted">利用履歴はありません。</p>';
  } catch (error) {
    secretList.innerHTML = `<p class="muted">${escapeHtml(error.message)}</p>`;
    usageList.replaceChildren();
  }
}

async function disableSecret(credentialId) {
  if (!confirm(`${credentialId} を失効しますか？`)) return;
  try {
    await api(`/api/secrets/${encodeURIComponent(credentialId)}`, {
      method: "DELETE",
      headers: adminHeaders(),
    });
    await loadSecrets();
  } catch (error) { alert(error.message); }
}

async function saveCredentialBundle(event) {
  event.preventDefault();
  if (!state.passkeyAuthenticated) await loginWithPasskey();
  const base = $("#credential-base").value.trim().replace(/\/+$/, "");
  const account = $("#credential-account").value.trim();
  const origin = new URL($("#credential-origin").value).origin;
  const usernameInput = $("#credential-username");
  const passwordInput = $("#credential-password");
  const totpInput = $("#credential-totp");
  const values = {
    username: usernameInput.value,
    password: passwordInput.value,
    totp_seed: totpInput.value.replaceAll(" ", ""),
  };
  usernameInput.value = "";
  passwordInput.value = "";
  totpInput.value = "";
  const specifications = [
    ["username", "username_fill"],
    ["password", "password_fill"],
    ["totp_seed", "totp_fill"],
  ];
  const entries = specifications.filter(([kind]) => values[kind]).map(([kind, action]) => ({
    credential_id: `${base}/${kind}`,
    kind,
    account_label: account,
    allowed_origins: [origin],
    allowed_actions: [action],
    value: values[kind],
  }));
  if (!entries.length) throw new Error("Username、Password、TOTPのいずれかを入力してください。");
  try {
    for (const entry of entries) {
      await api("/api/secrets", { method: "POST", body: JSON.stringify(entry) });
      entry.value = "";
    }
    await loadSecrets();
    alert(`${entries.length}件の認証情報をWindows DPAPIで暗号化保存しました。`);
  } finally {
    for (const key of Object.keys(values)) values[key] = "";
    for (const entry of entries) entry.value = "";
  }
}

$("#credential-form").addEventListener("submit", (event) => {
  saveCredentialBundle(event).catch((error) => alert(error.message));
});
$("#refresh-secrets").addEventListener("click", loadSecrets);

async function loadBrowserProfiles() {
  if (!hasAdminAccess()) return alert("Admin Tokenを入力するか、Face IDでサインインしてください。");
  const list = $("#browser-profile-list");
  try {
    const profiles = await api("/api/browser/profiles", {
      headers: adminHeaders(),
    });
    list.replaceChildren();
    for (const profile of profiles) {
      const row = document.createElement("article");
      row.className = "browser-profile-row";
      row.innerHTML = `<div><strong>${escapeHtml(profile.profile)}</strong><small>${escapeHtml(profile.state)}${profile.url ? ` · ${escapeHtml(profile.url)}` : ""}${profile.takeover_reason ? ` · ${escapeHtml(profile.takeover_reason)}` : ""}</small></div><div class="card-actions"></div>`;
      const actions = row.querySelector(".card-actions");
      if (profile.state === "human" || profile.state === "paused") {
        const release = document.createElement("button");
        release.type = "button";
        release.textContent = "本人操作を終了";
        release.addEventListener("click", () => releaseTakeover(profile.profile));
        actions.append(release);
      }
      if (profile.running) {
        const close = document.createElement("button");
        close.type = "button";
        close.className = "danger";
        close.textContent = "Profile終了";
        close.addEventListener("click", () => closeBrowserProfile(profile.profile));
        actions.append(close);
      }
      list.append(row);
    }
  } catch (error) {
    list.innerHTML = `<p class="muted">${escapeHtml(error.message)}</p>`;
  }
}

async function closeBrowserProfile(profile) {
  if (!confirm(`${profile} profileを終了しますか？`)) return;
  try {
    await api(`/api/browser/profiles/${encodeURIComponent(profile)}`, {
      method: "DELETE",
      headers: adminHeaders(),
    });
    await Promise.all([loadBrowserProfiles(), loadTasks()]);
  } catch (error) { alert(error.message); }
}

async function releaseTakeover(profile) {
  try {
    await api(`/api/browser/takeover/${encodeURIComponent(profile)}/release`, {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify({ outcome: "completed" }),
    });
    await loadBrowserProfiles();
  } catch (error) { alert(error.message); }
}

$("#refresh-browser-profiles").addEventListener("click", loadBrowserProfiles);

let activityStatus = { enabled: false, blocked_domains: [] };

async function loadActivityStatus() {
  activityStatus = await api("/api/activity/status");
  const button = $("#activity-toggle");
  button.textContent = activityStatus.enabled ? "収集を停止" : "収集を開始";
  button.classList.toggle("danger", activityStatus.enabled);
  $("#activity-blocked-domains").value = activityStatus.blocked_domains.join("\n");
}

async function updateActivity(enabled, blockedDomains) {
  if (!hasAdminAccess()) return alert("Admin Tokenを入力するか、Face IDでサインインしてください。");
  try {
    activityStatus = await api("/api/activity/status", {
      method: "PUT",
      headers: adminHeaders(),
      body: JSON.stringify({ enabled, blocked_domains: blockedDomains }),
    });
    await loadActivityStatus();
  } catch (error) { alert(error.message); }
}

$("#activity-toggle").addEventListener("click", () => updateActivity(!activityStatus.enabled, activityStatus.blocked_domains));
$("#save-activity-domains").addEventListener("click", () => {
  const domains = $("#activity-blocked-domains").value.split("\n").map((value) => value.trim()).filter(Boolean);
  updateActivity(activityStatus.enabled, domains);
});

function metric(label, value) {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

let proactiveSettings = null;

async function loadProactive() {
  const [settings, opportunities] = await Promise.all([
    api("/api/proactive/settings"),
    api("/api/opportunities?state=open&limit=30"),
  ]);
  proactiveSettings = settings;
  const button = $("#proactive-toggle");
  button.textContent = settings.enabled ? "先回りを停止" : "先回りを開始";
  button.classList.toggle("danger", settings.enabled);
  const list = $("#opportunity-list");
  list.replaceChildren();
  for (const item of opportunities) {
    const row = document.createElement("article");
    row.className = "pending-row";
    row.innerHTML = `<div><span class="task-state">${escapeHtml(item.attention)}</span><strong>${escapeHtml(item.category)}</strong><p>${escapeHtml(item.summary)}</p><small>confidence ${Number(item.confidence).toFixed(2)} · Evidence ${escapeHtml(item.evidence_event_ids.join(", "))}</small></div><button type="button">解決済み</button>`;
    row.querySelector("button").addEventListener("click", () => resolveOpportunity(item.opportunity_id));
    list.append(row);
  }
  if (!opportunities.length) list.innerHTML = '<p class="muted">未解決Opportunityはありません。</p>';
}

async function updateProactiveEnabled() {
  if (!proactiveSettings) await loadProactive();
  if (!hasAdminAccess()) return alert("Admin Tokenを入力するか、Face IDでサインインしてください。");
  await api("/api/proactive/settings", {
    method: "PUT",
    headers: adminHeaders(),
    body: JSON.stringify({ ...proactiveSettings, enabled: !proactiveSettings.enabled }),
  });
  await loadProactive();
}

async function resolveOpportunity(opportunityId) {
  await api(`/api/opportunities/${encodeURIComponent(opportunityId)}/resolve`, {
    method: "POST", headers: adminHeaders(), body: "{}",
  });
  await loadProactive();
}

$("#proactive-toggle").addEventListener("click", () => updateProactiveEnabled().catch((error) => alert(error.message)));

async function loadOps() {
  if (!hasAdminAccess()) return alert("Admin Tokenを入力するか、Face IDでサインインしてください。");
  const headers = adminHeaders();
  const [health, metrics, connectors, budgets, payees, runs, lineDesktop] = await Promise.all([
    api("/api/system/health", { headers }),
    api("/api/metrics", { headers }),
    api("/api/connectors", { headers }),
    api("/api/economic/budgets", { headers }),
    api("/api/money/payees", { headers }),
    api("/api/benchmark/runs?limit=1", { headers }),
    api("/api/channels/line-desktop/status", { headers }),
  ]);
  $("#system-health").innerHTML = [
    metric("Status", health.status),
    metric("DB", `${(health.database.bytes / 1048576).toFixed(1)} / ${(health.database.quota_bytes / 1048576).toFixed(0)} MiB`),
    metric("RAM", health.process.resident_memory_bytes ? `${(health.process.resident_memory_bytes / 1048576).toFixed(1)} MiB` : "unavailable"),
    metric("GPU", health.gpu.length ? `${health.gpu[0].utilization_percent}% · ${health.gpu[0].memory_used_mib} MiB` : "unavailable"),
    metric("Warnings", health.warnings.join(", ") || "none"),
  ].join("");
  const lineSession = {
    logged_in: "ログイン済み",
    login_required: "LINEでログインが必要",
    unknown: "判定中",
  }[lineDesktop.session_state] || "待機中";
  $("#line-desktop-health").innerHTML = [
    metric("Bridge", lineDesktop.bridge?.status || "offline"),
    metric("LINE", lineSession),
    metric("Visible chats", lineDesktop.visible_chat_count ?? 0),
    metric("Stored", lineDesktop.stored ?? 0),
    metric("Last sync", lineDesktop.last_sync_at ? new Date(lineDesktop.last_sync_at).toLocaleString("ja-JP") : "not yet"),
    metric("Capture", lineDesktop.screenshots_persisted ? "warning: persisted" : "memory only"),
    metric("Send", lineDesktop.send_enabled ? "approval required" : "disabled"),
  ].join("");
  $("#model-metrics").innerHTML = [
    metric("Model turns", metrics.model.turns),
    metric("Tokens/s", metrics.model.tokens_per_second ?? "not measured"),
    metric("Tool calls", metrics.tools.total),
    metric("Tool p95", metrics.tools.duration_ms.p95 == null ? "not measured" : `${metrics.tools.duration_ms.p95} ms`),
    metric("Policy denials", metrics.safety.policy_denials),
  ].join("");
  renderConnectors(connectors);
  $("#budget-list").innerHTML = budgets.length ? budgets.map((item) => metric(`${item.category} / ${item.currency}`, `${item.per_action_limit} · day ${item.daily_limit} · month ${item.monthly_limit}`)).join("") : '<p class="muted">Budgetは未設定です。</p>';
  $("#payee-list").innerHTML = payees.length ? payees.map((item) => `<article class="usage-row"><strong>${escapeHtml(item.display_name)}</strong><span>${escapeHtml(item.payee_id)}</span><small>${item.trusted ? "trusted" : "untrusted"} · Entity ${escapeHtml(item.entity_id)}</small></article>`).join("") : '<p class="muted">Payeeは未登録です。</p>';
  $("#benchmark-result").innerHTML = runs.length ? [metric("Latest score", runs[0].overall_score), metric("Policy violations", runs[0].policy_violations), metric("Run", runs[0].run_id)].join("") : '<p class="muted">Benchmarkはまだ実行されていません。</p>';
  await Promise.all([loadAudit(), loadProactive()]);
}

function renderConnectors(connectors) {
  const list = $("#connector-list");
  list.replaceChildren();
  for (const connector of connectors) {
    const row = document.createElement("article");
    row.className = "usage-row";
    row.innerHTML = `<strong>${escapeHtml(connector.provider)}</strong><span>${connector.enabled ? "enabled" : "disabled"}</span><small>${escapeHtml(connector.scopes.join(", ") || "no scopes")} · ${escapeHtml(connector.status)}</small>`;
    if (connector.enabled) {
      const button = document.createElement("button");
      button.textContent = "失効";
      button.className = "danger";
      button.addEventListener("click", () => revokeConnector(connector.provider));
      row.append(button);
    }
    list.append(row);
  }
  if (!connectors.length) list.innerHTML = '<p class="muted">Connectorは未設定です。</p>';
}

async function revokeConnector(provider) {
  if (!confirm(`${provider} connectorを失効しますか？`)) return;
  await api(`/api/connectors/${encodeURIComponent(provider)}`, {
    method: "PUT", headers: adminHeaders(), body: JSON.stringify({ enabled: false, scopes: [] }),
  });
  await loadOps();
}

async function loadAudit() {
  const query = $("#audit-search").value.trim();
  const events = await api(`/api/audit?limit=100${query ? `&q=${encodeURIComponent(query)}` : ""}`, { headers: adminHeaders() });
  $("#audit-list").innerHTML = events.length ? events.map((item) => `<article class="usage-row"><strong>${escapeHtml(item.action)}</strong><span>${escapeHtml(item.result)}</span><small>${escapeHtml(item.actor)} · ${new Date(item.created_at).toLocaleString("ja-JP")} · ${escapeHtml(JSON.stringify(item.details))}</small></article>`).join("") : '<p class="muted">一致するAudit Eventはありません。</p>';
}

$("#audit-search-form").addEventListener("submit", (event) => {
  event.preventDefault();
  loadAudit().catch((error) => alert(error.message));
});
$("#refresh-ops").addEventListener("click", () => loadOps().catch((error) => alert(error.message)));

async function runBenchmark(caseIds) {
  if (!hasAdminAccess()) return alert("Admin Tokenを入力するか、Face IDでサインインしてください。");
  const full = !caseIds.length;
  if (full && !confirm("設定済みAdapterへのread-only接続を含む全17 Caseを1回実行しますか？")) return;
  $("#benchmark-result").innerHTML = '<p class="muted">実行中…</p>';
  const report = await api("/api/benchmark/run", {
    method: "POST", headers: adminHeaders(), body: JSON.stringify({ case_ids: caseIds, trials: 1 }),
  });
  $("#benchmark-result").innerHTML = [metric("Overall", report.overall_score), metric("Pass@1", report.pass_at_1), metric("Skipped", report.skipped_cases), metric("Policy violations", report.policy_violations)].join("");
}
$("#run-smoke-benchmark").addEventListener("click", () => runBenchmark(["voice.time"]).catch((error) => alert(error.message)));
$("#run-full-benchmark").addEventListener("click", () => runBenchmark([]).catch((error) => alert(error.message)));

$("#export-data").addEventListener("click", async () => {
  try {
    const response = await fetch("/api/data/export", { headers: adminHeaders() });
    if (!response.ok) throw new Error((await response.json()).detail || `HTTP ${response.status}`);
    const link = document.createElement("a");
    link.href = URL.createObjectURL(await response.blob());
    link.download = "personal-agent-export.json";
    link.click();
    URL.revokeObjectURL(link.href);
  } catch (error) { alert(error.message); }
});

$("#delete-data").addEventListener("click", async () => {
  const scope = $("#delete-scope").value;
  const confirmation = $("#delete-confirmation").value;
  if (confirmation !== `DELETE:${scope}`) return alert(`DELETE:${scope} と正確に入力してください。`);
  if (!confirm(`${scope} のデータを削除します。回復できない可能性があります。続行しますか？`)) return;
  try {
    await api("/api/data/delete", {
      method: "POST", headers: adminHeaders(), body: JSON.stringify({ scope, confirmation }),
    });
    $("#delete-confirmation").value = "";
    await Promise.all([loadTasks(), loadMemory(), loadOps()]);
  } catch (error) { alert(error.message); }
});

$("#passkey-register-form").addEventListener("submit", (event) =>
  registerPasskey(event).catch((error) => alert(error.message)));
$("#passkey-login").addEventListener("click", () =>
  loginWithPasskey().catch((error) => alert(error.message)));
$("#passkey-logout").addEventListener("click", () =>
  logoutPasskey().catch((error) => alert(error.message)));
$("#admin-token").addEventListener("change", () =>
  loadPasskeyStatus().catch((error) => console.debug("Passkey status failed", error)));

const initialTab = location.hash.slice(1);
if (["chat", "tasks", "memory", "controls", "ops"].includes(initialTab)) activateTab(initialTab);
async function refreshPrimaryData() {
  await Promise.allSettled([
    loadTasks(), loadMemory(), loadLocks(), loadActivityStatus(), loadProactive(),
  ]);
}

async function initialize() {
  await loadHealth();
  const passkey = await loadPasskeyStatus();
  if (passkey.authenticated) await refreshPrimaryData();
}

initialize().catch((error) => {
  console.error("PWA initialization failed", error);
  $("#health-text").textContent = "Authentication required";
});
setInterval(loadHealth, 30000);
setInterval(pollNotification, 2000);
if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js");
