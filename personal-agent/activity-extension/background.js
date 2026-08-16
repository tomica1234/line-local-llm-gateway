const QUEUE_KEY = "encryptedActivityQueue";
const CRYPTO_KEY = "activityQueueCryptoKey";
const MAX_QUEUE_SIZE = 10000;
let queueOperation = Promise.resolve();

function serialized(operation) {
  const result = queueOperation.then(operation);
  queueOperation = result.catch(() => {});
  return result;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function queueCryptoKey() {
  const stored = await browser.storage.local.get(CRYPTO_KEY);
  if (stored[CRYPTO_KEY]) {
    return crypto.subtle.importKey("jwk", stored[CRYPTO_KEY], "AES-GCM", false, ["encrypt", "decrypt"]);
  }
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const exported = await crypto.subtle.exportKey("jwk", key);
  await browser.storage.local.set({ [CRYPTO_KEY]: exported });
  return key;
}

async function encryptEvent(event) {
  const key = await queueCryptoKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(event));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  return { iv: bytesToBase64(iv), data: bytesToBase64(new Uint8Array(ciphertext)) };
}

async function decryptEvent(record) {
  const key = await queueCryptoKey();
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(record.iv) },
    key,
    base64ToBytes(record.data),
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

async function enqueue(event) {
  const settings = await browser.storage.local.get([QUEUE_KEY, "paused", "deviceId"]);
  if (settings.paused) return;
  const queue = settings[QUEUE_KEY] || [];
  const deviceId = settings.deviceId || crypto.randomUUID();
  if (!settings.deviceId) await browser.storage.local.set({ deviceId });
  queue.push(await encryptEvent({ ...event, device_id: deviceId }));
  if (queue.length > MAX_QUEUE_SIZE) queue.splice(0, queue.length - MAX_QUEUE_SIZE);
  await browser.storage.local.set({ [QUEUE_KEY]: queue });
}

async function flush() {
  const settings = await browser.storage.local.get([QUEUE_KEY, "paused", "coreUrl", "activityToken"]);
  const queue = settings[QUEUE_KEY] || [];
  if (settings.paused || !queue.length || !settings.coreUrl || !settings.activityToken) return;
  const records = queue.slice(0, 500);
  let events;
  try {
    events = await Promise.all(records.map(decryptEvent));
  } catch {
    return;
  }
  try {
    const response = await fetch(`${settings.coreUrl.replace(/\/$/, "")}/api/activity/batch`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Activity-Token": settings.activityToken,
      },
      body: JSON.stringify({ events }),
    });
    if (!response.ok) return;
    await browser.storage.local.set({ [QUEUE_KEY]: queue.slice(records.length) });
  } catch {
    // The encrypted queue remains on-device and is retried by the next alarm.
  }
}

browser.runtime.onMessage.addListener((message) => {
  if (message?.type === "activity_event") return serialized(() => enqueue(message.event));
  if (message?.type === "flush_now") return serialized(flush);
  return undefined;
});

browser.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "flush-activity") serialized(flush);
});
browser.alarms.create("flush-activity", { delayInMinutes: 0.25, periodInMinutes: 0.5 });
serialized(flush);
