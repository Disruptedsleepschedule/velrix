const { createHash, timingSafeEqual } = require("node:crypto");
const { performance } = require("node:perf_hooks");

const LIMITS = Object.freeze({
  chatMessageLength: 4000,
  chatRequestsPerMinute: 20,
  verifyRequestsPerMinute: 10,
  chatConcurrent: 2,
  verifyConcurrent: 2,
  registryResponseBytes: 1024 * 1024,
  capabilityResponseBytes: 64 * 1024,
  modelResponseBytes: 1024 * 1024,
  verifyEndpoints: 5,
  verifyTimeoutMs: 60000
});

function createApiGuard(limit, getKey = () => process.env.VELRIX_API_KEY, now = () => performance.now()) {
  // One shared credential has one shared budget, even across client IPs.
  let timestamps = [];
  return (req, res, next) => {
    const expected = getKey();
    const supplied = req.get("x-api-key");
    const digest = value => createHash("sha256").update(value).digest();
    if (typeof expected !== "string" || !expected.trim() ||
        typeof supplied !== "string" ||
        !timingSafeEqual(digest(expected), digest(supplied))) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    const time = now();
    timestamps = timestamps.filter(timestamp => time - timestamp < 60000);
    if (timestamps.length >= limit) {
      res.set("Retry-After", String(Math.max(1, Math.ceil((timestamps[0] + 60000 - time) / 1000))));
      return res.status(429).json({ error: "Rate limit exceeded" });
    }
    timestamps.push(time);
    next();
  };
}

function createChatGuard(getKey, now) {
  return createApiGuard(LIMITS.chatRequestsPerMinute, getKey, now);
}

function createVerifyGuard(getKey, now) {
  return createApiGuard(LIMITS.verifyRequestsPerMinute, getKey, now);
}

function limitConcurrency(limit, handler) {
  let active = 0;
  return async (req, res, next) => {
    if (active >= limit) {
      res.set("Retry-After", "1");
      return res.status(503).json({ error: "Concurrent operation limit exceeded" });
    }
    active++;
    try {
      return await handler(req, res, next);
    } finally {
      active--;
    }
  };
}

function discardBody(response) {
  // Do not wait for a remote peer to acknowledge cancellation.
  if (response.body) void response.body.cancel().catch(() => {});
}

async function readLimitedBody(response, maxBytes, signal) {
  const tooLarge = () => Object.assign(new Error("External response exceeds size limit"), { code: "RESPONSE_TOO_LARGE" });
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null && Number(declaredLength) > maxBytes) {
    discardBody(response);
    throw tooLarge();
  }
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  let complete = false;
  try {
    while (true) {
      const { done, value } = await withinDeadline(signal, () => reader.read());
      if (done) { complete = true; break; }
      total += value.byteLength;
      if (total > maxBytes) throw tooLarge();
      chunks.push(Buffer.from(value));
    }
    signal.throwIfAborted();
    return Buffer.concat(chunks, total);
  } finally {
    if (!complete) void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

async function readLimitedJson(response, maxBytes, signal) {
  const bytes = await readLimitedBody(response, maxBytes, signal);
  return JSON.parse(bytes.toString("utf8"));
}

// The SDK uses this transport too, so model responses cannot bypass the cap.
async function boundedModelFetch(url, init = {}) {
  const signal = init.signal || AbortSignal.timeout(30000);
  const response = await fetch(url, { ...init, signal });
  const bytes = await readLimitedBody(response, LIMITS.modelResponseBytes, signal);
  const headers = new Headers(response.headers);
  headers.delete("content-encoding");
  headers.delete("content-length");
  return new Response([204, 205, 304].includes(response.status) ? null : bytes, {
    status: response.status, statusText: response.statusText, headers
  });
}

// Also bounds DNS and retry waits, which do not natively accept AbortSignal.
function withinDeadline(signal, operation) {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    Promise.resolve().then(() => {
      signal.throwIfAborted();
      return operation();
    }).then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
  });
}

module.exports = { LIMITS, createChatGuard, createVerifyGuard, limitConcurrency,
  withinDeadline, readLimitedBody, readLimitedJson, discardBody, boundedModelFetch };
