const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const security = require("../security");
const { LIMITS, createChatGuard, createVerifyGuard, withinDeadline,
  readLimitedJson, boundedModelFetch } = security;

function response() {
  return {
    statusCode: 200, headers: {},
    status(code) { this.statusCode = code; return this; },
    set(name, value) { this.headers[name] = value; return this; },
    json(body) { this.body = body; return this; }
  };
}

// Load the real routes with all external effects replaced. No dotenv, SDK,
// network client, DNS service, or listening socket is invoked.
function harness(options = {}) {
  const routes = {};
  const calls = { ai: 0, fetch: [], dns: 0, signals: [], lookup: null };
  const app = {
    use() {}, get(route, ...handlers) { routes[route] = handlers; },
    post(route, ...handlers) { routes[route] = handlers; }, listen() {}
  };
  const express = () => app;
  express.json = () => () => {};
  const mocks = {
    dotenv: { config() {} }, express,
    openai: class {
      constructor(config) {
        assert.equal(config.fetch, boundedModelFetch);
        this.responses = { create: async () => {
          calls.ai++;
          if (options.ai) return options.ai();
          return { output_text: "offline reply" };
        } };
      }
    },
    net: require("node:net"),
    dns: { promises: { lookup: async () => {
      calls.dns++;
      if (options.dns) return options.dns();
      return [{ address: "8.8.8.8", family: 4 }];
    } } },
    undici: { Agent: class { constructor(config) { calls.lookup = config.connect.lookup; } } },
    "ipaddr.js": require("ipaddr.js"),
    "./security": {
      ...security,
      LIMITS,
      createChatGuard: () => createChatGuard(() => Object.hasOwn(options, "key") ? options.key : "test-key", options.now),
      createVerifyGuard: () => createVerifyGuard(() => Object.hasOwn(options, "key") ? options.key : "test-key", options.now),
      withinDeadline
    },
    "node:timers/promises": options.retryTimers || require("node:timers/promises")
  };
  const context = {
    require(name) {
      assert.ok(Object.hasOwn(mocks, name), `Unexpected dependency: ${name}`);
      return mocks[name];
    },
    process: { env: {} }, URL, AbortController, AbortSignal,
    console: { log() {}, error() {} },
    setTimeout(fn, ms) {
      return setTimeout(fn, ms === LIMITS.verifyTimeoutMs ? (options.deadlineMs || 1000) : ms);
    }, clearTimeout,
    fetch: async (url, init) => {
      calls.fetch.push({ url, method: init.method || "GET", headers: init.headers, redirect: init.redirect });
      calls.signals.push(init.signal);
      let result;
      if (options.fetch) result = await options.fetch(url, init, calls.fetch.length);
      else if (url.startsWith("https://api.8004scan.io/")) {
        result = { ok: true, json: async () => ({
          token_id: "96147",
          raw_metadata: { offchain_content: { services: options.services || [] } }
        }) };
      } else result = { ok: true, status: 200, json: async () => ({ response: "VELRIX_CAPABILITY_OK" }) };
      if ("body" in result) return result;
      // Adapt legacy JSON fixtures to the streaming response contract.
      let consumed = false;
      return { ...result, headers: new Headers(), body: {
        cancel: async () => {},
        getReader: () => ({
          async read() {
            if (consumed) return { done: true };
            consumed = true;
            return { done: false, value: Buffer.from(JSON.stringify(await result.json())) };
          }, cancel: async () => {}, releaseLock() {}
        })
      } };
    }
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../index.js"), "utf8"), context);
  return {
    calls,
    async request(route, body, key = route === "/verify" ? "test-key" : undefined) {
      const req = { body, get: name => name === "x-api-key" ? key : undefined };
      const res = response();
      const handlers = routes[route];
      async function run(i) {
        if (i < handlers.length) {
          let continuation;
          await handlers[i](req, res, () => { continuation = run(i + 1); });
          await continuation;
        }
      }
      await run(0);
      return res;
    }
  };
}

test("chat denies missing configuration and missing/wrong credentials without AI calls", async () => {
  for (const [configured, supplied] of [[undefined, "test-key"], ["", "test-key"], ["   ", "test-key"], ["test-key", undefined], ["test-key", "wrong"]]) {
    const h = harness({ key: configured });
    assert.equal((await h.request("/chat", { message: "hello" }, supplied)).statusCode, 401);
    assert.equal(h.calls.ai, 0);
  }
});

test("chat preserves successful response and accepts exact message limit", async () => {
  const h = harness({ key: "test-key" });
  const res = await h.request("/chat", { message: "x".repeat(LIMITS.chatMessageLength) }, "test-key");
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.agent, "Velrix");
  assert.equal(res.body.response, "offline reply");
  assert.equal(h.calls.ai, 1);
});

test("chat rejects oversized, empty, non-string and absent messages before AI", async () => {
  const h = harness({ key: "test-key" });
  for (const message of [undefined, null, "", "   ", 1, {}, []]) {
    assert.equal((await h.request("/chat", { message }, "test-key")).statusCode, 400);
  }
  assert.equal((await h.request("/chat", undefined, "test-key")).statusCode, 400);
  assert.equal((await h.request("/chat", { message: "x".repeat(LIMITS.chatMessageLength + 1) }, "test-key")).statusCode, 413);
  assert.equal(h.calls.ai, 0);
});

test("chat rate limit blocks request 21 with Retry-After", async () => {
  const h = harness({ key: "test-key" });
  for (let i = 0; i < LIMITS.chatRequestsPerMinute; i++) {
    assert.equal((await h.request("/chat", { message: "hello" }, "test-key")).statusCode, 200);
  }
  const res = await h.request("/chat", { message: "hello" }, "test-key");
  assert.equal(res.statusCode, 429);
  assert.ok(Number(res.headers["Retry-After"]) > 0);
  assert.equal(h.calls.ai, LIMITS.chatRequestsPerMinute);
});

test("rate budget resets after a minute; unauthorized requests do not consume it", () => {
  let time = 0;
  const guard = createChatGuard(() => "test-key", () => time);
  const send = key => {
    const res = response();
    guard({ get: () => key }, res, () => { res.accepted = true; });
    return res;
  };
  for (let i = 0; i < 30; i++) assert.equal(send("wrong").statusCode, 401);
  for (let i = 0; i < 20; i++) assert.equal(send("test-key").accepted, true);
  assert.equal(send("test-key").statusCode, 429);
  time = 60000;
  assert.equal(send("test-key").accepted, true);
});

const target = { network: "base", agentId: "96147" };
const service = { endpoint: "https://agent.example/chat" };
const pending = () => new Promise(() => {});
const registry = services => new Response(JSON.stringify({
  token_id: "96147", raw_metadata: { offchain_content: { services } }
}));

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

async function waitFor(predicate) {
  for (let i = 0; i < 100; i++) {
    if (predicate()) return;
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.fail("Expected operation did not start");
}

test("verify rejects excess endpoints before DNS or endpoint requests", async () => {
  const h = harness({ services: Array(LIMITS.verifyEndpoints + 1).fill(service) });
  assert.equal((await h.request("/verify", target)).statusCode, 422);
  assert.equal(h.calls.fetch.length, 1);
  assert.equal(h.calls.dns, 0);
});

test("verify accepts the endpoint limit and preserves report and capability results", async () => {
  const h = harness({ services: Array(LIMITS.verifyEndpoints).fill(service) });
  const res = await h.request("/verify", target);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.verification.declaredEndpoints.length, LIMITS.verifyEndpoints);
  assert.equal(res.body.report.capability.passedCount, LIMITS.verifyEndpoints);
  assert.equal(h.calls.fetch.length, 1 + 2 * LIMITS.verifyEndpoints);
});

test("verify preserves empty-service reports and validates malformed services", async () => {
  assert.equal((await harness().request("/verify", target)).statusCode, 200);
  assert.equal((await harness({ services: {} }).request("/verify", target)).statusCode, 502);
  assert.equal((await harness().request("/verify", { ...target, network: "other" })).statusCode, 400);
});

test("verify deadline bounds upstream fetch and aborts its signal", async () => {
  const h = harness({ deadlineMs: 15, fetch: pending });
  assert.equal((await h.request("/verify", target)).statusCode, 504);
  assert.equal(h.calls.signals[0].aborted, true);
  assert.equal(h.calls.fetch.length, 1);
});

test("verify deadline bounds upstream JSON body reading", async () => {
  const h = harness({ deadlineMs: 15, fetch: async () => ({ ok: true, json: pending }) });
  assert.equal((await h.request("/verify", target)).statusCode, 504);
  assert.equal(h.calls.dns, 0);
});

test("verify deadline bounds DNS and prevents later endpoint requests", async () => {
  const h = harness({ deadlineMs: 15, services: [service], dns: pending });
  assert.equal((await h.request("/verify", target)).statusCode, 504);
  assert.equal(h.calls.fetch.length, 1);
});

test("verify deadline bounds endpoint health, capability fetch and capability JSON", async () => {
  for (const stage of ["health", "capability", "body"]) {
    const h = harness({ deadlineMs: 15, fetch: async (url, init, count) => {
      if (count === 1) return { ok: true, json: async () => ({ raw_metadata: { offchain_content: { services: [service] } } }) };
      if (stage === "health" || (stage === "capability" && init.method === "POST")) return pending();
      return { ok: true, status: 200, json: pending };
    } });
    assert.equal((await h.request("/verify", target)).statusCode, 504, stage);
    assert.equal(h.calls.signals.at(-1).aborted, true);
    assert.equal(h.calls.fetch.length, stage === "health" ? 2 : 3);
  }
});

test("verify deadline cancels retry wait without starting another request", async () => {
  let retrySignal;
  const h = harness({ deadlineMs: 15,
    retryTimers: { setTimeout: async (ms, value, { signal }) => { retrySignal = signal; return pending(); } },
    fetch: async (url, init, count) => {
      if (count === 1) return { ok: true, json: async () => ({ raw_metadata: { offchain_content: { services: [service] } } }) };
      return { ok: false, status: 503, json: async () => ({}) };
    }
  });
  assert.equal((await h.request("/verify", target)).statusCode, 504);
  assert.equal(retrySignal.aborted, true);
  assert.equal(h.calls.fetch.length, 3);
});

test("expired deadline never starts an operation", async () => {
  const controller = new AbortController();
  controller.abort();
  let started = false;
  assert.throws(() => withinDeadline(controller.signal, () => { started = true; }));
  assert.equal(started, false);
});

test("verify preserves retry success within the total budget", async () => {
  const h = harness({
    retryTimers: { setTimeout: async () => {} },
    fetch: async (url, init, count) => {
      if (count === 1) return { ok: true, json: async () => ({ raw_metadata: { offchain_content: { services: [service] } } }) };
      if (count === 3) return { ok: false, status: 503, json: async () => ({}) };
      return { ok: true, status: 200, json: async () => ({ response: "VELRIX_CAPABILITY_OK" }) };
    }
  });
  const res = await h.request("/verify", target);
  assert.equal(res.statusCode, 200);
  const capability = res.body.verification.capabilityTests[0];
  assert.equal(capability.passed, true);
  assert.equal(capability.attempts, 2);
  assert.equal(capability.retried, true);
  assert.equal(h.calls.fetch.length, 4);
});

test("verify still blocks direct private-IP endpoints without contacting them", async () => {
  const h = harness({ services: [{ endpoint: "http://127.0.0.1/chat" }] });
  const res = await h.request("/verify", target);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.verification.endpointSafety[0].safe, false);
  assert.equal(res.body.report.capability.passedCount, 0);
  assert.equal(h.calls.fetch.length, 1);
  assert.equal(h.calls.dns, 0);
});

test("verify rejects missing, empty and incorrect credentials before any external work", async () => {
  for (const [configured, supplied] of [[undefined, "test-key"], ["", "test-key"], ["   ", "test-key"], ["test-key", null], ["test-key", "wrong"]]) {
    const h = harness({ key: configured });
    assert.equal((await h.request("/verify", target, supplied)).statusCode, 401);
    assert.equal(h.calls.fetch.length, 0);
    assert.equal(h.calls.dns, 0);
  }
});

test("verify enforces its own sliding rate quota with Retry-After", async () => {
  const h = harness();
  for (let i = 0; i < LIMITS.verifyRequestsPerMinute; i++) {
    assert.equal((await h.request("/verify", target)).statusCode, 200);
  }
  const rejected = await h.request("/verify", target);
  assert.equal(rejected.statusCode, 429);
  assert.ok(Number(rejected.headers["Retry-After"]) > 0);
  assert.equal(h.calls.fetch.length, LIMITS.verifyRequestsPerMinute);
  assert.equal((await h.request("/chat", { message: "hello" }, "test-key")).statusCode, 200);
});

test("sliding windows prevent the previous 40-request boundary burst", () => {
  for (const [factory, limit] of [[createChatGuard, LIMITS.chatRequestsPerMinute], [createVerifyGuard, LIMITS.verifyRequestsPerMinute]]) {
    let time = 0;
    const guard = factory(() => "test-key", () => time);
    const send = () => {
      const res = response();
      guard({ get: () => "test-key" }, res, () => { res.accepted = true; });
      return res;
    };
    time = 59999;
    for (let i = 0; i < limit; i++) assert.equal(send().accepted, true);
    time = 60000;
    assert.equal(send().statusCode, 429);
    time = 119998;
    assert.equal(send().statusCode, 429);
    time = 119999;
    assert.equal(send().accepted, true);
  }
});

test("chat bounds in-flight model calls and releases slots on success and failure", async () => {
  const jobs = [deferred(), deferred()];
  let started = 0;
  const h = harness({ ai: () => {
    if (started < jobs.length) return jobs[started++].promise;
    return { output_text: "next" };
  } });
  const active = Array.from({ length: LIMITS.chatConcurrent }, () => h.request("/chat", { message: "hello" }, "test-key"));
  await waitFor(() => h.calls.ai === LIMITS.chatConcurrent);
  const rejected = await h.request("/chat", { message: "hello" }, "test-key");
  assert.equal(rejected.statusCode, 503);
  assert.equal(rejected.headers["Retry-After"], "1");
  assert.equal(h.calls.ai, LIMITS.chatConcurrent);
  jobs[0].resolve({ output_text: "ok" });
  jobs[1].reject(new Error("offline simulated failure"));
  const results = await Promise.all(active);
  assert.equal(results[0].statusCode, 200);
  assert.equal(results[1].statusCode, 500);
  assert.equal((await h.request("/chat", { message: "hello" }, "test-key")).statusCode, 200);
});

test("verify bounds in-flight operations and releases slots on upstream failure", async () => {
  const jobs = [deferred(), deferred()];
  let started = 0;
  const h = harness({ fetch: () => started < jobs.length ? jobs[started++].promise : registry([]) });
  const active = Array.from({ length: LIMITS.verifyConcurrent }, () => h.request("/verify", target));
  await waitFor(() => h.calls.fetch.length === LIMITS.verifyConcurrent);
  const rejected = await h.request("/verify", target);
  assert.equal(rejected.statusCode, 503);
  assert.equal(h.calls.fetch.length, LIMITS.verifyConcurrent);
  jobs[0].resolve(registry([]));
  jobs[1].reject(new Error("offline upstream failure"));
  const results = await Promise.all(active);
  assert.equal(results[0].statusCode, 200);
  assert.equal(results[1].statusCode, 500);
  assert.equal((await h.request("/verify", target)).statusCode, 200);
});

test("verify releases concurrency slots after total timeout", async () => {
  let hang = true;
  const h = harness({ deadlineMs: 15, fetch: () => hang ? pending() : registry([]) });
  const jobs = Array.from({ length: LIMITS.verifyConcurrent }, () => h.request("/verify", target));
  await waitFor(() => h.calls.fetch.length === LIMITS.verifyConcurrent);
  assert.equal((await h.request("/verify", target)).statusCode, 503);
  assert.ok((await Promise.all(jobs)).every(res => res.statusCode === 504));
  hang = false;
  assert.equal((await h.request("/verify", target)).statusCode, 200);
});

test("limited JSON accepts the exact byte limit and counts UTF-8 bytes", async () => {
  const signal = new AbortController().signal;
  const json = JSON.stringify({ text: "ü🙂" });
  const bytes = Buffer.byteLength(json);
  assert.deepEqual(await readLimitedJson(new Response(json), bytes, signal), { text: "ü🙂" });
  await assert.rejects(readLimitedJson(new Response(json), bytes - 1, signal), { code: "RESPONSE_TOO_LARGE" });
});

test("limited JSON rejects declared oversize without reading and cancels the body", async () => {
  let cancelled = false, read = false;
  const res = {
    headers: new Headers({ "content-length": "1025" }),
    body: { cancel: async () => { cancelled = true; }, getReader() { read = true; throw new Error("must not read"); } }
  };
  await assert.rejects(readLimitedJson(res, 1024, new AbortController().signal), { code: "RESPONSE_TOO_LARGE" });
  assert.equal(cancelled, true);
  assert.equal(read, false);
});

test("limited JSON bounds chunked/decompressed bytes despite absent or lying length", async () => {
  for (const headers of [{}, { "content-length": "1", "content-encoding": "gzip" }]) {
    let cancelled = false;
    let reads = 0;
    const body = new ReadableStream({
      pull(controller) { reads++; controller.enqueue(Buffer.alloc(600)); },
      cancel() { cancelled = true; }
    });
    await assert.rejects(readLimitedJson(new Response(body, { headers }), 1024, new AbortController().signal), { code: "RESPONSE_TOO_LARGE" });
    assert.equal(cancelled, true);
    assert.ok(reads <= 3);
  }
});

test("registry oversized response returns 502 without endpoint work", async () => {
  const h = harness({ fetch: async () => new Response("{}", { headers: { "content-length": String(LIMITS.registryResponseBytes + 1) } }) });
  assert.equal((await h.request("/verify", target)).statusCode, 502);
  assert.equal(h.calls.dns, 0);
});

test("oversized capability response is explicit and is never retried", async () => {
  const h = harness({ fetch: async (url, init, count) => {
    if (count === 1) return registry([service]);
    if (init.method === "GET") return new Response("health");
    return new Response("x".repeat(LIMITS.capabilityResponseBytes + 1));
  } });
  const res = await h.request("/verify", target);
  const capability = res.body.verification.capabilityTests[0];
  assert.equal(capability.reason, "Capability response exceeds size limit");
  assert.equal(capability.attempts, 1);
  assert.equal(capability.retried, false);
  assert.equal(h.calls.fetch.length, 3);
});

test("401 capability has a separate report status and never receives credentials", async () => {
  const h = harness({ key: "synthetic-private-test-credential", fetch: async (url, init, count) => {
    if (count === 1) return registry([service, { endpoint: "https://unknown.example/chat" }]);
    return new Response("authentication needed", { status: init.method === "POST" ? 401 : 200 });
  } });
  const res = await h.request("/verify", target, "synthetic-private-test-credential");
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.report.capability.status, "AUTHENTICATION_REQUIRED");
  assert.equal(res.body.report.capability.authenticationRequiredCount, 2);
  assert.ok(res.body.verification.capabilityTests.every(item => item.authenticationRequired && item.attempts === 1));
  for (const call of h.calls.fetch) {
    const headers = new Headers(call.headers);
    assert.equal(headers.has("x-api-key"), false);
    assert.equal(headers.has("authorization"), false);
    assert.equal(call.redirect, "manual");
    assert.equal(JSON.stringify(call).includes("synthetic-private-test-credential"), false);
  }
  assert.equal(JSON.stringify(res.body).includes("synthetic-private-test-credential"), false);
});

test("health GET body is cancelled without consuming it", async () => {
  let cancelled = false;
  const h = harness({ fetch: async (url, init, count) => {
    if (count === 1) return registry([service]);
    if (init.method === "GET") return new Response(new ReadableStream({ cancel() { cancelled = true; } }));
    return new Response(JSON.stringify({ response: "VELRIX_CAPABILITY_OK" }));
  } });
  assert.equal((await h.request("/verify", target)).statusCode, 200);
  assert.equal(cancelled, true);
});

test("DNS-resolved private IP remains blocked and is never contacted", async () => {
  const h = harness({ services: [service], dns: async () => [{ address: "10.0.0.1", family: 4 }] });
  const res = await h.request("/verify", target);
  assert.equal(res.body.verification.endpointSafety[0].safe, false);
  assert.equal(h.calls.fetch.length, 1);
});

test("model transport enforces its byte cap without real fetch", async () => {
  const originalFetch = global.fetch;
  try {
    global.fetch = async () => new Response("oversize", { headers: { "content-length": String(LIMITS.modelResponseBytes + 1) } });
    await assert.rejects(boundedModelFetch("https://offline.invalid"), { code: "RESPONSE_TOO_LARGE" });
    global.fetch = async () => new Response('{"output":[]}', { headers: { "content-encoding": "gzip", "content-length": "13" } });
    const response = await boundedModelFetch("https://offline.invalid");
    assert.deepEqual(await response.json(), { output: [] });
    assert.equal(response.headers.has("content-encoding"), false);
    assert.equal(response.headers.has("content-length"), false);
  } finally {
    global.fetch = originalFetch;
  }
});

test("limited response body cancels a stalled real stream on deadline", async () => {
  let cancelled = false;
  const controller = new AbortController();
  const response = new Response(new ReadableStream({ cancel() { cancelled = true; } }));
  const reading = readLimitedJson(response, 1024, controller.signal);
  controller.abort(new Error("offline deadline"));
  await assert.rejects(reading, /offline deadline/);
  assert.equal(cancelled, true);
});

test("connection-time DNS guard rejects private and mixed answers", async () => {
  for (const addresses of [
    [{ address: "10.0.0.1", family: 4 }],
    [{ address: "8.8.8.8", family: 4 }, { address: "::ffff:127.0.0.1", family: 6 }]
  ]) {
    const h = harness({ dns: async () => addresses });
    const error = await new Promise(resolve => h.calls.lookup("agent.example", { all: true }, error => resolve(error)));
    assert.equal(error.message, "Unsafe IP address");
  }
});
