require("dotenv").config();

const express = require("express");
const OpenAI = require("openai");
const net = require("net");
const dns = require("dns").promises;

const app = express();
const PORT = process.env.PORT || 3000;

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

app.use(express.json());

function isSafeEndpoint(endpoint) {
  try {
    const url = new URL(endpoint);

    if (url.protocol !== "https:" && url.protocol !== "http:") {
      return false;
    }

    const hostname = url.hostname.toLowerCase();

    if (
      hostname === "localhost" ||
      hostname === "0.0.0.0" ||
      hostname === "::1" ||
      hostname.endsWith(".local")
    ) {
      return false;
    }

    if (net.isIP(hostname)) {
      const parts = hostname.split(".").map(Number);

      if (
        hostname.startsWith("127.") ||
        hostname.startsWith("10.") ||
        hostname.startsWith("192.168.") ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
      ) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}

function isPrivateIP(ip) {
  if (!net.isIP(ip)) {
    return true;
  }

  if (ip === "::1" || ip === "0.0.0.0") {
    return true;
  }

  if (
    ip.startsWith("127.") ||
    ip.startsWith("10.") ||
    ip.startsWith("192.168.")
  ) {
    return true;
  }

  const parts = ip.split(".").map(Number);

  if (
    parts.length === 4 &&
    parts[0] === 172 &&
    parts[1] >= 16 &&
    parts[1] <= 31
  ) {
    return true;
  }

  return false;
}

async function resolveSafeEndpoint(endpoint) {
  try {
    if (!isSafeEndpoint(endpoint)) {
      return {
        safe: false,
        reason: "Unsafe or invalid URL"
      };
    }

    const url = new URL(endpoint);

    const addresses = await dns.lookup(url.hostname, {
      all: true
    });

    if (addresses.length === 0) {
      return {
        safe: false,
        reason: "Domain could not be resolved"
      };
    }

    for (const address of addresses) {
      if (isPrivateIP(address.address)) {
        return {
          safe: false,
          reason: "Endpoint resolves to a private IP"
        };
      }
    }

    return {
      safe: true,
      hostname: url.hostname,
      addresses: addresses.map(item => item.address)
    };
  } catch (error) {
    return {
      safe: false,
      reason: "DNS lookup failed"
    };
  }
}
async function checkEndpointHealth(endpoint) {
  const safety = await resolveSafeEndpoint(endpoint);

  if (!safety.safe) {
    return {
      endpoint,
      reachable: false,
      tested: false,
      reason: safety.reason
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);

  const startedAt = Date.now();

  try {
    const response = await fetch(endpoint, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal
    });

    const responseTimeMs = Date.now() - startedAt;

    return {
      endpoint,
      reachable: true,
      tested: true,
      httpStatus: response.status,
      responseTimeMs
    };
  } catch (error) {
    return {
      endpoint,
      reachable: false,
      tested: true,
      reason:
        error.name === "AbortError"
          ? "Request timed out"
          : "Connection failed"
    };
  } finally {
    clearTimeout(timeout);
  }
}
async function testChatCapability(endpoint) {
  const safety = await resolveSafeEndpoint(endpoint);

  if (!safety.safe) {
    return {
      endpoint,
      tested: false,
      passed: false,
      reason: safety.reason
    };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  const startedAt = Date.now();

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      redirect: "manual",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        message: "Reply with exactly: VELRIX_CAPABILITY_OK"
      }),
      signal: controller.signal
    });

    const responseTimeMs = Date.now() - startedAt;

    let data = null;

    try {
      data = await response.json();
    } catch {
      // Response was not JSON.
    }

    const responseText =
      typeof data?.response === "string"
        ? data.response.trim()
        : "";

    const passed =
      response.ok &&
      responseText === "VELRIX_CAPABILITY_OK";

    return {
      endpoint,
      tested: true,
      passed,
      httpStatus: response.status,
      responseTimeMs,
      expected: "VELRIX_CAPABILITY_OK",
      received: responseText || null
    };
  } catch (error) {
    return {
      endpoint,
      tested: true,
      passed: false,
      reason:
        error.name === "AbortError"
          ? "Capability test timed out"
          : "Capability test failed"
    };
  } finally {
    clearTimeout(timeout);
  }
}
app.get("/", (req, res) => {
  res.json({
    agent: "Velrix",
    agentId: 96147,
    network: "Base",
    status: "online",
    ai: true
  });
});

app.post("/chat", async (req, res) => {
  try {
    const message = req.body.message;

    if (!message) {
      return res.status(400).json({
        error: "message is required"
      });
    }

    const response = await openai.responses.create({
      model: "gpt-6-astra",
      instructions:
        "You are Velrix, an autonomous AI agent registered as ERC-8004 Agent #96147 on Base. Be concise, useful, and clear.",
      input: message
    });

    res.json({
      agent: "Velrix",
      response: response.output_text
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Velrix AI request failed"
    });
  }
});

app.post("/verify", async (req, res) => {
  try {
    const { network, agentId } = req.body;

    if (!network || !agentId) {
      return res.status(400).json({
        error: "network and agentId are required"
      });
    }

    if (network.toLowerCase() !== "base") {
      return res.status(400).json({
        error: "Velrix Verify currently supports Base only"
      });
    }

    const chainId = 8453;

    const apiResponse = await fetch(
      `https://api.8004scan.io/api/v1/agents/${chainId}/${agentId}`
    );

    if (!apiResponse.ok) {
      return res.status(apiResponse.status).json({
        error: "Agent could not be found",
        chainId,
        agentId
      });
    }

    const agentData = await apiResponse.json();

    const services =
      agentData?.raw_metadata?.offchain_content?.services || [];

    const declaredEndpoints = services
      .map(service => service.endpoint)
      .filter(endpoint => typeof endpoint === "string");

    const endpointSafety = [];

    for (const endpoint of declaredEndpoints) {
      const safety = await resolveSafeEndpoint(endpoint);

      endpointSafety.push({
        endpoint,
        ...safety
      });
    }
const endpointHealth = [];

for (const endpoint of declaredEndpoints) {
  const health = await checkEndpointHealth(endpoint);
  endpointHealth.push(health);
}
const capabilityTests = [];

for (const endpoint of declaredEndpoints) {
  const capability = await testChatCapability(endpoint);
  capabilityTests.push(capability);
}
    res.json({
      verifier: "Velrix",
      version: "0.1",
      target: {
        network: "Base",
        chainId,
        agentId
      },
      verification: {
        identityFound: true,
        declaredEndpoints,
        endpointSafety,
        endpointHealth,
        capabilityTests
      },
      evidence: agentData
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Velrix Verify failed"
    });
  }
});

app.listen(PORT, () => {
  console.log(`Velrix is running at http://localhost:${PORT}`);
});