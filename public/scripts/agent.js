"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const http = require("http");

// ─── Config ──────────────────────────────────────────────────────────────────
const POLL_INTERVAL_MS = 30 * 1000;
const REQUEST_TIMEOUT = 10 * 1000; // 10 s — covers packet loss on LAN
const CONFIG_FILE = path.join(__dirname, "config.json");
const LOG_FILE = path.join(__dirname, "rig-agent.log");

// Miner credentials — kept as constants (set during discovery by installer).
// If your firmware uses different credentials, update these.
const MINER_USER = "root";
const MINER_PASS = "root";

// ─── Runtime state ───────────────────────────────────────────────────────────
let isClaimable = false;
let verificationDone = false;
let verificationMessage = "Pending";
let backendUrl = "http://localhost:3001"; // overwritten by config on startup
let lastHeartbeatAt = null;

// Module-scope timer reference so the shutdown handler can clear it
// regardless of which lifecycle stage we were in when the signal arrived.
let pollTimer = null;

// ─── Logger ──────────────────────────────────────────────────────────────────
function log(level, msg) {
  const line = `[${new Date().toISOString()}] [${level}] ${msg}`;
  console.log(line);
  try {
    fs.appendFileSync(LOG_FILE, line + "\n");
  } catch (_) {}
}

// ─── Config loader ───────────────────────────────────────────────────────────
function loadConfig() {
  const raw = fs.readFileSync(CONFIG_FILE, "utf8").replace(/^\uFEFF/, ""); // strip BOM
  return JSON.parse(raw);
}

// ─── Digest Auth helpers (UNCHANGED from production) ─────────────────────────
function parseChallenge(header) {
  const out = {};
  const re = /(\w+)=(?:"([^"]+)"|([^\s,]+))/g;
  let m;
  while ((m = re.exec(header)) !== null) {
    out[m[1]] = m[2] !== undefined ? m[2] : m[3];
  }
  return out;
}

function buildAuthHeader(method, uriPath, challenge) {
  const { realm, nonce, qop } = challenge;

  const ha1 = crypto
    .createHash("md5")
    .update(`${MINER_USER}:${realm}:${MINER_PASS}`)
    .digest("hex");

  const ha2 = crypto
    .createHash("md5")
    .update(`${method}:${uriPath}`)
    .digest("hex");

  // qop=auth path (most common on modern firmware)
  if (qop && qop.includes("auth")) {
    const nc = "00000001";
    const cnonce = crypto.randomBytes(8).toString("hex");
    const response = crypto
      .createHash("md5")
      .update(`${ha1}:${nonce}:${nc}:${cnonce}:auth:${ha2}`)
      .digest("hex");

    return (
      `Digest username="${MINER_USER}", realm="${realm}", nonce="${nonce}", ` +
      `uri="${uriPath}", qop=auth, nc=${nc}, cnonce="${cnonce}", response="${response}"`
    );
  }

  // qop-absent fallback (older firmware)
  const response = crypto
    .createHash("md5")
    .update(`${ha1}:${nonce}:${ha2}`)
    .digest("hex");

  return (
    `Digest username="${MINER_USER}", realm="${realm}", nonce="${nonce}", ` +
    `uri="${uriPath}", response="${response}"`
  );
}

// ─── Low-level HTTP GET with timeout (UNCHANGED) ─────────────────────────────
function httpGet(host, port, uriPath, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host,
        port,
        path: uriPath,
        method: "GET",
        headers,
        timeout: REQUEST_TIMEOUT,
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () =>
          resolve({ status: res.statusCode, headers: res.headers, body }),
        );
      },
    );

    req.on("timeout", () => {
      req.destroy();
      reject(
        new Error(
          `Request to ${uriPath} timed out after ${REQUEST_TIMEOUT / 1000}s`,
        ),
      );
    });

    req.on("error", (err) =>
      reject(new Error(`Request to ${uriPath} failed: ${err.message}`)),
    );
    req.end();
  });
}

// ─── Digest fetch: probe → 401 → authenticated request (UNCHANGED) ───────────
async function digestGet(host, port, uriPath) {
  const probe = await httpGet(host, port, uriPath);

  if (probe.status === 200) {
    log("WARN", `${uriPath} returned 200 without auth — proceeding`);
    return probe.body;
  }

  if (probe.status !== 401) {
    throw new Error(`Expected 401 from ${uriPath}, got ${probe.status}`);
  }

  const wwwAuth = probe.headers["www-authenticate"];
  if (!wwwAuth) {
    throw new Error(`401 with no WWW-Authenticate header on ${uriPath}`);
  }

  const challenge = parseChallenge(wwwAuth);

  if (challenge.stale === "true") {
    log("WARN", `Stale nonce on ${uriPath} — using fresh nonce from challenge`);
  }

  const authHeader = buildAuthHeader("GET", uriPath, challenge);
  const authed = await httpGet(host, port, uriPath, {
    Authorization: authHeader,
  });

  if (authed.status !== 200) {
    throw new Error(
      `Digest auth failed on ${uriPath} — HTTP ${authed.status}. ` +
        `Check MINER_USER / MINER_PASS constants.`,
    );
  }

  return authed.body;
}

// ─── Fetch & RSA-decrypt wallet address from backend ─────────────────────────
async function fetchWalletAddress() {
  const config = loadConfig();
  backendUrl = config.backendUrl || backendUrl;

  const machineId = config.machine_id;
  if (!machineId) {
    throw new Error("machine_id missing from config.json");
  }

  const privateKeyPath = path.join(__dirname, "private_key.pem");
  if (!fs.existsSync(privateKeyPath)) {
    throw new Error(
      "private_key.pem not found — was the installer run correctly?",
    );
  }
  const privateKey = fs.readFileSync(privateKeyPath, "utf8");

  const url = new URL(
    `/api/encrypted-address?machineId=${encodeURIComponent(machineId)}`,
    backendUrl,
  );

  const response = await new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port || 5000,
        path: url.pathname + url.search,
        method: "GET",
        timeout: REQUEST_TIMEOUT,
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve(data));
      },
    );
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("encrypted-address request timed out"));
    });
    req.on("error", reject);
    req.end();
  });

  const parsed = JSON.parse(response);
  if (!parsed.success || !parsed.encryptedAddress) {
    throw new Error(
      parsed.message || "No encrypted address returned from backend",
    );
  }

  const decryptedBuf = crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    Buffer.from(parsed.encryptedAddress, "base64"),
  );

  global.operatorWallet = decryptedBuf.toString("utf8");
  log("INFO", "Connection established with frontend UI");
}

// ─── Verify install token with backend ───────────────────────────────────────
async function verifyWallet() {
  const config = loadConfig();
  backendUrl = config.backendUrl || backendUrl;

  let decoded;
  try {
    decoded = JSON.parse(
      Buffer.from(config.payload, "base64").toString("utf8"),
    );
  } catch (e) {
    log("ERROR", "Failed to decode config payload: " + e.message);
    verificationDone = true;
    verificationMessage = "Verification Failed — bad payload";
    return;
  }

  const { installToken } = decoded;
  if (!installToken) {
    log("ERROR", "No installToken found in config payload");
    verificationDone = true;
    verificationMessage = "Verification Failed — missing installToken";
    return;
  }

  const body = JSON.stringify({ installToken });
  const url = new URL("/api/validate-token", backendUrl);

  const response = await new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: url.hostname,
        port: url.port || 3001,
        path: url.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
        timeout: REQUEST_TIMEOUT,
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve(data));
      },
    );
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("validate-token request timed out"));
    });
    req.on("error", reject);
    req.write(body);
    req.end();
  });

  const parsed = JSON.parse(response.replace(/^\uFEFF/, ""));

  isClaimable = parsed.success === true;
  if (parsed.wallet) {
    global.operatorWallet = parsed.wallet; // secondary fallback if RSA step set it already
  }

  verificationDone = true;
  verificationMessage = isClaimable
    ? "Installation Verified"
    : parsed.message || "Verification Failed";

  log("INFO", `Verification: ${verificationMessage}`);
}

// ─── Send telemetry payload to backend ───────────────────────────────────────
async function sendToBackend(heartbeat) {
  try {
    const config = loadConfig();

    if (!config.machine_id) {
      throw new Error("machine_id missing in config");
    }

    const machineId = config.machine_id;
    const decoded = JSON.parse(
      Buffer.from(config.payload, "base64").toString("utf8"),
    );

    const payload = {
      machine: {
        machine_id: machineId,
        operator: decoded.operator || "unknown",
        pool: decoded.pool || "unknown",
        operator_wallet: global.operatorWallet || "unknown",
        worker_id: decoded.worker_id || "worker-1",
        created_at: Date.now(),
      },
      status: {
        machine_id: machineId,
        status: heartbeat.status,
        hashrate: heartbeat.metrics.hashrate_ths,
        temperature: heartbeat.metrics.max_chip_temp,
        uptime: heartbeat.metrics.uptime_sec,
        watt: heartbeat.metrics.watt,
        last_heartbeat: heartbeat.timestamp_ms,
      },
      telemetry: {
        machine_id: machineId,
        hashrate: heartbeat.metrics.hashrate_ths,
        rate_avg: heartbeat.metrics.rate_30m_ghs,
        temperature: heartbeat.metrics.max_chip_temp,
        uptime: heartbeat.metrics.uptime_sec,
        watt: heartbeat.metrics.watt,
        timestamp: heartbeat.timestamp_ms,
      },
    };

    const body = JSON.stringify(payload);
    const url = new URL("/api/onboard", backendUrl);

    const response = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          hostname: url.hostname,
          port: url.port || 3001,
          path: url.pathname,
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(body),
          },
          timeout: REQUEST_TIMEOUT,
        },
        (res) => {
          let data = "";
          res.on("data", (c) => (data += c));
          res.on("end", () => resolve(data));
        },
      );
      req.on("timeout", () => {
        req.destroy();
        reject(new Error("onboard request timed out"));
      });
      req.on("error", reject);
      req.write(body);
      req.end();
    });

    log("INFO", "Telemetry sent to backend");
    log("INFO", response);
  } catch (err) {
    // Backend failure must NEVER stop us from polling the miner.
    log("ERROR", "Failed to send telemetry: " + err.message);
  }
}

// ─── Poll miner via real Digest-authenticated API ────────────────────────────
async function poll() {
  try {
    const config = loadConfig();
    const minerHost = config.miner_ip;
    const minerPort = config.miner_port || 80;
    const discoveryStatus = config.discovery?.status || "unknown";

    if (!minerHost) {
      throw new Error(
        "miner_ip is not set in config.json — miner was not discovered",
      );
    }

    const raw = await digestGet(minerHost, minerPort, "/cgi-bin/stats.cgi");

    let data;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      throw new Error(`Invalid JSON from miner: ${raw.slice(0, 120)}`);
    }

    const stats = data?.STATS?.[0];
    if (!stats) {
      throw new Error("No STATS[0] in response — unexpected firmware format");
    }

    const hashrate_ghs = stats.rate_avg ?? stats.rate_30m ?? stats.rate_5s ?? 0;

    const chains = stats.chain ?? [];
    const temps = chains.flatMap((c) => c.temp_chip ?? []);
    const maxTemp = temps.length ? Math.max(...temps) : 0;

    const metrics = {
      hashrate_ths: hashrate_ghs / 1000,
      hashrate_ghs,
      rate_5s_ghs: stats.rate_5s ?? 0,
      rate_30m_ghs: stats.rate_30m ?? 0,
      hardware_errors: chains.reduce((s, c) => s + (c.hw ?? 0), 0),
      uptime_sec: stats.elapsed ?? 0,
      watt: stats.watt ?? 0,
      fan_speeds: stats.fan ?? [],
      max_chip_temp: maxTemp,
    };

    // Status mirrors the original production agent: a reachable miner with
    // positive hashrate is ONLINE; reachable-but-zero-hashrate is OFFLINE.
    const now = Date.now();
    const rigStatus = metrics.hashrate_ths > 0 ? "ONLINE" : "OFFLINE";
    lastHeartbeatAt = now;

    const heartbeat = {
      batch_id: crypto.randomUUID(),
      timestamp_ms: now,
      miner_host: minerHost,
      miner_port: minerPort,
      // Real Antminer firmware exposes INFO.type ("Antminer S19k Pro"). The
      // miner_version fallback is defensive coverage for stripped firmwares.
      miner_type: data?.INFO?.type ?? data?.INFO?.miner_version ?? "unknown",
      discovery_status: discoveryStatus,
      status: rigStatus,
      claimable: isClaimable,
      verification_done: verificationDone,
      verification_message: verificationMessage,
      metrics,
    };

    log(
      "INFO",
      `POLL OK | ${metrics.hashrate_ths.toFixed(2)} TH/s | ` +
        `hw_err=${metrics.hardware_errors} | temp=${maxTemp}°C | ` +
        `power=${metrics.watt}W | uptime=${metrics.uptime_sec}s | ` +
        `claimable=${isClaimable}`,
    );

    console.log(JSON.stringify(heartbeat, null, 2));

    await sendToBackend(heartbeat);
  } catch (err) {
    log(
      "ERROR",
      `Poll failed — retrying in ${POLL_INTERVAL_MS / 1000}s | ${err.message}`,
    );
  }
}

// ─── Shutdown handler ────────────────────────────────────────────────────────
// Registered by start() BEFORE any awaited initialization so Ctrl+C/SIGTERM
// is honoured at every lifecycle stage, not only after polling has begun.
function shutdown(signal) {
  log("INFO", `${signal} — stopping.`);
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  // Forceful exit. Any in-flight HTTP request to the miner or backend is
  // abandoned, which is the right behavior for an interrupt — we don't want
  // a hung backend socket to delay shutdown by up to REQUEST_TIMEOUT.
  process.exit(0);
}

// ─── Entry point ─────────────────────────────────────────────────────────────
async function start() {
  log("INFO", "Agent starting...");

  // Register signal handlers FIRST, before any awaited work. Previously
  // these were registered after startup completed, so a Ctrl+C during
  // fetchWalletAddress() / verifyWallet() / first poll() bypassed the
  // cleanup logging. Doing it up-front makes shutdown deterministic at
  // every lifecycle stage. Safe because pollTimer starts as null and the
  // handler null-checks before clearing.
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  // Step 1 — backend init is BEST-EFFORT.
  try {
    await fetchWalletAddress();
  } catch (err) {
    log(
      "WARN",
      `fetchWalletAddress failed (continuing without wallet): ${err.message}`,
    );
  }

  try {
    await verifyWallet();
  } catch (err) {
    log("WARN", `verifyWallet failed (continuing unverified): ${err.message}`);
    verificationDone = true;
    verificationMessage = "Verification Failed — backend unreachable";
  }

  // Step 2 — first poll immediately, then on interval.
  await poll();
  pollTimer = setInterval(poll, POLL_INTERVAL_MS);
}

start().catch((err) => {
  log("ERROR", `Fatal: ${err.message}`);
  process.exit(1);
});
