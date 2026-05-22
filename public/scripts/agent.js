"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const http = require("http");

// ─── Config ──────────────────────────────────────────────────────────────────
const POLL_INTERVAL_MS = 30 * 1000;
const REQUEST_TIMEOUT = 10 * 1000;
const CONFIG_FILE = path.join(__dirname, "config.json");
const LOG_FILE = path.join(__dirname, "rig-agent.log");

const MINER_USER = "root";
const MINER_PASS = "root";

// ─── Runtime state ───────────────────────────────────────────────────────────
let isClaimable = false;
let verificationDone = false;
let verificationMessage = "Pending";
let backendUrl = "http://localhost:3001";
let lastHeartbeatAt = null;
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
  const raw = fs.readFileSync(CONFIG_FILE, "utf8").replace(/^\uFEFF/, "");
  return JSON.parse(raw);
}

// ─── getMachines ─────────────────────────────────────────────────────────────
// Returns the machines array from config, normalised to always be an array.
// Supports both:
//   New format:  { machines: [ { machine_id, miner_ip, miner_port }, ... ] }
//   Legacy format: { machine_id, miner_ip, miner_port }  (single-rig installs)
function getMachines(config) {
  if (Array.isArray(config.machines) && config.machines.length > 0) {
    return config.machines;
  }
  // Legacy single-machine config — wrap so the rest of the code is uniform.
  if (config.machine_id && config.miner_ip) {
    return [
      {
        machine_id: config.machine_id,
        miner_ip: config.miner_ip,
        miner_port: config.miner_port || 80,
        miner_type: "unknown",
        auth_mode: "unknown",
      },
    ];
  }
  return [];
}

// ─── Digest Auth helpers ──────────────────────────────────────────────────────
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

  const response = crypto
    .createHash("md5")
    .update(`${ha1}:${nonce}:${ha2}`)
    .digest("hex");

  return (
    `Digest username="${MINER_USER}", realm="${realm}", nonce="${nonce}", ` +
    `uri="${uriPath}", response="${response}"`
  );
}

// ─── Low-level HTTP GET with timeout ──────────────────────────────────────────
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

// ─── Digest-authenticated GET ─────────────────────────────────────────────────
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

// ─── Fetch & RSA-decrypt wallet address from backend ──────────────────────────
// Uses the first machine's machine_id. All machines share the same wallet.
async function fetchWalletAddress() {
  const config = loadConfig();
  backendUrl = config.backendUrl || backendUrl;

  const machines = getMachines(config);
  if (machines.length === 0) {
    throw new Error("No machines found in config.json");
  }

  // Use first machine's ID to fetch the (shared) encrypted wallet.
  const machineId = machines[0].machine_id;
  if (!machineId) {
    throw new Error(
      "machine_id missing from first machine entry in config.json",
    );
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
  log("INFO", "Wallet address decrypted successfully");
}

// ─── Verify install token with backend ────────────────────────────────────────
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
    global.operatorWallet = parsed.wallet;
  }

  verificationDone = true;
  verificationMessage = isClaimable
    ? "Installation Verified"
    : parsed.message || "Verification Failed";

  log("INFO", `Verification: ${verificationMessage}`);
}

// ─── Send telemetry for one machine to backend ────────────────────────────────
async function sendToBackend(machine, heartbeat) {
  try {
    const config = loadConfig();

    const decoded = JSON.parse(
      Buffer.from(config.payload, "base64").toString("utf8"),
    );

    const payload = {
      machine: {
        machine_id: machine.machine_id,
        operator: decoded.operator || "unknown",
        pool: decoded.pool || "unknown",
        operator_wallet: global.operatorWallet || "unknown",
        worker_id: decoded.worker_id || "worker-1",
        created_at: Date.now(),
      },
      status: {
        machine_id: machine.machine_id,
        status: heartbeat.status,
        hashrate: heartbeat.metrics.hashrate_ths,
        temperature: heartbeat.metrics.max_chip_temp,
        uptime: heartbeat.metrics.uptime_sec,
        watt: heartbeat.metrics.watt,
        last_heartbeat: heartbeat.timestamp_ms,
      },
      telemetry: {
        machine_id: machine.machine_id,
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

    log("INFO", `[${machine.miner_ip}] Telemetry sent`);
    log("INFO", response);
  } catch (err) {
    log(
      "ERROR",
      `[${machine.miner_ip}] Failed to send telemetry: ${err.message}`,
    );
  }
}

// ─── Poll one machine ─────────────────────────────────────────────────────────
// Fetches stats from a single miner, builds a heartbeat, ships it to backend.
// Returns true if the miner responded, false on any error.
async function pollMachine(machine) {
  const { machine_id, miner_ip, miner_port = 80 } = machine;

  try {
    const raw = await digestGet(miner_ip, miner_port, "/cgi-bin/stats.cgi");

    let data;
    try {
      data = JSON.parse(raw);
    } catch (e) {
      throw new Error(
        `Invalid JSON from miner ${miner_ip}: ${raw.slice(0, 120)}`,
      );
    }

    const stats = data?.STATS?.[0];
    if (!stats) {
      throw new Error(
        `No STATS[0] in response from ${miner_ip} — unexpected firmware format`,
      );
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

    const now = Date.now();
    const rigStatus = metrics.hashrate_ths > 0 ? "ONLINE" : "OFFLINE";
    lastHeartbeatAt = now;

    const heartbeat = {
      batch_id: crypto.randomUUID(),
      timestamp_ms: now,
      machine_id,
      miner_host: miner_ip,
      miner_port,
      miner_type:
        data?.INFO?.type ??
        data?.INFO?.miner_version ??
        machine.miner_type ??
        "unknown",
      discovery_status: "found",
      status: rigStatus,
      claimable: isClaimable,
      verification_done: verificationDone,
      verification_message: verificationMessage,
      metrics,
    };

    log(
      "INFO",
      `[${miner_ip}] POLL OK | ${metrics.hashrate_ths.toFixed(2)} TH/s | ` +
        `temp=${maxTemp}°C | power=${metrics.watt}W | uptime=${metrics.uptime_sec}s`,
    );

    await sendToBackend(machine, heartbeat);
    return true;
  } catch (err) {
    log("ERROR", `[${miner_ip}] Poll failed: ${err.message}`);
    return false;
  }
}

// ─── Poll all machines ────────────────────────────────────────────────────────
// Iterates through every machine in config.machines[], polls each in parallel,
// then logs a summary.
async function poll() {
  const config = loadConfig();
  backendUrl = config.backendUrl || backendUrl;
  const machines = getMachines(config);

  if (machines.length === 0) {
    log("WARN", "No machines configured — skipping poll");
    return;
  }

  log("INFO", `--- Poll cycle start: ${machines.length} machine(s) ---`);

  // Fire all polls concurrently; each handles its own errors internally.
  const results = await Promise.all(machines.map((m) => pollMachine(m)));

  const online = results.filter(Boolean).length;
  const offline = results.length - online;

  log(
    "INFO",
    `--- Poll cycle end: ${online}/${machines.length} online, ${offline} unreachable ---`,
  );
}

// ─── Shutdown handler ────────────────────────────────────────────────────────
function shutdown(signal) {
  log("INFO", `${signal} — stopping.`);
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  process.exit(0);
}

// ─── Entry point ─────────────────────────────────────────────────────────────
async function start() {
  log("INFO", "Agent starting (multi-rig mode) ...");

  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));

  // Log discovered machine list on startup.
  try {
    const config = loadConfig();
    const machines = getMachines(config);
    log("INFO", `Config loaded — ${machines.length} machine(s) configured:`);
    machines.forEach((m, i) =>
      log(
        "INFO",
        `  [${i + 1}] machine_id=${m.machine_id}  ip=${m.miner_ip}:${m.miner_port || 80}`,
      ),
    );
  } catch (err) {
    log("ERROR", `Could not read config on startup: ${err.message}`);
  }

  // Step 1 — backend init is best-effort (wallet + verification).
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
