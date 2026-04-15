"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const http = require("http");

// ─── Config ─────────────────────────────────────────────
const POLL_INTERVAL_MS = 30 * 1000;
const CONFIG_FILE = path.join(__dirname, "config.json");
const MOCK_FILE = path.join(__dirname, "mock-telemetry.json");

// ─── State ──────────────────────────────────────────────
let isClaimable = false;
let verificationDone = false;
let verificationMessage = "Pending";
let backendUrl = "http://localhost:3001";

// ─── Telemetry Hash Storage ──────────────────────────────
let storedTelemetryHash = null;

// ─── Logger ─────────────────────────────────────────────
function log(level, msg) {
  console.log(`[${new Date().toISOString()}] [${level}] ${msg}`);
}

// ─── Load Config ────────────────────────────────────────
function loadConfig() {
  const raw = fs.readFileSync(CONFIG_FILE, "utf8").replace(/^\uFEFF/, "");
  return JSON.parse(raw);
}

// ─── Hash Telemetry ─────────────────────────────────────
function hashTelemetry(telemetry) {
  const json = JSON.stringify(telemetry);
  return crypto.createHash("sha256").update(json, "utf8").digest("hex");
}

// ─── Verify Installation ────────────────────────────────
async function verifyWallet() {
  const config = loadConfig();
  backendUrl = config.backendUrl || backendUrl;

  const decoded = JSON.parse(
    Buffer.from(config.payload, "base64").toString("utf8"),
  );

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
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve(data));
      },
    );

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

// ─── SEND TO BACKEND ──────────────────────────────
async function sendToBackend(heartbeat) {
  try {
    const config = loadConfig();

    const decoded = JSON.parse(
      Buffer.from(config.payload, "base64").toString("utf8"),
    );

    if (!config.machine_id) {
      throw new Error("machine_id missing in config");
    }

    const machineId = config.machine_id;

    const payload = {
      machine: {
        machine_id: machineId,
        operator: decoded.operator || "unknown",
        pool: decoded.pool || "unknown",
        operator_wallet: global.operatorWallet || "unknown",
        worker_id: decoded.worker_id || "worker-1",
        fingerprint: storedTelemetryHash,
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
        },
        (res) => {
          let data = "";
          res.on("data", (c) => (data += c));
          res.on("end", () => resolve(data));
        },
      );

      req.on("error", reject);
      req.write(body);
      req.end();
    });

    log("INFO", "Telemetry sent to backend");
    log("INFO", response);
  } catch (err) {
    log("ERROR", "Failed to send telemetry: " + err.message);
  }
}

// ─── Poll using MOCK ────────────────────────────────────
async function poll() {
  try {
    const raw = fs.readFileSync(MOCK_FILE, "utf8");
    const data = JSON.parse(raw);

    const stats = data.STATS[0];

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

    const heartbeat = {
      batch_id: crypto.randomUUID(),
      timestamp_ms: Date.now(),
      miner_host: "mock",
      miner_type: data.INFO?.type ?? "mock",
      status: metrics.hashrate_ths > 0 ? "ONLINE" : "OFFLINE",
      claimable: isClaimable,
      verification_done: verificationDone,
      verification_message: verificationMessage,
      metrics,
    };

    storedTelemetryHash = hashTelemetry(heartbeat);

    log(
      "INFO",
      `MOCK POLL | ${metrics.hashrate_ths.toFixed(2)} TH/s | claimable=${isClaimable}`,
    );

    log("INFO", `Telemetry hash stored: ${storedTelemetryHash}`);

    console.log(JSON.stringify(heartbeat, null, 2));

    // ✅ NEW: send to backend
    await sendToBackend(heartbeat);
  } catch (err) {
    log("ERROR", err.message);
  }
}

// ─── Start ──────────────────────────────────────────────
async function start() {
  log("INFO", "Mock agent starting...");

  await verifyWallet();

  await poll();
  setInterval(poll, POLL_INTERVAL_MS);
}

start();
