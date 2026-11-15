import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { networkInterfaces } from "node:os";
import { isIP } from "node:net";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { app, BrowserWindow, dialog, ipcMain } from "electron";

const PORT = 8765;
const MAX_REPORT_BYTES = 1024 * 1024;
const __dirname = path.dirname(fileURLToPath(import.meta.url));

let mainWindow;
let receiverToken;
let latestReport = null;
let scanStats = { usbScanCount: 0, goodUsbCount: 0, badUsbCount: 0 };
let scanStatsQueue = Promise.resolve();

function isPrivateAddress(address) {
  const normalized = address.replace(/^::ffff:/i, "").toLowerCase();
  if (normalized === "::1" || normalized.startsWith("fe80:")) return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;

  if (isIP(normalized) !== 4) return false;
  const [first, second] = normalized.split(".").map(Number);

  return (
    first === 10 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168) ||
    (first === 169 && second === 254) ||
    first === 127
  );
}

function getReceiverAddresses() {
  return Object.entries(networkInterfaces()).flatMap(([name, entries]) =>
    (entries ?? [])
      .filter(
        (entry) =>
          (entry.family === "IPv4" || entry.family === 4) &&
          !entry.internal &&
          isPrivateAddress(entry.address),
      )
      .map((entry) => ({ name, address: entry.address })),
  );
}

async function loadReceiverToken() {
  const tokenPath = path.join(app.getPath("userData"), "receiver-token");
  try {
    const storedToken = (await readFile(tokenPath, "utf8")).trim();
    if (storedToken) return storedToken;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  const token = randomBytes(32).toString("hex");
  await writeFile(tokenPath, token, { encoding: "utf8", flag: "wx", mode: 0o600 });
  return token;
}

function isValidCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

async function loadLegacyUsbScanCount() {
  const countPath = path.join(app.getPath("userData"), "usb-scan-count");
  try {
    const countText = (await readFile(countPath, "utf8")).trim();
    const storedCount = Number(countText);
    if (!/^\d+$/.test(countText) || !isValidCount(storedCount)) {
      throw new Error("Stored USB scan count is invalid.");
    }
    return storedCount;
  } catch (error) {
    if (error.code === "ENOENT") return 0;
    throw error;
  }
}

async function loadUsbScanStats() {
  const statsPath = path.join(app.getPath("userData"), "usb-scan-stats.json");
  try {
    const stats = JSON.parse(await readFile(statsPath, "utf8"));
    if (
      !stats ||
      typeof stats !== "object" ||
      Array.isArray(stats) ||
      !["usbScanCount", "goodUsbCount", "badUsbCount"].every((key) =>
        isValidCount(stats[key]),
      )
    ) {
      throw new Error("Stored USB scan statistics are invalid.");
    }
    return stats;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    return {
      usbScanCount: await loadLegacyUsbScanCount(),
      goodUsbCount: 0,
      badUsbCount: 0,
    };
  }
}

function getReportMaliciousResult(report) {
  if (typeof report.malicious === "boolean") return report.malicious;
  if (typeof report.malicious === "string") {
    const malicious = report.malicious.trim().toUpperCase();
    if (malicious === "YES") return true;
    if (malicious === "NO") return false;
  }
  if (typeof report.detection?.threat_detected === "boolean") {
    return report.detection.threat_detected;
  }
  return undefined;
}

function recordUsbScan(report) {
  const update = scanStatsQueue.then(async () => {
    const maliciousResult = getReportMaliciousResult(report);
    const nextStats = {
      usbScanCount: scanStats.usbScanCount + 1,
      goodUsbCount: scanStats.goodUsbCount + (maliciousResult === false ? 1 : 0),
      badUsbCount: scanStats.badUsbCount + (maliciousResult === true ? 1 : 0),
    };
    const statsPath = path.join(app.getPath("userData"), "usb-scan-stats.json");
    await writeFile(statsPath, JSON.stringify(nextStats), {
      encoding: "utf8",
      mode: 0o600,
    });
    scanStats = nextStats;
    return scanStats;
  });
  scanStatsQueue = update.then(
    () => undefined,
    () => undefined,
  );
  return update;
}

function sendJson(response, status, payload) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  response.end(JSON.stringify(payload));
}

function hasValidToken(request) {
  const authorization = request.headers.authorization ?? "";
  const supplied = Buffer.from(
    authorization.startsWith("Bearer ") ? authorization.slice(7) : "",
  );
  const expected = Buffer.from(receiverToken);

  return (
    supplied.length === expected.length &&
    timingSafeEqual(supplied, expected)
  );
}

async function handleRequest(request, response) {
  const requestUrl = new URL(request.url ?? "/", "http://localhost");

  if (request.method === "GET" && requestUrl.pathname === "/health") {
    sendJson(response, 200, { status: "ready" });
    return;
  }

  if (request.method !== "POST" || requestUrl.pathname !== "/report") {
    sendJson(response, 404, { error: "Endpoint not found." });
    return;
  }

  if (!isPrivateAddress(request.socket.remoteAddress ?? "")) {
    sendJson(response, 403, { error: "Only local network connections are allowed." });
    return;
  }

  if (!hasValidToken(request)) {
    sendJson(response, 401, { error: "A valid bearer token is required." });
    return;
  }

  if (
    !String(request.headers["content-type"] ?? "")
      .toLowerCase()
      .startsWith("application/json")
  ) {
    sendJson(response, 415, { error: "Content-Type must be application/json." });
    return;
  }

  const chunks = [];
  let bytesReceived = 0;
  let tooLarge = false;

  for await (const chunk of request) {
    bytesReceived += chunk.length;
    if (bytesReceived > MAX_REPORT_BYTES) {
      tooLarge = true;
    } else {
      chunks.push(chunk);
    }
  }

  if (tooLarge) {
    sendJson(response, 413, { error: "Report exceeds the 1 MB size limit." });
    return;
  }

  let report;
  try {
    report = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    sendJson(response, 400, { error: "Request body must contain valid JSON." });
    return;
  }

  if (!report || typeof report !== "object" || Array.isArray(report)) {
    sendJson(response, 400, { error: "Report must be a JSON object." });
    return;
  }

  const updatedUsbScanStats = await recordUsbScan(report);
  latestReport = report;
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send(
      "brick:report-received",
      report,
      updatedUsbScanStats,
    );
  }

  sendJson(response, 200, { status: "accepted" });
}

const receiver = createServer((request, response) => {
  handleRequest(request, response).catch((error) => {
    console.error("Failed to process Raspberry Pi report:", error);
    if (!response.headersSent) {
      sendJson(response, 500, { error: "The report could not be processed." });
    }
  });
});

receiver.requestTimeout = 15_000;
receiver.headersTimeout = 10_000;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 760,
    minHeight: 600,
    backgroundColor: "#414141",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  mainWindow.on("closed", () => {
    mainWindow = null;
  });
  mainWindow.webContents.on("did-fail-load", (_event, code, description) => {
    console.error(`B.R.I.C.K. page load failed (${code}): ${description}`);
  });
  mainWindow.webContents.on("render-process-gone", (_event, details) => {
    console.error("B.R.I.C.K. renderer process exited:", details);
  });

  if (app.isPackaged) {
    mainWindow.loadFile(path.join(__dirname, "../dist/index.html"));
  } else {
    mainWindow.loadURL("http://127.0.0.1:5173");
  }
}

ipcMain.handle("brick:receiver-info", () => ({
  port: PORT,
  token: receiverToken,
  addresses: getReceiverAddresses(),
  latestReport,
  ...scanStats,
}));

app.whenReady().then(async () => {
  try {
    receiverToken = await loadReceiverToken();
    scanStats = await loadUsbScanStats();
    await new Promise((resolve, reject) => {
      receiver.once("error", reject);
      receiver.listen(PORT, "0.0.0.0", resolve);
    });
    createWindow();
  } catch (error) {
    console.error("Failed to start B.R.I.C.K. report receiver:", error);
    dialog.showErrorBox(
      "B.R.I.C.K. could not start",
      `The report receiver could not start: ${error.message}`,
    );
    app.quit();
  }
});

app.on("window-all-closed", () => {
  app.quit();
});

app.on("before-quit", () => {
  receiver.close();
});
