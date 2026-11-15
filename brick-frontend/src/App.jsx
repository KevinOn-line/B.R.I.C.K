import { useEffect, useRef, useState } from "react";
import mockReport from "./data/mockReport.json";
import "./App.css";

const normalize = (value) =>
  typeof value === "string" ? value.trim().toUpperCase().replace(/[\s-]+/g, "_") : "";

function getMaliciousResult(report) {
  const malicious = report?.malicious;
  if (typeof malicious === "boolean") return malicious;
  if (typeof malicious === "string") {
    const normalized = normalize(malicious);
    if (normalized === "YES") return true;
    if (normalized === "NO") return false;
  }

  return typeof report?.detection?.threat_detected === "boolean"
    ? report.detection.threat_detected
    : undefined;
}

function isDeviceConnected(device) {
  if (!device) return false;
  if (typeof device.connected === "boolean") return device.connected;

  const status = normalize(device.connection_status);
  if (status) {
    return ["CONNECTED", "ONLINE"].includes(status);
  }

  return true;
}

function getNetworkState(network = {}) {
  const status = normalize(
    network.status ?? network.security_status ?? network.network_status,
  );
  const isUnsecure =
    ["UNSECURE", "UNSECURED", "INSECURE", "UNSAFE"].includes(status) ||
    network.secure === false ||
    network.is_secure === false ||
    network.normal === false;

  return isUnsecure
    ? { label: "Unsecure", tone: "orange" }
    : { label: "Normal", tone: "green" };
}

function formatTimestamp(value) {
  if (value === null || value === undefined || value === "") return "Unknown";

  let date;
  if (typeof value === "number") {
    date = new Date(value * 1000);
  } else if (typeof value === "string") {
    const trimmed = value.trim();
    if (/^\d+$/.test(trimmed)) {
      date = new Date(Number(trimmed) * 1000);
    } else {
      date = new Date(trimmed);
    }
  }

  if (!(date instanceof Date) || Number.isNaN(date.getTime())) {
    return String(value);
  }

  const monthNames = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
  ];
  const month = monthNames[date.getUTCMonth()];
  const day = date.getUTCDate();
  const year = date.getUTCFullYear();
  const hours = String(date.getUTCHours()).padStart(2, "0");
  const minutes = String(date.getUTCMinutes()).padStart(2, "0");

  return `${month} ${day}, ${year} -- ${hours}:${minutes} UTC`;
}

function isNetworkActive(network = {}) {
  const active =
    network.active ?? network.monitoring_enabled ?? network.dns_filtering_enabled;
  if (typeof active === "boolean") return active;

  const status = normalize(
    network.dns_filtering ?? network.status ?? network.network_status,
  );
  return !["INACTIVE", "DISABLED", "OFFLINE", "FALSE"].includes(status);
}

function normalizeReport(report = {}) {
  const details = report?.details ?? {};
  const device = report?.device ?? {};
  const detection = report?.detection ?? {};
  const network = report?.network_security ?? {};
  const summary = report?.summary ?? {};

  return {
    ...report,
    metadata: {
      ...(report?.metadata ?? {}),
      timestamp: report?.metadata?.timestamp ?? report?.timestamp ?? "Unknown",
    },
    device: {
      ...device,
      connected:
        typeof device.connected === "boolean"
          ? device.connected
          : typeof report?.connected === "boolean"
            ? report.connected
            : true,
    },
    detection: {
      ...detection,
      category:
        detection.category ??
        detection.threat_category ??
        details.threat_type ??
        "Unknown",
    },
    network_security: {
      ...network,
      status:
        network.status ??
        report?.security_status ??
        report?.network_status,
      active:
        typeof network.active === "boolean"
          ? network.active
          : typeof report?.network_active === "boolean"
            ? report.network_active
            : undefined,
    },
    summary: {
      ...summary,
      message:
        summary.message ??
        report?.message ??
        details.threat_details ??
        "Nothing to Report",
    },
  };
}

function App() {
  const desktopBridge = window.brickDesktop;
  const [report, setReport] = useState(desktopBridge ? null : mockReport);
  const [connected, setConnected] = useState(
    () => !desktopBridge && Boolean(mockReport),
  );
  const [scanStats, setScanStats] = useState(() => {
    const maliciousResult = getMaliciousResult(mockReport);
    return {
      usbScanCount: desktopBridge || !mockReport ? 0 : 1,
      goodUsbCount: !desktopBridge && maliciousResult === false ? 1 : 0,
      badUsbCount: !desktopBridge && maliciousResult === true ? 1 : 0,
    };
  });
  const [showReport, setShowReport] = useState(false);
  const [showConnection, setShowConnection] = useState(false);
  const [receiverInfo, setReceiverInfo] = useState(null);
  const [receiverError, setReceiverError] = useState("");
  const reportDialogRef = useRef(null);
  const connectionDialogRef = useRef(null);

  useEffect(() => {
    if (!desktopBridge) return undefined;

    let active = true;
    const unsubscribe = desktopBridge.onReport((incomingReport, incomingScanStats) => {
      setReport(incomingReport);
      setConnected(true);
      setScanStats(incomingScanStats);
      setReceiverError("");
    });

    desktopBridge
      .getReceiverInfo()
      .then((info) => {
        if (!active) return;
        setReceiverInfo(info);
        setScanStats({
          usbScanCount: info.usbScanCount,
          goodUsbCount: info.goodUsbCount,
          badUsbCount: info.badUsbCount,
        });
        if (info.latestReport) {
          setReport(info.latestReport);
          setConnected(true);
        }
      })
      .catch((error) => {
        if (active) {
          setReceiverError(error.message || "Unable to start the report receiver.");
        }
      });

    return () => {
      active = false;
      unsubscribe();
    };
  }, [desktopBridge]);

  useEffect(() => {
    const reportDialog = reportDialogRef.current;
    const connectionDialog = connectionDialogRef.current;

    if (showReport && reportDialog && !reportDialog.open) {
      reportDialog.showModal();
    } else if (!showReport && reportDialog?.open) {
      reportDialog.close();
    }

    if (showConnection && connectionDialog && !connectionDialog.open) {
      connectionDialog.showModal();
    } else if (!showConnection && connectionDialog?.open) {
      connectionDialog.close();
    }
  }, [showReport, showConnection]);

  useEffect(() => {
    if (!showReport && !showConnection) return undefined;

    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        setShowReport(false);
        setShowConnection(false);
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [showReport, showConnection]);

  const normalizedReport = normalizeReport(report);
  const detection = normalizedReport.detection ?? {};
  const network = normalizedReport.network_security ?? {};
  const device = normalizedReport.device;
  const maliciousResult = getMaliciousResult(report);
  const isMalicious = maliciousResult === true;
  const threatKnown = maliciousResult !== undefined;
  const classifiedUsbCount = scanStats.goodUsbCount + scanStats.badUsbCount;
  const confidencePercent =
    classifiedUsbCount > 0
      ? (scanStats.goodUsbCount / classifiedUsbCount) * 100
      : null;
  const confidenceTone =
    confidencePercent === null
      ? "unknown"
      : confidencePercent <= 40
        ? "red"
        : confidencePercent <= 60
          ? "yellow"
          : "green";
  const deviceConnected = isDeviceConnected(device);
  const deviceTrust = isMalicious ? "untrusted" : "trusted";
  const action = isMalicious
    ? { label: "REMOVE", tone: "red" }
    : { label: "NOT NEEDED", tone: "green" };
  const networkActive = connected && isNetworkActive(network);
  const networkState = connected
    ? getNetworkState(network)
    : { label: "Inactive", tone: "red" };
  const faceState = !threatKnown ? "inconclusive" : isMalicious ? "threat" : "safe";
  const faceMessage = !threatKnown
    ? "Inconclusive"
    : isMalicious
      ? "Threat Detected!"
      : "No Threat Detected";
  const type =
    normalizedReport?.details?.partition ??
    detection.category ??
    detection.threat_category ??
    "Unknown";
  const typeTone = /(^|[^a-z0-9])(malware|trojan)([^a-z0-9]|$)/i.test(type)
    ? "red"
    : "green";
  const terminalMessage =
    normalizedReport.summary?.message?.trim() ||
    normalizedReport.summary?.final_message?.trim() ||
    report?.summary?.final_message?.trim() ||
    report?.final_message?.trim() ||
    report?.message?.trim() ||
    "Nothing to Report";
  const deviceId = report?.device_id ?? device?.device_identifier ?? device?.vendor_id ?? "Unknown";
  const statusLabel =
    String(report?.status ?? "Scanned").trim() || "Scanned";
  const maliciousLabel = isMalicious ? "Yes" : "No";
  const latestCheckLabel = !threatKnown
    ? "Unknown"
    : isMalicious
      ? "Bad"
      : "Good";
  const latestCheckTone = !threatKnown
    ? "orange"
    : isMalicious
      ? "red"
      : "green";

  return (
    <main className="dashboard">
      <section className="side-column" aria-label="Inspection details">
        <article className={`readout action-card tone-${action.tone}`}>
          <h2>Action</h2>
          <p className={`tone-${action.tone}`}>{action.label}</p>
        </article>

        <article className={`readout type-card tone-${typeTone}`}>
          <h2>Type</h2>
          <p>{type}</p>
        </article>

        <article className={`readout device-card tone-${deviceTrust}`}>
          <h2>Device info</h2>
          <p>Device ID: {deviceId}</p>
          <p>Status: {statusLabel}</p>
          <p>Malicious: {maliciousLabel}</p>
          <p>Trust: {deviceTrust === "trusted" ? "Trusted" : "Untrusted"}</p>
        </article>
      </section>

      <section className="center-column" aria-label="B.R.I.C.K. status">
        <div className={`status-screen ${faceState}`}>
          <div className="screen-content">
            <svg
              className="pixel-face"
              viewBox="0 0 200 200"
              role="img"
              aria-label={faceMessage}
              shapeRendering="crispEdges"
            >
              <g fill="currentColor">
                <path d="M75 10h50v10h20v10h10v10h10v20h10v60h-10v20h-10v10h-10v10h-20v10H75v-10H55v-10H45v-10H35v-20H25V60h10V40h10V30h10V20h20V10Zm0 10v10H55v10H45v20H35v60h10v20h10v10h20v10h50v-10h20v-10h10v-20h10V60h-10V40h-10V30h-20V20H75Z" />
                <path d="M60 75h20v20H60zM120 75h20v20h-20z" />
                {isMalicious ? (
                  <path d="M65 135h10v-10h10v-10h30v10h10v10h10v10h-10v-10h-10v-10H85v10H75v10H65z" />
                ) : threatKnown ? (
                  <path d="M65 120h10v10h10v10h30v-10h10v-10h10v10h-10v10h-10v10H85v-10H75v-10H65z" />
                ) : (
                  <path d="M65 132h70v10H65z" />
                )}
              </g>
            </svg>
            <p className="screen-message">{faceMessage}</p>
          </div>
        </div>

        <div className="system-strip">
          <div className="system-cell">
            <span className="cell-label">B.R.I.C.K</span>
            <button
              className={`cell-value connection-toggle tone-${connected ? "green" : "red"}`}
              type="button"
              aria-haspopup="dialog"
              aria-controls="connection-dialog"
              onClick={() => setShowConnection(true)}
            >
              {connected ? "Online" : "Offline"}
            </button>
          </div>
          <div className="system-cell">
            <span className="cell-label">Device</span>
            <span
              className={`cell-value tone-${!deviceConnected ? "red" : !connected ? "orange" : deviceTrust}`}
            >
              {!deviceConnected
                ? "No connection"
                : !connected
                  ? "Connection"
                  : isMalicious
                    ? "Untrusted"
                    : "Trusted"}
            </span>
          </div>
          <div className="system-cell">
            <span className="cell-label">Network</span>
            <span className={`cell-value tone-${networkState.tone}`}>
              {networkState.label}
            </span>
          </div>
        </div>

        <button
          className="terminal-button"
          type="button"
          aria-haspopup="dialog"
          aria-controls="inspection-report-dialog"
          onClick={() => setShowReport((value) => !value)}
        >
          <span>
            Timestamp - “{formatTimestamp(normalizedReport.metadata?.timestamp ?? report?.timestamp ?? "Unknown")}”
          </span>
          <span>Final Message - “{terminalMessage}”</span>
          <span className="terminal-prompt">Click to view report</span>
        </button>
      </section>

      <section className="side-column" aria-label="Security metrics">
        <article className="readout action-card confidence-card">
          <h2>Confidence</h2>
          <p className={`confidence-value tone-${confidenceTone}`}>
            {confidencePercent === null
              ? "N/A"
              : `${confidencePercent.toFixed(1)}%`}
          </p>
        </article>

        <article className="readout type-card usb-count-card">
          <h2>USBs checked</h2>
          <p>{scanStats.usbScanCount}</p>
          <span className={`latest-check-status tone-${latestCheckTone}`}>
            Most recent: {latestCheckLabel}
          </span>
        </article>

        <article
          className={`readout network-card tone-${networkActive ? "green" : "red"}`}
        >
          <h2>Network</h2>
          <p className={`network-status tone-${networkActive ? "green" : "red"}`}>
            {networkActive ? "Active" : "Inactive"}
          </p>
        </article>
      </section>

      <dialog
        className="report-dialog"
        id="inspection-report-dialog"
        ref={reportDialogRef}
        aria-labelledby="report-dialog-title"
        onClose={() => setShowReport(false)}
        onClick={(event) => {
          if (event.target === event.currentTarget) {
            setShowReport(false);
          }
        }}
      >
        <div className="report-dialog-header">
          <h2 id="report-dialog-title">Inspection report</h2>
          <button
            className="report-close"
            type="button"
            aria-label="Close inspection report"
            onClick={() => setShowReport(false)}
          >
            ×
          </button>
        </div>
        <pre className="json-view">
          {report
            ? JSON.stringify(report, null, 2)
            : "No report has been received yet."}
        </pre>
      </dialog>

      <dialog
        className="report-dialog connection-dialog"
        id="connection-dialog"
        ref={connectionDialogRef}
        aria-labelledby="connection-dialog-title"
        onClose={() => setShowConnection(false)}
        onClick={(event) => {
          if (event.target === event.currentTarget) {
            setShowConnection(false);
          }
        }}
      >
        <div className="report-dialog-header">
          <h2 id="connection-dialog-title">Raspberry Pi connection</h2>
          <button
            className="report-close"
            type="button"
            aria-label="Close connection details"
            onClick={() => setShowConnection(false)}
          >
            ×
          </button>
        </div>

        {desktopBridge ? (
          <div className="receiver-details">
            <p>
              The app listens for reports on TCP port {receiverInfo?.port ?? 8765}.
              Configure the Pi to POST each JSON report to one of these addresses:
            </p>
            {receiverInfo?.addresses?.length ? (
              <ul>
                {receiverInfo.addresses.map(({ address, name }) => (
                  <li key={`${name}-${address}`}>
                    <span>{name}</span>
                    <code>http://{address}:{receiverInfo.port}/report</code>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="tone-orange">
                No private Ethernet address found. Connect the cable and configure
                an IPv4 address on the PC&apos;s Ethernet adapter.
              </p>
            )}
            <div className="receiver-token">
              <strong>Bearer token</strong>
              <code>{receiverInfo?.token ?? "Loading..."}</code>
            </div>
            <p className={`receiver-status tone-${connected ? "green" : "orange"}`}>
              {connected ? "Report received" : "Waiting for a report"}
            </p>
            <p className="receiver-help">
              Send an HTTP POST with Content-Type application/json and
              Authorization: Bearer &lt;token&gt;.
            </p>
            {receiverError && <p className="tone-red">{receiverError}</p>}
          </div>
        ) : (
          <p>
            The network receiver is available in the packaged Windows app. Run
            the installed app to receive reports from the Pi.
          </p>
        )}
      </dialog>
    </main>
  );
}

export default App;
