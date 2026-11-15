import { useEffect, useRef, useState } from "react";
import mockReport from "./data/mockReport.json";
import "./App.css";

const normalize = (value) =>
  typeof value === "string" ? value.trim().toUpperCase().replace(/[\s-]+/g, "_") : "";

function isBrickOnline(system = {}) {
  const connection = normalize(
    system.connection_status ?? system.application_connection,
  );
  const piStatus = normalize(system.raspberry_pi_status);
  const backend = normalize(system.backend_status);
  const connectionIsOnline = connection
    ? ["CONNECTED", "ONLINE", "RUNNING"].includes(connection)
    : piStatus
      ? ["ONLINE", "RUNNING", "CONNECTED"].includes(piStatus)
      : ["RUNNING", "ONLINE", "CONNECTED"].includes(backend);
  const backendIsRunning =
    !backend || ["RUNNING", "ONLINE", "CONNECTED"].includes(backend);

  return connectionIsOnline && backendIsRunning;
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

function getDeviceTrust(device) {
  const trusted = device?.trusted ?? device?.trusted_device;
  if (typeof trusted === "boolean") {
    return trusted ? "trusted" : "untrusted";
  }

  const status = normalize(device?.trust_status ?? trusted);
  if (["TRUSTED", "SAFE"].includes(status)) return "trusted";
  if (["UNTRUSTED", "UNSAFE"].includes(status)) return "untrusted";
  return "unknown";
}

function getAction(response = {}, threatDetected) {
  const action = normalize(response.action_taken);
  const access = normalize(
    response.device_access ?? response.device_access_status,
  );
  const blocked =
    action === "BLOCKED" ||
    ["BLOCKED", "RESTRICTED"].includes(access);
  const unblocked =
    action === "UNBLOCKED" ||
    access === "UNBLOCKED" ||
    (threatDetected && access === "NOT_BLOCKED");

  if (unblocked) return { label: "Unblocked", tone: "red" };
  if (blocked) {
    return threatDetected
      ? { label: "Blocked", tone: "green" }
      : { label: "Not needed", tone: "green" };
  }
  if (!threatDetected || ["", "NONE", "NO_ACTION", "NOT_NEEDED"].includes(action)) {
    return { label: "Not needed", tone: threatDetected ? "red" : "green" };
  }

  return { label: response.action_taken, tone: "red" };
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

function isNetworkActive(network = {}) {
  const active =
    network.active ?? network.monitoring_enabled ?? network.dns_filtering_enabled;
  if (typeof active === "boolean") return active;

  const status = normalize(
    network.dns_filtering ?? network.status ?? network.network_status,
  );
  return !["INACTIVE", "DISABLED", "OFFLINE", "FALSE"].includes(status);
}

function App() {
  const desktopBridge = window.brickDesktop;
  const [report, setReport] = useState(desktopBridge ? null : mockReport);
  const [connected, setConnected] = useState(
    () => !desktopBridge && isBrickOnline(mockReport.system),
  );
  const [showReport, setShowReport] = useState(false);
  const [showConnection, setShowConnection] = useState(false);
  const [receiverInfo, setReceiverInfo] = useState(null);
  const [receiverError, setReceiverError] = useState("");
  const reportDialogRef = useRef(null);
  const connectionDialogRef = useRef(null);

  useEffect(() => {
    if (!desktopBridge) return undefined;

    let active = true;
    const unsubscribe = desktopBridge.onReport((incomingReport) => {
      setReport(incomingReport);
      setConnected(isBrickOnline(incomingReport.system));
      setReceiverError("");
    });

    desktopBridge
      .getReceiverInfo()
      .then((info) => {
        if (!active) return;
        setReceiverInfo(info);
        if (info.latestReport) {
          setReport(info.latestReport);
          setConnected(isBrickOnline(info.latestReport.system));
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

  const detection = report?.detection ?? {};
  const network = report?.network_security ?? {};
  const response = report?.response ?? {};
  const risk = report?.risk_assessment ?? {};
  const device = report?.device;
  const threatKnown = typeof detection.threat_detected === "boolean";
  const threatDetected = detection.threat_detected === true;
  const deviceConnected = isDeviceConnected(device);
  const deviceTrust = getDeviceTrust(device);

  const confidence = Number(
    detection.confidence ?? detection.detection_confidence,
  );
  const confidencePercent = Number.isFinite(confidence)
    ? confidence <= 1
      ? confidence * 100
      : confidence
    : null;
  const confidenceTone =
    confidencePercent === null
      ? "orange"
      : confidencePercent >= 70
        ? "green"
        : confidencePercent >= 40
          ? "orange"
          : "red";
  const confidenceIsInconclusive =
    confidencePercent !== null &&
    confidencePercent >= 40 &&
    confidencePercent < 70;

  const riskScore = Number(risk.score ?? risk.risk_score);
  const riskTone = Number.isFinite(riskScore)
    ? riskScore <= 40
      ? "green"
      : riskScore <= 60
        ? "orange"
        : "red"
    : "orange";
  const action = getAction(response, threatDetected);
  const networkState = getNetworkState(network);
  const networkActive = isNetworkActive(network);
  const faceState = !threatKnown ? "inconclusive" : threatDetected ? "threat" : "safe";
  const faceMessage = !threatKnown
    ? "Inconclusive"
    : threatDetected
      ? "Threat Detected!"
      : "No Threat Detected";
  const type = detection.category ?? detection.threat_category ?? "Unknown";
  const typeTone = /(^|[^a-z0-9])(malware|trojan)([^a-z0-9]|$)/i.test(type)
    ? "red"
    : "green";
  const terminalMessage =
    report?.summary?.message?.trim() ||
    report?.summary?.final_message?.trim() ||
    report?.final_message?.trim() ||
    report?.message?.trim() ||
    "Nothing to Report";
  const blockedRequests = Number(network.blocked_requests);

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
          {deviceConnected ? (
            <>
              <p>{device?.device_name ?? "Unknown"}</p>
              <p>{device?.manufacturer ?? device?.device_type ?? "Unknown"}</p>
              <p>{device?.vendor_id ?? device?.device_identifier ?? "Unknown"}</p>
              <p>{device?.product_id ?? "Unknown"}</p>
              <p className={`tone-${deviceTrust}`}>
                {deviceTrust === "trusted"
                  ? "Trusted"
                  : deviceTrust === "untrusted"
                    ? "Untrusted"
                    : "Unknown"}
              </p>
            </>
          ) : (
            <p className="tone-red">No connection</p>
          )}
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
                {threatDetected ? (
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
                  : deviceTrust === "trusted"
                    ? "Trusted"
                    : deviceTrust === "untrusted"
                      ? "Untrusted"
                      : "Check"}
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
            Timestamp - “{report?.metadata?.timestamp ?? "Unknown"}”
          </span>
          <span>Final Message - “{terminalMessage}”</span>
          <span className="terminal-prompt">Click to view report</span>
        </button>
      </section>

      <section className="side-column" aria-label="Security metrics">
        <article
          className={`readout action-card confidence-card tone-${confidenceTone}`}
        >
          <h2>Confidence</h2>
          <p className={`tone-${confidenceTone}`}>
            {confidencePercent === null ? "Unknown" : `${confidencePercent.toFixed(1)}%`}
          </p>
          {confidenceIsInconclusive && (
            <span className="metric-note tone-orange">Inconclusive</span>
          )}
        </article>

        <article className={`readout type-card risk-card tone-${riskTone}`}>
          <h2>Risk score</h2>
          <p className={`tone-${riskTone}`}>
            {Number.isFinite(riskScore) ? `${String(riskScore).padStart(2, "0")}/100` : "Unknown"}
          </p>
        </article>

        <article
          className={`readout network-card tone-${networkActive ? "green" : "red"}`}
        >
          <h2>Network</h2>
          <p className={`network-status tone-${networkActive ? "green" : "red"}`}>
            {networkActive ? "Active" : "Inactive"}
          </p>
          <p>
            {Number.isFinite(blockedRequests) ? blockedRequests : 0} blocked requests
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
