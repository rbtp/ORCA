// VelociraptorModal.jsx
// Drawer overlay with embedded Velociraptor GUI via reverse proxy iframe

import { useState, useEffect, useRef, useCallback } from "react";

const POLL_INTERVAL_MS = 3000;

export default function VelociraptorModal({ isOpen, onClose }) {
  const [status, setStatus] = useState(null); // { running, pid, port, config_exists, log }
  const [loading, setLoading] = useState(false);
  const startInflight = useRef(false);
  const pollRef = useRef(null);

  // ── Status polling ──────────────────────────────────────────────────────
  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/velociraptor/status");
      const data = await res.json();
      setStatus(data);
    } catch {
      // silently fail — backend may be restarting
    }
  }, []);

  useEffect(() => {
    if (!isOpen) return;
    fetchStatus();
    pollRef.current = setInterval(fetchStatus, POLL_INTERVAL_MS);
    return () => clearInterval(pollRef.current);
  }, [isOpen, fetchStatus]);

  // ── Actions ─────────────────────────────────────────────────────────────
  const handleStart = async () => {
    if (startInflight.current) return;
    startInflight.current = true;
    setLoading(true);
    try {
      const res = await fetch("/api/velociraptor/start", { method: "POST" });
      const data = await res.json();
      setStatus(data);
      // Give Velociraptor time to bind before iframe loads
      setTimeout(fetchStatus, 8000);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
      startInflight.current = false;
    }
  };

  const handleStop = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/velociraptor/stop", { method: "POST" });
      const data = await res.json();
      setStatus(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  const running = status?.running ?? false;

  return (
    <>
      {/* Backdrop */}
      <div
        className="velo-backdrop"
        onClick={onClose}
        style={{
          position: "fixed", inset: 0,
          background: "rgba(0,0,0,0.55)",
          zIndex: 1000,
        }}
      />

      {/* Drawer */}
      <div
        style={{
          position: "fixed",
          top: 0, right: 0, bottom: 0,
          width: "min(1200px, 92vw)",
          background: "var(--color-bg-secondary, #1a1d23)",
          borderLeft: "1px solid var(--color-border, #2e3340)",
          zIndex: 1001,
          display: "flex",
          flexDirection: "column",
          boxShadow: "-8px 0 32px rgba(0,0,0,0.4)",
        }}
      >
        {/* Header */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            padding: "12px 16px",
            borderBottom: "1px solid var(--color-border, #2e3340)",
            background: "var(--color-bg-primary, #13151a)",
            flexShrink: 0,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {/* Status dot */}
            <span
              style={{
                width: 9, height: 9,
                borderRadius: "50%",
                background: running ? "#22c55e" : "#ef4444",
                boxShadow: running ? "0 0 6px #22c55e" : "none",
                display: "inline-block",
                transition: "background 0.3s",
              }}
            />
            <span style={{
              fontFamily: "var(--font-mono, monospace)",
              fontSize: 13,
              fontWeight: 600,
              color: "var(--color-text-primary, #e2e8f0)",
              letterSpacing: "0.05em",
            }}>
              VELOCIRAPTOR
            </span>
            {running && status?.pid && (
              <span style={{
                fontSize: 11,
                color: "var(--color-text-muted, #64748b)",
                fontFamily: "var(--font-mono, monospace)",
              }}>
                PID {status.pid}
              </span>
            )}
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {/* Start / Stop */}
            <button
              onClick={running ? handleStop : handleStart}
              disabled={loading || status === null}
              style={{
                padding: "5px 14px",
                fontSize: 12,
                fontWeight: 600,
                borderRadius: 4,
                border: "none",
                cursor: loading ? "wait" : "pointer",
                background: running ? "#ef444420" : "#22c55e20",
                color: running ? "#ef4444" : "#22c55e",
                transition: "all 0.2s",
                letterSpacing: "0.04em",
              }}
            >
              {loading ? "…" : running ? "STOP" : "START"}
            </button>

            {/* Close */}
            <button
              onClick={onClose}
              style={{
                background: "none", border: "none",
                color: "var(--color-text-muted, #64748b)",
                fontSize: 18, cursor: "pointer", lineHeight: 1,
                padding: "2px 6px",
              }}
            >
              ×
            </button>
          </div>
        </div>

        {/* Body */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 20, color: "var(--color-text-muted, #64748b)" }}>
          {!running ? (
            <>
              <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M5.636 18.364a9 9 0 1 0 12.728-12.728M12 8v4m0 4h.01" strokeLinecap="round"/>
              </svg>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 14, fontWeight: 600, color: "var(--color-text-primary, #e2e8f0)", marginBottom: 6 }}>
                  Velociraptor is not running
                </div>
                <div style={{ fontSize: 12 }}>
                  {status?.config_exists === false
                    ? "A new config will be auto-generated on first start."
                    : "Click START to launch the GUI."}
                </div>
              </div>
              {status?.log?.length > 0 && <LogPanel log={status.log} />}
            </>
          ) : (
            <>
              <div style={{ textAlign: "center" }}>
                <div style={{ fontSize: 14, fontWeight: 600, color: "#22c55e", marginBottom: 8 }}>
                  ● VELOCIRAPTOR RUNNING
                </div>
                <div style={{ fontSize: 11, color: "var(--color-text-muted, #64748b)", marginBottom: 24, fontFamily: "monospace" }}>
                  PID {status?.pid} · PORT {status?.port}
                </div>
                <a
                  href={`https://${window.location.hostname}:${status?.port || 8889}/app/index.html`}
                  target="_blank"
                  rel="noreferrer"
                  style={{
                    display: "inline-block",
                    padding: "10px 28px",
                    background: "rgba(0,255,65,0.08)",
                    border: "1px solid rgba(0,255,65,0.3)",
                    color: "#00ff41",
                    fontSize: 12,
                    fontWeight: 700,
                    letterSpacing: "0.08em",
                    textDecoration: "none",
                    fontFamily: "monospace",
                    cursor: "pointer",
                  }}
                >
                  OPEN VELOCIRAPTOR ↗
                </a>
              </div>
              {status?.log?.length > 0 && <LogPanel log={status.log} />}
            </>
          )}
        </div>
      </div>
    </>
  );
}

// ── Sub-components ──────────────────────────────────────────────────────────

function LogPanel({ log }) {
  return (
    <div style={{
      width: "min(560px, 90%)",
      background: "var(--color-bg-primary, #13151a)",
      border: "1px solid var(--color-border, #2e3340)",
      borderRadius: 6,
      padding: "10px 12px",
      maxHeight: 140,
      overflowY: "auto",
      fontFamily: "var(--font-mono, monospace)",
      fontSize: 11,
      color: "var(--color-text-muted, #64748b)",
      lineHeight: 1.6,
    }}>
      {log.map((line, i) => <div key={i}>{line}</div>)}
    </div>
  );
}

function Spinner() {
  return (
    <div style={{
      width: 32, height: 32,
      border: "3px solid var(--color-border, #2e3340)",
      borderTopColor: "#22c55e",
      borderRadius: "50%",
      animation: "velo-spin 0.8s linear infinite",
    }}>
      <style>{`@keyframes velo-spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
