import React, { useState, useEffect, useRef, useCallback } from "react";
import { ICON_MAP } from "../../assets/iconManifest";

// ─── constants ────────────────────────────────────────────────────────────────
const GREEN  = "#00ff41";
const AMBER  = "#ffaa00";
const RED    = "#ff4141";
const DIM    = "#444";
const DIM2   = "#666";
const BG     = "#000";
const PANEL  = "#0a0a0a";
const BORDER = "#1a1a1a";
const BORDER2= "#222";

const DEFAULT_SECTIONS = [
  { id: "summary",   label: "INVESTIGATION SUMMARY",  enabled: true,  detail: false },
  { id: "daily",     label: "DAILY UPDATE",            enabled: true,  detail: false },
  { id: "assets",    label: "ASSET BREAKDOWN",         enabled: true,  detail: false, showTimeline: false, showBluf: false, showActors: false },
  { id: "network",   label: "NETWORK MAP",             enabled: true,  detail: false },
  { id: "bluf",      label: "BLUF NOTES",              enabled: true,  detail: false },
  { id: "timeline",  label: "ANALYST TIMELINE",        enabled: true,  detail: true  },
  { id: "verdicts",  label: "TECHNIQUE VERDICTS",      enabled: true,  detail: false },
];

const authHdr = () => ({ 'Content-Type': 'application/json' });

// ─── helpers ──────────────────────────────────────────────────────────────────
function fmt(n) { return (n ?? 0).toLocaleString(); }
function pct(a, b) { return b ? ((a / b) * 100).toFixed(1) + "%" : "0%"; }

function verdictColor(v) {
  if (!v) return DIM2;
  const u = v.toUpperCase();
  if (u === "MALICIOUS")     return RED;
  if (u === "NON_MALICIOUS" || u === "NON-MALICIOUS") return GREEN;
  if (u === "EVIDENCE FOUND") return AMBER;
  return DIM2;
}

function statusColor(s) {
  const u = (s || "").toUpperCase();
  if (u === "CLOSED")          return GREEN;
  if (u === "PENDING_REVIEW")  return AMBER;
  if (u === "IN_PROGRESS")     return "#4af";
  return DIM2;
}

// ─── sub-components ───────────────────────────────────────────────────────────

function MetricTile({ label, value, color }) {
  return (
    <div style={{
      background: PANEL, border: `1px solid ${BORDER2}`,
      padding: "14px 18px", minWidth: 110,
    }}>
      <div style={{ color: DIM2, fontFamily: "monospace", fontSize: 10, marginBottom: 6, letterSpacing: 2 }}>
        {label}
      </div>
      <div style={{ color: color || GREEN, fontFamily: "monospace", fontSize: 28, fontWeight: "bold" }}>
        {value}
      </div>
    </div>
  );
}

function SectionToggle({ section, onToggle, onToggleDetail, onToggleAssetOption, onDragStart, onDragOver, onDrop, isDragging }) {
  return (
    <div
      draggable
      onDragStart={onDragStart}
      onDragOver={onDragOver}
      onDrop={onDrop}
      style={{
        display: "flex", alignItems: "center", gap: 10,
        padding: "8px 10px",
        background: isDragging ? "#111" : "transparent",
        border: `1px solid ${isDragging ? GREEN : BORDER}`,
        cursor: "grab", marginBottom: 4,
        opacity: section.enabled ? 1 : 0.4,
        transition: "all 0.15s",
        flexWrap: "wrap",
      }}
    >
      <span style={{ color: DIM, fontSize: 12, userSelect: "none", cursor: "grab" }}>⠿</span>

      <div
        onClick={() => onToggle(section.id)}
        style={{
          width: 28, height: 14, background: section.enabled ? GREEN : "#1a1a1a",
          border: `1px solid ${section.enabled ? GREEN : DIM}`,
          cursor: "pointer", position: "relative", flexShrink: 0,
        }}
      >
        <div style={{
          position: "absolute", top: 2,
          left: section.enabled ? 14 : 2,
          width: 8, height: 8,
          background: section.enabled ? BG : DIM,
          transition: "left 0.15s",
        }} />
      </div>

      <span style={{ fontFamily: "monospace", fontSize: 11, color: section.enabled ? GREEN : DIM, flex: 1, letterSpacing: 1 }}>
        {section.label}
      </span>

      {["timeline", "verdicts", "daily"].includes(section.id) && section.enabled && (
        <div
          onClick={() => onToggleDetail(section.id)}
          style={{
            fontFamily: "monospace", fontSize: 9, padding: "2px 6px",
            border: `1px solid ${section.detail ? AMBER : DIM}`,
            color: section.detail ? AMBER : DIM, cursor: "pointer",
            letterSpacing: 1,
          }}
        >
          {section.detail ? "DETAIL ON" : "DETAIL OFF"}
        </div>
      )}

      {/* Asset section sub-toggles */}
      {section.id === "assets" && section.enabled && (
        <div style={{ display: "flex", gap: 4, width: "100%", paddingLeft: 48, marginTop: 4 }}>
          {[
            { key: "showTimeline", label: "+ TIMELINE" },
            { key: "showBluf",     label: "+ BLUF" },
            { key: "showActors",   label: "+ ACTORS" },
          ].map(({ key, label }) => (
            <div
              key={key}
              onClick={() => onToggleAssetOption(key)}
              style={{
                fontFamily: "monospace", fontSize: 9, padding: "2px 6px",
                border: `1px solid ${section[key] ? AMBER : DIM}`,
                color: section[key] ? AMBER : DIM, cursor: "pointer",
                letterSpacing: 1,
              }}
            >
              {label}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function SectionHeader({ label }) {
  return (
    <div style={{
      fontFamily: "monospace", fontSize: 11, color: GREEN,
      letterSpacing: 3, borderBottom: `1px solid ${GREEN}`,
      paddingBottom: 6, marginBottom: 16, marginTop: 28,
    }}>
      {label}
    </div>
  );
}

// ─── asset technique table ───────────────────────────────────────────────────
function AssetTechniqueTable({ techniques, timeline, showTimeline, showBluf, showActors, assetId }) {
  if (!techniques || techniques.length === 0) {
    return (
      <div style={{ fontFamily: "monospace", fontSize: 11, color: DIM2, padding: "10px 0" }}>
        No techniques in threat profile.
      </div>
    );
  }

  const assetNotes = (timeline || []).filter(n => String(n.asset_id) === String(assetId));
  const notesByTCode = {};
  for (const n of assetNotes) {
    if (!notesByTCode[n.t_code]) notesByTCode[n.t_code] = [];
    notesByTCode[n.t_code].push(n);
  }

  const showNotes = showTimeline || showBluf;

  return (
    <table style={{ width: "100%", borderCollapse: "collapse", marginTop: 10 }}>
      <thead>
        <tr>
          {["T-CODE", "TECHNIQUE", "DESCRIPTION", ...(showActors ? ["ACTORS"] : []), "VERDICT", "STATUS", "EVID."].map(h => (
            <th key={h} style={{
              fontFamily: "monospace", fontSize: 10, color: GREEN,
              textAlign: "left", padding: "6px 10px",
              borderBottom: `1px solid ${BORDER2}`, letterSpacing: 1,
              whiteSpace: "nowrap",
            }}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {techniques.map((t, i) => {
          const allNotes = notesByTCode[t.t_code] || [];
          const visibleNotes = allNotes.filter(n => {
            const isBluf = (n.note_type || "").toUpperCase() === "BLUF";
            return isBluf ? showBluf : showTimeline;
          });
          const rowBg = i % 2 ? "#0d0d0d" : "transparent";

          return (
            <React.Fragment key={t.t_code}>
              <tr style={{ background: rowBg }}>
                <td style={{ fontFamily: "monospace", fontSize: 11, color: GREEN, padding: "6px 10px", whiteSpace: "nowrap", fontWeight: "bold" }}>
                  {t.t_code}
                </td>
                <td style={{ fontFamily: "monospace", fontSize: 11, color: "#aaa", padding: "6px 10px", maxWidth: 180 }}>
                  {t.technique_name}
                </td>
                <td style={{ fontFamily: "monospace", fontSize: 10, color: DIM2, padding: "6px 10px", maxWidth: 320, lineHeight: 1.5 }}>
                  {t.technique_description
                    ? t.technique_description.length > 180
                      ? t.technique_description.slice(0, 180) + "\u2026"
                      : t.technique_description
                    : "\u2014"}
                </td>
                {showActors && (
                  <td style={{ fontFamily: "monospace", fontSize: 10, color: AMBER, padding: "6px 10px", maxWidth: 200, lineHeight: 1.6 }}>
                    {(t.associated_actors || "\u2014").split(", ").map((a, ai) => (
                      <div key={ai}>{a}</div>
                    ))}
                  </td>
                )}
                <td style={{ fontFamily: "monospace", fontSize: 11, color: verdictColor(t.verdict), padding: "6px 10px", fontWeight: "bold", whiteSpace: "nowrap" }}>
                  {t.verdict || "\u2014"}
                </td>
                <td style={{ fontFamily: "monospace", fontSize: 11, color: statusColor(t.technique_status), padding: "6px 10px", whiteSpace: "nowrap" }}>
                  {t.technique_status || "\u2014"}
                </td>
                <td style={{ fontFamily: "monospace", fontSize: 11, color: t.evidence_imported ? GREEN : DIM2, padding: "6px 10px", textAlign: "center" }}>
                  {t.evidence_imported ? "\u2713" : "\u2014"}
                </td>
              </tr>

              {showNotes && visibleNotes.map((n, ni) => {
                const isBluf = (n.note_type || "").toUpperCase() === "BLUF";
                return (
                  <tr key={`note-${ni}`} style={{ background: "#060606" }}>
                    <td colSpan={6} style={{
                      padding: "5px 10px 5px 32px",
                      borderLeft: `2px solid ${isBluf ? AMBER : BORDER2}`,
                    }}>
                      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                        <span style={{
                          fontFamily: "monospace", fontSize: 10,
                          color: isBluf ? AMBER : GREEN,
                          fontWeight: isBluf ? "bold" : "normal",
                        }}>
                          {isBluf ? "\u2605 BLUF" : "NOTE"}
                        </span>
                        <span style={{ fontFamily: "monospace", fontSize: 10, color: DIM2 }}>
                          [{(n.initials || n.author || "??").toUpperCase()}]
                        </span>
                        <span style={{ fontFamily: "monospace", fontSize: 10, color: DIM2 }}>
                          {new Date(n.created_at).toLocaleString()}
                        </span>
                      </div>
                      <div style={{
                        fontFamily: "monospace", fontSize: 11,
                        color: isBluf ? AMBER : "#ccc",
                        fontWeight: isBluf ? "bold" : "normal",
                        marginTop: 3, paddingLeft: 4,
                      }}>
                        {n.text}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </React.Fragment>
          );
        })}
      </tbody>
    </table>
  );
}

// ─── main component ───────────────────────────────────────────────────────────
export default function ReportsView() {
  const [cases, setCases]         = useState([]);
  const [selectedCase, setSelectedCase] = useState(null);
  const [reportData, setReportData]     = useState(null);
  const [loading, setLoading]           = useState(false);
  const [exporting, setExporting]       = useState(null);
  const [sections, setSections]         = useState(DEFAULT_SECTIONS);
  const [dragIdx, setDragIdx]           = useState(null);

  const now = new Date();
  const yesterday = new Date(now - 86400000);
  const toLocal = (d) => d.toISOString().slice(0, 16);
  const [rangeFrom, setRangeFrom] = useState(toLocal(yesterday));
  const [rangeTo,   setRangeTo]   = useState(toLocal(now));

  useEffect(() => {
    fetch(`${import.meta.env.VITE_API_URL}/api/mitre/cases`, { credentials: 'include', headers: authHdr() })
      .then(r => r.json())
      .then(d => setCases(Array.isArray(d) ? d : d.cases || []))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedCase) return;
    setLoading(true);
    setReportData(null);
    fetch(`${import.meta.env.VITE_API_URL}/api/reports/${encodeURIComponent(selectedCase)}`, { credentials: 'include', headers: authHdr() })
      .then(r => r.json())
      .then(d => { setReportData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [selectedCase]);

  // ── drag reorder ────────────────────────────────────────────
  const handleDragStart = (i) => setDragIdx(i);
  const handleDragOver  = (e) => e.preventDefault();
  const handleDrop      = (i) => {
    if (dragIdx === null || dragIdx === i) return;
    const next = [...sections];
    const [moved] = next.splice(dragIdx, 1);
    next.splice(i, 0, moved);
    setSections(next);
    setDragIdx(null);
  };

  const toggleSection       = (id) => setSections(s => s.map(x => x.id === id ? { ...x, enabled: !x.enabled } : x));
  const toggleDetail        = (id) => setSections(s => s.map(x => x.id === id ? { ...x, detail: !x.detail } : x));
  const toggleAssetOption   = (key) => setSections(s => s.map(x => x.id === "assets" ? { ...x, [key]: !x[key] } : x));

  // ── export ──────────────────────────────────────────────────
  const handleExport = async (format) => {
    if (!selectedCase || !reportData) return;
    setExporting(format);
    try {
      const body = {
        sections: sections.filter(s => s.enabled).map(s => ({ id: s.id, detail: s.detail })),
        range_from: rangeFrom,
        range_to: rangeTo,
      };
      const res = await fetch(
        `${import.meta.env.VITE_API_URL}/api/reports/${encodeURIComponent(selectedCase)}/export?format=${format}`,
        { method: "POST", credentials: 'include', headers: { ...authHdr(), "Content-Type": "application/json" }, body: JSON.stringify(body) }
      );
      if (!res.ok) throw new Error("Export failed");
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href     = url;
      a.download = `orca_report_${selectedCase.replace(/\s+/g, "_")}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error(e);
    } finally {
      setExporting(null);
    }
  };

  // ── daily delta ─────────────────────────────────────────────
  const getDailyData = useCallback(() => {
    if (!reportData) return null;
    const from = new Date(rangeFrom).getTime();
    const to   = new Date(rangeTo).getTime();

    const closedInRange = (reportData.techniques || []).filter(t => {
      if (!t.closed_at) return false;
      const ts = new Date(t.closed_at).getTime();
      return ts >= from && ts <= to;
    });

    const notesInRange = (reportData.timeline || []).filter(n => {
      const ts = new Date(n.created_at).getTime();
      return ts >= from && ts <= to;
    });

    const byAsset = {};
    for (const t of closedInRange) {
      const aid = t.asset_id || "unknown";
      if (!byAsset[aid]) byAsset[aid] = { hostname: t.hostname || aid, closed: 0, malicious: 0, non_malicious: 0 };
      byAsset[aid].closed++;
      if ((t.verdict || "").toUpperCase() === "MALICIOUS")     byAsset[aid].malicious++;
      if ((t.verdict || "").toUpperCase() === "NON-MALICIOUS") byAsset[aid].non_malicious++;
    }

    return { closedInRange, notesInRange, byAsset: Object.values(byAsset) };
  }, [reportData, rangeFrom, rangeTo]);

  // ─────────────────────────────────────────────────────────────
  const renderSection = (sec) => {
    if (!reportData) return null;
    const s = reportData.summary || {};

    switch (sec.id) {

      case "summary":
        return (
          <div key="summary">
            <SectionHeader label="INVESTIGATION SUMMARY" />
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 16 }}>
              <MetricTile label="TOTAL TECHNIQUES" value={fmt(s.total_techniques)} />
              <MetricTile label="CLOSED"           value={fmt(s.closed)} />
              <MetricTile label="WITH EVIDENCE"    value={fmt(s.with_evidence)} />
              <MetricTile label="NO ARTIFACTS"     value={fmt(s.no_artifacts)}  color={DIM2} />
              <MetricTile label="PENDING"          value={fmt(s.pending)}        color={AMBER} />
              <MetricTile label="COMPLETION"       value={pct(s.closed, s.total_techniques)} />
              <MetricTile label="MALICIOUS"        value={fmt(s.malicious)}      color={RED} />
              <MetricTile label="NON-MALICIOUS"    value={fmt(s.non_malicious)}  color={GREEN} />
              <MetricTile label="EVIDENCE FOUND"   value={fmt(s.evidence_found || 0)} color={"#aa44ff"} />
            </div>
          </div>
        );

      case "daily": {
        const dd = getDailyData();
        return (
          <div key="daily">
            <SectionHeader label="DAILY UPDATE" />
            <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 16, flexWrap: "wrap" }}>
              <span style={{ fontFamily: "monospace", fontSize: 11, color: DIM2 }}>FROM</span>
              <input type="datetime-local" value={rangeFrom} onChange={e => setRangeFrom(e.target.value)}
                style={{ background: PANEL, border: `1px solid ${BORDER2}`, color: GREEN, fontFamily: "monospace", fontSize: 11, padding: "4px 8px" }} />
              <span style={{ fontFamily: "monospace", fontSize: 11, color: DIM2 }}>TO</span>
              <input type="datetime-local" value={rangeTo} onChange={e => setRangeTo(e.target.value)}
                style={{ background: PANEL, border: `1px solid ${BORDER2}`, color: GREEN, fontFamily: "monospace", fontSize: 11, padding: "4px 8px" }} />
            </div>
            {dd && (
              <>
                <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
                  <MetricTile label="TECHNIQUES CLOSED" value={fmt(dd.closedInRange.length)} />
                  <MetricTile label="ANALYST ENTRIES"   value={fmt(dd.notesInRange.length)} color={AMBER} />
                  <MetricTile label="MALICIOUS FINDS"   value={fmt(dd.closedInRange.filter(t => (t.verdict||'').toUpperCase()==='MALICIOUS').length)} color={RED} />
                </div>
                {dd.byAsset.length > 0 && (
                  <table style={{ width: "100%", borderCollapse: "collapse", marginBottom: 16 }}>
                    <thead>
                      <tr>
                        {["ASSET","CLOSED","MALICIOUS","NON-MALICIOUS"].map(h => (
                          <th key={h} style={{ fontFamily: "monospace", fontSize: 10, color: GREEN, textAlign: "left", padding: "6px 10px", borderBottom: `1px solid ${BORDER2}`, letterSpacing: 1 }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {dd.byAsset.map((a, i) => (
                        <tr key={i} style={{ background: i % 2 ? "#0d0d0d" : "transparent" }}>
                          <td style={{ fontFamily: "monospace", fontSize: 11, color: "#aaa", padding: "5px 10px" }}>{a.hostname}</td>
                          <td style={{ fontFamily: "monospace", fontSize: 11, color: GREEN,   padding: "5px 10px" }}>{a.closed}</td>
                          <td style={{ fontFamily: "monospace", fontSize: 11, color: RED,     padding: "5px 10px" }}>{a.malicious}</td>
                          <td style={{ fontFamily: "monospace", fontSize: 11, color: GREEN,   padding: "5px 10px" }}>{a.non_malicious}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {sec.detail && dd.notesInRange.length > 0 && (
                  <div style={{ borderLeft: `2px solid ${BORDER2}`, paddingLeft: 12 }}>
                    {dd.notesInRange.map((n, i) => (
                      <div key={i} style={{ marginBottom: 12 }}>
                        <div style={{ fontFamily: "monospace", fontSize: 10, color: AMBER, marginBottom: 4 }}>
                          [{(n.initials || n.author || "??").toUpperCase()}] [{n.t_code || "CASE"}]  {new Date(n.created_at).toLocaleString()}
                        </div>
                        <div style={{ fontFamily: "monospace", fontSize: 11, color: "#ccc" }}>{n.text}</div>
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}
          </div>
        );
      }

      case "assets": {
        const perAsset = reportData.per_asset_techniques || {};
        const assetSec = sections.find(s => s.id === "assets") || sec;

        return (
          <div key="assets">
            <SectionHeader label="ASSET BREAKDOWN" />
            {(reportData.assets || []).map((asset) => {
              const techniques = perAsset[asset.id] || perAsset[String(asset.id)] || [];
              const closed     = techniques.filter(t => { const v = (t.verdict||'').toUpperCase(); return v === 'MALICIOUS' || v === 'NON-MALICIOUS'; }).length;
              const malicious  = techniques.filter(t => (t.verdict||'').toUpperCase() === 'MALICIOUS').length;
              const total      = techniques.length || s.total_techniques || 1;
              const pctDone    = total > 0 ? ((closed / total) * 100).toFixed(0) : 0;


              return (
                <div key={asset.id} style={{ marginBottom: 24, padding: 16, background: PANEL, border: `1px solid ${BORDER2}` }}>
                  {/* Asset header */}
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
                    <span style={{ fontFamily: "monospace", fontSize: 13, color: GREEN, fontWeight: "bold" }}>{asset.hostname}</span>
                    <span style={{ fontFamily: "monospace", fontSize: 10, color: DIM2 }}>
                      {asset.os}  ·  {asset.asset_type}  ·  {asset.analysis_mode}
                    </span>
                  </div>

                  {/* Progress bar */}
                  <div style={{ height: 4, background: "#111", marginBottom: 10 }}>
                    <div style={{ height: 4, width: `${pctDone}%`, background: malicious > 0 ? RED : GREEN, transition: "width 0.3s" }} />
                  </div>
                  <div style={{ display: "flex", gap: 20, marginBottom: 14 }}>
                    <span style={{ fontFamily: "monospace", fontSize: 11, color: "#aaa" }}>
                      CLOSED <span style={{ color: GREEN }}>{closed}</span> / {total}
                    </span>
                    <span style={{ fontFamily: "monospace", fontSize: 11, color: RED }}>{malicious} MALICIOUS</span>
                    <span style={{ fontFamily: "monospace", fontSize: 11, color: DIM2 }}>{pctDone}% COMPLETE</span>
                  </div>

                  {/* Technique table */}
                  <AssetTechniqueTable
                    techniques={techniques}
                    timeline={reportData.timeline}
                    showTimeline={assetSec.showTimeline}
                    showBluf={assetSec.showBluf}
                    showActors={assetSec.showActors}
                    assetId={asset.id}
                  />

                </div>
              );
            })}
          </div>
        );
      }

      case "network": {
        const mapData = reportData.map_data || {};
        const mapNodes = mapData.nodes || [];
        const mapLinks = mapData.links || [];
        const NW = 160, NH = 64, PAD = 60;
        const positioned = mapNodes.map((n, i) => ({
          ...n,
          px: n.x != null ? n.x : (50 + (i % 4) * (NW + 40)),
          py: n.y != null ? n.y : (50 + Math.floor(i / 4) * (NH + 60)),
        }));
        const xs = positioned.map(n => n.px), ys = positioned.map(n => n.py);
        const vbX = Math.min(...xs) - PAD;
        const vbY = Math.min(...ys) - PAD;
        const vbW = Math.max(...xs) - Math.min(...xs) + NW + PAD * 2;
        const vbH = Math.max(...ys) - Math.min(...ys) + NH + PAD * 2;
        const byId = {};
        positioned.forEach(n => { byId[n.hostname] = n; if (n.id) byId[n.id] = n; });
        const osCol = os => {
          const l = (os || "").toLowerCase();
          if (l.includes("windows")) return "#0078d4";
          if (l.includes("linux"))   return "#00ff41";
          if (l.includes("firmware"))return "#ff8800";
          return "#ffaa00";
        };
        const ICON = 32, ICON_X = 8, ICON_Y = 16, TEXT_X = 48;
        const iconFor = t => ICON_MAP[(t || "DEFAULT").toUpperCase()] || ICON_MAP.DEFAULT;
        return (
          <div key="network">
            <SectionHeader label="NETWORK MAP" />
            {mapNodes.length === 0 ? (
              <div style={{ background: PANEL, border: `1px solid ${BORDER2}`, padding: 20, fontFamily: "monospace", fontSize: 11, color: DIM2 }}>
                No network map data saved. Open the case and add nodes to the map — it auto-saves.
              </div>
            ) : (
              <div style={{ background: "#050505", border: `1px solid ${BORDER2}`, overflow: "hidden" }}>
                <svg viewBox={`${vbX} ${vbY} ${vbW} ${vbH}`} width="100%" style={{ display: "block" }}>
                  {mapLinks.map((lnk, i) => {
                    const src = byId[lnk.source] || byId[lnk.source_id];
                    const tgt = byId[lnk.target] || byId[lnk.target_id];
                    if (!src || !tgt) return null;
                    const x1 = src.px + NW/2, y1 = src.py + NH/2, x2 = tgt.px + NW/2, y2 = tgt.py + NH/2;
                    const dash = lnk.link_type === "VPN" ? "8,4" : lnk.link_type === "WIRELESS" ? "3,3" : undefined;
                    return (
                      <g key={i}>
                        <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="#333" strokeWidth={1.5} strokeDasharray={dash} />
                        <text x={(x1+x2)/2} y={(y1+y2)/2-4} fill="#555" fontSize={9} fontFamily="monospace" textAnchor="middle">{lnk.link_type||"WIRED"}</text>
                      </g>
                    );
                  })}
                  {positioned.map((n, i) => {
                    const col = osCol(n.os);
                    const name = (n.hostname || "?").substring(0, 18).toUpperCase();
                    return (
                      <g key={i}>
                        <rect x={n.px} y={n.py} width={NW} height={NH} fill="#0d0d0d" stroke={col} strokeWidth={1.5} rx={2} />
                        <image
                          href={iconFor(n.type)}
                          x={n.px+ICON_X} y={n.py+ICON_Y} width={ICON} height={ICON}
                          style={{ filter: "brightness(0) invert(65%) sepia(97%) saturate(2800%) hue-rotate(95deg)" }}
                        />
                        <text x={n.px+TEXT_X} y={n.py+18} fill={col} fontSize={11} fontFamily="Courier New" fontWeight="bold">{name}</text>
                        <text x={n.px+TEXT_X} y={n.py+34} fill="#666" fontSize={9} fontFamily="Courier New">{(n.ip||"—").substring(0,20)}</text>
                        <text x={n.px+TEXT_X} y={n.py+50} fill="#444" fontSize={8} fontFamily="Courier New">{(n.os||"UNKNOWN").substring(0,22).toUpperCase()}</text>
                      </g>
                    );
                  })}
                </svg>
              </div>
            )}
          </div>
        );
      }

      case "bluf":
        return (
          <div key="bluf">
            <SectionHeader label="BLUF NOTES" />
            {!(reportData.bluf_notes || []).length
              ? <div style={{ fontFamily: "monospace", fontSize: 11, color: DIM2 }}>No BLUF notes recorded.</div>
              : (reportData.bluf_notes || []).map((n, i) => (
                <div key={i} style={{ marginBottom: 14, borderLeft: `2px solid ${AMBER}`, paddingLeft: 12 }}>
                  <div style={{ fontFamily: "monospace", fontSize: 10, color: AMBER, marginBottom: 4 }}>
                    [{(n.author || "ANALYST").toUpperCase()}]  {new Date(n.created_at).toLocaleString()}
                  </div>
                  <div style={{ fontFamily: "monospace", fontSize: 12, color: "#ccc", lineHeight: 1.6 }}>{n.text}</div>
                </div>
              ))
            }
          </div>
        );

      case "timeline":
        return (
          <div key="timeline">
            <SectionHeader label="ANALYST TIMELINE" />
            {!(reportData.timeline || []).length
              ? <div style={{ fontFamily: "monospace", fontSize: 11, color: DIM2 }}>No timeline entries.</div>
              : (reportData.timeline || []).map((e, i) => (
                <div key={i} style={{ marginBottom: sec.detail ? 16 : 8, display: "flex", gap: 12, alignItems: sec.detail ? "flex-start" : "center" }}>
                  <span style={{ fontFamily: "monospace", fontSize: 10, color: DIM2, whiteSpace: "nowrap", minWidth: 130 }}>
                    {new Date(e.created_at).toLocaleString()}
                  </span>
                  <span style={{ fontFamily: "monospace", fontSize: 10, color: GREEN, minWidth: 80 }}>
                    [{(e.initials || "??").toUpperCase()}]
                  </span>
                  <span style={{ fontFamily: "monospace", fontSize: 10, color: AMBER, minWidth: 90 }}>
                    {e.t_code || "CASE"}
                  </span>
                  {sec.detail && (
                    <span style={{ fontFamily: "monospace", fontSize: 11, color: "#ccc" }}>{e.text}</span>
                  )}
                </div>
              ))
            }
          </div>
        );

      case "verdicts":
        return (
          <div key="verdicts">
            <SectionHeader label="TECHNIQUE VERDICTS" />
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  {["T-CODE","TECHNIQUE","VERDICT","STATUS","EVIDENCE"].map(h => (
                    <th key={h} style={{ fontFamily: "monospace", fontSize: 10, color: GREEN, textAlign: "left", padding: "6px 10px", borderBottom: `1px solid ${BORDER2}`, letterSpacing: 1 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(reportData.techniques || []).map((t, i) => (
                  <tr key={i} style={{ background: i % 2 ? "#0d0d0d" : "transparent" }}>
                    <td style={{ fontFamily: "monospace", fontSize: 11, color: GREEN,    padding: "5px 10px", whiteSpace: "nowrap" }}>{t.t_code}</td>
                    <td style={{ fontFamily: "monospace", fontSize: 11, color: "#aaa",   padding: "5px 10px" }}>{t.technique_name}</td>
                    <td style={{ fontFamily: "monospace", fontSize: 11, color: verdictColor(t.verdict), padding: "5px 10px", fontWeight: "bold" }}>{t.verdict || "—"}</td>
                    <td style={{ fontFamily: "monospace", fontSize: 11, color: statusColor(t.technique_status), padding: "5px 10px" }}>{t.technique_status || "—"}</td>
                    <td style={{ fontFamily: "monospace", fontSize: 11, color: t.evidence_imported ? GREEN : DIM2, padding: "5px 10px", textAlign: "center" }}>
                      {t.evidence_imported ? "✓" : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );

      default:
        return null;
    }
  };

  // ─────────────────────────────────────────────────────────────
  return (
    <div style={{ display: "flex", height: "100vh", background: BG, overflow: "hidden" }}>

      {/* ── LEFT: case list + builder ─────────────────────────── */}
      <div style={{
        width: 260, flexShrink: 0, borderRight: `1px solid ${BORDER}`,
        display: "flex", flexDirection: "column", overflow: "hidden",
      }}>

        <div style={{ padding: "16px 14px 12px", borderBottom: `1px solid ${BORDER}` }}>
          <div style={{ fontFamily: "monospace", fontSize: 10, color: DIM2, letterSpacing: 2, marginBottom: 8 }}>
            SELECT INVESTIGATION
          </div>
          <div style={{ maxHeight: 200, overflowY: "auto" }}>
            {cases.length === 0
              ? <div style={{ fontFamily: "monospace", fontSize: 11, color: DIM }}>No cases found.</div>
              : cases.map(c => {
                const name = typeof c === "string" ? c : c.case_name || c.name;
                return (
                  <div key={name}
                    onClick={() => setSelectedCase(name)}
                    style={{
                      fontFamily: "monospace", fontSize: 11, padding: "6px 8px",
                      cursor: "pointer", marginBottom: 2,
                      color: selectedCase === name ? BG : GREEN,
                      background: selectedCase === name ? GREEN : "transparent",
                      border: `1px solid ${selectedCase === name ? GREEN : BORDER}`,
                    }}
                  >
                    {name}
                  </div>
                );
              })
            }
          </div>
        </div>

        <div style={{ padding: "14px", borderBottom: `1px solid ${BORDER}`, flex: 1, overflowY: "auto" }}>
          <div style={{ fontFamily: "monospace", fontSize: 10, color: DIM2, letterSpacing: 2, marginBottom: 10 }}>
            REPORT BUILDER
          </div>
          <div style={{ fontFamily: "monospace", fontSize: 9, color: DIM, marginBottom: 10, lineHeight: 1.6 }}>
            DRAG TO REORDER · TOGGLE SECTIONS
          </div>
          {sections.map((sec, i) => (
            <SectionToggle
              key={sec.id}
              section={sec}
              onToggle={toggleSection}
              onToggleDetail={toggleDetail}
              onToggleAssetOption={toggleAssetOption}
              onDragStart={() => handleDragStart(i)}
              onDragOver={handleDragOver}
              onDrop={() => handleDrop(i)}
              isDragging={dragIdx === i}
            />
          ))}
        </div>

        <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 8 }}>
          {[["docx", "EXPORT WORD (.docx)"], ["pdf", "EXPORT PDF (.pdf)"]].map(([fmt, label]) => (
            <button key={fmt} onClick={() => handleExport(fmt)}
              disabled={!selectedCase || !reportData || !!exporting}
              style={{
                fontFamily: "monospace", fontSize: 11, padding: "9px 0",
                background: "transparent",
                border: `1px solid ${!selectedCase || !reportData ? DIM : GREEN}`,
                color: !selectedCase || !reportData ? DIM : GREEN,
                cursor: !selectedCase || !reportData ? "not-allowed" : "pointer",
                letterSpacing: 1,
              }}
            >
              {exporting === fmt ? "GENERATING..." : label}
            </button>
          ))}
        </div>
      </div>

      {/* ── RIGHT: report preview ─────────────────────────────── */}
      <div style={{ flex: 1, overflowY: "auto", padding: "24px 32px" }}>

        {!selectedCase && (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: DIM, fontFamily: "monospace", fontSize: 12 }}>
            SELECT AN INVESTIGATION TO GENERATE REPORT
          </div>
        )}

        {selectedCase && loading && (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: DIM2, fontFamily: "monospace", fontSize: 11 }}>
            LOADING...
          </div>
        )}

        {selectedCase && !loading && reportData && (
          <>
            <div style={{ marginBottom: 24, borderBottom: `1px solid ${BORDER2}`, paddingBottom: 16 }}>
              <div style={{ fontFamily: "monospace", fontSize: 20, color: GREEN, fontWeight: "bold", marginBottom: 4 }}>
                {selectedCase.toUpperCase()}
              </div>
              <div style={{ fontFamily: "monospace", fontSize: 11, color: DIM2 }}>
                {reportData.focus_country
                  ? <>FOCUS: <span style={{ color: GREEN }}>{reportData.focus_country.toUpperCase()}</span></>
                  : null}
                {(() => {
                  const groups = [...new Set((reportData.techniques || [])
                    .flatMap(t => (t.associated_actors || "").split(", ").filter(Boolean)))].sort();
                  if (!groups.length) return null;
                  return (
                    <span>
                      {reportData.focus_country ? "  ·  " : ""}
                      THREAT GROUPS: <span style={{ color: AMBER }}>{groups.join("  ·  ")}</span>
                    </span>
                  );
                })()}
                {"  ·  "}GENERATED: {new Date(reportData.generated_at || Date.now()).toLocaleString()}
              </div>
            </div>

            {sections.filter(s => s.enabled).map(sec => renderSection(sec))}
          </>
        )}
      </div>
    </div>
  );
}
