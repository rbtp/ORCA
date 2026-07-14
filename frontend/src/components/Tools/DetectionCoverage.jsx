import React, { useState, useEffect, useMemo } from 'react';

const API_URL = `${import.meta.env.VITE_API_URL}/api/coverage`;

const getAuthHeaders = () => ({
  'Authorization': `Bearer ${localStorage.getItem('orca_token')}`,
  'Content-Type': 'application/json',
});

// ── helpers ───────────────────────────────────────────────────────────────────

const tcodeColor = (t) => {
  if (t.has_vql) return '#00ff41';   // covered
  if (t.has_yaml) return '#ffaa00';  // partial
  return '#ff4444';                  // none
};

const pctColor = (pct) => {
  if (pct >= 70) return '#00ff41';
  if (pct >= 35) return '#ffaa00';
  return '#ff4444';
};

const fmtDate = (iso) => {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleDateString(); } catch { return '—'; }
};

// ── main component ─────────────────────────────────────────────────────────────

export default function DetectionCoverage() {
  const [data, setData]         = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [expanded, setExpanded] = useState(new Set());
  const [search, setSearch]     = useState('');
  const [sortDir, setSortDir]   = useState('desc'); // 'desc' | 'asc'
  const [tcSearch, setTcSearch] = useState('');     // per-entry T-code filter (shared by all expanded)

  useEffect(() => {
    fetch(API_URL, { headers: getAuthHeaders() })
      .then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(d => setData(Array.isArray(d) ? d : []))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const countries = useMemo(() => data.filter(d => d.type === 'country'), [data]);
  const profiles  = useMemo(() => data.filter(d => d.type === 'profile'), [data]);

  const filterAndSort = (list) => {
    const q = search.trim().toLowerCase();
    const filtered = q
      ? list.filter(e =>
          e.name.toLowerCase().includes(q) ||
          e.tcodes.some(t => t.t_code.toLowerCase().includes(q) || t.name.toLowerCase().includes(q))
        )
      : list;
    return [...filtered].sort((a, b) =>
      sortDir === 'desc' ? b.coverage_pct - a.coverage_pct : a.coverage_pct - b.coverage_pct
    );
  };

  const sortedCountries = useMemo(() => filterAndSort(countries), [countries, search, sortDir]);
  const sortedProfiles  = useMemo(() => filterAndSort(profiles),  [profiles, search, sortDir]);

  const toggleExpand = (name) => setExpanded(prev => {
    const next = new Set(prev);
    next.has(name) ? next.delete(name) : next.add(name);
    return next;
  });

  // Global summary stats
  const totalCountries = countries.length;
  const avgPct = totalCountries > 0
    ? Math.round(countries.reduce((s, c) => s + c.coverage_pct, 0) / totalCountries)
    : 0;
  const totalTcodes = countries.reduce((s, c) => s + c.total, 0);
  const totalCovered = countries.reduce((s, c) => s + c.covered, 0);

  if (loading) return <div style={loadStyle}>LOADING_COVERAGE_MATRIX...</div>;
  if (error)   return <div style={errStyle}>COVERAGE_FETCH_ERROR: {error}</div>;

  return (
    <div style={{ padding: '40px', background: '#000', minHeight: '100vh', color: '#fff', fontFamily: 'monospace' }}>

      {/* Header */}
      <div style={{ marginBottom: '48px' }}>
        <h2 style={{ color: '#ffaa00', letterSpacing: '8px', fontSize: '24px', margin: 0, fontWeight: 900 }}>
          DETECTION_COVERAGE
        </h2>
        <div style={{ color: '#222', fontSize: '10px', letterSpacing: '2px', marginTop: '8px' }}>
          VQL/YAML COVERAGE vs COUNTRY T-CODE ATTRIBUTION // SOURCE: ref_artifact_library
        </div>

        {/* Summary tiles */}
        <div style={{ display: 'flex', gap: '24px', marginTop: '32px' }}>
          {[
            ['COUNTRIES', totalCountries, '#ffaa00'],
            ['UNIQUE_TCODES', new Set(countries.flatMap(c => c.tcodes.map(t => t.t_code))).size, '#aaa'],
            ['COVERED_TCODES', totalCovered, '#00ff41'],
            ['AVG_COVERAGE', `${avgPct}%`, pctColor(avgPct)],
            ['CUSTOM_PROFILES', profiles.length, '#00b8ff'],
          ].map(([lbl, val, col]) => (
            <div key={lbl} style={{ background: '#050505', border: '1px solid #111', padding: '20px 28px', minWidth: '120px' }}>
              <div style={{ color: '#333', fontSize: '9px', letterSpacing: '2px', marginBottom: '8px' }}>{lbl}</div>
              <div style={{ color: col, fontSize: '22px', fontWeight: 900 }}>{val}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Controls */}
      <div style={{ display: 'flex', gap: '16px', marginBottom: '32px', alignItems: 'center' }}>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="FILTER_BY_COUNTRY_OR_TCODE..."
          style={inputStyle}
        />
        <button
          onClick={() => setSortDir(d => d === 'desc' ? 'asc' : 'desc')}
          style={sortBtnStyle}
        >
          SORT_PCT {sortDir === 'desc' ? '▼' : '▲'}
        </button>
        <div style={{ color: '#222', fontSize: '10px', whiteSpace: 'nowrap' }}>
          {sortedCountries.length + sortedProfiles.length} ENTRIES
        </div>
      </div>

      {/* T-code search (shown when anything is expanded) */}
      {expanded.size > 0 && (
        <div style={{ marginBottom: '16px' }}>
          <input
            value={tcSearch}
            onChange={e => setTcSearch(e.target.value)}
            placeholder="SEARCH_WITHIN_EXPANDED_TCODE_LISTS..."
            style={{ ...inputStyle, borderColor: '#1a1a1a', width: '360px' }}
          />
        </div>
      )}

      {/* Legend */}
      <div style={{ display: 'flex', gap: '20px', marginBottom: '24px' }}>
        {[['VQL + YAML', '#00ff41'], ['YAML_ONLY', '#ffaa00'], ['UNCOVERED', '#ff4444']].map(([lbl, col]) => (
          <div key={lbl} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '10px', color: '#444' }}>
            <div style={{ width: '10px', height: '10px', background: col }} />
            {lbl}
          </div>
        ))}
      </div>

      {/* Countries section */}
      {sortedCountries.length > 0 && (
        <div style={{ marginBottom: '48px' }}>
          <div style={{ color: '#333', fontSize: '10px', letterSpacing: '3px', marginBottom: '16px', borderBottom: '1px solid #0a0a0a', paddingBottom: '8px' }}>
            COUNTRIES ({sortedCountries.length})
          </div>
          {sortedCountries.map(entry => (
            <CoverageRow
              key={entry.name}
              entry={entry}
              isExpanded={expanded.has(entry.name)}
              onToggle={() => toggleExpand(entry.name)}
              tcSearch={tcSearch}
            />
          ))}
        </div>
      )}

      {/* Profiles section */}
      {sortedProfiles.length > 0 && (
        <div>
          <div style={{ color: '#0a2a3a', fontSize: '10px', letterSpacing: '3px', marginBottom: '16px', borderBottom: '1px solid #0a0a0a', paddingBottom: '8px' }}>
            CUSTOM_PROFILES ({sortedProfiles.length})
          </div>
          {sortedProfiles.map(entry => (
            <CoverageRow
              key={entry.name}
              entry={entry}
              isExpanded={expanded.has(entry.name)}
              onToggle={() => toggleExpand(entry.name)}
              tcSearch={tcSearch}
              isProfile
            />
          ))}
        </div>
      )}

      {sortedCountries.length === 0 && sortedProfiles.length === 0 && (
        <div style={{ color: '#111', textAlign: 'center', marginTop: '80px', fontSize: '18px', letterSpacing: '8px' }}>
          NO_COVERAGE_DATA
        </div>
      )}
    </div>
  );
}

// ── CoverageRow sub-component ──────────────────────────────────────────────────

function CoverageRow({ entry, isExpanded, onToggle, tcSearch, isProfile = false }) {
  const accent = isProfile ? '#00b8ff' : '#ffaa00';
  const borderAccent = isProfile ? '#0a1a2a' : '#1a1200';

  const filteredTcodes = useMemo(() => {
    if (!tcSearch.trim()) return entry.tcodes;
    const q = tcSearch.toLowerCase();
    return entry.tcodes.filter(t =>
      t.t_code.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)
    );
  }, [entry.tcodes, tcSearch]);

  const pct = entry.coverage_pct;
  const col = pctColor(pct);

  // Mini coverage bar breakdown
  const covPct  = entry.total ? (entry.covered  / entry.total) * 100 : 0;
  const partPct = entry.total ? (entry.partial   / entry.total) * 100 : 0;
  const nonePct = entry.total ? ((entry.total - entry.covered - entry.partial) / entry.total) * 100 : 0;

  return (
    <div style={{ marginBottom: '4px' }}>
      {/* Row header */}
      <div
        onClick={onToggle}
        style={{
          display: 'grid',
          gridTemplateColumns: '240px 80px 1fr 120px 24px',
          alignItems: 'center',
          gap: '16px',
          padding: '14px 20px',
          background: isExpanded ? '#050505' : '#030303',
          border: `1px solid ${isExpanded ? borderAccent : '#0a0a0a'}`,
          cursor: 'pointer',
          transition: 'all 0.15s',
        }}
      >
        <div>
          {isProfile && <span style={{ color: '#00b8ff', fontSize: '8px', marginRight: '6px', letterSpacing: '1px' }}>⬡ PROFILE</span>}
          <span style={{ color: isExpanded ? accent : '#555', fontSize: '12px', fontWeight: isExpanded ? 'bold' : 'normal' }}>
            {entry.name}
          </span>
        </div>

        <div style={{ color: col, fontSize: '14px', fontWeight: 900, textAlign: 'right' }}>
          {pct}%
        </div>

        {/* Stacked bar */}
        <div style={{ height: '6px', display: 'flex', background: '#111', overflow: 'hidden' }}>
          <div style={{ width: `${covPct}%`,  background: '#00ff41', transition: 'width 0.4s' }} />
          <div style={{ width: `${partPct}%`, background: '#ffaa00', transition: 'width 0.4s' }} />
          <div style={{ width: `${nonePct}%`, background: '#1a0000', transition: 'width 0.4s' }} />
        </div>

        <div style={{ color: '#333', fontSize: '9px', textAlign: 'right', letterSpacing: '1px' }}>
          {entry.covered}/{entry.total} VQL &nbsp;
          <span style={{ color: '#1a1200' }}>{entry.partial} YAML</span>
        </div>

        <div style={{ color: '#333', fontSize: '11px', textAlign: 'center' }}>
          {isExpanded ? '▲' : '▼'}
        </div>
      </div>

      {/* Expanded T-code table */}
      {isExpanded && (
        <div style={{ border: `1px solid ${borderAccent}`, borderTop: 'none', background: '#020202', padding: '0' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '10px' }}>
            <thead>
              <tr style={{ color: '#333', borderBottom: '1px solid #0a0a0a' }}>
                <th style={thStyle}>T-CODE</th>
                <th style={thStyle}>TECHNIQUE_NAME</th>
                <th style={{ ...thStyle, textAlign: 'center' }}>VQL</th>
                <th style={{ ...thStyle, textAlign: 'center' }}>YAML</th>
                <th style={{ ...thStyle, textAlign: 'right' }}>LAST_UPDATED</th>
              </tr>
            </thead>
            <tbody>
              {filteredTcodes.length === 0 && (
                <tr>
                  <td colSpan={5} style={{ padding: '20px', color: '#222', textAlign: 'center', fontSize: '10px' }}>
                    NO_MATCHING_TCODES
                  </td>
                </tr>
              )}
              {filteredTcodes.map(t => (
                <tr key={t.t_code} style={{ borderBottom: '1px solid #080808' }}>
                  <td style={{ ...tdStyle, color: tcodeColor(t), fontWeight: 'bold' }}>{t.t_code}</td>
                  <td style={{ ...tdStyle, color: '#444' }}>{t.name || '—'}</td>
                  <td style={{ ...tdStyle, textAlign: 'center' }}>
                    {t.has_vql
                      ? <span style={{ color: '#00ff41', fontSize: '12px' }}>✓</span>
                      : <span style={{ color: '#222', fontSize: '11px' }}>✗</span>}
                  </td>
                  <td style={{ ...tdStyle, textAlign: 'center' }}>
                    {t.has_yaml
                      ? <span style={{ color: '#ffaa00', fontSize: '12px' }}>✓</span>
                      : <span style={{ color: '#222', fontSize: '11px' }}>✗</span>}
                  </td>
                  <td style={{ ...tdStyle, textAlign: 'right', color: '#1a1a1a' }}>{fmtDate(t.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ padding: '8px 16px', color: '#111', fontSize: '9px', borderTop: '1px solid #0a0a0a' }}>
            SHOWING {filteredTcodes.length} OF {entry.tcodes.length} TECHNIQUES
          </div>
        </div>
      )}
    </div>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────
const inputStyle  = { flex: 1, background: '#050505', border: '1px solid #1a1a1a', color: '#eee', padding: '12px 16px', fontSize: '11px', outline: 'none', fontFamily: 'monospace', boxSizing: 'border-box' };
const sortBtnStyle = { background: 'none', border: '1px solid #1a1a1a', color: '#444', padding: '12px 20px', cursor: 'pointer', fontFamily: 'monospace', fontSize: '10px', whiteSpace: 'nowrap' };
const thStyle     = { padding: '10px 16px', fontWeight: 'normal', textAlign: 'left', letterSpacing: '1px' };
const tdStyle     = { padding: '8px 16px', color: '#555' };
const loadStyle   = { color: '#ffaa00', fontFamily: 'monospace', padding: '60px', fontSize: '13px' };
const errStyle    = { color: '#ff4444', fontFamily: 'monospace', padding: '60px', fontSize: '13px' };
