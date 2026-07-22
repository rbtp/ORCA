import React, { useState, useEffect, useMemo } from 'react';

const formatMitreData = (rawText) => {
  if (!rawText) return { body: null, citations: [] };
  const citations = [];
  const citationRegex = /\(Citation: ([^)]+)\)/g;
  let match;
  while ((match = citationRegex.exec(rawText)) !== null) {
    if (!citations.includes(match[1])) citations.push(match[1]);
  }
  let processedText = rawText;
  citations.forEach((cite, i) => {
    const escapedCite = cite.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`\\(Citation: ${escapedCite}\\)`, 'g');
    processedText = processedText.replace(regex, `[[${i + 1}]]`);
  });
  const parts = processedText.split(/(\[[^\]]+\]\([^)]+\))/g);
  const body = parts.map((part, i) => {
    const linkMatch = part.match(/\[([^\]]+)\]\(([^)]+)\)/);
    if (linkMatch) return <a key={i} href={linkMatch[2]} target="_blank" rel="noopener noreferrer" style={{ color: '#00ff41', textDecoration: 'none', borderBottom: '1px solid #1a1a1a' }}>{linkMatch[1]}</a>;
    const segments = part.split(/(\[\[\d+\]\])/g);
    return segments.map((seg, j) => {
      const citeMatch = seg.match(/\[\[(\d+)\]\]/);
      if (citeMatch) return <sup key={j} style={{ color: '#00ff41', fontSize: '9px', marginLeft: '2px' }}>[{citeMatch[1]}]</sup>;
      return seg;
    });
  });
  return { body, citations };
};

export default function MitreInspector() {
  const [searchTerm, setSearchTerm] = useState('');
  const [geoData, setGeoData] = useState([]);
  const [allGroups, setAllGroups] = useState([]);
  const [mitigations, setMitigations] = useState([]);
  const [software, setSoftware] = useState([]);

  const API_BASE = `${import.meta.env.VITE_API_URL}/api/mitre`;

  const normalize = (item) => {
    if (!item) return null;
    const clean = {};
    Object.keys(item).forEach(key => {
        const cleanKey = key.toLowerCase().trim().replace(/\s+/g, '_');
        clean[cleanKey] = item[key];
    });
    return {
      ...clean,
      id: clean.id || clean.s_code || clean.m_code || clean.t_code || clean.external_id || "",
      stix_id: clean.stix_id || clean.source_ref || clean.target_ref || "",
      name: clean.name || "Unknown",
      description: clean.description || ""
    };
  };

  // --- INITIAL SYNC WITH AUTH ---
  useEffect(() => {
    fetch(`${API_BASE}/sidebar`, {
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
    })
      .then(r => {
        if (!r.ok) throw new Error("AUTH_REJECTED");
        return r.json();
      })
      .then(data => {
        setGeoData((data.geopolitical || []).map(c => ({
          ...c, associated_groups: (c.associated_groups || []).map(normalize)
        })));
        setAllGroups((data.groups || []).map(normalize));
        setSoftware((data.software || []).map(normalize));
        setMitigations((data.mitigations || []).map(normalize));
      })
      .catch(e => console.error("ORCA_SYNC_FAIL", e));
  }, []);

  // --- SELECT HANDLER WITH AUTH ---
  const handleSelect = async (type, rawData) => {
    const data = normalize(rawData);
    const identifier = data.id || data.stix_id;
    if (!identifier) return;

    window.dispatchEvent(new CustomEvent('orca-intel-select', { 
      detail: { type, data: { name: data.name, description: "SYNCING...", loading: true } } 
    }));

    try {
      const response = await fetch(`${API_BASE}/${type}s/${identifier}`, {
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
      });
      
      const fullDossier = await response.json();
      const cleanDossier = normalize(fullDossier);
      const formatted = formatMitreData(cleanDossier.description);

      window.dispatchEvent(new CustomEvent('orca-intel-select', { 
        detail: { 
          type, 
          data: { 
            ...cleanDossier,
            loading: false,
            formattedBody: formatted.body,
            formattedCitations: formatted.citations,
            linkedSoftware: (fullDossier.software || []).map(normalize),
            linkedMitigations: (fullDossier.mitigations || []).map(normalize),
            linkedTechniques: (fullDossier.techniques || []).map(normalize)
          } 
        } 
      }));
    } catch (err) {
      console.error("DIAGNOSTIC_FETCH_ERROR:", err);
    }
  };

  const fGroups = useMemo(() => allGroups.filter(g => g.name.toLowerCase().includes(searchTerm.toLowerCase())), [searchTerm, allGroups]);
  const fSoft = useMemo(() => software.filter(s => s.name.toLowerCase().includes(searchTerm.toLowerCase())), [searchTerm, software]);
  const fMit = useMemo(() => mitigations.filter(m => m.name.toLowerCase().includes(searchTerm.toLowerCase())), [searchTerm, mitigations]);

  return (
    <div style={{ width: '240px', background: '#080808', borderRight: '1px solid #1a1a1a', height: '100vh', overflowY: 'auto', fontFamily: 'monospace', flexShrink: 0 }}>
      <div style={{ padding: '15px', borderBottom: '1px solid #1a1a1a', position: 'sticky', top: 0, background: '#080808', zIndex: 10 }}>
        <div style={{ fontSize: '9px', color: '#333', letterSpacing: '1px', marginBottom: '8px', fontWeight: 900 }}>INTEL_ENGINE</div>
        <input
          placeholder="FILTER..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{ width: '100%', background: '#000', border: '1px solid #222', padding: '8px', color: '#00ff41', outline: 'none', fontSize: '10px' }}
        />
      </div>

      <details style={{ borderBottom: '1px solid #111' }}>
        <summary style={{ padding: '10px 15px', background: '#0d0d0d', color: '#00ff41', fontSize: '10px', cursor: 'pointer', listStyle: 'none', fontWeight: 900 }}>[+] GEOPOLITICAL</summary>
        {geoData.map((item, i) => (
          <details key={i} style={{ padding: '2px 15px' }}>
            <summary style={{ color: '#666', fontSize: '10px', cursor: 'pointer', padding: '4px 0' }}>{item.country_name}</summary>
            {item.associated_groups.map((g, idx) => (
              <div key={idx} onClick={() => handleSelect('group', g)} style={{ color: '#aaa', fontSize: '10px', padding: '4px 0', paddingLeft: '10px', cursor: 'pointer', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {g.name}
              </div>
            ))}
          </details>
        ))}
      </details>

      <details style={{ borderBottom: '1px solid #111' }}>
        <summary style={{ padding: '10px 15px', background: '#0d0d0d', color: '#00ff41', fontSize: '10px', cursor: 'pointer', listStyle: 'none', fontWeight: 900 }}>[+] THREAT_GROUPS</summary>
        <div style={{ maxHeight: '300px', overflowY: 'auto', padding: '5px 15px' }}>
          {fGroups.map((g, i) => (
            <div key={i} onClick={() => handleSelect('group', g)} style={{ color: '#aaa', fontSize: '10px', padding: '5px 0', cursor: 'pointer', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {g.name}
            </div>
          ))}
        </div>
      </details>

      <details style={{ borderBottom: '1px solid #111' }}>
        <summary style={{ padding: '10px 15px', background: '#0d0d0d', color: '#00ff41', fontSize: '10px', cursor: 'pointer', listStyle: 'none', fontWeight: 900 }}>[+] SOFTWARE</summary>
        <div style={{ padding: '5px 15px' }}>
          {fSoft.map((s, i) => (
            <div key={i} onClick={() => handleSelect('software', s)} style={{ color: '#aaa', fontSize: '10px', padding: '5px 0', cursor: 'pointer', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              <span style={{ color: '#00ff41', fontSize: '9px' }}>[{s.id}]</span> {s.name}
            </div>
          ))}
        </div>
      </details>

      <details style={{ borderBottom: '1px solid #111' }}>
        <summary style={{ padding: '10px 15px', background: '#0d0d0d', color: '#00ff41', fontSize: '10px', cursor: 'pointer', listStyle: 'none', fontWeight: 900 }}>[+] MITIGATIONS</summary>
        <div style={{ padding: '5px 15px' }}>
          {fMit.map((m, i) => (
            <div key={i} onClick={() => handleSelect('mitigation', m)} style={{ color: '#aaa', fontSize: '10px', padding: '5px 0', cursor: 'pointer', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              <span style={{ color: '#00ff41', fontSize: '9px' }}>[{m.id}]</span> {m.name}
            </div>
          ))}
        </div>
      </details>
    </div>
  );
}