import React, { useEffect, useRef, useState, useCallback } from 'react';
import * as d3 from 'd3';
import { ICON_MAP } from '../../assets/iconManifest';

// ─── Status badge config ─────────────────────────────────────────────────────
// Derives a simple status from a node's asset data.
// Extend this as verdict data becomes available on nodes.
const getNodeStatus = (node, caseAssets, techniqueStatuses = {}) => {
  const asset = caseAssets.find(a => a.hostname === node.hostname);
  if (!asset) return 'UNKNOWN';

  const assetTechniques = techniqueStatuses[asset.id];
  if (!assetTechniques || Object.keys(assetTechniques).length === 0) return 'UNKNOWN';

  const entries = Object.values(assetTechniques);
  if (entries.some(e => e.verdict === 'MALICIOUS')) return 'COMPROMISED';

  const statuses = entries.map(e => e.technique_status);
  if (statuses.some(s => s === 'IN_PROGRESS' || s === 'PENDING_REVIEW')) return 'NOTED';
  if (statuses.every(s => s === 'CLOSED')) return 'CLEAN';
  return 'UNKNOWN';
};

const STATUS_COLORS = {
  CLEAN:      '#00ff41',
  NOTED:      '#ffaa00',
  COMPROMISED:'#ff4141',
  UNKNOWN:    '#333333',
};

// ─── Link style config ───────────────────────────────────────────────────────
const getLinkStyle = (link) => {
  const type = (link.link_type || 'WIRED').toUpperCase();
  switch (type) {
    case 'WIRELESS': return { dasharray: '6,4',  width: 1.5, opacity: 0.25 };
    case 'VPN':      return { dasharray: '2,3',  width: 2,   opacity: 0.3  };
    case 'WIRED':
    default:         return { dasharray: null,   width: 2,   opacity: 0.2  };
  }
};

export default function NetworkMap({
  activeNodes,
  activeLinks = [],
  updateNodeData,
  onInitiateLink,
  onDeleteNode,
  onInvestigateAsset,
  investigatingAssetId,
  isFetchingTactics,
  caseAssets = [],
  techniqueStatuses = {},
  onToggleMaximize,
  isMaximized = false,
  mapBackgroundUrl,
  onUploadMapBackground,
  onClearMapBackground,
}) {
  const d3Container   = useRef(null);
  const svgRef        = useRef(null);
  const zoomRef        = useRef(null);
  const bgFileInputRef = useRef(null);
  const [contextMenu, setContextMenu] = useState(null);
  const [hoveredLink, setHoveredLink] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [searchQuery, setSearchQuery]   = useState('');
  // Whether mapBackgroundUrl actually resolves to a real image -- there's no
  // upfront "does this case have a background" flag from the backend, so
  // this is discovered by trying to load it and watching for onerror/onload
  // (see the <image> element below), same as any optional-image pattern.
  const [hasBackground, setHasBackground] = useState(false);

  // ─── Search highlight: dim non-matching nodes ────────────────────────────
  useEffect(() => {
    if (!svgRef.current) return;
    const q = searchQuery.trim().toLowerCase();
    d3.select(svgRef.current)
      .selectAll('#node-group g')
      .attr('opacity', d => {
        if (!q) return 1;
        const haystack = `${d.displayName || ''} ${d.hostname}`.toLowerCase();
        return haystack.includes(q) ? 1 : 0.08;
      });
  }, [searchQuery]);

  // ─── Pulse ring: re-apply when investigatingAssetId changes ─────────────
  useEffect(() => {
    if (!svgRef.current) return;
    d3.select(svgRef.current)
      .selectAll('.pulse-ring')
      .attr('opacity', function() {
        const hostname = d3.select(this.parentNode).datum()?.hostname;
        return String(hostname) === String(investigatingAssetId) ? 1 : 0;
      });
  }, [investigatingAssetId]);

  // ─── Main D3 effect ──────────────────────────────────────────────────────
  useEffect(() => {
    // No longer bails out on zero nodes -- a case with a map background but
    // no devices placed yet should still show the backdrop, not a blank div.
    if (!d3Container.current) return;

    const width  = d3Container.current.clientWidth  || 800;
    const height = d3Container.current.clientHeight || 500;

    const nodes = activeNodes.map(d => {
      const hasSavedPos = d.x != null && d.y != null;
      return {
        ...d,
        id: d.hostname,
        // Only a node with an explicitly saved (dragged) position gets
        // pinned via fx/fy -- everything else stays a free node so the
        // collision force can still separate overlapping ones. But give a
        // free node a starting x/y near canvas center (with a little
        // jitter so several new nodes don't start exactly coincident)
        // instead of letting d3 fall back to its own default spawn point,
        // which can land far from center depending on the node's index --
        // confirmed live 2026-08-18, that's what made newly-added nodes
        // visibly rocket/fling across the canvas into place instead of
        // gently settling.
        x: hasSavedPos ? d.x : width / 2 + (Math.random() - 0.5) * 40,
        y: hasSavedPos ? d.y : height / 2 + (Math.random() - 0.5) * 40,
        fx: hasSavedPos ? d.x : undefined,
        fy: hasSavedPos ? d.y : undefined,
      };
    });

    const links = activeLinks.map(d => ({ ...d }));

    d3.select(d3Container.current).selectAll('*').remove();

    // ── SVG + zoom container ─────────────────────────────────────────────
    const svg = d3.select(d3Container.current)
      .append('svg')
      .attr('width', '100%')
      .attr('height', '100%')
      .attr('viewBox', `0 0 ${width} ${height}`);

    svgRef.current = svg.node();

    // Dismiss menus/flyout on canvas click
    svg.on('click', () => {
      setContextMenu(null);
      setSelectedNode(null);
    });

    const gZoom = svg.append('g').attr('id', 'zoom-container');

    const zoom = d3.zoom()
      .scaleExtent([0.2, 4])
      .on('zoom', (event) => {
        gZoom.attr('transform', event.transform);
      });

    svg.call(zoom);
    zoomRef.current = zoom;

    // Restore saved transform if present
    const savedTransform = d3Container.current._zoomTransform;
    if (savedTransform) svg.call(zoom.transform, savedTransform);

    // Save transform on zoom/pan for persistence across re-renders
    zoom.on('zoom.save', (event) => {
      d3Container.current._zoomTransform = event.transform;
      gZoom.attr('transform', event.transform);
    });

    // ── Background image (floor plan / diagram backdrop) ──────────────────
    // Lives inside gZoom, before the link/node layers, so it pans and zooms
    // together with the diagram instead of staying fixed to the viewport --
    // devices dragged onto a spot on the floor plan should stay anchored to
    // that spot as the user pans/zooms around. Sized generously around the
    // simulation's own center point rather than fit to the SVG's current
    // viewBox, so it doesn't need to be re-sized every time the container
    // resizes.
    if (mapBackgroundUrl) {
      gZoom.insert('image', ':first-child')
        .attr('href', mapBackgroundUrl)
        .attr('x', width / 2 - 800)
        .attr('y', height / 2 - 600)
        .attr('width', 1600)
        .attr('height', 1200)
        .attr('preserveAspectRatio', 'xMidYMid meet')
        .attr('opacity', 0.55)
        .style('pointer-events', 'none')
        .on('load', () => setHasBackground(true))
        .on('error', () => setHasBackground(false));
    }

    const gLinks = gZoom.append('g').attr('id', 'link-group');
    const gNodes = gZoom.append('g').attr('id', 'node-group');

    // ── Links: visual layer ──────────────────────────────────────────────
    const linkVisual = gLinks
      .selectAll('.link-line')
      .data(links)
      .join('line')
      .attr('class', 'link-line')
      .attr('stroke', '#00ff41')
      .attr('stroke-width',   d => getLinkStyle(d).width)
      .attr('stroke-opacity', d => getLinkStyle(d).opacity)
      .attr('stroke-dasharray', d => getLinkStyle(d).dasharray || null)
      .style('pointer-events', 'none');

    // ── Links: hit area ──────────────────────────────────────────────────
    gLinks
      .selectAll('.link-hit')
      .data(links)
      .join('line')
      .attr('class', 'link-hit')
      .attr('stroke', 'transparent')
      .attr('stroke-width', 20)
      .style('cursor', 'pointer')
      .style('pointer-events', 'all')
      .on('mouseover', function(event, d) {
        setHoveredLink(d);
        linkVisual.filter(l => l.id === d.id)
          .attr('stroke-opacity', 1)
          .attr('stroke-width', getLinkStyle(d).width + 1);
      })
      .on('mouseout', function(event, d) {
        setHoveredLink(null);
        linkVisual.filter(l => l.id === d.id)
          .attr('stroke-opacity', getLinkStyle(d).opacity)
          .attr('stroke-width', getLinkStyle(d).width);
      });

    // ── Simulation ───────────────────────────────────────────────────────
    const simulation = d3.forceSimulation(nodes)
      .force('link',      d3.forceLink(links).id(d => d.id).distance(150).strength(0.1))
      .force('charge',    d3.forceManyBody().strength(-20))
      .force('center',    d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(65).strength(0.7))
      .velocityDecay(0.4)
      .alphaDecay(0.02)
      .alphaTarget(0)
      .stop();

    simulation.alpha(0.3).restart();

    // ── Nodes ────────────────────────────────────────────────────────────
    const node = gNodes
      .selectAll('g')
      .data(nodes)
      .join('g')
      .attr('cursor', 'grab')
      .on('click', (event, d) => {
        event.stopPropagation();
        setContextMenu(null);
        setSelectedNode(prev =>
          prev && prev.hostname === d.hostname ? null : d
        );
      })
      .on('contextmenu', (event, d) => {
        event.preventDefault();
        event.stopPropagation();
        setSelectedNode(null);
        const potentialTargets = activeNodes
          .filter(n => n.hostname !== d.hostname)
          .sort((a, b) => (a.displayName || a.hostname).localeCompare(b.displayName || b.hostname));
        setContextMenu({ x: event.pageX, y: event.pageY, node: d, targets: potentialTargets });
      })
      .call(d3.drag()
        .on('start', (event, d) => {
          if (!event.active) simulation.alphaTarget(0.2).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on('drag', (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on('end', (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          if (updateNodeData) {
            updateNodeData(d, 'COORD_UPDATE', { x: d.x, y: d.y, fx: d.fx, fy: d.fy });
          }
        })
      );

    // Invisible hit area, sized to the node's full visual footprint (out to
    // the pulse ring's radius) -- drag/click/contextmenu are bound to the
    // <g> itself, which has no hit-testing of its own without a filled
    // shape under the pointer. The solid circle below is only r=24, and the
    // pulse ring is stroke-only (fill:none doesn't register hits), so the
    // ring-shaped gap between them fell through to the SVG's own pan/zoom
    // handler -- confirmed live 2026-08-18: grabbing a node in that gap
    // panned the whole canvas instead of dragging the node, which reads as
    // "everything moves" since a pan shifts every node at once.
    node.append('circle')
      .attr('r', 34)
      .attr('fill', 'transparent');

    // Pulse ring (shown when this node is being investigated)
    node.append('circle')
      .attr('class', 'pulse-ring')
      .attr('r', 34)
      .attr('fill', 'none')
      .attr('stroke', '#00ff41')
      .attr('stroke-width', 1)
      .attr('stroke-dasharray', '3,2')
      .attr('opacity', d =>
        String(d.hostname) === String(investigatingAssetId) ? 1 : 0
      )
      .style('animation', d =>
        String(d.hostname) === String(investigatingAssetId)
          ? 'orca-pulse 1.8s ease-in-out infinite'
          : 'none'
      );

    // Outer circle
    node.append('circle')
      .attr('r', 24)
      .attr('fill', '#020202')
      .attr('stroke', '#00ff41')
      .attr('stroke-opacity', 0.3)
      .attr('stroke-dasharray', '2,2');

    // Asset icon
    node.append('image')
      .attr('href', d => ICON_MAP[(d.type || 'DEFAULT').toUpperCase()] || ICON_MAP['DEFAULT'])
      .attr('width', 38)
      .attr('height', 38)
      .attr('x', -19)
      .attr('y', -19)
      .style('filter', 'brightness(0) invert(65%) sepia(97%) saturate(2800%) hue-rotate(95deg)')
      .style('image-rendering', 'pixelated')
      .style('pointer-events', 'none');

    // Status badge (top-right of node circle)
    node.append('circle')
      .attr('class', 'status-badge')
      .attr('r', 5)
      .attr('cx', 18)
      .attr('cy', -18)
      .attr('fill', d => STATUS_COLORS[getNodeStatus(d, caseAssets, techniqueStatuses)] || STATUS_COLORS.UNKNOWN)
      .attr('stroke', '#020202')
      .attr('stroke-width', 1.5);

    // Display label (custom name if set, else the real hostname)
    node.append('text')
      .text(d => d.displayName || d.hostname)
      .attr('text-anchor', 'middle')
      .attr('y', 42)
      .attr('fill', '#00ff41')
      .style('font-size', '11px')
      .style('font-family', 'monospace')
      .style('text-shadow', '1px 1px 2px #000')
      .style('pointer-events', 'none');

    // ── Tick ─────────────────────────────────────────────────────────────
    simulation.on('tick', () => {
      gLinks.selectAll('.link-hit, .link-line')
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);

      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Keep the SVG's internal coordinate system (viewBox) matched to the
    // container's actual rendered size. Without this, width/height were
    // only ever measured once when this effect ran, so toggling
    // MAXIMIZE_MAP (or any other container resize -- window resize,
    // sidebar collapse) left the viewBox stuck at the old, usually much
    // smaller, dimensions while the <svg width="100%" height="100%">
    // itself filled the new size -- confirmed live 2026-08-18, that
    // viewBox/actual-size mismatch is exactly what made zoom/pan feel like
    // it jumped to "some crazy place": mouse-drag deltas get interpreted
    // in the stale, disproportionate viewBox space.
    const resizeObserver = new ResizeObserver(entries => {
      const entry = entries[0];
      if (!entry) return;
      const newWidth = entry.contentRect.width || width;
      const newHeight = entry.contentRect.height || height;
      svg.attr('viewBox', `0 0 ${newWidth} ${newHeight}`);
      simulation.force('center', d3.forceCenter(newWidth / 2, newHeight / 2));
      simulation.alpha(0.3).restart();
    });
    resizeObserver.observe(d3Container.current);

    return () => {
      simulation.stop();
      resizeObserver.disconnect();
    };
  }, [activeNodes, activeLinks, updateNodeData, caseAssets, techniqueStatuses, mapBackgroundUrl]);

  // ─── Flyout: resolve full asset data from caseAssets ────────────────────
  const flyoutAsset = selectedNode
    ? caseAssets.find(a => a.hostname === selectedNode.hostname) || selectedNode
    : null;

  const isBeingInvestigated = flyoutAsset &&
    String(flyoutAsset.id) === String(investigatingAssetId);

  // ─── Zoom controls ───────────────────────────────────────────────────────
  const handleZoom = useCallback((factor) => {
    if (!svgRef.current || !zoomRef.current) return;
    d3.select(svgRef.current)
      .transition().duration(250)
      .call(zoomRef.current.scaleBy, factor);
  }, []);

  const handleZoomReset = useCallback(() => {
    if (!svgRef.current || !zoomRef.current) return;
    d3.select(svgRef.current)
      .transition().duration(350)
      .call(zoomRef.current.transform, d3.zoomIdentity);
  }, []);

  return (
    <div
      style={{ position: 'relative', width: '100%', height: '100%', overflow: 'hidden' }}
      onClick={() => { setContextMenu(null); setSelectedNode(null); }}
    >
      {/* ── Canvas ── */}
      <div ref={d3Container} style={{ width: '100%', height: '100%', background: '#020202' }} />

      {/* ── Search bar ── */}
      <div style={{
        position: 'absolute', top: 12, left: 12, zIndex: 100,
        display: 'flex', alignItems: 'center', gap: 6,
      }}>
        <span style={{ color: '#999', fontFamily: 'monospace', fontSize: '10px' }}>SEARCH:</span>
        <input
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          placeholder="hostname..."
          style={{
            background: 'rgba(0,0,0,0.85)', border: '1px solid #1a1a1a',
            color: '#00ff41', fontFamily: 'monospace', fontSize: '10px',
            padding: '4px 8px', outline: 'none', width: '140px',
          }}
          onClick={e => e.stopPropagation()}
        />
        {searchQuery && (
          <span
            onClick={e => { e.stopPropagation(); setSearchQuery(''); }}
            style={{ color: '#aaa', cursor: 'pointer', fontSize: '10px', fontFamily: 'monospace' }}
          >✕</span>
        )}
      </div>

      {/* ── Zoom controls ── */}
      <div style={{
        position: 'absolute', bottom: 16, right: 16, zIndex: 100,
        display: 'flex', flexDirection: 'column', gap: 4,
      }}>
        {[
          { label: '+', action: () => handleZoom(1.3) },
          { label: '−', action: () => handleZoom(1 / 1.3) },
          { label: '⌂', action: handleZoomReset },
        ].map(({ label, action }) => (
          <button
            key={label}
            onClick={e => { e.stopPropagation(); action(); }}
            style={{
              width: 28, height: 28, background: '#0a0a0a', border: '1px solid #1a1a1a',
              color: '#00ff41', fontFamily: 'monospace', fontSize: '13px',
              cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}
          >{label}</button>
        ))}
      </div>

      {/* ── Link type legend ── */}
      <div style={{
        position: 'absolute', bottom: 16, left: 12, zIndex: 100,
        fontFamily: 'monospace', fontSize: '9px', color: '#999',
        display: 'flex', flexDirection: 'column', gap: 4,
      }}>
        {[
          { label: 'WIRED',    dash: 'none'  },
          { label: 'WIRELESS', dash: '6px 4px' },
          { label: 'VPN',      dash: '2px 3px' },
        ].map(({ label, dash }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <svg width="24" height="6" style={{ overflow: 'visible' }}>
              <line x1="0" y1="3" x2="24" y2="3"
                stroke="#00ff41" strokeWidth="1.5" strokeOpacity="0.4"
                strokeDasharray={dash === 'none' ? undefined : dash}
              />
            </svg>
            <span>{label}</span>
          </div>
        ))}
      </div>

      {/* ── Top-right: maximize toggle + status legend ── */}
      <div style={{
        position: 'absolute', top: 12, right: 16, zIndex: 200,
        display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 8,
      }}>
        <div style={{ display: 'flex', gap: 6 }}>
          {onUploadMapBackground && (
            <>
              <input
                ref={bgFileInputRef}
                type="file"
                accept="image/*"
                style={{ display: 'none' }}
                onClick={e => { e.target.value = null; }}
                onChange={e => {
                  const f = e.target.files[0];
                  if (f) onUploadMapBackground(f);
                }}
              />
              {hasBackground && onClearMapBackground && (
                <button
                  onClick={e => { e.stopPropagation(); onClearMapBackground(); }}
                  style={{
                    background: 'none', color: '#999', border: '1px solid #333',
                    padding: '6px 10px', fontSize: '9px', fontWeight: 'bold',
                    cursor: 'pointer', fontFamily: 'monospace', letterSpacing: 1,
                  }}
                >
                  [ CLEAR_BACKGROUND ]
                </button>
              )}
              <button
                onClick={e => { e.stopPropagation(); bgFileInputRef.current?.click(); }}
                style={{
                  background: 'none', color: '#00ff41', border: '1px solid #00ff41',
                  padding: '6px 10px', fontSize: '9px', fontWeight: 'bold',
                  cursor: 'pointer', fontFamily: 'monospace', letterSpacing: 1,
                }}
              >
                [ {hasBackground ? 'CHANGE' : 'UPLOAD'}_MAP_BACKGROUND ]
              </button>
            </>
          )}
          {onToggleMaximize && (
            <button
              onClick={e => { e.stopPropagation(); onToggleMaximize(); }}
              style={{
                background: '#00ff41', color: '#000', border: 'none',
                padding: '6px 12px', fontSize: '9px', fontWeight: 'bold',
                cursor: 'pointer', fontFamily: 'monospace', letterSpacing: 1,
              }}
            >
              {isMaximized ? '[ EXIT_FULLSCREEN ]' : '[ MAXIMIZE_MAP ]'}
            </button>
          )}
        </div>
        <div style={{
          fontFamily: 'monospace', fontSize: '9px',
          display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'flex-end',
          background: 'rgba(0,0,0,0.6)', padding: '6px 8px',
        }}>
          {Object.entries(STATUS_COLORS).map(([status, color]) => (
            <div key={status} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <span style={{ color: color === '#333333' ? '#666' : color }}>{status}</span>
              <div style={{ width: 7, height: 7, borderRadius: '50%', background: color, flexShrink: 0 }} />
            </div>
          ))}
        </div>
      </div>

      {/* ── Link hover tooltip ── */}
      {hoveredLink && (
        <div style={{
          position: 'absolute', bottom: 20, left: '50%', transform: 'translateX(-50%)',
          padding: '8px 12px', background: '#0a0a0a', border: '1px solid #1a1a1a',
          fontFamily: 'monospace', color: '#00ff41', fontSize: '11px',
          pointerEvents: 'none', zIndex: 3000, whiteSpace: 'nowrap',
        }}>
          <span style={{ color: '#aaa' }}>SRC </span>{hoveredLink.source.id || hoveredLink.source}
          <span style={{ color: '#aaa', margin: '0 8px' }}>↔</span>
          <span style={{ color: '#aaa' }}>DST </span>{hoveredLink.target.id || hoveredLink.target}
          <span style={{ color: '#999', margin: '0 8px' }}>|</span>
          {(hoveredLink.link_type || 'WIRED')}
          <span style={{ color: '#999', margin: '0 8px' }}>|</span>
          <span style={{ color: '#aaa' }}>VLAN </span>{hoveredLink.vlan || '1'}
        </div>
      )}

      {/* ── Node detail flyout ── */}
      {flyoutAsset && (
        <div
          style={{
            position: 'absolute', top: 12, left: '50%', transform: 'translateX(-50%)',
            width: 320, background: '#060606', border: '1px solid #1a1a1a',
            fontFamily: 'monospace', fontSize: '11px', color: '#00ff41',
            zIndex: 2500,
          }}
          onClick={e => e.stopPropagation()}
        >
          {/* Header */}
          <div style={{
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            padding: '8px 12px', borderBottom: '1px solid #111', background: '#0a0a0a',
          }}>
            <span style={{ fontWeight: 'bold', letterSpacing: 1 }}>
              {selectedNode?.displayName || flyoutAsset.hostname}
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{
                width: 7, height: 7, borderRadius: '50%',
                background: STATUS_COLORS[getNodeStatus(selectedNode, caseAssets, techniqueStatuses)],
              }} />
              <span
                onClick={() => setSelectedNode(null)}
                style={{ color: '#aaa', cursor: 'pointer', fontSize: '13px', lineHeight: 1 }}
              >✕</span>
            </div>
          </div>

          {/* Fields */}
          <div style={{ padding: '10px 12px', display: 'grid', gap: 6 }}>
            {[
              ['IP',       flyoutAsset.ip],
              ['MAC',      flyoutAsset.mac_address || flyoutAsset.mac],
              ['OS',       `${flyoutAsset.os || '—'} ${flyoutAsset.os_version || flyoutAsset.version || ''}`.trim()],
              ['FORM',     flyoutAsset.form_factor || flyoutAsset.type],
              ['SUBNET',   flyoutAsset.subnet_mask],
              ['GATEWAY',  flyoutAsset.gateway],
            ].filter(([, v]) => v).map(([label, value]) => (
              <div key={label} style={{ display: 'flex', gap: 8 }}>
                <span style={{ color: '#999', minWidth: 60 }}>{label}</span>
                <span style={{ color: '#aaa' }}>{value}</span>
              </div>
            ))}

            {(flyoutAsset.asset_notes || flyoutAsset.nodeNote) && (
              <div style={{ marginTop: 4, paddingTop: 6, borderTop: '1px solid #111' }}>
                <div style={{ color: '#999', marginBottom: 3 }}>NOTE</div>
                <div style={{
                  color: '#bbb', fontSize: '10px', lineHeight: 1.5,
                  maxHeight: 60, overflowY: 'auto',
                }}>
                  {flyoutAsset.asset_notes || flyoutAsset.nodeNote}
                </div>
              </div>
            )}
          </div>

          {/* Investigate button */}
          <div style={{ padding: '8px 12px', borderTop: '1px solid #111' }}>
            {isFetchingTactics && isBeingInvestigated ? (
              <div style={{ color: '#aaa', fontSize: '10px', textAlign: 'center', padding: '4px 0' }}>
                LOADING_THREAT_PROFILE...
              </div>
            ) : (
              <button
                onClick={() => {
                  if (onInvestigateAsset && flyoutAsset.id) {
                    onInvestigateAsset(flyoutAsset.id);
                    setSelectedNode(null);
                  }
                }}
                disabled={!flyoutAsset.id}
                style={{
                  width: '100%', padding: '7px', background: flyoutAsset.id ? '#00ff41' : '#111',
                  color: flyoutAsset.id ? '#000' : '#333', border: 'none',
                  fontFamily: 'monospace', fontSize: '10px', fontWeight: 'bold',
                  cursor: flyoutAsset.id ? 'pointer' : 'not-allowed', letterSpacing: 1,
                }}
              >
                {isBeingInvestigated ? '[ INVESTIGATION_ACTIVE ]' : '[ OPEN_EVIDENCE_WINDOW ]'}
              </button>
            )}
          </div>
        </div>
      )}

      {/* ── Context menu ── */}
      {contextMenu && (
        <div
          style={{
            position: 'fixed', top: contextMenu.y, left: contextMenu.x,
            background: '#0a0a0a', border: '1px solid #00ff41',
            zIndex: 4000, minWidth: '185px', padding: '4px',
          }}
          onClick={e => e.stopPropagation()}
        >
          <div style={{
            padding: '6px 12px 4px', fontSize: '9px', color: '#999',
            borderBottom: '1px solid #111', marginBottom: '2px', letterSpacing: 1,
          }}>
            {contextMenu.node.displayName || contextMenu.node.hostname}
          </div>

          <MenuBtn onClick={() => { updateNodeData(contextMenu.node, 'RENAME'); setContextMenu(null); }}>
            RENAME_DEVICE
          </MenuBtn>

          <MenuBtn onClick={() => { updateNodeData(contextMenu.node, 'IP'); setContextMenu(null); }}>
            SET_IP_ADDRESS
          </MenuBtn>

          <MenuBtn onClick={() => { updateNodeData(contextMenu.node, 'NOTE'); setContextMenu(null); }}>
            EDIT_SYSTEM_NOTE
          </MenuBtn>

          {['SWITCH', 'ROUTER', 'FIREWALL'].includes(contextMenu.node.type?.toUpperCase()) && (
            <MenuBtn onClick={() => { updateNodeData(contextMenu.node, 'CONFIG'); setContextMenu(null); }}>
              PASTE_RUNNING_CONFIG
            </MenuBtn>
          )}

          <div className="group" style={{ position: 'relative' }}>
            <MenuBtn>ESTABLISH_UPLINK {'>'}</MenuBtn>
            <div style={{
              display: 'none', position: 'absolute', left: '100%', top: 0,
              background: '#0a0a0a', border: '1px solid #00ff41',
              maxHeight: '250px', overflowY: 'auto', minWidth: '150px',
            }} className="group-hover">
              {contextMenu.targets.length === 0
                ? <div style={{ padding: '8px 12px', fontSize: '10px', color: '#999' }}>NO_OTHER_NODES</div>
                : contextMenu.targets.map(t => (
                    <MenuBtn key={t.hostname} onClick={() => { onInitiateLink(contextMenu.node, t); setContextMenu(null); }}>
                      {t.displayName || t.hostname}
                    </MenuBtn>
                  ))
              }
            </div>
          </div>

          {/* Investigate from context menu — only for registered assets */}
          {contextMenu.node.id != null && onInvestigateAsset && (
            <>
              <div style={{ height: '1px', background: '#111', margin: '4px 0' }} />
              {isFetchingTactics && String(investigatingAssetId) === String(contextMenu.node.id)
                ? <div style={{ padding: '8px 12px', fontSize: '10px', color: '#aaa' }}>LOADING...</div>
                : (
                  <MenuBtn
                    style={{ color: '#00ff41', fontWeight: 'bold' }}
                    onClick={() => {
                      onInvestigateAsset(contextMenu.node.id);
                      setContextMenu(null);
                    }}
                  >
                    INVESTIGATE_ASSET
                  </MenuBtn>
                )
              }
            </>
          )}

          <div style={{ height: '1px', background: '#111', margin: '4px 0' }} />

          <MenuBtn
            style={{ color: '#ff4141' }}
            onClick={() => { onDeleteNode(contextMenu.node); setContextMenu(null); }}
          >
            DELETE_FROM_WORKSPACE
          </MenuBtn>
        </div>
      )}

      <style>{`
        @keyframes orca-pulse {
          0%   { r: 30; stroke-opacity: 0.8; }
          50%  { r: 38; stroke-opacity: 0.2; }
          100% { r: 30; stroke-opacity: 0.8; }
        }
        .group:hover .group-hover { display: block !important; }
        ::-webkit-scrollbar       { width: 4px; }
        ::-webkit-scrollbar-track { background: #000; }
        ::-webkit-scrollbar-thumb { background: #00ff41; }
      `}</style>
    </div>
  );
}

const MenuBtn = ({ children, onClick, style }) => (
  <div
    onClick={onClick}
    style={{
      padding: '8px 12px', fontSize: '11px', color: '#00ff41',
      cursor: 'pointer', fontFamily: 'monospace', transition: 'background 0.1s ease',
      ...style,
    }}
    onMouseOver={e => e.currentTarget.style.background = '#1a1a1a'}
    onMouseOut={e => e.currentTarget.style.background  = 'transparent'}
  >
    {'> '}{children}
  </div>
);
