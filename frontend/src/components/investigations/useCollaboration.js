import { useState, useEffect, useRef, useCallback } from 'react';

const API_BASE = `${import.meta.env.VITE_API_URL}/api/mitre`;
const getAuth = () => ({
  'Authorization': `Bearer ${localStorage.getItem('orca_token')}`,
  'Content-Type': 'application/json',
});

/**
 * useCollaboration
 *
 * Maintains a persistent SSE connection to /api/mitre/collaboration/stream.
 * Tracks technique locks, tool locks, and queues access-attempt notifications.
 *
 * Returns:
 *   techniqueLocks   — Map of "assetId:tCode" → { locked_by, locked_by_initials, locked_at }
 *   toolLocks        — Map of "assetId:toolName" → { locked_by, locked_by_initials }
 *   notifications    — Array of persistent notification objects { id, type, message, payload }
 *   dismissNotification(id) — removes a notification
 *   claimTechnique(assetId, tCode) → Promise<{ status, locked_by?, locked_by_initials? }>
 *   releaseTechnique(assetId, tCode) → Promise
 *   submitTechnique(assetId, tCode) → Promise
 *   closeTechnique(assetId, tCode) → Promise
 *   kickbackTechnique(assetId, tCode) → Promise
 *   acquireToolLock(assetId, toolName) → Promise<{ status, locked_by? }>
 *   releaseToolLock(assetId, toolName) → Promise
 *   techniqueStatuses — Map of "assetId:tCode" → status object (from DB)
 *   loadTechniqueStatuses(assetId) → Promise  (call on EvidenceWindow open)
 *   connected        — boolean SSE connection state
 */
export function useCollaboration() {
  const [connected, setConnected]             = useState(false);
  const [techniqueLocks, setTechniqueLocks]   = useState(new Map());
  const [toolLocks, setToolLocks]             = useState(new Map());
  const [notifications, setNotifications]     = useState([]);
  const [techniqueStatuses, setTechniqueStatuses] = useState(new Map());
  const esRef   = useRef(null);
  const notifId = useRef(0);

  // ── SSE connection ──────────────────────────────────────────────────────────
  useEffect(() => {
    let es;
    let retryTimeout;

    const connect = () => {
      const token = localStorage.getItem('orca_token');
      if (!token) return;

      // EventSource doesn't support custom headers — pass token as query param
      // Backend needs to support ?token= as fallback (see note below)
      es = new EventSource(
        `${API_BASE}/collaboration/stream?token=${encodeURIComponent(token)}`
      );
      esRef.current = es;

      es.onopen = () => setConnected(true);

      es.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          handleSSEEvent(msg);
        } catch {}
      };

      es.onerror = () => {
        setConnected(false);
        es.close();
        // Reconnect after 5s
        retryTimeout = setTimeout(connect, 5000);
      };
    };

    connect();
    return () => {
      if (es) es.close();
      clearTimeout(retryTimeout);
    };
  }, []);

  const handleSSEEvent = useCallback((msg) => {
    const key = (aid, t) => `${aid}:${t}`;

    switch (msg.type) {
      case 'technique_claimed':
        setTechniqueLocks(prev => {
          const next = new Map(prev);
          next.set(key(msg.asset_id, msg.t_code), {
            locked_by: msg.claimed_by,
            locked_by_initials: msg.claimed_by_initials,
            locked_at: new Date().toISOString(),
          });
          return next;
        });
        break;

      case 'technique_released':
      case 'technique_closed':
        setTechniqueLocks(prev => {
          const next = new Map(prev);
          next.delete(key(msg.asset_id, msg.t_code));
          return next;
        });
        break;

      case 'technique_submitted':
        // No lock change — just update status locally
        setTechniqueStatuses(prev => {
          const next = new Map(prev);
          const k = key(msg.asset_id, msg.t_code);
          const existing = next.get(k) || {};
          next.set(k, { ...existing, technique_status: 'PENDING_REVIEW' });
          return next;
        });
        break;

      case 'technique_kickback':
        setTechniqueStatuses(prev => {
          const next = new Map(prev);
          const k = key(msg.asset_id, msg.t_code);
          const existing = next.get(k) || {};
          next.set(k, { ...existing, technique_status: 'IN_PROGRESS' });
          return next;
        });
        break;

      case 'technique_access_attempt':
        // This fires only on the lock holder — add a persistent notification
        addNotification('ACCESS_ATTEMPT', {
          message: `[ ${msg.attempted_by_initials || msg.attempted_by} ] attempted to access ${msg.t_code}`,
          payload: msg,
        });
        break;

      case 'technique_kicked_back':
        addNotification('KICKBACK', {
          message: `${msg.t_code} kicked back by ${msg.kicked_back_by} — review required`,
          payload: msg,
        });
        break;

      case 'tool_locked':
        setToolLocks(prev => {
          const next = new Map(prev);
          next.set(key(msg.asset_id, msg.tool_name), {
            locked_by: msg.locked_by,
            locked_by_initials: msg.locked_by_initials,
          });
          return next;
        });
        break;

      case 'tool_released':
        setToolLocks(prev => {
          const next = new Map(prev);
          next.delete(key(msg.asset_id, msg.tool_name));
          return next;
        });
        break;

      case 'asset_mode_changed':
        addNotification('INFO', {
          message: `Asset ${msg.asset_id} mode changed to ${msg.analysis_mode} by ${msg.changed_by}`,
          payload: msg,
        });
        break;

      default:
        break;
    }
  }, []);

  const addNotification = (type, { message, payload }) => {
    const id = ++notifId.current;
    setNotifications(prev => [...prev, { id, type, message, payload, ts: new Date() }]);
  };

  const dismissNotification = useCallback((id) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  // ── Technique state machine actions ────────────────────────────────────────
  const claimTechnique = useCallback(async (assetId, tCode) => {
    const res = await fetch(`${API_BASE}/techniques/claim`, {
      method: 'POST', headers: getAuth(),
      body: JSON.stringify({ asset_id: assetId, t_code: tCode }),
    });
    return res.json();
  }, []);

  const releaseTechnique = useCallback(async (assetId, tCode) => {
    await fetch(`${API_BASE}/techniques/release`, {
      method: 'POST', headers: getAuth(),
      body: JSON.stringify({ asset_id: assetId, t_code: tCode }),
    });
  }, []);

  const submitTechnique = useCallback(async (assetId, tCode) => {
    const res = await fetch(`${API_BASE}/techniques/submit`, {
      method: 'POST', headers: getAuth(),
      body: JSON.stringify({ asset_id: assetId, t_code: tCode }),
    });
    return res.json();
  }, []);

  const closeTechnique = useCallback(async (assetId, tCode) => {
    const res = await fetch(`${API_BASE}/techniques/close`, {
      method: 'POST', headers: getAuth(),
      body: JSON.stringify({ asset_id: assetId, t_code: tCode }),
    });
    return res.json();
  }, []);

  const kickbackTechnique = useCallback(async (assetId, tCode) => {
    const res = await fetch(`${API_BASE}/techniques/kickback`, {
      method: 'POST', headers: getAuth(),
      body: JSON.stringify({ asset_id: assetId, t_code: tCode }),
    });
    return res.json();
  }, []);

  // ── Tool locks ──────────────────────────────────────────────────────────────
  const acquireToolLock = useCallback(async (assetId, toolName) => {
    const res = await fetch(`${API_BASE}/tools/lock`, {
      method: 'POST', headers: getAuth(),
      body: JSON.stringify({ asset_id: assetId, tool_name: toolName }),
    });
    return res.json();
  }, []);

  const releaseToolLock = useCallback(async (assetId, toolName) => {
    await fetch(`${API_BASE}/tools/release`, {
      method: 'POST', headers: getAuth(),
      body: JSON.stringify({ asset_id: assetId, tool_name: toolName }),
    });
  }, []);

  // ── Technique status loader ─────────────────────────────────────────────────
  const loadTechniqueStatuses = useCallback(async (assetId) => {
    try {
      const res = await fetch(`${API_BASE}/techniques/${assetId}/status`, { headers: getAuth() });
      const rows = await res.json();
      setTechniqueStatuses(prev => {
        const next = new Map(prev);
        rows.forEach(r => {
          next.set(`${assetId}:${r.t_code}`, r);
          // Seed lock map from DB state
          if (r.lock_held_by) {
            setTechniqueLocks(lp => {
              const ln = new Map(lp);
              ln.set(`${assetId}:${r.t_code}`, {
                locked_by: r.lock_held_by_username,
                locked_by_initials: r.lock_held_by_initials,
                locked_at: r.locked_at,
              });
              return ln;
            });
          }
        });
        return next;
      });
    } catch {}
  }, []);

  return {
    connected,
    techniqueLocks,
    toolLocks,
    notifications,
    dismissNotification,
    claimTechnique,
    releaseTechnique,
    submitTechnique,
    closeTechnique,
    kickbackTechnique,
    acquireToolLock,
    releaseToolLock,
    techniqueStatuses,
    loadTechniqueStatuses,
  };
}