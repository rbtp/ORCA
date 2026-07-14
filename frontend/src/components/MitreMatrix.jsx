import React, { useEffect, useState } from 'react';
import axios from 'axios';

const MitreMatrix = ({ aggregatedList: initialList = [] }) => {
    const [layout, setLayout] = useState([]);
    const [loading, setLoading] = useState(true);
    // 1. Internal state to hold the highlighted techniques
    const [highlights, setHighlights] = useState(initialList);

    const API_BASE = `${import.meta.env.VITE_API_URL}/api/mitre`;

    useEffect(() => {
        // Fetch the structural layout (Tactics -> Techniques)
        axios.get(`${API_BASE}/matrix-layout`)
            .then(res => {
                setLayout(res.data);
                setLoading(false);
            })
            .catch(err => console.error("Matrix layout failed", err));

        // 2. LISTEN FOR AGGREGATION EVENTS FROM SIDEBAR
        const handleUpdate = (e) => {
            if (e.detail && e.detail.techniques) {
                console.log("MATRIX_SYNC: Highlighting", e.detail.techniques.length, "techniques");
                setHighlights(e.detail.techniques);
            }
        };

        window.addEventListener('orca-heatmap-update', handleUpdate);
        return () => window.removeEventListener('orca-heatmap-update', handleUpdate);
    }, []);

    if (loading) return (
        <div style={{ 
            color: '#00ff41', 
            padding: '50px', 
            fontFamily: 'monospace', 
            background: '#050505', 
            height: '100vh' 
        }}>
            INITIALIZING_TACTICAL_GRID...
        </div>
    );

    return (
        <div style={{ 
            display: 'flex', 
            overflowX: 'auto', 
            background: '#050505', 
            padding: '20px', 
            gap: '8px',
            height: '100%',
            border: '1px solid #1a1a1a',
            fontFamily: 'monospace'
        }}>
            {layout.map((col, idx) => (
                <div key={idx} style={{ minWidth: '200px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    {/* TACTIC HEADER */}
                    <div style={{ 
                        background: '#111', 
                        color: '#00ff41', 
                        padding: '12px', 
                        fontSize: '10px', 
                        fontWeight: 'bold', 
                        textAlign: 'center', 
                        border: '1px solid #333', 
                        letterSpacing: '1px',
                        marginBottom: '10px'
                    }}>
                        {col.tactic.toUpperCase()}
                    </div>

                    {/* TECHNIQUES */}
                    {col.techniques.map(tech => {
                        const isActive = highlights.includes(tech.id);
                        const isSub = tech.id.includes('.'); // Visual check for sub-techniques

                        return (
                            <div key={tech.id} style={{
                                padding: '8px', 
                                fontSize: '9px',
                                lineHeight: '1.2',
                                // Red highlight for active, dark for inactive
                                background: isActive ? 'rgba(185, 28, 28, 0.9)' : '#0a0a0a',
                                color: isActive ? '#fff' : '#666',
                                border: isActive ? '1px solid #ff4444' : '1px solid #1a1a1a',
                                transition: 'all 0.2s ease',
                                minHeight: '35px',
                                display: 'flex', 
                                alignItems: 'center',
                                marginLeft: isSub ? '15px' : '0px', // Indent sub-techniques
                                opacity: isSub && !isActive ? 0.5 : 1,
                                position: 'relative'
                            }}>
                                {tech.name}
                                {isActive && (
                                    <div style={{ 
                                        position: 'absolute', 
                                        right: '4px', 
                                        top: '2px', 
                                        fontSize: '7px', 
                                        color: 'rgba(255,255,255,0.5)' 
                                    }}>
                                        {tech.id}
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            ))}
        </div>
    );
};

export default MitreMatrix;