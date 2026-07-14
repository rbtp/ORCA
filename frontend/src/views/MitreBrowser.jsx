import React, { useState } from 'react';
import MitreSidebar from '../components/MitreSidebar';
import './MitreBrowser.css';

const MitreBrowser = () => {
    // State now holds the specific intel object rather than aggregate stats
    const [intelData, setIntelData] = useState(null);

    const handleUpdateIntelligence = (data) => {
        setIntelData(data);
    };

    return (
        <div className="mitre-browser-container">
            {/* LEFT SIDE: Navigation/Selection */}
            <MitreSidebar onUpdateIntelligence={handleUpdateIntelligence} />

            {/* RIGHT SIDE: The Intelligence Display */}
            <div className="intelligence-pane">
                {!intelData ? (
                    <div className="empty-state">
                        <h2>ORCA_READY</h2>
                        <p>Select a threat actor from the sidebar to view the intelligence dossier.</p>
                    </div>
                ) : (
                    <div className="intel-content">
                        <header className="intel-header">
                            <h1>{intelData.name || "Threat Intelligence Dossier"}</h1>
                            <div className="stats-bar">
                                <span>Status: ACTIVE_INVESTIGATION</span>
                                <span>Techniques: {intelData.linkedTechniques?.length || 0}</span>
                            </div>
                        </header>

                        <div className="intel-body">
                           {/* Detailed Dossier Content or Matrix would be injected here */}
                           <p>{intelData.description || "No description provided."}</p>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default MitreBrowser;