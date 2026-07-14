import React, { useState } from 'react';

const AssetActionTab = ({ assetId, assetName, setInvestigatingAsset, setTimelineAsset }) => {
  const [selectedAction, setSelectedAction] = useState("Investigate");
  const [isExecuting, setIsExecuting] = useState(false);

  const handleExecute = async () => {
    setIsExecuting(true);
    try {
      if (selectedAction === "Investigate") {
        if (setInvestigatingAsset) setInvestigatingAsset(assetId);
      } else if (selectedAction === "Timeline") {
        if (setTimelineAsset) setTimelineAsset(assetId);
      } else if (selectedAction === "Reports") {
        alert("REPORTS: Module not yet implemented.");
      }
    } catch (err) {
      console.error("EXECUTION_UPLINK_FAILURE:", err);
      alert("CRITICAL: Failed to connect to backend service.");
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
      <select
        value={selectedAction}
        onChange={e => setSelectedAction(e.target.value)}
        disabled={isExecuting}
        style={SelectStyle}
      >
        <option value="Investigate">INVESTIGATE</option>
        <option value="Timeline">TIMELINE</option>
        <option value="Reports">REPORTS</option>
      </select>
      <button
        onClick={handleExecute}
        disabled={isExecuting}
        style={{ ...ExecuteBtn, opacity: isExecuting ? 0.5 : 1 }}
      >
        {isExecuting ? "PROCESSING..." : "EXECUTE"}
      </button>
    </div>
  );
};

const SelectStyle = {
  padding: '6px', background: '#000', color: '#00ff41',
  border: '1px solid #1a1a1a', fontSize: '11px', fontFamily: 'monospace',
  outline: 'none', flex: 1
};
const ExecuteBtn = {
  padding: '6px 15px', background: '#00ff41', color: '#000',
  border: 'none', cursor: 'pointer', fontWeight: 'bold',
  fontSize: '11px', fontFamily: 'monospace'
};

export default AssetActionTab;
