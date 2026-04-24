import React, { useState, useEffect } from 'react';
import '../styles/AssignCCTV.css';

const AssignCCTV = ({ selectedFloorId }) => {
  const [floors, setFloors] = useState([]);
  const [cctvs, setCCTVs] = useState([]);
  const [selectedFloor, setSelectedFloor] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showAddCCTVForm, setShowAddCCTVForm] = useState(false);
  const [cctvFormData, setCCTVFormData] = useState({
    name: '',
    location: '',
    ipAddress: ''
  });

  useEffect(() => {
    fetchFloors();
  }, []);

  useEffect(() => {
    if (selectedFloor) {
      fetchCCTVsByFloor();
    }
  }, [selectedFloor]);

  const fetchFloors = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('authToken');
      const response = await fetch('http://localhost:5000/api/floors', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setFloors(data.floors || []);
        if (data.floors && data.floors.length > 0) {
          setSelectedFloor(selectedFloorId || data.floors[0].id);
        }
        setError(null);
      }
    } catch (err) {
      console.error('Error fetching floors:', err);
      setError('Failed to load floors');
    } finally {
      setLoading(false);
    }
  };

  const fetchCCTVsByFloor = async () => {
    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`http://localhost:5000/api/cctvs/floor/${selectedFloor}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        setCCTVs(data.cctvs || []);
      }
    } catch (err) {
      console.error('Error fetching CCTVs:', err);
    }
  };

  const currentFloor = floors.find(f => f.id === selectedFloor);
  const floorCCTVs = cctvs.filter(c => c.floorId === selectedFloor);
  const availableCCTVs = cctvs.filter(c => !c.floorId || c.floorId !== selectedFloor);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setCCTVFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleAddCCTV = async (e) => {
    e.preventDefault();
    if (!cctvFormData.name || !cctvFormData.location || !cctvFormData.ipAddress) {
      alert('Please fill in all fields');
      return;
    }

    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch('http://localhost:5000/api/cctvs', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: cctvFormData.name,
          location: cctvFormData.location,
          ipAddress: cctvFormData.ipAddress,
          floorId: selectedFloor,
          status: 'active'
        })
      });

      if (response.ok) {
        const data = await response.json();
        await fetchCCTVsByFloor();
        setCCTVFormData({ name: '', location: '', ipAddress: '' });
        setShowAddCCTVForm(false);
        alert('CCTV added successfully');
      } else {
        alert('Failed to add CCTV');
      }
    } catch (err) {
      console.error('Error adding CCTV:', err);
      alert('Error adding CCTV');
    }
  };

  const handleAssignCCTV = async (cctvId) => {
    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`http://localhost:5000/api/cctvs/${cctvId}/assign`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ floorId: selectedFloor })
      });

      if (response.ok) {
        await fetchCCTVsByFloor();
      }
    } catch (err) {
      console.error('Error assigning CCTV:', err);
    }
  };

  const handleUnassignCCTV = async (cctvId) => {
    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`http://localhost:5000/api/cctvs/${cctvId}/unassign`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        await fetchCCTVsByFloor();
      }
    } catch (err) {
      console.error('Error unassigning CCTV:', err);
    }
  };

  return (
    <div className="assign-cctv-container">
      <div className="assign-header">
        <h2>Assign CCTVs to Floors</h2>
        <button 
          className="btn-add-cctv"
          onClick={() => setShowAddCCTVForm(true)}
          disabled={loading}
        >
          ➕ Add New CCTV
        </button>
      </div>

      {loading && <div style={{ textAlign: 'center', padding: '20px', color: '#1B4332' }}>⏳ Loading floors...</div>}
      {error && <div style={{ textAlign: 'center', padding: '20px', color: 'red' }}>❌ {error}</div>}

      {!loading && !error && floors.length > 0 && (
        <>
          {/* Floor Selection */}
          <div className="floor-selector-wrapper">
            <label>Select Floor:</label>
            <select 
              value={selectedFloor || ''} 
              onChange={(e) => setSelectedFloor(parseInt(e.target.value))}
              className="floor-selector"
            >
              <option value="">-- Select a Floor --</option>
              {floors.map(floor => (
                <option key={floor.id} value={floor.id}>
                  {floor.name} (Level {floor.level})
                </option>
              ))}
            </select>
          </div>

          {currentFloor && (
            <div className="current-floor-info">
              <h3>Floor Details: {currentFloor.name}</h3>
              <div className="floor-stats">
                <div className="stat">
                  <span className="stat-label">Level:</span>
                  <span className="stat-value">{currentFloor.level}</span>
                </div>
                <div className="stat">
                  <span className="stat-label">Area:</span>
                  <span className="stat-value">{currentFloor.area} sq.m</span>
                </div>
                <div className="stat">
                  <span className="stat-label">Assigned CCTVs:</span>
                  <span className="stat-value badge">{floorCCTVs.length}</span>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* Add CCTV Form */}
      {showAddCCTVForm && (
        <div className="cctv-form-wrapper">
          <div className="cctv-form">
            <h3>Add New CCTV Camera</h3>
            <form onSubmit={handleAddCCTV}>
              <div className="form-group">
                <label>CCTV Name *</label>
                <input
                  type="text"
                  name="name"
                  value={cctvFormData.name}
                  onChange={handleInputChange}
                  placeholder="e.g., CCTV-006"
                  required
                />
              </div>

              <div className="form-group">
                <label>Location *</label>
                <input
                  type="text"
                  name="location"
                  value={cctvFormData.location}
                  onChange={handleInputChange}
                  placeholder="e.g., Entrance, Production Area"
                  required
                />
              </div>

              <div className="form-group">
                <label>IP Address *</label>
                <input
                  type="text"
                  name="ipAddress"
                  value={cctvFormData.ipAddress}
                  onChange={handleInputChange}
                  placeholder="e.g., 192.168.1.20"
                  required
                />
              </div>

              <div className="form-actions">
                <button type="submit" className="btn-submit">
                  Add CCTV
                </button>
                <button 
                  type="button" 
                  className="btn-cancel"
                  onClick={() => setShowAddCCTVForm(false)}
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {!loading && !error && currentFloor && (
        <div className="cctv-assignment-grid">
        {/* Assigned CCTVs */}
        <div className="assigned-section">
          <h4>Assigned CCTVs ({floorCCTVs.length})</h4>
          {floorCCTVs.length === 0 ? (
            <div className="empty-state">
              <p>No CCTVs assigned to this floor yet.</p>
            </div>
          ) : (
            <div className="cctv-list">
              {floorCCTVs.map(cctv => (
                <div key={cctv.id} className="cctv-item assigned">
                  <div className="cctv-info">
                    <h5>{cctv.name}</h5>
                    <p className="cctv-location">📍 {cctv.location}</p>
                    <p className="cctv-ip">🌐 {cctv.ipAddress}</p>
                    <span className={`cctv-status ${cctv.status}`}>
                      ● {cctv.status}
                    </span>
                  </div>
                  <button 
                    className="btn-remove"
                    onClick={() => handleUnassignCCTV(cctv.id)}
                    title="Unassign this CCTV"
                  >
                    ➖ Remove
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Available CCTVs */}
        <div className="available-section">
          <h4>Available CCTVs ({availableCCTVs.length})</h4>
          {availableCCTVs.length === 0 ? (
            <div className="empty-state">
              <p>All CCTVs are assigned. Add more or unassign from other floors.</p>
            </div>
          ) : (
            <div className="cctv-list">
              {availableCCTVs.map(cctv => (
                <div key={cctv.id} className="cctv-item available">
                  <div className="cctv-info">
                    <h5>{cctv.name}</h5>
                    <p className="cctv-location">📍 {cctv.location}</p>
                    <p className="cctv-ip">🌐 {cctv.ipAddress}</p>
                    <span className={`cctv-status ${cctv.status}`}>
                      ● {cctv.status}
                    </span>
                  </div>
                  <button 
                    className="btn-assign"
                    onClick={() => handleAssignCCTV(cctv.id)}
                    title="Assign this CCTV"
                  >
                    ➕ Assign
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
      )}
    </div>
  );
};

export default AssignCCTV;
