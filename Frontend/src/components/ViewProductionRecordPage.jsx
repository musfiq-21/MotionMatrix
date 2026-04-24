import React, { useState, useEffect } from 'react';
import '../styles/ViewProductionRecordPage.css';

const SHIFT_MAP = {
  'Morning': 1,
  'Afternoon': 2,
  'Evening': 3,
  'Night': 4
};

const SHIFT_NAMES = {
  1: 'Morning',
  2: 'Afternoon',
  3: 'Evening',
  4: 'Night'
};

export default function ViewProductionRecordPage({ user, floorManagerId, department }) {
  const [records, setRecords] = useState([]);
  const [showAddForm, setShowAddForm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [floorId, setFloorId] = useState(null);
  const [target, setTarget] = useState(100);
  const [formData, setFormData] = useState({
    shift: 'Morning',
    workersCount: '',
    produced: '',
    qualityRate: '',
    notes: ''
  });

  // Get floor ID from props or localStorage
  useEffect(() => {
    let id = null;
    
    // Try to get from props first
    if (user?.assignedFloorId) {
      id = user.assignedFloorId;
    } else {
      // Try to get from localStorage (multiple possible keys)
      const floorManagerUser = localStorage.getItem('floorManagerUser');
      const adminUser = localStorage.getItem('adminUser');
      const workerUser = localStorage.getItem('workerUser');
      
      let userData = null;
      if (floorManagerUser) userData = JSON.parse(floorManagerUser);
      if (adminUser) userData = JSON.parse(adminUser);
      if (workerUser) userData = JSON.parse(workerUser);
      
      if (userData?.assignedFloorId) {
        id = userData.assignedFloorId;
      }
    }

    if (id) {
      setFloorId(id);
    } else {
      setError('No floor assigned to your account');
    }
  }, [user]);

  // Fetch production records
  const fetchRecords = async () => {
    if (!floorId) return;
    
    setLoading(true);
    setError('');
    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`http://localhost:5000/api/production-records/floor/${floorId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (!response.ok) {
        throw new Error(`Failed to fetch records: ${response.statusText}`);
      }

      const data = await response.json();
      setRecords(data);
    } catch (err) {
      console.error('Error fetching production records:', err);
      setError('Failed to load production records');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (floorId) {
      fetchRecords();
    }
  }, [floorId]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleAddRecord = async (e) => {
    e.preventDefault();
    
    if (!formData.workersCount || !formData.produced || !formData.qualityRate) {
      setError('Please fill in all required fields');
      return;
    }

    setLoading(true);
    setError('');
    
    try {
      const token = localStorage.getItem('authToken');
      const userName = user?.name || 'Floor Manager';
      
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      const payload = {
        floorId,
        date: today.toISOString(),
        shift: SHIFT_MAP[formData.shift],
        workersCount: parseInt(formData.workersCount),
        produced: parseInt(formData.produced),
        target: parseInt(target),
        qualityRate: parseFloat(formData.qualityRate),
        notes: formData.notes || null
      };

      const response = await fetch('http://localhost:5000/api/production-records', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to create production record');
      }

      const newRecord = await response.json();
      setRecords([newRecord, ...records]);
      setFormData({
        shift: 'Morning',
        workersCount: '',
        produced: '',
        qualityRate: '',
        notes: ''
      });
      setShowAddForm(false);
    } catch (err) {
      console.error('Error adding production record:', err);
      setError(err.message || 'Failed to add production record');
    } finally {
      setLoading(false);
    }
  };

  const calculateStats = () => {
    if (records.length === 0) return { avgProduction: 0, avgQuality: 0, totalWorkers: 0 };
    
    const totalProduction = records.reduce((sum, r) => sum + r.produced, 0);
    const avgProduction = Math.round(totalProduction / records.length);
    const totalQuality = records.reduce((sum, r) => sum + (r.qualityRate || 0), 0);
    const avgQuality = (totalQuality / records.length).toFixed(2);
    const totalWorkers = records.reduce((sum, r) => sum + r.workersCount, 0);

    return { avgProduction, avgQuality, totalWorkers };
  };

  const stats = calculateStats();
  const floorName = floorId ? `Floor ${floorId}` : 'Loading...';

  if (!floorId) {
    return (
      <div className="production-record-page">
        <div className="fm-page-header">
          <h2>Production Records</h2>
          <p>Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="production-record-page">
      <div className="fm-page-header">
        <h2>Production Records - {floorName}</h2>
        <p>Track and manage floor production history</p>
      </div>

      {error && <div className="error-message">{error}</div>}

      {/* Stats Overview */}
      <div className="production-stats-grid">
        <div className="production-stat-card">
          <div className="stat-icon">📊</div>
          <div className="stat-info">
            <h4>Average Production</h4>
            <p className="stat-value">{stats.avgProduction} units</p>
          </div>
        </div>
        <div className="production-stat-card">
          <div className="stat-icon">⭐</div>
          <div className="stat-info">
            <h4>Average Quality</h4>
            <p className="stat-value">{stats.avgQuality}%</p>
          </div>
        </div>
        <div className="production-stat-card">
          <div className="stat-icon">👷</div>
          <div className="stat-info">
            <h4>Total Workers</h4>
            <p className="stat-value">{stats.totalWorkers}</p>
          </div>
        </div>
        <div className="production-stat-card">
          <div className="stat-icon">📝</div>
          <div className="stat-info">
            <h4>Records</h4>
            <p className="stat-value">{records.length}</p>
          </div>
        </div>
      </div>

      {/* Add Production Record Button */}
      <div className="production-action-bar">
        <button 
          className="btn-add-record"
          onClick={() => setShowAddForm(!showAddForm)}
          disabled={loading}
        >
          {showAddForm ? '❌ Cancel' : '➕ Add Production Record'}
        </button>
      </div>

      {/* Add Production Form */}
      {showAddForm && (
        <div className="add-record-form-wrapper">
          <form className="add-record-form" onSubmit={handleAddRecord}>
            <h3>New Production Record</h3>
            
            <div className="form-grid">
              <div className="form-group">
                <label>Shift</label>
                <select 
                  name="shift"
                  value={formData.shift}
                  onChange={handleInputChange}
                >
                  <option>Morning</option>
                  <option>Afternoon</option>
                  <option>Evening</option>
                  <option>Night</option>
                </select>
              </div>

              <div className="form-group">
                <label>Workers Count *</label>
                <input 
                  type="number"
                  name="workersCount"
                  value={formData.workersCount}
                  onChange={handleInputChange}
                  placeholder="e.g., 15"
                  required
                />
              </div>

              <div className="form-group">
                <label>Target Production</label>
                <input 
                  type="number"
                  value={target}
                  onChange={(e) => setTarget(parseInt(e.target.value))}
                  placeholder="e.g., 500"
                />
              </div>

              <div className="form-group">
                <label>Units Produced *</label>
                <input 
                  type="number"
                  name="produced"
                  value={formData.produced}
                  onChange={handleInputChange}
                  placeholder="e.g., 450"
                  required
                />
              </div>

              <div className="form-group">
                <label>Quality Rate (%) *</label>
                <input 
                  type="number"
                  name="qualityRate"
                  step="0.1"
                  min="0"
                  max="100"
                  value={formData.qualityRate}
                  onChange={handleInputChange}
                  placeholder="e.g., 98.5"
                  required
                />
              </div>
            </div>

            <div className="form-group full-width">
              <label>Notes</label>
              <textarea 
                name="notes"
                value={formData.notes}
                onChange={handleInputChange}
                placeholder="Add any notes about the production..."
              />
            </div>

            <div className="form-actions">
              <button type="submit" className="btn-submit" disabled={loading}>
                {loading ? 'Saving...' : 'Save Record'}
              </button>
              <button 
                type="button" 
                className="btn-cancel"
                onClick={() => setShowAddForm(false)}
                disabled={loading}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Production Records List */}
      <div className="production-records-section">
        <h3>Production History</h3>
        {loading && records.length === 0 ? (
          <div className="no-records">
            <p>Loading production records...</p>
          </div>
        ) : records.length === 0 ? (
          <div className="no-records">
            <p>No production records yet. Add one to get started!</p>
          </div>
        ) : (
          <div className="records-table-wrapper">
            <table className="records-table">
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Shift</th>
                  <th>Workers</th>
                  <th>Target</th>
                  <th>Produced</th>
                  <th>Efficiency</th>
                  <th>Quality</th>
                  <th>Recorded By</th>
                  <th>Notes</th>
                </tr>
              </thead>
              <tbody>
                {records.map(record => (
                  <tr key={record.id}>
                    <td className="date-cell">
                      {new Date(record.date).toLocaleDateString()}
                    </td>
                    <td>{SHIFT_NAMES[record.shift]}</td>
                    <td className="center">{record.workersCount}</td>
                    <td className="center">{record.target}</td>
                    <td className="center">{record.produced} units</td>
                    <td className="center">
                      <span className={`efficiency-badge ${record.efficiency >= 95 ? 'excellent' : record.efficiency >= 80 ? 'good' : 'fair'}`}>
                        {record.efficiency}%
                      </span>
                    </td>
                    <td className="center">
                      <span className={`quality-badge ${record.qualityRate >= 98 ? 'excellent' : record.qualityRate >= 95 ? 'good' : 'fair'}`}>
                        {record.qualityRate ? record.qualityRate.toFixed(1) : 'N/A'}%
                      </span>
                    </td>
                    <td>{record.recordedBy}</td>
                    <td className="notes-cell">{record.notes || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
