import React, { useState, useEffect } from 'react';
import '../styles/OvertimeRequest.css';

export default function OvertimeRequest({ user }) {
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({
    date: '',
    hours: '',
    reason: ''
  });
  const [requests, setRequests] = useState([]);
  const [floorManager, setFloorManager] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState('');

  useEffect(() => {
    fetchUserAndFloorManager();
  }, []);

  const fetchUserAndFloorManager = async () => {
    try {
      const token = localStorage.getItem('authToken');
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      };

      // Get current user's assigned floor from the backend
      const userRes = await fetch('http://localhost:5000/api/auth/me', { headers });
      if (!userRes.ok) throw new Error('Failed to fetch user');
      
      const userData = await userRes.json();
      const assignedFloorId = userData.user?.assignedFloorId;

      if (assignedFloorId) {
        // Get floor manager for this floor
        const managerRes = await fetch(`http://localhost:5000/api/users/floor-manager/${assignedFloorId}`, { headers });
        if (managerRes.ok) {
          const managerData = await managerRes.json();
          if (managerData.success && managerData.floorManager) {
            setFloorManager(managerData.floorManager);
          }
        }
      }
      
      setError(null);
    } catch (err) {
      console.error('Error fetching user/floor manager:', err);
      setError('Failed to load overtime data');
    }
    
    fetchRequests();
  };

  const fetchRequests = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('authToken');
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      };

      // Fetch worker's overtime requests
      const requestsRes = await fetch('http://localhost:5000/api/overtime/my-requests', { headers });
      if (requestsRes.ok) {
        const requestsData = await requestsRes.json();
        setRequests(requestsData.overtimeRequests || []);
      }
    } catch (err) {
      console.error('Error fetching requests:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchData = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('authToken');
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      };

      // Get floor manager info for assigned floor
      if (user?.assignedFloorId) {
        try {
          const managerRes = await fetch(`http://localhost:5000/api/users/floor-manager/${user.assignedFloorId}`, { headers });
          if (managerRes.ok) {
            const managerData = await managerRes.json();
            if (managerData.success && managerData.floorManager) {
              setFloorManager(managerData.floorManager);
            }
          } else {
            console.warn('⚠️ Floor manager not found for this floor');
          }
        } catch (fmError) {
          console.error('Error fetching floor manager:', fmError);
        }
      } else {
        console.warn('⚠️ User is not assigned to a floor');
      }

      // Fetch worker's overtime requests
      const requestsRes = await fetch('http://localhost:5000/api/overtime/my-requests', { headers });
      if (requestsRes.ok) {
        const requestsData = await requestsRes.json();
        setRequests(requestsData.overtimeRequests || []);
      } else {
        console.warn('⚠️ Failed to fetch overtime requests');
      }

      setError(null);
    } catch (err) {
      console.error('Error fetching data:', err);
      setError('Failed to load overtime data');
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmitRequest = async () => {
    if (!formData.date || !formData.hours || !formData.reason.trim()) {
      alert('Please fill in all fields');
      return;
    }

    try {
      const token = localStorage.getItem('authToken');
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      };

      // Get current user to get assignedFloorId
      const userRes = await fetch('http://localhost:5000/api/auth/me', { headers });
      if (!userRes.ok) throw new Error('Failed to get user info');
      
      const userData = await userRes.json();
      const assignedFloorId = userData.user?.assignedFloorId;

      if (!assignedFloorId) {
        alert('You are not assigned to a floor');
        return;
      }

      // Get floor manager for this floor
      const managerRes = await fetch(`http://localhost:5000/api/users/floor-manager/${assignedFloorId}`, { headers });
      if (!managerRes.ok) throw new Error('Floor manager not found');
      
      const managerData = await managerRes.json();
      const floorManagerId = managerData.floorManager?.id;

      if (!floorManagerId) {
        alert('Floor manager not found for your floor');
        return;
      }

      // Submit the overtime request
      const response = await fetch('http://localhost:5000/api/overtime/submit', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          floorManagerId,
          date: formData.date,
          hours: parseInt(formData.hours),
          reason: formData.reason.trim()
        })
      });

      if (response.ok) {
        const newRequestData = await response.json();
        const newRequest = newRequestData.overtimeRequest || newRequestData;
        setRequests([newRequest, ...requests]);
        setFormData({ date: '', hours: '', reason: '' });
        setShowForm(false);
        setSuccessMessage('Overtime request submitted successfully!');
        setTimeout(() => setSuccessMessage(''), 3000);
      } else {
        const errorData = await response.json();
        alert(errorData.message || 'Failed to submit overtime request');
      }
    } catch (err) {
      console.error('Error submitting request:', err);
      alert('Error: ' + err.message);
    }
  };

  const getStatusColor = (status) => {
    switch(status) {
      case 'pending':
        return '#D97706';
      case 'approved':
        return '#10B981';
      case 'rejected':
        return '#EF4444';
      default:
        return '#1B4332';
    }
  };

  const getTodayDate = () => {
    const today = new Date();
    return today.toISOString().split('T')[0];
  };

  return (
    <div className="overtime-request-container">
      <div className="overtime-header">
        <h2>⏰ Overtime Request</h2>
        <button 
          className="btn-request-overtime"
          onClick={() => setShowForm(!showForm)}
        >
          {showForm ? '✕ Cancel' : '➕ New Request'}
        </button>
      </div>

      {successMessage && (
        <div className="success-message">
          ✓ {successMessage}
        </div>
      )}

      {error && (
        <div className="error-message">
          ✕ {error}
        </div>
      )}

      {/* Request Form */}
      {showForm && (
        <div className="overtime-form-wrapper">
          <div className="overtime-form">
            <h3>Submit Overtime Request</h3>

            {floorManager ? (
              <div className="manager-assigned">
                <p>📋 Floor Manager: <strong>{floorManager.name}</strong></p>
                <p className="manager-contact">📧 {floorManager.email}</p>
              </div>
            ) : (
              <div className="no-manager">
                <p>⚠️ No floor manager assigned to your floor. Please contact administration.</p>
              </div>
            )}

            <div className="form-group">
              <label>Date *</label>
              <input
                type="date"
                name="date"
                value={formData.date}
                onChange={handleInputChange}
                min={getTodayDate()}
                required
              />
            </div>

            <div className="form-row">
              <div className="form-group">
                <label>Hours *</label>
                <input
                  type="number"
                  name="hours"
                  value={formData.hours}
                  onChange={handleInputChange}
                  min="1"
                  max="8"
                  placeholder="1-8 hours"
                  required
                />
              </div>
            </div>

            <div className="form-group">
              <label>Reason for Overtime *</label>
              <textarea
                name="reason"
                value={formData.reason}
                onChange={handleInputChange}
                placeholder="Explain why you need overtime..."
                rows="4"
                required
              />
            </div>

            <div className="form-actions">
              <button 
                className="btn-submit"
                onClick={handleSubmitRequest}
                disabled={!formData.date || !formData.hours || !formData.reason.trim()}
              >
                ✓ Submit Request
              </button>
              <button 
                className="btn-cancel"
                onClick={() => setShowForm(false)}
              >
                ✕ Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Requests List */}
      <div className="requests-list">
        <h3>Your Overtime Requests</h3>

        {loading ? (
          <div className="loading">Loading overtime requests...</div>
        ) : requests.length === 0 ? (
          <div className="no-requests">
            <p>No overtime requests submitted yet.</p>
          </div>
        ) : (
          <div className="requests-grid">
            {requests.map(request => (
              <div key={request.id} className="request-card">
                <div className="request-header">
                  <div className="request-date">
                    <p className="date-label">Date</p>
                    <p className="date-value">
                      {new Date(request.date).toLocaleDateString('en-US', { 
                        month: 'short', 
                        day: 'numeric', 
                        year: 'numeric' 
                      })}
                    </p>
                  </div>
                  <div 
                    className="status-badge"
                    style={{ backgroundColor: `${getStatusColor(request.status)}20`, borderLeft: `4px solid ${getStatusColor(request.status)}` }}
                  >
                    <span style={{ color: getStatusColor(request.status), fontWeight: '600' }}>
                      {request.status.toUpperCase()}
                    </span>
                  </div>
                </div>

                <div className="request-body">
                  <div className="request-detail">
                    <span className="label">Hours:</span>
                    <span className="value">{request.hours} hours</span>
                  </div>
                  <div className="request-detail">
                    <span className="label">Reason:</span>
                    <span className="value">{request.reason}</span>
                  </div>
                  <div className="request-detail">
                    <span className="label">Submitted:</span>
                    <span className="value">
                      {new Date(request.submittedAt).toLocaleDateString()}
                    </span>
                  </div>
                </div>

                <div className="request-footer">
                  {request.floorManager && (
                    <p className="manager-note">
                      📌 Assigned to: <strong>{request.floorManager.name}</strong>
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
