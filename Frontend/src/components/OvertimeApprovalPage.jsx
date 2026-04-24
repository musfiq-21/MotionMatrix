import React, { useState, useEffect } from 'react';
import '../styles/OvertimeApprovalPage.css';

export default function OvertimeApprovalPage({ user }) {
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState('');

  useEffect(() => {
    fetchRequests();
  }, [user]);

  const fetchRequests = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('authToken');
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      };

      // Fetch overtime requests for this floor manager
      const response = await fetch('http://localhost:5000/api/overtime/floor-manager/requests', { headers });
      if (response.ok) {
        const data = await response.json();
        // Handle both direct array and wrapped response
        const requestsList = Array.isArray(data) ? data : (data.overtimeRequests || []);
        setRequests(requestsList);
      } else {
        console.error('Failed to load requests:', response.status);
        setError('Failed to load overtime requests');
      }
    } catch (err) {
      console.error('Error fetching requests:', err);
      setError('Failed to load overtime requests');
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (requestId) => {
    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`http://localhost:5000/api/overtime/${requestId}/approve`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        setSuccessMessage('Overtime request approved!');
        await fetchRequests(); // Refresh the list
        setTimeout(() => setSuccessMessage(''), 2000);
      } else {
        const errorData = await response.json();
        alert(errorData.message || 'Failed to approve request');
      }
    } catch (err) {
      console.error('Error approving request:', err);
      alert('Failed to approve request');
    }
  };

  const handleReject = async (requestId) => {
    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`http://localhost:5000/api/overtime/${requestId}/reject`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        setSuccessMessage('Overtime request rejected!');
        await fetchRequests(); // Refresh the list
        setTimeout(() => setSuccessMessage(''), 2000);
      } else {
        const errorData = await response.json();
        alert(errorData.message || 'Failed to reject request');
      }
    } catch (err) {
      console.error('Error rejecting request:', err);
      alert('Failed to reject request');
    }
  };

  const pendingRequests = requests.filter(r => r.status === 'pending');
  const approvedRequests = requests.filter(r => r.status === 'approved');
  const rejectedRequests = requests.filter(r => r.status === 'rejected');

  const OvertimeRequestRow = ({ request, status }) => (
    <div className="overtime-request-card">
      <div className="request-header">
        <h4>{request.worker?.name || 'Unknown Worker'}</h4>
        <span className={`request-status status-${status}`}>{status.toUpperCase()}</span>
      </div>
      <div className="request-details">
        <div className="detail-item">
          <span className="label">Date:</span>
          <span className="value">
            {new Date(request.date).toLocaleDateString('en-US', { 
              month: 'short', 
              day: 'numeric', 
              year: 'numeric' 
            })}
          </span>
        </div>
        <div className="detail-item">
          <span className="label">Hours:</span>
          <span className="value">{request.hours} hours</span>
        </div>
        <div className="detail-item">
          <span className="label">Reason:</span>
          <span className="value">{request.reason}</span>
        </div>
        <div className="detail-item">
          <span className="label">Submitted:</span>
          <span className="value">
            {new Date(request.submittedAt).toLocaleDateString()}
          </span>
        </div>
      </div>
      
      {status === 'pending' && (
        <div className="request-actions">
          <button 
            className="btn-approve"
            onClick={() => handleApprove(request.id)}
          >
            ✓ Approve
          </button>
          <button 
            className="btn-reject"
            onClick={() => handleReject(request.id)}
          >
            ✗ Reject
          </button>
        </div>
      )}
    </div>
  );

  return (
    <div className="overtime-approval-page">
      <div className="fm-page-header">
        <h2>Overtime Approval Management</h2>
        <p>Review and manage worker overtime requests</p>
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

      {loading ? (
        <div className="loading">Loading overtime requests...</div>
      ) : (
        <>
          {/* Pending Requests */}
          <section className="overtime-section">
            <h3>⏳ Pending Requests ({pendingRequests.length})</h3>
            <div className="requests-container">
              {pendingRequests.length === 0 ? (
                <div className="no-requests">
                  <p>No pending overtime requests</p>
                </div>
              ) : (
                pendingRequests.map(request => (
                  <OvertimeRequestRow 
                    key={request.id} 
                    request={request} 
                    status="pending"
                  />
                ))
              )}
            </div>
          </section>

          {/* Approved Requests */}
          <section className="overtime-section">
            <h3>✅ Approved ({approvedRequests.length})</h3>
            <div className="requests-container">
              {approvedRequests.length === 0 ? (
                <div className="no-requests">
                  <p>No approved requests</p>
                </div>
              ) : (
                approvedRequests.map(request => (
                  <OvertimeRequestRow 
                    key={request.id} 
                    request={request} 
                    status="approved"
                  />
                ))
              )}
            </div>
          </section>

          {/* Rejected Requests */}
          <section className="overtime-section">
            <h3>❌ Rejected ({rejectedRequests.length})</h3>
            <div className="requests-container">
              {rejectedRequests.length === 0 ? (
                <div className="no-requests">
                  <p>No rejected requests</p>
                </div>
              ) : (
                rejectedRequests.map(request => (
                  <OvertimeRequestRow 
                    key={request.id} 
                    request={request} 
                    status="rejected"
                  />
                ))
              )}
            </div>
          </section>
        </>
      )}
    </div>
  );
}
