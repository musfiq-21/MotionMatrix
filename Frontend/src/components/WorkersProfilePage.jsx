import React, { useState, useEffect } from 'react';
import '../styles/WorkersProfilePage.css';

export default function WorkersProfilePage({ user }) {
  const [assignedWorkers, setAssignedWorkers] = useState([]);
  const [unassignedWorkers, setUnassignedWorkers] = useState([]);
  const [floors, setFloors] = useState([]);
  const [selectedWorker, setSelectedWorker] = useState(null);
  const [selectedFloor, setSelectedFloor] = useState('');
  const [showAssignModal, setShowAssignModal] = useState(false);
  const [showMessageModal, setShowMessageModal] = useState(false);
  const [messageText, setMessageText] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState('');

  useEffect(() => {
    fetchData();
  }, [user]);

  const fetchData = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('authToken');
      const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      };

      // Fetch floors
      const floorsRes = await fetch('http://localhost:5000/api/floors', { headers });
      if (floorsRes.ok) {
        const floorsData = await floorsRes.json();
        setFloors(floorsData.floors || []);
      }

      // Fetch assigned workers for this floor manager
      if (user?.assignedFloorId) {
        const assignedRes = await fetch(`http://localhost:5000/api/users/floor/${user.assignedFloorId}`, { headers });
        if (assignedRes.ok) {
          const assignedData = await assignedRes.json();
          // New endpoint returns { floorManager, workers, count }
          setAssignedWorkers(assignedData.workers || []);
        }
      }

      // Fetch unassigned workers
      const unassignedRes = await fetch('http://localhost:5000/api/users/workers/unassigned', { headers });
      if (unassignedRes.ok) {
        const unassignedData = await unassignedRes.json();
        setUnassignedWorkers(unassignedData.workers || []);
      }

      setError(null);
    } catch (err) {
      console.error('Error fetching data:', err);
      setError('Failed to load worker data');
    } finally {
      setLoading(false);
    }
  };

  const handleAssignClick = (worker) => {
    setSelectedWorker(worker);
    setSelectedFloor(user?.assignedFloorId || '');
    setShowAssignModal(true);
  };

  const handleAssignWorker = async () => {
    if (!selectedWorker || !selectedFloor) {
      alert('Please select a floor');
      return;
    }

    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`http://localhost:5000/api/users/${selectedWorker.id}/assign-floor`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ assignedFloorId: parseInt(selectedFloor) })
      });

      if (response.ok) {
        setSuccessMessage(`${selectedWorker.name} has been assigned to the floor!`);
        setShowAssignModal(false);
        setTimeout(() => setSuccessMessage(''), 3000);
        // Refresh the worker lists
        fetchData();
      } else {
        const errorData = await response.json();
        alert(errorData.message || 'Failed to assign worker');
      }
    } catch (err) {
      console.error('Error assigning worker:', err);
      alert('Error assigning worker');
    }
  };

  const handleSendMessage = (worker) => {
    setSelectedWorker(worker);
    setMessageText('');
    setShowMessageModal(true);
  };

  const handleSubmitMessage = async () => {
    if (!messageText.trim()) {
      alert('Please enter a message');
      return;
    }

    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch('http://localhost:5000/api/messages', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          toId: selectedWorker.id,
          content: messageText.trim()
        })
      });

      if (response.ok) {
        setSuccessMessage('Message sent successfully!');
        setShowMessageModal(false);
        setTimeout(() => setSuccessMessage(''), 2000);
      } else {
        alert('Failed to send message');
      }
    } catch (err) {
      console.error('Error sending message:', err);
      alert('Error sending message');
    }
  };

  const WorkerCard = ({ worker, isAssigned }) => (
    <div className="worker-card">
      <div className="worker-card-avatar">👤</div>
      <div className="worker-card-info">
        <h4>{worker.name}</h4>
        <p className="worker-department">{worker.department}</p>
        <p className="worker-position">{worker.position}</p>
        <p className="worker-phone">📞 {worker.phone}</p>
        {worker.assignedFloorId && (
          <p className="worker-floor">🏢 Floor #{worker.assignedFloorId}</p>
        )}
      </div>
      <div className="worker-card-actions">
        {isAssigned && (
          <button 
            className="btn-message"
            onClick={() => handleSendMessage(worker)}
            title="Send message to worker"
          >
            💬 Message
          </button>
        )}
        <button 
          className="btn-assign"
          onClick={() => handleAssignClick(worker)}
          title="Assign worker to floor"
        >
          📍 {isAssigned ? 'Reassign' : 'Assign'}
        </button>
      </div>
    </div>
  );

  return (
    <div className="workers-profile-page">
      <div className="fm-page-header">
        <h2>Workers Profile Management</h2>
        <p>Manage assigned and unassigned workers for your floor</p>
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

      <div className="workers-profile-container">
        {/* Assigned Workers Section */}
        <section className="workers-section">
          <div className="section-header">
            <h3>Assigned Workers ({assignedWorkers.length})</h3>
            <p>Workers currently assigned to your floor</p>
          </div>
          
          {loading ? (
            <div className="loading">Loading workers...</div>
          ) : assignedWorkers.length === 0 ? (
            <div className="no-workers-message">
              <p>No workers assigned to your floor yet</p>
            </div>
          ) : (
            <div className="workers-grid">
              {assignedWorkers.map(worker => (
                <WorkerCard key={worker.id} worker={worker} isAssigned={true} />
              ))}
            </div>
          )}
        </section>

        {/* Unassigned Workers Section */}
        <section className="workers-section">
          <div className="section-header">
            <h3>Available Workers ({unassignedWorkers.length})</h3>
            <p>Workers available to assign to your floor</p>
          </div>

          {loading ? (
            <div className="loading">Loading workers...</div>
          ) : unassignedWorkers.length === 0 ? (
            <div className="no-workers-message">
              <p>No unassigned workers available</p>
            </div>
          ) : (
            <div className="workers-grid">
              {unassignedWorkers.map(worker => (
                <WorkerCard key={worker.id} worker={worker} isAssigned={false} />
              ))}
            </div>
          )}
        </section>
      </div>

      {/* Assignment Modal */}
      {showAssignModal && selectedWorker && (
        <div className="modal-overlay" onClick={() => setShowAssignModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Assign Worker to Floor</h3>
              <button className="modal-close" onClick={() => setShowAssignModal(false)}>✕</button>
            </div>
            <div className="modal-body">
              <div className="assignment-info">
                <p><strong>Worker:</strong> {selectedWorker.name}</p>
                <p><strong>Department:</strong> {selectedWorker.department}</p>
                <p><strong>Position:</strong> {selectedWorker.position}</p>
              </div>

              <div className="form-group">
                <label>Select Floor *</label>
                <select 
                  value={selectedFloor} 
                  onChange={(e) => setSelectedFloor(e.target.value)}
                  className="floor-select"
                >
                  <option value="">Choose a floor</option>
                  {floors.map(floor => (
                    <option key={floor.id} value={floor.id}>
                      {floor.name} (Level {floor.level})
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="modal-footer">
              <button 
                className="btn-cancel" 
                onClick={() => setShowAssignModal(false)}
              >
                Cancel
              </button>
              <button 
                className="btn-assign-confirm" 
                onClick={handleAssignWorker}
                disabled={!selectedFloor}
              >
                Assign Worker
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Message Modal */}
      {showMessageModal && selectedWorker && (
        <div className="modal-overlay" onClick={() => setShowMessageModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>Send Message to {selectedWorker.name}</h3>
              <button className="modal-close" onClick={() => setShowMessageModal(false)}>✕</button>
            </div>
            <div className="modal-body">
              <textarea
                className="message-input"
                placeholder="Type your message here..."
                value={messageText}
                onChange={(e) => setMessageText(e.target.value)}
                rows={6}
              />
            </div>
            <div className="modal-footer">
              <button 
                className="btn-cancel" 
                onClick={() => setShowMessageModal(false)}
              >
                Cancel
              </button>
              <button 
                className="btn-send" 
                onClick={handleSubmitMessage}
              >
                Send Message
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
