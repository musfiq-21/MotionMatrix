import React, { useState } from 'react';
import '../styles/WorkerDashboard.css';
import UnifiedChat from './UnifiedChat';
import OvertimeRequest from './OvertimeRequest';
import WorkerProfile from './WorkerProfile';

export default function WorkerDashboard({ user }) {
  const [activeSection, setActiveSection] = useState('dashboard');

  return (
    <div className="worker-dashboard">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <h2>Worker Portal</h2>
        </div>
        <nav className="sidebar-menu">
          <button
            className={`menu-item ${activeSection === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveSection('dashboard')}
          >
            📊 Dashboard
          </button>
          <button
            className={`menu-item ${activeSection === 'chat' ? 'active' : ''}`}
            onClick={() => setActiveSection('chat')}
          >
            💬 Chat
          </button>
          <button
            className={`menu-item ${activeSection === 'overtime' ? 'active' : ''}`}
            onClick={() => setActiveSection('overtime')}
          >
            ⏰ Overtime Request
          </button>
          <button
            className={`menu-item ${activeSection === 'profile' ? 'active' : ''}`}
            onClick={() => setActiveSection('profile')}
          >
            👤 Profile
          </button>
          <button
            className={`menu-item logout-btn`}
            onClick={() => window.location.href = '/'}
          >
            🚪 Logout
          </button>
        </nav>
      </aside>

      {/* Main Content */}
      <main className="content-area">
        {/* Dashboard Section */}
        {activeSection === 'dashboard' && (
          <div className="dashboard-section">
            <div className="welcome-header">
              <h1>Welcome, {user?.name}!</h1>
              <p className="subtitle">Here's your work dashboard</p>
            </div>

            <div className="dashboard-cards">
              <div className="info-card">
                <div className="card-icon">👷</div>
                <h3>Role</h3>
                <p className="card-value">{user?.role?.replace('_', ' ').toUpperCase()}</p>
              </div>

              <div className="info-card">
                <div className="card-icon">🏢</div>
                <h3>Department</h3>
                <p className="card-value">{user?.department}</p>
              </div>

              <div className="info-card">
                <div className="card-icon">📧</div>
                <h3>Email</h3>
                <p className="card-value-small">{user?.email}</p>
              </div>

              <div className="info-card">
                <div className="card-icon">🆔</div>
                <h3>Employee ID</h3>
                <p className="card-value">#{user?.id}</p>
              </div>
            </div>

            <div className="feature-cards">
              <h3>Quick Actions</h3>
              <div className="cards-grid">
                <div className="feature-card">
                  <div className="feature-icon">💬</div>
                  <div className="feature-content">
                    <h4>Chat</h4>
                    <p>Communicate directly with your floor manager about work-related matters and get quick responses.</p>
                    <button 
                      className="feature-btn"
                      onClick={() => setActiveSection('chat')}
                    >
                      Open Chat
                    </button>
                  </div>
                </div>

                <div className="feature-card">
                  <div className="feature-icon">⏰</div>
                  <div className="feature-content">
                    <h4>Overtime Request</h4>
                    <p>Submit overtime requests for additional hours and track the approval status in real-time.</p>
                    <button 
                      className="feature-btn"
                      onClick={() => setActiveSection('overtime')}
                    >
                      Request Overtime
                    </button>
                  </div>
                </div>

                <div className="feature-card">
                  <div className="feature-icon">👤</div>
                  <div className="feature-content">
                    <h4>Profile</h4>
                    <p>View and manage your profile information including role, department, and contact details.</p>
                    <button 
                      className="feature-btn"
                      onClick={() => setActiveSection('profile')}
                    >
                      View Profile
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Chat Section */}
        {activeSection === 'chat' && <UnifiedChat user={user} />}

        {/* Overtime Section */}
        {activeSection === 'overtime' && <OvertimeRequest user={user} />}

        {/* Profile Section */}
        {activeSection === 'profile' && <WorkerProfile user={user} currentUser={user} />}
      </main>
    </div>
  );
}
