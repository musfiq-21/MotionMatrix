import React, { useState } from 'react';
import '../styles/OwnerManagerDashboard.css';
import UnifiedChat from './UnifiedChat';
import GraphViewPage from './GraphViewPage';
import ReportViewPage from './ReportViewPage';
import OwnerManagerProfile from './OwnerManagerProfile';

export default function OwnerManagerDashboard({ user }) {
  const [activeSection, setActiveSection] = useState('dashboard');

  const getUserTitle = () => {
    return user?.role === 'owner' ? 'Owner' : 'Manager';
  };

  return (
    <div className="owner-manager-dashboard">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <h2>{getUserTitle()} Portal</h2>
          <p className="subtitle">{user?.department}</p>
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
            className={`menu-item ${activeSection === 'graph' ? 'active' : ''}`}
            onClick={() => setActiveSection('graph')}
          >
            📈 View Graphs
          </button>
          <button
            className={`menu-item ${activeSection === 'report' ? 'active' : ''}`}
            onClick={() => setActiveSection('report')}
          >
            📋 View Reports
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
              <p className="subtitle">Your {getUserTitle()} Dashboard</p>
            </div>

            <div className="dashboard-cards">
              <div className="info-card">
                <div className="card-icon">👤</div>
                <h3>Role</h3>
                <p className="card-value">{getUserTitle()}</p>
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
                    <p>Communicate with team members and floor managers about important matters.</p>
                    <button 
                      className="feature-btn"
                      onClick={() => setActiveSection('chat')}
                    >
                      Send Message
                    </button>
                  </div>
                </div>

                <div className="feature-card">
                  <div className="feature-icon">📈</div>
                  <div className="feature-content">
                    <h4>Graphs</h4>
                    <p>View production, attendance, and equipment uptime analytics and trends.</p>
                    <button 
                      className="feature-btn"
                      onClick={() => setActiveSection('graph')}
                    >
                      View Graphs
                    </button>
                  </div>
                </div>

                <div className="feature-card">
                  <div className="feature-icon">📋</div>
                  <div className="feature-content">
                    <h4>Reports</h4>
                    <p>Access detailed reports on production, attendance, and equipment performance.</p>
                    <button 
                      className="feature-btn"
                      onClick={() => setActiveSection('report')}
                    >
                      View Reports
                    </button>
                  </div>
                </div>

                <div className="feature-card">
                  <div className="feature-icon">👤</div>
                  <div className="feature-content">
                    <h4>Profile</h4>
                    <p>Manage your profile information and personal settings.</p>
                    <button 
                      className="feature-btn"
                      onClick={() => setActiveSection('profile')}
                    >
                      My Profile
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Chat Section */}
        {activeSection === 'chat' && <UnifiedChat user={user} />}

        {/* Graph Section */}
        {activeSection === 'graph' && <GraphViewPage />}

        {/* Report Section */}
        {activeSection === 'report' && <ReportViewPage />}

        {/* Profile Section */}
        {activeSection === 'profile' && <OwnerManagerProfile user={user} currentUser={user} />}
      </main>
    </div>
  );
}
