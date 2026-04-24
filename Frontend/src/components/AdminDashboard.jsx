import React, { useState, useEffect } from 'react';
import '../styles/AdminDashboard.css';
import AdminProfile from './AdminProfile';
import AddWorker from './AddWorker';
import UnifiedChat from './UnifiedChat';
import CreateFloor from './CreateFloor';
import AssignCCTV from './AssignCCTV';

const AdminDashboard = ({ onLogout, adminUser }) => {
  const [activeSection, setActiveSection] = useState('dashboard');
  const [adminData, setAdminData] = useState(adminUser || {});
  const [allUsers, setAllUsers] = useState([]);
  const [workers, setWorkers] = useState([]);
  const [stats, setStats] = useState({
    totalUsers: 0,
    totalWorkers: 0,
    totalManagers: 0,
    totalFloorManagers: 0
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (adminUser) {
      setAdminData(adminUser);
    }
  }, [adminUser]);

  // Fetch all users
  useEffect(() => {
    const fetchUsers = async () => {
      try {
        setLoading(true);
        const token = localStorage.getItem('authToken');
        
        const response = await fetch('http://localhost:5000/api/users', {
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
        
        if (response.ok) {
          const data = await response.json();
          const users = data.users || [];
          setAllUsers(users);
          
          // Calculate stats
          const stats = {
            totalUsers: users.length,
            totalWorkers: users.filter(u => u.role === 'WORKER').length,
            totalManagers: users.filter(u => u.role === 'MANAGER').length,
            totalFloorManagers: users.filter(u => u.role === 'FLOOR_MANAGER').length
          };
          setStats(stats);
          
          // Filter workers
          setWorkers(users.filter(u => u.role === 'WORKER'));
        } else {
          setError('Failed to fetch users');
        }
      } catch (error) {
        console.error('Error fetching users:', error);
        setError('Error loading users');
      } finally {
        setLoading(false);
      }
    };

    if (activeSection === 'dashboard' || activeSection === 'viewWorkers') {
      fetchUsers();
    }
  }, [activeSection]);

  const handleLogout = () => {
    onLogout();
  };

  // Generate initials for avatar
  const getInitials = (name) => {
    return name
      .split(' ')
      .map(word => word[0])
      .join('')
      .toUpperCase()
      .slice(0, 2);
  };

  // Dynamic description based on role
  const getDescription = () => {
    switch(adminData.role?.toLowerCase()) {
      case 'admin':
      case 'administrator':
        return 'Manage workers, accounts, floors, CCTV systems, and communicate with all team members';
      default:
        return 'Manage workers, accounts, and communicate with floor managers';
    }
  };

  const getRoleColor = (role) => {
    switch(role?.toUpperCase()) {
      case 'WORKER':
        return '#10B981';
      case 'FLOOR_MANAGER':
        return '#D97706';
      case 'MANAGER':
        return '#1B4332';
      case 'OWNER':
        return '#9333EA';
      case 'ADMIN':
        return '#EF4444';
      default:
        return '#666';
    }
  };

  return (
    <div className="admin-dashboard">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="sidebar-header">
          <h3>MotionMatrix</h3>
          <p className="admin-role">{adminData.name}</p>
          <p className="admin-role-type">{adminData.role || 'Administrator'}</p>
        </div>

        <nav className="sidebar-menu">
          <button
            className={`menu-item ${activeSection === 'dashboard' ? 'active' : ''}`}
            onClick={() => setActiveSection('dashboard')}
          >
            📊 Dashboard
          </button>
          <button
            className={`menu-item ${activeSection === 'profile' ? 'active' : ''}`}
            onClick={() => setActiveSection('profile')}
          >
            👤 My Profile
          </button>
          <button
            className={`menu-item ${activeSection === 'addWorker' ? 'active' : ''}`}
            onClick={() => setActiveSection('addWorker')}
          >
            👷 Add Worker / Account
          </button>
          <button
            className={`menu-item ${activeSection === 'viewWorkers' ? 'active' : ''}`}
            onClick={() => setActiveSection('viewWorkers')}
          >
            👥 View All Workers
          </button>
          <button
            className={`menu-item ${activeSection === 'createFloor' ? 'active' : ''}`}
            onClick={() => setActiveSection('createFloor')}
          >
            🏢 Create Floor
          </button>
          <button
            className={`menu-item ${activeSection === 'assignCCTV' ? 'active' : ''}`}
            onClick={() => setActiveSection('assignCCTV')}
          >
            🎥 Assign CCTV
          </button>
          <button
            className={`menu-item ${activeSection === 'chat' ? 'active' : ''}`}
            onClick={() => setActiveSection('chat')}
          >
            💬 Chat
          </button>
        </nav>

        <button className="logout-btn" onClick={handleLogout}>
          🚪 Logout
        </button>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        {/* Header */}
        <header className="dashboard-header">
          <div className="header-info">
            <h1>Welcome, {adminData.name}</h1>
            <p>{getDescription()}</p>
          </div>
          <div className="user-profile">
            <div className="profile-avatar-dynamic">
              {getInitials(adminData.name)}
            </div>
            <div className="profile-info">
              <p className="profile-email">{adminData.email}</p>
              <p className="profile-role">{adminData.role || 'Administrator'}</p>
            </div>
          </div>
        </header>

        {/* Content Area */}
        <section className="content-area">
          {/* Dashboard Overview */}
          {activeSection === 'dashboard' && (
            <div className="dashboard-overview">
              <h2>Dashboard Overview</h2>
              {error && <div className="error-banner">{error}</div>}
              <div className="stats-grid">
                <div className="stat-card">
                  <div className="stat-icon">👷</div>
                  <div className="stat-info">
                    <h3>Total Workers</h3>
                    <p className="stat-number">{stats.totalWorkers}</p>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon">👤</div>
                  <div className="stat-info">
                    <h3>All Accounts</h3>
                    <p className="stat-number">{stats.totalUsers}</p>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon">🏭</div>
                  <div className="stat-info">
                    <h3>Floor Managers</h3>
                    <p className="stat-number">{stats.totalFloorManagers}</p>
                  </div>
                </div>
                <div className="stat-card">
                  <div className="stat-icon">📊</div>
                  <div className="stat-info">
                    <h3>Managers</h3>
                    <p className="stat-number">{stats.totalManagers}</p>
                  </div>
                </div>
              </div>

              <div className="feature-cards">
                <h3>Quick Actions</h3>
                <div className="cards-grid">
                  <div className="feature-card">
                    <div className="feature-icon">👷</div>
                    <div className="feature-content">
                      <h4>Add Worker</h4>
                      <p>Add new workers and accounts to the system with proper role and department assignments.</p>
                      <button 
                        className="feature-btn"
                        onClick={() => setActiveSection('addWorker')}
                      >
                        Add Worker
                      </button>
                    </div>
                  </div>

                  <div className="feature-card">
                    <div className="feature-icon">👥</div>
                    <div className="feature-content">
                      <h4>View Workers</h4>
                      <p>See all workers and accounts registered in the system with their details and assignments.</p>
                      <button 
                        className="feature-btn"
                        onClick={() => setActiveSection('viewWorkers')}
                      >
                        View Workers
                      </button>
                    </div>
                  </div>

                  <div className="feature-card">
                    <div className="feature-icon">🏢</div>
                    <div className="feature-content">
                      <h4>Create Floor</h4>
                      <p>Set up new floors with proper configurations for production management and monitoring.</p>
                      <button 
                        className="feature-btn"
                        onClick={() => setActiveSection('createFloor')}
                      >
                        Create Floor
                      </button>
                    </div>
                  </div>

                  <div className="feature-card">
                    <div className="feature-icon">🎥</div>
                    <div className="feature-content">
                      <h4>Assign CCTV</h4>
                      <p>Configure and assign CCTV cameras to floors for real-time monitoring and security.</p>
                      <button 
                        className="feature-btn"
                        onClick={() => setActiveSection('assignCCTV')}
                      >
                        Assign CCTV
                      </button>
                    </div>
                  </div>

                  <div className="feature-card">
                    <div className="feature-icon">💬</div>
                    <div className="feature-content">
                      <h4>Send Message</h4>
                      <p>Communicate directly with floor managers and workers for important updates and notifications.</p>
                      <button 
                        className="feature-btn"
                        onClick={() => setActiveSection('chat')}
                      >
                        Send Message
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* View All Workers */}
          {activeSection === 'viewWorkers' && (
            <div className="view-workers-section">
              <h2>👥 All Users & Workers</h2>
              {error && <div className="error-banner">{error}</div>}
              {loading ? (
                <div className="loading">Loading users...</div>
              ) : allUsers.length === 0 ? (
                <div className="no-data">
                  <p>No users found. Add workers using the "Add Worker" section.</p>
                </div>
              ) : (
                <div className="users-table-wrapper">
                  <table className="users-table">
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Department</th>
                        <th>Phone</th>
                        <th>Worker ID</th>
                        <th>Assigned Floor</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {allUsers.map(user => (
                        <tr key={user.id}>
                          <td className="name-cell">{user.name}</td>
                          <td>{user.email}</td>
                          <td>
                            <span 
                              className="role-badge"
                              style={{ 
                                backgroundColor: getRoleColor(user.role) + '20',
                                color: getRoleColor(user.role),
                                borderColor: getRoleColor(user.role)
                              }}
                            >
                              {user.role}
                            </span>
                          </td>
                          <td>{user.department || '-'}</td>
                          <td>{user.phone || '-'}</td>
                          <td>{user.workerId || '-'}</td>
                          <td>{user.assignedFloorId || '-'}</td>
                          <td>
                            <span className={`status-badge ${user.status?.toLowerCase()}`}>
                              {user.status || 'active'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Profile Page */}
          {activeSection === 'profile' && <AdminProfile user={adminData} currentUser={user} />}

          {/* Add Worker */}
          {activeSection === 'addWorker' && <AddWorker />}

          {/* Create Floor */}
          {activeSection === 'createFloor' && (
            <CreateFloor onSelectFloor={(floorId) => setActiveSection('assignCCTV')} />
          )}

          {/* Assign CCTV */}
          {activeSection === 'assignCCTV' && <AssignCCTV />}

          {/* Chat */}
          {activeSection === 'chat' && <UnifiedChat user={adminUser} />}
        </section>
      </main>
    </div>
  );
};

export default AdminDashboard;
