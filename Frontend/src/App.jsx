import { useState, useEffect } from 'react'
import HomePage from './components/HomePage'
import LoginPage from './components/LoginPage'
import AdminDashboard from './components/AdminDashboard'
import WorkerDashboard from './components/WorkerDashboard'
import OwnerManagerDashboard from './components/OwnerManagerDashboard'
import FloorManagerDashboard from './components/FloorManagerDashboard'
import logo from './assets/logo.jpeg'
import './App.css'

function App() {
  const [currentPage, setCurrentPage] = useState(() => {
    // Get initial page from URL hash
    const hash = window.location.hash.slice(1) || 'home'
    return hash
  })
  const [isTransitioning, setIsTransitioning] = useState(false)
  
  // User state management
  const [adminUser, setAdminUser] = useState(() => {
    const savedUser = localStorage.getItem('adminUser')
    return savedUser ? JSON.parse(savedUser) : null
  })
  const [workerUser, setWorkerUser] = useState(() => {
    const savedUser = localStorage.getItem('workerUser')
    return savedUser ? JSON.parse(savedUser) : null
  })
  const [ownerManagerUser, setOwnerManagerUser] = useState(() => {
    const savedUser = localStorage.getItem('ownerManagerUser')
    return savedUser ? JSON.parse(savedUser) : null
  })
  const [floorManagerUser, setFloorManagerUser] = useState(() => {
    const savedUser = localStorage.getItem('floorManagerUser')
    return savedUser ? JSON.parse(savedUser) : null
  })

  // Get current user based on authenticated state
  const getCurrentUser = () => {
    return adminUser || workerUser || ownerManagerUser || floorManagerUser
  }

  // Check if user is authenticated
  const isAuthenticated = () => {
    return Boolean(getCurrentUser())
  }

  // Validate that user has access to the page they're trying to view
  const hasAccessToPage = (page) => {
    switch (page) {
      case 'admin':
        return adminUser !== null
      case 'worker':
        return workerUser !== null
      case 'ownerManager':
        return ownerManagerUser !== null
      case 'floorManager':
        return floorManagerUser !== null
      case 'login':
      case 'home':
      case 'register':
        return true
      default:
        return false
    }
  }

  // Handle browser back button and hash changes
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.slice(1) || 'home'
      setIsTransitioning(true)
      setTimeout(() => {
        setCurrentPage(hash)
        setIsTransitioning(false)
      }, 150)
    }

    window.addEventListener('hashchange', handleHashChange)
    return () => window.removeEventListener('hashchange', handleHashChange)
  }, [])

  const navigateToPage = (page) => {
    // Prevent navigation to protected pages without authentication
    if (['admin', 'worker', 'ownerManager', 'floorManager'].includes(page) && !hasAccessToPage(page)) {
      console.warn(`Unauthorized access attempt to ${page}`)
      window.location.hash = '#login'
      return
    }

    // Change URL hash which will trigger hashchange event
    window.location.hash = `#${page}`
  }

  const goBack = () => {
    // Use browser's native back button
    window.history.back()
  }

  const handleNavigateToLogin = () => {
    navigateToPage('login')
  }

  const handleBackToHome = () => {
    navigateToPage('home')
  }

  const handleLoginSuccess = (userRole, userData) => {
    console.log('🎯 handleLoginSuccess called with:', { userRole, userData });
    
    // Admin users access the admin dashboard
    if (userRole === 'admin') {
      console.log('✅ Setting admin user and navigating to admin dashboard');
      setAdminUser(userData)
      localStorage.setItem('adminUser', JSON.stringify(userData))
      navigateToPage('admin')
    } 
    // Worker users access the worker dashboard
    else if (userRole === 'worker') {
      console.log('✅ Setting worker user and navigating to worker dashboard');
      setWorkerUser(userData)
      localStorage.setItem('workerUser', JSON.stringify(userData))
      navigateToPage('worker')
    }
    // Owner and Manager users access the owner/manager dashboard
    else if (userRole === 'owner' || userRole === 'manager') {
      console.log('✅ Setting owner/manager user and navigating to ownerManager dashboard');
      setOwnerManagerUser(userData)
      localStorage.setItem('ownerManagerUser', JSON.stringify(userData))
      navigateToPage('ownerManager')
    }
    // Floor Manager users access the floor manager dashboard
    else if (userRole === 'floor_manager') {
      console.log('✅ Setting floor manager user and navigating to floorManager dashboard');
      setFloorManagerUser(userData)
      localStorage.setItem('floorManagerUser', JSON.stringify(userData))
      navigateToPage('floorManager')
    }
    // Other roles cannot access the dashboards
    else {
      console.warn('⚠️ Unknown role:', userRole);
      navigateToPage('home')
    }
  }

  const handleLogout = () => {
    setAdminUser(null)
    setWorkerUser(null)
    setOwnerManagerUser(null)
    setFloorManagerUser(null)
    // Clear all user types from localStorage
    localStorage.removeItem('adminUser')
    localStorage.removeItem('workerUser')
    localStorage.removeItem('ownerManagerUser')
    localStorage.removeItem('floorManagerUser')
    // Navigate to home
    navigateToPage('home')
  }

  return (
    <div className="app">
      {/* Navbar - Always visible when logged in, or on home/login pages */}
      {((adminUser || workerUser || ownerManagerUser || floorManagerUser) || currentPage !== 'admin' && currentPage !== 'worker' && currentPage !== 'ownerManager' && currentPage !== 'floorManager') && (
        <nav className="navbar">
          <div className="nav-container">
            <div className="nav-logo-container">
              <img src="/src/assets/logo.jpeg" alt="MotionMatrix Logo" className="nav-logo-img" />
              <h2 className="nav-logo">MotionMatrix</h2>
            </div>
            <div className="nav-buttons">
              {isAuthenticated() ? (
                <>
                  <button 
                    className="nav-btn nav-back-btn"
                    onClick={goBack}
                    title="Go back to previous page"
                  >
                    ← Back
                  </button>
                  <button 
                    className="nav-btn nav-login-btn"
                    onClick={() => navigateToPage(
                      adminUser ? 'admin' : 
                      workerUser ? 'worker' : 
                      ownerManagerUser ? 'ownerManager' : 
                      floorManagerUser ? 'floorManager' : 'home'
                    )}
                  >
                    {adminUser ? 'Admin Dashboard' : 
                     workerUser ? 'Worker Dashboard' : 
                     ownerManagerUser ? 'Owner/Manager Dashboard' : 
                     floorManagerUser ? 'Floor Manager Dashboard' : 'Dashboard'}
                  </button>
                  <button 
                    className="nav-btn nav-register-btn"
                    onClick={handleLogout}
                  >
                    Logout
                  </button>
                </>
              ) : (
                <button 
                  className="nav-btn nav-login-btn"
                  onClick={handleNavigateToLogin}
                >
                  Sign In
                </button>
              )}
            </div>
          </div>
        </nav>
      )}

      {/* Home Page */}
      {currentPage === 'home' && (
        <HomePage onNavigateToLogin={handleNavigateToLogin} />
      )}
      
      {/* Login Page */}
      {currentPage === 'login' && (
        <div className={`page-wrapper ${isTransitioning ? 'fade-out' : 'fade-in'}`}>
          <LoginPage onBack={goBack} onLoginSuccess={handleLoginSuccess} />
        </div>
      )}

      {/* Admin Dashboard - Protected Route */}
      {currentPage === 'admin' && adminUser && hasAccessToPage('admin') ? (
        <AdminDashboard 
          onLogout={handleLogout} 
          adminUser={adminUser}
          onNavigateToHome={() => navigateToPage('home')}
        />
      ) : currentPage === 'admin' && (!adminUser || !hasAccessToPage('admin')) ? (
        <div style={{ padding: '40px', textAlign: 'center', marginTop: '100px' }}>
          <h2>🔒 Access Denied</h2>
          <p>You do not have permission to access this page.</p>
          <button 
            onClick={() => navigateToPage('home')}
            style={{
              padding: '10px 20px',
              backgroundColor: '#1B4332',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '1rem'
            }}
          >
            Return to Home
          </button>
        </div>
      ) : null}

      {/* Worker Dashboard - Protected Route */}
      {currentPage === 'worker' && workerUser && hasAccessToPage('worker') ? (
        <WorkerDashboard 
          user={workerUser}
        />
      ) : currentPage === 'worker' && (!workerUser || !hasAccessToPage('worker')) ? (
        <div style={{ padding: '40px', textAlign: 'center', marginTop: '100px' }}>
          <h2>🔒 Access Denied</h2>
          <p>You do not have permission to access this page.</p>
          <button 
            onClick={() => navigateToPage('home')}
            style={{
              padding: '10px 20px',
              backgroundColor: '#1B4332',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '1rem'
            }}
          >
            Return to Home
          </button>
        </div>
      ) : null}

      {/* Owner/Manager Dashboard - Protected Route */}
      {currentPage === 'ownerManager' && ownerManagerUser && hasAccessToPage('ownerManager') ? (
        <OwnerManagerDashboard 
          user={ownerManagerUser}
        />
      ) : currentPage === 'ownerManager' && (!ownerManagerUser || !hasAccessToPage('ownerManager')) ? (
        <div style={{ padding: '40px', textAlign: 'center', marginTop: '100px' }}>
          <h2>🔒 Access Denied</h2>
          <p>You do not have permission to access this page.</p>
          <button 
            onClick={() => navigateToPage('home')}
            style={{
              padding: '10px 20px',
              backgroundColor: '#1B4332',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '1rem'
            }}
          >
            Return to Home
          </button>
        </div>
      ) : null}

      {/* Floor Manager Dashboard - Protected Route */}
      {currentPage === 'floorManager' && floorManagerUser && hasAccessToPage('floorManager') ? (
        <FloorManagerDashboard 
          user={floorManagerUser}
        />
      ) : currentPage === 'floorManager' && (!floorManagerUser || !hasAccessToPage('floorManager')) ? (
        <div style={{ padding: '40px', textAlign: 'center', marginTop: '100px' }}>
          <h2>🔒 Access Denied</h2>
          <p>You do not have permission to access this page.</p>
          <button 
            onClick={() => navigateToPage('home')}
            style={{
              padding: '10px 20px',
              backgroundColor: '#1B4332',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '1rem'
            }}
          >
            Return to Home
          </button>
        </div>
      ) : null}
    </div>
  )
}

export default App
