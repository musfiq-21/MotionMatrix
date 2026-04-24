import React, { useState } from 'react';
import '../styles/LoginPage.css';
import logo from '../assets/logo.jpeg';

const LoginPage = ({ onBack, onLoginSuccess }) => {
  const [formState, setFormState] = useState('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [recoveryEmail, setRecoveryEmail] = useState('');
  const [errors, setErrors] = useState({});
  const [message, setMessage] = useState('');

  const validateEmail = (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    const newErrors = {};
    
    if (!email) newErrors.email = 'Email is required';
    else if (!validateEmail(email)) newErrors.email = 'Invalid email format';
    
    if (!password) newErrors.password = 'Password is required';
    else if (password.length < 6) newErrors.password = 'Password must be at least 6 characters';

    if (Object.keys(newErrors).length === 0) {
      try {
        console.log('🔐 Attempting login with:', email);
        // Call backend login API
        const response = await fetch('http://localhost:5000/api/auth/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            email: email,
            password: password
          })
        });

        const data = await response.json();
        console.log('📤 Backend response:', data);

        if (data.success) {
          setMessage('✅ Login successful! Redirecting...');
          
          // Store auth token in localStorage
          localStorage.setItem('authToken', data.token);
          console.log('🔑 Auth token stored in localStorage');
          
          // Store user data in localStorage
          const userData = {
            id: data.user.id,
            name: data.user.name,
            email: data.user.email,
            role: data.user.role,
            department: data.user.department,
            phone: data.user.phone,
            assignedFloorId: data.user.assignedFloorId
          };

          // Convert role to lowercase for frontend routing
          const roleLower = data.user.role.toLowerCase();
          console.log('👤 User role (uppercase):', data.user.role);
          console.log('👤 User role (lowercase):', roleLower);

          setTimeout(() => {
            // Pass user data to parent component with lowercase role
            console.log('🎯 Calling onLoginSuccess with role:', roleLower);
            onLoginSuccess(roleLower, userData);
          }, 800);
        } else {
          console.error('❌ Login failed:', data.message);
          setErrors({ auth: data.message || 'Login failed' });
        }
      } catch (error) {
        console.error('❌ Login error:', error);
        setErrors({ auth: 'Error connecting to server: ' + error.message });
      }
    } else {
      setErrors(newErrors);
    }
  };

  const handleRecovery = (e) => {
    e.preventDefault();
    const newErrors = {};
    
    if (!recoveryEmail) newErrors.recoveryEmail = 'Email is required';
    else if (!validateEmail(recoveryEmail)) newErrors.recoveryEmail = 'Invalid email format';
    
    if (!newPassword) newErrors.newPassword = 'New password is required';
    else if (newPassword.length < 6) newErrors.newPassword = 'Password must be at least 6 characters';
    
    if (!confirmPassword) newErrors.confirmPassword = 'Confirm password is required';
    else if (newPassword !== confirmPassword) newErrors.confirmPassword = 'Passwords do not match';

    if (Object.keys(newErrors).length === 0) {
      handleResetPassword(e);
    } else {
      setErrors(newErrors);
    }
  };

  const handleResetPassword = async (e) => {
    try {
      setMessage('');
      const response = await fetch('http://localhost:5000/api/auth/reset-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          email: recoveryEmail,
          newPassword: newPassword
        })
      });

      const data = await response.json();

      if (data.success) {
        setMessage('✅ Password reset successful! Redirecting to login...');
        setNewPassword('');
        setConfirmPassword('');
        setRecoveryEmail('');
        setErrors({});
        setTimeout(() => {
          setFormState('login');
          setMessage('');
        }, 2000);
      } else {
        setErrors({ auth: data.message || 'Password reset failed' });
      }
    } catch (error) {
      setErrors({ auth: 'Error: ' + error.message });
    }
  };

  return (
    <div className="login-page">
      <div className="login-container">
        <div className="login-box" style={{ position: 'relative' }}>
          <h1 className="login-title">MotionMatrix</h1>
          <p className="login-subtitle">Factory Management System</p>

          {message && <div className="message-alert">{message}</div>}
          {errors.auth && <div className="error-alert">{errors.auth}</div>}

          {formState === 'login' && (
            <form className="login-form" onSubmit={handleLogin}>
              <div className="form-group">
                <label htmlFor="email">Email Address</label>
                <input
                  id="email"
                  type="email"
                  placeholder="Enter your email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className={errors.email ? 'input-error' : ''}
                />
                {errors.email && <span className="error-text">{errors.email}</span>}
              </div>

              <div className="form-group">
                <label htmlFor="password">Password</label>
                <div className="password-input-wrapper">
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    placeholder="Enter your password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className={errors.password ? 'input-error' : ''}
                  />
                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? '👁️' : '👁️‍🗨️'}
                  </button>
                </div>
                {errors.password && <span className="error-text">{errors.password}</span>}
              </div>

              <button type="submit" className="btn-login">Sign In</button>

              <div className="form-footer">
                <p onClick={() => setFormState('recovery')} className="forgot-password">
                  Forgot your password?
                </p>
              </div>
            </form>
          )}

          {formState === 'recovery' && (
            <form className="recovery-form" onSubmit={handleRecovery}>
              <h2>Reset Your Password</h2>
              <p className="recovery-text">
                Enter your email and new password to reset your account.
              </p>

              <div className="form-group">
                <label htmlFor="recovery-email">Email Address</label>
                <input
                  id="recovery-email"
                  type="email"
                  placeholder="Enter your registered email"
                  value={recoveryEmail}
                  onChange={(e) => setRecoveryEmail(e.target.value)}
                  className={errors.recoveryEmail ? 'input-error' : ''}
                />
                {errors.recoveryEmail && <span className="error-text">{errors.recoveryEmail}</span>}
              </div>

              <div className="form-group">
                <label htmlFor="new-password">New Password</label>
                <div className="password-input-wrapper">
                  <input
                    id="new-password"
                    type={showNewPassword ? 'text' : 'password'}
                    placeholder="Enter new password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    className={errors.newPassword ? 'input-error' : ''}
                  />
                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                  >
                    {showNewPassword ? '👁️' : '👁️‍🗨️'}
                  </button>
                </div>
                {errors.newPassword && <span className="error-text">{errors.newPassword}</span>}
              </div>

              <div className="form-group">
                <label htmlFor="confirm-password">Confirm Password</label>
                <div className="password-input-wrapper">
                  <input
                    id="confirm-password"
                    type={showConfirmPassword ? 'text' : 'password'}
                    placeholder="Confirm new password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className={errors.confirmPassword ? 'input-error' : ''}
                  />
                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  >
                    {showConfirmPassword ? '👁️' : '👁️‍🗨️'}
                  </button>
                </div>
                {errors.confirmPassword && <span className="error-text">{errors.confirmPassword}</span>}
              </div>

              <button type="submit" className="btn-login">Reset Password</button>

              <div className="form-footer">
                <p onClick={() => {
                  setFormState('login');
                  setRecoveryEmail('');
                  setNewPassword('');
                  setConfirmPassword('');
                  setErrors({});
                  setMessage('');
                }} className="back-to-login">
                  Back to Login
                </p>
              </div>
            </form>
          )}

        </div>

        <div className="button-container-bottom">
          <button className="back-btn" onClick={onBack}>
            <span className="back-icon">←</span>
            <span className="back-text">Back to Home</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
