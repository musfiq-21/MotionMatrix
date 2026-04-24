import React, { useState } from 'react';
import '../styles/RegisterPage.css';
import logo from '../assets/logo.jpeg';

const RegisterPage = ({ onBack, onRegisterSuccess }) => {
  const [formData, setFormData] = useState({
    name: '',
    role: '',
    email: '',
    password: '',
    confirmPassword: '',
    nid: '',
    gender: '',
    assignedFloorId: '',
    department: '',
    phone: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [errors, setErrors] = useState({});
  const [message, setMessage] = useState('');
  const [isRegistered, setIsRegistered] = useState(false);
  const [floors, setFloors] = useState([]);
  const [floorsLoading, setFloorsLoading] = useState(false);

  // Fetch floors on component mount
  React.useEffect(() => {
    const fetchFloors = async () => {
      try {
        setFloorsLoading(true);
        const response = await fetch('http://localhost:5000/api/floors');
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.floors) {
            setFloors(data.floors);
          }
        }
      } catch (error) {
        console.error('Error fetching floors:', error);
      } finally {
        setFloorsLoading(false);
      }
    };
    fetchFloors();
  }, []);

  const validateEmail = (email) => {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  };

  const handleBack = () => {
    if (!isRegistered) {
      // If not registered, go back to home
      onBack('home');
    } else {
      // If registered, go to login
      onBack();
    }
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value
    });
    // Clear error for this field when user starts typing
    if (errors[name]) {
      setErrors({
        ...errors,
        [name]: ''
      });
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const newErrors = {};

    // Validation
    if (!formData.name.trim()) newErrors.name = 'Full name is required';
    if (!formData.role) newErrors.role = 'Role is required';
    if (['WORKER', 'FLOOR_MANAGER'].includes(formData.role.toUpperCase()) && !formData.assignedFloorId) {
      newErrors.assignedFloorId = 'Floor assignment is required for this role';
    }
    if (!formData.email) newErrors.email = 'Email is required';
    else if (!validateEmail(formData.email)) newErrors.email = 'Invalid email format';
    if (!formData.password) newErrors.password = 'Password is required';
    else if (formData.password.length < 6) newErrors.password = 'Password must be at least 6 characters';
    if (!formData.confirmPassword) newErrors.confirmPassword = 'Please confirm password';
    else if (formData.password !== formData.confirmPassword) newErrors.confirmPassword = 'Passwords do not match';
    if (!formData.nid.trim()) newErrors.nid = 'NID or Birth Certificate number is required';
    if (!formData.gender) newErrors.gender = 'Please select gender';
    // Department is not required for OWNER role
    if (!formData.department && formData.role.toUpperCase() !== 'OWNER') newErrors.department = 'Department is required';
    if (!formData.phone.trim()) newErrors.phone = 'Phone number is required';

    if (Object.keys(newErrors).length === 0) {
      try {
        const response = await fetch('http://localhost:5000/api/auth/register', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            name: formData.name,
            email: formData.email,
            password: formData.password,
            confirmPassword: formData.confirmPassword,
            role: formData.role.toUpperCase(),
            department: formData.department,
            phone: formData.phone,
            nid: formData.nid,
            gender: formData.gender,
            assignedFloorId: formData.assignedFloorId ? parseInt(formData.assignedFloorId) : null
          })
        });

        const data = await response.json();
        if (data.success) {
          setIsRegistered(true);
          setMessage('Registration successful! Redirecting to login...');
          setTimeout(() => {
            onRegisterSuccess();
          }, 1500);
        } else {
          setErrors({ submit: data.message || 'Registration failed' });
        }
      } catch (error) {
        console.error('Registration error:', error);
        setErrors({ submit: 'Error connecting to server: ' + error.message });
      }
    } else {
      setErrors(newErrors);
    }
  };

  return (
    <div className="register-page">
      <div className="register-container">
        <div className="register-box">
          <h1 className="register-title">Create Account</h1>
          <p className="register-subtitle">Join MotionMatrix Factory Management</p>

          {message && <div className="message-alert">{message}</div>}

          <form className="register-form" onSubmit={handleSubmit}>
            {/* Full Name */}
            <div className="form-group">
              <label htmlFor="name">Full Name</label>
              <input
                id="name"
                type="text"
                name="name"
                placeholder="Enter your full name"
                value={formData.name}
                onChange={handleChange}
                className={errors.name ? 'input-error' : ''}
              />
              {errors.name && <span className="error-text">{errors.name}</span>}
            </div>

            {/* Role */}
            <div className="form-group">
              <label htmlFor="role">Role</label>
              <select
                id="role"
                name="role"
                value={formData.role}
                onChange={handleChange}
                className={errors.role ? 'input-error' : ''}
              >
                <option value="">Select your role</option>
                <option value="WORKER">Worker</option>
                <option value="FLOOR_MANAGER">Floor Manager</option>
                <option value="OWNER">Owner/Manager</option>
                <option value="ADMIN">Admin</option>
              </select>
              {errors.role && <span className="error-text">{errors.role}</span>}
            </div>

            {/* Assigned Floor (for WORKER and FLOOR_MANAGER) */}
            {['WORKER', 'FLOOR_MANAGER'].includes(formData.role.toUpperCase()) && (
              <div className="form-group">
                <label htmlFor="assignedFloorId">Assigned Floor</label>
                <select
                  id="assignedFloorId"
                  name="assignedFloorId"
                  value={formData.assignedFloorId}
                  onChange={handleChange}
                  className={errors.assignedFloorId ? 'input-error' : ''}
                  disabled={floorsLoading}
                >
                  <option value="">Select a floor</option>
                  {floors.map(floor => (
                    <option key={floor.id} value={floor.id}>
                      {floor.name} (Level {floor.level})
                    </option>
                  ))}
                </select>
                {errors.assignedFloorId && <span className="error-text">{errors.assignedFloorId}</span>}
              </div>
            )}

            {/* Department */}
            {formData.role.toUpperCase() !== 'OWNER' && (
            <div className="form-group">
              <label htmlFor="department">Department</label>
              <select
                id="department"
                name="department"
                value={formData.department}
                onChange={handleChange}
                className={errors.department ? 'input-error' : ''}
              >
                <option value="">Select department</option>
                <option value="Sewing">Sewing</option>
                <option value="Cutting">Cutting</option>
                <option value="Finishing">Finishing</option>
                <option value="Quality Control">Quality Control</option>
                <option value="Packing">Packing</option>
              </select>
              {errors.department && <span className="error-text">{errors.department}</span>}
            </div>
            )}

            {/* Phone */}
            <div className="form-group">
              <label htmlFor="phone">Phone Number</label>
              <input
                id="phone"
                type="tel"
                name="phone"
                placeholder="Enter your phone number"
                value={formData.phone}
                onChange={handleChange}
                className={errors.phone ? 'input-error' : ''}
              />
              {errors.phone && <span className="error-text">{errors.phone}</span>}
            </div>

            {/* Email */}
            <div className="form-group">
              <label htmlFor="email">Email Address</label>
              <input
                id="email"
                type="email"
                name="email"
                placeholder="Enter your email"
                value={formData.email}
                onChange={handleChange}
                className={errors.email ? 'input-error' : ''}
              />
              {errors.email && <span className="error-text">{errors.email}</span>}
            </div>

            {/* Password */}
            <div className="form-group">
              <label htmlFor="password">Password</label>
              <div className="password-input-wrapper">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  name="password"
                  placeholder="Create a password"
                  value={formData.password}
                  onChange={handleChange}
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

            {/* Confirm Password */}
            <div className="form-group">
              <label htmlFor="confirmPassword">Confirm Password</label>
              <div className="password-input-wrapper">
                <input
                  id="confirmPassword"
                  type={showConfirmPassword ? 'text' : 'password'}
                  name="confirmPassword"
                  placeholder="Confirm your password"
                  value={formData.confirmPassword}
                  onChange={handleChange}
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

            {/* NID / Birth Certificate */}
            <div className="form-group">
              <label htmlFor="nid">NID or Birth Certificate Number</label>
              <input
                id="nid"
                type="text"
                name="nid"
                placeholder="Enter NID or Birth Certificate number"
                value={formData.nid}
                onChange={handleChange}
                className={errors.nid ? 'input-error' : ''}
              />
              {errors.nid && <span className="error-text">{errors.nid}</span>}
            </div>

            {/* Gender */}
            <div className="form-group gender-group">
              <label>Gender</label>
              <div className="gender-options">
                <label className="radio-label">
                  <input
                    type="radio"
                    name="gender"
                    value="male"
                    checked={formData.gender === 'male'}
                    onChange={handleChange}
                  />
                  Male
                </label>
                <label className="radio-label">
                  <input
                    type="radio"
                    name="gender"
                    value="female"
                    checked={formData.gender === 'female'}
                    onChange={handleChange}
                  />
                  Female
                </label>
              </div>
              {errors.gender && <span className="error-text">{errors.gender}</span>}
            </div>

            {errors.submit && <div className="error-alert">{errors.submit}</div>}
            <button type="submit" className="btn-register">Create Account</button>

            <div className="form-footer">
              <p>Already have an account? <span className="login-link" onClick={onBack}>Login here</span></p>
            </div>
          </form>
        </div>

        <div className="button-container-bottom">
          <button className="back-btn" onClick={handleBack}>
            <span className="back-icon">←</span>
            <span className="back-text">Back</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default RegisterPage;
