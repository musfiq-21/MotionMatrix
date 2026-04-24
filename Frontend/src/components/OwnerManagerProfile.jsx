import React, { useState, useEffect } from 'react';
import '../styles/OwnerManagerProfile.css';
import '../styles/messaging-modal.css';
import SocketService from '../services/socketService';

export default function OwnerManagerProfile({ user, currentUser }) {
  const [showEditModal, setShowEditModal] = useState(false);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [showMessagingModal, setShowMessagingModal] = useState(false);
  const [messages, setMessages] = useState([]);
  const [messageText, setMessageText] = useState('');
  const [socket, setSocket] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    department: ''
  });
  const [passwordData, setPasswordData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [editMessage, setEditMessage] = useState('');
  const [passwordMessage, setPasswordMessage] = useState('');

  useEffect(() => {
    setFormData({
      name: user?.name || '',
      email: user?.email || '',
      department: user?.department || ''
    });
  }, [user]);

  useEffect(() => {
    const token = localStorage.getItem('authToken');
    if (token && showMessagingModal) {
      const socketInstance = SocketService.connect(token);
      setSocket(socketInstance);
      loadMessages();
      SocketService.onMessageReceived((msg) => {
        setMessages(prev => [...prev, msg]);
      });
    }
  }, [showMessagingModal]);

  const loadMessages = async () => {
    try {
      if (!user?.id || !currentUser?.id) return;
      const token = localStorage.getItem('authToken');
      const response = await fetch(`http://localhost:5000/api/messages/between/${user.id}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (response.ok) {
        const data = await response.json();
        setMessages(data.messages || []);
      }
    } catch (error) {
      console.error('Error loading messages:', error);
    }
  };

  const sendMessage = async () => {
    if (!messageText.trim() || !socket) return;
    socket.emit('send_message', { toId: user.id, content: messageText });
    setMessageText('');
  };

  const getUserRole = () => {
    return user?.role === 'owner' ? 'Owner' : 'Manager';
  };

  const handleEditProfileClick = () => {
    setEditMessage('');
    setShowEditModal(true);
  };

  const handleChangePasswordClick = () => {
    setPasswordMessage('');
    setPasswordData({
      currentPassword: '',
      newPassword: '',
      confirmPassword: ''
    });
    setShowPasswordModal(true);
  };

  const handleFormChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handlePasswordChange = (e) => {
    const { name, value } = e.target;
    setPasswordData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSaveProfile = async () => {
    if (!formData.name.trim() || !formData.email.trim()) {
      setEditMessage('Please fill in all required fields');
      return;
    }

    try {
      const token = localStorage.getItem('authToken');
      
      if (!user || !user.id) {
        setEditMessage('User information not found');
        return;
      }

      const response = await fetch(`http://localhost:5000/api/users/${user.id}`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: formData.name,
          email: formData.email,
          department: formData.department
        })
      });

      const data = await response.json();

      if (data.success) {
        setEditMessage('✅ Profile updated successfully!');
        setFormData({
          name: data.user.name,
          email: data.user.email,
          department: data.user.department
        });
        setTimeout(() => {
          setShowEditModal(false);
          setEditMessage('');
        }, 1500);
      } else {
        setEditMessage(data.message || 'Error updating profile');
      }
    } catch (error) {
      console.error('Error updating profile:', error);
      setEditMessage('Error: ' + error.message);
    }
  };

  const handleChangePassword = async () => {
    if (!passwordData.currentPassword || !passwordData.newPassword || !passwordData.confirmPassword) {
      setPasswordMessage('Please fill in all fields');
      return;
    }

    if (passwordData.newPassword !== passwordData.confirmPassword) {
      setPasswordMessage('New passwords do not match');
      return;
    }

    try {
      const token = localStorage.getItem('authToken');
      
      if (!user || !user.id) {
        setPasswordMessage('User information not found');
        return;
      }

      // Call backend API to change password
      const response = await fetch(`http://localhost:5000/api/auth/change-password`, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          currentPassword: passwordData.currentPassword,
          newPassword: passwordData.newPassword
        })
      });

      const data = await response.json();

      if (data.success) {
        setPasswordMessage('✅ Password changed successfully!');
        setTimeout(() => {
          setShowPasswordModal(false);
          setPasswordMessage('');
          setPasswordData({
            currentPassword: '',
            newPassword: '',
            confirmPassword: ''
          });
        }, 1500);
      } else {
        setPasswordMessage(data.message || 'Error changing password');
      }
    } catch (error) {
      console.error('Error changing password:', error);
      setPasswordMessage('Error: ' + error.message);
    }
  };

  return (
    <div className="om-profile-container">
      <div className="profile-header">
        <h2>👤 My Profile</h2>
      </div>

      {/* Horizontal Profile Card */}
      <div className="profile-card-horizontal">
        <div className="profile-left">
          <div className="profile-avatar-large">
            {user?.role === 'owner' ? '👑' : '📊'}
          </div>
          <div className="profile-name-section">
            <h2>{user?.name}</h2>
            <p className="role-badge">{getUserRole()}</p>
          </div>
        </div>

        <div className="profile-divider-vertical"></div>

        <div className="profile-right">
          <div className="profile-detail-row">
            <div className="detail-col">
              <span className="detail-label">Employee ID</span>
              <span className="detail-value">#{user?.id}</span>
            </div>
            <div className="detail-col">
              <span className="detail-label">Department</span>
              <span className="detail-value">{user?.department}</span>
            </div>
            <div className="detail-col">
              <span className="detail-label">Email</span>
              <span className="detail-value">{user?.email}</span>
            </div>
            <div className="detail-col">
              <span className="detail-label">Status</span>
              <span className="detail-value status-active">🟢 Active</span>
            </div>
          </div>
        </div>
      </div>

      {/* Work Information Section */}
      <div className="work-info-section">
        <h3>Role Information</h3>
        
        <div className="info-grid">
          <div className="info-box">
            <span className="info-icon">📍</span>
            <div className="info-content">
              <p className="info-label">Department</p>
              <p className="info-value">{user?.department}</p>
            </div>
          </div>

          <div className="info-box">
            <span className="info-icon">👥</span>
            <div className="info-content">
              <p className="info-label">Role</p>
              <p className="info-value">{getUserRole()}</p>
            </div>
          </div>

          <div className="info-box">
            <span className="info-icon">📅</span>
            <div className="info-content">
              <p className="info-label">Member Since</p>
              <p className="info-value">{user?.createdAt ? new Date(user.createdAt).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) : 'N/A'}</p>
            </div>
          </div>

          <div className="info-box">
            <span className="info-icon">🌐</span>
            <div className="info-content">
              <p className="info-label">Status</p>
              <p className="info-value">🟢 {user?.status || 'Active'}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="profile-actions">
        <button className="action-button primary" onClick={handleEditProfileClick}>
          ✎ Edit Profile
        </button>
        <button className="action-button secondary" onClick={handleChangePasswordClick}>
          🔐 Change Password
        </button>
        {currentUser?.id !== user?.id && (
          <button className="action-button message" onClick={() => setShowMessagingModal(true)}>
            💬 Send Message
          </button>
        )}
      </div>

      {/* Edit Profile Modal */}
      {showEditModal && (
        <div className="profile-modal-overlay" onClick={() => setShowEditModal(false)}>
          <div className="profile-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>✎ Edit Profile</h3>
              <button className="modal-close" onClick={() => setShowEditModal(false)}>✕</button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Full Name</label>
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleFormChange}
                  placeholder="Enter your name"
                />
              </div>
              <div className="form-group">
                <label>Email</label>
                <input
                  type="email"
                  name="email"
                  value={formData.email}
                  onChange={handleFormChange}
                  placeholder="Enter your email"
                />
              </div>
              <div className="form-group">
                <label>Department</label>
                <input
                  type="text"
                  name="department"
                  value={formData.department}
                  onChange={handleFormChange}
                  placeholder="Department"
                  disabled
                />
              </div>
              {editMessage && (
                <div className={`message ${editMessage.includes('Error') || editMessage.includes('Please') ? 'error' : 'success'}`}>
                  {editMessage}
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button className="btn-cancel" onClick={() => setShowEditModal(false)}>Cancel</button>
              <button className="btn-save" onClick={handleSaveProfile}>Save Changes</button>
            </div>
          </div>
        </div>
      )}

      {/* Messaging Modal */}
      {showMessagingModal && (
        <div className="profile-modal-overlay" onClick={() => setShowMessagingModal(false)}>
          <div className="profile-modal messaging-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>💬 Message {user?.name}</h3>
              <button className="modal-close" onClick={() => setShowMessagingModal(false)}>✕</button>
            </div>
            <div className="modal-body chat-body">
              <div className="chat-messages">
                {messages.map((msg, idx) => (
                  <div key={idx} className={`message-item ${msg.fromId === currentUser?.id ? 'sent' : 'received'}`}>
                    <p className="message-text">{msg.content}</p>
                    <span className="message-time">{new Date(msg.createdAt).toLocaleTimeString()}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="modal-footer chat-footer">
              <input
                type="text"
                value={messageText}
                onChange={(e) => setMessageText(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                placeholder="Type message..."
                className="message-input"
              />
              <button onClick={sendMessage} className="btn-send">Send</button>
            </div>
          </div>
        </div>
      )}

      {/* Change Password Modal */}
      {showPasswordModal && (
        <div className="profile-modal-overlay" onClick={() => setShowPasswordModal(false)}>
          <div className="profile-modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>🔐 Change Password</h3>
              <button className="modal-close" onClick={() => setShowPasswordModal(false)}>✕</button>
            </div>
            <div className="modal-body">
              <div className="form-group">
                <label>Current Password</label>
                <input
                  type="password"
                  name="currentPassword"
                  value={passwordData.currentPassword}
                  onChange={handlePasswordChange}
                  placeholder="Enter current password"
                />
              </div>
              <div className="form-group">
                <label>New Password</label>
                <input
                  type="password"
                  name="newPassword"
                  value={passwordData.newPassword}
                  onChange={handlePasswordChange}
                  placeholder="Enter new password"
                />
              </div>
              <div className="form-group">
                <label>Confirm Password</label>
                <input
                  type="password"
                  name="confirmPassword"
                  value={passwordData.confirmPassword}
                  onChange={handlePasswordChange}
                  placeholder="Confirm new password"
                />
              </div>
              {passwordMessage && (
                <div className={`message ${passwordMessage.includes('Error') || passwordMessage.includes('incorrect') || passwordMessage.includes('not match') || passwordMessage.includes('Please') ? 'error' : 'success'}`}>
                  {passwordMessage}
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button className="btn-cancel" onClick={() => setShowPasswordModal(false)}>Cancel</button>
              <button className="btn-save" onClick={handleChangePassword}>Change Password</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
