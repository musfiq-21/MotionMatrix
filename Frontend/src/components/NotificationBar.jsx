import React, { useState, useEffect } from 'react';
import '../styles/NotificationBar.css';

export default function NotificationBar({ floorManagerId, unreadCount, onNotificationUpdate }) {
  const [notifications, setNotifications] = useState([]);
  const [showDropdown, setShowDropdown] = useState(false);

  useEffect(() => {
    // Notifications will be fetched from API in the future
    // For now, initialize empty
    setNotifications([]);
    onNotificationUpdate(0);
  }, [floorManagerId, onNotificationUpdate]);

  const handleNotificationClick = (notificationId) => {
    // Mark notification as read in the future when notifications API is ready
    const updated = notifications.map(n => 
      n.id === notificationId ? { ...n, read: true } : n
    );
    setNotifications(updated);
    const unreadCount = updated.filter(n => !n.read).length;
    onNotificationUpdate(unreadCount);
  };

  const getNotificationIcon = (type) => {
    switch (type) {
      case 'overtime':
        return '⏰';
      case 'production':
        return '📈';
      case 'maintenance':
        return '⚠️';
      default:
        return '🔔';
    }
  };

  const formatTime = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  };

  return (
    <div className="notification-bar-container">
      <button 
        className="notification-bell-btn"
        onClick={() => setShowDropdown(!showDropdown)}
      >
        🔔
        {unreadCount > 0 && <span className="notification-badge">{unreadCount}</span>}
      </button>

      {showDropdown && (
        <div className="notification-dropdown-panel">
          <div className="notification-dropdown-header">
            <h3>Notifications</h3>
            <button 
              className="notification-close-btn"
              onClick={() => setShowDropdown(false)}
            >
              ✕
            </button>
          </div>
          
          <div className="notification-dropdown-content">
            {notifications.length === 0 ? (
              <div className="notification-empty-state">
                <p>No notifications</p>
              </div>
            ) : (
              <div className="notification-list">
                {notifications.map(notification => (
                  <div 
                    key={notification.id}
                    className={`notification-item ${!notification.read ? 'unread' : ''}`}
                    onClick={() => handleNotificationClick(notification.id)}
                  >
                    <div className="notification-icon">
                      {getNotificationIcon(notification.type)}
                    </div>
                    <div className="notification-content">
                      <h4>{notification.title}</h4>
                      <p>{notification.message}</p>
                      <span className="notification-time">{formatTime(notification.timestamp)}</span>
                    </div>
                    {!notification.read && <div className="notification-read-dot" />}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
