import React, { useState, useEffect, useRef } from 'react';
import '../styles/ChatBoxPage.css';
import SocketService from '../services/socketService';

export default function ChatBoxPage({ user }) {
  const [availableContacts, setAvailableContacts] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [socket, setSocket] = useState(null);
  const messagesEndRef = useRef(null);
  const listenerSetupDone = useRef(false);

  // Initialize socket and fetch contacts on component mount
  useEffect(() => {
    const token = localStorage.getItem('authToken');
    if (!token || !user?.id) {
      setError('Not authenticated');
      setLoading(false);
      return;
    }

    console.log('🔌 Initializing chat for user:', user.name, user.role);

    // Connect to WebSocket
    const socketInstance = SocketService.connect(token);
    setSocket(socketInstance);

    // Fetch available contacts from database
    fetchAvailableContacts();

    return () => {
      console.log('🧹 ChatBoxPage cleanup');
      // Remove specific listeners on unmount
      SocketService.removeListener('receive_message');
      SocketService.removeListener('error');
    };
  }, [user]);

  // Set up message listeners ONLY ONCE after socket is available
  useEffect(() => {
    if (!socket || listenerSetupDone.current) {
      console.log('⏭️ Skipping listener setup - socket:', socket ? 'ready' : 'not ready', 'done:', listenerSetupDone.current);
      return;
    }

    console.log('📡 Setting up socket listeners...');
    listenerSetupDone.current = true;

    // Listen for incoming messages
    SocketService.onMessageReceived((message) => {
      console.log('📨 Received message in ChatBoxPage:', message);
      setMessages(prev => {
        // Avoid duplicates
        if (prev.some(m => m.id === message.id)) {
          return prev;
        }
        return [...prev, message];
      });
    });

    // Listen for errors
    SocketService.onError((errorData) => {
      console.error('❌ Socket Error:', errorData);
      setError(errorData.message || 'An error occurred');
      setTimeout(() => setError(''), 3000);
    });

    return () => {
      // Don't cleanup listeners here - they're cleaned up on component unmount
      // This prevents re-registration on every render
    };
  }, [socket]);

  // Auto-scroll to latest message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const fetchAvailableContacts = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('authToken');
      
      console.log('📱 Fetching available contacts...');
      const response = await fetch('http://localhost:5000/api/messages/available-contacts', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        console.log(`✅ Loaded ${data.count} contacts:`, data.contacts);
        setAvailableContacts(data.contacts || []);
        setError('');

        // Auto-select first contact if available
        if (data.contacts && data.contacts.length > 0) {
          loadChatHistory(data.contacts[0]);
        }
      } else {
        const errorData = await response.json();
        console.error('❌ Failed to fetch contacts:', errorData);
        setError(errorData.message || 'Failed to load contacts');
      }
    } catch (err) {
      console.error('❌ Error fetching contacts:', err);
      setError('Error loading contacts: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const loadChatHistory = async (contact) => {
    try {
      console.log(`💬 Loading chat history with ${contact.name}`);
      setSelectedUser(contact);
      setMessages([]);

      const token = localStorage.getItem('authToken');
      const response = await fetch(`http://localhost:5000/api/messages/between/${contact.id}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        console.log(`✅ Loaded ${data.count} messages`);
        setMessages(data.messages || []);
      } else {
        console.warn('⚠️ Could not load message history');
      }
    } catch (err) {
      console.error('❌ Error loading chat history:', err);
      setError('Error loading chat history');
    }
  };

  const handleSendMessage = async () => {
    if (!newMessage.trim() || !selectedUser) {
      console.warn('⚠️ Cannot send: empty message or no contact selected');
      return;
    }

    console.log(`📤 Sending message to ${selectedUser.name}:`, newMessage);
    
    const messageContent = newMessage;
    const toId = parseInt(selectedUser.id);

    // Emit via WebSocket
    if (socket && socket.connected) {
      SocketService.sendMessage(toId, messageContent);
      console.log('✅ Message emitted via socket');
    } else {
      console.warn('⚠️ Socket not connected, only saving via REST');
    }

    // Also save via REST API for persistence
    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch('http://localhost:5000/api/messages/send', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          toId: toId,
          content: messageContent
        })
      });

      if (response.ok) {
        const savedMessage = await response.json();
        console.log('✅ Message saved via API');
      } else {
        console.error('❌ Failed to save message via API');
      }
    } catch (err) {
      console.error('❌ Error saving message:', err);
    }
    
    // Add message to local state immediately for instant display
    setMessages(prev => [...prev, {
      id: Date.now(),
      fromId: user.id,
      toId: toId,
      content: messageContent,
      createdAt: new Date().toISOString(),
      from: { id: user.id, name: user.name, role: user.role },
      to: selectedUser
    }]);

    setNewMessage('');
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const getRoleEmoji = (role) => {
    switch(role?.toUpperCase()) {
      case 'ADMIN':
        return '👨‍💼';
      case 'OWNER':
        return '👑';
      case 'MANAGER':
        return '📊';
      case 'FLOOR_MANAGER':
        return '👷';
      case 'WORKER':
        return '👤';
      default:
        return '💬';
    }
  };

  const getRoleColor = (role) => {
    switch(role?.toUpperCase()) {
      case 'ADMIN':
        return '#EF4444';
      case 'OWNER':
        return '#9333EA';
      case 'MANAGER':
        return '#1B4332';
      case 'FLOOR_MANAGER':
        return '#D97706';
      case 'WORKER':
        return '#10B981';
      default:
        return '#666';
    }
  };

  if (loading) {
    return (
      <div className="chatbox-page-container">
        <div className="loading-state">Loading contacts...</div>
      </div>
    );
  }

  return (
    <div className="chatbox-page-container">
      <div className="chatbox-layout">
        {/* Contacts List */}
        <aside className="conversation-users">
          <h3>💬 Contacts</h3>
          {error && <div className="error-message">{error}</div>}
          
          {availableContacts.length === 0 ? (
            <div className="no-contacts">No contacts available for your role</div>
          ) : (
            <div className="users-list">
              {availableContacts.map(contact => (
                <div
                  key={contact.id}
                  className={`user-item ${selectedUser?.id === contact.id ? 'active' : ''}`}
                  onClick={() => loadChatHistory(contact)}
                  style={{ borderLeftColor: getRoleColor(contact.role) }}
                >
                  <div className="user-avatar">{getRoleEmoji(contact.role)}</div>
                  <div className="user-info">
                    <p className="user-name">{contact.name}</p>
                    <p className="user-role">{contact.role.replace(/_/g, ' ')}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </aside>

        {/* Chat Area */}
        <div className="chat-area">
          {selectedUser ? (
            <>
              <div className="chat-header">
                <div className="selected-user-info">
                  <div className="user-avatar-large">{getRoleEmoji(selectedUser.role)}</div>
                  <div>
                    <h2>{selectedUser.name}</h2>
                    <p>{selectedUser.role.replace(/_/g, ' ')} {selectedUser.department ? `- ${selectedUser.department}` : ''}</p>
                  </div>
                </div>
              </div>

              <div className="chat-messages">
                {messages.length === 0 ? (
                  <div className="no-messages">
                    <p>No messages yet. Start the conversation!</p>
                  </div>
                ) : (
                  messages.map((msg) => (
                    <div 
                      key={msg.id} 
                      className={`message ${msg.fromId === user?.id ? 'sent' : 'received'}`}
                    >
                      <div className="message-avatar">
                        {getRoleEmoji(msg.from?.role || msg.to?.role)}
                      </div>
                      <div className="message-content">
                        <p className="message-sender">{msg.from?.name || msg.to?.name || 'Unknown'}</p>
                        <div className="message-bubble">
                          {msg.content}
                        </div>
                        <p className="message-time">
                          {new Date(msg.createdAt).toLocaleTimeString([], { 
                            hour: '2-digit', 
                            minute: '2-digit' 
                          })}
                        </p>
                      </div>
                    </div>
                  ))
                )}
                <div ref={messagesEndRef} />
              </div>

              <div className="chat-input-area">
                <textarea
                  value={newMessage}
                  onChange={(e) => setNewMessage(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="Type your message... (Press Enter to send)"
                  className="chat-input"
                  rows="3"
                />
                <button 
                  onClick={handleSendMessage}
                  className="btn-send-message"
                  disabled={!newMessage.trim()}
                >
                  📤 Send
                </button>
              </div>
            </>
          ) : (
            <div className="no-chat">
              <p>Select a contact to start chatting</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
