import React, { useState, useEffect, useRef } from 'react';
import '../styles/WorkerChatBox.css';
import SocketService from '../services/socketService';

export default function WorkerChatBox({ user }) {
  const [availableContacts, setAvailableContacts] = useState([]);
  const [selectedContact, setSelectedContact] = useState(null);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [socket, setSocket] = useState(null);
  const messagesEndRef = useRef(null);
  const listenerSetupDone = useRef(false);

  useEffect(() => {
    const token = localStorage.getItem('authToken');
    if (!token || !user?.id) {
      setError('Not authenticated');
      setLoading(false);
      return;
    }

    console.log('🔌 Worker Chat: Initializing for user:', user.name);

    // Connect to WebSocket
    const socketInstance = SocketService.connect(token);
    setSocket(socketInstance);

    // Fetch available contacts
    fetchAvailableContacts();

    return () => {
      console.log('🧹 WorkerChatBox cleanup');
      SocketService.removeListener('receive_message');
      SocketService.removeListener('error');
    };
  }, [user]);

  // Set up message listeners ONLY ONCE after socket is available
  useEffect(() => {
    if (!socket || listenerSetupDone.current) {
      return;
    }

    console.log('📡 Setting up socket listeners in WorkerChatBox...');
    listenerSetupDone.current = true;

    SocketService.onMessageReceived((message) => {
      console.log('📨 Worker received message:', message);
      setMessages(prev => {
        // Avoid duplicates
        if (prev.some(m => m.id === message.id)) {
          return prev;
        }
        return [...prev, message];
      });
    });

    SocketService.onError((errorData) => {
      console.error('❌ Error:', errorData);
      setError(errorData.message);
      setTimeout(() => setError(''), 3000);
    });
  }, [socket]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const fetchAvailableContacts = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('authToken');
      
      console.log('📱 Worker fetching available contacts...');
      const response = await fetch('http://localhost:5000/api/messages/available-contacts', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        console.log(`✅ Worker: Loaded ${data.count} contacts:`, data.contacts);
        setAvailableContacts(data.contacts || []);
        // Auto-select first contact if available
        if (data.contacts && data.contacts.length > 0) {
          loadChatHistory(data.contacts[0]);
          setSelectedContact(data.contacts[0]);
        }
        setError('');
      } else {
        setError('Failed to load contacts');
      }
    } catch (err) {
      console.error('❌ Error fetching contacts:', err);
      setError('Error loading contacts');
    } finally {
      setLoading(false);
    }
  };

  const loadChatHistory = async (contact) => {
    try {
      const token = localStorage.getItem('authToken');
      const response = await fetch(`http://localhost:5000/api/messages/between/${contact.id}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        console.log(`✅ Loaded ${data.count} messages`);
        setMessages(data.messages || []);
      }
    } catch (err) {
      console.error('❌ Error loading chat history:', err);
    }
  };

  const handleSelectContact = (contact) => {
    console.log('👤 Selected contact:', contact.name);
    setSelectedContact(contact);
    loadChatHistory(contact);
  };

  const handleSendMessage = async () => {
    if (!newMessage.trim() || !selectedContact) return;

    const messageContent = newMessage;
    const toId = parseInt(selectedContact.id);

    try {
      const token = localStorage.getItem('authToken');
      
      // Emit via Socket.io if connected
      if (socket && socket.connected) {
        SocketService.sendMessage(toId, messageContent);
        console.log('✅ Message emitted via socket');
      }

      // Also send via REST API for persistence
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
        console.log('✅ Message saved via API');
        // Add message to local state immediately
        setMessages(prev => [...prev, {
          id: Date.now(),
          fromId: user.id,
          toId: toId,
          content: messageContent,
          createdAt: new Date().toISOString(),
          from: { id: user.id, name: user.name, role: user.role },
          to: selectedContact
        }]);
        setNewMessage('');
      }
    } catch (error) {
      console.error('❌ Error sending message:', error);
      setError('Failed to send message');
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  if (loading) {
    return (
      <div className="worker-chatbox-container">
        <div className="loading">Loading contacts...</div>
      </div>
    );
  }

  if (availableContacts.length === 0) {
    return (
      <div className="worker-chatbox-container">
        <div className="no-contacts">
          <p>No available contacts to message.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="worker-chatbox-container">
      <div className="chat-wrapper">
        {/* Contacts List */}
        <div className="contacts-panel">
          <h3>💬 Available Contacts</h3>
          {error && <div className="error-message">{error}</div>}
          <div className="contacts-list">
            {availableContacts.map(contact => (
              <div
                key={contact.id}
                className={`contact-item ${selectedContact?.id === contact.id ? 'active' : ''}`}
                onClick={() => handleSelectContact(contact)}
              >
                <div className="contact-avatar">{contact.name.charAt(0)}</div>
                <div className="contact-info">
                  <p className="contact-name">{contact.name}</p>
                  <p className="contact-role">{contact.role}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Chat Area */}
        <div className="chat-panel">
          {selectedContact && (
            <>
              <div className="chat-header">
                <h2>💬 {selectedContact.name}</h2>
                <p>{selectedContact.department}</p>
              </div>

              <div className="chat-messages">
                {messages.length === 0 ? (
                  <div className="no-messages">
                    <p>No messages yet. Start the conversation!</p>
                  </div>
                ) : (
                  messages
                    .filter(msg =>
                      (msg.fromId === user?.id && msg.toId === selectedContact.id) ||
                      (msg.fromId === selectedContact.id && msg.toId === user?.id)
                    )
                    .map((msg, index) => (
                      <div 
                        key={msg.id || index} 
                        className={`message ${msg.fromId === user?.id ? 'sent' : 'received'}`}
                      >
                        <div className="message-bubble">
                          {msg.content}
                        </div>
                        <div className="message-time">
                          {new Date(msg.createdAt).toLocaleTimeString([], { 
                            hour: '2-digit', 
                            minute: '2-digit' 
                          })}
                        </div>
                      </div>
                    ))
                )}
                <div ref={messagesEndRef} />
              </div>

              <div className="chat-input-area">
                <input
                  type="text"
                  value={newMessage}
                  onChange={(e) => setNewMessage(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="Type your message..."
                  className="chat-input"
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
          )}
        </div>
      </div>
    </div>
  );
}

