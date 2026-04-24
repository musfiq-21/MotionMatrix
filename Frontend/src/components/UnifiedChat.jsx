import React, { useState, useEffect, useRef } from 'react';
import '../styles/UnifiedChat.css';
import SocketService from '../services/socketService';

export default function UnifiedChat({ user }) {
  const [contacts, setContacts] = useState([]);
  const [selectedContact, setSelectedContact] = useState(null);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [socket, setSocket] = useState(null);
  const [onlineUsers, setOnlineUsers] = useState(new Set());
  const [typingUsers, setTypingUsers] = useState(new Set());
  const [searchQuery, setSearchQuery] = useState('');
  const messagesEndRef = useRef(null);
  const listenerSetupDone = useRef(false);
  const typingTimeoutRef = useRef(null);
  const processedMessageIds = useRef(new Set()); // Track processed message IDs
  const recentMessageHashes = useRef(new Map()); // Track recent messages by content hash with timestamp

  // Initialize socket connection
  useEffect(() => {
    const token = localStorage.getItem('authToken');
    if (!token || !user?.id) {
      setError('Not authenticated');
      setLoading(false);
      return;
    }

    console.log('🔌 UnifiedChat: Initializing for user:', user.name, user.role);
    const socketInstance = SocketService.connect(token);
    setSocket(socketInstance);
    fetchContacts();

    return () => {
      console.log('🧹 UnifiedChat cleanup');
      SocketService.removeListener('receive_message');
      SocketService.removeListener('error');
      SocketService.removeListener('user_online');
      SocketService.removeListener('user_offline');
      SocketService.removeListener('user_typing');
      SocketService.removeListener('user_stopped_typing');
    };
  }, [user]);

  // Set up socket listeners
  useEffect(() => {
    if (!socket || listenerSetupDone.current) return;

    console.log('📡 Setting up socket listeners...');
    listenerSetupDone.current = true;

    SocketService.onMessageReceived((message) => {
      console.log('📨 Received message via socket:', message);
      
      // Check 1: If ID already processed
      if (processedMessageIds.current.has(message.id)) {
        console.log('⏭️ Message ID already processed, skipping:', message.id);
        return;
      }
      
      // Check 2: If same content arrived recently (duplicate detection)
      if (isRecentDuplicate(message)) {
        console.log('⏭️ Duplicate message content detected, skipping:', message.content);
        return;
      }
      
      // Check 3: If already in current messages state
      setMessages(prev => {
        const alreadyExists = prev.some(m => m.id === message.id);
        if (alreadyExists) {
          console.log('⏭️ Message already in state, skipping:', message.id);
          return prev;
        }
        
        // Skip if own message (already added via REST API)
        if (message.fromId === user?.id) {
          console.log('⏭️ Skipping own message (already added via REST API)');
          return prev;
        }
        
        // Mark as processed
        processedMessageIds.current.add(message.id);
        const hash = `${message.fromId}:${message.toId}:${message.content}`;
        recentMessageHashes.current.set(hash, Date.now());
        
        console.log('✅ Adding new message to state');
        return [...prev, message];
      });
    });

    SocketService.onError((errorData) => {
      console.error('❌ Socket error:', errorData);
      setError(errorData.message);
      setTimeout(() => setError(''), 5000);
    });

    SocketService.onUserOnline((data) => {
      console.log('🟢 User online:', data.userId);
      setOnlineUsers(prev => new Set([...prev, data.userId]));
    });

    SocketService.onUserOffline((data) => {
      console.log('🔴 User offline:', data.userId);
      setOnlineUsers(prev => {
        const newSet = new Set(prev);
        newSet.delete(data.userId);
        return newSet;
      });
    });

    SocketService.onUserTyping((data) => {
      if (selectedContact?.id === data.fromId) {
        setTypingUsers(prev => new Set([...prev, data.fromId]));
      }
    });

    SocketService.onUserStoppedTyping((data) => {
      setTypingUsers(prev => {
        const newSet = new Set(prev);
        newSet.delete(data.fromId);
        return newSet;
      });
    });
  }, [socket, user?.id]);

  // Auto-scroll to latest message
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Fetch available contacts
  const fetchContacts = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('authToken');
      const response = await fetch('http://localhost:5000/api/messages/available-contacts', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        console.log('✅ Loaded contacts:', data.contacts);
        setContacts(data.contacts || []);
        
        if (data.contacts?.length > 0) {
          processedMessageIds.current.clear(); // Clear for initial load
          recentMessageHashes.current.clear();
          setSelectedContact(data.contacts[0]);
          setMessages([]); // Clear old messages
          loadMessages(data.contacts[0].id);
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

  // Load chat history
  const loadMessages = async (contactId) => {
    try {
      const token = localStorage.getItem('authToken');
      console.log(`📥 Loading message history with contact ID: ${contactId}`);
      
      const response = await fetch(`http://localhost:5000/api/messages/between/${contactId}`, {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        console.log(`✅ Loaded ${data.count} messages:`, data.messages);
        
        // Mark all loaded messages as processed
        data.messages?.forEach(msg => {
          processedMessageIds.current.add(msg.id);
          // Create hash for duplicate detection
          const hash = `${msg.fromId}:${msg.toId}:${msg.content}`;
          recentMessageHashes.current.set(hash, Date.now());
        });
        
        setMessages(data.messages || []);
      } else {
        const errorData = await response.json();
        console.error('❌ Failed to load messages:', errorData);
        setMessages([]);
      }
    } catch (err) {
      console.error('❌ Error loading messages:', err);
      setMessages([]);
    }
  };

  // Helper function to check if message is a recent duplicate
  const isRecentDuplicate = (msg) => {
    const hash = `${msg.fromId}:${msg.toId}:${msg.content}`;
    const lastSeen = recentMessageHashes.current.get(hash);
    
    if (!lastSeen) return false;
    
    // If same content was seen within last 2 seconds, it's a duplicate
    const timeDiff = Date.now() - lastSeen;
    return timeDiff < 2000;
  };

  // Handle contact selection
  const handleSelectContact = (contact) => {
    console.log(`📞 Selecting contact: ${contact.name}`);
    setSelectedContact(contact);
    setTypingUsers(new Set());
    setMessages([]); // Clear old messages first
    processedMessageIds.current.clear(); // Clear processed IDs for new contact
    recentMessageHashes.current.clear(); // Clear hash cache for new contact
    loadMessages(contact.id);
  };

  // Handle send message
  const handleSendMessage = async () => {
    if (!newMessage.trim() || !selectedContact) {
      console.warn('⚠️ Cannot send: empty message or no contact selected');
      return;
    }

    const messageContent = newMessage;
    const toId = parseInt(selectedContact.id);

    try {
      const token = localStorage.getItem('authToken');
      
      console.log(`\n${'='.repeat(50)}`);
      console.log(`📤 SENDING MESSAGE`);
      console.log(`To: ${selectedContact.name} (ID: ${toId})`);
      console.log(`Content: "${messageContent.substring(0, 50)}..."`);

      // Save via REST API
      const response = await fetch('http://localhost:5000/api/messages/send', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ toId, content: messageContent })
      });

      console.log(`REST API Response: ${response.status} ${response.statusText}`);

      if (response.ok) {
        const data = await response.json();
        console.log('✅ Message saved via API:', data.data);
        
        // Add message to state using server-provided ID
        const savedMessage = {
          id: data.data.id,
          fromId: user.id,
          toId,
          content: messageContent,
          createdAt: data.data.createdAt || new Date().toISOString(),
          from: { id: user.id, name: user.name, role: user.role },
          to: selectedContact
        };
        
        // Mark as processed before emitting socket
        processedMessageIds.current.add(savedMessage.id);
        const hash = `${user.id}:${toId}:${messageContent}`;
        recentMessageHashes.current.set(hash, Date.now());
        console.log('🏷️ Message marked as processed with hash:', hash);
        
        setMessages(prev => [...prev, savedMessage]);
        setNewMessage('');
        
        // Emit via socket only after REST API succeeds
        if (socket?.connected) {
          SocketService.sendMessage(toId, messageContent);
          console.log('✅ Message emitted via socket');
        }
        
        console.log(`${'='.repeat(50)}\n`);
      } else {
        const errorData = await response.json();
        console.error('❌ REST API Error:', errorData);
        setError(errorData.message || 'Failed to send message');
        console.log(`${'='.repeat(50)}\n`);
      }
    } catch (error) {
      console.error('❌ Error sending message:', error);
      setError('Failed to send message: ' + error.message);
    }
  };

  // Handle typing
  const handleTyping = () => {
    if (selectedContact && socket?.connected) {
      SocketService.sendTyping(parseInt(selectedContact.id));
      
      clearTimeout(typingTimeoutRef.current);
      typingTimeoutRef.current = setTimeout(() => {
        SocketService.sendStopTyping(parseInt(selectedContact.id));
      }, 3000);
    }
  };

  // Handle key press
  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  // Filter contacts based on search
  const filteredContacts = contacts.filter(contact =>
    contact.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    contact.role.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Get filtered messages for selected contact
  const filteredMessages = messages.filter(msg =>
    (msg.fromId === user?.id && msg.toId === selectedContact?.id) ||
    (msg.fromId === selectedContact?.id && msg.toId === user?.id)
  );

  if (loading) {
    return (
      <div className="unified-chat-container">
        <div className="loading-state">
          <div className="spinner"></div>
          <p>Loading chat...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="unified-chat-container">
      <div className="chat-wrapper">
        {/* Sidebar */}
        <div className="chat-sidebar">
          <div className="sidebar-header">
            <h2>💬 Messages</h2>
            <button className="btn-refresh" onClick={fetchContacts} title="Refresh">
              🔄
            </button>
          </div>

          {/* Search Bar */}
          <div className="search-container">
            <input
              type="text"
              placeholder="Search contacts..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="search-input"
            />
          </div>

          {/* Contacts List */}
          <div className="contacts-container">
            {filteredContacts.length === 0 ? (
              <div className="no-contacts">
                <p>No contacts available</p>
              </div>
            ) : (
              filteredContacts.map(contact => (
                <div
                  key={contact.id}
                  className={`contact-item ${selectedContact?.id === contact.id ? 'active' : ''}`}
                  onClick={() => handleSelectContact(contact)}
                >
                  <div className="contact-avatar">
                    <span className="avatar-text">{contact.name.charAt(0).toUpperCase()}</span>
                    {onlineUsers.has(contact.id) && <span className="online-indicator"></span>}
                  </div>
                  <div className="contact-details">
                    <div className="contact-name">{contact.name}</div>
                    <div className="contact-role">{contact.role.replace(/_/g, ' ')}</div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Main Chat Area */}
        <div className="chat-main">
          {!selectedContact ? (
            <div className="empty-state">
              <div className="empty-icon">💬</div>
              <h2>Select a contact to start chatting</h2>
              <p>Choose a contact from the list to view conversation</p>
            </div>
          ) : (
            <>
              {/* Chat Header */}
              <div className="chat-header">
                <div className="header-info">
                  <div className="header-avatar">
                    {selectedContact.name.charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <h3>{selectedContact.name}</h3>
                    <p>{selectedContact.role.replace(/_/g, ' ')}</p>
                  </div>
                </div>
                {onlineUsers.has(selectedContact.id) && (
                  <div className="online-status">🟢 Online</div>
                )}
              </div>

              {/* Messages Area */}
              <div className="messages-area">
                {filteredMessages.length === 0 ? (
                  <div className="no-messages">
                    <p>No messages yet. Start the conversation!</p>
                  </div>
                ) : (
                  <div className="messages-list">
                    {filteredMessages.map((msg, idx) => (
                      <div
                        key={msg.id || idx}
                        className={`message-group ${msg.fromId === user?.id ? 'sent' : 'received'}`}
                      >
                        {msg.fromId !== user?.id && (
                          <div className="message-avatar-small">
                            {selectedContact.name.charAt(0).toUpperCase()}
                          </div>
                        )}
                        <div className="message-bubble">
                          <p className="message-text">{msg.content}</p>
                          <span className="message-time">
                            {new Date(msg.createdAt).toLocaleTimeString([], {
                              hour: '2-digit',
                              minute: '2-digit'
                            })}
                          </span>
                        </div>
                      </div>
                    ))}
                    {typingUsers.has(selectedContact.id) && (
                      <div className="message-group received">
                        <div className="message-avatar-small">
                          {selectedContact.name.charAt(0).toUpperCase()}
                        </div>
                        <div className="message-bubble typing-indicator">
                          <span></span>
                          <span></span>
                          <span></span>
                        </div>
                      </div>
                    )}
                    <div ref={messagesEndRef} />
                  </div>
                )}
              </div>

              {/* Error Message */}
              {error && (
                <div className="error-banner">
                  <span>⚠️ {error}</span>
                  <button onClick={() => setError('')}>✕</button>
                </div>
              )}

              {/* Message Input */}
              <div className="message-input-area">
                <textarea
                  value={newMessage}
                  onChange={(e) => {
                    setNewMessage(e.target.value);
                    handleTyping();
                  }}
                  onKeyPress={handleKeyPress}
                  placeholder="Type your message..."
                  className="message-textarea"
                  rows="3"
                />
                <button
                  onClick={handleSendMessage}
                  className="btn-send"
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
