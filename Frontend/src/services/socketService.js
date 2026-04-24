import { io } from 'socket.io-client';

let socket = null;
let listeners = new Map(); // Track registered listeners

const SocketService = {
  connect: (token) => {
    if (socket && socket.connected) {
      console.log('🔄 Socket already connected, reusing...');
      return socket;
    }

    console.log('🔌 Creating new socket connection...');
    
    socket = io('http://localhost:5000', {
      auth: {
        token: token
      },
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: 5
    });

    socket.on('connect', () => {
      console.log('✅ Connected to WebSocket server');
    });

    socket.on('connect_error', (error) => {
      console.error('❌ Connection error:', error);
    });

    socket.on('disconnect', () => {
      console.log('❌ Disconnected from WebSocket server');
    });

    return socket;
  },

  disconnect: () => {
    if (socket) {
      // Clear all tracked listeners
      listeners.forEach((_, eventName) => {
        socket.off(eventName);
      });
      listeners.clear();
      socket.disconnect();
      socket = null;
      console.log('🔌 Socket disconnected and cleaned up');
    }
  },

  sendMessage: (toId, content) => {
    if (socket && socket.connected) {
      const toIdNum = parseInt(toId);
      console.log(`📤 Emitting send_message to ${toIdNum}`, { toId: toIdNum, content: content.substring(0, 50) });
      socket.emit('send_message', { toId: toIdNum, content });
    } else {
      console.warn('⚠️ Socket not connected');
    }
  },

  onMessageReceived: (callback) => {
    if (socket) {
      // Remove old listener if exists
      if (listeners.has('receive_message')) {
        socket.off('receive_message', listeners.get('receive_message'));
      }
      // Register new listener
      socket.on('receive_message', callback);
      listeners.set('receive_message', callback);
      console.log('📨 receive_message listener registered');
    } else {
      console.warn('⚠️ Socket not available');
    }
  },

  onMessageSent: (callback) => {
    if (socket) {
      if (listeners.has('message_sent')) {
        socket.off('message_sent', listeners.get('message_sent'));
      }
      socket.on('message_sent', callback);
      listeners.set('message_sent', callback);
    }
  },

  onError: (callback) => {
    if (socket) {
      if (listeners.has('error')) {
        socket.off('error', listeners.get('error'));
      }
      socket.on('error', callback);
      listeners.set('error', callback);
      console.log('❌ error listener registered');
    }
  },

  onUserOnline: (callback) => {
    if (socket) {
      if (listeners.has('user_online')) {
        socket.off('user_online', listeners.get('user_online'));
      }
      socket.on('user_online', callback);
      listeners.set('user_online', callback);
    }
  },

  onUserOffline: (callback) => {
    if (socket) {
      if (listeners.has('user_offline')) {
        socket.off('user_offline', listeners.get('user_offline'));
      }
      socket.on('user_offline', callback);
      listeners.set('user_offline', callback);
    }
  },

  onUserTyping: (callback) => {
    if (socket) {
      if (listeners.has('user_typing')) {
        socket.off('user_typing', listeners.get('user_typing'));
      }
      socket.on('user_typing', callback);
      listeners.set('user_typing', callback);
    }
  },

  onUserStoppedTyping: (callback) => {
    if (socket) {
      if (listeners.has('user_stopped_typing')) {
        socket.off('user_stopped_typing', listeners.get('user_stopped_typing'));
      }
      socket.on('user_stopped_typing', callback);
      listeners.set('user_stopped_typing', callback);
    }
  },

  sendTyping: (toId) => {
    if (socket && socket.connected) {
      socket.emit('typing', { toId: parseInt(toId) });
    }
  },

  sendStopTyping: (toId) => {
    if (socket && socket.connected) {
      socket.emit('stop_typing', { toId: parseInt(toId) });
    }
  },

  removeListener: (eventName) => {
    if (socket && listeners.has(eventName)) {
      socket.off(eventName, listeners.get(eventName));
      listeners.delete(eventName);
      console.log(`🧹 Removed listener: ${eventName}`);
    }
  },

  removeAllListeners: () => {
    listeners.forEach((_, eventName) => {
      if (socket) {
        socket.off(eventName);
      }
    });
    listeners.clear();
    console.log('🧹 All listeners removed');
  },

  getSocket: () => socket
};

export default SocketService;
