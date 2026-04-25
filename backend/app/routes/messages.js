const express = require('express');
const router = express.Router();
const {
  sendMessage,
  getMessagesBetween,
  getConversations,
  markAsRead,
  getUnreadCount,
  deleteMessage,
  getAvailableContacts
} = require('../controllers/messageController');
const { auth } = require('../middleware/auth');

// All routes require authentication
router.use(auth);

// Send message
router.post('/send', sendMessage);

// Get messages between two users
router.get('/between/:userId', getMessagesBetween);

// Get all conversations
router.get('/conversations', getConversations);

// Get available contacts based on role
router.get('/available-contacts', getAvailableContacts);

// Get unread count
router.get('/unread/count', getUnreadCount);

// Mark message as read
router.put('/:messageId/read', markAsRead);

// Delete message
router.delete('/:messageId', deleteMessage);

module.exports = router;

// Delete message
router.delete('/:messageId', deleteMessage);

module.exports = router;
