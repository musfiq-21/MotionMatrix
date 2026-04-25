const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Send message
const sendMessage = async (req, res) => {
  try {
    const { toId, content } = req.body;
    const fromId = req.user.id;
    const io = req.io;

    if (!toId || !content) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields'
      });
    }

    // Ensure toId is a number
    const toIdNum = parseInt(toId);
    if (isNaN(toIdNum)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid recipient ID'
      });
    }

    // Verify recipient exists
    const recipient = await prisma.user.findUnique({
      where: { id: toIdNum },
      select: { id: true, name: true, role: true, assignedFloorId: true }
    });

    if (!recipient) {
      return res.status(404).json({
        success: false,
        message: 'Recipient not found'
      });
    }

    // Get sender info
    const sender = await prisma.user.findUnique({
      where: { id: parseInt(fromId) },
      select: { id: true, name: true, role: true, assignedFloorId: true }
    });

    if (!sender) {
      return res.status(404).json({
        success: false,
        message: 'Sender not found'
      });
    }

    console.log(`\n${'='.repeat(60)}`);
    console.log(`📤 REST API MESSAGE RECEIVED`);
    console.log(`Sender: ${sender.name} (ID: ${sender.id}, Role: ${sender.role})`);
    console.log(`Recipient: ${recipient.name} (ID: ${recipient.id}, Role: ${recipient.role})`);
    console.log(`Content: "${content.substring(0, 50)}..."`);

    const message = await prisma.message.create({
      data: {
        fromId: parseInt(fromId),
        toId: toIdNum,
        content
      },
      include: {
        from: { select: { id: true, name: true, role: true } },
        to: { select: { id: true, name: true, role: true } }
      }
    });

    console.log(`✅ Message SAVED to database (ID: ${message.id})`);

    // NOTE: Socket emission is handled by the socket.io event handler in index.js
    // This REST endpoint only saves the message, real-time delivery is via WebSocket

    console.log(`${'='.repeat(60)}\n`);

    res.status(201).json({
      success: true,
      message: 'Message sent successfully',
      data: message
    });
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to send message',
      error: error.message
    });
  }
};

// Get messages between two users
const getMessagesBetween = async (req, res) => {
  try {
    const { userId } = req.params;
    const currentUserId = req.user.id;

    const messages = await prisma.message.findMany({
      where: {
        OR: [
          {
            fromId: parseInt(currentUserId),
            toId: parseInt(userId)
          },
          {
            fromId: parseInt(userId),
            toId: parseInt(currentUserId)
          }
        ]
      },
      include: {
        from: {
          select: { id: true, name: true, email: true, role: true }
        },
        to: {
          select: { id: true, name: true, email: true, role: true }
        }
      },
      orderBy: { createdAt: 'asc' }
    });

    res.json({
      success: true,
      count: messages.length,
      messages
    });
  } catch (error) {
    console.error('Get messages between error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch messages',
      error: error.message
    });
  }
};

// Get all conversations for current user
const getConversations = async (req, res) => {
  try {
    const userId = req.user.id;

    // Get unique users the current user has messaged
    const conversations = await prisma.message.findMany({
      where: {
        OR: [
          { fromId: parseInt(userId) },
          { toId: parseInt(userId) }
        ]
      },
      include: {
        from: true,
        to: true
      },
      orderBy: { createdAt: 'desc' }
    });

    // Get unique users
    const uniqueUsers = {};
    conversations.forEach(msg => {
      const otherUser = msg.fromId === parseInt(userId) ? msg.to : msg.from;
      if (!uniqueUsers[otherUser.id]) {
        uniqueUsers[otherUser.id] = {
          id: otherUser.id,
          name: otherUser.name,
          email: otherUser.email,
          role: otherUser.role,
          department: otherUser.department,
          lastMessage: msg.content,
          lastMessageTime: msg.createdAt
        };
      }
    });

    const users = Object.values(uniqueUsers);

    res.json({
      success: true,
      count: users.length,
      conversations: users
    });
  } catch (error) {
    console.error('Get conversations error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch conversations',
      error: error.message
    });
  }
};

// Mark message as read
const markAsRead = async (req, res) => {
  try {
    const { messageId } = req.params;

    const message = await prisma.message.update({
      where: { id: parseInt(messageId) },
      data: { read: true }
    });

    res.json({
      success: true,
      message: 'Message marked as read',
      data: message
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'Message not found'
      });
    }
    console.error('Mark as read error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to mark message as read',
      error: error.message
    });
  }
};

// Get unread message count
const getUnreadCount = async (req, res) => {
  try {
    const userId = req.user.id;

    const unreadCount = await prisma.message.count({
      where: {
        toId: parseInt(userId),
        read: false
      }
    });

    res.json({
      success: true,
      unreadCount
    });
  } catch (error) {
    console.error('Get unread count error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch unread count',
      error: error.message
    });
  }
};

// Delete message
const deleteMessage = async (req, res) => {
  try {
    const { messageId } = req.params;

    await prisma.message.delete({
      where: { id: parseInt(messageId) }
    });

    res.json({
      success: true,
      message: 'Message deleted successfully'
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'Message not found'
      });
    }
    console.error('Delete message error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete message',
      error: error.message
    });
  }
};

// Get available contacts based on role
const getAvailableContacts = async (req, res) => {
  try {
    const user = req.user;
    const userId = user.id;
    const userRole = user.role;
    const userFloor = user.assignedFloorId;
    
    console.log(`📱 Getting contacts for user: ID=${userId}, Role=${userRole}, Floor=${userFloor}`);
    
    let contacts = [];

    if (userRole === 'FLOOR_MANAGER') {
      // Floor manager can message: WORKER (of their floor), OWNER, MANAGER, ADMIN
      console.log(`🏭 Floor Manager - Fetching workers on floor ${userFloor}, plus owner/manager/admin`);
      contacts = await prisma.user.findMany({
        where: {
          OR: [
            { role: 'WORKER', assignedFloorId: userFloor },
            { role: { in: ['OWNER', 'MANAGER', 'ADMIN'] } }
          ],
          id: { not: userId }
        },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          department: true,
          assignedFloorId: true
        }
      });
    } else if (userRole === 'WORKER') {
      // Worker can only message their assigned floor manager
      console.log(`👤 Worker - Fetching floor manager on floor ${userFloor}`);
      contacts = await prisma.user.findMany({
        where: {
          role: 'FLOOR_MANAGER',
          assignedFloorId: userFloor,
          id: { not: userId }
        },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          department: true,
          assignedFloorId: true
        }
      });
    } else if (userRole === 'OWNER' || userRole === 'MANAGER') {
      // Owner/Manager can message: all FLOOR_MANAGERS, ADMIN
      console.log(`👑 Owner/Manager - Fetching all floor managers and admin`);
      contacts = await prisma.user.findMany({
        where: {
          OR: [
            { role: 'FLOOR_MANAGER' },
            { role: 'ADMIN' }
          ],
          id: { not: userId }
        },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          department: true,
          assignedFloorId: true
        }
      });
    } else if (userRole === 'ADMIN') {
      // Admin can message: FLOOR_MANAGER, MANAGER, OWNER
      console.log(`👨‍💼 Admin - Fetching floor managers, managers, and owners`);
      contacts = await prisma.user.findMany({
        where: {
          role: { in: ['FLOOR_MANAGER', 'MANAGER', 'OWNER'] },
          id: { not: userId }
        },
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          department: true,
          assignedFloorId: true
        }
      });
    }

    console.log(`✅ Found ${contacts.length} contacts for ${userRole}`);
    
    res.json({
      success: true,
      count: contacts.length,
      contacts
    });
  } catch (error) {
    console.error('❌ Get available contacts error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch available contacts',
      error: error.message
    });
  }
};

module.exports = {
  sendMessage,
  getMessagesBetween,
  getConversations,
  markAsRead,
  getUnreadCount,
  deleteMessage,
  getAvailableContacts
};
