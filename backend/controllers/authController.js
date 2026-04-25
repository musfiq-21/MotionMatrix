const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Register
const register = async (req, res) => {
  try {
    const { name, email, password, confirmPassword, role, department, phone, nid, gender, joinDate, position, workerId, assignedFloorId } = req.body;

    console.log('📝 Register attempt with data:', { name, email, role, department, phone });

    // Normalize role to uppercase
    const roleUpper = role ? role.toUpperCase() : '';

    // Validation - provide specific error messages
    if (!name || !name.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Full name is required'
      });
    }
    
    if (!email || !email.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }
    
    if (!phone || !phone.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Phone number is required'
      });
    }
    
    if (!password) {
      return res.status(400).json({
        success: false,
        message: 'Password is required'
      });
    }
    
    if (!roleUpper) {
      return res.status(400).json({
        success: false,
        message: 'Role is required'
      });
    }

    // Department is not required for OWNER role
    if (roleUpper !== 'OWNER' && (!department || !department.trim())) {
      return res.status(400).json({
        success: false,
        message: 'Department is required for this role'
      });
    }

    // Validate floor assignment is required for WORKER and FLOOR_MANAGER
    if (['WORKER', 'FLOOR_MANAGER'].includes(roleUpper) && !assignedFloorId) {
      return res.status(400).json({
        success: false,
        message: `Assigned floor is required for ${roleUpper} role`
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
    }

    // Check if user exists
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exists'
      });
    }

    // Validate floor exists if assigning
    if (assignedFloorId) {
      const floor = await prisma.floor.findUnique({
        where: { id: parseInt(assignedFloorId) }
      });

      if (!floor) {
        return res.status(400).json({
          success: false,
          message: 'Assigned floor does not exist'
        });
      }
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        role: roleUpper,
        department: department || null,
        phone,
        nid,
        gender,
        joinDate: joinDate ? new Date(joinDate) : new Date(),
        position,
        workerId,
        assignedFloorId: assignedFloorId ? parseInt(assignedFloorId) : null
      }
    });

    // Generate token
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        role: user.role,
        name: user.name,
        assignedFloorId: user.assignedFloorId
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE }
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        phone: user.phone,
        assignedFloorId: user.assignedFloorId
      },
      token
    });
  } catch (error) {
    console.error('Register error:', error);
    
    // Handle Prisma unique constraint errors
    if (error.code === 'P2002') {
      const field = error.meta?.target?.[0] || 'field';
      const fieldName = field === 'email' ? 'Email' : 
                       field === 'nid' ? 'NID' :
                       field === 'workerId' ? 'Worker ID' : field;
      return res.status(400).json({
        success: false,
        message: `${fieldName} already exists. Please use a different ${fieldName.toLowerCase()}.`
      });
    }
    
    console.error('Detailed register error:', {
      code: error.code,
      message: error.message,
      meta: error.meta
    });
    
    res.status(500).json({
      success: false,
      message: error.message || 'Registration failed',
      error: error.message
    });
  }
};

// Login
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Find user
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Generate token
    const token = jwt.sign(
      { 
        id: user.id, 
        email: user.email, 
        role: user.role,
        name: user.name,
        assignedFloorId: user.assignedFloorId
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRE }
    );

    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        phone: user.phone,
        assignedFloorId: user.assignedFloorId
      },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Login failed',
      error: error.message
    });
  }
};

// Get current user
const getCurrentUser = async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        department: true,
        phone: true,
        nid: true,
        gender: true,
        joinDate: true,
        position: true,
        workerId: true,
        status: true,
        assignedFloorId: true,
        createdAt: true
      }
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      user
    });
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user',
      error: error.message
    });
  }
};

// Reset Password
const resetPassword = async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    // Validation
    if (!email || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Email and new password are required'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Password must be at least 6 characters'
      });
    }

    // Find user by email
    const user = await prisma.user.findUnique({
      where: { email }
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user password
    await prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword }
    });

    res.json({
      success: true,
      message: 'Password reset successfully'
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reset password',
      error: error.message
    });
  }
};

// Change password (requires current password verification)
const changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    console.log('🔐 Change password request for user:', userId);

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        message: 'Current password and new password are required'
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'New password must be at least 6 characters'
      });
    }

    // Get user from database
    const user = await prisma.user.findUnique({
      where: { id: userId }
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password in database
    const updatedUser = await prisma.user.update({
      where: { id: userId },
      data: { password: hashedPassword }
    });

    console.log('✅ Password changed successfully for user:', userId);

    res.json({
      success: true,
      message: 'Password changed successfully'
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to change password',
      error: error.message
    });
  }
};

module.exports = {
  register,
  login,
  getCurrentUser,
  resetPassword,
  changePassword
};
