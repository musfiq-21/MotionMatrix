const bcrypt = require('bcryptjs');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Create user (for adding workers/staff)
const createUser = async (req, res) => {
  try {
    console.log('📝 POST /api/users - Creating new user:', req.body.email);
    const { name, email, password, confirmPassword, role, department, phone, nid, gender, joinDate, position, workerId, assignedFloorId } = req.body;

    console.log('📊 User creation data:', { name, email, role, department, phone });

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

    // Validate floor assignment is required for WORKER and FLOOR_MANAGER roles
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

    // Check if email already exists
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Email already exists'
      });
    }

    // Check if workerId already exists (if provided)
    if (workerId) {
      const existingWorker = await prisma.user.findUnique({
        where: { workerId }
      });

      if (existingWorker) {
        return res.status(400).json({
          success: false,
          message: 'Worker ID already exists'
        });
      }
    }

    // Check if NID already exists (if provided)
    if (nid) {
      const existingNid = await prisma.user.findUnique({
        where: { nid }
      });

      if (existingNid) {
        return res.status(400).json({
          success: false,
          message: 'NID already exists'
        });
      }
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
        nid: nid || null,
        gender,
        joinDate: joinDate ? new Date(joinDate) : new Date(),
        position,
        workerId: workerId || null,
        assignedFloorId: assignedFloorId ? parseInt(assignedFloorId) : null
      },
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
        assignedFloorId: true
      }
    });

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      user
    });
  } catch (error) {
    console.error('Create user error:', error);
    
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
    
    // More detailed error logging
    console.error('Detailed error:', {
      code: error.code,
      message: error.message,
      meta: error.meta
    });
    
    res.status(500).json({
      success: false,
      message: error.message || 'Failed to create user',
      error: error.message
    });
  }
};

// Get all users
const getAllUsers = async (req, res) => {
  try {
    const { role, department } = req.query;
    
    const where = {};
    if (role) where.role = role;
    if (department) where.department = department;

    const users = await prisma.user.findMany({
      where,
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
        assignedFloorId: true,
        status: true,
        createdAt: true
      }
    });

    res.json({
      success: true,
      count: users.length,
      users
    });
  } catch (error) {
    console.error('Get all users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users',
      error: error.message
    });
  }
};

// Get user by ID
const getUserById = async (req, res) => {
  try {
    const { id } = req.params;

    const user = await prisma.user.findUnique({
      where: { id: parseInt(id) },
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
        assignedFloorId: true,
        status: true,
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
    console.error('Get user by ID error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch user',
      error: error.message
    });
  }
};

// Update user
const updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, email, phone, position, department, gender, assignedFloorId } = req.body;

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

    // Check if email is being updated and if it already exists (but not for this user)
    if (email) {
      const existingUser = await prisma.user.findUnique({
        where: { email }
      });

      if (existingUser && existingUser.id !== parseInt(id)) {
        return res.status(400).json({
          success: false,
          message: 'Email already exists'
        });
      }
    }

    const user = await prisma.user.update({
      where: { id: parseInt(id) },
      data: {
        ...(name && { name }),
        ...(email && { email }),
        ...(phone && { phone }),
        ...(position && { position }),
        ...(department && { department }),
        ...(gender && { gender }),
        ...(assignedFloorId && { assignedFloorId: parseInt(assignedFloorId) })
      },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        department: true,
        phone: true,
        nid: true,
        gender: true,
        position: true,
        assignedFloorId: true,
        createdAt: true
      }
    });

    res.json({
      success: true,
      message: 'User updated successfully',
      user
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update user',
      error: error.message
    });
  }
};

// Change password
const changePassword = async (req, res) => {
  try {
    console.log('🔐 PUT /api/users/:id/change-password - Changing password for user:', req.params.id);
    const { id } = req.params;
    const { currentPassword, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: 'Passwords do not match'
      });
    }

    const user = await prisma.user.findUnique({
      where: { id: parseInt(id) }
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await prisma.user.update({
      where: { id: parseInt(id) },
      data: { password: hashedPassword }
    });

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

// Get users by role
const getUsersByRole = async (req, res) => {
  try {
    const { role } = req.params;

    const users = await prisma.user.findMany({
      where: { role },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        department: true,
        phone: true,
        position: true
      }
    });

    res.json({
      success: true,
      count: users.length,
      users
    });
  } catch (error) {
    console.error('Get users by role error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users',
      error: error.message
    });
  }
};

// Get users by department
const getUsersByDepartment = async (req, res) => {
  try {
    const { department } = req.params;

    const users = await prisma.user.findMany({
      where: { department },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        department: true,
        phone: true,
        position: true
      }
    });

    res.json({
      success: true,
      count: users.length,
      users
    });
  } catch (error) {
    console.error('Get users by department error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users',
      error: error.message
    });
  }
};

// Delete user
const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.user.delete({
      where: { id: parseInt(id) }
    });

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    console.error('Delete user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete user',
      error: error.message
    });
  }
};

// Get workers by floor
const getWorkersByFloor = async (req, res) => {
  try {
    const { floorId } = req.params;

    // Get floor manager for this floor
    const floorManager = await prisma.user.findFirst({
      where: {
        assignedFloorId: parseInt(floorId),
        role: 'FLOOR_MANAGER'
      },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        phone: true
      }
    });

    // Get all workers assigned to this floor
    const workers = await prisma.user.findMany({
      where: {
        assignedFloorId: parseInt(floorId),
        role: 'WORKER'
      },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        department: true,
        phone: true,
        position: true,
        workerId: true,
        assignedFloorId: true
      }
    });

    res.json({
      success: true,
      floorManager,
      workers,
      count: workers.length
    });
  } catch (error) {
    console.error('Get workers by floor error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch workers',
      error: error.message
    });
  }
};

// Get floor manager for a specific floor
const getFloorManager = async (req, res) => {
  try {
    const { floorId } = req.params;

    const floorManager = await prisma.user.findFirst({
      where: {
        assignedFloorId: parseInt(floorId),
        role: 'FLOOR_MANAGER'
      },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        phone: true,
        assignedFloorId: true
      }
    });

    if (!floorManager) {
      return res.status(404).json({
        success: false,
        message: 'No floor manager assigned to this floor'
      });
    }

    res.json({
      success: true,
      floorManager
    });
  } catch (error) {
    console.error('Get floor manager error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch floor manager',
      error: error.message
    });
  }
};

// Get unassigned workers
const getUnassignedWorkers = async (req, res) => {
  try {
    const workers = await prisma.user.findMany({
      where: {
        role: 'WORKER',
        assignedFloorId: null
      },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        department: true,
        phone: true,
        position: true,
        workerId: true,
        assignedFloorId: true
      }
    });

    res.json({
      success: true,
      workers,
      count: workers.length
    });
  } catch (error) {
    console.error('Get unassigned workers error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch unassigned workers',
      error: error.message
    });
  }
};

// Assign worker to floor
const assignWorkerToFloor = async (req, res) => {
  try {
    const { workerId } = req.params;
    const { assignedFloorId } = req.body;

    // Validate floor exists
    const floor = await prisma.floor.findUnique({
      where: { id: parseInt(assignedFloorId) }
    });

    if (!floor) {
      return res.status(404).json({
        success: false,
        message: 'Floor not found'
      });
    }

    // Update worker with floor assignment
    const worker = await prisma.user.update({
      where: { id: parseInt(workerId) },
      data: {
        assignedFloorId: parseInt(assignedFloorId)
      },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        department: true,
        phone: true,
        position: true,
        workerId: true,
        assignedFloorId: true
      }
    });

    res.json({
      success: true,
      message: 'Worker assigned to floor successfully',
      worker
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'Worker not found'
      });
    }
    console.error('Assign worker to floor error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to assign worker to floor',
      error: error.message
    });
  }
};

module.exports = {
  createUser,
  getAllUsers,
  getUserById,
  updateUser,
  changePassword,
  getUsersByRole,
  getUsersByDepartment,
  deleteUser,
  getWorkersByFloor,
  getFloorManager,
  getUnassignedWorkers,
  assignWorkerToFloor
};
