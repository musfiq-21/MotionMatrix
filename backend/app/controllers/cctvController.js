const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Create CCTV
const createCCTV = async (req, res) => {
  try {
    const { name, location, status, ipAddress, floorId } = req.body;

    if (!name || !location) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields'
      });
    }

    const cctv = await prisma.cCTV.create({
      data: {
        name,
        location,
        status: status || 'active',
        ipAddress,
        floorId: floorId ? parseInt(floorId) : null
      }
    });

    res.status(201).json({
      success: true,
      message: 'CCTV created successfully',
      cctv
    });
  } catch (error) {
    console.error('Create CCTV error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create CCTV',
      error: error.message
    });
  }
};

// Get all CCTVs
const getAllCCTVs = async (req, res) => {
  try {
    const cctvs = await prisma.cCTV.findMany({
      include: {
        floor: true
      }
    });

    res.json({
      success: true,
      count: cctvs.length,
      cctvs
    });
  } catch (error) {
    console.error('Get all CCTVs error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch CCTVs',
      error: error.message
    });
  }
};

// Get CCTV by ID
const getCCTVById = async (req, res) => {
  try {
    const { id } = req.params;

    const cctv = await prisma.cCTV.findUnique({
      where: { id: parseInt(id) },
      include: {
        floor: true
      }
    });

    if (!cctv) {
      return res.status(404).json({
        success: false,
        message: 'CCTV not found'
      });
    }

    res.json({
      success: true,
      cctv
    });
  } catch (error) {
    console.error('Get CCTV by ID error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch CCTV',
      error: error.message
    });
  }
};

// Get CCTVs by floor
const getCCTVsByFloor = async (req, res) => {
  try {
    const { floorId } = req.params;

    const cctvs = await prisma.cCTV.findMany({
      where: { floorId: parseInt(floorId) },
      include: {
        floor: true
      }
    });

    res.json({
      success: true,
      count: cctvs.length,
      cctvs
    });
  } catch (error) {
    console.error('Get CCTVs by floor error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch CCTVs',
      error: error.message
    });
  }
};

// Update CCTV
const updateCCTV = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, location, status, ipAddress, floorId } = req.body;

    const cctv = await prisma.cCTV.update({
      where: { id: parseInt(id) },
      data: {
        ...(name && { name }),
        ...(location && { location }),
        ...(status && { status }),
        ...(ipAddress && { ipAddress }),
        ...(floorId !== undefined && { floorId: floorId ? parseInt(floorId) : null })
      },
      include: {
        floor: true
      }
    });

    res.json({
      success: true,
      message: 'CCTV updated successfully',
      cctv
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'CCTV not found'
      });
    }
    console.error('Update CCTV error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update CCTV',
      error: error.message
    });
  }
};

// Assign CCTV to floor
const assignCCTVToFloor = async (req, res) => {
  try {
    const { id } = req.params; // CCTV ID from URL
    const { floorId } = req.body;

    if (!id || !floorId) {
      return res.status(400).json({
        success: false,
        message: 'CCTV ID and Floor ID are required'
      });
    }

    // Verify floor exists
    const floor = await prisma.floor.findUnique({
      where: { id: parseInt(floorId) }
    });

    if (!floor) {
      return res.status(404).json({
        success: false,
        message: 'Floor not found'
      });
    }

    // Verify CCTV exists
    const existingCCTV = await prisma.cCTV.findUnique({
      where: { id: parseInt(id) }
    });

    if (!existingCCTV) {
      return res.status(404).json({
        success: false,
        message: 'CCTV not found'
      });
    }

    const cctv = await prisma.cCTV.update({
      where: { id: parseInt(id) },
      data: { floorId: parseInt(floorId) },
      include: {
        floor: true
      }
    });

    res.json({
      success: true,
      message: 'CCTV assigned to floor successfully',
      cctv
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'CCTV not found'
      });
    }
    console.error('Assign CCTV error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to assign CCTV',
      error: error.message
    });
  }
};

// Unassign CCTV from floor
const unassignCCTVFromFloor = async (req, res) => {
  try {
    const { id } = req.params; // CCTV ID from URL

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'CCTV ID is required'
      });
    }

    // Verify CCTV exists
    const existingCCTV = await prisma.cCTV.findUnique({
      where: { id: parseInt(id) }
    });

    if (!existingCCTV) {
      return res.status(404).json({
        success: false,
        message: 'CCTV not found'
      });
    }

    const cctv = await prisma.cCTV.update({
      where: { id: parseInt(id) },
      data: { floorId: null },
      include: {
        floor: true
      }
    });

    res.json({
      success: true,
      message: 'CCTV unassigned from floor successfully',
      cctv
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'CCTV not found'
      });
    }
    console.error('Unassign CCTV error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to unassign CCTV',
      error: error.message
    });
  }
};

// Delete CCTV
const deleteCCTV = async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.cCTV.delete({
      where: { id: parseInt(id) }
    });

    res.json({
      success: true,
      message: 'CCTV deleted successfully'
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'CCTV not found'
      });
    }
    console.error('Delete CCTV error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete CCTV',
      error: error.message
    });
  }
};

// Get CCTVs for the floor manager's assigned floor
const getMyFloorCCTVs = async (req, res) => {
  try {
    const { userId } = req.params; // Floor manager's user ID
    
    // Get the floor manager's user details
    const user = await prisma.user.findUnique({
      where: { id: parseInt(userId) },
      select: { 
        role: true,
        assignedFloorId: true 
      }
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Only floor managers can view their floor's CCTVs
    if (user.role !== 'FLOOR_MANAGER') {
      return res.status(403).json({
        success: false,
        message: 'Only floor managers can access this endpoint'
      });
    }

    if (!user.assignedFloorId) {
      return res.status(400).json({
        success: false,
        message: 'Floor manager has no assigned floor'
      });
    }
    
    // Get CCTVs only for the assigned floor
    const cctvs = await prisma.cCTV.findMany({
      where: { floorId: user.assignedFloorId },
      include: {
        floor: true
      }
    });

    res.json({
      success: true,
      count: cctvs.length,
      cctvs
    });
  } catch (error) {
    console.error('Get my floor CCTVs error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch CCTVs',
      error: error.message
    });
  }
};

module.exports = {
  createCCTV,
  getAllCCTVs,
  getCCTVById,
  getCCTVsByFloor,
  updateCCTV,
  assignCCTVToFloor,
  unassignCCTVFromFloor,
  deleteCCTV,
  getMyFloorCCTVs
};
