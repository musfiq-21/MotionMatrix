const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Create floor
const createFloor = async (req, res) => {
  try {
    const { name, level, area, status } = req.body;

    if (!name || level === undefined || !area) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields'
      });
    }

    const floor = await prisma.floor.create({
      data: {
        name,
        level: parseInt(level),
        area: parseInt(area),
        status: status || 'active'
      },
      include: {
        cctvs: true
      }
    });

    res.status(201).json({
      success: true,
      message: 'Floor created successfully',
      floor
    });
  } catch (error) {
    console.error('Create floor error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create floor',
      error: error.message
    });
  }
};

// Get all floors
const getAllFloors = async (req, res) => {
  try {
    const floors = await prisma.floor.findMany({
      include: {
        cctvs: true
      }
    });

    res.json({
      success: true,
      count: floors.length,
      floors
    });
  } catch (error) {
    console.error('Get all floors error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch floors',
      error: error.message
    });
  }
};

// Get floor by ID
const getFloorById = async (req, res) => {
  try {
    const { id } = req.params;

    const floor = await prisma.floor.findUnique({
      where: { id: parseInt(id) },
      include: {
        cctvs: true
      }
    });

    if (!floor) {
      return res.status(404).json({
        success: false,
        message: 'Floor not found'
      });
    }

    res.json({
      success: true,
      floor
    });
  } catch (error) {
    console.error('Get floor by ID error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch floor',
      error: error.message
    });
  }
};

// Update floor
const updateFloor = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, level, area, status } = req.body;

    const floor = await prisma.floor.update({
      where: { id: parseInt(id) },
      data: {
        ...(name && { name }),
        ...(level !== undefined && { level: parseInt(level) }),
        ...(area && { area: parseInt(area) }),
        ...(status && { status })
      },
      include: {
        cctvs: true
      }
    });

    res.json({
      success: true,
      message: 'Floor updated successfully',
      floor
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'Floor not found'
      });
    }
    console.error('Update floor error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update floor',
      error: error.message
    });
  }
};

// Delete floor
const deleteFloor = async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.floor.delete({
      where: { id: parseInt(id) }
    });

    res.json({
      success: true,
      message: 'Floor deleted successfully'
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'Floor not found'
      });
    }
    console.error('Delete floor error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete floor',
      error: error.message
    });
  }
};

module.exports = {
  createFloor,
  getAllFloors,
  getFloorById,
  updateFloor,
  deleteFloor
};
