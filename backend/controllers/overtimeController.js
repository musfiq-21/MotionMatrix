const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Submit overtime request
const submitOvertimeRequest = async (req, res) => {
  try {
    const { floorManagerId, date, hours, reason } = req.body;
    const workerId = req.user.id;

    if (!floorManagerId || !date || !hours || !reason) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields'
      });
    }

    // Get worker details
    const worker = await prisma.user.findUnique({
      where: { id: parseInt(workerId) }
    });

    if (!worker || worker.role !== 'WORKER') {
      return res.status(403).json({
        success: false,
        message: 'Only workers can submit overtime requests'
      });
    }

    // Verify floor manager exists and is on the same floor as the worker
    const floorManager = await prisma.user.findUnique({
      where: { id: parseInt(floorManagerId) }
    });

    if (!floorManager || floorManager.role !== 'FLOOR_MANAGER') {
      return res.status(404).json({
        success: false,
        message: 'Floor manager not found'
      });
    }

    // Verify both are on the same floor
    if (worker.assignedFloorId !== floorManager.assignedFloorId) {
      return res.status(403).json({
        success: false,
        message: 'Floor manager must be on the same floor as the worker'
      });
    }

    if (!worker.assignedFloorId) {
      return res.status(403).json({
        success: false,
        message: 'Worker must be assigned to a floor'
      });
    }

    const overtimeRequest = await prisma.overtimeRequest.create({
      data: {
        workerId: parseInt(workerId),
        floorManagerId: parseInt(floorManagerId),
        date: new Date(date),
        hours: parseInt(hours),
        reason,
        status: 'pending'
      },
      include: {
        worker: {
          select: { id: true, name: true, email: true, department: true }
        },
        floorManager: {
          select: { id: true, name: true, email: true }
        }
      }
    });

    res.status(201).json({
      success: true,
      message: 'Overtime request submitted successfully',
      overtimeRequest
    });
  } catch (error) {
    console.error('Submit overtime request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit overtime request',
      error: error.message
    });
  }
};

// Get overtime requests for current worker
const getOvertimeRequestsByWorker = async (req, res) => {
  try {
    const workerId = req.user.id;

    const overtimeRequests = await prisma.overtimeRequest.findMany({
      where: { workerId: parseInt(workerId) },
      include: {
        worker: {
          select: { id: true, name: true, email: true, department: true }
        },
        floorManager: {
          select: { id: true, name: true, email: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json({
      success: true,
      count: overtimeRequests.length,
      overtimeRequests
    });
  } catch (error) {
    console.error('Get overtime requests by worker error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch overtime requests',
      error: error.message
    });
  }
};

// Get overtime requests for floor manager
const getOvertimeRequestsByFloorManager = async (req, res) => {
  try {
    const floorManagerId = req.user.id;

    const overtimeRequests = await prisma.overtimeRequest.findMany({
      where: { floorManagerId: parseInt(floorManagerId) },
      include: {
        worker: {
          select: { id: true, name: true, email: true, department: true }
        },
        floorManager: {
          select: { id: true, name: true, email: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json({
      success: true,
      count: overtimeRequests.length,
      overtimeRequests
    });
  } catch (error) {
    console.error('Get overtime requests by floor manager error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch overtime requests',
      error: error.message
    });
  }
};

// Get all overtime requests (Admin/Owner only)
const getAllOvertimeRequests = async (req, res) => {
  try {
    const { status } = req.query;

    const where = {};
    if (status) where.status = status;

    const overtimeRequests = await prisma.overtimeRequest.findMany({
      where,
      include: {
        worker: {
          select: { id: true, name: true, email: true, department: true }
        },
        floorManager: {
          select: { id: true, name: true, email: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    res.json({
      success: true,
      count: overtimeRequests.length,
      overtimeRequests
    });
  } catch (error) {
    console.error('Get all overtime requests error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch overtime requests',
      error: error.message
    });
  }
};

// Get overtime request by ID
const getOvertimeRequestById = async (req, res) => {
  try {
    const { id } = req.params;

    const overtimeRequest = await prisma.overtimeRequest.findUnique({
      where: { id: parseInt(id) },
      include: {
        worker: {
          select: { id: true, name: true, email: true, department: true }
        },
        floorManager: {
          select: { id: true, name: true, email: true }
        }
      }
    });

    if (!overtimeRequest) {
      return res.status(404).json({
        success: false,
        message: 'Overtime request not found'
      });
    }

    res.json({
      success: true,
      overtimeRequest
    });
  } catch (error) {
    console.error('Get overtime request by ID error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch overtime request',
      error: error.message
    });
  }
};

// Approve overtime request
const approveOvertimeRequest = async (req, res) => {
  try {
    const { id } = req.params;

    const overtimeRequest = await prisma.overtimeRequest.update({
      where: { id: parseInt(id) },
      data: {
        status: 'approved',
        respondedAt: new Date()
      },
      include: {
        worker: {
          select: { id: true, name: true, email: true }
        },
        floorManager: {
          select: { id: true, name: true, email: true }
        }
      }
    });

    res.json({
      success: true,
      message: 'Overtime request approved',
      overtimeRequest
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'Overtime request not found'
      });
    }
    console.error('Approve overtime request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to approve overtime request',
      error: error.message
    });
  }
};

// Reject overtime request
const rejectOvertimeRequest = async (req, res) => {
  try {
    const { id } = req.params;

    const overtimeRequest = await prisma.overtimeRequest.update({
      where: { id: parseInt(id) },
      data: {
        status: 'rejected',
        respondedAt: new Date()
      },
      include: {
        worker: {
          select: { id: true, name: true, email: true }
        },
        floorManager: {
          select: { id: true, name: true, email: true }
        }
      }
    });

    res.json({
      success: true,
      message: 'Overtime request rejected',
      overtimeRequest
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'Overtime request not found'
      });
    }
    console.error('Reject overtime request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reject overtime request',
      error: error.message
    });
  }
};

// Delete overtime request
const deleteOvertimeRequest = async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.overtimeRequest.delete({
      where: { id: parseInt(id) }
    });

    res.json({
      success: true,
      message: 'Overtime request deleted successfully'
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'Overtime request not found'
      });
    }
    console.error('Delete overtime request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete overtime request',
      error: error.message
    });
  }
};

module.exports = {
  submitOvertimeRequest,
  getOvertimeRequestsByWorker,
  getOvertimeRequestsByFloorManager,
  getAllOvertimeRequests,
  getOvertimeRequestById,
  approveOvertimeRequest,
  rejectOvertimeRequest,
  deleteOvertimeRequest
};
