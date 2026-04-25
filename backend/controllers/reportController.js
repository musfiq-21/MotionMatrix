const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

// Create report
const createReport = async (req, res) => {
  try {
    const { title, department, period, data } = req.body;

    if (!title || !department || !period || !data) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields'
      });
    }

    const report = await prisma.report.create({
      data: {
        title,
        department,
        date: new Date(),
        period,
        data
      }
    });

    res.status(201).json({
      success: true,
      message: 'Report created successfully',
      report
    });
  } catch (error) {
    console.error('Create report error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create report',
      error: error.message
    });
  }
};

// Get all reports
const getAllReports = async (req, res) => {
  try {
    const { department } = req.query;

    const where = {};
    if (department) where.department = department;

    const reports = await prisma.report.findMany({
      where,
      orderBy: { date: 'desc' }
    });

    res.json({
      success: true,
      count: reports.length,
      reports
    });
  } catch (error) {
    console.error('Get all reports error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch reports',
      error: error.message
    });
  }
};

// Get report by ID
const getReportById = async (req, res) => {
  try {
    const { id } = req.params;

    const report = await prisma.report.findUnique({
      where: { id: parseInt(id) }
    });

    if (!report) {
      return res.status(404).json({
        success: false,
        message: 'Report not found'
      });
    }

    res.json({
      success: true,
      report
    });
  } catch (error) {
    console.error('Get report by ID error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch report',
      error: error.message
    });
  }
};

// Delete report
const deleteReport = async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.report.delete({
      where: { id: parseInt(id) }
    });

    res.json({
      success: true,
      message: 'Report deleted successfully'
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'Report not found'
      });
    }
    console.error('Delete report error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete report',
      error: error.message
    });
  }
};

// Create graph data
const createGraphData = async (req, res) => {
  try {
    const { type, title, period, unit, data } = req.body;

    if (!type || !title || !period || !unit || !data) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields'
      });
    }

    const graphData = await prisma.graphData.create({
      data: {
        type,
        title,
        period,
        unit,
        data
      }
    });

    res.status(201).json({
      success: true,
      message: 'Graph data created successfully',
      graphData
    });
  } catch (error) {
    console.error('Create graph data error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create graph data',
      error: error.message
    });
  }
};

// Get all graph data
const getAllGraphData = async (req, res) => {
  try {
    const graphData = await prisma.graphData.findMany({
      orderBy: { createdAt: 'desc' }
    });

    res.json({
      success: true,
      count: graphData.length,
      graphData
    });
  } catch (error) {
    console.error('Get all graph data error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch graph data',
      error: error.message
    });
  }
};

// Get graph data by type
const getGraphDataByType = async (req, res) => {
  try {
    const { type } = req.params;

    const graphData = await prisma.graphData.findFirst({
      where: { type }
    });

    if (!graphData) {
      return res.status(404).json({
        success: false,
        message: 'Graph data not found'
      });
    }

    res.json({
      success: true,
      graphData
    });
  } catch (error) {
    console.error('Get graph data by type error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch graph data',
      error: error.message
    });
  }
};

// Get graph data by ID
const getGraphDataById = async (req, res) => {
  try {
    const { id } = req.params;

    const graphData = await prisma.graphData.findUnique({
      where: { id: parseInt(id) }
    });

    if (!graphData) {
      return res.status(404).json({
        success: false,
        message: 'Graph data not found'
      });
    }

    res.json({
      success: true,
      graphData
    });
  } catch (error) {
    console.error('Get graph data by ID error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch graph data',
      error: error.message
    });
  }
};

// Update graph data
const updateGraphData = async (req, res) => {
  try {
    const { id } = req.params;
    const { type, title, period, unit, data } = req.body;

    const graphData = await prisma.graphData.update({
      where: { id: parseInt(id) },
      data: {
        ...(type && { type }),
        ...(title && { title }),
        ...(period && { period }),
        ...(unit && { unit }),
        ...(data && { data })
      }
    });

    res.json({
      success: true,
      message: 'Graph data updated successfully',
      graphData
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'Graph data not found'
      });
    }
    console.error('Update graph data error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update graph data',
      error: error.message
    });
  }
};

// Delete graph data
const deleteGraphData = async (req, res) => {
  try {
    const { id } = req.params;

    await prisma.graphData.delete({
      where: { id: parseInt(id) }
    });

    res.json({
      success: true,
      message: 'Graph data deleted successfully'
    });
  } catch (error) {
    if (error.code === 'P2025') {
      return res.status(404).json({
        success: false,
        message: 'Graph data not found'
      });
    }
    console.error('Delete graph data error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete graph data',
      error: error.message
    });
  }
};

module.exports = {
  createReport,
  getAllReports,
  getReportById,
  deleteReport,
  createGraphData,
  getAllGraphData,
  getGraphDataByType,
  getGraphDataById,
  updateGraphData,
  deleteGraphData
};
