const express = require('express');
const router = express.Router();
const {
  createReport,
  getAllReports,
  getReportById,
  deleteReport
} = require('../controllers/reportController');
const { auth, authorize } = require('../middleware/auth');

// All routes require authentication
router.use(auth);

// Get all reports
router.get('/', getAllReports);

// Get report by ID
router.get('/:id', getReportById);

// Create report (Admin/Owner only)
router.post('/', authorize('ADMIN', 'OWNER'), createReport);

// Delete report (Admin/Owner only)
router.delete('/:id', authorize('ADMIN', 'OWNER'), deleteReport);

module.exports = router;
