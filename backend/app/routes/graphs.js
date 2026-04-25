const express = require('express');
const router = express.Router();
const {
  createGraphData,
  getAllGraphData,
  getGraphDataByType,
  getGraphDataById,
  updateGraphData,
  deleteGraphData
} = require('../controllers/reportController');
const { auth, authorize } = require('../middleware/auth');

// All routes require authentication
router.use(auth);

// Get all graph data
router.get('/', getAllGraphData);

// Get graph data by ID
router.get('/:id', getGraphDataById);

// Get graph data by type
router.get('/type/:type', getGraphDataByType);

// Create graph data (Admin/Owner only)
router.post('/', authorize('ADMIN', 'OWNER'), createGraphData);

// Update graph data (Admin/Owner only)
router.put('/:id', authorize('ADMIN', 'OWNER'), updateGraphData);

// Delete graph data (Admin/Owner only)
router.delete('/:id', authorize('ADMIN', 'OWNER'), deleteGraphData);

module.exports = router;
