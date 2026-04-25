const express = require('express');
const router = express.Router();
const {
  createFloor,
  getAllFloors,
  getFloorById,
  updateFloor,
  deleteFloor
} = require('../controllers/floorController');
const { auth, authorize } = require('../middleware/auth');

// All routes require authentication
router.use(auth);

// Get all floors
router.get('/', getAllFloors);

// Get floor by ID
router.get('/:id', getFloorById);

// Create floor (Admin/Owner only)
router.post('/', authorize('ADMIN', 'OWNER'), createFloor);

// Update floor (Admin/Owner only)
router.put('/:id', authorize('ADMIN', 'OWNER'), updateFloor);

// Delete floor (Admin/Owner only)
router.delete('/:id', authorize('ADMIN', 'OWNER'), deleteFloor);

module.exports = router;
