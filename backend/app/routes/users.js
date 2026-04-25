const express = require('express');
const router = express.Router();
const {
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
} = require('../controllers/userController');
const { auth, authorize } = require('../middleware/auth');

// Public routes (no auth required)
// Must come BEFORE auth middleware
router.post('/', createUser);

// Change password route - MUST be before /:id route to match correctly
router.put('/:id/change-password', changePassword);

// Apply authentication middleware for routes below
router.use(auth);

// Protected routes (require authentication)
// Get all users (Admin only)
router.get('/', authorize('ADMIN', 'OWNER'), getAllUsers);

// Get users by role
router.get('/role/:role', getUsersByRole);

// Get users by department
router.get('/department/:department', getUsersByDepartment);

// Get floor manager for a specific floor
router.get('/floor-manager/:floorId', getFloorManager);

// Get workers assigned to a specific floor
router.get('/floor/:floorId', getWorkersByFloor);

// Get unassigned workers
router.get('/workers/unassigned', getUnassignedWorkers);

// Assign worker to floor
router.put('/:workerId/assign-floor', assignWorkerToFloor);

// Get user by ID
router.get('/:id', getUserById);

// Update user
router.put('/:id', updateUser);

// Delete user (Admin only)
router.delete('/:id', authorize('ADMIN', 'OWNER'), deleteUser);

module.exports = router;
