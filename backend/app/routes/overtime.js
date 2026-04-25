const express = require('express');
const router = express.Router();
const {
  submitOvertimeRequest,
  getOvertimeRequestsByWorker,
  getOvertimeRequestsByFloorManager,
  getAllOvertimeRequests,
  getOvertimeRequestById,
  approveOvertimeRequest,
  rejectOvertimeRequest,
  deleteOvertimeRequest
} = require('../controllers/overtimeController');
const { auth, authorize } = require('../middleware/auth');

// All routes require authentication
router.use(auth);

// Submit overtime request (Workers only)
router.post('/submit', authorize('WORKER'), submitOvertimeRequest);

// Get my overtime requests (Workers)
router.get('/my-requests', authorize('WORKER'), getOvertimeRequestsByWorker);

// Get overtime requests as floor manager
router.get('/floor-manager/requests', authorize('FLOOR_MANAGER'), getOvertimeRequestsByFloorManager);

// Get all overtime requests (Admin/Owner only)
router.get('/', authorize('ADMIN', 'OWNER'), getAllOvertimeRequests);

// Get overtime request by ID
router.get('/:id', getOvertimeRequestById);

// Approve overtime request (Floor manager only)
router.put('/:id/approve', authorize('FLOOR_MANAGER'), approveOvertimeRequest);

// Reject overtime request (Floor manager only)
router.put('/:id/reject', authorize('FLOOR_MANAGER'), rejectOvertimeRequest);

// Delete overtime request (Admin/Owner only)
router.delete('/:id', authorize('ADMIN', 'OWNER'), deleteOvertimeRequest);

module.exports = router;
