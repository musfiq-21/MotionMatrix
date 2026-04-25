const express = require('express');
const router = express.Router();
const {
  createCCTV,
  getAllCCTVs,
  getCCTVById,
  getCCTVsByFloor,
  updateCCTV,
  assignCCTVToFloor,
  unassignCCTVFromFloor,
  deleteCCTV,
  getMyFloorCCTVs
} = require('../controllers/cctvController');
const { auth, authorize } = require('../middleware/auth');

// All routes require authentication
router.use(auth);

// Get CCTVs for floor manager's assigned floor (Floor Manager only)
router.get('/my-floor/:userId', authorize('FLOOR_MANAGER'), getMyFloorCCTVs);

// Get CCTVs by floor (everyone)
router.get('/floor/:floorId', getCCTVsByFloor);

// Get all CCTVs (Admin/Owner)
router.get('/', authorize('ADMIN', 'OWNER'), getAllCCTVs);

// Get CCTV by ID
router.get('/:id', getCCTVById);

// Create CCTV (Admin/Owner only)
router.post('/', authorize('ADMIN', 'OWNER'), createCCTV);

// Update CCTV (Admin/Owner only)
router.put('/:id', authorize('ADMIN', 'OWNER'), updateCCTV);

// Assign CCTV to floor (Admin/Owner/Floor Manager)
router.put('/:id/assign', authorize('ADMIN', 'OWNER', 'FLOOR_MANAGER'), assignCCTVToFloor);

// Unassign CCTV from floor (Admin/Owner/Floor Manager)
router.put('/:id/unassign', authorize('ADMIN', 'OWNER', 'FLOOR_MANAGER'), unassignCCTVFromFloor);

// Delete CCTV (Admin/Owner only)
router.delete('/:id', authorize('ADMIN', 'OWNER'), deleteCCTV);

module.exports = router;
