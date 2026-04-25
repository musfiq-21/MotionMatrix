const express = require('express');
const router = express.Router();
const { register, login, getCurrentUser, resetPassword, changePassword } = require('../controllers/authController');
const { auth } = require('../middleware/auth');

// Public routes
router.post('/register', register);
router.post('/login', login);
router.post('/reset-password', resetPassword);

// Protected routes
router.get('/me', auth, getCurrentUser);
router.put('/change-password', auth, changePassword);

module.exports = router;
