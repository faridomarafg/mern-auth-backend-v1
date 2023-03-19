const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const protect = require('../middleWare/authMiddleware');

router.post('/register', userController.registerUser);
router.post('/login', userController.loginUser);
router.get('/logout', userController.logoutUser);
router.post('/forgotpassword', userController.forgotPassword);
router.put('/resetpassword/:resetToken', userController.resetPassword);

module.exports = router


