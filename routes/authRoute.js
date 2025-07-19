const express = require('express');
const router = express.Router();
const { signup,login , refreshToken, PostLogout , checkAuth,forgotPassword,verifyPassResetCode,resetPassword} = require('../services/authService');
const authService = require('../services/authService');

router.post('/signup', signup);
router.post('/refresh-token', refreshToken);
router.get('/check',authService.protect, checkAuth); // New route
router.post('/login', login);
router.post('/logout',authService.protect, PostLogout);
router.post('/forgotPassword', forgotPassword);
router.post('/verifyResetCode', verifyPassResetCode);
router.post('/resetPassword', resetPassword);


module.exports = router;



