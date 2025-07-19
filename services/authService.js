const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const asyncHandler = require('express-async-handler');
const ApiError = require('../utils/apiError');
const { createAccessToken, createRefreshToken } = require('../utils/createToken');
const { refreshAccessToken ,getUserIdFromToken } = require('../utils/auth');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const sendEmail = require('../utils/sendEmail');
const RefreshToken = require('../models/RefreshToken.model'); 
const User = require('../models/userModel');

authenticator.options = { 
  digits: 6,
  algorithm: 'sha256'
};

// @route   POST /signup
exports.signup = asyncHandler(async (req, res, next) => {
  const user = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    phone: req.body.phone 
  });

  const emailVerificationToken = crypto.randomBytes(64).toString('hex') + ':' + (new Date()).toISOString();
  user.emailVerificationToken = emailVerificationToken;
  await user.save();

  const verificationUrl = `${req.protocol}://${req.get('host')}/verifyEmail/${emailVerificationToken}`;
  const message = `Hi ${user.name},\nPlease verify your email by clicking the following link:\n${verificationUrl}\nThis link is valid for 15 minutes.`;
  try {
    await sendEmail({
      email: user.email,
      subject: 'Verify Your Email',
      message
    });
  } catch (err) {
    user.emailVerificationToken = undefined;
    await user.save();
    return next(new ApiError('Failed to send verification email', 500));
  }

  // 4- توليد التوكنات
  const accessToken = createAccessToken(user._id);
  const refreshToken = createRefreshToken(user._id);

  const refreshTokenDoc = new RefreshToken({
    token: refreshToken,
    userId: user._id,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
  });
  await refreshTokenDoc.save();

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 1000, // 1 hour
  });
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  console.log('User signed up, accessToken and refreshToken generated:', { userId: user._id });
  res.status(201).json({ data: user, accessToken, message: 'User created! Please verify your email.' });
});

// @route   POST /login
exports.login = asyncHandler(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return next(new ApiError('Incorrect email or password', 401));
  }

  if (user.enable2FA && user.otpSecret) {
    return res.status(200).json({ status: 'otp', message: 'Please provide OTP' });
  }

  await RefreshToken.deleteMany({ userId: user._id });

  const accessToken = createAccessToken(user._id);
  const refreshToken = createRefreshToken(user._id);

  const refreshTokenDoc = new RefreshToken({
    token: refreshToken,
    userId: user._id,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
  });
  await refreshTokenDoc.save();

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 1000,    // 1 hour
  }); 
  res.cookie('refreshToken', refreshToken, { 
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,  
  });

  user.status = 'active';
  await user.save();

  const userObj = user.toObject();
  delete userObj.password;

  console.log('User logged in, accessToken and refreshToken generated:', { userId: user._id });
  res.status(200).json({ data: userObj, accessToken });
});



// @route   POST /refresh-token
exports.refreshToken = asyncHandler(async (req, res, next) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    console.log('No refresh token provided in cookies');
    return next(new ApiError('No refresh token provided', 401));
  }

  try {
    const userId = await refreshAccessToken(refreshToken, res);
    res.status(200).json({ accessToken: res.cookies.accessToken });
  } catch (err) {
    next(err);
  }
});

// @route   POST /logout
// @route   POST /logout
// @route   POST /logout
exports.PostLogout = asyncHandler(async (req, res, next) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    console.log('No refresh token provided in cookies for logout');
    return next(new ApiError('No session found, already logged out or invalid session', 400));
  }

  // Check if refresh token exists in the database
  const tokenDoc = await RefreshToken.findOne({ token: refreshToken });
  if (!tokenDoc) {
    console.log('Refresh token not found in database:', { refreshToken, userId: req.user._id });
    return next(new ApiError('Session already logged out or invalid', 400));
  }

  // Delete the refresh token for the current session
  await RefreshToken.deleteOne({ token: refreshToken });
  console.log('Refresh token deleted for current session:', { refreshToken, userId: req.user._id });

  // Clear cookies
  res.clearCookie('accessToken', { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
  res.clearCookie('refreshToken', { httpOnly: true, secure: process.env.NODE_ENV === 'production' });

  // Set user status to inactive for the current session
  req.user.status = 'inactive';
  await req.user.save();
  console.log('User status set to inactive:', { userId: req.user._id });

  console.log('User logged out successfully from current session');
  res.status(200).json({ status: 'success', message: 'Logged out successfully from current session', fullUserData: req.user });
});
// @route   GET /check
exports.checkAuth = asyncHandler(async (req, res, next) => {

  try {
    // const userId = await getUserIdFromToken(req, res, next);
        const userId = req.user._id; // Get userId from req.user set by protect middleware
    if (!userId) {
      console.log('No userId returned from getUserIdFromToken');
      return next(new ApiError('Unable to authenticate user', 401));
    }

  const user = await User.findById(userId).select('name email role status phone enable2FA emailVerified');
    if (!user) {
      console.log('User not found:', { userId });
      return next(new ApiError('User not found', 404));
    }

    console.log('User authenticated successfully:', { userId });
    res.status(200).json({ 
      status: 'success', 
      data: { 
        userId, 
        name: user.name, 
        email: user.email, 
        role: user.role, 
        status: user.status,
        phone: user.phone,
        enable2FA: user.enable2FA,
        emailVerified: user.emailVerified 
      } 
    });
  } catch (err) {
    console.error('Check auth error:', err);
    next(err);
  }
});


exports.protect = asyncHandler(async (req, res, next) => {
  try {
    console.log('Request cookies:', req.cookies);

    // Check for token in headers first, then cookies
    let accessToken = req.headers.authorization?.startsWith('Bearer') 
      ? req.headers.authorization.split(' ')[1]
      : req.cookies.accessToken;

    if (!accessToken) {
      console.log('No access token provided, attempting to refresh with refreshToken');
      const refreshToken = req.cookies.refreshToken;
      if (!refreshToken) {
        if (req.originalUrl === '/home') {
          console.log('No tokens for /home, proceeding without authentication');
          return next();
        }
        return next(new ApiError('You are not logged in, please login to access this route', 401));
      }

      try {
        const userId = await refreshAccessToken(refreshToken, res);
        accessToken = res.cookies.accessToken;
        if (!accessToken) {
          return next(new ApiError('Failed to refresh token', 401));
        }
      } catch (err) {
        return next(err);
      }
    }

    // Verify access token
    let decoded;
    try {
      decoded = jwt.verify(accessToken, process.env.JWT_SECRET_KEY);
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        console.log('Access token expired, attempting to refresh with refreshToken');
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
          if (req.originalUrl === '/home') {
            console.log('No tokens for /home, proceeding without authentication');
            return next();
          }
          return next(new ApiError('No refresh token provided', 401));
        }
        try {
          const userId = await refreshAccessToken(refreshToken, res);
          accessToken = res.cookies.accessToken;
          decoded = jwt.verify(accessToken, process.env.JWT_SECRET_KEY);
        } catch (refreshErr) {
          return next(refreshErr);
        }
      } else {
        console.log('Invalid access token:', { error: err.message });
        return next(new ApiError('Invalid access token', 401));
      }
    }

    // Check if user exists
    const currentUser = await User.findById(decoded.userId);
    if (!currentUser) {
      return next(new ApiError('The user that belongs to this token no longer exists', 401));
    }

    // Check if user changed password after token was issued
    if (currentUser.passwordChangedAt) {
      const passChangedTimestamp = parseInt(currentUser.passwordChangedAt.getTime() / 1000, 10);
      if (passChangedTimestamp > decoded.iat) {
        return next(new ApiError('User recently changed password. Please login again.', 401));
      }
    }

    // Attach user to request
    req.user = currentUser;
    console.log('User authenticated successfully:', { userId: currentUser._id });
    next();
  } catch (err) {
    console.error('Protect middleware error:', err);
    next(err);
  }
});


// @desc    Authorization (User Permissions)
["admin"]
exports.allowedTo = (...roles) =>
  asyncHandler(async (req, res, next) => {
    // 1) access roles
    // 2) access registered user (req.user.role)
    if (!roles.includes(req.user.role)) {
      return next(
        new ApiError('You are not allowed to access this route', 403)
      );
    }
    next();
  });


// @route   POST /setupOtp
exports.setupOtp = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user._id);
  if (!user) {
    return next(new ApiError('User not found', 401));
  }

  const secret = authenticator.generateSecret(32);
  user.otpSecret = secret;
  await user.save();

  const service = 'Name_Of_Your_Service'; // Replace with your service name
  const otpauth = authenticator.keyuri(user.email, service, secret);
  const qrCodeUrl = await qrcode.toDataURL(otpauth);

  res.status(200).json({
    status: 'success',
    data: { qrCodeUrl, secret }
  });
});

// @route   POST /disableOtp
exports.disableOtp = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user._id);
  if (!user) {
    return next(new ApiError('User not found', 401));
  }

  user.otpSecret = undefined;
  await user.save();

  res.status(200).json({
    status: 'success',
    message: 'OTP authentication disabled'
  });
});

// @route   POST /enable2FA
exports.enable2FA = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user._id);
  if (!user) {
    return next(new ApiError('User not found', 401));
  }

  if (!user.otpSecret) {
    return next(new ApiError('OTP not set up. Please set up OTP first', 400));
  }

  user.enable2FA = true;
  await user.save();

  res.status(200).json({
    status: 'success',
    message: 'Two-factor authentication enabled'
  });
});

// @route   POST /disable2FA
exports.disable2FA = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user._id);
  if (!user) {
    return next(new ApiError('User not found', 401));
  }

  user.enable2FA = false;
  await user.save();

  res.status(200).json({
    status: 'success',
    message: 'Two-factor authentication disabled'
  });
});





  // @route   POST /validateOtp
exports.validateOtp = asyncHandler(async (req, res, next) => {
  const { email, token } = req.body;
  if (!email || !token) {
    return next(new ApiError('Email and OTP are required', 400));
  }

  const user = await User.findOne({ email });
  if (!user) {
    return next(new ApiError('User not found', 401));
  }

  if (!user.otpSecret) {
    return next(new ApiError('OTP authentication not enabled', 400));
  }

  const isValid = authenticator.verify({ token, secret: user.otpSecret });
  if (!isValid) {
    return next(new ApiError('Invalid OTP', 401));
  }

  await RefreshToken.deleteMany({ userId: user._id });

  const accessToken = createAccessToken(user._id);
  const refreshToken = createRefreshToken(user._id);

  const refreshTokenDoc = new RefreshToken({
    token: refreshToken,
    userId: user._id,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });
  await refreshTokenDoc.save();

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 1000,
  });
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  user.status = 'active';
  await user.save();

  const userObj = user.toObject();
  delete userObj.password;

  res.status(200).json({ status: 'success', data: userObj, accessToken });
});

// @route   GET /sendVerificationEmail
exports.sendVerificationEmail = asyncHandler(async (req, res, next) => {
  const user = await User.findById(req.user._id);
  if (!user) {
    return next(new ApiError('User not found', 401));
  }

  if (user.emailVerified) {
    return next(new ApiError('Email already verified', 400));
  }

  const emailVerificationToken = crypto.randomBytes(64).toString('hex') + ':' + (new Date()).toISOString();
  user.emailVerificationToken = emailVerificationToken;
  await user.save();

  const verificationUrl = `${req.protocol}://${req.get('host')}/auth/verifyEmail/${emailVerificationToken}`;
  const message = `Hi ${user.name},\nPlease verify your email by clicking the following link:\n${verificationUrl}\nThis link is valid for 15 minutes.`;
  try {
    await sendEmail({
      email: user.email,
      subject: 'Verify Your Email',
      message
    });
  } catch (err) {
    user.emailVerificationToken = undefined;
    await user.save();
    return next(new ApiError('Failed to send verification email', 500));
  }

  res.status(200).json({ status: 'success', message: 'Verification email sent' });
});

// @route   GET /verifyEmail/:token
exports.verifyEmail = asyncHandler(async (req, res, next) => {
  const token = req.params.token;
  if (!token) {
    return next(new ApiError('Verification token is required', 400));
  }

  const [userId, verificationCode] = token.split(':');
  const user = await User.findById(userId);
  if (!user) {
    return next(new ApiError('User not found', 404));
  }

  if (user.emailVerified) {
    user.emailVerificationToken = undefined;
    await user.save();
    return res.status(200).json({ status: 'success', message: 'Email already verified' });
  }

  if (user.emailVerificationToken !== token) {
    return next(new ApiError('Invalid verification token', 400));
  }

  const createdDate = new Date(verificationCode.split(':').pop());
  if (Math.abs(Date.now() - createdDate.getTime()) > 15 * 60 * 1000) {
    return next(new ApiError('Verification token expired', 400));
  }

  user.emailVerified = true;
  user.emailVerificationToken = undefined;
  await user.save();

  res.status(200).json({ status: 'success', message: 'Email verified successfully' });
});

// @route   POST /forgotPassword
// @access  Public
exports.forgotPassword = asyncHandler(async (req, res, next) => {
  const { email } = req.body;
  if (!email) {
    return next(new ApiError('Email is required', 400));
  }

  const user = await User.findOne({ email });
  if (!user) {
    return next(new ApiError(`No user found with email ${email}`, 404));
  }

  const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
  const hashedResetCode = crypto.createHash('sha256').update(resetCode).digest('hex');

  user.passwordResetCode = hashedResetCode;
  user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
  user.passwordResetVerified = false;

  await user.save();

  const message = `Hi ${user.name},\nWe received a request to reset your password.\n${resetCode}\nEnter this code to complete the reset.\nThis code is valid for 10 minutes.\nThanks for helping us keep your account secure.`;
  try {
    await sendEmail({
      email: user.email,
      subject: 'Your Password Reset Code (Valid for 10 Minutes)',
      message,
    });
    console.log('Password reset code sent to email:', { email });
  } catch (err) {
    console.error('Error sending password reset email:', err);
    user.passwordResetCode = undefined;
    user.passwordResetExpires = undefined;
    user.passwordResetVerified = undefined;
    await user.save();
    return next(new ApiError('Failed to send reset code email', 500));
  }

  res.status(200).json({ status: 'success', message: 'Reset code sent to email' });
});

// @route   POST /verifyResetCode
// @access  Public
exports.verifyPassResetCode = asyncHandler(async (req, res, next) => {
  const { resetCode } = req.body;
  if (!resetCode) {
    return next(new ApiError('Reset code is required', 400));
  }

  const hashedResetCode = crypto.createHash('sha256').update(resetCode).digest('hex');

  const user = await User.findOne({
    passwordResetCode: hashedResetCode,
    passwordResetExpires: { $gt: Date.now() },
  });
  if (!user) {
    return next(new ApiError('Reset code is invalid or expired', 400));
  }

  user.passwordResetVerified = true;
  await user.save();

  console.log('Reset code verified successfully:', { email: user.email });
  res.status(200).json({ status: 'success', message: 'Reset code verified' });
});

// @route   POST /resetPassword
// @access  Public
exports.resetPassword = asyncHandler(async (req, res, next) => {
  const { email, newPassword } = req.body;
  if (!email || !newPassword) {
    return next(new ApiError('Email and new password are required', 400));
  }

  const user = await User.findOne({ email });
  if (!user) {
    return next(new ApiError(`No user found with email ${email}`, 404));
  }

  if (!user.passwordResetVerified) {
    return next(new ApiError('Reset code not verified', 400));
  }

  user.password = newPassword;
  user.passwordResetCode = undefined;
  user.passwordResetExpires = undefined;
  user.passwordResetVerified = undefined;
  user.status = 'active';

  await user.save();

  const accessToken = createAccessToken(user._id);
  const refreshToken = createRefreshToken(user._id);

  const refreshTokenDoc = new RefreshToken({
    token: refreshToken,
    userId: user._id,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
  });
  await refreshTokenDoc.save();

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 1000, // 1 hour
  });
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  console.log('Password reset successfully, new tokens generated:', { userId: user._id });
  res.status(200).json({ status: 'success', message: 'Password reset successfully', accessToken });
});



// route  /logout-all =sessions
















