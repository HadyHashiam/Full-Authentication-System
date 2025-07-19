const jwt = require('jsonwebtoken');
const ApiError = require('./apiError');
const { createAccessToken } = require('./createToken');
const RefreshToken = require('../models/RefreshToken.model');

// Helper function to refresh access token
const refreshAccessToken = async (refreshToken, res) => {
  try {
    console.log('Attempting to refresh access token with refreshToken:', { refreshToken });
    const decodedRefresh = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET_KEY);
    const storedToken = await RefreshToken.findOne({
      token: refreshToken,
      userId: decodedRefresh.userId,
    });

    if (!storedToken || storedToken.expiresAt < new Date()) {
      console.log('Invalid or expired refresh token:', { refreshToken });
      throw new ApiError('Invalid or expired refresh token', 401);
    }

    const newAccessToken = createAccessToken(decodedRefresh.userId);
    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1 * 60 * 1000, // 1 minute for testing
    });

    console.log('New access token generated:', { userId: decodedRefresh.userId, newAccessToken });
    return decodedRefresh.userId;
  } catch (err) {
    console.error('Refresh access token error:', err);
    throw err;
  }
};

// Function to get userId from token
const getUserIdFromToken = async (req, res, next) => {
  try {
    console.log('Request cookies:', req.cookies);

    let token = req.headers.authorization?.split(' ')[1] || req.cookies.accessToken;

    // If no access token, try to refresh directly, unless it's the /home route
    if (!token) {
      console.log('No access token provided, attempting to refresh with refreshToken');
      const refreshToken = req.cookies.refreshToken;
      if (!refreshToken) {
        console.log('No refresh token found in cookies');
        if (req.originalUrl === '/home') {
          console.log('No tokens for /home, returning null userId');
          return null; // Allow /home to proceed without authentication
        }
        throw new ApiError('No refresh token provided', 401);
      }
      return await refreshAccessToken(refreshToken, res);
    }

    // Verify access token
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
      return decoded.userId;
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        console.log('Access token expired, attempting to refresh with refreshToken');
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
          console.log('No refresh token found in cookies');
          if (req.originalUrl === '/home') {
            console.log('No tokens for /home, returning null userId');
            return null; // Allow /home to proceed without authentication
          }
          throw new ApiError('No refresh token provided', 401);
        }
        return await refreshAccessToken(refreshToken, res);
      }
      console.log('Invalid access token:', { error: err.message });
      throw new ApiError('Invalid access token', 401);
    }
  } catch (err) {
    console.error('Token verification error:', err);
    next(err);
  }
};

module.exports = { getUserIdFromToken, refreshAccessToken };