
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');

dotenv.config({ path: '.env' });

const createAccessToken = (payload) => {
  const token = jwt.sign({ userId: payload }, process.env.JWT_SECRET_KEY, {
    expiresIn: '15m', // 1 minute for testing
  });
  console.log('Access token created:', { userId: payload, token });
  return token;
};

const createRefreshToken = (payload) => {
  const token = jwt.sign({ userId: payload }, process.env.JWT_REFRESH_SECRET_KEY, {
    expiresIn: '7d', // 7 days
  });
  console.log('Refresh token created:', { userId: payload, token });
  return token;
};

module.exports = { createAccessToken, createRefreshToken };



//Key Rotation   >> must apply in ( refreshAccessToken / Protect Middleware)

// const jwt = require('jsonwebtoken');
// const { getCurrentKeys } = require('./keyRotation');

// const createAccessToken = async (userId) => {
//   const { jwtSecretKey } = await getCurrentKeys();
//   return jwt.sign({ userId }, jwtSecretKey, { expiresIn: '1h' });
// };

// const createRefreshToken = async (userId) => {
//   const { jwtRefreshSecretKey } = await getCurrentKeys();
//   return jwt.sign({ userId }, jwtRefreshSecretKey, { expiresIn: '7d' });
// };

// module.exports = { createAccessToken, createRefreshToken };