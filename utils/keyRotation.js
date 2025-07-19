const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

const Key = require('../models/KeyModel'); 

const rotateKeys = async () => {
  try {
    const newSecret = crypto.randomBytes(64).toString('hex');
    const newRefreshSecret = crypto.randomBytes(64).toString('hex');

    const newKey = new Key({
      jwtSecretKey: newSecret,
      jwtRefreshSecretKey: newRefreshSecret,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) 
    });
    await newKey.save();

    await Key.deleteMany({ expiresAt: { $lt: new Date() } });

    console.log('Keys rotated successfully:', { newSecret, newRefreshSecret });
    return { newSecret, newRefreshSecret };
  } catch (err) {
    console.error('Error rotating keys:', err);
    throw err;
  }
};

const getCurrentKeys = async () => {
  const latestKey = await Key.findOne().sort({ createdAt: -1 });
  if (!latestKey) {

    const { newSecret, newRefreshSecret } = await rotateKeys();
    return { jwtSecretKey: newSecret, jwtRefreshSecretKey: newRefreshSecret };
  }
  return {
    jwtSecretKey: latestKey.jwtSecretKey,
    jwtRefreshSecretKey: latestKey.jwtRefreshSecretKey
  };
};

module.exports = { rotateKeys, getCurrentKeys };