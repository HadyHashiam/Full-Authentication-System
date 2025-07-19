const mongoose = require('mongoose');

const keySchema = new mongoose.Schema({
  jwtSecretKey: { type: String, required: true },
  jwtRefreshSecretKey: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
});

module.exports = mongoose.model('key', keySchema);