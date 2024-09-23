// models/Otp.js
const mongoose = require('mongoose')

const otpSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true,
  },
  otp: {
    type: String,
  },
  identify: {
    type: String, // value email or phone
    required: true,
  },
  attempts: {
    type: Number,
    default: 0,
  }
}, { timestamps: true })

module.exports = otpSchema