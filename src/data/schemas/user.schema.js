const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    trim: true,
    required: [true, 'Name is required'],
  },
  email: {
    type: String,
    unique: true,
    sparse: true,
    lowercase: true,
    trim: true,
    index: true,
  },
  phone: {
    type: String,
    unique: true,
    sparse: true,
    trim: true,
    index: true,
  },
  password: {
    type: String,
    required: true,
    minlength: [8, 'Password must be at least 8 characters long'],
    select: false,
  },
  picture: {
    type: String,
    default: 'default.png',
  },
  emailVerifiedAt: {
    type: Date,
    default: null,
  },
  phoneVerifiedAt: {
    type: Date,
    default: null,
  },
  activatedAt: {
    type: Date,
    default: Date.now,
    index: true,
  },
  lastLogin: {
    type: Date,
  },
}, { timestamps: true })

module.exports = userSchema