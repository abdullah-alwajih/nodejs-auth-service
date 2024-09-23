const mongoose = require('mongoose')
const crypto = require('crypto')

const clientSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  clientId: {
    type: String,
    unique: true,
    default: () => crypto.randomBytes(16).toString('hex'),
    index: true,
  },
  clientSecret: {
    type: String,
    required: true,
    default: () => crypto.randomBytes(32).toString('hex'),
  },
  redirectUris: {
    type: [String],
    required: true,
    validate: {
      validator: function (v) {
        return v.length > 0
      },
      message: 'At least one redirect URI is required',
    },
  },
  scopes: {
    type: [String],
    enum: ['read', 'write', 'delete'],
    default: ['read'],
  },
  trusted: {
    type: Boolean,
    default: false,
  },
  active: {
    type: Boolean,
    default: true,
    index: true,
  },
}, { timestamps: true })

module.exports = clientSchema