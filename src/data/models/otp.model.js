const mongoose = require('mongoose')
const otpSchema = require('../schemas/otp.schema')
const crypto = require('crypto')

otpSchema.methods.generateOTP = function () {
  this.otp = crypto.randomInt(100000, 999999).toString()
  return this.otp
}

otpSchema.methods.isLocked = function () {
  return this.lockUntil && this.lockUntil > Date.now()
}

otpSchema.methods.incrementAttempts = function () {
  this.attempts += 1
  if (this.attempts >= 5) {
    this.lockUntil = Date.now() + 15 * 60 * 1000 // 15 minutes
  }
  return this.save()
}

otpSchema.methods.isExpired = async function () {
  const otpExpirationTime = new Date(this.updatedAt.getTime() + 10 * 60 * 1000)
  if (otpExpirationTime < new Date()) {
    this.otp = null
    await this.save()
    return true
  }
  return false
}

const OTP = mongoose.model('Otp', otpSchema)
module.exports = OTP