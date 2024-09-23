const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const mongoose = require('mongoose');
const userSchema = require('../schemas/user.schema');

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(12);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods = {
  comparePassword(candidatePassword) {
    return bcrypt.compare(candidatePassword, this.password);
  },
  incrementFailedAttempts() {
    this.failedLoginAttempts += 1;
    if (this.failedLoginAttempts >= 5) {
      this.lockUntil = Date.now() + 15 * 60 * 1000; // 15 دقيقة
    }
    return this.save();
  },
  resetFailedAttempts() {
    this.failedLoginAttempts = 0;
    this.lockUntil = null;
    return this.save();
  },
};


module.exports = mongoose.model('User', userSchema);
