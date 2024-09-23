const express = require('express')
const {
  loginValidator,
  registerValidator, forgotPasswordValidator,
  resetPasswordValidator, changePasswordValidator, verifyOTPValidator,
} = require('./auth.middleware')

const {
  authenticated,
  register,
  login,
  forgotPassword,
  verifyPassResetCode,
  resetPassword,
  changeUserPassword,
  verifyOtp,
} = require('../manager/controllers/auth.controller')

const router = express.Router()

router.post('/register', registerValidator, register)
router.post('/login', loginValidator, login)
router.post('/verify-otp', verifyOTPValidator, verifyOtp)
router.post('/forgot-password', forgotPasswordValidator, forgotPassword)
router.put('/reset-password', resetPasswordValidator, resetPassword)
router.use(authenticated)
router.put('/change-password', changePasswordValidator, changeUserPassword)

module.exports = router
