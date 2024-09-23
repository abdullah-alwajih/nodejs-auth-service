const bcrypt = require('bcryptjs')
const { body, check } = require('express-validator')
const User = require('../../data/models/user.model')

const validateUserName = body('name')
.trim()
.notEmpty()
.withMessage((value, { req }) => req.__('validation.nameRequired'))

const validateUserEmail = body('email')
.if(body('phone').isEmpty())
.notEmpty()
.withMessage((value, { req }) => req.__('validation.eitherEmailOrPhoneRequired'))
.bail()
.isEmail()
.normalizeEmail()
.withMessage((value, { req }) => req.__('validation.invalidEmail'))

const validateUserPhone = body('phone')
.if(body('email').isEmpty())
.notEmpty()
.withMessage((value, { req }) => req.__('validation.eitherEmailOrPhoneRequired'))
.bail()
.isMobilePhone(['ar-EG', 'ar-SA'])
.withMessage((value, { req }) => req.__('validation.invalidPhoneNumber'))

const validateEmailOrPhone = [validateUserEmail, validateUserPhone]

const validateEmailAndPhone = [
  validateEmailOrPhone,
  body('email').if(body('phone').isEmpty())
  .custom(async (email, { req }) => {
    if (email) {
      const existingUser = await User.findOne({ email }).lean()
      if (existingUser) {
        throw new Error(req.__('validation.emailAlreadyExists')) // Email already exists
      }
    }
    return true
  }),

  body('phone').if(body('email').isEmpty())
  .custom(async (phone, { req }) => {
    if (phone) {
      const existingUser = await User.findOne({ phone }).lean()
      if (existingUser) {
        throw new Error(req.__('validation.phoneAlreadyExists')) // Phone already exists
      }
    }
    return true
  })
]

const validateUserPassword = body('password')
.notEmpty()
.withMessage((value, { req }) => req.__('validation.passwordRequired'))
.isLength({ min: 8 })
.withMessage((value, { req }) => req.__('validation.passwordTooShort'))
.matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])/)
.withMessage((value, { req }) => req.__('validation.passwordRequirements'))

const validateUserCurrentPassword = body('currentPassword')
.notEmpty()
.withMessage((value, { req }) => req.__('validation.currentPasswordRequired'))
.custom(async (val, { req }) => {
  const user = await User.findById(req.params.id)
  if (!user) {
    throw new Error(req.__('validation.noUserFoundForId'))
  }
  const isCorrectPassword = await bcrypt.compare(req.body.currentPassword, user.password)
  if (!isCorrectPassword) {
    throw new Error(req.__('validation.incorrectCurrentPassword'))
  }
  return true
})

const validateUserPicture = body('picture').optional()

const validateUserOtp = body('otp')
.isLength({ min: 6, max: 6 })
.withMessage((value, { req }) => req.__('validation.otpMustBeSixDigits'))
.isNumeric()
.withMessage((value, { req }) => req.__('validation.otpMustContainOnlyNumbers'))

module.exports = {
  validateUserName,
  validateEmailOrPhone,
  validateEmailAndPhone,
  validateUserPassword,
  validateUserCurrentPassword,
  validateUserPicture,
  validateUserOtp,
}
