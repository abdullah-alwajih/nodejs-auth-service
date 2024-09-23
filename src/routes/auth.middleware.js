const {
  validateUserName,
  validateUserPassword,
  validateUserOtp,
  validateUserCurrentPassword,
  validateEmailOrPhone,
  validateEmailAndPhone, validateUserPicture,
} = require('../manager/validators/auth.validator')

const validatorMiddleware = require('../core/middlewares/validatorMiddleware')
const { uploadSingle } = require('../core/middlewares/uploadFileMiddleware')

const uploadUserImage = uploadSingle('users', 'image', { width: 600, height: 600 })

exports.registerValidator = [
  uploadUserImage,
  validateUserName,
  validateEmailAndPhone,
  validateUserPassword,
  validateUserPicture,
  validatorMiddleware,
]

exports.loginValidator = [
  validateEmailOrPhone,
  validateUserPassword,
  validatorMiddleware,
]

exports.forgotPasswordValidator = [
  validateEmailOrPhone,
  validatorMiddleware,
]

exports.resetPasswordValidator = [
  validateEmailOrPhone,
  validateUserOtp,
  validateUserPassword,
  validatorMiddleware,
]

exports.changePasswordValidator = [
  validateUserPassword,
  validateUserCurrentPassword,
  validatorMiddleware,
]

exports.verifyOTPValidator = [
  validateEmailOrPhone,
  validateUserOtp,
  validatorMiddleware,
]
