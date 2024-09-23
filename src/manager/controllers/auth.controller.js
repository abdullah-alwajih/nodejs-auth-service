const crypto = require('crypto')
const bcrypt = require('bcryptjs')
const asyncHandler = require('express-async-handler')
const User = require('../../data/models/user.model')
const ApiError = require('../../core/base/models/apiError')
const createToken = require('../../core/utils/token')
const sendEmail = require('../../core/utils/mail')
const sendSMS = require('../../core/utils/sms')
const jwt = require('jsonwebtoken')
const OTP = require('../../data/models/otp.model')

exports.authenticated = asyncHandler(async (req, res, next) => {
  const { authorization } = req.headers

  if (!(authorization && authorization.startsWith('Bearer') && authorization.split(' ')[1])) {
    return next(new ApiError(401, __('error.not_logged_in')))
  }

  try {
    const decoded = jwt.verify(authorization.split(' ')[1], process.env.JWT_SECRET_KEY)

    const currentUser = await User.findById(decoded.userId)
    if (!currentUser) {
      return next(new ApiError(401, __('error.user_no_longer_exists')))
    }

    if (currentUser.passwordChangedAt) {
      const passChangedTimestamp = parseInt(currentUser.passwordChangedAt.getTime() / 1000, 10)
      if (passChangedTimestamp > decoded.iat) {
        return next(new ApiError(401, __('error.password_changed')))
      }
    }

    req.user = currentUser
    next()
  } catch (error) {
    switch (error.name) {
      case 'TokenExpiredError':
        return next(new ApiError(401, __('error.expired_token')))
      case 'JsonWebTokenError':
        return next(new ApiError(401, __('error.invalid_token')))
      default:
        return next(new ApiError(500, __('error.failed_to_authenticate')))
    }
  }

})

exports.register = asyncHandler(async (req, res, next) => {
  // 1- Create user
  const user = await User.create({
    name: req.body.name,
    email: req.body.email,
    phone: req.body.phone,
    password: req.body.password,
    picture: req.body.picture,
  })
  // 2- Generate and send OTP
  const identify = req.body.email || req.body.phone;
  await createAndSendOTP(user._id, identify);


  // 2- Generate token
  const token = createToken(user._id)

  res.status(201).json({
    status: 'success',
    message: 'User registered successfully. Please verify your account.',
    data: { user, token },
  })
})

async function createAndSendOTP (userId, identify) {
  const otp = new OTP({ user: userId, identify })
  const code = otp.generateOTP()

  if (identify.includes('@')) {  // Assuming email contains '@'
    await sendEmail(identify, 'Verification OTP', `Your OTP is: ${code}`)
  } else {
    await sendSMS(identify, `Your OTP is: ${code}`)
  }

  otp.attempts += 1
  await otp.save()

  return code
}

exports.login = asyncHandler(async (req, res, next) => {
  // 1) check if password and email in the body (validation)
  // 2) check if user exist & check if password is correct
  const user = await User.findOne({ email: req.body.email })

  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {
    return next(new ApiError(401, __('Incorrect email or password')))
  }
  // 3) generate token
  const token = createToken(user._id)

  // Delete password from response
  delete user._doc.password
  // 4) send response to client side
  res.status(200).json({ data: user, token })
})

exports.forgotPassword = asyncHandler(async (req, res, next) => {
  // 1) Get user by email
  const user = await User.findOne({ email: req.body.email })
  if (!user) {
    return next(new ApiError(404, `There is no user with that email ${req.body.email}`,))
  }
  // 2) If user exist, Generate hash reset random 6 digits and save it in db
  const resetCode = crypto.randomBytes(3).toString('hex').toUpperCase()
  // Save hashed password reset code into db
  user.passwordResetCode = crypto
  .createHash('sha256')
  .update(resetCode)
  .digest('hex')
  // Add expiration time for password reset code (10 min)
  user.passwordResetExpires = Date.now() + 10 * 60 * 1000
  user.passwordResetVerified = false

  await user.save()

  // 3) Send the reset code via email
  const message = `Hi ${user.name},\n We received a request to reset the password on your E-shop Account. \n ${resetCode} \n Enter this code to complete the reset. \n Thanks for helping us keep your account secure.\n The E-shop Team`
  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset code (valid for 10 min)', message,
    })
  } catch (err) {
    user.passwordResetCode = undefined
    user.passwordResetExpires = undefined
    user.passwordResetVerified = undefined

    await user.save()
    return next(new ApiError(500, 'There is an error in sending email',))
  }

  res
  .status(200)
  .json({ status: 'Success', message: 'Reset code sent to email' })
})

// @desc    Verify password reset code
// @route   POST /api/v1/auth/verifyResetCode
// @access  Public
exports.verifyPassResetCode = asyncHandler(async (req, res, next) => {
  // 1) Get user based on reset code
  const hashedResetCode = crypto
  .createHash('sha256')
  .update(req.body.resetCode)
  .digest('hex')

  const user = await User.findOne({
    passwordResetCode: hashedResetCode, passwordResetExpires: { $gt: Date.now() },
  })
  if (!user) {
    return next(new ApiError(404, 'Reset code invalid or expired'))
  }

  // 2) Reset code valid
  user.passwordResetVerified = true
  await user.save()

  res.status(200).json({ status: 'Success', })
})

// @desc    Reset password
// @route   POST /api/v1/auth/resetPassword
// @access  Public
exports.resetPassword = asyncHandler(async (req, res, next) => {
  // 1) Get user based on email
  const user = await User.findOne({ email: req.body.email })
  if (!user) {
    return next(new ApiError(404, `There is no user with email ${req.body.email}`,))
  }

  // 2) Check if reset code verified
  if (!user.passwordResetVerified) {
    return next(new ApiError(400, 'Reset code not verified',))
  }

  user.password = req.body.newPassword
  user.passwordResetCode = undefined
  user.passwordResetExpires = undefined
  user.passwordResetVerified = undefined

  await user.save()

  // 3) if everything is ok, generate token
  const token = createToken(user._id)
  res.status(200).json({ token })
})

exports.changeUserPassword = asyncHandler(async (req, res, next) => {
  const document = await User.findByIdAndUpdate(
    req.params.id,
    {
      password: await bcrypt.hash(req.body.password, 12),
      passwordChangedAt: Date.now(),
    },
    {
      new: true,
    }
  )

  if (!document) {
    return next(new ApiError(404, `No document for this id ${req.params.id}`))
  }
  res.status(200).json({ data: document })
})

exports.verifyOtp = asyncHandler(async (req, res) => {
  const { otp, email, phone } = req.body;
  const identify = email || phone;
  const identifierType = email ? 'email' : 'phone';

  // البحث عن OTP حيث otp ليس null ويتوافق مع المعرف
  const otpRecord = await OTP.findOne({
    otp,
    identify,
    otp: { $ne: null },
  }).sort({ createdAt: -1 });

  if (!otpRecord) {
    throw new ApiError(400, 'Invalid or expired OTP');
  }
  const isExpired = otp.isExpired();
  if (isExpired) {
    throw new ApiError(400, 'OTP has expired');
  }

  const user = await User.findById(otpRecord.user);
  if (!user) {
    throw new ApiError(404, 'User not found');
  }

  // التحقق من تطابق المعرف مع معلومات المستخدم
  if (
    (identifierType === 'email' && user.email !== identify) ||
    (identifierType === 'phone' && user.phone !== identify)
  ) {
    throw new ApiError(400, 'Identifier does not match user records');
  }

  // تحديث حالة التحقق للمستخدم
  if (identifierType === 'email') {
    user.emailVerifiedAt = Date.now();
  } else {
    user.phoneVerifiedAt = Date.now();
  }
  await user.save();

  // تعيين otp إلى null لمنع إعادة استخدامه
  otpRecord.otp = null;
  await otpRecord.save();

  res.status(200).json({
    status: 'success',
    message: 'Account verified successfully',
    data: { user },
  });
});