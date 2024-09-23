const ApiError = require("../base/models/apiError");


const errorFormat = (err, res) => {
  res.status(err.statusCode).json({
    status: err.status,
    message: err.message,
    ...(process.env.NODE_ENV === 'development' && {error: err, stack: err.stack})
  });
};

const errorMiddleware = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';
  if (err.name === 'JsonWebTokenError') err = new ApiError(401, __('error.invalid_token'));
  else if (err.name === 'TokenExpiredError') err = new ApiError(401, __('error.expired_token'));
  errorFormat(err, res);
};

module.exports = errorMiddleware;