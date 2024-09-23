const cors = require('cors')
const ApiError = require("../base/models/apiError");

const initCROSOrigins = (app) => {
  const whitelist = ['https://api-ecommerce-abdullah.vercel.app', 'https://ecommerce-git-main-abdullahalwajih.vercel.app', 'https://ecommerce-qbm9txq4u-abdullahalwajih.vercel.app', 'http://localhost:3000']
  const corsOptions = {
    origin: function (origin, callback) {
      if (whitelist.indexOf(origin) !== -1 || !origin) {
        callback(null, true)
      } else {
        new ApiError(401, 'Not allowed by CORS')
      }
    }
  }
  app.use(cors(corsOptions));
}

module.exports = initCROSOrigins;