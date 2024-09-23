const mongoose = require('mongoose');

const dbConnection = () => {
  mongoose.connect(process.env.MONGODB_URI).then(connection => {
    console.log(`Database Connected ${connection.connection.host}`);
  }).catch(error => {
    console.log(`Database Connected error ${error}`);
    process.exit(1);
  });
}

module.exports = dbConnection;
