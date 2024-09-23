const mongoose = require('mongoose')
const clientSchema = require('../schemas/client.schema')

module.exports = mongoose.model('Client', clientSchema)
