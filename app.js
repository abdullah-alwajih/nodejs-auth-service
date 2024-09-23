require('dotenv').config();
const express = require('express')
const path = require('path')
const cookieParser = require('cookie-parser')
const logger = require('morgan')

const authRouter = require('./src/routes/auth.route')
const dbConnection = require('./src/core/config/database')
const initLocales = require('./src/core/config/locales')

const app = express()
dbConnection();

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));


initLocales(app);
app.use('/auth', authRouter);


module.exports = app;
