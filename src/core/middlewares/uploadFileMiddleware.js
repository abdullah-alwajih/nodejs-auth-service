const asyncHandler = require('express-async-handler');
const imageProcessor = require("../utils/imageProcessing");
const upload = require("../utils/fileUpload");

const uploadFile = (filePath, fieldName, options) => asyncHandler(async (req, res, next) => {
  if (req.file) {
    req.body[fieldName] = await imageProcessor(req.file.buffer, filePath, options);
  }
  next();
})

const uploadFiles = (filePath, fields, options) => asyncHandler(async (req, res, next) => {
  if (!req.files) return next(); // Skip processing if req.files is undefined

  await Promise.all(fields.map(async ({name, maxCount}) => {
    const files = req.files[name];
    if (files?.length) {
      req.body[name] = await imageProcessor(maxCount === 1 ? files[0] : files, filePath, options);
    }
  }));

  next();
})

const uploadSingle = (filePath, fieldName = 'image', options) => [upload.single(fieldName), uploadFile(filePath, fieldName, options)];

const uploadFields = (filePath, fields, options) => [upload.fields(fields), uploadFiles(filePath, fields, options)];

module.exports = {uploadSingle, uploadFields}