const sharp = require("sharp");
const path = require("path");

const imageProcessor = async (files, filePath, options = {}) => {
  const {width, height, quality = 90} = options;
  const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)

  const processFile = async (file, index = null) => {
    const fileName = `${filePath}-${uniqueSuffix}${index !== null ? `-${index + 1}` : ''}-${path.parse(file.originalname).name.trim().replace(/\s+/g, '-')}.jpeg`;
    const image = sharp(file.buffer);
    width && height && image.resize(width, height);
    await image.jpeg({quality}).toFile(`public/uploads/${filePath}/${fileName}`);
    return fileName;
  };

  return Array.isArray(files)
    ? Promise.all(files.map((file, index) => processFile(file, index)))
    : processFile(files);
}

module.exports = imageProcessor;