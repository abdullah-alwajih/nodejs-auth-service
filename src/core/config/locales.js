const i18n = require("i18n");
const path = require("path");

const initLocales = (app) => {
  // Configure i18n
  i18n.configure({
    locales: ['en', 'ar'], // List all the supported languages
    directory: path.join(__dirname, '../../../public/locales'), // Path to the locales directory
    defaultLocale: 'ar', // Default language
    register: global,
    autoReload: true,  // Reload translations when files are updated
    updateFiles: false,  // Disable updating translation files with missing keys
    syncFiles: false,  // Disable creating missing files
    objectNotation: true,  // Enable dot notation for nested translations
  });

  // Initialize i18n
  app.use(i18n.init);

  // Middleware to detect language from query parameter, cookie, or header
  app.use((req, res, next) => {
    const lang = req.query.lang || req.cookies.lang || req.headers['accept-language'] || 'ar';
    req.setLocale(lang);
    next();
  })

}

module.exports = initLocales;
