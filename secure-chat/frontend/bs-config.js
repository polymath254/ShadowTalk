// bs-config.js
const history = require('connect-history-api-fallback');
const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = {
  port: 3000,
  server: {
    baseDir: './',
    middleware: [
      history(),
      function (req, res, next) { next(); }, // required for middleware to be an array
      createProxyMiddleware('/api', {
        target: 'http://localhost:8000',
        changeOrigin: true
      })
    ]
  }
};
