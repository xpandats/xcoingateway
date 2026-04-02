'use strict';

const { createLogger } = require('./src/logger');
const { createAuditLogger } = require('./src/auditLogger');

module.exports = {
  createLogger,
  createAuditLogger,
};
