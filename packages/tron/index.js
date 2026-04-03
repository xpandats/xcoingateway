'use strict';

const TronAdapter = require('./src/adapters/tron');
const BlockchainAdapter = require('./src/adapters/base');
const { getTronWeb } = require('./src/tronWeb');

module.exports = {
  TronAdapter,
  BlockchainAdapter,
  getTronWeb,
};
