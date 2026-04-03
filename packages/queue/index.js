'use strict';

const { createPublisher, createConsumer } = require('./src/queueClient');
const { QUEUES } = require('./src/queues');

module.exports = { createPublisher, createConsumer, QUEUES };
