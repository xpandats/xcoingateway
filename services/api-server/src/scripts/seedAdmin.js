'use strict';

/**
 * Admin Seed Script — Creates the first admin user.
 *
 * Usage: node services/api-server/src/scripts/seedAdmin.js
 *
 * This is run ONCE during initial setup.
 * The admin user bypasses the approval flow.
 *
 * SECURITY: This script must ONLY be run locally or in a secure deployment context.
 * It reads the admin credentials from environment variables.
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../../../.env.local') });

const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const { connectDB, disconnectDB, User } = require('@xcg/database');
const { validateMasterKey } = require('@xcg/crypto');
const { createLogger } = require('@xcg/logger');
const { ROLES } = require('@xcg/common').constants;

const logger = createLogger('seed-admin');

const ADMIN_EMAIL = process.env.ADMIN_SEED_EMAIL || 'admin@xcoingateway.com';
const ADMIN_PASSWORD = process.env.ADMIN_SEED_PASSWORD || null;
const ADMIN_FIRST_NAME = process.env.ADMIN_SEED_FIRST_NAME || 'System';
const ADMIN_LAST_NAME = process.env.ADMIN_SEED_LAST_NAME || 'Admin';
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 12;

async function seedAdmin() {
  try {
    logger.info('Starting admin seed...');

    // Validate
    if (!ADMIN_PASSWORD) {
      logger.error('ADMIN_SEED_PASSWORD environment variable is required');
      logger.info('Set it in .env.local: ADMIN_SEED_PASSWORD=YourSecure@Password123');
      process.exit(1);
    }

    if (ADMIN_PASSWORD.length < 12) {
      logger.error('Admin password must be at least 12 characters for production safety');
      process.exit(1);
    }

    validateMasterKey();
    await connectDB(process.env.MONGODB_URI);

    // Check if admin already exists
    const existing = await User.findOne({ email: ADMIN_EMAIL });
    if (existing) {
      logger.warn('Admin user already exists', { email: ADMIN_EMAIL, role: existing.role });
      if (existing.role !== ROLES.ADMIN) {
        logger.info('Upgrading existing user to admin role...');
        existing.role = ROLES.ADMIN;
        existing.isApproved = true;
        existing.approvedAt = new Date();
        await existing.save();
        logger.info('User upgraded to admin');
      }
      await disconnectDB();
      process.exit(0);
    }

    // Create admin
    const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, BCRYPT_ROUNDS);

    const admin = await User.create({
      email: ADMIN_EMAIL,
      passwordHash,
      firstName: ADMIN_FIRST_NAME,
      lastName: ADMIN_LAST_NAME,
      role: ROLES.ADMIN,
      isActive: true,
      isApproved: true, // Admin is pre-approved
      approvedAt: new Date(),
      passwordHistory: [passwordHash],
    });

    logger.info('Admin user created successfully', {
      email: ADMIN_EMAIL,
      userId: admin._id.toString(),
      role: ROLES.ADMIN,
    });
    logger.info('You can now log in with these credentials.');

    await disconnectDB();
    process.exit(0);

  } catch (err) {
    logger.error('Admin seed failed', { error: err.message });
    process.exit(1);
  }
}

seedAdmin();
