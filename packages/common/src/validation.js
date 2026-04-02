'use strict';

/**
 * Validation schemas and validator utility.
 * Uses Joi for schema-based input validation.
 * Every API input MUST be validated through these schemas.
 */

const Joi = require('joi');
const AppError = require('./errors/AppError');
const { ErrorCodes } = require('./errors/codes');

// --- Reusable field schemas ---

const fields = {
  email: Joi.string().email().trim().lowercase().max(255),
  password: Joi.string().min(8).max(128)
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])/)
    .message('Password must contain at least 1 uppercase, 1 lowercase, 1 digit, and 1 special character'),
  name: Joi.string().trim().min(1).max(100),
  businessName: Joi.string().trim().min(1).max(200),
  tronAddress: Joi.string().regex(/^T[a-zA-Z1-9]{33}$/).message('Invalid TRC20 address'),
  mongoId: Joi.string().regex(/^[a-f\d]{24}$/i).message('Invalid ID format'),
  amount: Joi.number().positive().precision(6).max(1000000),
  url: Joi.string().uri({ scheme: ['https'] }).max(500),
  apiKey: Joi.string().length(64),
  totpCode: Joi.string().length(6).regex(/^\d+$/).message('TOTP must be 6 digits'),
  ip: Joi.string().ip(),
  page: Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(100).default(20),
  nonce: Joi.string().uuid(),
  timestamp: Joi.number().integer().positive(),
  idempotencyKey: Joi.string().uuid(),
};

// --- Auth schemas ---

const authRegister = Joi.object({
  email: fields.email.required(),
  password: fields.password.required(),
  firstName: fields.name.required(),
  lastName: fields.name.required(),
}).options({ stripUnknown: true });

const authLogin = Joi.object({
  email: fields.email.required(),
  password: fields.password.required(),
  totpCode: fields.totpCode.optional(),
}).options({ stripUnknown: true });

const authChangePassword = Joi.object({
  currentPassword: fields.password.required(),
  newPassword: fields.password.required(),
}).options({ stripUnknown: true });

const auth2faVerify = Joi.object({
  totpCode: fields.totpCode.required(),
}).options({ stripUnknown: true });

// --- Merchant schemas ---

const merchantCreate = Joi.object({
  businessName: fields.businessName.required(),
  email: fields.email.required(),
  webhookUrl: fields.url.optional().allow(''),
  withdrawalAddress: fields.tronAddress.optional().allow(''),
}).options({ stripUnknown: true });

const merchantUpdate = Joi.object({
  businessName: fields.businessName.optional(),
  webhookUrl: fields.url.optional().allow(''),
  withdrawalAddress: fields.tronAddress.optional(),
}).options({ stripUnknown: true });

// --- Invoice schemas ---

const invoiceCreate = Joi.object({
  amount: fields.amount.required(),
  currency: Joi.string().valid('USDT').default('USDT'),
  description: Joi.string().trim().max(500).optional().allow(''),
  metadata: Joi.object().max(10).optional(),
  callbackUrl: fields.url.optional(),
  idempotencyKey: fields.idempotencyKey.optional(),
}).options({ stripUnknown: true });

// --- Wallet schemas ---

const walletAdd = Joi.object({
  address: fields.tronAddress.required(),
  encryptedPrivateKey: Joi.string().required(),
  label: Joi.string().trim().max(50).optional().allow(''),
  network: Joi.string().valid('tron').default('tron'),
}).options({ stripUnknown: true });

// --- Withdrawal schemas ---

const withdrawalCreate = Joi.object({
  amount: fields.amount.required(),
  toAddress: fields.tronAddress.required(),
  idempotencyKey: fields.idempotencyKey.optional(),
}).options({ stripUnknown: true });

// --- Pagination schema ---

const pagination = Joi.object({
  page: fields.page,
  limit: fields.limit,
  sortBy: Joi.string().valid('createdAt', 'amount', 'status').default('createdAt'),
  sortOrder: Joi.string().valid('asc', 'desc').default('desc'),
}).options({ stripUnknown: true });

// --- Merchant API (HMAC-signed requests) ---

const merchantApiHeaders = Joi.object({
  'x-api-key': fields.apiKey.required(),
  'x-nonce': fields.nonce.required(),
  'x-timestamp': fields.timestamp.required(),
  'x-signature': Joi.string().required(),
}).options({ allowUnknown: true });

// --- Schemas export ---

const schemas = {
  auth: { register: authRegister, login: authLogin, changePassword: authChangePassword, verify2fa: auth2faVerify },
  merchant: { create: merchantCreate, update: merchantUpdate },
  invoice: { create: invoiceCreate },
  wallet: { add: walletAdd },
  withdrawal: { create: withdrawalCreate },
  pagination,
  merchantApiHeaders,
};

/**
 * Validate data against a Joi schema.
 * Throws AppError with validation details on failure.
 *
 * @param {Joi.Schema} schema - Joi schema to validate against
 * @param {object} data - Data to validate
 * @returns {object} Validated and sanitized data
 * @throws {AppError} If validation fails
 */
function validate(schema, data) {
  const { error, value } = schema.validate(data, { abortEarly: false });

  if (error) {
    const details = error.details.map((d) => ({
      field: d.path.join('.'),
      message: d.message,
    }));

    throw AppError.badRequest(
      'Validation failed',
      ErrorCodes.VALIDATION_FAILED,
      details,
    );
  }

  return value;
}

module.exports = { validate, schemas, fields };
