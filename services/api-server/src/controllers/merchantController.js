'use strict';

/**
 * @module controllers/merchantController
 *
 * Merchant Controller — Admin endpoints for merchant management.
 *
 * Routes (all require: authenticate + authorize('admin') + adminIpCheck):
 *   POST   /admin/merchants                          — Create merchant
 *   GET    /admin/merchants                          — List merchants
 *   GET    /admin/merchants/:id                      — Get merchant details
 *   PUT    /admin/merchants/:id                      — Update merchant
 *   PUT    /admin/merchants/:id/status               — Activate/suspend
 *   POST   /admin/merchants/:id/api-keys             — Generate new API key
 *   DELETE /admin/merchants/:id/api-keys/:keyId      — Revoke API key
 *   POST   /admin/merchants/:id/webhook-secret-rotate — Rotate webhook secret
 */

const Joi = require('joi');
const { validate, schemas, AppError } = require('@xcg/common');
const { config }   = require('../config');
const asyncHandler = require('../utils/asyncHandler');
const MerchantService = require('../services/merchantService');
const logger = require('@xcg/logger').createLogger('merchant-ctrl');

const svc = new MerchantService();

// ─── Validation schemas ──────────────────────────────────────────────────────

const createSchema = Joi.object({
  userId:            Joi.string().hex().length(24).required(),
  businessName:      Joi.string().trim().min(1).max(200).required(),
  email:             Joi.string().email().optional().allow(''),
  webhookUrl:        Joi.string().uri({ scheme: ['https'] }).max(500).optional().allow(''),
  withdrawalAddress: Joi.string().pattern(/^T[1-9A-HJ-NP-Za-km-z]{33}$/).optional().allow(''),
}).options({ stripUnknown: true });

const updateSchema = Joi.object({
  businessName:               Joi.string().trim().min(1).max(200).optional(),
  webhookUrl:                 Joi.string().uri({ scheme: ['https'] }).max(500).optional().allow(''),
  withdrawalAddress:          Joi.string().pattern(/^T[1-9A-HJ-NP-Za-km-z]{33}$/).optional().allow(''),
  withdrawalAddressVerified:  Joi.boolean().optional(),
}).options({ stripUnknown: true });

const apiKeySchema = Joi.object({
  label: Joi.string().trim().max(50).optional().allow(''),
}).options({ stripUnknown: true });

const paginationSchema = Joi.object({
  page:   Joi.number().integer().min(1).max(1000).default(1),
  limit:  Joi.number().integer().min(1).max(100).default(20),
  search: Joi.string().trim().max(100).optional().allow(''),
}).options({ stripUnknown: true });

// ─── Handlers ────────────────────────────────────────────────────────────────

async function createMerchant(req, res) {
  const data = validate(createSchema, req.body);
  const result = await svc.createMerchant(data, data.userId, {
    userId: req.user._id,
    ip:     req.ip,
  });
  res.status(201).json({ success: true, data: result });
}

async function listMerchants(req, res) {
  const query  = validate(paginationSchema, req.query);
  const result = await svc.listMerchants(query);
  res.json({ success: true, data: result });
}

async function getMerchant(req, res) {
  const merchant = await svc.getMerchant(req.params.id);
  res.json({ success: true, data: { merchant } });
}

async function updateMerchant(req, res) {
  const data = validate(updateSchema, req.body);
  const merchant = await svc.updateMerchant(req.params.id, data, {
    userId: req.user._id,
    ip:     req.ip,
  });
  res.json({ success: true, data: { merchant } });
}

async function setMerchantStatus(req, res) {
  const { isActive } = req.body;
  if (typeof isActive !== 'boolean') throw AppError.badRequest('isActive must be boolean');
  const merchant = await svc.setMerchantStatus(req.params.id, isActive, {
    userId: req.user._id,
    ip:     req.ip,
  });
  res.json({ success: true, data: { merchant } });
}

async function createApiKey(req, res) {
  const { label } = validate(apiKeySchema, req.body);
  const result = await svc.createApiKey(req.params.id, label, {
    userId: req.user._id,
    ip:     req.ip,
  });
  res.status(201).json({ success: true, data: result });
}

async function revokeApiKey(req, res) {
  await svc.revokeApiKey(req.params.id, req.params.keyId, {
    userId: req.user._id,
    ip:     req.ip,
  });
  res.json({ success: true, message: 'API key revoked' });
}

async function rotateWebhookSecret(req, res) {
  const result = await svc.rotateWebhookSecret(req.params.id, {
    userId: req.user._id,
    ip:     req.ip,
  });
  res.json({ success: true, data: result });
}

module.exports = {
  createMerchant:       asyncHandler(createMerchant),
  listMerchants:        asyncHandler(listMerchants),
  getMerchant:          asyncHandler(getMerchant),
  updateMerchant:       asyncHandler(updateMerchant),
  setMerchantStatus:    asyncHandler(setMerchantStatus),
  createApiKey:         asyncHandler(createApiKey),
  revokeApiKey:         asyncHandler(revokeApiKey),
  rotateWebhookSecret:  asyncHandler(rotateWebhookSecret),
};
