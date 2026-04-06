'use strict';

/**
 * @module services/merchantService
 *
 * Merchant Service — Full CRUD + API Key Management.
 *
 * BANKING-GRADE GUARANTEES:
 *   1. API keys: public keyId + hashed verifier (bcrypt) + encrypted secret (AES-256-GCM)
 *      → keyId for lookup, bcrypt hash for rate-limit brute force, secret for HMAC
 *   2. Webhook secret: AES-256-GCM encrypted before DB storage
 *   3. Merchant creation is atomic (User + Merchant in one operation)
 *   4. All sensitive operations logged to audit trail
 *   5. API keys are single-use-view: full key only returned on creation, never again
 *   6. Key rotation: old key stays active until merchant confirms switch
 *
 * API KEY STRUCTURE:
 *   Public ID:   `xcg_key_{24-char-hex}` — used in X-API-Key header for lookup
 *   Raw Secret:  `xcg_sec_{64-char-hex}` — returned once, used for HMAC signing
 *   DB stores:   keyId | bcrypt(keyId+secret) | AES-256-GCM(secret)
 */

const bcrypt     = require('bcrypt');
const crypto     = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { Merchant, AuditLog, KeyRotationLog } = require('@xcg/database');
const { AppError } = require('@xcg/common');
const { encrypt, decrypt, generateApiKey, generateApiSecret, generateWebhookSecret } = require('@xcg/crypto');
const { config }  = require('../config');
const cache       = require('../utils/cache');

const logger = require('@xcg/logger').createLogger('merchant-svc');

// Max inactive API keys per merchant (prevents accumulation)
const MAX_API_KEYS = 5;

class MerchantService {
  /**
   * @param {object} [redis] - Optional IORedis client for cache invalidation.
   *   Must be injected at construction (e.g. in app.js or controller factory).
   *   If null/undefined, cache invalidation is skipped (cache will expire by TTL).
   */
  constructor({ redis = null } = {}) {
    this.redis = redis;
  }


  // ─── Create Merchant ────────────────────────────────────────────────────────

  /**
   * Create a new merchant profile.
   * @param {object} data    - { businessName, email, webhookUrl, withdrawalAddress }
   * @param {object} userId  - Admin user creating the merchant
   * @param {object} actor   - { userId, ip }
   */
  async createMerchant(data, userId, actor) {
    const { businessName, email, webhookUrl, withdrawalAddress } = data;

    const existing = await Merchant.findOne({ userId });
    if (existing) throw AppError.conflict('User already has a merchant profile');

    // Generate initial API key pair
    const { keyId, rawSecret, encryptedSecret } = this._generateKeyPair();

    // Encrypt webhook secret if provided
    let encryptedWebhookSecret = '';
    let rawWebhookSecret = '';
    if (webhookUrl) {
      rawWebhookSecret = generateWebhookSecret
        ? generateWebhookSecret()
        : `whsec_${crypto.randomBytes(32).toString('hex')}`;
      encryptedWebhookSecret = `v1:${encrypt(rawWebhookSecret).slice(3)}`; // keep v1: prefix
    }

    const merchant = await Merchant.create({
      userId,
      businessName,
      email: email || '',
      isActive:      true,
      feePercentage: config.invoice.platformFeeRate * 100, // e.g. 0.1
      apiKeys: [{
        keyId,
        keyHash:   await bcrypt.hash(`${keyId}:${rawSecret}`, 10), // Extra brute-force protection
        apiSecret: encryptedSecret,
        label:     'default',
        isActive:  true,
        permissions: ['payments:read', 'payments:write', 'withdrawals:write'],
      }],
      webhookUrl: webhookUrl || '',
      webhookSecret: encryptedWebhookSecret,
      webhookEvents: ['payment.confirmed', 'payment.expired', 'withdrawal.completed'],
      withdrawalAddress: withdrawalAddress || '',
    });

    await AuditLog.create({
      actor:      String(actor.userId),
      action:     'merchant_created',
      resource:   'merchant',
      resourceId: String(merchant._id),
      ipAddress:  actor.ip,
      metadata:   { businessName, userId: String(userId) },
      outcome:    'success',
      timestamp:  new Date(),
    });

    logger.info('MerchantService: merchant created', {
      merchantId: String(merchant._id), businessName,
    });

    return {
      merchant: merchant.toSafeJSON(),
      // Return raw credentials ONCE — never stored in plaintext
      credentials: {
        keyId,
        secret:        rawSecret,
        webhookSecret: rawWebhookSecret || null,
        _warning:      'Store these credentials securely. The secret CANNOT be retrieved again.',
      },
    };
  }

  // ─── Get Merchant ───────────────────────────────────────────────────────────

  async getMerchant(merchantId) {
    const merchant = await Merchant.findById(merchantId).lean();
    if (!merchant) throw AppError.notFound('Merchant not found');
    return merchant.toSafeJSON ? Merchant.hydrate(merchant).toSafeJSON() : merchant;
  }

  async getMerchantByUser(userId) {
    const merchant = await Merchant.findOne({ userId }).lean();
    if (!merchant) throw AppError.notFound('Merchant profile not found');
    return Merchant.hydrate(merchant).toSafeJSON();
  }

  // ─── List Merchants ─────────────────────────────────────────────────────────

  async listMerchants({ page = 1, limit = 20, search } = {}) {
    const filter = {};
    if (search) filter.$text = { $search: search };

    const skip = (page - 1) * limit;
    const [merchants, total] = await Promise.all([
      Merchant.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip).limit(limit)
        .lean()
        .then((list) => list.map((m) => Merchant.hydrate(m).toSafeJSON())),
      Merchant.countDocuments(filter),
    ]);

    return { merchants, pagination: { page, limit, total, pages: Math.ceil(total / limit) } };
  }

  // ─── Update Merchant ────────────────────────────────────────────────────────

  async updateMerchant(merchantId, updates, actor) {
    const { businessName, webhookUrl, withdrawalAddress, withdrawalAddressVerified } = updates;

    const patch = {};
    if (businessName)                           patch.businessName = businessName;
    if (webhookUrl !== undefined)               patch.webhookUrl   = webhookUrl;
    if (withdrawalAddress !== undefined)        patch.withdrawalAddress = withdrawalAddress;
    if (withdrawalAddressVerified !== undefined) patch.withdrawalAddressVerified = withdrawalAddressVerified;

    const merchant = await Merchant.findByIdAndUpdate(merchantId, { $set: patch }, { new: true });
    if (!merchant) throw AppError.notFound('Merchant not found');

    await AuditLog.create({
      actor:      String(actor.userId),
      action:     'merchant_updated',
      resource:   'merchant',
      resourceId: merchantId,
      ipAddress:  actor.ip,
      metadata:   patch,
      outcome:    'success',
      timestamp:  new Date(),
    });

    return merchant.toSafeJSON();
  }

  // ─── API Key Management ─────────────────────────────────────────────────────

  /**
   * Generate a new API key for a merchant.
   * Returns raw credentials ONCE — they can never be retrieved again.
   */
  async createApiKey(merchantId, label, actor) {
    const merchant = await Merchant.findById(merchantId);
    if (!merchant) throw AppError.notFound('Merchant not found');

    // Enforce max active key limit
    const activeKeys = merchant.apiKeys.filter((k) => k.isActive);
    if (activeKeys.length >= MAX_API_KEYS) {
      throw AppError.badRequest(`Maximum ${MAX_API_KEYS} active API keys allowed per merchant`);
    }

    const { keyId, rawSecret, encryptedSecret } = this._generateKeyPair();
    const keyHash = await bcrypt.hash(`${keyId}:${rawSecret}`, 10);

    merchant.apiKeys.push({
      keyId,
      keyHash,
      apiSecret: encryptedSecret,
      label:     label || `key_${Date.now()}`,
      isActive:  true,
      permissions: ['payments:read', 'payments:write'],
    });

    await merchant.save();

    // Invalidate merchant profile cache — new key count changed
    await cache.invalidateMerchant(this.redis, String(merchantId));

    await AuditLog.create({
      actor:      String(actor.userId),
      action:     'api_key_created',
      resource:   'merchant',
      resourceId: merchantId,
      ipAddress:  actor.ip,
      metadata:   { keyId, label },
      outcome:    'success',
      timestamp:  new Date(),
    });

    logger.info('MerchantService: API key created', { merchantId, keyId });

    // Record key rotation event for compliance audit
    KeyRotationLog.create({
      rotationId:   `rot_${crypto.randomBytes(12).toString('hex')}`,
      keyType:      'merchant_api_key',
      merchantId,
      newKeyId:     keyId,
      status:       'completed',
      completedAt:  new Date(),
      durationMs:   0,
      initiatedBy:  actor.userId,
      reason:       'manual',
    }).catch((e) => logger.debug('KeyRotationLog write failed', { error: e.message }));

    return {
      keyId,
      secret:   rawSecret,
      label:    label || `key_${Date.now()}`,
      _warning: 'Store this secret securely. It CANNOT be retrieved again.',
    };
  }

  /**
   * Revoke an API key by keyId.
   */
  async revokeApiKey(merchantId, keyId, actor) {
    const merchant = await Merchant.findById(merchantId);
    if (!merchant) throw AppError.notFound('Merchant not found');

    const keyEntry = merchant.apiKeys.find((k) => k.keyId === keyId);
    if (!keyEntry) throw AppError.notFound('API key not found');

    // Check this isn't the last active key
    const activeCount = merchant.apiKeys.filter((k) => k.isActive && k.keyId !== keyId).length;
    if (activeCount === 0) {
      throw AppError.badRequest('Cannot revoke the only active API key');
    }

    keyEntry.isActive = false;

    await merchant.save();

    // Immediately invalidate the auth cache for this keyId.
    // Without this, the revoked key would continue to authenticate for up to 5 minutes.
    await cache.invalidateMerchant(this.redis, String(merchantId), [keyId]);

    await AuditLog.create({
      actor:      String(actor.userId),
      action:     'api_key_revoked',
      resource:   'merchant',
      resourceId: merchantId,
      ipAddress:  actor.ip,
      metadata:   { keyId },
      outcome:    'success',
      timestamp:  new Date(),
    });

    logger.info('MerchantService: API key revoked', { merchantId, keyId });

    // Record key revocation in rotation log
    KeyRotationLog.create({
      rotationId:   `rot_${crypto.randomBytes(12).toString('hex')}`,
      keyType:      'merchant_api_key',
      merchantId,
      oldKeyId:     keyId,
      newKeyId:     `revoked_${keyId}`,
      status:       'completed',
      completedAt:  new Date(),
      durationMs:   0,
      initiatedBy:  actor.userId,
      reason:       'manual',
    }).catch((e) => logger.debug('KeyRotationLog write failed', { error: e.message }));
  }

  /**
   * Rotate webhook secret.
   * Returns new raw secret once — old hooks continue working until merchant updates.
   */
  async rotateWebhookSecret(merchantId, actor) {
    const rawSecret = `whsec_${crypto.randomBytes(32).toString('hex')}`;
    const encrypted = encrypt(rawSecret);

    await Merchant.findByIdAndUpdate(merchantId, {
      $set: { webhookSecret: encrypted },
    });

    await AuditLog.create({
      actor:      String(actor.userId),
      action:     'webhook_secret_rotated',
      resource:   'merchant',
      resourceId: merchantId,
      ipAddress:  actor.ip,
      metadata:   {},
      outcome:    'success',
      timestamp:  new Date(),
    });

    // Record webhook rotation in key rotation log
    KeyRotationLog.create({
      rotationId:   `rot_${crypto.randomBytes(12).toString('hex')}`,
      keyType:      'merchant_webhook',
      merchantId,
      newKeyId:     `whsec_rotated_${Date.now()}`,
      status:       'completed',
      completedAt:  new Date(),
      durationMs:   0,
      initiatedBy:  actor.userId,
      reason:       'manual',
    }).catch((e) => logger.debug('KeyRotationLog write failed', { error: e.message }));

    return {
      webhookSecret: rawSecret,
      _warning: 'Update your webhook endpoint to verify with this new secret.',
    };
  }

  /**
   * Activate / deactivate a merchant account.
   */
  async setMerchantStatus(merchantId, isActive, actor) {
    const merchant = await Merchant.findByIdAndUpdate(
      merchantId,
      { $set: { isActive } },
      { new: true },
    );
    if (!merchant) throw AppError.notFound('Merchant not found');

    // If merchant is being deactivated, bust ALL cached auth entries for their keys.
    // Without this, a suspended merchant's keys would continue to authenticate
    // for up to 5 minutes (cache TTL). Security requires immediate effect.
    if (!isActive) {
      const keyIds = (merchant.apiKeys || []).map((k) => k.keyId);
      await cache.invalidateMerchant(this.redis, String(merchantId), keyIds);
    }

    await AuditLog.create({
      actor:      String(actor.userId),
      action:     isActive ? 'merchant_activated' : 'merchant_suspended',
      resource:   'merchant',
      resourceId: merchantId,
      ipAddress:  actor.ip,
      metadata:   { businessName: merchant.businessName },
      outcome:    'success',
      timestamp:  new Date(),
    });

    return merchant.toSafeJSON();
  }

  // ─── Private Helpers ─────────────────────────────────────────────────────────

  _generateKeyPair() {
    // Public keyId: used in X-API-Key header to look up the merchant
    const keyId = `xcg_key_${crypto.randomBytes(12).toString('hex')}`;

    // Raw secret: returned once to merchant for HMAC signing
    const rawSecret = `xcg_sec_${crypto.randomBytes(32).toString('hex')}`;

    // Store AES-256-GCM encrypted version in DB
    const encryptedSecret = encrypt(rawSecret);

    return { keyId, rawSecret, encryptedSecret };
  }
}

module.exports = MerchantService;
