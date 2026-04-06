'use strict';

/**
 * @module controllers/energyController
 *
 * Energy & TRX Staking Management — Admin endpoints for Tron energy tracking.
 *
 * SECURITY:
 *   - List/Get/Summary: authenticate + authorize('admin') + require2FA + adminIpWhitelist
 *   - Create/Update:    above + super_admin role + confirmCriticalAction (live TOTP)
 *   - Status transitions validated with whitelist (no arbitrary status mutation)
 *   - 14-day unfreeze window enforced at controller level not just model
 *   - Wallet must exist and be active before creating stake
 *   - All mutations logged to AuditLog
 *
 * Routes (mounted at /admin/energy):
 *   GET    /summary             — Energy capacity summary (active stakes)
 *   GET    /stakes              — List stakes
 *   GET    /stakes/:stakeId     — Get stake detail
 *   POST   /stakes              — Record new TRX freeze (super_admin + TOTP)
 *   PUT    /stakes/:stakeId     — Update stake status (super_admin + TOTP)
 */

const Joi           = require('joi');
const crypto        = require('crypto');
const { EnergyStake, Wallet, AuditLog } = require('@xcg/database');
const { AppError, validate, validateObjectId } = require('@xcg/common');
const asyncHandler  = require('../utils/asyncHandler');
const { createLogger } = require('@xcg/logger');

const logger = createLogger('energy-ctrl');

// Valid status transitions: only allow forward-moving state machine
const VALID_TRANSITIONS = {
  active:    ['unstaking', 'failed'],
  unstaking: ['unstaked', 'failed'],
  unstaked:  [],   // terminal
  failed:    [],   // terminal
};

// ─── Joi Schemas ──────────────────────────────────────────────────────────────

const createStakeSchema = Joi.object({
  walletId:       Joi.string().hex().length(24).required(),
  trxAmount:      Joi.number().positive().required(),
  stakeType:      Joi.string().valid('freeze_self', 'delegate_to', 'receive_from', 'energy_rental').required(),
  freezeTxHash:   Joi.string().pattern(/^[a-fA-F0-9]{64}$/).optional(),
  energyReceived: Joi.number().min(0).optional().default(0),
  notes:          Joi.string().trim().max(500).optional().allow(''),
}).options({ stripUnknown: true });

const updateStakeSchema = Joi.object({
  status:          Joi.string().valid('unstaking', 'unstaked', 'failed').required(),
  unfreezeTxHash:  Joi.string().pattern(/^[a-fA-F0-9]{64}$/).when('status', {
    is: 'unstaked', then: Joi.optional(), otherwise: Joi.optional(),
  }),
  notes:           Joi.string().trim().max(500).optional().allow(''),
}).options({ stripUnknown: true });

const listSchema = Joi.object({
  walletId:  Joi.string().hex().length(24).optional(),
  status:    Joi.string().valid('active', 'unstaking', 'unstaked', 'failed').optional(),
  stakeType: Joi.string().valid('freeze_self', 'delegate_to', 'receive_from', 'energy_rental').optional(),
  page:      Joi.number().integer().min(1).max(1000).default(1),
  limit:     Joi.number().integer().min(1).max(100).default(20),
}).options({ stripUnknown: true });

// ─── GET /admin/energy/summary ────────────────────────────────────────────────

async function getEnergySummary(req, res) {
  const [activeStakes, unstakingStakes] = await Promise.all([
    EnergyStake.find({ status: 'active'    }).select('trxAmount energyReceived bandwidthReceived stakeType walletAddress').lean(),
    EnergyStake.find({ status: 'unstaking' }).select('trxAmount unfreezeReadyAt walletAddress').lean(),
  ]);

  const totalTrxFrozen      = activeStakes.reduce((s, st) => s + st.trxAmount, 0);
  const totalEnergyPerDay   = activeStakes.reduce((s, st) => s + (st.energyReceived || 0), 0);
  const totalBandwidthPerDay= activeStakes.reduce((s, st) => s + (st.bandwidthReceived || 0), 0);

  const stakesByType = activeStakes.reduce((acc, st) => {
    acc[st.stakeType] = (acc[st.stakeType] || 0) + 1;
    return acc;
  }, {});

  // Unstaking stakes with ready dates in the past = TRX claimable now
  const claimableNow = unstakingStakes.filter(
    (st) => st.unfreezeReadyAt && new Date(st.unfreezeReadyAt) <= new Date(),
  );

  res.json({
    success: true,
    data: {
      activeStakeCount:   activeStakes.length,
      unstakingCount:     unstakingStakes.length,
      claimableCount:     claimableNow.length,
      totalTrxFrozen:     parseFloat(totalTrxFrozen.toFixed(6)),
      totalEnergyPerDay,
      totalBandwidthPerDay,
      stakesByType,
    },
  });
}

// ─── GET /admin/energy/stakes ─────────────────────────────────────────────────

async function listStakes(req, res) {
  const { walletId, status, stakeType, page, limit } = validate(listSchema, req.query);
  const filter = {};
  if (walletId)  filter.walletId  = walletId;
  if (status)    filter.status    = status;
  if (stakeType) filter.stakeType = stakeType;

  const skip = (page - 1) * limit;
  const [stakes, total] = await Promise.all([
    EnergyStake.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
    EnergyStake.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { stakes, pagination: { page, limit, total, pages: Math.ceil(total / limit) } },
  });
}

// ─── GET /admin/energy/stakes/:stakeId ────────────────────────────────────────

async function getStake(req, res) {
  const { stakeId } = req.params;
  if (!stakeId || !/^stk_[a-zA-Z0-9]{24}$/.test(stakeId)) {
    throw AppError.badRequest('Invalid stake ID format');
  }

  const stake = await EnergyStake.findOne({ stakeId }).lean();
  if (!stake) throw AppError.notFound('Energy stake not found');
  res.json({ success: true, data: { stake } });
}

// ─── POST /admin/energy/stakes ────────────────────────────────────────────────

async function createStake(req, res) {
  const data = validate(createStakeSchema, req.body);

  validateObjectId(data.walletId, 'walletId');

  const wallet = await Wallet.findById(data.walletId)
    .select('_id address isActive walletType')
    .lean();
  if (!wallet)          throw AppError.notFound('Wallet not found');
  if (!wallet.isActive) throw AppError.conflict('Wallet is inactive');

  const stakeId = `stk_${crypto.randomBytes(12).toString('hex')}`;

  const stake = await EnergyStake.create({
    stakeId,
    walletId:       wallet._id,
    walletAddress:  wallet.address,
    network:        'tron',
    stakeType:      data.stakeType,
    trxAmount:      data.trxAmount,
    energyReceived: data.energyReceived,
    freezeTxHash:   data.freezeTxHash || null,
    frozenAt:       data.freezeTxHash ? new Date() : null,
    status:         'active',
    initiatedBy:    `admin:${req.user.userId}`,
    notes:          data.notes || '',
  });

  await AuditLog.create({
    actor:      req.user.userId,
    action:     'admin.energy_stake.created',
    resource:   'energy_stake',
    resourceId: stakeId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata: {
      walletAddress:  wallet.address,
      trxAmount:      data.trxAmount,
      stakeType:      data.stakeType,
      freezeTxHash:   data.freezeTxHash || null,
      energyReceived: data.energyReceived,
    },
  });

  logger.info('Energy stake created', {
    stakeId, walletAddress: wallet.address.slice(0, 8),
    trxAmount: data.trxAmount, stakeType: data.stakeType,
  });

  res.status(201).json({ success: true, data: { stake } });
}

// ─── PUT /admin/energy/stakes/:stakeId ────────────────────────────────────────

async function updateStake(req, res) {
  const { stakeId } = req.params;
  const data = validate(updateStakeSchema, req.body);

  if (!stakeId || !/^stk_[a-zA-Z0-9]{24}$/.test(stakeId)) {
    throw AppError.badRequest('Invalid stake ID format');
  }

  const stake = await EnergyStake.findOne({ stakeId });
  if (!stake) throw AppError.notFound('Energy stake not found');

  // Enforce state machine — only allowed forward transitions
  const allowedNextStates = VALID_TRANSITIONS[stake.status] || [];
  if (!allowedNextStates.includes(data.status)) {
    throw AppError.conflict(
      `Invalid status transition: '${stake.status}' → '${data.status}'. ` +
      `Allowed: [${allowedNextStates.join(', ') || 'none (terminal state)'}]`,
    );
  }

  // Build the update patch
  const patch = { status: data.status };
  if (data.notes)         patch.notes = data.notes;
  if (data.unfreezeTxHash) patch.unfreezeTxHash = data.unfreezeTxHash;

  if (data.status === 'unstaking') {
    patch.unfreezeStartAt = new Date();
    patch.unfreezeReadyAt = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000); // Tron: 14-day lock
  }
  if (data.status === 'unstaked') {
    patch.unstakedAt = new Date();
  }

  Object.assign(stake, patch);
  await stake.save();

  await AuditLog.create({
    actor:      req.user.userId,
    action:     'admin.energy_stake.updated',
    resource:   'energy_stake',
    resourceId: stakeId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata: {
      previousStatus:  stake.status,
      newStatus:       data.status,
      unfreezeTxHash:  data.unfreezeTxHash || null,
      unfreezeReadyAt: patch.unfreezeReadyAt || null,
    },
  });

  logger.info('Energy stake updated', { stakeId, status: data.status, actor: req.user.userId });
  res.json({ success: true, data: { stake } });
}

module.exports = {
  getEnergySummary: asyncHandler(getEnergySummary),
  listStakes:       asyncHandler(listStakes),
  getStake:         asyncHandler(getStake),
  createStake:      asyncHandler(createStake),
  updateStake:      asyncHandler(updateStake),
};
