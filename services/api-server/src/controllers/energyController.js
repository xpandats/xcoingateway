'use strict';

/**
 * @module controllers/energyController
 *
 * Energy & Staking Management — Admin endpoints for TRX freeze/unfreeze tracking.
 *
 * Routes (mounted at /admin/energy):
 *   GET    /stakes              — List all energy stakes
 *   GET    /stakes/:stakeId     — Get stake detail
 *   POST   /stakes              — Record new TRX freeze (TOTP)
 *   PUT    /stakes/:stakeId     — Update stake status (TOTP)
 *   GET    /summary             — Energy capacity summary across all wallets
 */

const { v4: uuidv4 } = require('uuid');
const { EnergyStake, Wallet, AuditLog } = require('@xcg/database');
const { AppError } = require('@xcg/common');
const asyncHandler = require('../utils/asyncHandler');
const logger = require('@xcg/logger').createLogger('energy-ctrl');

// ─── GET /admin/energy/stakes ─────────────────────────────────────────────────

async function listStakes(req, res) {
  const { walletId, status, stakeType, page = 1, limit = 20 } = req.query;
  const filter = {};
  if (walletId)   filter.walletId = walletId;
  if (status)     filter.status = status;
  if (stakeType)  filter.stakeType = stakeType;

  const skip = (Math.max(1, parseInt(page, 10)) - 1) * parseInt(limit, 10);
  const [stakes, total] = await Promise.all([
    EnergyStake.find(filter).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit, 10)).lean(),
    EnergyStake.countDocuments(filter),
  ]);

  res.json({
    success: true,
    data: { stakes, pagination: { page: parseInt(page, 10), limit: parseInt(limit, 10), total, pages: Math.ceil(total / parseInt(limit, 10)) } },
  });
}

// ─── GET /admin/energy/stakes/:stakeId ────────────────────────────────────────

async function getStake(req, res) {
  const stake = await EnergyStake.findOne({ stakeId: req.params.stakeId }).lean();
  if (!stake) throw AppError.notFound('Energy stake not found');
  res.json({ success: true, data: stake });
}

// ─── POST /admin/energy/stakes ────────────────────────────────────────────────

async function createStake(req, res) {
  const { walletId, trxAmount, stakeType, freezeTxHash, energyReceived, notes } = req.body;

  if (!walletId || !trxAmount || !stakeType) {
    throw AppError.badRequest('walletId, trxAmount, and stakeType are required');
  }

  const wallet = await Wallet.findById(walletId).select('_id address isActive').lean();
  if (!wallet) throw AppError.notFound('Wallet not found');

  const stake = await EnergyStake.create({
    stakeId:         `stk_${uuidv4().replace(/-/g, '').slice(0, 24)}`,
    walletId,
    walletAddress:   wallet.address,
    network:         'tron',
    stakeType,
    trxAmount,
    energyReceived:  energyReceived || 0,
    freezeTxHash:    freezeTxHash || null,
    frozenAt:        freezeTxHash ? new Date() : null,
    status:          'active',
    initiatedBy:     `admin:${req.user._id}`,
    notes:           notes || '',
  });

  await AuditLog.create({
    actor:      req.user.userId || String(req.user._id),
    action:     'admin.energy_stake_created',
    resource:   'energy_stake',
    resourceId: stake.stakeId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { walletAddress: wallet.address, trxAmount, stakeType },
  });

  logger.info('Energy stake created', { stakeId: stake.stakeId, walletAddress: wallet.address, trxAmount });
  res.status(201).json({ success: true, data: stake });
}

// ─── PUT /admin/energy/stakes/:stakeId ────────────────────────────────────────

async function updateStake(req, res) {
  const { stakeId } = req.params;
  const { status, unfreezeTxHash, notes } = req.body;

  if (!status) throw AppError.badRequest('status is required');

  const validStatuses = ['active', 'unstaking', 'unstaked', 'failed'];
  if (!validStatuses.includes(status)) {
    throw AppError.badRequest(`Invalid status. Must be: ${validStatuses.join(', ')}`);
  }

  const update = { status };
  if (status === 'unstaking') {
    update.unfreezeStartAt = new Date();
    update.unfreezeReadyAt = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000); // 14 days
  }
  if (status === 'unstaked') update.unstakedAt = new Date();
  if (unfreezeTxHash) update.unfreezeTxHash = unfreezeTxHash;
  if (notes) update.notes = notes;

  const stake = await EnergyStake.findOneAndUpdate(
    { stakeId },
    { $set: update },
    { new: true },
  );

  if (!stake) throw AppError.notFound('Energy stake not found');

  await AuditLog.create({
    actor:      req.user.userId || String(req.user._id),
    action:     'admin.energy_stake_updated',
    resource:   'energy_stake',
    resourceId: stakeId,
    ipAddress:  req.ip,
    outcome:    'success',
    timestamp:  new Date(),
    metadata:   { newStatus: status, unfreezeTxHash },
  });

  logger.info('Energy stake updated', { stakeId, status });
  res.json({ success: true, data: stake });
}

// ─── GET /admin/energy/summary ────────────────────────────────────────────────

async function getEnergySummary(req, res) {
  const activeStakes = await EnergyStake.find({ status: 'active' }).lean();

  const totalTrxFrozen    = activeStakes.reduce((s, st) => s + st.trxAmount, 0);
  const totalEnergyPerDay = activeStakes.reduce((s, st) => s + (st.energyReceived || 0), 0);
  const stakesByType      = {};

  for (const s of activeStakes) {
    stakesByType[s.stakeType] = (stakesByType[s.stakeType] || 0) + 1;
  }

  res.json({
    success: true,
    data: {
      activeStakeCount: activeStakes.length,
      totalTrxFrozen,
      totalEnergyPerDay,
      stakesByType,
    },
  });
}

module.exports = {
  listStakes:      asyncHandler(listStakes),
  getStake:        asyncHandler(getStake),
  createStake:     asyncHandler(createStake),
  updateStake:     asyncHandler(updateStake),
  getEnergySummary:asyncHandler(getEnergySummary),
};
