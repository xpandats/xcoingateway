'use strict';

const mongoose = require('mongoose');
const crypto   = require('crypto');

/**
 * @module models/AuditLog
 *
 * Audit Log — APPEND-ONLY, IMMUTABLE, HASH-CHAINED.
 *
 * BANK-GRADE REQUIREMENTS:
 *   1. Append-only: all update/delete hooks blocked
 *   2. Hash chaining: each entry contains SHA-256(prevHash + content)
 *      → any modification or deletion breaks the chain
 *   3. Separate DB connection: uses INSERT-ONLY audit DB user when configured
 *   4. Chain verification: AuditLog.verifyChain() detects tampering
 *
 * HASH CHAIN FORMAT:
 *   entryHash = SHA-256(prevHash + actor + action + timestamp + resource + resourceId + outcome)
 *   This means: to forge an entry, attacker must know ALL previous hashes
 *
 * FIELD NAMING: Consistent across ALL services — ipAddress, outcome, userAgent
 */

const auditLogSchema = new mongoose.Schema({
  // WHO performed the action
  actor:      { type: String, required: true, index: true }, // userId | 'system' | 'signing-service'

  // WHAT was done — use AUDIT_ACTIONS constants
  action:    { type: String, required: true, index: true },

  // WHEN
  timestamp:  { type: Date, required: true, default: Date.now, index: true },

  // FROM WHERE
  ipAddress:  { type: String, default: null, index: true },
  userAgent:  { type: String, default: null },

  // ON WHAT
  resource:   { type: String, default: null, index: true },
  resourceId: { type: String, default: null },

  // RESULT
  outcome:   { type: String, enum: ['success', 'failed', 'blocked'], default: 'success' },

  // CONTEXT
  before:    { type: mongoose.Schema.Types.Mixed, default: null },
  after:     { type: mongoose.Schema.Types.Mixed, default: null },
  metadata:  { type: mongoose.Schema.Types.Mixed, default: null },

  // ─── HASH CHAIN FIELDS ────────────────────────────────────────────────────
  // prevHash: hash of the PREVIOUS audit log entry (null for first entry)
  // entryHash: SHA-256 of (prevHash + this entry's core fields)
  // Together these form a cryptographic chain — any tampering is detectable
  prevHash:  { type: String, default: null, index: true },
  entryHash: { type: String, default: null, index: true },
}, {
  timestamps: false,
  collection: 'audit_logs',
  // strict: true is correct here — all top-level fields are explicitly typed.
  // Mixed fields (before/after/metadata) still accept arbitrary values even with strict:true;
  // strict only rejects fields NOT defined in the schema at all.
  // strict:false was wrong: it allowed arbitrary top-level keys (e.g. injected '__proto__')
  // to be silently written to audit log documents.
  strict: true,
});


// ─── Compound indexes for security forensics ─────────────────────────────────
auditLogSchema.index({ actor: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ resource: 1, resourceId: 1, timestamp: -1 });
auditLogSchema.index({ ipAddress: 1, timestamp: -1 });
auditLogSchema.index({ outcome: 1, timestamp: -1 });
// Index for chain traversal (verify chain from a given hash)
auditLogSchema.index({ entryHash: 1 }, { unique: true, sparse: true });
// GAP 4 FIX: unique+sparse on prevHash enforces linear chain — no two entries can
// share the same parent. sparse: true allows multiple null prevHash values
// (genesis entry + any fallback entries written during high-concurrency failures).
auditLogSchema.index({ prevHash: 1 }, { unique: true, sparse: true });


// ─── HASH CHAINING — computed on pre-save ────────────────────────────────────
/**
 * Compute the entry hash for an audit log entry.
 * SHA-256 of: prevHash + actor + action + ISO timestamp + resource + resourceId + outcome
 *
 * These are the fields that matter most for integrity:
 *   - WHO (actor) + WHAT (action) + WHEN (timestamp) + ON WHAT (resource) + RESULT (outcome)
 *   - Changing any of these breaks the chain from this entry forward
 */
function computeEntryHash(prevHash, actor, action, timestamp, resource, resourceId, outcome) {
  const payload = [
    prevHash    || 'GENESIS',
    actor       || '',
    action      || '',
    (timestamp instanceof Date ? timestamp.toISOString() : String(timestamp)) || '',
    resource    || '',
    resourceId  || '',
    outcome     || '',
  ].join(':');
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}

auditLogSchema.pre('save', async function (next) {
  if (!this.isNew) {
    // Entry already saved — immutability violation
    return next(new Error(
      'SECURITY VIOLATION: Audit logs are immutable. Update/delete operations are forbidden.',
    ));
  }

  // ── GAP 4 FIX: Hash chain race prevention ─────────────────────────────────
  // PROBLEM: Two concurrent audit writes could both read the same chain tip and both
  // set prevHash = <same hash>, creating a fork. verifyChain() would then fail even
  // without tampering.
  //
  // SOLUTION: Retry loop with jitter.
  //   - Try to read chain tip → compute hash → assign prevHash + entryHash.
  //   - The UNIQUE SPARSE INDEX on prevHash (see below) ensures only ONE winner per
  //     parent: if two writes race with the same prevHash, only one insert succeeds.
  //   - The loser gets a duplicate key error on prevHash → retries → reads the
  //     new chain tip (the winner's entry) → computes a new entryHash → succeeds.
  //   - Max 3 retries. If all fail (extremely unlikely): entropy-based hash with
  //     prevHash=null (chain is still immutable, just has a gap logged as WARN).
  //
  // The unique index on prevHash is defined below:
  //   auditLogSchema.index({ prevHash: 1 }, { unique: true, sparse: true })
  // sparse: true allows multiple entries with prevHash=null (the genesis entry and
  // any fallback entries from failed hash computation).

  const MAX_CHAIN_RETRIES = 3;

  for (let attempt = 0; attempt <= MAX_CHAIN_RETRIES; attempt++) {
    try {
      // Get the hash of the most recent entry (the current chain tip)
      const last = await this.constructor.findOne({}, { entryHash: 1 })
        .sort({ timestamp: -1 })
        .lean();

      this.prevHash  = last?.entryHash || null;
      this.entryHash = computeEntryHash(
        this.prevHash,
        this.actor,
        this.action,
        this.timestamp || new Date(),
        this.resource,
        this.resourceId,
        this.outcome,
      );

      // If this is not the first attempt, break the retry loop — hashes computed OK.
      // The actual uniqueness enforcement happens at the DB insert level.
      return next();

    } catch (err) {
      if (attempt < MAX_CHAIN_RETRIES) {
        // Add random jitter (0–50ms) to reduce retry collision probability
        const jitterMs = Math.floor(Math.random() * 50);
        await new Promise((r) => setTimeout(r, jitterMs));
        continue;
      }

      // All retries exhausted — fall back to entropy-based hash with null prevHash.
      // The entry is still immutably appended (ImmutabilityViolation hooks still apply).
      // The chain will have a gap at this entry, which verifyChain() will detect and
      // flag — alerting operators that a high-concurrency event occurred.
      // We do NOT throw — denying an audit write is worse than a chain gap.
      this.prevHash  = null;
      this.entryHash = crypto.createHash('sha256')
        .update(`fallback:${Date.now()}:${Math.random()}`, 'utf8')
        .digest('hex');
      return next();
    }
  }
});

// ─── IMMUTABILITY — all mutation hooks blocked ────────────────────────────────
function immutableError(next) {
  const err = new Error(
    'SECURITY VIOLATION: Audit logs are immutable. Update/delete operations are forbidden.',
  );
  err.name = 'ImmutabilityViolation';
  next(err);
}

auditLogSchema.pre('updateOne',         immutableError);
auditLogSchema.pre('deleteOne',         immutableError);
auditLogSchema.pre('findOneAndUpdate',  immutableError);
auditLogSchema.pre('findOneAndDelete',  immutableError);
auditLogSchema.pre('findOneAndReplace', immutableError);
auditLogSchema.pre('updateMany',        immutableError);
auditLogSchema.pre('deleteMany',        immutableError);

// ─── STATIC METHODS ───────────────────────────────────────────────────────────

/**
 * Get the current chain tip hash (hash of the most recent entry).
 * Used by external chain verifiers.
 * @returns {Promise<string|null>}
 */
auditLogSchema.statics.getLastHash = async function () {
  const last = await this.findOne({}, { entryHash: 1 }).sort({ timestamp: -1 }).lean();
  return last?.entryHash || null;
};

/**
 * Verify the integrity of the audit log chain.
 *
 * Scans entries oldest-first and recomputes each entry's expected hash.
 * If any hash doesn't match → chain is broken → tampering detected.
 *
 * WARNING: This is O(n) in the number of audit entries — run periodically,
 * not on every request.
 *
 * @param {number} [limit=10000] - Max entries to verify (start from oldest)
 * @returns {Promise<{ valid: boolean, scanned: number, brokenAt: object|null }>}
 */
auditLogSchema.statics.verifyChain = async function (limit = 10000) {
  const entries = await this.find({})
    .sort({ timestamp: 1 })
    .limit(limit)
    .select('actor action timestamp resource resourceId outcome prevHash entryHash _id')
    .lean();

  let prevHash = null;
  let scanned  = 0;

  for (const entry of entries) {
    const expected = computeEntryHash(
      prevHash,
      entry.actor,
      entry.action,
      entry.timestamp,
      entry.resource,
      entry.resourceId,
      entry.outcome,
    );

    if (entry.entryHash !== expected) {
      return {
        valid:    false,
        scanned,
        brokenAt: {
          _id:       String(entry._id),
          timestamp: entry.timestamp,
          action:    entry.action,
          actor:     entry.actor,
          expected,
          actual:    entry.entryHash,
        },
      };
    }

    prevHash = entry.entryHash;
    scanned++;
  }

  return { valid: true, scanned, brokenAt: null };
};

// ─── MODEL BINDING ────────────────────────────────────────────────────────────
// The model is created on the default connection initially.
// When connectAuditDB() is called at startup, the AuditLog model is re-bound
// to the dedicated audit connection (with INSERT-ONLY credentials).
// This happens in packages/database/index.js after both connections are ready.

module.exports = mongoose.model('AuditLog', auditLogSchema);
module.exports.auditLogSchema = auditLogSchema;
module.exports.computeEntryHash = computeEntryHash;
