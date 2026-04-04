#!/usr/bin/env node
'use strict';

/**
 * @module scripts/backup/mongoBackup
 *
 * Automated MongoDB Backup — Mainnet Requirement #5.
 *
 * BANK-GRADE REQUIREMENTS:
 *   1. Creates a mongodump archive of the full database
 *   2. Encrypts the archive using AES-256-GCM before storage
 *   3. Rotates old backups (deletes backups older than RETENTION_DAYS)
 *   4. Logs every backup run to console + optional log file
 *   5. Exits with code 1 on failure (allows cron/scheduler to alert)
 *
 * SETUP — Run daily via cron:
 *   0 2 * * * /usr/bin/node /app/scripts/backup/mongoBackup.js >> /var/log/xcg-backup.log 2>&1
 *
 * Or via Docker/PM2 ecosystem task (recommended for production):
 *   Schedule as a separate process — never the main API server process.
 *
 * ENV VARS REQUIRED:
 *   MONGODB_URI              — Main database URI for mongodump
 *   BACKUP_ENCRYPTION_KEY    — 64 hex chars (32 bytes) for backup encryption
 *   BACKUP_DIR               — Directory to store backup files (default: ./backups)
 *   BACKUP_RETENTION_DAYS    — Days to keep backups (default: 30)
 *
 * RECOVERY:
 *   1. node scripts/backup/mongoRestore.js --file backup_2026-04-05.archive.enc
 *   2. Decrypts the archive
 *   3. Runs mongorestore
 */

const { execSync, spawnSync } = require('child_process');
const crypto   = require('crypto');
const fs       = require('fs');
const path     = require('path');

// ─── Config ───────────────────────────────────────────────────────────────────

const MONGODB_URI      = process.env.MONGODB_URI;
const BACKUP_ENC_KEY   = process.env.BACKUP_ENCRYPTION_KEY;
const BACKUP_DIR       = process.env.BACKUP_DIR || path.join(process.cwd(), 'backups');
const RETENTION_DAYS   = parseInt(process.env.BACKUP_RETENTION_DAYS || '30', 10);
const AUDIT_LOG_URI    = process.env.AUDIT_MONGODB_URI || MONGODB_URI;

const IV_LENGTH      = 16;
const AUTH_TAG_LEN   = 16;

// ─── Validation ───────────────────────────────────────────────────────────────

function validate() {
  if (!MONGODB_URI) {
    fatal('BACKUP FAILED: MONGODB_URI is not set');
  }
  if (!BACKUP_ENC_KEY || BACKUP_ENC_KEY.length !== 64) {
    fatal('BACKUP FAILED: BACKUP_ENCRYPTION_KEY must be 64 hex characters (32 bytes). Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
  }

  // Check mongodump is available
  const result = spawnSync('mongodump', ['--version'], { encoding: 'utf8' });
  if (result.error) {
    fatal('BACKUP FAILED: mongodump not found. Install MongoDB Database Tools.');
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function log(msg, obj = '') {
  const ts = new Date().toISOString();
  console.log(`[${ts}] BACKUP: ${msg}`, obj ? JSON.stringify(obj) : '');
}

function fatal(msg) {
  console.error(`[${new Date().toISOString()}] BACKUP FATAL: ${msg}`);
  process.exit(1);
}

function encryptFile(inputPath, outputPath) {
  const key = Buffer.from(BACKUP_ENC_KEY, 'hex');
  const iv  = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, {
    authTagLength: AUTH_TAG_LEN,
  });

  const input  = fs.readFileSync(inputPath);
  const encrypted = Buffer.concat([cipher.update(input), cipher.final()]);
  const authTag   = cipher.getAuthTag();

  // Format: iv (16 bytes) + authTag (16 bytes) + ciphertext
  const output = Buffer.concat([iv, authTag, encrypted]);
  fs.writeFileSync(outputPath, output);

  // Zero sensitive data
  key.fill(0);
  iv.fill(0);

  return { sizeBytes: output.length };
}

function rotateOldBackups() {
  const files = fs.readdirSync(BACKUP_DIR);
  const cutoff = Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000;
  let rotated = 0;

  for (const file of files) {
    if (!file.endsWith('.archive.enc')) continue;
    const filePath = path.join(BACKUP_DIR, file);
    const stat = fs.statSync(filePath);
    if (stat.mtimeMs < cutoff) {
      fs.unlinkSync(filePath);
      log(`Rotated old backup: ${file}`);
      rotated++;
    }
  }

  return rotated;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  log('Starting backup run');

  validate();

  // Ensure backup directory exists
  if (!fs.existsSync(BACKUP_DIR)) {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    log(`Created backup directory: ${BACKUP_DIR}`);
  }

  const dateStr     = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const archiveName = `xcg_backup_${dateStr}.archive`;
  const archivePath = path.join(BACKUP_DIR, archiveName);
  const encPath     = archivePath + '.enc';

  // ── Step 1: Run mongodump ──────────────────────────────────────────────────
  log('Running mongodump...');

  const dumpResult = spawnSync('mongodump', [
    `--uri=${MONGODB_URI}`,
    `--archive=${archivePath}`,
    '--gzip',
  ], {
    encoding: 'utf8',
    timeout:  10 * 60 * 1000, // 10 minute timeout
  });

  if (dumpResult.status !== 0) {
    // Clean up partial file
    if (fs.existsSync(archivePath)) fs.unlinkSync(archivePath);
    fatal(`mongodump failed: ${dumpResult.stderr || dumpResult.error?.message}`);
  }

  const archiveStat = fs.statSync(archivePath);
  log(`mongodump complete`, { sizeBytes: archiveStat.size });

  // ── Step 2: Also dump audit DB if separate ────────────────────────────────
  if (process.env.AUDIT_MONGODB_URI) {
    const auditArchiveName = `xcg_audit_backup_${dateStr}.archive`;
    const auditArchivePath = path.join(BACKUP_DIR, auditArchiveName);

    log('Running mongodump for audit DB...');
    const auditResult = spawnSync('mongodump', [
      `--uri=${AUDIT_LOG_URI}`,
      `--archive=${auditArchivePath}`,
      '--gzip',
    ], { encoding: 'utf8', timeout: 5 * 60 * 1000 });

    if (auditResult.status === 0) {
      const { sizeBytes } = encryptFile(auditArchivePath, auditArchivePath + '.enc');
      fs.unlinkSync(auditArchivePath);
      log('Audit DB backup encrypted', { sizeBytes });
    } else {
      log(`WARNING: Audit DB backup failed: ${auditResult.stderr}`);
    }
  }

  // ── Step 3: Encrypt the archive ───────────────────────────────────────────
  log('Encrypting backup archive...');
  const { sizeBytes: encSize } = encryptFile(archivePath, encPath);

  // Delete unencrypted archive immediately
  fs.unlinkSync(archivePath);
  log(`Backup encrypted`, { encPath, sizeBytes: encSize });

  // ── Step 4: Verify encrypted file exists and is non-empty ────────────────
  const encStat = fs.statSync(encPath);
  if (encStat.size < 100) {
    fatal(`Encrypted backup file is suspiciously small (${encStat.size} bytes) — aborting`);
  }

  // ── Step 5: Rotate old backups ────────────────────────────────────────────
  const rotated = rotateOldBackups();

  log('Backup completed successfully', {
    archiveFile:    path.basename(encPath),
    encryptedBytes: encSize,
    retentionDays:  RETENTION_DAYS,
    rotatedFiles:   rotated,
  });

  console.log(`BACKUP_SUCCESS file=${encPath} size=${encSize}`);
  process.exit(0);
}

main().catch((err) => fatal(`Unexpected error: ${err.message}`));
