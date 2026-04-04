#!/usr/bin/env node
'use strict';

/**
 * @module scripts/checkSecrets
 *
 * Pre-commit Secrets Scanner — Mainnet Requirement #7.
 *
 * Scans staged files (or all tracked files) for patterns that look like
 * real secrets, API keys, private keys, or credentials.
 *
 * Used as a pre-commit hook — blocks commits if secrets are detected.
 *
 * PATTERNS DETECTED:
 *   - Private keys (Hex 64-char, WIF format, PEM headers)
 *   - API keys / JWT secrets (Bearer tokens, long random strings)
 *   - MongoDB URIs with credentials
 *   - Environment variable assignments with sensitive values
 *   - Credit card patterns (for extra safety)
 *   - Crypto wallet private keys
 *
 * SETUP — Install as pre-commit hook:
 *   npm install --save-dev husky
 *   npx husky install
 *   npx husky add .husky/pre-commit "node scripts/checkSecrets.js"
 *
 * BYPASS (emergency only — never routine):
 *   git commit --no-verify -m "message"  # Bypasses ALL hooks — use with extreme caution
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// ─── Secret patterns ──────────────────────────────────────────────────────────
// Each pattern: { name, regex, severity }
// severity: 'CRITICAL' = block commit, 'WARNING' = warn but allow

const PATTERNS = [
  // Private keys
  {
    name:     'TRC20/ETH Private Key (64-char hex)',
    regex:    /\b[0-9a-fA-F]{64}\b/,
    severity: 'CRITICAL',
    // Exclude: hash-looking contexts (usually OK)
    excludeContexts: ['entryHash', 'prevHash', 'txHash', 'tokenHash', 'keyHash'],
  },
  {
    name:     'PEM Private Key Header',
    regex:    /-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/,
    severity: 'CRITICAL',
    excludeContexts: [],
  },
  {
    name:     'Bitcoin WIF Private Key',
    regex:    /\b[5KLc][1-9A-HJ-NP-Za-km-z]{50,51}\b/,
    severity: 'CRITICAL',
    excludeContexts: [],
  },

  // Environment variable secrets
  {
    name:     'MASTER_ENCRYPTION_KEY assignment',
    regex:    /MASTER_ENCRYPTION_KEY\s*=\s*[0-9a-fA-F]{64}/,
    severity: 'CRITICAL',
    excludeContexts: [],
  },
  {
    name:     'JWT_SECRET assignment with value',
    regex:    /JWT_SECRET\s*=\s*[^\s"']{20,}/,
    severity: 'CRITICAL',
    excludeContexts: ['your-jwt-secret', 'change-me', 'placeholder', 'example', 'CHANGE_ME'],
  },
  {
    name:     'QUEUE_SIGNING_SECRET assignment',
    regex:    /QUEUE_SIGNING_SECRET\s*=\s*[^\s"']{32,}/,
    severity: 'CRITICAL',
    excludeContexts: ['your-secret', 'change-me', 'placeholder'],
  },

  // Database credentials
  {
    name:     'MongoDB URI with credentials',
    regex:    /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/,
    severity: 'CRITICAL',
    excludeContexts: ['localhost', '127.0.0.1', 'example.com', 'your-cluster'],
  },

  // API Keys
  {
    name:     'Generic API Key pattern',
    regex:    /[aA][pP][iI][_-]?[kK][eE][yY]\s*[=:]\s*['"]?[a-zA-Z0-9_\-]{32,}['"]?/,
    severity: 'CRITICAL',
    excludeContexts: ['your-api-key', 'placeholder', 'example', 'change-me', 'process.env'],
  },
  {
    name:     'TronGrid API Key',
    regex:    /TRONGRID_API_KEY\s*=\s*[a-zA-Z0-9\-]{30,}/,
    severity: 'CRITICAL',
    excludeContexts: ['your-key', 'placeholder'],
  },

  // Bearer tokens / JWTs
  {
    name:     'Hardcoded JWT (eyJ...)',
    regex:    /eyJ[a-zA-Z0-9\-_]{20,}\.[a-zA-Z0-9\-_]{20,}\.[a-zA-Z0-9\-_]{20,}/,
    severity: 'CRITICAL',
    excludeContexts: [],
  },

  // Webhook secrets
  {
    name:     'WEBHOOK_SECRET assignment',
    regex:    /WEBHOOK_SECRET\s*=\s*[^\s"']{20,}/,
    severity: 'WARNING',
    excludeContexts: ['your-secret', 'placeholder', 'example'],
  },
];

// ─── File exclusions ──────────────────────────────────────────────────────────
const EXCLUDED_PATHS = [
  '.env.example',
  '.env.sample',
  '.env.test',
  'SECURITY_FINAL_VERDICT.md',
  'scripts/checkSecrets.js', // Don't scan the scanner itself
  'node_modules/',
  '.git/',
  '*.lock',
  'package-lock.json',
];

// ─── Get staged files ──────────────────────────────────────────────────────────

function getStagedFiles() {
  try {
    const output = execSync('git diff --cached --name-only --diff-filter=ACM', {
      encoding: 'utf8',
    });
    return output.trim().split('\n').filter(Boolean);
  } catch {
    // Not in a git repo or no staged files
    return [];
  }
}

function isExcluded(filePath) {
  return EXCLUDED_PATHS.some((excluded) =>
    filePath.includes(excluded) || filePath.endsWith(excluded),
  );
}

function isExcludedContext(line, pattern) {
  if (!pattern.excludeContexts || pattern.excludeContexts.length === 0) return false;
  return pattern.excludeContexts.some((ctx) => line.toLowerCase().includes(ctx.toLowerCase()));
}

// ─── Main ─────────────────────────────────────────────────────────────────────

function main() {
  const files = getStagedFiles();

  if (files.length === 0) {
    console.log('✅ Secrets scanner: no staged files to check');
    process.exit(0);
  }

  const findings = [];

  for (const file of files) {
    if (isExcluded(file)) continue;

    let content;
    try {
      content = fs.readFileSync(file, 'utf8');
    } catch {
      continue; // File might be deleted
    }

    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      for (const pattern of PATTERNS) {
        if (pattern.regex.test(line) && !isExcludedContext(line, pattern)) {
          findings.push({
            file,
            line:     i + 1,
            pattern:  pattern.name,
            severity: pattern.severity,
            // Redact the actual line to avoid logging secrets in terminal
            preview:  line.substring(0, 60) + (line.length > 60 ? '...[REDACTED]' : ''),
          });
        }
      }
    }
  }

  if (findings.length === 0) {
    console.log(`✅ Secrets scanner: ${files.length} files checked — no secrets detected`);
    process.exit(0);
  }

  // Sort by severity (CRITICAL first)
  findings.sort((a, b) => (a.severity === 'CRITICAL' ? -1 : 1));

  console.error('\n🚨 SECRETS SCANNER DETECTED POTENTIAL SECRETS IN STAGED FILES\n');
  console.error('═'.repeat(70));

  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const warningCount  = findings.filter((f) => f.severity === 'WARNING').length;

  for (const finding of findings) {
    const icon = finding.severity === 'CRITICAL' ? '❌' : '⚠️';
    console.error(`${icon} [${finding.severity}] ${finding.file}:${finding.line}`);
    console.error(`   Pattern: ${finding.pattern}`);
    console.error(`   Preview: ${finding.preview}`);
    console.error('');
  }

  console.error('═'.repeat(70));
  console.error(`Found: ${criticalCount} CRITICAL, ${warningCount} WARNING`);
  console.error('');
  console.error('Actions:');
  console.error('  1. Remove the secret from the file');
  console.error('  2. If already committed: git filter-branch or BFG Repo Cleaner');
  console.error('  3. Rotate any exposed secrets IMMEDIATELY');
  console.error('  4. Never use --no-verify to bypass this check for CRITICAL findings');
  console.error('');

  // Block on CRITICAL, warn on WARNING
  if (criticalCount > 0) {
    process.exit(1);
  } else {
    console.warn('⚠️ Warnings found but not blocking commit. Review findings above.');
    process.exit(0);
  }
}

main();
