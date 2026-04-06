'use strict';

/**
 * @test notification-service/alerts
 *
 * Tests the AlertService — Telegram alert delivery.
 *
 * Mocks:
 *   - axios (outbound HTTP to Telegram API) → controlled
 */

const mockAxiosPost = jest.fn();
jest.mock('axios', () => ({ post: (...args) => mockAxiosPost(...args) }));

const AlertService = require('../src/alerts');

const createLogger = () => ({
  info:  jest.fn(),
  warn:  jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
});

describe('AlertService', () => {
  let alertService;
  let logger;

  beforeEach(() => {
    jest.clearAllMocks();
    logger = createLogger();
  });

  // ── Happy Path ──────────────────────────────────────────────────────────────

  describe('handle() — Telegram configured', () => {
    beforeEach(() => {
      alertService = new AlertService({
        botToken: 'test_bot_token_123',
        chatId: '-1001234567890',
        logger,
      });
    });

    test('sends Telegram message with correct emoji for alert type', async () => {
      mockAxiosPost.mockResolvedValue({ data: { ok: true } });

      await alertService.handle({
        type: 'reconciliation_mismatch',
        service: 'reconciliation-service',
        message: 'Ledger mismatch detected',
      });

      expect(mockAxiosPost).toHaveBeenCalledTimes(1);

      const [url, body, config] = mockAxiosPost.mock.calls[0];

      // Correct Telegram API URL
      expect(url).toBe('https://api.telegram.org/bottest_bot_token_123/sendMessage');

      // Chat ID matches
      expect(body.chat_id).toBe('-1001234567890');

      // Message includes the alert type and emoji
      expect(body.text).toContain('🚨'); // reconciliation_mismatch emoji
      expect(body.text).toContain('reconciliation_mismatch');
      expect(body.text).toContain('reconciliation-service');

      // Markdown mode
      expect(body.parse_mode).toBe('Markdown');

      // Timeout configured
      expect(config.timeout).toBe(8000);
    });

    test('uses default emoji for unknown alert type', async () => {
      mockAxiosPost.mockResolvedValue({ data: { ok: true } });

      await alertService.handle({
        type: 'some_unknown_alert_type',
        service: 'test',
        message: 'Test',
      });

      const body = mockAxiosPost.mock.calls[0][1];
      expect(body.text).toContain('ℹ️'); // default emoji
    });

    test('includes txHash and merchantId when present', async () => {
      mockAxiosPost.mockResolvedValue({ data: { ok: true } });

      await alertService.handle({
        type: 'stale_block',
        service: 'blockchain-listener',
        message: 'Block stale',
        txHash: '0xabc123',
        merchantId: 'merchant_456',
      });

      const body = mockAxiosPost.mock.calls[0][1];
      expect(body.text).toContain('0xabc123');
      expect(body.text).toContain('merchant_456');
    });
  });

  // ── Telegram Not Configured ─────────────────────────────────────────────────

  describe('handle() — Telegram not configured', () => {
    test('logs warning but does not crash when botToken missing', async () => {
      alertService = new AlertService({
        botToken: '',
        chatId: '',
        logger,
      });

      await alertService.handle({
        type: 'system_error',
        service: 'api-server',
        message: 'Something broke',
      });

      // No HTTP call made
      expect(mockAxiosPost).not.toHaveBeenCalled();

      // Warning logged
      expect(logger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Telegram not configured'),
        expect.any(Object),
      );
    });
  });

  // ── Telegram API Failure ────────────────────────────────────────────────────

  describe('handle() — Telegram API failure', () => {
    test('logs error but never crashes when Telegram API fails', async () => {
      alertService = new AlertService({
        botToken: 'valid_token',
        chatId: '-100999',
        logger,
      });

      mockAxiosPost.mockRejectedValue(new Error('ECONNREFUSED'));

      // Should NOT throw
      await expect(
        alertService.handle({
          type: 'no_hot_wallet',
          service: 'withdrawal-engine',
          message: 'No hot wallet available',
        }),
      ).resolves.not.toThrow();

      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('Telegram delivery failed'),
        expect.objectContaining({ type: 'no_hot_wallet' }),
      );
    });
  });
});
