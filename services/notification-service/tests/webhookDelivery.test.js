'use strict';

/**
 * @test notification-service/webhookDelivery
 *
 * Tests the WebhookDeliveryEngine — HMAC-signed webhook delivery with retry.
 *
 * All external deps are mocked:
 *   - axios (outbound HTTP) → controlled responses
 *   - @xcg/database (Merchant, WebhookDelivery) → in-memory returns
 *   - @xcg/crypto (decrypt) → passthrough
 *   - ./ssrfCheck (validateOutboundUrl) → configurable
 */

// ── Mocks ─────────────────────────────────────────────────────────────────────

const mockAxiosPost = jest.fn();
jest.mock('axios', () => ({ post: (...args) => mockAxiosPost(...args) }));

const mockMerchantFindById = jest.fn();
const mockWebhookDeliveryCreate = jest.fn();
jest.mock('@xcg/database', () => ({
  Merchant: {
    findById: (...args) => ({
      select: () => ({ lean: () => mockMerchantFindById(...args) }),
    }),
  },
  WebhookDelivery: {
    create: (...args) => mockWebhookDeliveryCreate(...args),
  },
}));

const mockDecrypt = jest.fn();
jest.mock('@xcg/crypto', () => ({
  decrypt: (...args) => mockDecrypt(...args),
}));

const mockValidateOutboundUrl = jest.fn();
jest.mock('../src/ssrfCheck', () => ({
  validateOutboundUrl: (...args) => mockValidateOutboundUrl(...args),
}));

const WebhookDeliveryEngine = require('../src/webhookDelivery');

// ── Test Helpers ──────────────────────────────────────────────────────────────

const createLogger = () => ({
  info:  jest.fn(),
  warn:  jest.fn(),
  error: jest.fn(),
  debug: jest.fn(),
});

const validMerchant = {
  _id: '507f1f77bcf86cd799439011',
  webhookUrl: 'https://merchant.example.com/callback',
  webhookSecret: 'encrypted_secret_blob',
  businessName: 'TestCo',
  isActive: true,
};

const validData = {
  event: 'payment.confirmed',
  merchantId: '507f1f77bcf86cd799439011',
  invoiceId: 'inv_test_123',
  amount: '10.50',
  txHash: 'abc123def456',
};

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('WebhookDeliveryEngine', () => {
  let engine;
  let logger;

  beforeEach(() => {
    jest.clearAllMocks();
    logger = createLogger();
    engine = new WebhookDeliveryEngine({ logger });
    mockWebhookDeliveryCreate.mockResolvedValue({});
  });

  // ── Happy Path ──────────────────────────────────────────────────────────────

  describe('deliver() — success', () => {
    test('delivers webhook with correct HMAC signature', async () => {
      mockMerchantFindById.mockResolvedValue(validMerchant);
      mockDecrypt.mockReturnValue('raw_webhook_secret_123');
      mockValidateOutboundUrl.mockImplementation(() => {}); // pass
      mockAxiosPost.mockResolvedValue({ status: 200 });

      await engine.deliver(validData, 'idem_key_1');

      // axios was called with correct URL
      expect(mockAxiosPost).toHaveBeenCalledTimes(1);
      const [url, payload, config] = mockAxiosPost.mock.calls[0];
      expect(url).toBe('https://merchant.example.com/callback');

      // Payload has required fields
      expect(payload.event).toBe('payment.confirmed');
      expect(payload.merchantId).toBe('507f1f77bcf86cd799439011');
      expect(payload.data.invoiceId).toBe('inv_test_123');

      // HMAC signature header present in correct format
      const sigHeader = config.headers['X-XCG-Signature'];
      expect(sigHeader).toMatch(/^t=\d+,v1=[a-f0-9]{64}$/);

      // Delivery event header
      expect(config.headers['X-XCG-Event']).toBe('payment.confirmed');
      expect(config.headers['X-XCG-Delivery']).toBe('idem_key_1');

      // DB record created as success
      expect(mockWebhookDeliveryCreate).toHaveBeenCalledTimes(1);
      const dbRecord = mockWebhookDeliveryCreate.mock.calls[0][0];
      expect(dbRecord.success).toBe(true);
      expect(dbRecord.attempts).toBe(1);
    });
  });

  // ── Skip Conditions ─────────────────────────────────────────────────────────

  describe('deliver() — skip conditions', () => {
    test('skips when merchant has no webhookUrl', async () => {
      mockMerchantFindById.mockResolvedValue({ ...validMerchant, webhookUrl: null });

      await engine.deliver(validData, 'idem_2');

      expect(mockAxiosPost).not.toHaveBeenCalled();
      expect(mockWebhookDeliveryCreate).not.toHaveBeenCalled();
    });

    test('skips when merchant is inactive', async () => {
      mockMerchantFindById.mockResolvedValue({ ...validMerchant, isActive: false });

      await engine.deliver(validData, 'idem_3');

      expect(mockAxiosPost).not.toHaveBeenCalled();
    });

    test('skips when merchant not found', async () => {
      mockMerchantFindById.mockResolvedValue(null);

      await engine.deliver(validData, 'idem_4');

      expect(mockAxiosPost).not.toHaveBeenCalled();
    });
  });

  // ── Security ────────────────────────────────────────────────────────────────

  describe('deliver() — security', () => {
    test('blocks delivery when SSRF check fails', async () => {
      mockMerchantFindById.mockResolvedValue(validMerchant);
      mockValidateOutboundUrl.mockImplementation(() => {
        throw new Error('SSRF: Webhook URL must use HTTPS');
      });

      await engine.deliver(validData, 'idem_5');

      expect(mockAxiosPost).not.toHaveBeenCalled();
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('SSRF check failed'),
        expect.any(Object),
      );
    });

    test('blocks delivery when webhook secret decryption fails', async () => {
      mockMerchantFindById.mockResolvedValue(validMerchant);
      mockValidateOutboundUrl.mockImplementation(() => {});
      mockDecrypt.mockImplementation(() => {
        throw new Error('Decryption failed: invalid ciphertext');
      });

      await engine.deliver(validData, 'idem_6');

      expect(mockAxiosPost).not.toHaveBeenCalled();
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('failed to decrypt webhook secret'),
        expect.any(Object),
      );
    });
  });

  // ── Retry ───────────────────────────────────────────────────────────────────

  describe('deliver() — retry behavior', () => {
    test('retries on HTTP failure and records exhausted attempts', async () => {
      mockMerchantFindById.mockResolvedValue(validMerchant);
      mockDecrypt.mockReturnValue('secret');
      mockValidateOutboundUrl.mockImplementation(() => {});

      // All attempts fail (simulate 500)
      mockAxiosPost.mockRejectedValue({
        message: 'Request failed with status code 500',
        response: { status: 500 },
      });

      // Override the delay so tests don't wait
      engine._delay = jest.fn().mockResolvedValue();

      await engine.deliver(validData, 'idem_7');

      // Should have attempted MAX_ATTEMPTS (7) times
      expect(mockAxiosPost).toHaveBeenCalledTimes(7);

      // DB record shows failure
      const dbRecord = mockWebhookDeliveryCreate.mock.calls[0][0];
      expect(dbRecord.success).toBe(false);
      expect(dbRecord.attempts).toBe(7);

      // Logged permanent failure
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('all attempts exhausted'),
        expect.any(Object),
      );
    });
  });

  // ── Payload Shape ───────────────────────────────────────────────────────────

  describe('_buildEventData()', () => {
    test('payment.confirmed includes correct fields', () => {
      const result = engine._buildEventData('payment.confirmed', {
        invoiceId: 'inv_1', amount: '5.00', txHash: 'tx_1', status: 'confirmed',
      });
      expect(result).toHaveProperty('invoiceId', 'inv_1');
      expect(result).toHaveProperty('amount', '5.00');
      expect(result).toHaveProperty('txHash', 'tx_1');
      expect(result).toHaveProperty('status', 'confirmed');
      expect(result).toHaveProperty('confirmedAt');
    });

    test('payment.expired includes invoiceId and expiredAt', () => {
      const result = engine._buildEventData('payment.expired', { invoiceId: 'inv_2', amount: '3.00' });
      expect(result).toHaveProperty('invoiceId', 'inv_2');
      expect(result).toHaveProperty('expiredAt');
    });

    test('withdrawal.completed includes toAddress and txHash', () => {
      const result = engine._buildEventData('withdrawal.completed', {
        withdrawalId: 'wdl_1', amount: '100', toAddress: 'TAddr123', txHash: 'tx_2',
      });
      expect(result).toHaveProperty('withdrawalId', 'wdl_1');
      expect(result).toHaveProperty('toAddress', 'TAddr123');
      expect(result).toHaveProperty('txHash', 'tx_2');
    });

    test('unknown event returns raw data', () => {
      const result = engine._buildEventData('some.custom.event', { foo: 'bar' });
      expect(result).toHaveProperty('raw');
    });
  });
});
