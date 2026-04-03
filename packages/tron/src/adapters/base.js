'use strict';

/**
 * @module adapters/base
 *
 * Abstract Blockchain Adapter Interface.
 *
 * ARCHITECTURE: Chain-agnostic pattern.
 * Every supported chain (Tron, EVM, Solana...) MUST implement this interface.
 * Adding a new chain = adding a new adapter file only. Zero changes to core engine.
 *
 * DO NOT put any chain-specific logic here.
 */

class BlockchainAdapter {
  /**
   * @param {string} name - Chain identifier (e.g. 'tron', 'ethereum')
   * @param {object} config - Chain-specific config
   */
  constructor(name, config) {
    if (new.target === BlockchainAdapter) {
      throw new Error('BlockchainAdapter is abstract — do not instantiate directly');
    }
    this.name = name;
    this.config = config;
  }

  /**
   * Get latest finalized block number.
   * @returns {Promise<number>}
   */
  async getLatestBlock() {
    throw new Error(`${this.name}: getLatestBlock() not implemented`);
  }

  /**
   * Get all USDT transfers in a specific block.
   * @param {number} blockNum
   * @returns {Promise<Array<TransferEvent>>}
   *
   * Each TransferEvent MUST include:
   *   txHash       {string}  — unique transaction hash
   *   blockNum     {number}  — block number (for confirmation counting)
   *   fromAddress  {string}  — sender address
   *   toAddress    {string}  — recipient address (our wallet)
   *   amount       {string}  — amount as string (BigInt-safe)
   *   tokenContract{string}  — contract address of the token
   *   tokenSymbol  {string}  — token symbol (must be 'USDT')
   *   timestamp    {number}  — Unix timestamp of the block
   */
  async getTransfersInBlock(blockNum) {
    throw new Error(`${this.name}: getTransfersInBlock() not implemented`);
  }

  /**
   * Get current confirmation count for a transaction.
   * Confirmations = latestBlock - txBlock
   * @param {string} txHash
   * @returns {Promise<number>}
   */
  async getConfirmations(txHash) {
    throw new Error(`${this.name}: getConfirmations() not implemented`);
  }

  /**
   * Get USDT balance for an address.
   * @param {string} address
   * @returns {Promise<string>} Balance as string in full units (not sun/wei)
   */
  async getUSDTBalance(address) {
    throw new Error(`${this.name}: getUSDTBalance() not implemented`);
  }

  /**
   * Broadcast a pre-signed transaction.
   * @param {object} signedTx
   * @returns {Promise<{ txHash: string }>}
   */
  async broadcastTransaction(signedTx) {
    throw new Error(`${this.name}: broadcastTransaction() not implemented`);
  }

  /**
   * Validate a wallet address format for this chain.
   * @param {string} address
   * @returns {boolean}
   */
  isValidAddress(address) {
    throw new Error(`${this.name}: isValidAddress() not implemented`);
  }

  /**
   * @returns {string} The official USDT token contract address for this chain.
   * MUST be hardcoded — never from user input or env variable.
   */
  getUSDTContractAddress() {
    throw new Error(`${this.name}: getUSDTContractAddress() not implemented`);
  }
}

module.exports = BlockchainAdapter;
