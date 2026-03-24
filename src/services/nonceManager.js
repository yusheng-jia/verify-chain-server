/**
 * 🔒 Nonce管理服务
 *
 * 防重放攻击的Nonce管理
 * 包括nonce存储、验证、清理等功能
 */

const { SECURITY_CONFIG } = require("../config/constants");

// 🔒 Nonce防重放存储（存储已使用的nonce和时间戳）
const usedNonces = new Map(); // key: nonce, value: timestamp

/**
 * 初始化nonce清理定时器
 */
function initNonceCleanup() {
  setInterval(() => {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [nonce, timestamp] of usedNonces.entries()) {
      if (now - timestamp > SECURITY_CONFIG.NONCE_EXPIRY_TIME) {
        usedNonces.delete(nonce);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      console.log(
        `🧹 Cleaned up ${cleanedCount} expired nonces. Current nonce count: ${usedNonces.size}`,
      );
    }
  }, SECURITY_CONFIG.NONCE_CLEANUP_INTERVAL);

  console.log("🔒 Nonce cleanup timer initialized");
}

/**
 * 验证nonce是否已被使用
 * @param {string} nonce - 要验证的nonce
 * @returns {boolean} true表示nonce已被使用
 */
function isNonceUsed(nonce) {
  return usedNonces.has(nonce);
}

/**
 * 记录nonce使用
 * @param {string} nonce - 要记录的nonce
 * @param {number} timestamp - 使用时间戳（可选，默认为当前时间）
 */
function recordNonceUsage(nonce, timestamp = Date.now()) {
  usedNonces.set(nonce, timestamp);
}

/**
 * 验证nonce（检查是否已使用并记录使用）
 * @param {string} nonce - 要验证和记录的nonce
 * @returns {object} 验证结果 {isValid: boolean, error?: string}
 */
function validateAndRecordNonce(nonce) {
  if (!nonce) {
    return {
      isValid: false,
      error: "Nonce is required",
    };
  }

  if (isNonceUsed(nonce)) {
    const previousUsage = usedNonces.get(nonce);
    return {
      isValid: false,
      error: "Nonce has already been used",
      previousUsage: new Date(previousUsage).toISOString(),
    };
  }

  recordNonceUsage(nonce);
  return {
    isValid: true,
  };
}

/**
 * 获取nonce使用统计信息
 * @returns {object} 统计信息
 */
function getNonceStats() {
  const nonceList = Array.from(usedNonces.entries()).map(
    ([nonce, timestamp]) => ({
      nonce: nonce,
      usedAt: new Date(timestamp).toISOString(),
      ageMinutes: Math.floor((Date.now() - timestamp) / (60 * 1000)),
    }),
  );

  return {
    totalActiveNonces: usedNonces.size,
    nonceExpiryTimeHours: SECURITY_CONFIG.NONCE_EXPIRY_TIME / (60 * 60 * 1000),
    cleanupIntervalMinutes:
      SECURITY_CONFIG.NONCE_CLEANUP_INTERVAL / (60 * 1000),
    recentNonces: nonceList.slice(-10), // 显示最近10个nonce
    allNonces: nonceList,
  };
}

/**
 * 获取当前活跃nonce数量
 * @returns {number} 活跃nonce数量
 */
function getActiveNonceCount() {
  return usedNonces.size;
}

/**
 * 清除所有nonce（用于测试或重置）
 */
function clearAllNonces() {
  const count = usedNonces.size;
  usedNonces.clear();
  console.log(`🧹 Cleared ${count} nonces`);
}

module.exports = {
  initNonceCleanup,
  isNonceUsed,
  recordNonceUsage,
  validateAndRecordNonce,
  getNonceStats,
  getActiveNonceCount,
  clearAllNonces,
};
