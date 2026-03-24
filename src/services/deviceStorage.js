/**
 * 🔒 设备信息存储服务
 *
 * 管理已验证设备的信息存储和检索
 * 包括设备ID、公钥、证书信息等
 */

// 🔒 安全的设备信息存储（内存缓存，生产环境应使用数据库）
const verifiedDevices = new Map();

/**
 * 存储设备信息
 * @param {string} deviceId - 设备ID
 * @param {object} deviceInfo - 完整的设备信息对象
 * @returns {object} 存储的设备信息
 */
function storeDeviceInfo(deviceId, deviceInfo) {
  // 确保deviceInfo包含必要的字段
  const completeDeviceInfo = {
    deviceId,
    platform: deviceInfo.platform || "unknown",
    keyId: deviceInfo.keyId,
    publicKey: deviceInfo.publicKey, // 存储公钥用于后续签名验证
    attestationCertificatePublicKey: deviceInfo.attestationCertificatePublicKey,
    certificateChain: deviceInfo.certificateChain,
    challenge: deviceInfo.challenge,
    attestationObject: deviceInfo.attestationObject,
    keyInfo: deviceInfo.keyInfo,
    securityLevel: deviceInfo.securityLevel,
    attestation: deviceInfo.attestation,
    assertionCounter: deviceInfo.assertionCounter || 0,
    certificateInfo: deviceInfo.certificateInfo,
    registrationTime: deviceInfo.registrationTime || new Date().toISOString(),
    isVerified: true,
  };

  verifiedDevices.set(deviceId, completeDeviceInfo);
  return completeDeviceInfo;
}

/**
 * 获取设备信息
 * @param {string} deviceId - 设备ID
 * @returns {object|undefined} 设备信息或undefined
 */
function getDeviceInfo(deviceId) {
  return verifiedDevices.get(deviceId);
}

/**
 * 获取所有已注册设备的列表（用于管理界面）
 * @returns {Array} 设备信息数组
 */
function getAllDevices() {
  return Array.from(verifiedDevices.entries()).map(([deviceId, info]) => ({
    deviceId,
    platform: info.platform || "unknown",
    keyId: info.keyId,
    registrationTime: info.registrationTime,
    isVerified: info.isVerified,
    securityLevel: info.securityLevel,
    keyInfo: info.keyInfo,
    certificateInfo: {
      subject: info.certificateInfo?.subject || "Unknown",
      issuer: info.certificateInfo?.issuer || "Unknown",
      organization: info.certificateInfo?.organization || "Unknown",
    },
  }));
}

/**
 * 获取已注册设备的数量
 * @returns {number} 设备数量
 */
function getDeviceCount() {
  return verifiedDevices.size;
}

function updateDeviceInfo(deviceId, updates) {
  const existing = verifiedDevices.get(deviceId);
  if (!existing) {
    return undefined;
  }

  const updated = {
    ...existing,
    ...updates,
  };

  verifiedDevices.set(deviceId, updated);
  return updated;
}

/**
 * 删除设备信息（可选功能）
 * @param {string} deviceId - 设备ID
 * @returns {boolean} 是否成功删除
 */
function removeDevice(deviceId) {
  return verifiedDevices.delete(deviceId);
}

module.exports = {
  storeDeviceInfo,
  getDeviceInfo,
  getAllDevices,
  getDeviceCount,
  updateDeviceInfo,
  removeDevice,
};
