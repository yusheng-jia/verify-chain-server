/**
 * 🎯 Challenge 管理服务
 *
 * 为设备注册下发一次性 challenge。
 * iOS App Attest 必须使用服务端签发的 challenge；
 * Android 可以逐步迁移到同样模式。
 */

const crypto = require("crypto");
const { SECURITY_CONFIG } = require("../config/constants");

const issuedChallenges = new Map();

function buildKey({ deviceId, platform, purpose = "register" }) {
  return `${platform}:${purpose}:${deviceId}`;
}

function initChallengeCleanup() {
  setInterval(() => {
    const now = Date.now();
    let cleanedCount = 0;

    for (const [key, record] of issuedChallenges.entries()) {
      if (record.expiresAt <= now) {
        issuedChallenges.delete(key);
        cleanedCount++;
      }
    }

    if (cleanedCount > 0) {
      console.log(
        `🧹 Cleaned up ${cleanedCount} expired challenges. Current challenge count: ${issuedChallenges.size}`,
      );
    }
  }, SECURITY_CONFIG.CHALLENGE_CLEANUP_INTERVAL);

  console.log("🎯 Challenge cleanup timer initialized");
}

function issueChallenge({ deviceId, platform, purpose = "register" }) {
  const challengeBuffer = crypto.randomBytes(32);
  const challenge = challengeBuffer.toString("base64");
  const issuedAt = Date.now();
  const expiresAt = issuedAt + SECURITY_CONFIG.CHALLENGE_EXPIRY_TIME;
  const key = buildKey({ deviceId, platform, purpose });

  const record = {
    challenge,
    platform,
    deviceId,
    purpose,
    issuedAt,
    expiresAt,
  };

  issuedChallenges.set(key, record);
  return record;
}

function getChallengeRecord({ deviceId, platform, purpose = "register" }) {
  return issuedChallenges.get(buildKey({ deviceId, platform, purpose }));
}

function validateChallenge({
  deviceId,
  platform,
  challenge,
  purpose = "register",
}) {
  console.log(
    `🔍 Validating challenge for deviceId=${deviceId}, platform=${platform}, purpose=${purpose}`,
  );
  const record = getChallengeRecord({ deviceId, platform, purpose });

  if (!record) {
    return {
      isValid: false,
      error: "No active challenge found for this device and platform",
    };
  }

  if (record.expiresAt <= Date.now()) {
    issuedChallenges.delete(buildKey({ deviceId, platform, purpose }));
    return {
      isValid: false,
      error: "Challenge has expired",
    };
  }

  if (record.challenge !== challenge) {
    return {
      isValid: false,
      error: "Challenge does not match the latest issued challenge",
    };
  }

  return {
    isValid: true,
    issuedAt: record.issuedAt,
    expiresAt: record.expiresAt,
  };
}

function consumeChallenge({ deviceId, platform, purpose = "register" }) {
  return issuedChallenges.delete(buildKey({ deviceId, platform, purpose }));
}

module.exports = {
  initChallengeCleanup,
  issueChallenge,
  getChallengeRecord,
  validateChallenge,
  consumeChallenge,
};
