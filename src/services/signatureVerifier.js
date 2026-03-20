/**
 * 🔐 签名验证服务
 *
 * 处理Android/iOS设备的签名验证
 * 包括数据构建、签名验证等功能
 */

const crypto = require("crypto");
const { SECURITY_CONFIG } = require("../config/constants");

/**
 * 构建用于签名的数据（Android格式）
 * @param {string} phone - 电话号码
 * @param {number} timestamp - 时间戳
 * @param {string} nonce - 随机数
 * @returns {string} 构建的签名数据
 */
function buildSignData(phone, timestamp, nonce) {
  // Android客户端使用的格式：query parameter style
  const signData = `phone=${phone}&timestamp=${timestamp}&nonce=${nonce}`;
  console.log(`📝 Built sign data: ${signData}`);
  return signData;
}

/**
 * 验证RSA签名 (SHA256withRSA)
 * @param {string} data - 原始数据
 * @param {string} signature - Base64编码的签名
 * @param {string} publicKeyPem - PEM格式的公钥
 * @returns {object} 验证结果
 */
function verifyRSASignature(data, signature, publicKeyPem) {
  try {
    console.log(`🔍 Verifying RSA signature...`);
    console.log(`   Data length: ${data.length} bytes`);
    console.log(`   Signature length: ${signature.length} chars (base64)`);

    // 调试：检查公钥是否存在和类型
    console.log(`   Public key: ${publicKeyPem ? "[present]" : "[MISSING]"}`);
    console.log(`   Public key type: ${typeof publicKeyPem}`);

    if (!publicKeyPem) {
      throw new Error("Public key is missing or undefined");
    }

    if (typeof publicKeyPem !== "string") {
      throw new Error(
        `Public key must be a string, but received ${typeof publicKeyPem}`,
      );
    }

    console.log(`   Public key length: ${publicKeyPem.length} chars`);
    console.log(`   Public key preview: ${publicKeyPem.substring(0, 100)}...`);

    // 创建验证器
    const verifier = crypto.createVerify("SHA256");
    verifier.update(data, "utf8");

    // 验证签名
    const isValid = verifier.verify(publicKeyPem, signature, "base64");

    console.log(
      `${isValid ? "✅" : "❌"} RSA signature verification: ${isValid ? "VALID" : "INVALID"}`,
    );

    return {
      success: true,
      isValid: isValid,
      algorithm: "SHA256withRSA",
      dataHash: crypto.createHash("sha256").update(data, "utf8").digest("hex"),
    };
  } catch (error) {
    console.error(`❌ RSA signature verification error: ${error.message}`);
    return {
      success: false,
      error: `Signature verification failed: ${error.message}`,
    };
  }
}

/**
 * 验证时间戳（防重放和时间窗口检查）
 * @param {number} timestamp - 要验证的时间戳
 * @returns {object} 验证结果
 */
function validateTimestamp(timestamp) {
  const now = Date.now();
  const timeDiff = now - timestamp; // 注意：不用abs，区分过去/未来
  const maxAllowedDiff = SECURITY_CONFIG.TIMESTAMP_TOLERANCE;
  const maxFuture = SECURITY_CONFIG.MAX_TIMESTAMP_FUTURE;

  console.log(`⏰ Timestamp validation:`);
  console.log(`   Current time: ${new Date(now).toISOString()}`);
  console.log(`   Request time: ${new Date(timestamp).toISOString()}`);
  console.log(
    `   Time difference: ${timeDiff}ms (${Math.round(timeDiff / 1000)}s)`,
  );
  console.log(
    `   Max allowed past: ${maxAllowedDiff}ms (${Math.round(maxAllowedDiff / 1000)}s)`,
  );
  console.log(
    `   Max allowed future: ${maxFuture}ms (${Math.round(maxFuture / 1000)}s)`,
  );

  // 🔒 检查timestamp不能太旧
  if (timeDiff > maxAllowedDiff) {
    return {
      isValid: false,
      error: `Timestamp too old. Age: ${Math.round(timeDiff / 1000)}s, Max allowed: ${Math.round(maxAllowedDiff / 1000)}s`,
      timeDifferenceMs: timeDiff,
      maxAllowedMs: maxAllowedDiff,
    };
  }

  // 🔒 检查timestamp不能太新（防止时钟攻击）
  if (timeDiff < -maxFuture) {
    return {
      isValid: false,
      error: `Timestamp too far in future. Future: ${Math.round(-timeDiff / 1000)}s, Max allowed: ${Math.round(maxFuture / 1000)}s`,
      timeDifferenceMs: timeDiff,
      maxFutureMs: maxFuture,
    };
  }

  return {
    isValid: true,
    timeDifferenceMs: timeDiff,
    maxAllowedMs: maxAllowedDiff,
  };
}

/**
 * 🔒 验证设备会话是否仍然有效（基于注册时间）
 * @param {object} deviceInfo - 设备信息
 * @returns {object} 验证结果
 */
function validateDeviceSession(deviceInfo) {
  const now = Date.now();
  const registrationTime = new Date(deviceInfo.registrationTime).getTime();
  const sessionAge = now - registrationTime;
  const maxSessionAge = SECURITY_CONFIG.DEVICE_SESSION_EXPIRY;

  console.log(`🔐 Device session validation:`);
  console.log(`   Current time: ${new Date(now).toISOString()}`);
  console.log(`   Registration time: ${deviceInfo.registrationTime}`);
  console.log(`   Session age: ${Math.round(sessionAge / 1000)}s`);
  console.log(`   Max session age: ${Math.round(maxSessionAge / 1000)}s`);

  if (sessionAge > maxSessionAge) {
    return {
      isValid: false,
      error: `Device session expired. Age: ${Math.round(sessionAge / 1000)}s, Max: ${Math.round(maxSessionAge / 1000)}s. Please re-register device.`,
      sessionAgeMs: sessionAge,
      maxSessionAgeMs: maxSessionAge,
      registrationTime: deviceInfo.registrationTime,
    };
  }

  return {
    isValid: true,
    sessionAgeMs: sessionAge,
    maxSessionAgeMs: maxSessionAge,
    registrationTime: deviceInfo.registrationTime,
  };
}

/**
 * 完整的签名验证流程
 * @param {object} params - 验证参数
 * @param {string} params.phone - 电话号码
 * @param {number} params.timestamp - 时间戳
 * @param {string} params.nonce - 随机数
 * @param {string} params.signature - Base64编码的签名
 * @param {string} params.publicKey - PEM格式的公钥
 * @returns {object} 完整验证结果
 */
function verifyMessageSignature(params) {
  const { phone, timestamp, nonce, signature, publicKey } = params;

  console.log(
    `🔐 Starting complete signature verification for phone: ${phone}`,
  );

  // 🔧 Validate publicKey type and extract string if needed
  console.log(`   Public key type: ${typeof publicKey}`);
  console.log(`   Public key present: ${publicKey ? "YES" : "NO"}`);

  let publicKeyString = publicKey;
  if (typeof publicKey === "object" && publicKey !== null) {
    console.log(`   PublicKey is an object, keys: ${Object.keys(publicKey)}`);
    if (publicKey.publicKey && typeof publicKey.publicKey === "string") {
      publicKeyString = publicKey.publicKey;
      console.log(`   ✅ Extracted PEM string from publicKey object`);
    } else {
      console.error(`   ❌ PublicKey object doesn't contain valid PEM string`);
      return {
        success: false,
        step: "public_key_extraction",
        error: "PublicKey is an object but doesn't contain valid PEM string",
        publicKeyObject: publicKey,
      };
    }
  }

  if (typeof publicKeyString !== "string") {
    console.error(`   ❌ PublicKey is not a string: ${typeof publicKeyString}`);
    return {
      success: false,
      step: "public_key_validation",
      error: `PublicKey must be a string, but received ${typeof publicKeyString}`,
      publicKeyType: typeof publicKeyString,
    };
  }

  console.log(
    `   ✅ PublicKey validated as string (${publicKeyString.length} chars)`,
  );

  // 1. 验证时间戳
  const timestampValidation = validateTimestamp(timestamp);
  if (!timestampValidation.isValid) {
    return {
      success: false,
      step: "timestamp_validation",
      error: timestampValidation.error,
      details: timestampValidation,
    };
  }

  // 2. 构建签名数据
  const signData = buildSignData(phone, timestamp, nonce);

  // 3. 验证RSA签名
  const signatureVerification = verifyRSASignature(
    signData,
    signature,
    publicKeyString, // ✅ Use validated string version
  );
  if (!signatureVerification.success) {
    return {
      success: false,
      step: "signature_verification",
      error: signatureVerification.error,
    };
  }

  if (!signatureVerification.isValid) {
    return {
      success: false,
      step: "signature_validation",
      error: "Signature verification failed - signature does not match",
      details: signatureVerification,
    };
  }

  console.log(
    `✅ Complete signature verification successful for phone: ${phone}`,
  );

  return {
    success: true,
    verification: {
      timestamp: timestampValidation,
      signature: signatureVerification,
      signData: signData,
    },
  };
}

/**
 * 验证参数完整性
 * @param {object} params - 要验证的参数
 * @returns {object} 验证结果
 */
function validateSignatureParams(params) {
  const { phone, timestamp, nonce, signature } = params;
  const errors = [];

  if (!phone || typeof phone !== "string") {
    errors.push("phone is required and must be a string");
  }

  if (!timestamp || typeof timestamp !== "number") {
    errors.push("timestamp is required and must be a number");
  }

  if (!nonce || typeof nonce !== "string") {
    errors.push("nonce is required and must be a string");
  }

  if (!signature || typeof signature !== "string") {
    errors.push("signature is required and must be a string");
  }

  if (errors.length > 0) {
    return {
      isValid: false,
      errors: errors,
    };
  }

  return {
    isValid: true,
  };
}

/**
 * 生成签名验证摘要信息
 * @param {object} params - 验证参数
 * @returns {object} 摘要信息
 */
function generateVerificationSummary(params) {
  const { phone, timestamp, nonce, signature, publicKey } = params;

  return {
    phone: phone,
    timestamp: {
      value: timestamp,
      iso: new Date(timestamp).toISOString(),
      ageSeconds: Math.floor((Date.now() - timestamp) / 1000),
    },
    nonce: {
      value: nonce,
      length: nonce.length,
    },
    signature: {
      length: signature.length,
      algorithm: "SHA256withRSA",
      hash:
        crypto
          .createHash("sha256")
          .update(signature)
          .digest("hex")
          .substring(0, 16) + "...",
    },
    publicKey: {
      available: !!publicKey,
      hash: publicKey
        ? crypto
            .createHash("sha256")
            .update(publicKey)
            .digest("hex")
            .substring(0, 16) + "..."
        : "N/A",
    },
  };
}

module.exports = {
  buildSignData,
  verifyRSASignature,
  validateTimestamp,
  validateDeviceSession, // 🔒 新增设备会话验证
  verifyMessageSignature,
  validateSignatureParams,
  generateVerificationSummary,
};
