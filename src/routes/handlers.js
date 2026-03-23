/**
 * 🌐 路由处理器
 *
 * Express路由处理器，处理所有API端点
 * 包括设备注册、消息验证、管理接口等
 */

const {
  SECURITY_CONFIG,
  SERVICE_INFO,
  SUPPORTED_PLATFORMS,
} = require("../config/constants");
const deviceStorage = require("../services/deviceStorage");
const nonceManager = require("../services/nonceManager");
const certificateVerifier = require("../services/certificateVerifier");
const signatureVerifier = require("../services/signatureVerifier");

/**
 * 健康检查端点
 */
function healthCheck(req, res) {
  console.log("📊 Health check requested");

  res.json({
    status: "healthy",
    service: SERVICE_INFO.name,
    version: SERVICE_INFO.version,
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
    stats: {
      registeredDevices: deviceStorage.getDeviceCount(),
      activeNonces: nonceManager.getActiveNonceCount(),
    },
  });
}

/**
 * 设备注册端点（兼容原API格式）
 */
function registerDevice(req, res) {
  console.log("🔍 DEBUG: registerDevice function called");
  console.log("🔍 DEBUG: Request body:", JSON.stringify(req.body, null, 2));

  try {
    // 兼容原有的certChain格式和新的certificateChain格式
    const { deviceId, platform, certificateChain, certChain, challenge } =
      req.body;

    console.log("🔍 DEBUG: Extracted parameters:");
    console.log(`   deviceId: ${deviceId}`);
    console.log(`   platform: ${platform}`);
    console.log(`   certChain: ${certChain ? "[present]" : "[missing]"}`);
    console.log(
      `   certificateChain: ${certificateChain ? "[present]" : "[missing]"}`,
    );

    const normalizedPlatform =
      typeof platform === "string" ? platform.toLowerCase() : platform;

    // 确定使用哪个证书链参数（优先使用certChain以保持向后兼容性）
    const actualCertChain = certChain || certificateChain;

    console.log(
      `🔍 DEBUG: actualCertChain: ${actualCertChain ? "[present]" : "[missing]"}`,
    );

    console.log(`📱 Device registration request: ${deviceId}`);
    console.log(
      `📊 Request format: ${certChain ? "Original (certChain)" : "New (certificateChain)"}`,
    );

    // 验证请求参数
    if (!deviceId) {
      return res.status(400).json({
        success: false,
        error: "deviceId is required",
      });
    }

    if (!platform || typeof platform !== "string") {
      return res.status(400).json({
        success: false,
        error: "platform is required and must be a string",
        supportedPlatforms: SUPPORTED_PLATFORMS,
      });
    }

    if (!SUPPORTED_PLATFORMS.includes(normalizedPlatform)) {
      return res.status(400).json({
        success: false,
        error: `Unsupported platform: ${platform}`,
        supportedPlatforms: SUPPORTED_PLATFORMS,
      });
    }

    if (!actualCertChain) {
      return res.status(400).json({
        success: false,
        error:
          "Certificate chain is required (certChain or certificateChain parameter)",
      });
    }

    if (!Array.isArray(actualCertChain) || actualCertChain.length === 0) {
      return res.status(400).json({
        success: false,
        error: "Certificate chain must be a non-empty array",
      });
    }

    // 检查设备是否已注册（允许重复注册以更新参数）
    const existingDevice = deviceStorage.getDeviceInfo(deviceId);
    const isUpdate = !!existingDevice;
    if (existingDevice) {
      console.log(`🔄 Device already exists, will update: ${deviceId}`);
      console.log(
        `📊 Previous registration: ${existingDevice.registrationTime}`,
      );
    }

    // 验证证书链和提取设备信息
    const verificationResult = certificateVerifier.verifyAndExtractDeviceInfo({
      platform: normalizedPlatform,
      certificateChain: actualCertChain,
    });

    if (!verificationResult.success) {
      console.error(
        `❌ Certificate verification failed for ${deviceId}: ${verificationResult.error}`,
      );

      // 提供更详细的错误信息，帮助客户端调试
      const errorResponse = {
        success: false,
        error: verificationResult.error,
        deviceId: deviceId,
        platform: normalizedPlatform,
        certificateChainLength: actualCertChain.length,
      };

      // 如果有额外的调试信息，添加到响应中
      if (verificationResult.certificateIndex !== undefined) {
        errorResponse.failedCertificateIndex =
          verificationResult.certificateIndex;
        errorResponse.totalCertificates = verificationResult.totalCertificates;
      }

      if (verificationResult.certificatePreview) {
        errorResponse.certificatePreview =
          verificationResult.certificatePreview;
      }

      // 记录详细的调试信息
      console.error(`📊 Certificate verification details:`);
      console.error(`   Device ID: ${deviceId}`);
      console.error(`   Certificate chain length: ${actualCertChain.length}`);
      console.error(`   Error: ${verificationResult.error}`);

      if (actualCertChain.length > 0) {
        console.error(
          `   First certificate preview: ${actualCertChain[0]?.substring(0, 100)}...`,
        );
      }

      return res.status(400).json(errorResponse);
    }

    // 调试：显示验证结果
    console.log(`🔍 DEBUG: verificationResult:`);
    console.log(`   success: ${verificationResult.success}`);
    console.log(
      `   publicKey: ${verificationResult.publicKey ? "[present]" : "[missing]"}`,
    );
    if (verificationResult.publicKey) {
      console.log(
        `   publicKey length: ${verificationResult.publicKey.length} chars`,
      );
      console.log(
        `   publicKey preview: ${verificationResult.publicKey.substring(0, 100)}...`,
      );
    }
    console.log(`   keyInfo: ${JSON.stringify(verificationResult.keyInfo)}`);

    // 存储设备信息
    const deviceInfo = {
      deviceId: deviceId,
      platform: normalizedPlatform,
      publicKey: verificationResult.publicKey,
      certificateChain: actualCertChain, // 修复：使用actualCertChain而不是certificateChain
      keyInfo: verificationResult.keyInfo,
      securityLevel: verificationResult.securityLevel,
      attestation: verificationResult.verification.attestation,
      certificateInfo: verificationResult.verification.leafCertificate,
      registrationTime: new Date().toISOString(),
    };

    // 调试：显示将要存储的设备信息
    console.log(`🔍 DEBUG: deviceInfo to be stored:`);
    console.log(`   deviceId: ${deviceInfo.deviceId}`);
    console.log(
      `   publicKey: ${deviceInfo.publicKey ? "[present]" : "[missing]"}`,
    );
    console.log(`   keyInfo: ${JSON.stringify(deviceInfo.keyInfo)}`);

    deviceStorage.storeDeviceInfo(deviceId, deviceInfo);

    const actionType = isUpdate ? "updated" : "registered";
    console.log(`✅ Device ${actionType} successfully: ${deviceId}`);
    console.log(`🔐 Security level: ${deviceInfo.securityLevel}`);
    console.log(
      `📋 Key info: ${deviceInfo.keyInfo.type} ${deviceInfo.keyInfo.size}bit`,
    );
    if (isUpdate && existingDevice) {
      console.log(
        `📊 Previous registration: ${existingDevice.registrationTime}`,
      );
      console.log(`📊 Updated registration: ${deviceInfo.registrationTime}`);
    }

    res.json({
      success: true,
      deviceId: deviceId,
      platform: normalizedPlatform,
      action: isUpdate ? "updated" : "registered",
      registrationTime: deviceInfo.registrationTime,
      previousRegistrationTime: isUpdate
        ? existingDevice.registrationTime
        : undefined,
      securityLevel: deviceInfo.securityLevel,
      keyInfo: deviceInfo.keyInfo,
      certificateInfo: {
        subject: deviceInfo.certificateInfo.subject,
        validUntil: deviceInfo.certificateInfo.validUntil,
        fingerprint: deviceInfo.certificateInfo.fingerprint,
      },
    });
  } catch (error) {
    console.error(`❌ Registration error: ${error.message}`);
    res.status(500).json({
      success: false,
      error: "Internal server error during registration",
    });
  }
}

/**
 * 发送消息验证端点
 */
function sendMessage(req, res) {
  try {
    const { deviceId, platform, phone, timestamp, nonce, signature } = req.body;
    const normalizedPlatform =
      typeof platform === "string" ? platform.toLowerCase() : platform;

    console.log(
      `📨 Message verification request from device: ${deviceId}, platform: ${normalizedPlatform}, phone: ${phone}`,
    );

    // 参数验证
    const paramValidation = signatureVerifier.validateSignatureParams({
      phone,
      timestamp,
      nonce,
      signature,
    });

    if (!paramValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: "Invalid parameters",
        details: paramValidation.errors,
      });
    }

    if (!deviceId) {
      return res.status(400).json({
        success: false,
        error: "deviceId is required",
      });
    }

    if (!platform || typeof platform !== "string") {
      return res.status(400).json({
        success: false,
        error: "platform is required and must be a string",
        supportedPlatforms: SUPPORTED_PLATFORMS,
      });
    }

    if (!SUPPORTED_PLATFORMS.includes(normalizedPlatform)) {
      return res.status(400).json({
        success: false,
        error: `Unsupported platform: ${platform}`,
        supportedPlatforms: SUPPORTED_PLATFORMS,
      });
    }

    // 获取设备信息
    const deviceInfo = deviceStorage.getDeviceInfo(deviceId);
    if (!deviceInfo) {
      console.log(`❌ Device not found: ${deviceId}`);
      return res.status(404).json({
        success: false,
        error: "Device not registered",
      });
    }

    if (deviceInfo.platform !== normalizedPlatform) {
      console.log(
        `❌ Platform mismatch for device ${deviceId}: expected ${deviceInfo.platform}, received ${normalizedPlatform}`,
      );
      return res.status(400).json({
        success: false,
        error: "Platform mismatch for registered device",
        registeredPlatform: deviceInfo.platform,
        requestPlatform: normalizedPlatform,
      });
    }

    // 调试：显示获取到的设备信息
    console.log(`🔍 DEBUG: Retrieved deviceInfo for ${deviceId}:`);
    console.log(`   deviceId: ${deviceInfo.deviceId}`);
    console.log(
      `   publicKey: ${deviceInfo.publicKey ? "[present]" : "[missing]"}`,
    );
    console.log(`   publicKey type: ${typeof deviceInfo.publicKey}`);
    if (deviceInfo.publicKey && typeof deviceInfo.publicKey === "string") {
      console.log(`   publicKey length: ${deviceInfo.publicKey.length} chars`);
    } else if (deviceInfo.publicKey) {
      console.log(`   publicKey length: undefined chars`);
      console.log(`   publicKey is not a string!`);
    }
    console.log(`   keyInfo: ${JSON.stringify(deviceInfo.keyInfo)}`);

    // 🔒 验证设备会话是否有效（基于注册时间）
    const sessionValidation =
      signatureVerifier.validateDeviceSession(deviceInfo);
    if (!sessionValidation.isValid) {
      console.log(`❌ Device session expired: ${sessionValidation.error}`);
      return res.status(401).json({
        success: false,
        error: sessionValidation.error,
        errorCode: "SESSION_EXPIRED",
        registrationTime: sessionValidation.registrationTime,
        sessionAgeMs: sessionValidation.sessionAgeMs,
        requiresReregistration: true,
      });
    }

    console.log(
      `✅ Device session valid (age: ${Math.round(sessionValidation.sessionAgeMs / 1000)}s)`,
    );

    // 验证nonce（防重放）
    const nonceValidation = nonceManager.validateAndRecordNonce(nonce);
    if (!nonceValidation.isValid) {
      console.log(`❌ Nonce validation failed: ${nonceValidation.error}`);
      return res.status(400).json({
        success: false,
        error: nonceValidation.error,
        previousUsage: nonceValidation.previousUsage,
      });
    }

    // 签名验证
    const verificationResult = signatureVerifier.verifyMessageSignature({
      phone,
      timestamp,
      nonce,
      signature,
      publicKey: deviceInfo.publicKey,
    });

    if (!verificationResult.success) {
      console.log(
        `❌ Signature verification failed: ${verificationResult.error}`,
      );
      return res.status(400).json({
        success: false,
        error: verificationResult.error,
        step: verificationResult.step,
      });
    }

    console.log(
      `✅ Message verification successful for device ${deviceId}, phone: ${phone}`,
    );

    const response = {
      success: true,
      deviceId: deviceId,
      platform: normalizedPlatform,
      phone: phone,
      timestamp: new Date(timestamp).toISOString(),
      nonce: nonce,
      verification: {
        signatureValid: true,
        timestampValid: true,
        nonceValid: true,
        securityLevel: deviceInfo.securityLevel,
      },
      verificationTime: new Date().toISOString(),
    };

    res.json(response);

    // 记录成功验证日志
    console.log(`📊 Verification summary:`);
    console.log(`   Device: ${deviceId}`);
    console.log(`   Phone: ${phone}`);
    console.log(`   Security Level: ${deviceInfo.securityLevel}`);
    console.log(`   Verification Time: ${response.verificationTime}`);
  } catch (error) {
    console.error(`❌ Message verification error: ${error.message}`);
    res.status(500).json({
      success: false,
      error: "Internal server error during verification",
    });
  }
}

/**
 * 获取所有已注册设备
 */
function getDevices(req, res) {
  try {
    console.log("📱 Listing all registered devices");

    const devices = deviceStorage.getAllDevices();

    // 返回设备摘要信息（不包含敏感信息）
    const deviceSummaries = devices.map((device) => ({
      deviceId: device.deviceId,
      platform: device.platform,
      registrationTime: device.registrationTime,
      securityLevel: device.securityLevel,
      keyInfo: device.keyInfo,
      certificateSubject: device.certificateInfo?.subject || "N/A",
      certificateValidUntil: device.certificateInfo?.validUntil || "N/A",
    }));

    res.json({
      success: true,
      count: deviceSummaries.length,
      devices: deviceSummaries,
    });
  } catch (error) {
    console.error(`❌ Error listing devices: ${error.message}`);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
}

/**
 * 获取nonce统计信息
 */
function getNonceStats(req, res) {
  try {
    console.log("🔒 Retrieving nonce statistics");

    const stats = nonceManager.getNonceStats();

    res.json({
      success: true,
      ...stats,
    });
  } catch (error) {
    console.error(`❌ Error getting nonce stats: ${error.message}`);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
}

/**
 * 系统状态信息
 */
function getSystemStatus(req, res) {
  try {
    const devices = deviceStorage.getAllDevices();
    const nonceStats = nonceManager.getNonceStats();

    const status = {
      service: SERVICE_INFO,
      timestamp: new Date().toISOString(),
      uptime: {
        seconds: Math.floor(process.uptime()),
        human: formatUptime(process.uptime()),
      },
      devices: {
        total: devices.length,
        byPlatform: devices.reduce((acc, device) => {
          acc[device.platform || "unknown"] =
            (acc[device.platform || "unknown"] || 0) + 1;
          return acc;
        }, {}),
        bySecurityLevel: devices.reduce((acc, device) => {
          acc[device.securityLevel] = (acc[device.securityLevel] || 0) + 1;
          return acc;
        }, {}),
      },
      nonces: {
        active: nonceStats.totalActiveNonces,
        expiryHours: nonceStats.nonceExpiryTimeHours,
        cleanupIntervalMinutes: nonceStats.cleanupIntervalMinutes,
      },
      security: {
        timestampToleranceSeconds: SECURITY_CONFIG.TIMESTAMP_TOLERANCE / 1000,
        nonceExpiryHours: SECURITY_CONFIG.NONCE_EXPIRY_TIME / (60 * 60 * 1000),
      },
    };

    res.json(status);
  } catch (error) {
    console.error(`❌ Error getting system status: ${error.message}`);
    res.status(500).json({
      success: false,
      error: "Internal server error",
    });
  }
}

/**
 * 格式化运行时间
 */
function formatUptime(seconds) {
  const days = Math.floor(seconds / (24 * 60 * 60));
  const hours = Math.floor((seconds % (24 * 60 * 60)) / (60 * 60));
  const minutes = Math.floor((seconds % (60 * 60)) / 60);
  const secs = Math.floor(seconds % 60);

  return `${days}d ${hours}h ${minutes}m ${secs}s`;
}

module.exports = {
  healthCheck,
  registerDevice,
  sendMessage,
  getDevices,
  getNonceStats,
  getSystemStatus,
};
