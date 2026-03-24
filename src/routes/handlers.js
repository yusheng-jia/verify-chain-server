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
const challengeManager = require("../services/challengeManager");
const nonceManager = require("../services/nonceManager");
const certificateVerifier = require("../services/certificateVerifier");
const iosAppAttestService = require("../services/iosAppAttestService");
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

function issueChallenge(req, res) {
  try {
    const { deviceId, platform, purpose = "register" } = req.body || {};
    const normalizedPlatform =
      typeof platform === "string" ? platform.toLowerCase() : platform;

    if (!deviceId || typeof deviceId !== "string") {
      return res.status(400).json({
        success: false,
        error: "deviceId is required and must be a string",
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

    const challengeRecord = challengeManager.issueChallenge({
      deviceId,
      platform: normalizedPlatform,
      purpose,
    });

    return res.json({
      success: true,
      deviceId,
      platform: normalizedPlatform,
      purpose,
      challenge: challengeRecord.challenge,
      issuedAt: new Date(challengeRecord.issuedAt).toISOString(),
      expiresAt: new Date(challengeRecord.expiresAt).toISOString(),
      expiresInMs: challengeRecord.expiresAt - challengeRecord.issuedAt,
    });
  } catch (error) {
    console.error(`❌ Challenge issue error: ${error.message}`);
    return res.status(500).json({
      success: false,
      error: "Internal server error during challenge issue",
    });
  }
}

/**
 * 设备注册端点（兼容原API格式）
 */
function registerDevice(req, res) {
  try {
    // 兼容原有的certChain格式和新的certificateChain格式
    const {
      deviceId,
      platform,
      certificateChain,
      certChain,
      challenge,
      keyId,
      attestationObject,
    } = req.body;

    const normalizedPlatform =
      typeof platform === "string" ? platform.toLowerCase() : platform;

    // 确定使用哪个证书链参数（优先使用certChain以保持向后兼容性）
    const actualCertChain = certChain || certificateChain;

    console.log(`📱 Device registration request: ${deviceId}`);

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

    // 检查设备是否已注册（允许重复注册以更新参数）
    const existingDevice = deviceStorage.getDeviceInfo(deviceId);
    const isUpdate = !!existingDevice;
    if (existingDevice) {
      console.log(`🔄 Device already exists, will update: ${deviceId}`);
    }

    let verificationResult;

    if (normalizedPlatform === "ios") {
      const challengeValidation = challengeManager.validateChallenge({
        deviceId,
        platform: normalizedPlatform,
        challenge,
      });

      if (!challengeValidation.isValid) {
        return res.status(400).json({
          success: false,
          error: challengeValidation.error,
          platform: "ios",
          step: "challenge_validation",
        });
      }

      const iosValidation = iosAppAttestService.validateRegistrationParams({
        keyId,
        challenge,
        attestationObject,
      });

      if (!iosValidation.isValid) {
        return res.status(400).json({
          success: false,
          error: "Invalid iOS registration parameters",
          details: iosValidation.errors,
        });
      }

      let iosRegistrationRecord;
      try {
        iosRegistrationRecord = iosAppAttestService.verifyAttestation({
          keyId,
          challenge,
          attestationObject,
        });

        console.log(`🍎 iOS attestation verification succeeded: ${deviceId}`);
      } catch (error) {
        console.error(
          `❌ iOS attestation verification failed for device ${deviceId}: ${error.message}`,
        );

        return res.status(400).json({
          success: false,
          error: error.message,
          platform: "ios",
          step: "attestation_verification",
        });
      }

      verificationResult = {
        success: true,
        verification: {
          attestation: iosRegistrationRecord.attestation,
          leafCertificate: iosRegistrationRecord.certificateInfo,
        },
        publicKey: iosRegistrationRecord.publicKey,
        attestationCertificatePublicKey:
          iosRegistrationRecord.attestationCertificatePublicKey,
        keyInfo: iosRegistrationRecord.keyInfo,
        securityLevel: iosRegistrationRecord.securityLevel,
        assertionCounter: iosRegistrationRecord.assertionCounter,
      };

      challengeManager.consumeChallenge({
        deviceId,
        platform: normalizedPlatform,
      });
    } else {
      if (!challenge || typeof challenge !== "string") {
        return res.status(400).json({
          success: false,
          error: "challenge is required for Android registration",
          platform: normalizedPlatform,
          step: "challenge_validation",
        });
      }

      const androidChallengeValidation = challengeManager.validateChallenge({
        deviceId,
        platform: normalizedPlatform,
        challenge,
      });

      if (!androidChallengeValidation.isValid) {
        return res.status(400).json({
          success: false,
          error: androidChallengeValidation.error,
          platform: normalizedPlatform,
          step: "challenge_validation",
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

      verificationResult = certificateVerifier.verifyAndExtractDeviceInfo({
        platform: normalizedPlatform,
        certificateChain: actualCertChain,
      });

      challengeManager.consumeChallenge({
        deviceId,
        platform: normalizedPlatform,
      });
    }

    if (!verificationResult.success) {
      console.error(
        `❌ Certificate verification failed for ${deviceId}: ${verificationResult.error}`,
      );

      const errorResponse = {
        success: false,
        error: verificationResult.error,
        deviceId: deviceId,
        platform: normalizedPlatform,
        certificateChainLength: actualCertChain?.length,
      };

      if (verificationResult.certificateIndex !== undefined) {
        errorResponse.failedCertificateIndex =
          verificationResult.certificateIndex;
        errorResponse.totalCertificates = verificationResult.totalCertificates;
      }

      if (verificationResult.certificatePreview) {
        errorResponse.certificatePreview =
          verificationResult.certificatePreview;
      }

      return res.status(400).json(errorResponse);
    }

    // 存储设备信息
    const deviceInfo = {
      deviceId: deviceId,
      platform: normalizedPlatform,
      keyId: normalizedPlatform === "ios" ? keyId : undefined,
      publicKey: verificationResult.publicKey,
      attestationCertificatePublicKey:
        normalizedPlatform === "ios"
          ? verificationResult.attestationCertificatePublicKey
          : undefined,
      certificateChain:
        normalizedPlatform === "android" ? actualCertChain : undefined,
      challenge: normalizedPlatform === "ios" ? challenge : undefined,
      attestationObject:
        normalizedPlatform === "ios" ? attestationObject : undefined,
      keyInfo: verificationResult.keyInfo,
      securityLevel: verificationResult.securityLevel,
      attestation: verificationResult.verification.attestation,
      assertionCounter:
        normalizedPlatform === "ios" ? verificationResult.assertionCounter : 0,
      certificateInfo: verificationResult.verification.leafCertificate,
      registrationTime: new Date().toISOString(),
    };

    deviceStorage.storeDeviceInfo(deviceId, deviceInfo);

    const actionType = isUpdate ? "updated" : "registered";
    console.log(`✅ Device ${actionType} successfully: ${deviceId}`);
    console.log(`🔐 Security level: ${deviceInfo.securityLevel}`);
    console.log(
      `📋 Key info: ${deviceInfo.keyInfo.type} ${deviceInfo.keyInfo.size}bit`,
    );
    if (isUpdate && existingDevice) {
      console.log(`📊 Registration updated: ${deviceInfo.registrationTime}`);
    }

    res.json({
      success: true,
      deviceId: deviceId,
      platform: normalizedPlatform,
      keyId: normalizedPlatform === "ios" ? keyId : undefined,
      action: isUpdate ? "updated" : "registered",
      registrationTime: deviceInfo.registrationTime,
      previousRegistrationTime: isUpdate
        ? existingDevice.registrationTime
        : undefined,
      securityLevel: deviceInfo.securityLevel,
      keyInfo: deviceInfo.keyInfo,
      verificationMode:
        normalizedPlatform === "ios"
          ? "ios_app_attest"
          : "android_attestation_certificate_chain",
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
    const {
      deviceId,
      platform,
      phone,
      timestamp,
      nonce,
      signature,
      keyId,
      assertion,
    } = req.body;
    const normalizedPlatform =
      typeof platform === "string" ? platform.toLowerCase() : platform;

    console.log(
      `📨 Message verification request from device: ${deviceId}, platform: ${normalizedPlatform}, phone: ${phone}`,
    );

    const commonParamValidation = signatureVerifier.validateSignatureParams({
      phone,
      timestamp,
      nonce,
      signature:
        normalizedPlatform === "ios" ? "ios_assertion_placeholder" : signature,
    });

    if (!commonParamValidation.isValid) {
      return res.status(400).json({
        success: false,
        error: "Invalid parameters",
        details: commonParamValidation.errors,
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

    if (normalizedPlatform === "ios") {
      const iosValidation = iosAppAttestService.validateAssertionParams({
        keyId,
        assertion,
      });

      if (!iosValidation.isValid) {
        return res.status(400).json({
          success: false,
          error: "Invalid iOS message parameters",
          details: iosValidation.errors,
        });
      }

      if (deviceInfo.keyId && deviceInfo.keyId !== keyId) {
        return res.status(400).json({
          success: false,
          error: "keyId does not match the registered iOS device",
          registeredKeyId: deviceInfo.keyId,
          requestKeyId: keyId,
        });
      }

      if (!deviceInfo.publicKey) {
        return res.status(400).json({
          success: false,
          error: "Registered iOS device is missing App Attest public key",
        });
      }

      let iosVerification;
      try {
        iosVerification = iosAppAttestService.verifyAssertion({
          keyId,
          assertion,
          phone,
          timestamp,
          nonce,
          publicKey: deviceInfo.publicKey,
          attestationCertificatePublicKey:
            deviceInfo.attestationCertificatePublicKey,
          previousCounter: deviceInfo.assertionCounter || 0,
        });
      } catch (error) {
        return res.status(400).json({
          success: false,
          error: error.message,
          platform: "ios",
          step: "assertion_verification",
        });
      }

      deviceStorage.updateDeviceInfo(deviceId, {
        assertionCounter: iosVerification.signCount,
      });

      const response = {
        success: true,
        deviceId,
        platform: "ios",
        keyId,
        phone,
        timestamp: new Date(timestamp).toISOString(),
        nonce,
        verification: {
          assertionValid: true,
          timestampValid: true,
          nonceValid: true,
          securityLevel: deviceInfo.securityLevel,
          assertionCounter: iosVerification.signCount,
          verificationMode: iosVerification.verificationMode,
        },
        verificationTime: new Date().toISOString(),
      };

      res.json(response);

      console.log(`📊 Verification summary:`);
      console.log(`   Device: ${deviceId}`);
      console.log(`   Phone: ${phone}`);
      console.log(`   Security Level: ${deviceInfo.securityLevel}`);
      console.log(`   Verification Time: ${response.verificationTime}`);

      return;
    }

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
  issueChallenge,
  registerDevice,
  sendMessage,
  getDevices,
  getNonceStats,
  getSystemStatus,
};
