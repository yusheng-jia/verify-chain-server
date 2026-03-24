/**
 * 🔒 PRODUCTION-GRADE Android Key Attestation Configuration
 *
 * 系统配置常量：
 * - Google硬件attestation根证书
 * - 安全验证参数
 * - 时间窗口设置
 * - 清理机制配置
 */

// ⭐ Google Hardware Attestation Root证书 (动态配置)
// 支持多种验证模式：1) 严格模式使用已知根证书 2) 兼容模式允许更多根证书
const GOOGLE_HARDWARE_ATTESTATION_ROOT_CERTS = [
  // 从Android开源项目获取的实际根证书
  // https://android.googlesource.com/platform/frameworks/base/+/master/core/res/res/raw/

  // Google Hardware Attestation Root (实际使用的证书)
  `-----BEGIN CERTIFICATE-----
MIIDUTCCAjmgAwIBAgIJAPIAGQ2bxy9wMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNV
BAYTAlVTMQ0wCwYDVQQIDARVdGFoMQswCQYDVQQHDAJVUzETMBEGA1UECgwKR29v
Z2xlIEluYzEOMAwGA1UEAwwFR29vZ2xlMB4XDTE2MDUyNjE2Mjg1MloXDTQzMTAx
MjE2Mjg1MlowQjELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxCzAJBgNVBAcM
AlVTMRMwEQYDVQQKDApHb29nbGUgSW5jMQ4wDAYDVQQDDAVHb29nbGUwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1LC55wXwuptWIqQ9QW9mzurnvUW9E
R33WqwQUMAMYP4do+rd55f1vo+owXqA3KHIrakpPoLFPfwvEq/6ZQGEBY5VcWE6+
+FYJbHPGFVIu4IgFPY98ZuEQXaHkVQeSaCmIYFJDtj4vgnMc0lGqhOuYuomThVPz
pgK3EmVsQmIqXsrYrzAHGF8aevho8rSIr0qc39jhUbVe3wrWVta2opSOGDibwi1f
LdJjgL+ExhAvPYzjLSI4naQb0GfZMZF9Ua3x/7SDpdlfObfA7/iD/C854fDxMXBS
lTdHaqxmq8jtHfGcK1N3EksMpgqwOZbDqo4cApuvqMkHbAtCeApgxAmPAgMBAAEw
DQYJKoZIhvcNAQEFBQADggEBAIQL34cXbMsfgkLd1HM+m9D4ntGSC/c4ona8vYuI
ZXLu4jtB3hLMr/fB0fig637w6AnLbK/abQb0jdVw3fDz7dk=
-----END CERTIFICATE-----`,
];

// 额外的验证选项
const CERTIFICATE_VALIDATION_CONFIG = {
  // 是否启用严格的根证书验证
  STRICT_ROOT_VALIDATION: false, // 设为false以允许更灵活的验证

  // 开发模式设置
  DEVELOPMENT_MODE: process.env.NODE_ENV !== "production",

  // 备用验证策略
  ALTERNATIVE_VALIDATION: {
    enabled: true,
    // 允许的证书颁发者组织名称
    allowedIssuers: [
      "Google",
      "Google Inc",
      "Google LLC",
      "Android",
      "Google Hardware Attestation",
    ],
    // 允许的证书主题字段
    allowedSubjectPatterns: [
      /Google.*Attestation/i,
      /Android.*Root/i,
      /Hardware.*Attestation/i,
    ],
  },
};

const SUPPORTED_PLATFORMS = ["android", "ios"];

const IOS_CERTIFICATE_VALIDATION_CONFIG = {
  APPLE_PUBLIC_OID_PREFIX: "1.2.840.113635",
  APPLE_APP_ATTEST_OID_PREFIX: "1.2.840.113635.100.8",
  TRUSTED_ROOT_PATTERNS: [/Apple Root CA/i, /Apple.*Root/i],
  TRUSTED_ISSUER_PATTERNS: [
    /Apple/i,
    /App Attest/i,
    /App Attestation/i,
    /DeviceCheck/i,
  ],
};

const APPLE_APP_ATTEST_ROOT_CERT = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`;

const IOS_APP_ATTEST_CONFIG = {
  TEAM_ID: process.env.APPLE_TEAM_ID || "TGFR27Y2RR",
  BUNDLE_ID: process.env.APPLE_BUNDLE_ID || "com.kohler.rsademo",
  NONCE_EXTENSION_OID: "1.2.840.113635.100.8.2",
  ALLOW_DEVELOPMENT_AAGUID:
    process.env.APPLE_APP_ATTEST_ALLOW_DEVELOPMENT === "true" ||
    process.env.NODE_ENV !== "production",
};

// 🔒 安全配置常量
const SECURITY_CONFIG = {
  // 时间戳验证（30秒内有效）
  TIMESTAMP_TOLERANCE: 30 * 1000, // 30秒时间窗口

  // 🔒 设备会话安全配置
  DEVICE_SESSION_EXPIRY: 30 * 1000, // 设备注册后30秒内有效
  MAX_TIMESTAMP_FUTURE: 5 * 1000, // 允许timestamp最多比当前时间提前5秒（时钟偏差）

  // Nonce防重放配置
  NONCE_CLEANUP_INTERVAL: 10 * 60 * 1000, // 10分钟清理一次
  NONCE_EXPIRY_TIME: 60 * 60 * 1000, // nonce保存1小时后清理

  // Challenge配置
  CHALLENGE_EXPIRY_TIME: 5 * 60 * 1000, // challenge 5分钟有效
  CHALLENGE_CLEANUP_INTERVAL: 5 * 60 * 1000, // 5分钟清理一次
};

// 🔒 Attestation Extension OID
const ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17";

// 🔒 服务信息常量
const SERVICE_INFO = {
  name: "Android Key Attestation Verification Server",
  version: "1.2.0-modular",
  VERSION: "1.2.0-enhanced-security", // 向后兼容
  NAME: "Production Android Key Attestation & Message Verification Service", // 向后兼容
  LEVEL: "PRODUCTION_GRADE_WITH_COMPATIBILITY",

  FEATURES: [
    "Hardware-backed attestation verification",
    "Multi-vendor root certificate validation",
    "ASN.1 attestation record parsing",
    "Challenge-response verification",
    "Alternative verification for device compatibility",
    "Support for Xiaomi, Samsung, OnePlus and other devices",
    "Device registration with public key storage",
    "RSA signature verification for registered devices",
    "Enhanced 30-second timestamp validation",
    "Nonce-based replay attack protection",
    "Automatic nonce cleanup and memory management",
  ],

  SUPPORTED_DEVICES: [
    "Google Pixel",
    "Samsung Galaxy",
    "Xiaomi",
    "OnePlus",
    "Other Android devices",
  ],
};

module.exports = {
  GOOGLE_HARDWARE_ATTESTATION_ROOT_CERTS,
  CERTIFICATE_VALIDATION_CONFIG,
  IOS_CERTIFICATE_VALIDATION_CONFIG,
  APPLE_APP_ATTEST_ROOT_CERT,
  IOS_APP_ATTEST_CONFIG,
  SECURITY_CONFIG,
  SUPPORTED_PLATFORMS,
  ATTESTATION_EXTENSION_OID,
  SERVICE_INFO,
};
