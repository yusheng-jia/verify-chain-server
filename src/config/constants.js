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
  // Google 官方 machine-readable trust anchors:
  // https://android.googleapis.com/attestation/root
  `-----BEGIN CERTIFICATE-----
MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw
NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS
Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7
tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj
nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq
C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ
oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O
JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg
sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi
igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M
RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E
aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um
AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud
IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7
174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC
W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G
tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx
oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG
1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF
mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz
lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw
n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu
zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo
vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn
w1IdYIg2Wxg7yHcQZemFQg==
-----END CERTIFICATE-----`,
  `-----BEGIN CERTIFICATE-----
MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc
MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET
MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4
WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex
MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG
EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt
G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5
Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA
MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH
EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY
uR2zh/80lQyu9vAFCj6E4AXc+osmRg==
-----END CERTIFICATE-----`,
];

// 额外的验证选项
const CERTIFICATE_VALIDATION_CONFIG = {
  // 是否启用严格的根证书验证
  STRICT_ROOT_VALIDATION: true, // 设为false以允许更灵活的验证

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
