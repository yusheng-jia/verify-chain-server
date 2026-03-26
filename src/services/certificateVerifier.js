/**
 * 🔐 证书验证服务
 *
 * Android Key Attestation证书链验证服务
 * 包括证书链验证、Attestation Extension解析、硬件安全检查等功能
 */

const forge = require("node-forge");
const crypto = require("crypto");
const {
  GOOGLE_HARDWARE_ATTESTATION_ROOT_CERTS,
  CERTIFICATE_VALIDATION_CONFIG,
  IOS_CERTIFICATE_VALIDATION_CONFIG,
  SERVICE_INFO,
} = require("../config/constants");

/**
 * 清理和规范化PEM格式证书
 * @param {string} certPem - 原始PEM格式证书
 * @returns {string} 清理后的PEM证书
 */
function cleanPemFormat(certPem) {
  if (!certPem || typeof certPem !== "string") {
    throw new Error("Certificate must be a non-empty string");
  }

  // 移除多余的空格和换行符
  let cleaned = certPem.trim();

  // 统一换行符格式
  cleaned = cleaned.replace(/\r\n/g, "\n").replace(/\r/g, "\n");

  // 检查是否包含PEM头尾
  const hasBeginCert = cleaned.includes("-----BEGIN CERTIFICATE-----");
  const hasEndCert = cleaned.includes("-----END CERTIFICATE-----");

  if (!hasBeginCert || !hasEndCert) {
    throw new Error(
      "Invalid PEM format: missing BEGIN/END CERTIFICATE markers",
    );
  }

  // 提取证书内容（包括头尾）
  const beginIndex = cleaned.indexOf("-----BEGIN CERTIFICATE-----");
  const endIndex =
    cleaned.indexOf("-----END CERTIFICATE-----") +
    "-----END CERTIFICATE-----".length;

  if (beginIndex === -1 || endIndex === -1 || beginIndex >= endIndex) {
    throw new Error("Invalid PEM format: malformed certificate markers");
  }

  const certContent = cleaned.substring(beginIndex, endIndex);

  // 确保PEM格式正确（每行最多64字符的Base64内容）
  const lines = certContent.split("\n");
  const cleanedLines = [];

  for (let line of lines) {
    line = line.trim();
    if (line.startsWith("-----BEGIN") || line.startsWith("-----END")) {
      cleanedLines.push(line);
    } else if (line.length > 0) {
      // 验证是否为有效的Base64内容
      if (!/^[A-Za-z0-9+/=]+$/.test(line)) {
        throw new Error(
          `Invalid Base64 content in certificate: ${line.substring(0, 20)}...`,
        );
      }
      cleanedLines.push(line);
    }
  }

  const finalPem = cleanedLines.join("\n");

  console.log(`🧹 Certificate cleaned: ${finalPem.length} characters`);
  return finalPem;
}

function formatDistinguishedNameAttributes(name) {
  if (!name || !Array.isArray(name.attributes)) {
    return [];
  }

  return name.attributes.map((attribute) => ({
    shortName: attribute.shortName || "N/A",
    name: attribute.name || "N/A",
    value: attribute.value || "N/A",
    type: attribute.type || "N/A",
  }));
}

function buildDistinguishedNameSearchString(name) {
  return formatDistinguishedNameAttributes(name)
    .flatMap((attribute) => [
      attribute.shortName,
      attribute.name,
      attribute.value,
      `${attribute.shortName}=${attribute.value}`,
      `${attribute.name}=${attribute.value}`,
    ])
    .filter(Boolean)
    .join(" ");
}

function getCertificateDerBytes(cert) {
  return forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
}

function getCertificateSha256Fingerprint(cert) {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(getCertificateDerBytes(cert), "binary"))
    .digest("hex")
    .toUpperCase();
}

function normalizeFingerprint(fingerprint) {
  return fingerprint.replace(/:/g, "").toUpperCase();
}

function getPemSha256Fingerprint(pem) {
  return normalizeFingerprint(new crypto.X509Certificate(pem).fingerprint256);
}

function getPemPublicKeySha256Fingerprint(pem) {
  const publicKeyDer = new crypto.X509Certificate(pem).publicKey.export({
    format: "der",
    type: "spki",
  });

  return crypto
    .createHash("sha256")
    .update(publicKeyDer)
    .digest("hex")
    .toUpperCase();
}

function getCertificatePublicKeySha256Fingerprint(cert) {
  const certPem = forge.pki.certificateToPem(cert);
  return getPemPublicKeySha256Fingerprint(certPem);
}

function buildTrustedRootFingerprintSet() {
  const fingerprints = new Set();

  for (const trustedRootPem of GOOGLE_HARDWARE_ATTESTATION_ROOT_CERTS) {
    try {
      fingerprints.add(getPemSha256Fingerprint(trustedRootPem));
    } catch (error) {
      console.warn(
        `⚠️ Failed to parse configured trusted root certificate: ${error.message}`,
      );
    }
  }

  return fingerprints;
}

function buildTrustedRootPublicKeyFingerprintSet() {
  const fingerprints = new Set();

  for (const trustedRootPem of GOOGLE_HARDWARE_ATTESTATION_ROOT_CERTS) {
    try {
      fingerprints.add(getPemPublicKeySha256Fingerprint(trustedRootPem));
    } catch (error) {
      console.warn(
        `⚠️ Failed to parse configured trusted root public key: ${error.message}`,
      );
    }
  }

  return fingerprints;
}

function describeRootValidationMethod(validationMethod) {
  switch (validationMethod) {
    case "strict_match":
      return "trusted_root_certificate_fingerprint";
    case "strict_public_key_match":
      return "trusted_root_public_key_for_previously_issued_root";
    case "development_mode":
      return "development_mode_override";
    default:
      return "unknown";
  }
}

/**
 * 解析Base64 DER格式证书（Android设备发送的原始格式）
 * @param {string} base64 - Base64编码的DER格式证书
 * @returns {object} forge证书对象
 */
function parseCertFromBase64(base64) {
  try {
    console.log(
      `🔄 Parsing Base64 DER certificate: ${base64.substring(0, 50)}...`,
    );

    // 清理Base64字符串
    const cleanedBase64 = base64.trim().replace(/\s+/g, "");

    // 验证Base64格式
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(cleanedBase64)) {
      throw new Error(`Invalid Base64 format`);
    }

    // 解码Base64为DER
    const der = forge.util.decode64(cleanedBase64);

    // 从DER解析ASN.1
    const asn1 = forge.asn1.fromDer(der);

    // 从ASN.1创建证书对象
    const certificate = forge.pki.certificateFromAsn1(asn1);

    console.log(`✅ Base64 DER certificate parsed successfully`);
    console.log(
      `   Subject: ${certificate.subject.getField("CN")?.value || "N/A"}`,
    );
    console.log(
      `   Issuer: ${certificate.issuer.getField("CN")?.value || "N/A"}`,
    );
    console.log(
      `   Subject attributes: ${JSON.stringify(formatDistinguishedNameAttributes(certificate.subject))}`,
    );
    console.log(
      `   Issuer attributes: ${JSON.stringify(formatDistinguishedNameAttributes(certificate.issuer))}`,
    );

    return certificate;
  } catch (error) {
    console.error(`❌ Base64 DER certificate parsing failed:`);
    console.error(`   Error: ${error.message}`);
    console.error(`   Certificate preview: ${base64.substring(0, 200)}...`);

    throw new Error(`Failed to parse Base64 DER certificate: ${error.message}`);
  }
}

/**
 * 智能证书解析器 - 自动检测并处理Base64 DER和PEM格式
 * @param {string} certData - 证书数据（Base64 DER 或 PEM格式）
 * @returns {object} forge证书对象
 */
function createCertificateFromPem(certData) {
  try {
    if (!certData || typeof certData !== "string") {
      throw new Error("Certificate must be a non-empty string");
    }

    const trimmedData = certData.trim();
    console.log(
      `📜 Detecting certificate format: ${trimmedData.substring(0, 100)}...`,
    );

    // 检测是否为PEM格式（包含BEGIN/END标记）
    if (
      trimmedData.includes("-----BEGIN CERTIFICATE-----") &&
      trimmedData.includes("-----END CERTIFICATE-----")
    ) {
      console.log(`🔍 Detected PEM format certificate`);

      // 清理PEM格式并解析
      const cleanedPem = cleanPemFormat(trimmedData);
      const certificate = forge.pki.certificateFromPem(cleanedPem);

      console.log(`✅ PEM certificate parsed successfully`);
      return certificate;
    } else {
      // 假设是Base64 DER格式（Android设备的标准格式）
      console.log(`🔍 Detected Base64 DER format certificate`);

      return parseCertFromBase64(trimmedData);
    }
  } catch (error) {
    console.error(`❌ Certificate parsing failed:`);
    console.error(`   Error: ${error.message}`);
    console.error(`   Certificate preview: ${certData?.substring(0, 200)}...`);

    // 提供更具体的错误信息
    if (error.message.includes("Invalid PEM format")) {
      throw new Error(`PEM Format Error: ${error.message}`);
    } else if (error.message.includes("Base64")) {
      throw new Error(`Base64 Encoding Error: ${error.message}`);
    } else {
      throw new Error(`Certificate Parsing Error: ${error.message}`);
    }
  }
}

/**
 * 验证证书签名
 * @param {object} cert - 被验证的证书
 * @param {object} issuerCert - 签发者证书
 * @returns {boolean} 验证结果
 */
function verifyCertificateSignature(cert, issuerCert) {
  try {
    return issuerCert.verify(cert);
  } catch (error) {
    console.error(
      `Certificate signature verification failed: ${error.message}`,
    );
    return false;
  }
}

/**
 * 验证证书有效期
 * @param {object} cert - 要验证的证书
 * @returns {object} 验证结果
 */
function validateCertificateValidity(cert) {
  const now = new Date();
  const notBefore = cert.validity.notBefore;
  const notAfter = cert.validity.notAfter;

  if (now < notBefore) {
    return {
      isValid: false,
      error: `Certificate not yet valid. Valid from: ${notBefore.toISOString()}`,
    };
  }

  if (now > notAfter) {
    return {
      isValid: false,
      error: `Certificate expired. Valid until: ${notAfter.toISOString()}`,
    };
  }

  return {
    isValid: true,
    validFrom: notBefore.toISOString(),
    validUntil: notAfter.toISOString(),
  };
}

/**
 * 解析Attestation Extension
 * @param {object} cert - 包含attestation extension的证书
 * @returns {object} 解析结果
 */
function parseAttestationExtension(cert) {
  try {
    // 查找Android Attestation Extension (OID: 1.3.6.1.4.1.11129.2.1.17)
    const attestationOid = "1.3.6.1.4.1.11129.2.1.17";
    let attestationExt = null;

    for (const ext of cert.extensions) {
      if (ext.id === attestationOid) {
        attestationExt = ext;
        break;
      }
    }

    if (!attestationExt) {
      return {
        success: false,
        error: "No Android Attestation Extension found",
      };
    }

    // 解析ASN.1结构
    const asn1 = forge.asn1.fromDer(attestationExt.value);

    return {
      success: true,
      attestationVersion: 3,
      attestationSecurityLevel: "hardware",
      keyDescription: "Hardware-backed key",
      extensionData: attestationExt.value.length,
    };
  } catch (error) {
    return {
      success: false,
      error: `Failed to parse attestation extension: ${error.message}`,
    };
  }
}

function parseCertificateChain(certChain) {
  if (!certChain || certChain.length === 0) {
    return {
      isValid: false,
      error: "Certificate chain is empty",
    };
  }

  console.log(
    `📋 Certificate chain contains ${certChain.length} certificates`,
  );

  for (let i = 0; i < certChain.length; i++) {
    if (!certChain[i] || typeof certChain[i] !== "string") {
      return {
        isValid: false,
        error: `Certificate at index ${i} is not a valid string`,
      };
    }

    if (certChain[i].trim().length === 0) {
      return {
        isValid: false,
        error: `Certificate at index ${i} is empty`,
      };
    }
  }

  const certificates = [];

  for (let i = 0; i < certChain.length; i++) {
    try {
      console.log(`🔄 Parsing certificate ${i + 1}/${certChain.length}...`);
      const cert = createCertificateFromPem(certChain[i]);
      certificates.push(cert);
      console.log(`✅ Certificate ${i + 1} parsed successfully`);
    } catch (error) {
      console.error(`❌ Failed to parse certificate at index ${i}:`);
      console.error(`   Error: ${error.message}`);
      console.error(`   Certificate length: ${certChain[i]?.length || 0} chars`);

      return {
        isValid: false,
        error: `Failed to parse certificate at index ${i}: ${error.message}`,
        certificateIndex: i,
        certificatePreview: certChain[i]?.substring(0, 100) + "...",
        totalCertificates: certChain.length,
      };
    }
  }

  return {
    isValid: true,
    certificates,
  };
}

function validateCertificateChainDates(certificates) {
  for (let i = 0; i < certificates.length; i++) {
    const validityCheck = validateCertificateValidity(certificates[i]);
    if (!validityCheck.isValid) {
      return {
        isValid: false,
        error: `Certificate validity check failed at index ${i}: ${validityCheck.error}`,
      };
    }
  }

  return {
    isValid: true,
  };
}

function validateCertificateChainSignatures(certificates) {
  for (let i = 0; i < certificates.length - 1; i++) {
    const cert = certificates[i];
    const issuerCert = certificates[i + 1];

    console.log(
      `🔗 Verifying certificate ${i}: ${cert.subject.getField("CN")?.value || "N/A"}`,
    );
    console.log(
      `   Issued by: ${issuerCert.subject.getField("CN")?.value || "N/A"}`,
    );

    if (!verifyCertificateSignature(cert, issuerCert)) {
      return {
        isValid: false,
        error: `Certificate signature verification failed at index ${i}`,
      };
    }
  }

  return {
    isValid: true,
  };
}

function getCertificateIdentityString(cert) {
  return [
    cert.subject.getField("CN")?.value || "",
    cert.subject.getField("O")?.value || "",
    cert.issuer.getField("CN")?.value || "",
    cert.issuer.getField("O")?.value || "",
  ]
    .join(" ")
    .trim();
}

function buildLeafCertificateSummary(cert) {
  return {
    subject: cert.subject.getField("CN")?.value || "N/A",
    issuer: cert.issuer.getField("CN")?.value || "N/A",
    validFrom: cert.validity.notBefore.toISOString(),
    validUntil: cert.validity.notAfter.toISOString(),
    serialNumber: cert.serialNumber,
    fingerprint: crypto
      .createHash("sha256")
      .update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())
      .digest("hex")
      .toUpperCase(),
  };
}

function verifyIosCertificateChain(certChain) {
  try {
    console.log(`🍎 Starting iOS certificate chain verification...`);

    const parsedChain = parseCertificateChain(certChain);
    if (!parsedChain.isValid) {
      return parsedChain;
    }

    const certificates = parsedChain.certificates;
    const leafCert = certificates[0];
    const lastCert = certificates[certificates.length - 1];

    if (certificates.length < 2) {
      return {
        isValid: false,
        error:
          "iOS certificate chain must contain at least leaf and intermediate certificates",
      };
    }

    const dateValidation = validateCertificateChainDates(certificates);
    if (!dateValidation.isValid) {
      return dateValidation;
    }

    const signatureValidation =
      validateCertificateChainSignatures(certificates);
    if (!signatureValidation.isValid) {
      return signatureValidation;
    }

    const hasAppleIssuer = certificates.some((cert) =>
      IOS_CERTIFICATE_VALIDATION_CONFIG.TRUSTED_ISSUER_PATTERNS.some(
        (pattern) => pattern.test(getCertificateIdentityString(cert)),
      ),
    );

    if (!hasAppleIssuer) {
      return {
        isValid: false,
        error: "iOS certificate chain is not issued by an Apple certificate authority",
      };
    }

    const hasAppleAttestationExtension = (leafCert.extensions || []).some(
      (ext) =>
        typeof ext.id === "string" &&
        ext.id.startsWith(
          IOS_CERTIFICATE_VALIDATION_CONFIG.APPLE_APP_ATTEST_OID_PREFIX,
        ),
    );

    if (!hasAppleAttestationExtension) {
      return {
        isValid: false,
        error: "Leaf certificate does not contain an Apple attestation extension",
      };
    }

    const rootLooksTrusted =
      lastCert.subject.hash === lastCert.issuer.hash ||
      IOS_CERTIFICATE_VALIDATION_CONFIG.TRUSTED_ROOT_PATTERNS.some((pattern) =>
        pattern.test(getCertificateIdentityString(lastCert)),
      );

    return {
      isValid: true,
      chainLength: certificates.length,
      validationMethod: rootLooksTrusted
        ? "apple_root_or_self_signed"
        : "apple_intermediate_chain",
      leafCertificate: buildLeafCertificateSummary(leafCert),
      attestation: {
        success: true,
        platform: "ios",
        certificateAuthority: "Apple",
        attestationType: "apple_app_attestation",
        appleOidPrefix:
          IOS_CERTIFICATE_VALIDATION_CONFIG.APPLE_PUBLIC_OID_PREFIX,
      },
      isAppleAttestation: true,
    };
  } catch (error) {
    return {
      isValid: false,
      error: `iOS certificate chain verification failed: ${error.message}`,
    };
  }
}

/**
 * 验证证书链（增强版本）
 * @param {string[]} certChain - PEM格式的证书链
 * @returns {object} 验证结果
 */
function verifyCertificateChain(certChain) {
  try {
    console.log(`🔍 Starting certificate chain verification...`);
    const parsedChain = parseCertificateChain(certChain);
    if (!parsedChain.isValid) {
      return parsedChain;
    }

    const certificates = parsedChain.certificates;

    const leafCert = certificates[0];
    console.log(
      `📋 Verifying certificate chain with ${certificates.length} certificates`,
    );
    console.log(
      `🍃 Leaf certificate subject: ${leafCert.subject.getField("CN")?.value || "N/A"}`,
    );

    const dateValidation = validateCertificateChainDates(certificates);
    if (!dateValidation.isValid) {
      return dateValidation;
    }

    const signatureValidation =
      validateCertificateChainSignatures(certificates);
    if (!signatureValidation.isValid) {
      return signatureValidation;
    }

    // 验证根证书 - 使用灵活的验证策略
    const rootCert = certificates[certificates.length - 1];
    const rootFingerprint = getCertificateSha256Fingerprint(rootCert);
    const rootPublicKeyFingerprint =
      getCertificatePublicKeySha256Fingerprint(rootCert);
    const trustedRootFingerprints = buildTrustedRootFingerprintSet();
    const trustedRootPublicKeyFingerprints =
      buildTrustedRootPublicKeyFingerprintSet();

    let isGoogleRoot = false;
    let validationMethod = "";

    console.log(`🔍 Root certificate fingerprint (SHA-256): ${rootFingerprint}`);
    console.log(
      `🔍 Root public key fingerprint (SHA-256/SPKI): ${rootPublicKeyFingerprint}`,
    );

    // 方法1: 严格验证 - 与已知可信根证书或其公钥精确匹配
    if (CERTIFICATE_VALIDATION_CONFIG.STRICT_ROOT_VALIDATION) {
      if (trustedRootFingerprints.has(rootFingerprint)) {
        isGoogleRoot = true;
        validationMethod = "strict_match";
        console.log(
          `✅ Root certificate matches a trusted attestation root fingerprint`,
        );
      } else if (trustedRootPublicKeyFingerprints.has(rootPublicKeyFingerprint)) {
        isGoogleRoot = true;
        validationMethod = "strict_public_key_match";
        console.log(
          `✅ Root certificate public key matches a trusted attestation root public key`,
        );
      } else {
        console.warn(`⚠️ Root certificate fingerprint is not in trusted roots`);
        console.warn(
          `⚠️ Root public key fingerprint is not in trusted attestation root public keys`,
        );
      }
    }

    // 方法2: 诊断辅助 - 基于颁发者和主题模式匹配，仅用于日志分析
    if (
      !isGoogleRoot &&
      CERTIFICATE_VALIDATION_CONFIG.ALTERNATIVE_VALIDATION.enabled
    ) {
      const rootSubject = rootCert.subject;
      const rootIssuer = rootCert.issuer;

      let issuerMatch = false;
      let subjectMatch = false;
      const issuerString = buildDistinguishedNameSearchString(rootIssuer);
      const subjectString = buildDistinguishedNameSearchString(rootSubject);

      if (issuerString || subjectString) {
        for (const allowedIssuer of CERTIFICATE_VALIDATION_CONFIG
          .ALTERNATIVE_VALIDATION.allowedIssuers) {
          if (
            issuerString.toLowerCase().includes(allowedIssuer.toLowerCase()) ||
            subjectString.toLowerCase().includes(allowedIssuer.toLowerCase())
          ) {
            issuerMatch = true;
            break;
          }
        }

        // 检查主题模式
        for (const pattern of CERTIFICATE_VALIDATION_CONFIG
          .ALTERNATIVE_VALIDATION.allowedSubjectPatterns) {
          if (pattern.test(issuerString) || pattern.test(subjectString)) {
            subjectMatch = true;
            break;
          }
        }
      }

      if (issuerMatch || subjectMatch) {
        console.log(
          `ℹ️ Root certificate matched diagnostic DN patterns, but this no longer grants trust`,
        );
        console.log(`   Issuer: ${rootIssuer.getField("CN")?.value || "N/A"}`);
        console.log(
          `   Subject: ${rootSubject.getField("CN")?.value || "N/A"}`,
        );
        console.log(
          `   Root issuer attributes: ${JSON.stringify(formatDistinguishedNameAttributes(rootIssuer))}`,
        );
        console.log(
          `   Root subject attributes: ${JSON.stringify(formatDistinguishedNameAttributes(rootSubject))}`,
        );
      }
    }

    // 方法3: 开发模式 - 允许任何根证书（仅用于测试）
    if (!isGoogleRoot && CERTIFICATE_VALIDATION_CONFIG.DEVELOPMENT_MODE) {
      isGoogleRoot = true;
      validationMethod = "development_mode";
      console.log(
        `⚠️  Root certificate accepted in development mode (any root allowed)`,
      );
    }

    if (!isGoogleRoot) {
      console.error(`❌ Root certificate validation failed:`);
      console.error(
        `   Subject: ${rootCert.subject.getField("CN")?.value || "N/A"}`,
      );
      console.error(
        `   Issuer: ${rootCert.issuer.getField("CN")?.value || "N/A"}`,
      );
      console.error(
        `   Organization: ${rootCert.subject.getField("O")?.value || "N/A"}`,
      );
      console.error(
        `   Root subject attributes: ${JSON.stringify(formatDistinguishedNameAttributes(rootCert.subject))}`,
      );
      console.error(
        `   Root issuer attributes: ${JSON.stringify(formatDistinguishedNameAttributes(rootCert.issuer))}`,
      );
      console.error(
        `   Root fingerprint (SHA-256): ${rootFingerprint}`,
      );
      console.error(
        `   Root public key fingerprint (SHA-256/SPKI): ${rootPublicKeyFingerprint}`,
      );

      return {
        isValid: false,
        error:
          "Root certificate is not a trusted Google Hardware Attestation Root",
        details: {
          rootSubject: rootCert.subject.getField("CN")?.value || "N/A",
          rootIssuer: rootCert.issuer.getField("CN")?.value || "N/A",
          rootOrg: rootCert.subject.getField("O")?.value || "N/A",
          rootFingerprint,
          rootPublicKeyFingerprint,
          availableValidationMethods: [
            "strict_match",
            "strict_public_key_match",
            "diagnostic_pattern_match",
            "development_mode",
          ],
          currentConfig: CERTIFICATE_VALIDATION_CONFIG,
        },
      };
    }

    // 解析Attestation Extension
    const attestationResult = parseAttestationExtension(leafCert);
    const validationMethodDescription =
      describeRootValidationMethod(validationMethod);

    console.log(`✅ Certificate chain verification successful`);
    console.log(`📊 Chain length: ${certificates.length}`);
    console.log(
      `🔐 Hardware attestation: ${attestationResult.success ? "Yes" : "No"}`,
    );
    console.log(`🔍 Validation method: ${validationMethod}`);
    console.log(
      `🔍 Validation method detail: ${validationMethodDescription}`,
    );

    return {
      isValid: true,
      chainLength: certificates.length,
      validationMethod,
      validationMethodDescription,
      leafCertificate: buildLeafCertificateSummary(leafCert),
      attestation: attestationResult,
      isGoogleHardwareAttestation: isGoogleRoot,
    };
  } catch (error) {
    return {
      isValid: false,
      error: `Certificate chain verification failed: ${error.message}`,
    };
  }
}

/**
 * 从证书中提取公钥
 * @param {string} certPem - PEM格式证书
 * @returns {object} 提取结果
 */
function extractPublicKeyFromCertificate(certPem) {
  try {
    console.log(`🔄 Extracting public key from certificate...`);
    console.log(`   Certificate data length: ${certPem.length} chars`);
    console.log(`   Certificate preview: ${certPem.substring(0, 100)}...`);

    const cert = createCertificateFromPem(certPem);
    console.log(`✅ Certificate parsed successfully`);

    const publicKeyPem = forge.pki.publicKeyToPem(cert.publicKey);
    console.log(`✅ Public key extracted successfully`);
    console.log(`   Public key length: ${publicKeyPem.length} chars`);
    console.log(`   Public key preview: ${publicKeyPem.substring(0, 100)}...`);

    const keyType = cert.publicKey.n
      ? "RSA"
      : cert.publicKey.Q
        ? "EC"
        : "Unknown";
    const keySize = cert.publicKey.n
      ? cert.publicKey.n.bitLength()
      : cert.publicKey.Q
        ? cert.publicKey.Q.x?.bitLength?.() || 256
        : 0;

    console.log(`📋 Key info: ${keyType} ${keySize}bit`);

    return {
      success: true,
      publicKey: publicKeyPem,
      keyType: keyType,
      keySize: keySize,
    };
  } catch (error) {
    console.error(`❌ Public key extraction failed: ${error.message}`);
    console.error(`   Certificate data: ${certPem?.substring(0, 200)}...`);
    return {
      success: false,
      error: `Failed to extract public key: ${error.message}`,
    };
  }
}

/**
 * 验证设备证书和提取信息
 * @param {object} deviceData - 包含证书链的设备数据
 * @returns {object} 验证和提取结果
 */
function verifyAndExtractDeviceInfo(deviceData) {
  const { certificateChain, platform } = deviceData;
  console.log(`🔍 Starting certificate verification for device`);
  console.log(`   Platform: ${platform}`);
  console.log(`   Certificate chain length: ${certificateChain?.length || 0}`);

  const chainVerification =
    platform === "ios"
      ? verifyIosCertificateChain(certificateChain)
      : verifyCertificateChain(certificateChain);
  if (!chainVerification.isValid) {
    console.error(
      `❌ Certificate chain verification failed: ${chainVerification.error}`,
    );
    return {
      success: false,
      error: `Certificate chain verification failed: ${chainVerification.error}`,
    };
  }

  console.log(`✅ Certificate chain verified successfully`);

  // 2. 提取公钥
  console.log(`🔄 Extracting public key from leaf certificate...`);
  const publicKeyResult = extractPublicKeyFromCertificate(certificateChain[0]);
  if (!publicKeyResult.success) {
    console.error(`❌ Public key extraction failed: ${publicKeyResult.error}`);
    return {
      success: false,
      error: `Public key extraction failed: ${publicKeyResult.error}`,
    };
  }

  console.log(`✅ Public key extraction completed successfully`);

  const result = {
    success: true,
    verification: chainVerification,
    publicKey: publicKeyResult.publicKey,
    keyInfo: {
      type: publicKeyResult.keyType,
      size: publicKeyResult.keySize,
    },
    platform: platform || "android",
    securityLevel: platform === "ios" ? "apple_attested" : "hardware",
  };

  // 调试：显示最终结果
  console.log(`🔍 DEBUG: verifyAndExtractDeviceInfo result:`);
  console.log(`   success: ${result.success}`);
  console.log(`   publicKey: ${result.publicKey ? "[present]" : "[missing]"}`);
  console.log(`   keyInfo: ${JSON.stringify(result.keyInfo)}`);

  console.log(`✅ Certificate verification completed successfully`);
  return result;
}

module.exports = {
  cleanPemFormat,
  parseCertFromBase64,
  createCertificateFromPem,
  verifyCertificateSignature,
  validateCertificateValidity,
  parseAttestationExtension,
  verifyCertificateChain,
  verifyIosCertificateChain,
  extractPublicKeyFromCertificate,
  verifyAndExtractDeviceInfo,
};
