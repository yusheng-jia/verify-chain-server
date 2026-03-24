/**
 * 🍎 iOS App Attest 服务
 *
 * 基于 Apple App Attest 的后端验证流程：
 * - register: 验证 attestationObject 并提取公钥
 * - sendMessage: 验证 assertion 签名与计数器
 */

const crypto = require("crypto");
const cbor = require("cbor");
const forge = require("node-forge");
const {
  APPLE_APP_ATTEST_ROOT_CERT,
  IOS_APP_ATTEST_CONFIG,
} = require("../config/constants");

const APP_ATTEST_PRODUCTION_AAGUID = Buffer.from(
  "appattest\0\0\0\0\0\0\0",
  "binary",
);
const APP_ATTEST_DEVELOPMENT_AAGUID = Buffer.from("appattestdevelop", "binary");

function validateRegistrationParams(params) {
  const { keyId, challenge, attestationObject } = params;
  const errors = [];

  if (!keyId || typeof keyId !== "string") {
    errors.push("keyId is required and must be a string");
  }

  if (!challenge || typeof challenge !== "string") {
    errors.push("challenge is required and must be a string");
  }

  if (!attestationObject || typeof attestationObject !== "string") {
    errors.push("attestationObject is required and must be a string");
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
}

function validateAssertionParams(params) {
  const { keyId, assertion } = params;
  const errors = [];

  if (!keyId || typeof keyId !== "string") {
    errors.push("keyId is required and must be a string");
  }

  if (!assertion || typeof assertion !== "string") {
    errors.push("assertion is required and must be a string");
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
}

function getAppId() {
  const { TEAM_ID, BUNDLE_ID } = IOS_APP_ATTEST_CONFIG;
  if (!TEAM_ID || !BUNDLE_ID) {
    throw new Error(
      "APPLE_TEAM_ID and APPLE_BUNDLE_ID must be configured for iOS App Attest verification",
    );
  }

  return `${TEAM_ID}.${BUNDLE_ID}`;
}

function sha256(data) {
  return crypto.createHash("sha256").update(data).digest();
}

function base64UrlToBuffer(value) {
  return base64UrlDecodeToBuffer(value);
}

function decodeClientChallenge(challenge) {
  try {
    return Buffer.from(challenge, "base64");
  } catch {
    return Buffer.from(challenge, "utf8");
  }
}

function ensureBuffer(value) {
  if (Buffer.isBuffer(value)) {
    return value;
  }

  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }

  throw new Error("Expected binary buffer value");
}

function bufferToPem(buffer, label = "CERTIFICATE") {
  const chunks = buffer.toString("base64").match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${chunks.join("\n")}\n-----END ${label}-----`;
}

function verifyCertificateSignature(cert, issuerCert) {
  try {
    return cert.verify(issuerCert.publicKey);
  } catch {
    return false;
  }
}

function verifyCertificateDates(certificates) {
  const now = Date.now();
  for (const cert of certificates) {
    const validFrom = Date.parse(cert.validFrom);
    const validTo = Date.parse(cert.validTo);
    if (now < validFrom || now > validTo) {
      throw new Error("App Attest certificate is not currently valid");
    }
  }
}

function verifyCertificateChain(x5cBuffers) {
  const certs = x5cBuffers.map(
    (buffer) => new crypto.X509Certificate(bufferToPem(buffer)),
  );
  const appleRoot = new crypto.X509Certificate(APPLE_APP_ATTEST_ROOT_CERT);

  verifyCertificateDates(certs);

  for (let i = 0; i < certs.length - 1; i++) {
    if (!certs[i].checkIssued(certs[i + 1])) {
      throw new Error(
        `App Attest certificate chain issuer mismatch at index ${i}`,
      );
    }
    if (!verifyCertificateSignature(certs[i], certs[i + 1])) {
      throw new Error(
        `App Attest certificate chain verification failed at index ${i}`,
      );
    }
  }

  if (!verifyCertificateSignature(certs[certs.length - 1], appleRoot)) {
    throw new Error(
      "App Attest certificate chain is not rooted in Apple App Attestation Root CA",
    );
  }

  return {
    leaf: certs[0],
    intermediate: certs[1],
    root: appleRoot,
    leafPem: bufferToPem(x5cBuffers[0]),
    leafDer: x5cBuffers[0],
  };
}

function readUInt16BE(buffer, offset) {
  return buffer.readUInt16BE(offset);
}

function readUInt32BE(buffer, offset) {
  return buffer.readUInt32BE(offset);
}

function parseAuthenticatorData(buffer) {
  if (buffer.length < 37) {
    throw new Error(
      `Authenticator data is too short: expected at least 37 bytes, got ${buffer.length}`,
    );
  }

  const rpIdHash = buffer.subarray(0, 32);
  const flags = buffer[32];
  const signCount = readUInt32BE(buffer, 33);
  let offset = 37;

  const result = {
    raw: buffer,
    rpIdHash,
    flags,
    signCount,
    counter: signCount,
  };

  // AT flag means attested credential data is present.
  // Registration attestation carries it; assertion usually does not.
  if (flags & 0x40) {
    if (buffer.length < offset + 18) {
      return result;
    }

    result.aaguid = buffer.subarray(offset, offset + 16);
    offset += 16;

    const credentialIdLength = readUInt16BE(buffer, offset);
    offset += 2;

    if (buffer.length < offset + credentialIdLength) {
      return result;
    }

    result.credentialId = buffer.subarray(offset, offset + credentialIdLength);
    offset += credentialIdLength;

    if (buffer.length > offset) {
      result.credentialPublicKeyBytes = buffer.subarray(offset);
    }
  }

  return result;
}

function extractNonceFromCertificate(leafCert) {
  const certAsn1 = forge.asn1.fromDer(
    forge.util.createBuffer(leafCert.toString("binary"), "binary"),
  );
  const nonceExtensionOid = IOS_APP_ATTEST_CONFIG.NONCE_EXTENSION_OID;
  let extensionValue = null;

  function walk(node) {
    if (!node || !Array.isArray(node.value)) {
      return;
    }

    if (
      node.type === forge.asn1.Type.SEQUENCE &&
      node.value.length >= 2 &&
      node.value[0].type === forge.asn1.Type.OID
    ) {
      const oid = forge.asn1.derToOid(node.value[0].value);
      if (oid === nonceExtensionOid) {
        const octetNode = node.value.find(
          (child) => child.type === forge.asn1.Type.OCTETSTRING,
        );
        if (octetNode && typeof octetNode.value === "string") {
          extensionValue = Buffer.from(octetNode.value, "binary");
          return;
        }
      }
    }

    for (const child of node.value) {
      walk(child);
      if (extensionValue) {
        return;
      }
    }
  }

  walk(certAsn1);

  if (!extensionValue) {
    throw new Error(
      "App Attest nonce extension was not found in leaf certificate",
    );
  }

  const asn1 = forge.asn1.fromDer(
    forge.util.createBuffer(extensionValue.toString("binary"), "binary"),
  );
  const octetStrings = [];

  function collectOctetStrings(node) {
    if (!node) {
      return;
    }

    if (
      node.type === forge.asn1.Type.OCTETSTRING &&
      typeof node.value === "string"
    ) {
      octetStrings.push(Buffer.from(node.value, "binary"));
    }

    if (Array.isArray(node.value)) {
      for (const child of node.value) {
        collectOctetStrings(child);
      }
    }
  }

  collectOctetStrings(asn1);

  const nonce = octetStrings.find((candidate) => candidate.length === 32);
  if (!nonce) {
    throw new Error(
      "Unable to extract App Attest nonce from certificate extension",
    );
  }

  return nonce;
}

function validateAaguid(aaguid) {
  const isProduction = aaguid.equals(APP_ATTEST_PRODUCTION_AAGUID);
  const isDevelopment = aaguid.equals(APP_ATTEST_DEVELOPMENT_AAGUID);

  if (isProduction) {
    return "production";
  }

  if (isDevelopment && IOS_APP_ATTEST_CONFIG.ALLOW_DEVELOPMENT_AAGUID) {
    return "development";
  }

  throw new Error("Unexpected App Attest AAGUID");
}

function validateRpIdHash(rpIdHash) {
  const expectedRpIdHash = sha256(Buffer.from(getAppId(), "utf8"));
  if (!rpIdHash.equals(expectedRpIdHash)) {
    throw new Error(
      "App identifier hash does not match APPLE_TEAM_ID.APPLE_BUNDLE_ID",
    );
  }
}

function buildLeafFingerprint(certBuffer) {
  return crypto
    .createHash("sha256")
    .update(certBuffer)
    .digest("hex")
    .toUpperCase();
}

function extractPublicKeyPemFromLeafCert(leafPem) {
  const x509 = new crypto.X509Certificate(leafPem);
  return x509.publicKey.export({
    type: "spki",
    format: "pem",
  });
}

function base64UrlEncode(buffer) {
  return Buffer.from(buffer)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecodeToBuffer(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding =
    normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + padding, "base64");
}

function extractPublicKeyPemFromCredentialPublicKey(credentialPublicKeyBytes) {
  const coseKey = cbor.decodeFirstSync(credentialPublicKeyBytes);

  const x = coseKey.get(-2);
  const y = coseKey.get(-3);
  const kty = coseKey.get(1);
  const crv = coseKey.get(-1);

  if (!x || !y) {
    throw new Error("Credential public key is missing x or y coordinates");
  }

  if (kty !== 2 || crv !== 1) {
    throw new Error("Unsupported App Attest credential public key type");
  }

  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: base64UrlEncode(ensureBuffer(x)),
    y: base64UrlEncode(ensureBuffer(y)),
  };

  return crypto.createPublicKey({
    key: jwk,
    format: "jwk",
  }).export({
    type: "spki",
    format: "pem",
  });
}

function computeKeyIdFromPublicKeyPem(publicKeyPem) {
  const keyObject = crypto.createPublicKey(publicKeyPem);
  const spkiDer = keyObject.export({
    type: "spki",
    format: "der",
  });

  return sha256(spkiDer);
}

function verifyAttestation(params) {
  const { keyId, challenge, attestationObject } = params;

  const decodedAttestation = ensureBuffer(
    Buffer.from(attestationObject, "base64"),
  );
  const decoded = cbor.decodeFirstSync(decodedAttestation);

  if (decoded.fmt !== "apple-appattest") {
    throw new Error(`Unexpected attestation format: ${decoded.fmt}`);
  }

  const authData = ensureBuffer(decoded.authData);
  const attStmt = decoded.attStmt || {};
  const x5c = Array.isArray(attStmt.x5c) ? attStmt.x5c.map(ensureBuffer) : [];

  if (x5c.length < 2) {
    throw new Error(
      "App Attest attestation must include leaf and intermediate certificates",
    );
  }

  const certChain = verifyCertificateChain(x5c);
  const parsedAuthData = parseAuthenticatorData(authData);

  validateRpIdHash(parsedAuthData.rpIdHash);

  if (!(parsedAuthData.flags & 0x40)) {
    throw new Error(
      "App Attest authenticator data is missing attested credential data",
    );
  }

  const environment = validateAaguid(parsedAuthData.aaguid);

  const decodedKeyId = base64UrlToBuffer(keyId);
  if (!parsedAuthData.credentialId.equals(decodedKeyId)) {
    throw new Error("keyId does not match attested credentialId");
  }

  const clientDataHash = sha256(decodeClientChallenge(challenge));
  const expectedNonce = sha256(Buffer.concat([authData, clientDataHash]));
  const certificateNonce = extractNonceFromCertificate(certChain.leafDer);

  if (!expectedNonce.equals(certificateNonce)) {
    throw new Error("App Attest nonce does not match challenge");
  }

  if (!parsedAuthData.credentialPublicKeyBytes) {
    throw new Error("App Attest registration is missing credential public key");
  }

  const publicKeyPem = extractPublicKeyPemFromCredentialPublicKey(
    parsedAuthData.credentialPublicKeyBytes,
  );

  const leafLegacy = certChain.leaf.toLegacyObject();
  const keyType = leafLegacy.asn1Curve ? "EC" : "Unknown";
  const keySize = leafLegacy.bits || 256;

  return {
    publicKey: publicKeyPem,
    attestationCertificatePublicKey: extractPublicKeyPemFromLeafCert(
      certChain.leafPem,
    ),
    keyInfo: {
      type: keyType,
      size: keySize,
    },
    securityLevel: "apple_app_attest",
    certificateInfo: {
      subject: leafLegacy.subject?.CN || "Apple App Attest",
      validUntil: new Date(certChain.leaf.validTo).toISOString(),
      fingerprint: buildLeafFingerprint(x5c[0]),
    },
    attestation: {
      success: true,
      platform: "ios",
      verificationMode: "apple_app_attest",
      status: "verified",
      keyId,
      environment,
      signCount: parsedAuthData.signCount,
      receiptPresent: !!attStmt.receipt,
    },
    assertionCounter: parsedAuthData.signCount,
  };
}

function splitAssertion(assertionBuffer) {
  try {
    const decoded = cbor.decodeFirstSync(assertionBuffer);
    const authenticatorData = decoded.authenticatorData || decoded.authData;
    const signature = decoded.signature || decoded.sig;

    if (authenticatorData && signature) {
      return {
        authenticatorData: ensureBuffer(authenticatorData),
        signature: ensureBuffer(signature),
      };
    }
  } catch (error) {
    // Ignore and try raw fallback below.
  }

  if (assertionBuffer.length <= 37) {
    throw new Error("Assertion payload is too short");
  }

  const authenticatorData = assertionBuffer.subarray(0, 37);
  const signature = assertionBuffer.subarray(37);

  return {
    authenticatorData,
    signature,
  };
}

function verifyAssertion(params) {
  const {
    keyId,
    assertion,
    phone,
    timestamp,
    nonce,
    publicKey,
    attestationCertificatePublicKey,
    previousCounter = 0,
  } = params;

  const assertionBuffer = Buffer.from(assertion, "base64");
  const { authenticatorData, signature } = splitAssertion(assertionBuffer);
  const parsedAuthData = parseAuthenticatorData(authenticatorData);

  validateRpIdHash(parsedAuthData.rpIdHash);

  const signData = Buffer.from(
    `phone=${phone}&timestamp=${timestamp}&nonce=${nonce}`,
    "utf8",
  );
  const clientDataHash = sha256(signData);
  const verificationData = Buffer.concat([authenticatorData, clientDataHash]);
  const assertionNonce = sha256(verificationData);

  let isValid = false;
  try {
    isValid = crypto.verify("sha256", assertionNonce, publicKey, signature);
  } catch {
    isValid = false;
  }

  if (!isValid && attestationCertificatePublicKey) {
    try {
      isValid = crypto.verify(
        "sha256",
        assertionNonce,
        attestationCertificatePublicKey,
        signature,
      );
    } catch {
      isValid = false;
    }
  }

  if (!isValid) {
    throw new Error("iOS assertion signature verification failed");
  }

  if (parsedAuthData.signCount <= previousCounter) {
    throw new Error("iOS assertion counter did not increase");
  }

  return {
    success: true,
    keyId,
    signCount: parsedAuthData.signCount,
    verificationMode: "apple_app_attest_assertion",
  };
}

module.exports = {
  validateRegistrationParams,
  validateAssertionParams,
  verifyAttestation,
  verifyAssertion,
};
