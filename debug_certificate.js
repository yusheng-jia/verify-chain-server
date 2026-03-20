/**
 * 🔍 证书调试工具
 *
 * 用于分析和调试证书链，帮助识别正确的Google Hardware Attestation Root证书
 */

const forge = require("node-forge");
const fs = require("fs");

/**
 * 分析证书详情
 */
function analyzeCertificate(cert, index) {
  console.log(`\n📄 Certificate ${index}:`);
  console.log(`   Subject CN: ${cert.subject.getField("CN")?.value || "N/A"}`);
  console.log(`   Subject O:  ${cert.subject.getField("O")?.value || "N/A"}`);
  console.log(`   Issuer CN:  ${cert.issuer.getField("CN")?.value || "N/A"}`);
  console.log(`   Issuer O:   ${cert.issuer.getField("O")?.value || "N/A"}`);
  console.log(`   Serial:     ${cert.serialNumber}`);
  console.log(`   Valid from: ${cert.validity.notBefore.toISOString()}`);
  console.log(`   Valid to:   ${cert.validity.notAfter.toISOString()}`);

  // 计算指纹
  const fingerprint = forge.md.sha256
    .create()
    .update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())
    .digest()
    .toHex()
    .toUpperCase();
  console.log(`   SHA256:     ${fingerprint}`);

  // 检查是否是根证书
  const isRoot = cert.subject.hash === cert.issuer.hash;
  console.log(`   Is Root:    ${isRoot ? "Yes" : "No"}`);

  return {
    subjectCN: cert.subject.getField("CN")?.value || "N/A",
    subjectO: cert.subject.getField("O")?.value || "N/A",
    issuerCN: cert.issuer.getField("CN")?.value || "N/A",
    issuerO: cert.issuer.getField("O")?.value || "N/A",
    serial: cert.serialNumber,
    fingerprint: fingerprint,
    isRoot: isRoot,
    pem: forge.pki.certificateToPem(cert),
  };
}

/**
 * 分析证书链
 */
function analyzeCertificateChain(certChain) {
  console.log(
    `🔍 Analyzing certificate chain with ${certChain.length} certificates\n`,
  );

  const certificates = [];
  const analysis = [];

  // 解析所有证书
  for (let i = 0; i < certChain.length; i++) {
    try {
      let cert;
      const certData = certChain[i].trim();

      if (certData.includes("-----BEGIN CERTIFICATE-----")) {
        // PEM 格式
        cert = forge.pki.certificateFromPem(certData);
      } else {
        // Base64 DER 格式
        const der = forge.util.decode64(certData);
        const asn1 = forge.asn1.fromDer(der);
        cert = forge.pki.certificateFromAsn1(asn1);
      }

      certificates.push(cert);
      const certAnalysis = analyzeCertificate(cert, i);
      analysis.push(certAnalysis);
    } catch (error) {
      console.error(`❌ Failed to parse certificate ${i}: ${error.message}`);
    }
  }

  // 找到根证书
  const rootCerts = analysis.filter((cert) => cert.isRoot);
  if (rootCerts.length > 0) {
    console.log(`\n🏆 Root Certificate(s) found:`);
    rootCerts.forEach((cert, index) => {
      console.log(`\nRoot ${index}:`);
      console.log(`Subject: ${cert.subjectCN} (${cert.subjectO})`);
      console.log(`Fingerprint: ${cert.fingerprint}`);
      console.log(`\nPEM Format:`);
      console.log(cert.pem);
    });
  }

  // 检查是否可能是Google证书
  console.log(`\n🔍 Google Certificate Analysis:`);
  analysis.forEach((cert, index) => {
    const isGoogle =
      cert.subjectO?.toLowerCase().includes("google") ||
      cert.issuerO?.toLowerCase().includes("google") ||
      cert.subjectCN?.toLowerCase().includes("google") ||
      cert.issuerCN?.toLowerCase().includes("google") ||
      cert.subjectCN?.toLowerCase().includes("android") ||
      cert.issuerCN?.toLowerCase().includes("android");

    if (isGoogle) {
      console.log(`Certificate ${index} appears to be Google/Android related:`);
      console.log(`  Subject: ${cert.subjectCN} (${cert.subjectO})`);
      console.log(`  Issuer: ${cert.issuerCN} (${cert.issuerO})`);
    }
  });

  return { certificates, analysis, rootCerts };
}

// 示例：从你的错误日志分析证书
function debugFailedCertificate() {
  // 这是从你的错误日志中提取的证书数据
  const certificatePreview =
    "MIIEvDCCAySgAwIBAgIBATANBgkqhkiG9w0BAQsFADA5MQwwCgYDVQQMDANURUUxKTAnBgNVBAUTIDI0MWFkZDA4NDgzNzcwYmQ3";

  console.log("🔍 Debugging the failed certificate from your logs...");
  console.log(`Certificate preview: ${certificatePreview}...`);
  console.log(
    "\n⚠️  This appears to be truncated. To properly debug, you need the full certificate chain.",
  );
  console.log(
    "To get the full certificate chain, check your application logs or the Android device output.",
  );
}

// 主函数
function main() {
  console.log("🔐 Certificate Chain Debugging Tool");
  console.log("=====================================\n");

  // 如果有命令行参数，读取文件
  if (process.argv.length > 2) {
    const filename = process.argv[2];
    try {
      const data = fs.readFileSync(filename, "utf8");
      const certs = data
        .split("-----END CERTIFICATE-----")
        .filter((cert) => cert.includes("-----BEGIN CERTIFICATE-----"))
        .map((cert) => cert + "-----END CERTIFICATE-----");

      if (certs.length > 0) {
        analyzeCertificateChain(certs);
      } else {
        console.log("❌ No certificates found in file");
      }
    } catch (error) {
      console.error(`❌ Error reading file: ${error.message}`);
    }
  } else {
    debugFailedCertificate();
    console.log("\nUsage:");
    console.log("  node debug_certificate.js [certificate_file.pem]");
    console.log(
      "\nOr modify this script to include your actual certificate chain data.",
    );
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  analyzeCertificate,
  analyzeCertificateChain,
};
