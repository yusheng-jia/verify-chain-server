const forge = require("node-forge");

function generateFakeCertChain() {
  // 1. 生成密钥对
  const keys = forge.pki.rsa.generateKeyPair(2048);

  // 2. 创建伪造的设备证书
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

  const attrs = [
    {
      name: "countryName",
      value: "US",
    },
    {
      name: "organizationName",
      value: "FakePhone Corporation",
    },
    {
      name: "commonName",
      value: "Fake Android Device",
    },
  ];

  cert.setSubject(attrs);
  cert.setIssuer(attrs); // 自签名

  // 3. 添加基本扩展 (故意不包含Google Attestation Extension!)
  cert.setExtensions([
    {
      name: "basicConstraints",
      cA: false,
    },
    {
      name: "keyUsage",
      keyCertSign: false,
      digitalSignature: true,
      nonRepudiation: true,
      keyEncipherment: true,
      dataEncipherment: true,
    },
  ]);

  // 4. 签名
  cert.sign(keys.privateKey);

  // 5. 转换为Base64
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
  const base64Cert = forge.util.encode64(der);

  return {
    publicKey: forge.pki.publicKeyToPem(keys.publicKey),
    certificate: base64Cert,
    privateKey: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

// 生成伪造数据
const fakeData = generateFakeCertChain();

console.log("=== FAKE CERTIFICATE DATA FOR TESTING ===");
console.log("Certificate (Base64):");
console.log(fakeData.certificate);
console.log("\nPublic Key (PEM):");
console.log(fakeData.publicKey);
