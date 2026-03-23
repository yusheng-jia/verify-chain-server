#!/usr/bin/env node

/**
 * 📱 Test Android Key Attestation Registration and Message Signing
 *
 * This script simulates the Android device workflow:
 * 1. Register device with certificate chain
 * 2. Send signed message for verification
 */

const fs = require("fs");
const crypto = require("crypto");

const SERVER_URL = "http://localhost:3000";

// 模拟Android设备发送的证书链（使用原始工作版本的测试数据）
const TEST_CERT_CHAIN = [
  // 使用有效的完整证书进行测试（Base64 DER格式）
  "MIIDUTCCAjmgAwIBAgIJAPIAGQ2bxy9wMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVTMRAwDgYDVQQIDAdBbmRyb2lkMRAwDgYDVQQHDAdBbmRyb2lkMQ8wDQYDVQQKDAZHb29nbGUwHhcNMTYwNTI2MTYyODUyWhcNNDMxMDEyMTYyODUyWjBCMQswCQYDVQQGEwJVUzEQMA4GA1UECAwHQW5kcm9pZDEQMA4GA1UEBwwHQW5kcm9pZDEPMA0GA1UECgwGR29vZ2xlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtSwuecF8LqbViKkPUFvZs7q57VFvREd91qsEFDADGD+HaPq3eeX9b6PqMF6gNyhyK2pKT6CxT38LxKv+mUBhAW+VXFhOvvhWCWxzxhVSLuCIBT2PfGbhEF2h5FUHkmgpSGBSQ7Y+L4JzHNJRqoTrmLqJk4VT86YCtxJlbEJiKl7K2K8wBxhfGnr4aPK0iK9KnN/Y4VG1Xt8K1lbWtqKUjhg4m8ItXy3SY4C/hMYQLz2M4y0iOJ2kG9Bn2TGRfVGt8f+0g6XZXzm3wO/4g/wvOeHw8TFwUpU3R2qsZqvI7R3xnCtTdxJLDKYKsDmWw6qOHAKbr6jJB2wLQngKYMQJjwIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQCECy+HF2zLH4JC3dRzPpvQ+J7Rkgv3OKJ2vL2LiGVy7uI7Qd4SzK/3wdH4oOt+8OgJy2yv2m0G9I3VcN3w8+3Z",

  // 根证书（简化版，基于原始代码中的有效证书）
  "MIICDzCCAZWgAwIBAgIBATAKBggqhkjOPQQDAzA5MQswCQYDVQQGEwJVUzEQMA4GA1UECgwHQW5kcm9pZDEYMBYGA1UEAwwPQW5kcm9pZCBSb290IENBMB4XDTIwMDEwMTAwMDAwMFoXDTQ1MDEwMTAwMDAwMFowOTELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJvaWQxGDAWBgNVBAMMD0FuZHJvaWQgUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABALT9XzBWLtXzW37bz8QOGdSoNDK2IhQYb3w+WkHBaDZJZzCYMQe7Q9q5z5QGwhNcNsBSL7MHJEgKbFY0LwTBmCjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBR5uB2FHW1o8i+eJsHFQ3W5IiRpSTAfBgNVHSMEGDAWgBR5uB2FHW1o8i+eJsHFQ3W5IiRpSTAKBggqhkjOPQQDAwNIADBFAiEAuOZfJE4vLILzf8D+3R1F3n7dL9PJ8D8CQu8oQ7t0ODAIhwCYLfOjJ8cILQ0tJ8T+K0q3ZdMqCg==",
];

// 测试设备ID
const TEST_DEVICE_ID = "test-device-13687668876";
const TEST_PHONE = "13687668876";

/**
 * 发送HTTP请求的工具函数
 */
async function sendRequest(endpoint, method, data) {
  try {
    console.log(`🌐 ${method} ${SERVER_URL}${endpoint}`);
    if (data) {
      console.log(`📤 Request body:`, JSON.stringify(data, null, 2));
    }

    const response = await fetch(`${SERVER_URL}${endpoint}`, {
      method: method,
      headers: {
        "Content-Type": "application/json",
      },
      body: data ? JSON.stringify(data) : undefined,
    });

    const result = await response.json();

    console.log(`📥 Response status: ${response.status}`);
    console.log(`📥 Response body:`, JSON.stringify(result, null, 2));

    return { status: response.status, data: result };
  } catch (error) {
    console.error(`❌ Request failed: ${error.message}`);
    return { error: error.message };
  }
}

/**
 * 生成随机nonce
 */
function generateNonce() {
  return crypto.randomBytes(16).toString("hex");
}

/**
 * 模拟Android设备的签名过程
 */
function simulateAndroidSigning(phone, timestamp, nonce) {
  // 构建签名数据（与Android客户端格式一致）
  const signData = `phone=${phone}&timestamp=${timestamp}&nonce=${nonce}`;
  console.log(`📝 Sign data: ${signData}`);

  // 生成RSA密钥对（模拟设备的私钥）
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  // 创建签名（SHA256withRSA）
  const signer = crypto.createSign("SHA256");
  signer.update(signData, "utf8");
  const signature = signer.sign(privateKey, "base64");

  console.log(`🔐 Generated signature: ${signature.substring(0, 50)}...`);
  console.log(
    `🔑 Public key (for reference): ${publicKey.substring(0, 100)}...`,
  );

  return { signData, signature, publicKey, privateKey };
}

/**
 * 1. 测试设备注册
 */
async function testDeviceRegistration() {
  console.log("\n📱 === Testing Device Registration ===");

  const registrationData = {
    deviceId: TEST_DEVICE_ID,
    platform: "android",
    certChain: TEST_CERT_CHAIN, // 使用兼容的原始格式
    challenge: crypto.randomBytes(32).toString("base64"), // 随机challenge
  };

  const result = await sendRequest("/register", "POST", registrationData);

  if (result.status === 200 || result.status === 409) {
    console.log(`✅ Device registration successful or already registered`);
    return true;
  } else {
    console.log(`❌ Device registration failed`);
    return false;
  }
}

/**
 * 2. 测试消息签名验证
 */
async function testMessageSigning() {
  console.log("\n✍️ === Testing Message Signing ===");

  const timestamp = Date.now();
  const nonce = generateNonce();

  // 模拟Android签名过程
  const { signData, signature } = simulateAndroidSigning(
    TEST_PHONE,
    timestamp,
    nonce,
  );

  const messageData = {
    deviceId: TEST_DEVICE_ID,
    platform: "android",
    phone: TEST_PHONE,
    timestamp: timestamp,
    nonce: nonce,
    signature: signature,
  };

  const result = await sendRequest("/sendMessage", "POST", messageData);

  if (result.status === 200) {
    console.log(`✅ Message signing verification successful`);
    return true;
  } else {
    console.log(`❌ Message signing verification failed`);
    if (result.data && result.data.error) {
      console.log(`   Error: ${result.data.error}`);
    }
    return false;
  }
}

/**
 * 3. 测试健康检查
 */
async function testHealthCheck() {
  console.log("\n❤️ === Testing Health Check ===");

  const result = await sendRequest("/health", "GET");

  if (result.status === 200) {
    console.log(`✅ Health check successful`);
    return true;
  } else {
    console.log(`❌ Health check failed`);
    return false;
  }
}

/**
 * 主测试函数
 */
async function runTests() {
  console.log("🔬 Starting Android Key Attestation Tests...");
  console.log("=".repeat(50));

  try {
    // 等待服务器启动
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // 1. 健康检查
    await testHealthCheck();

    // 2. 设备注册
    const registrationSuccess = await testDeviceRegistration();
    if (!registrationSuccess) {
      console.log(
        "❌ Skipping message signing test due to registration failure",
      );
      return;
    }

    // 3. 消息签名验证
    await testMessageSigning();

    console.log("\n" + "=".repeat(50));
    console.log("🎉 Tests completed!");
  } catch (error) {
    console.error("❌ Test execution failed:", error.message);
  }
}

// 运行测试
if (require.main === module) {
  runTests();
}

module.exports = {
  sendRequest,
  testDeviceRegistration,
  testMessageSigning,
  testHealthCheck,
};
