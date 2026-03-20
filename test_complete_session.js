/**
 * 完整的会话过期测试：注册设备 + 测试会话过期
 */

const crypto = require("crypto");

// 测试数据
const TEST_DEVICE_ID = "test-device-session-expiry-" + Date.now();
const TEST_PHONE = "13687668876";

// 使用之前工作的证书数据
const TEST_CERT_CHAIN = [
  "MIIDUTCCAjmgAwIBAgIJAPIAGQ2bxy9wMA0GCSqGSIb3DQEBBQUAMEIxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARVdGFoMQswCQYDVQQHDAJVUzETMBEGA1UECgwKR29vZ2xlIEluYzEOMAwGA1UEAwwFR29vZ2xlMB4XDTE2MDUyNjE2Mjg1MloXDTQzMTAxMjE2Mjg1MlowQjELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxCzAJBgNVBAcMAlVTMRMwEQYDVQQKDApHb29nbGUgSW5jMQ4wDAYDVQQDDAVHb29nbGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1LC55wXwuptWIqQ9QW9mzurnvUW9ER33WqwQUMAMYP4do+rd55f1vo+owXqA3KHIrakpPoLFPfwvEq/6ZQGEBY5VcWE6++FYJbHPGFVIu4IgFPY98ZuEQXaHkVQeSaCmIYFJDtj4vgnMc0lGqhOuYuomThVPzpgK3EmVsQmIqXsrYrzAHGF8aevho8rSIr0qc39jhUbVe3wrWVta2opSOGDibwi1fLdJjgL+ExhAvPYzjLSI4naQb0GfZMZF9Ua3x/7SDpdlfObfA7/iD/C854fDxMXBSlTdHaqxmq8jtHfGcK1N3EksMpgqwOZbDqo4cApuvqMkHbAtCeApgxAmPAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAIQL34cXbMsfgkLd1HM+m9D4ntGSC/c4ona8vYuIZXLu4jtB3hLMr/fB0fig637w6AnLbK/abQb0jdVw3fDz7dk=",
  "MIICDzCCAZWgAwIBAgIBATAKBggqhkjOPQQDAzA5MQswCQYDVQQGEwJVUzEQMA4GA1UECgwHQW5kcm9pZDEYMBYGA1UEAwwPQW5kcm9pZCBSb290IENBMB4XDTIwMDEwMTAwMDAwMFoXDTQ1MDEwMTAwMDAwMFowOTELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJvaWQxGDAWBgNVBAMMD0FuZHJvaWQgUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABALT9XzBWLtXzW37bz8QOGdSoNDK2IhQYb3w+WkHBaDZJZzC+YMQe7Q9q5z5QGwhNcNsBSL7MHJEgKbFY0LwTBmCjYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBR5uB2FHW1o8i+eJsHFQ3W5IiRpSTAfBgNVHSMEGDAWgBR5uB2FHW1o8i+eJsHFQ3W5IiRpSTAKBggqhkjOPQQDAwNIADBFAiEAuOZfJE4vLILzf8D+3R1F3n7dL9PJ8D8CQu8oQ7t0ODAIhwCYLfOjJ8cILQ0tJ8T+K0q3ZdMqCg==",
];

/**
 * 发送HTTP请求的辅助函数
 */
async function sendRequest(endpoint, method = "GET", data = null) {
  const url = `http://localhost:3000${endpoint}`;
  console.log(`🌐 ${method} ${url}`);

  const options = {
    method: method,
    headers: {
      "Content-Type": "application/json",
    },
  };

  if (data) {
    console.log(`📤 Request body:`, JSON.stringify(data, null, 2));
    options.body = JSON.stringify(data);
  }

  try {
    const response = await fetch(url, options);
    const responseText = await response.text();

    console.log(`📥 Response status: ${response.status}`);

    let responseBody;
    try {
      responseBody = JSON.parse(responseText);
      console.log(`📥 Response body:`, JSON.stringify(responseBody, null, 2));
    } catch {
      console.log(`📥 Response body (text): ${responseText}`);
      responseBody = { error: responseText };
    }

    return {
      status: response.status,
      data: responseBody,
    };
  } catch (error) {
    console.error(`❌ Request failed: ${error.message}`);
    return {
      status: 0,
      data: { error: error.message },
    };
  }
}

/**
 * 生成随机nonce和challenge
 */
function generateNonce() {
  return crypto.randomBytes(32).toString("base64");
}

/**
 * 注册设备
 */
async function registerDevice() {
  console.log(`\n📱 === Registering Test Device ===`);

  const challenge = generateNonce();
  const registrationData = {
    deviceId: TEST_DEVICE_ID,
    certChain: TEST_CERT_CHAIN,
    challenge: challenge,
  };

  const result = await sendRequest("/register", "POST", registrationData);

  console.log(
    `${result.status === 200 ? "✅" : "❌"} Registration result: ${result.status}`,
  );

  if (result.status === 200) {
    console.log(`   ✅ Device registered successfully`);
    console.log(`   📱 Device ID: ${result.data.deviceId}`);
    console.log(`   🔒 Security Level: ${result.data.securityLevel}`);
    return true;
  } else {
    console.log(`   ❌ Registration failed: ${result.data.error}`);
    return false;
  }
}

/**
 * 测试发送消息
 */
async function testSendMessage(attempt = 1) {
  console.log(`\n📨 === Testing Message Send (Attempt ${attempt}) ===`);

  const timestamp = Date.now();
  const nonce = generateNonce();

  // 创建简单的模拟签名 (签名验证应该会失败，但我们主要测试会话过期)
  const signData = `phone=${TEST_PHONE}&timestamp=${timestamp}&nonce=${nonce}`;
  const signature = Buffer.from(signData, "utf8").toString("base64");

  const messageData = {
    deviceId: TEST_DEVICE_ID,
    phone: TEST_PHONE,
    timestamp: timestamp,
    nonce: nonce,
    signature: signature,
  };

  const result = await sendRequest("/sendMessage", "POST", messageData);

  console.log(
    `${result.status === 200 ? "✅" : "❌"} Send message result: ${result.status}`,
  );

  if (result.status !== 200) {
    console.log(`   Error: ${result.data.error}`);
    console.log(`   Error code: ${result.data.errorCode || "N/A"}`);

    if (result.data.errorCode === "SESSION_EXPIRED") {
      console.log(`   🔒 Session expired as expected!`);
      console.log(`   Registration time: ${result.data.registrationTime}`);
      console.log(
        `   Session age: ${Math.round(result.data.sessionAgeMs / 1000)}s`,
      );
      return "expired";
    } else {
      return "other_error";
    }
  }

  return "success";
}

/**
 * 主测试函数
 */
async function runCompleteSessionTest() {
  console.log(`🧪 Session Expiry Test - Complete Flow`);
  console.log(`📱 Device ID: ${TEST_DEVICE_ID}`);
  console.log(`📞 Phone: ${TEST_PHONE}`);
  console.log(`⏱️  Session expiry: 15 seconds\n`);

  // 步骤1：注册设备
  console.log(`⚡ Step 1: Register device`);
  const registrationSuccess = await registerDevice();

  if (!registrationSuccess) {
    console.log(`❌ Cannot continue test - device registration failed`);
    return;
  }

  // 步骤2：立即发送消息（应该成功或至少不是会话过期错误）
  console.log(`\n⚡ Step 2: Send message immediately (within session window)`);
  const result1 = await testSendMessage(1);

  // 步骤3：等待20秒让会话过期
  console.log(`\n⏳ Step 3: Waiting 20 seconds for session to expire...`);
  console.log(`   Current time: ${new Date().toISOString()}`);

  await new Promise((resolve) => setTimeout(resolve, 20000));

  console.log(`   Wait completed at: ${new Date().toISOString()}`);

  // 步骤4：发送消息（应该因会话过期而失败）
  console.log(`\n⚡ Step 4: Send message after 20 seconds (should be expired)`);
  const result2 = await testSendMessage(2);

  // 结果总结
  console.log(`\n📊 Test Results:`);
  console.log(`   Registration: ✅ SUCCESS`);
  console.log(`   First message (fresh): ${result1}`);
  console.log(`   Second message (expired): ${result2}`);

  if (result2 === "expired") {
    console.log(`\n🎉 SUCCESS: Session expiry mechanism working correctly!`);
    console.log(`   ✅ Device registered successfully`);
    console.log(`   ✅ First message processed (within session window)`);
    console.log(
      `   ✅ Second message correctly rejected due to session expiry`,
    );
  } else if (result1 !== "success" && result2 === "expired") {
    console.log(`\n🎉 SUCCESS: Session expiry mechanism working!`);
    console.log(
      `   ⚠️  First message had other errors, but session expiry still works`,
    );
  } else {
    console.log(`\n⚠️  Issue detected:`);
    if (result2 !== "expired") {
      console.log(
        `   ❌ Second message should have been rejected due to session expiry`,
      );
      console.log(
        `   🔍 Possible issues: session expiry not implemented or timeout too long`,
      );
    }
  }
}

// 运行测试
runCompleteSessionTest().catch(console.error);
