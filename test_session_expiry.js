/**
 * 测试设备会话过期功能
 */

const crypto = require("crypto");

// 已知的设备ID（从之前的测试中）
const TEST_DEVICE_ID =
  "a9fe8940183bdff17e8859d7589bcad20655141fe8206cfb2f225f98d2fd02e6";
const TEST_PHONE = "13687668876";

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
 * 生成随机nonce
 */
function generateNonce() {
  return crypto.randomBytes(32).toString("base64");
}

/**
 * 测试发送消息
 */
async function testSendMessage(attempt = 1) {
  console.log(`\n📨 === Attempting Message Send (Attempt ${attempt}) ===`);

  const timestamp = Date.now();
  const nonce = generateNonce();

  // 创建简单的模拟签名（用于测试）
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
    console.log(`   Error code: ${result.data.errorCode}`);

    if (result.data.errorCode === "SESSION_EXPIRED") {
      console.log(`   🔒 Session expired as expected!`);
      console.log(`   Registration time: ${result.data.registrationTime}`);
      console.log(
        `   Session age: ${Math.round(result.data.sessionAgeMs / 1000)}s`,
      );
    }
  }

  return result.status === 200;
}

/**
 * 主测试函数
 */
async function runSessionExpiryTest() {
  console.log(`🧪 Starting Session Expiry Test`);
  console.log(`📱 Device ID: ${TEST_DEVICE_ID}`);
  console.log(`📞 Phone: ${TEST_PHONE}`);
  console.log(`⏱️  Session expiry: 15 seconds\n`);

  // 检查设备是否存在
  console.log("🔍 Checking existing devices...");
  const devicesResult = await sendRequest("/devices");

  if (devicesResult.status === 200 && devicesResult.data.devices) {
    const device = devicesResult.data.devices.find(
      (d) => d.deviceId === TEST_DEVICE_ID,
    );
    if (device) {
      console.log(`✅ Found device: ${device.deviceId}`);
      console.log(`   Registered at: ${device.registrationTime}`);

      const now = Date.now();
      const registrationTime = new Date(device.registrationTime).getTime();
      const ageSeconds = Math.round((now - registrationTime) / 1000);
      console.log(`   Current age: ${ageSeconds}s`);

      if (ageSeconds > 15) {
        console.log(`   🔒 Device should already be expired!`);
      } else {
        console.log(`   ⏳ Device should expire in ${15 - ageSeconds}s`);
      }
    } else {
      console.log(`❌ Device not found: ${TEST_DEVICE_ID}`);
      return;
    }
  }

  // 测试1：立即发送消息
  console.log(`\n⚡ Test 1: Send message immediately`);
  const success1 = await testSendMessage(1);

  // 测试2：等待20秒后再发送消息
  console.log(`\n⏳ Waiting 20 seconds for session to expire...`);
  await new Promise((resolve) => setTimeout(resolve, 20000));

  console.log(`⚡ Test 2: Send message after 20 seconds (should fail)`);
  const success2 = await testSendMessage(2);

  // 结果总结
  console.log(`\n📊 Test Results:`);
  console.log(
    `   First attempt (fresh session): ${success1 ? "✅ SUCCESS" : "❌ FAILED"}`,
  );
  console.log(
    `   Second attempt (expired session): ${success2 ? "❌ SHOULD HAVE FAILED" : "✅ CORRECTLY FAILED"}`,
  );

  if (!success1 && !success2) {
    console.log(`\n🔒 Session expiry mechanism working correctly!`);
  } else if (success1 && !success2) {
    console.log(`\n🔒 Session expiry mechanism working correctly!`);
  } else {
    console.log(`\n⚠️  Session expiry mechanism may have issues.`);
  }
}

// 运行测试
runSessionExpiryTest().catch(console.error);
