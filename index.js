/**
 * 📱 Android Key Attestation 验证服务器 - 模块化版本
 *
 * 功能：
 * 1. 🔐 验证Android设备的硬件证书链
 * 2. 📝 注册设备并存储公钥信息
 * 3. ✅ 验证设备签名的消息
 * 4. 🛡️ 防重放攻击（nonce + 时间窗口验证）
 * 5. 🔍 提供设备管理和统计接口
 *
 * 安全特性：
 * - 30秒时间窗口验证
 * - Nonce防重放机制
 * - 硬件级证书链验证
 * - RSA SHA256withRSA签名验证
 */

const express = require("express");
const bodyParser = require("body-parser");

// 导入配置和服务
const { SECURITY_CONFIG, SERVICE_INFO } = require("./src/config/constants");
const challengeManager = require("./src/services/challengeManager");
const nonceManager = require("./src/services/nonceManager");
const routeHandlers = require("./src/routes/handlers");

const app = express();
const PORT = 3000;

// 中间件配置
app.use(bodyParser.json({ limit: "10mb" })); // 支持大证书链
app.use(express.static("public"));

// 初始化服务
nonceManager.initNonceCleanup();
challengeManager.initChallengeCleanup();

// 📚 API路由配置
app.get("/health", routeHandlers.healthCheck);
app.post("/challenge", routeHandlers.issueChallenge);
app.post("/register", routeHandlers.registerDevice);
app.post("/sendMessage", routeHandlers.sendMessage);
app.get("/devices", routeHandlers.getDevices);
app.get("/nonces", routeHandlers.getNonceStats);
app.get("/status", routeHandlers.getSystemStatus);

// 🚀 启动服务器
app.listen(PORT, () => {
  console.log(`\n🚀 ${SERVICE_INFO.name}`);
  console.log(`📡 Listening on http://localhost:${PORT}`);
  console.log("🔗 Endpoints:");
  console.log(`   GET  /health`);
  console.log(`   POST /challenge`);
  console.log(`   POST /register`);
  console.log(`   POST /sendMessage`);
  console.log(`   GET  /devices`);
  console.log(`   GET  /nonces`);
  console.log(`   GET  /status`);
  console.log("🔐 Security:");
  console.log(
    `   Timestamp tolerance: ${SECURITY_CONFIG.TIMESTAMP_TOLERANCE / 1000}s`,
  );
  console.log(
    `   Nonce expiry: ${SECURITY_CONFIG.NONCE_EXPIRY_TIME / (60 * 60 * 1000)}h`,
  );
  console.log(
    `   Challenge expiry: ${SECURITY_CONFIG.CHALLENGE_EXPIRY_TIME / (60 * 1000)}m\n`,
  );
});
