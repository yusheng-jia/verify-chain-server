# verify-chain-server

Local Node.js verification server for:

- Android Key Attestation device registration
- iOS App Attest device registration
- Signed message verification after registration
- Replay protection with `challenge`, `nonce`, and timestamp checks

## What It Does

This server lets a mobile app prove that:

1. A key was created on a real mobile device
2. The key belongs to the expected platform (`android` or `ios`)
3. Later requests are signed by the same registered device key

Current platform flows:

- Android: certificate chain attestation + RSA signature verification
- iOS: App Attest attestation + assertion verification

## Current Security Model

Registration requires a server-issued `challenge`.

- `POST /challenge`
- `POST /register`

Message sending requires:

- registered device
- matching platform
- valid signature/assertion
- valid timestamp
- unused nonce

Notes:

- Device records are stored in memory
- Nonces are stored in memory
- Challenges are stored in memory
- Restarting the server clears all of the above

This is good for local development and protocol verification. For production, device state and counters should be persisted.

## Requirements

- Node.js 18+
- npm

## Install

```bash
npm install
```

## Run

```bash
npm start
```

Server default:

- Base URL: `http://localhost:3000`

Useful endpoints:

- `GET /health`
- `POST /challenge`
- `POST /register`
- `POST /sendMessage`
- `GET /devices`
- `GET /nonces`
- `GET /status`

## Environment Variables

For iOS App Attest verification:

- `APPLE_TEAM_ID`
- `APPLE_BUNDLE_ID`
- `APPLE_APP_ATTEST_ALLOW_DEVELOPMENT`

Example:

```bash
export APPLE_TEAM_ID=YOUR_TEAM_ID
export APPLE_BUNDLE_ID=com.example.app
export APPLE_APP_ATTEST_ALLOW_DEVELOPMENT=true
npm start
```

`APPLE_APP_ATTEST_ALLOW_DEVELOPMENT=true` is useful for local testing with development App Attest environments.

## API Flow

### Android

1. Client calls `POST /challenge`
2. Server returns a Base64 challenge
3. Android app generates an attested key using that challenge
4. Client calls `POST /register`
5. Android app later signs message data and calls `POST /sendMessage`

### iOS

1. Client calls `POST /challenge`
2. Server returns a Base64 challenge
3. iOS app uses App Attest `attestKey(...)`
4. Client calls `POST /register`
5. iOS app later uses `generateAssertion(...)` and calls `POST /sendMessage`

## Request Examples

### 1. Get Challenge

```json
{
  "deviceId": "device-001",
  "platform": "android",
  "purpose": "register"
}
```

### 2. Register Android Device

```json
{
  "deviceId": "device-001",
  "platform": "android",
  "challenge": "BASE64_CHALLENGE",
  "certChain": ["LEAF_CERT_BASE64", "INTERMEDIATE_CERT_BASE64"]
}
```

### 3. Register iOS Device

```json
{
  "deviceId": "device-001",
  "platform": "ios",
  "keyId": "APP_ATTEST_KEY_ID",
  "challenge": "BASE64_CHALLENGE",
  "attestationObject": "BASE64_ATTESTATION_OBJECT"
}
```

### 4. Android Send Message

```json
{
  "deviceId": "device-001",
  "platform": "android",
  "phone": "13800138000",
  "timestamp": 1774318694171,
  "nonce": "RANDOM_NONCE",
  "signature": "BASE64_RSA_SIGNATURE"
}
```

Android signs:

```text
phone=13800138000&timestamp=1774318694171&nonce=RANDOM_NONCE
```

### 5. iOS Send Message

```json
{
  "deviceId": "device-001",
  "platform": "ios",
  "keyId": "APP_ATTEST_KEY_ID",
  "phone": "13800138000",
  "timestamp": 1774318694171,
  "nonce": "RANDOM_NONCE",
  "assertion": "BASE64_ASSERTION"
}
```

The iOS app generates an App Attest assertion over:

```text
phone=13800138000&timestamp=1774318694171&nonce=RANDOM_NONCE
```

## Verification Summary Logs

Successful `sendMessage` requests print a compact summary like:

```text
📊 Verification summary:
   Device: a9fe8940183bdff17e8859d7589bcad20655141fe8206cfb2f225f98d2fd02e6
   Phone: 13800138000
   Security Level: hardware
   Verification Time: 2026-03-24T06:25:56.955Z
```

iOS will print the same summary format, with its own security level such as `apple_app_attest`.

## Limitations

- In-memory storage only
- No persistent device database
- No persistent iOS assertion counter storage across restarts
- No rate limiting
- No IP/device abuse controls yet

## Recommended Next Steps

- Persist device registrations in a database or Redis
- Persist nonce and challenge state if needed
- Add SMS abuse protection:
  - rate limiting
  - per-device quotas
  - per-phone quotas
  - IP-based controls
  - risk scoring

## Test Scripts

Project currently includes some local test/demo scripts:

- [`test_android_attestation.js`](/Users/kohleradmin/Development/Code/Node/verify-chain-server/test_android_attestation.js)
- [`test_complete_session.js`](/Users/kohleradmin/Development/Code/Node/verify-chain-server/test_complete_session.js)
- [`test_session_expiry.js`](/Users/kohleradmin/Development/Code/Node/verify-chain-server/test_session_expiry.js)
