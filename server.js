const express = require("express");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "please-change-this-secret-in-production";
const DATA_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "licenses.sqlite");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS product_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_key TEXT NOT NULL UNIQUE,
    customer_id TEXT NOT NULL,
    plan TEXT NOT NULL,
    features TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    max_devices INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS device_bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_key TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    device_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(product_key, user_id, device_hash)
  );
`);

function stableHash(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

const seedKeys = [
  {
    product_key: "PRO-2025-ALPHA",
    customer_id: "customer-001",
    plan: "pro",
    features: JSON.stringify(["dashboard", "reports", "api-access"]),
    expires_at: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    created_at: new Date().toISOString(),
    revoked: 0,
    status: "active",
    max_devices: 2
  },
  {
    product_key: "PRO-2025-BETA",
    customer_id: "customer-002",
    plan: "business",
    features: JSON.stringify(["dashboard", "reports", "api-access", "priority-support"]),
    expires_at: new Date(Date.now() + 400 * 24 * 60 * 60 * 1000).toISOString(),
    created_at: new Date().toISOString(),
    revoked: 0,
    status: "active",
    max_devices: 3
  },
  {
    product_key: "TRIAL-2025-START",
    customer_id: "customer-003",
    plan: "trial",
    features: JSON.stringify(["dashboard"]),
    expires_at: new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString(),
    created_at: new Date().toISOString(),
    revoked: 0,
    status: "active",
    max_devices: 1
  },
  {
    product_key: "REVOKED-2025-KEY",
    customer_id: "customer-004",
    plan: "enterprise",
    features: JSON.stringify(["dashboard", "reports", "api-access"]),
    expires_at: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString(),
    created_at: new Date().toISOString(),
    revoked: 1,
    status: "revoked",
    max_devices: 1
  },
  {
    product_key: "EXPIRED-2025-KEY",
    customer_id: "customer-005",
    plan: "pro",
    features: JSON.stringify(["dashboard", "reports"]),
    expires_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
    created_at: new Date().toISOString(),
    revoked: 0,
    status: "expired",
    max_devices: 1
  }
];

const insertKey = db.prepare(`
  INSERT OR IGNORE INTO product_keys (
    product_key,
    customer_id,
    plan,
    features,
    expires_at,
    created_at,
    revoked,
    status,
    max_devices
  ) VALUES (@product_key, @customer_id, @plan, @features, @expires_at, @created_at, @revoked, @status, @max_devices)
`);

for (const key of seedKeys) {
  insertKey.run(key);
}

function readProductKeyRecord(productKey) {
  const key = db.prepare(`
    SELECT * FROM product_keys WHERE product_key = ?
  `).get(productKey.trim());

  if (!key) {
    return null;
  }

  const parsedFeatures = JSON.parse(key.features || "[]");

  return {
    ...key,
    features: parsedFeatures,
    revoked: Number(key.revoked) === 1,
    status: key.status
  };
}

function productKeyIsUsable(record) {
  if (!record) return false;
  if (record.revoked) return false;
  if (record.status === "revoked") return false;
  if (record.status === "expired") return false;

  const now = new Date();
  if (new Date(record.expires_at) < now) {
    return false;
  }

  return true;
}

function buildJwtPayload(record, userId, deviceHash) {
  return {
    sub: record.customer_id,
    productKey: record.product_key,
    plan: record.plan,
    features: record.features,
    userId,
    deviceHash,
    customerId: record.customer_id,
    jti: crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60)
  };
}

function getDeviceHash(deviceFingerprint, userId) {
  const seed = deviceFingerprint && String(deviceFingerprint).trim()
    ? deviceFingerprint
    : userId || "unknown-device";

  return stableHash(seed);
}

function registerBinding(productKey, customerId, userId, deviceHash) {
  db.prepare(`
    INSERT OR IGNORE INTO device_bindings (product_key, customer_id, user_id, device_hash, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(productKey, customerId, userId, deviceHash, new Date().toISOString());
}

function countBindingsForUser(productKey, userId) {
  const row = db.prepare(`
    SELECT COUNT(*) AS count FROM device_bindings WHERE product_key = ? AND user_id = ?
  `).get(productKey);

  return Number(row?.count || 0);
}

function verifyActivationToken(token, expectedUserId, expectedDeviceFingerprint) {
  const payload = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256"] });

  const record = readProductKeyRecord(payload.productKey);
  if (!record || !productKeyIsUsable(record)) {
    throw new Error("Activation key references a non-usable product key.");
  }

  const deviceHash = getDeviceHash(expectedDeviceFingerprint, expectedUserId);
  const isMatchingUser = expectedUserId ? String(payload.userId) === String(expectedUserId) : true;
  const isMatchingDevice = String(payload.deviceHash) === String(deviceHash);

  if (!isMatchingUser) {
    throw new Error("Activation key belongs to a different user.");
  }

  if (!isMatchingDevice) {
    throw new Error("Activation key does not match the current device fingerprint.");
  }

  return payload;
}

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.get("/api/keys", (req, res) => {
  const rows = db.prepare(`
    SELECT product_key, customer_id, plan, status, revoked, expires_at FROM product_keys ORDER BY id ASC
  `).all();

  res.json({ keys: rows });
});

app.post("/api/validate-product-key", (req, res) => {
  const { productKey } = req.body || {};

  if (!productKey || typeof productKey !== "string") {
    return res.status(400).json({ valid: false, error: "Product key is required." });
  }

  const record = readProductKeyRecord(productKey.trim());

  if (!record || !productKeyIsUsable(record)) {
    return res.status(401).json({ valid: false, error: "Product key is invalid, revoked, or expired." });
  }

  return res.json({
    valid: true,
    productKey: record.product_key,
    customerId: record.customer_id,
    plan: record.plan,
    features: record.features,
    expiresAt: record.expires_at
  });
});

app.post("/api/generate-activation-key", (req, res) => {
  const { productKey, userId, deviceFingerprint } = req.body || {};

  if (!productKey || typeof productKey !== "string") {
    return res.status(400).json({ valid: false, error: "Product key is required." });
  }

  const trimmedKey = productKey.trim();
  const record = readProductKeyRecord(trimmedKey);

  if (!record || !productKeyIsUsable(record)) {
    return res.status(401).json({ valid: false, error: "Product key is invalid, revoked, or expired." });
  }

  const finalUserId = (userId && String(userId).trim()) || `demo-user-${Date.now()}`;
  const finalFingerprint = deviceFingerprint && String(deviceFingerprint).trim()
    ? deviceFingerprint
    : `device-${Date.now()}`;

  const deviceHash = getDeviceHash(finalFingerprint, finalUserId);
  const currentBindings = countBindingsForUser(trimmedKey, finalUserId);

  if (currentBindings >= Number(record.max_devices || 1)) {
    return res.status(403).json({
      valid: false,
      error: `User ${finalUserId} has reached the maximum number of device bindings for this product key.`
    });
  }

  registerBinding(trimmedKey, record.customer_id, finalUserId, deviceHash);

  const payload = buildJwtPayload(record, finalUserId, deviceHash);
  const token = jwt.sign(payload, JWT_SECRET, { algorithm: "HS256" });

  return res.json({
    valid: true,
    activationKey: token,
    customerId: record.customer_id,
    plan: record.plan,
    features: record.features,
    expiresAt: new Date(payload.exp * 1000).toISOString(),
    userId: finalUserId,
    deviceHash
  });
});

app.post("/api/validate-activation-key", (req, res) => {
  const { activationKey, userId, deviceFingerprint } = req.body || {};

  if (!activationKey || typeof activationKey !== "string") {
    return res.status(400).json({ valid: false, error: "Activation key is required." });
  }

  try {
    const payload = verifyActivationToken(activationKey.trim(), userId, deviceFingerprint);

    return res.json({
      valid: true,
      productKey: payload.productKey,
      customerId: payload.customerId,
      plan: payload.plan,
      features: payload.features,
      userId: payload.userId,
      expiresAt: new Date(payload.exp * 1000).toISOString()
    });
  } catch (error) {
    return res.status(401).json({ valid: false, error: error.message || "Activation key is invalid." });
  }
});

app.get("*", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Database-backed license demo running at http://localhost:${PORT}`);
});
