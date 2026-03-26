const db = require("../config/firebase");
const crypto = require("crypto");

// CA Key Pair — persists for server lifetime
const { publicKey: caPublicKey, privateKey: caPrivateKey } =
  crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });

// Challenge store { certId: { challenge, expiresAt } }
const challenges = {};
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

function hashPass(plaintext) {
  return crypto.createHash("sha256").update(plaintext).digest("hex");
}

function makeToken(username) {
  const hmac = crypto
    .createHmac("sha256", process.env.TOKEN_SECRET || "dev-secret-change-me")
    .update(username)
    .digest("hex");
  return `${username}:${hmac}`;
}

function verifyToken(token) {
  if (!token) return null;
  const [username, hmac] = token.split(":");
  if (!username || !hmac) return null;
  const expected = crypto
    .createHmac("sha256", process.env.TOKEN_SECRET || "dev-secret-change-me")
    .update(username)
    .digest("hex");
  return hmac === expected ? username : null;
}

// ── REGISTER ──────────────────────────────────────────────────────────────────
exports.register = async (req, res) => {
  const { username, password, role, adminToken } = req.body;

  if (!username || username.length < 3)
    return res.status(400).json({ success: false, message: "Username must be ≥3 chars" });
  if (!password || password.length < 6)
    return res.status(400).json({ success: false, message: "Password must be ≥6 chars" });

  // Admin role requires a valid admin session token
  if (role === "admin") {
    if (!adminToken)
      return res.status(403).json({ success: false, message: "Admin token required to create admin accounts" });

    const tokenUsername = verifyToken(adminToken);
    if (!tokenUsername)
      return res.status(403).json({ success: false, message: "Invalid admin token" });

    const adminSnap = await db.ref("users/" + tokenUsername).once("value");
    const adminUser = adminSnap.val();
    if (!adminUser || adminUser.role !== "admin")
      return res.status(403).json({ success: false, message: "Only admins can create admin accounts" });
  }

  const safeRole = role === "admin" ? "admin" : "user";

  // Check if username already exists
  const snap = await db.ref("users/" + username).once("value");
  if (snap.val())
    return res.status(409).json({ success: false, message: "Username already taken" });

  await db.ref("users/" + username).set({
    passwordHash: hashPass(password),
    role: safeRole,
    createdAt: Date.now()
  });

  res.json({ success: true });
};

// ── LOGIN ─────────────────────────────────────────────────────────────────────
exports.login = async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ success: false, message: "Missing credentials" });

  try {
    const snap = await db.ref("users/" + username).once("value");
    const user = snap.val();

    if (!user || user.passwordHash !== hashPass(password))
      return res.status(401).json({ success: false, message: "Invalid credentials" });

    const token = makeToken(username);
    res.json({ success: true, role: user.role, token, username });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// ── ISSUE CERTIFICATE ─────────────────────────────────────────────────────────
exports.issueCertificate = async (req, res) => {
  const { user } = req.body;
  if (!user || user.trim() === "")
    return res.status(400).json({ error: "Recipient name required" });

  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pub  = publicKey.export({ type: "spki",  format: "pem" });
  const priv = privateKey.export({ type: "pkcs8", format: "pem" });

  const certData = {
    user:       user.trim(),
    publicKey:  pub,
    issuedAt:   Date.now(),
    validUntil: Date.now() + 7 * 24 * 60 * 60 * 1000
  };

  const hash = crypto
    .createHash("sha256")
    .update(JSON.stringify(certData))
    .digest("hex");

  const sign = crypto.createSign("SHA256");
  sign.update(hash);
  sign.end();
  const signature = sign.sign(caPrivateKey, "hex");

  const cert = { ...certData, hash, signature, status: "valid" };

  try {
    const certId = Date.now().toString();
    await db.ref("certificates/" + certId).set(cert);
    res.json({ certId, privateKey: priv });
  } catch (err) {
    console.error("Issue error:", err);
    res.status(500).json({ error: "Failed to store certificate" });
  }
};

// ── VERIFY CERTIFICATE ────────────────────────────────────────────────────────
exports.verifyCertificate = async (req, res) => {
  const { certId } = req.body;
  if (!certId) return res.status(400).json({ status: "MISSING CERT ID ❌" });

  try {
    const snap = await db.ref("certificates/" + certId).once("value");
    const cert = snap.val();

    if (!cert) return res.json({ status: "NOT FOUND ❌" });
    if (cert.status === "revoked") return res.json({ status: "REVOKED ❌" });
    if (Date.now() > cert.validUntil) return res.json({ status: "EXPIRED ⏳" });

    const reHash = crypto
      .createHash("sha256")
      .update(JSON.stringify({
        user:       cert.user,
        publicKey:  cert.publicKey,
        issuedAt:   cert.issuedAt,
        validUntil: cert.validUntil
      }))
      .digest("hex");

    const verify = crypto.createVerify("SHA256");
    verify.update(reHash);
    verify.end();
    const valid = verify.verify(caPublicKey, cert.signature, "hex");

    res.json({ status: valid ? "VALID ✅" : "TAMPERED ❌" });
  } catch (err) {
    console.error("Verify error:", err);
    res.status(500).json({ status: "SERVER ERROR ❌" });
  }
};

// ── REVOKE CERTIFICATE ────────────────────────────────────────────────────────
exports.revokeCertificate = async (req, res) => {
  const { certId } = req.body;
  if (!certId) return res.status(400).json({ error: "certId required" });

  try {
    const snap = await db.ref("certificates/" + certId).once("value");
    if (!snap.val()) return res.status(404).json({ error: "Certificate not found" });

    await db.ref("certificates/" + certId).update({ status: "revoked" });
    res.json({ message: "Certificate revoked 🚫", certId });
  } catch (err) {
    console.error("Revoke error:", err);
    res.status(500).json({ error: "Revoke failed" });
  }
};

// ── GET ALL CERTIFICATES ──────────────────────────────────────────────────────
exports.getAllCertificates = async (req, res) => {
  try {
    const snap = await db.ref("certificates").once("value");
    res.json(snap.val() || {});
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch certificates" });
  }
};

// ── GENERATE CHALLENGE ────────────────────────────────────────────────────────
exports.generateChallenge = (req, res) => {
  const { certId } = req.body;
  if (!certId) return res.status(400).json({ error: "certId required" });

  // Clean expired challenges
  const now = Date.now();
  for (const id in challenges) {
    if (challenges[id].expiresAt < now) delete challenges[id];
  }

  const challenge = crypto.randomBytes(32).toString("hex");
  challenges[certId] = { challenge, expiresAt: now + CHALLENGE_TTL_MS };
  res.json({ challenge });
};

// ── VALIDATE CHALLENGE ────────────────────────────────────────────────────────
exports.validateChallenge = async (req, res) => {
  const { certId, signedChallenge } = req.body;
  if (!certId || !signedChallenge)
    return res.status(400).json({ result: "MISSING PARAMS ❌" });

  const entry = challenges[certId];
  if (!entry)
    return res.status(400).json({ result: "NO CHALLENGE — request one first ❌" });
  if (Date.now() > entry.expiresAt) {
    delete challenges[certId];
    return res.status(400).json({ result: "CHALLENGE EXPIRED ❌" });
  }

  try {
    const snap = await db.ref("certificates/" + certId).once("value");
    const cert = snap.val();
    if (!cert) return res.status(404).json({ result: "CERT NOT FOUND ❌" });

    const verify = crypto.createVerify("SHA256");
    verify.update(entry.challenge);
    verify.end();
    const ok = verify.verify(cert.publicKey, signedChallenge, "hex");

    delete challenges[certId]; // single-use

    res.json({ result: ok ? "AUTHENTIC USER ✅" : "INVALID SIGNATURE ❌" });
  } catch (err) {
    console.error("Validate challenge error:", err);
    res.status(500).json({ result: "SERVER ERROR ❌" });
  }
};