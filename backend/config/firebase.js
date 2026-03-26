const admin = require("firebase-admin");
const serviceAccount = require("../firebaseKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://certificate-authenticato-958f4-default-rtdb.firebaseio.com/"
});

const db = admin.database();

// Seed default admin on first run
async function seedAdmin() {
  const snap = await db.ref("users/admin").once("value");
  if (!snap.val()) {
    const crypto = require("crypto");
    await db.ref("users/admin").set({
      passwordHash: crypto.createHash("sha256").update("admin123").digest("hex"),
      role: "admin",
      createdAt: Date.now()
    });
    console.log("✅ Default admin seeded (admin / admin123) — change password immediately!");
  }
}
seedAdmin();

module.exports = db;