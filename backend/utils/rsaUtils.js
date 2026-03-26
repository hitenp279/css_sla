const crypto = require("crypto");

// Generate RSA key pair
function generateKeys() {
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
}

// Sign data
function signData(data, privateKey) {
  const sign = crypto.createSign("SHA256");
  sign.update(data);
  sign.end();
  return sign.sign(privateKey, "hex");
}

// Verify signature
function verifyData(data, signature, publicKey) {
  const verify = crypto.createVerify("SHA256");
  verify.update(data);
  verify.end();
  return verify.verify(publicKey, signature, "hex");
}

module.exports = { generateKeys, signData, verifyData };