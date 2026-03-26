const express = require("express");
const router  = express.Router();
const ctrl    = require("../controllers/certController");

router.post("/register",           ctrl.register);
router.post("/login",              ctrl.login);
router.post("/issue",              ctrl.issueCertificate);
router.post("/verify",             ctrl.verifyCertificate);
router.post("/revoke",             ctrl.revokeCertificate);
router.get("/all",                 ctrl.getAllCertificates);
router.post("/challenge",          ctrl.generateChallenge);
router.post("/validate-challenge", ctrl.validateChallenge);

module.exports = router;