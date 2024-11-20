const express = require("express");
const { register, login, forgotPassword, resetPassword, generate2FA, verify2FA } = require("../controllers/authController");

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);
router.post("/2fa/generate", generate2FA);
router.post("/2fa/verify", verify2FA);

module.exports = router;
