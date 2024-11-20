const User = require("../models/User");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const speakeasy = require("speakeasy");

// Helper: Generate Token
const generateToken = (id, role) => {
    return jwt.sign({ id, role }, process.env.JWT_SECRET, { expiresIn: "1h" });
};

// Register User
exports.register = async (req, res) => {
    try {
        const { username, email, password, role } = req.body;

        const user = new User({ username, email, password, role });
        await user.save();

        res.status(201).json({ message: "User registered successfully!" });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
};

// Login User
exports.login = async (req, res) => {
    try {
        const { username, password } = req.body;

        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ error: "Invalid credentials" });

        const isMatch = await user.matchPassword(password);
        if (!isMatch) return res.status(401).json({ error: "Invalid credentials" });

        const token = generateToken(user._id, user.role);

        res.status(200).json({ token, role: user.role });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Forgot Password
exports.forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "User not found" });

        // Generate Reset Token
        const resetToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "15m" });
        user.resetToken = resetToken;
        user.resetTokenExpiry = Date.now() + 15 * 60 * 1000; // 15 minutes
        await user.save();

        // Send Email
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Password Reset",
            text: `Reset your password using this token: ${resetToken}`,
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: "Password reset token sent!" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Reset Password
exports.resetPassword = async (req, res) => {
    try {
        const { resetToken, newPassword } = req.body;

        const decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
        const user = await User.findOne({ _id: decoded.id, resetToken });
        if (!user || user.resetTokenExpiry < Date.now()) {
            return res.status(400).json({ error: "Invalid or expired token" });
        }

        user.password = newPassword;
        user.resetToken = null;
        user.resetTokenExpiry = null;
        await user.save();

        res.status(200).json({ message: "Password reset successfully!" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
};

// Two-Factor Authentication (MFA)
exports.generate2FA = async (req, res) => {
    const secret = speakeasy.generateSecret();
    res.status(200).json({ secret: secret.base32 });
};

exports.verify2FA = async (req, res) => {
    const { token, secret } = req.body;

    const verified = speakeasy.totp.verify({ secret, encoding: "base32", token });
    if (!verified) return res.status(400).json({ error: "Invalid token" });

    res.status(200).json({ message: "2FA Verified!" });
};
