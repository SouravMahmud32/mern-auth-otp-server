const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const passport = require('passport');
const User = require('../models/User');
const router = express.Router();

require('dotenv').config();

// Configure nodemailer transporter using Ethereal account
const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    secure: false,
    auth: {
        user: 'ansley.koss@ethereal.email',
        pass: '4DCExBGHC42H6PhmP2'
    },
});

// Register route
router.post('/register', async (req, res) => {
    const { email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const otp = crypto.randomBytes(3).toString('hex'); // Generate OTP
        const otpExpires = Date.now() + 3600000; // 1 hour expiration

        user = new User({ email, password: hashedPassword, otp, otpExpires, isVerified: false });
        await user.save();

        const mailOptions = {
            from: 'noreply@example.com',
            to: email,
            subject: 'OTP for Account Verification',
            text: `Your OTP is: ${otp}`,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending OTP:', error);
                return res.status(500).json({ msg: 'Error sending OTP' });
            }
            console.log('Message sent:', info.messageId);
            console.log('Preview URL:', nodemailer.getTestMessageUrl(info));
            res.json({ msg: 'OTP sent to your email' });
        });
    } catch (err) {
        console.error('Server error:', err.message);
        res.status(500).send('Server error');
    }
});

// Verify OTP for registration
router.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'User does not exist' });
        }
        if (user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ msg: 'Invalid or expired OTP' });
        }

        user.isVerified = true;
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        // Create JWT
        const payload = { user: { id: user.id } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });
    } catch (err) {
        console.error('Server error:', err.message);
        res.status(500).send('Server error');
    }
});

// Login route
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid email or password' });
        }

        const otp = crypto.randomBytes(3).toString('hex');
        const otpExpires = Date.now() + 3600000; 

        user.otp = otp;
        user.otpExpires = otpExpires;
        await user.save();

        const mailOptions = {
            from: 'noreply@example.com',
            to: email,
            subject: 'OTP for Login',
            text: `Your OTP is: ${otp}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Error sending OTP:', error);
                return res.status(500).json({ msg: 'Error sending OTP' });
            }
            console.log('Message sent:', info.messageId);
            console.log('Preview URL:', nodemailer.getTestMessageUrl(info));
            res.json({ msg: 'OTP sent to your email' });
        });
    } catch (err) {
        console.error('Server error:', err.message);
        res.status(500).send('Server error');
    }
});

// Verify OTP for login
router.post('/verify-login-otp', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'User does not exist' });
        }
        if (user.otp !== otp || user.otpExpires < Date.now()) {
            return res.status(400).json({ msg: 'Invalid or expired OTP' });
        }

        // Clear OTP after successful verification
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        // Create JWT
        const payload = { user: { id: user.id } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });
    } catch (err) {
        console.error('Server error:', err.message);
        res.status(500).send('Server error');
    }
});

// Google OAuth Routes
router.get('/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        res.redirect('http://localhost:3001/home');
    }
);

router.get('/logout', (req, res) => {
    req.logout(err => {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

module.exports = router;
