require('dotenv').config();
const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const path = require('path');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const { body, validationResult } = require('express-validator');

const db = require('./db');
const { encrypt, decrypt } = require('./cryptoUtil');

// 1. Session Secret Validation
if (!process.env.SESSION_SECRET) {
    throw new Error('CRITICAL: SESSION_SECRET is not defined in environment variables.');
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Static files
app.use(express.static(path.join(__dirname, '../frontend')));

// 2. Secure Session Cookie
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 600000,
        httpOnly: true,
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production' // Requires HTTPS in production
    }
}));

// 3. CSRF Protection Middleware
const csrfProtection = csurf({ cookie: true });

// Endpoint to provide CSRF token to frontend
app.get('/api/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// 4. Rate Limiter for Login (Brute Force Protection)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login requests per `window`
    message: { error: 'Quá nhiều lần thử đăng nhập. Vui lòng thử lại sau 15 phút.' },
    standardHeaders: true, 
    legacyHeaders: false, 
});

const login2faLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, 
    max: 3, 
    message: { error: 'Quá nhiều lần thử mã OTP thất bại. Vui lòng thử lại sau 5 phút.' },
    standardHeaders: true, 
    legacyHeaders: false, 
});

// Helper for express-validator
const validate = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Dữ liệu đầu vào không hợp lệ' });
    }
    next();
};

// --- Endpoints ---

// User Registration with input validation and bcrypt
app.post('/api/register', csrfProtection, [
    body('username').trim().isLength({ min: 3, max: 30 }).escape(),
    body('password').isLength({ min: 6 })
], validate, async (req, res) => {
    const { username, password } = req.body;
    
    try {
        // 5. Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], function(err) {
            if (err) {
                return res.status(400).json({ error: 'Tên đăng nhập đã tồn tại' });
            }
            res.json({ success: true, message: 'Người dùng đăng ký thành công' });
        });
    } catch (err) {
        res.status(500).json({ error: 'Lỗi server' });
    }
});

// User Login with timing attack mitigation and session fixation fix
app.post('/api/login', loginLimiter, csrfProtection, [
    body('username').trim().notEmpty().escape(),
    body('password').notEmpty()
], validate, (req, res) => {
    const { username, password } = req.body;
    
    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
        let isValidPassword = false;
        
        if (user) {
            isValidPassword = await bcrypt.compare(password, user.password);
        } else {
            // 6. Timing Attack Mitigation: Always perform a bcrypt compare
            await bcrypt.compare(password, '$2b$10$dummyHashDummyHashDummyHashDummyHashDummy');
        }

        if (err || !user || !isValidPassword) {
            return res.status(401).json({ error: 'Sai tên đăng nhập hoặc mật khẩu' });
        }

        // 7. Session Fixation Mitigation: Regenerate session after basic auth
        req.session.regenerate((err) => {
            if (err) return res.status(500).json({ error: 'Lỗi phiên đăng nhập' });
            
            req.session.userId = user.id;
            req.session.username = user.username;

            if (user.two_factor_enabled) {
                req.session.pending2fa = true;
                return res.json({ require2fa: true, redirect: '/verify-2fa.html' });
            } else {
                // 8. Bypass 2FA Setup Fix: Do NOT set authenticated = true yet.
                req.session.pendingSetup2fa = true; 
                return res.json({ requireSetup: true, redirect: '/setup-2fa.html' });
            }
        });
    });
});

// Setup 2FA
app.post('/api/setup-2fa', csrfProtection, (req, res) => {
    if (!req.session.userId || !req.session.pendingSetup2fa) {
        return res.status(401).json({ error: 'Phiên đăng nhập đã hết hạn hoặc không hợp lệ' });
    }

    // 9. Use otplib@11 authenticator correctly
    const secret = authenticator.generateSecret();
    const otpauthUrl = authenticator.keyuri(req.session.username, 'MFA Demo App', secret);

    const encryptedSecret = encrypt(secret);

    db.run(`UPDATE users SET two_factor_secret = ? WHERE id = ?`, [encryptedSecret, req.session.userId], (err) => {
        if (err) return res.status(500).json({ error: 'Lỗi cơ sở dữ liệu' });

        qrcode.toDataURL(otpauthUrl, (err, dataUrl) => {
            if (err) return res.status(500).json({ error: 'Lỗi tạo mã QR' });
            res.json({ qrCode: dataUrl });
        });
    });
});

// Verify Setup 2FA
app.post('/api/verify-setup-2fa', csrfProtection, [
    body('token').isLength({ min: 6, max: 6 }).isNumeric()
], validate, (req, res) => {
    if (!req.session.userId || !req.session.pendingSetup2fa) {
        return res.status(401).json({ error: 'Phiên đăng nhập đã hết hạn' });
    }
    const { token } = req.body;
    // Lưu trước khi regenerate() xóa session cũ
    const currentUserId = req.session.userId;
    const currentUsername = req.session.username;

    db.get(`SELECT two_factor_secret FROM users WHERE id = ?`, [currentUserId], (err, user) => {
        if (err || !user || !user.two_factor_secret) return res.status(400).json({ error: 'Chưa cài đặt 2FA' });

        const secret = decrypt(user.two_factor_secret);
        const isValid = authenticator.check(token, secret);

        if (isValid) {
            db.run(`UPDATE users SET two_factor_enabled = 1 WHERE id = ?`, [currentUserId], (err) => {
                if (err) return res.status(500).json({ error: 'Lỗi cơ sở dữ liệu' });
                
                // Session fixation mitigation for 2FA success
                req.session.regenerate((err) => {
                    if (err) return res.status(500).json({ error: 'Lỗi phiên đăng nhập' });
                    req.session.userId = currentUserId;
                    req.session.username = currentUsername;
                    req.session.authenticated = true;
                    res.json({ success: true });
                });
            });
        } else {
            res.status(400).json({ error: 'Mã xác nhận không hợp lệ' });
        }
    });
});

// Verify Login 2FA
app.post('/api/verify-login-2fa', login2faLimiter, csrfProtection, [
    body('token').isLength({ min: 6, max: 6 }).isNumeric()
], validate, (req, res) => {
    if (!req.session.userId || !req.session.pending2fa) {
        return res.status(401).json({ error: 'Phiên đăng nhập hết hạn hoặc chưa yêu cầu 2FA' });
    }
    const { token } = req.body;
    // Lưu trước khi regenerate() xóa session cũ
    const currentUserId = req.session.userId;
    const currentUsername = req.session.username;

    db.get(`SELECT two_factor_secret FROM users WHERE id = ?`, [currentUserId], (err, user) => {
        if (err || !user || !user.two_factor_secret) return res.status(400).json({ error: 'Chưa cài đặt 2FA' });

        const secret = decrypt(user.two_factor_secret);
        const isValid = authenticator.check(token, secret);

        if (isValid) {
            // Session fixation mitigation for 2FA success
            req.session.regenerate((err) => {
                if (err) return res.status(500).json({ error: 'Lỗi phiên đăng nhập' });
                req.session.userId = currentUserId;
                req.session.username = currentUsername;
                req.session.authenticated = true;
                res.json({ success: true });
            });
        } else {
            res.status(400).json({ error: 'Mã xác nhận không hợp lệ' });
        }
    });
});

app.post('/api/logout', csrfProtection, (req, res) => {
    req.session.destroy();
    res.clearCookie('connect.sid');
    res.json({ success: true });
});

app.get('/api/dashboard', (req, res) => {
    if (!req.session.authenticated) {
        return res.status(401).json({ error: 'Không có quyền truy cập' });
    }
    res.json({ message: `Chào mừng đến với trang quản trị, ${req.session.username}!` });
});

// CSRF error handler
app.use(function (err, req, res, next) {
    if (err.code !== 'EBADCSRFTOKEN') return next(err);
    res.status(403).json({ error: 'CSRF token không hợp lệ' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
