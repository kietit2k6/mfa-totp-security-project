require('dotenv').config();
const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const path = require('path');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
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

// 3. Custom CSRF Protection Middleware
const csrfProtection = (req, res, next) => {
    // Tự động tạo CSRF token nếu chưa có trong session
    if (!req.session.csrfToken) {
        req.session.csrfToken = require('crypto').randomBytes(32).toString('hex');
    }

    // Các request đọc dữ liệu (GET, HEAD, OPTIONS) không cần kiểm tra CSRF
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
        return next();
    }

    // Các request thay đổi trạng thái (POST, PUT, DELETE,...) bắt buộc phải khớp Token
    const clientToken = req.headers['csrf-token'] || req.headers['x-csrf-token'];
    const sessionToken = req.session.csrfToken;

    if (!sessionToken || clientToken !== sessionToken) {
        console.warn(`[SECURITY] Từ chối request do lỗi CSRF Token từ IP: ${req.ip}`);
        return res.status(403).json({ error: 'CSRF token không hợp lệ hoặc đã hết hạn.' });
    }
    next();
};

// Endpoint để cung cấp CSRF token cho frontend
app.get('/api/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.session.csrfToken });
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
    windowMs: 15 * 60 * 1000, // 15 phút
    max: 5, // Giới hạn 5 lần thử mỗi IP
    message: { error: 'Quá nhiều lần thử mã OTP thất bại. IP đã bị khóa trong 15 phút.' },
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

// --- Security: In-memory stores ---

// 10. Account Lockout Tracking: userId -> { count, lockedUntil }
const failedOtpAttempts = new Map();

// 11. Used OTP Tracking (Replay Attack Prevention): "userId:token" -> timestamp
const usedOtpTokens = new Map();

// Tự động dọn dẹp OTP đã dùng mỗi 60 giây
setInterval(() => {
    const now = Date.now();
    for (const [key, timestamp] of usedOtpTokens) {
        if (now - timestamp > 60000) {
            usedOtpTokens.delete(key);
        }
    }
}, 60000);

function isAccountLocked(userId) {
    const record = failedOtpAttempts.get(userId);
    if (!record) return false;
    if (record.lockedUntil && Date.now() < record.lockedUntil) return true;
    if (record.lockedUntil && Date.now() >= record.lockedUntil) {
        failedOtpAttempts.delete(userId); // Hết thời gian khóa -> mở khóa
        return false;
    }
    return false;
}

function recordFailedOtp(userId) {
    const record = failedOtpAttempts.get(userId) || { count: 0, lockedUntil: null };
    record.count += 1;
    if (record.count >= 5) {
        record.lockedUntil = Date.now() + 15 * 60 * 1000; // Khóa tài khoản 15 phút
        console.warn(`[SECURITY] Tài khoản ID ${userId} đã bị khóa do nhập OTP sai 5 lần liên tiếp.`);
    }
    failedOtpAttempts.set(userId, record);
}

function resetFailedOtp(userId) {
    failedOtpAttempts.delete(userId);
}

function isOtpReplay(userId, token) {
    return usedOtpTokens.has(`${userId}:${token}`);
}

function markOtpUsed(userId, token) {
    usedOtpTokens.set(`${userId}:${token}`, Date.now());
}

// 12. Session Binding Middleware: Kiểm tra IP & User-Agent
function sessionGuard(req, res, next) {
    if (req.session && req.session.authenticated) {
        const currentIp = req.ip;
        const currentUserAgent = req.headers['user-agent'] || '';

        if (req.session.boundIp && req.session.boundIp !== currentIp) {
            console.warn(`[SECURITY] Session IP mismatch - User: ${req.session.username}, Expected: ${req.session.boundIp}, Got: ${currentIp}`);
            req.session.destroy();
            return res.status(401).json({ error: 'Phát hiện bất thường. Phiên đăng nhập đã bị hủy vì lý do bảo mật.' });
        }

        if (req.session.boundUserAgent && req.session.boundUserAgent !== currentUserAgent) {
            console.warn(`[SECURITY] Session User-Agent mismatch - User: ${req.session.username}`);
            req.session.destroy();
            return res.status(401).json({ error: 'Phát hiện bất thường. Phiên đăng nhập đã bị hủy vì lý do bảo mật.' });
        }
    }
    next();
}

app.use(sessionGuard);

// --- Endpoints ---

// User Registration with input validation and bcrypt
app.post('/api/register', csrfProtection, [
    body('username').trim().isLength({ min: 3, max: 30 }).escape(),
    body('password').isLength({ min: 8 })
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

    // Chống tấn công phát lại (Replay Attack)
    if (isOtpReplay(currentUserId, token)) {
        console.warn(`[SECURITY] Replay attack detected - User ID: ${currentUserId}, OTP đã được sử dụng trước đó.`);
        return res.status(400).json({ error: 'Mã OTP đã được sử dụng. Vui lòng đợi mã mới.' });
    }

    db.get(`SELECT two_factor_secret FROM users WHERE id = ?`, [currentUserId], (err, user) => {
        if (err || !user || !user.two_factor_secret) return res.status(400).json({ error: 'Chưa cài đặt 2FA' });

        const secret = decrypt(user.two_factor_secret);
        const isValid = authenticator.check(token, secret);

        if (isValid) {
            // Đánh dấu OTP đã sử dụng để chống replay
            markOtpUsed(currentUserId, token);

            db.run(`UPDATE users SET two_factor_enabled = 1 WHERE id = ?`, [currentUserId], (err) => {
                if (err) return res.status(500).json({ error: 'Lỗi cơ sở dữ liệu' });
                
                // Session fixation mitigation for 2FA success
                req.session.regenerate((err) => {
                    if (err) return res.status(500).json({ error: 'Lỗi phiên đăng nhập' });
                    req.session.userId = currentUserId;
                    req.session.username = currentUsername;
                    req.session.authenticated = true;
                    // Ràng buộc Session với IP và User-Agent
                    req.session.boundIp = req.ip;
                    req.session.boundUserAgent = req.headers['user-agent'] || '';
                    console.log(`[AUTH] User "${currentUsername}" đã kích hoạt 2FA thành công từ IP: ${req.ip}`);
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

    // Kiểm tra khóa tài khoản (Account Lockout)
    if (isAccountLocked(currentUserId)) {
        console.warn(`[SECURITY] Tài khoản ID ${currentUserId} đang bị khóa - từ chối xác thực OTP.`);
        return res.status(423).json({ error: 'Tài khoản đã bị khóa do nhập OTP sai quá 5 lần. Vui lòng thử lại sau 15 phút.' });
    }

    // Chống tấn công phát lại (Replay Attack)
    if (isOtpReplay(currentUserId, token)) {
        console.warn(`[SECURITY] Replay attack detected - User ID: ${currentUserId}, OTP đã được sử dụng trước đó.`);
        return res.status(400).json({ error: 'Mã OTP đã được sử dụng. Vui lòng đợi mã mới.' });
    }

    db.get(`SELECT two_factor_secret FROM users WHERE id = ?`, [currentUserId], (err, user) => {
        if (err || !user || !user.two_factor_secret) return res.status(400).json({ error: 'Chưa cài đặt 2FA' });

        const secret = decrypt(user.two_factor_secret);
        const isValid = authenticator.check(token, secret);

        if (isValid) {
            // Đánh dấu OTP đã sử dụng để chống replay
            markOtpUsed(currentUserId, token);
            // Reset bộ đếm OTP sai khi xác thực thành công
            resetFailedOtp(currentUserId);

            // Session fixation mitigation for 2FA success
            req.session.regenerate((err) => {
                if (err) return res.status(500).json({ error: 'Lỗi phiên đăng nhập' });
                req.session.userId = currentUserId;
                req.session.username = currentUsername;
                req.session.authenticated = true;
                // Ràng buộc Session với IP và User-Agent
                req.session.boundIp = req.ip;
                req.session.boundUserAgent = req.headers['user-agent'] || '';
                console.log(`[AUTH] User "${currentUsername}" đã xác thực 2FA thành công từ IP: ${req.ip}`);
                res.json({ success: true });
            });
        } else {
            // Ghi nhận lần nhập OTP sai
            recordFailedOtp(currentUserId);
            const record = failedOtpAttempts.get(currentUserId);
            const remaining = 5 - (record ? record.count : 0);

            if (remaining <= 0) {
                console.warn(`[SECURITY] Tài khoản "${currentUsername}" (ID: ${currentUserId}) đã bị khóa 15 phút từ IP: ${req.ip}`);
                res.status(423).json({ error: 'Tài khoản đã bị khóa do nhập OTP sai quá 5 lần. Vui lòng thử lại sau 15 phút.' });
            } else {
                console.warn(`[AUTH] User "${currentUsername}" nhập OTP sai. Còn ${remaining} lần thử.`);
                res.status(400).json({ error: `Mã OTP không hợp lệ. Còn ${remaining} lần thử.` });
            }
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

// Server port config and startup

const PORT = process.env.PORT || 3000;

// Chỉ lắng nghe cổng trực tiếp khi chạy ở máy local
if (!process.env.VERCEL) {
    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}

module.exports = app;
