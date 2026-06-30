const fs = require('fs');
const path = require('path');
const { MongoClient } = require('mongodb');
require('dotenv').config();

const mongoUri = process.env.MONGODB_URI;
let dbInstance = null;
let client = null;
let useMongo = false;

// Cấu hình fallback JSON nếu không có MongoDB URI
const dbPath = process.env.VERCEL 
    ? path.join('/tmp', 'users.json')
    : path.resolve(__dirname, 'users.json');

// Khởi tạo file dữ liệu trống nếu chưa tồn tại
if (!fs.existsSync(dbPath)) {
    try {
        fs.writeFileSync(dbPath, JSON.stringify([], null, 2), 'utf8');
    } catch(e) {
        console.warn("Không thể tạo file database JSON dự phòng:", e.message);
    }
}

function readJsonData() {
    try {
        if (fs.existsSync(dbPath)) {
            const raw = fs.readFileSync(dbPath, 'utf8');
            return JSON.parse(raw);
        }
    } catch (e) {
        console.error("Lỗi đọc file JSON dự phòng:", e);
    }
    return [];
}

function writeJsonData(data) {
    try {
        fs.writeFileSync(dbPath, JSON.stringify(data, null, 2), 'utf8');
    } catch (e) {
        console.error("Lỗi ghi file JSON dự phòng:", e);
    }
}

if (mongoUri) {
    useMongo = true;
    console.log("[DB Debug] Tìm thấy cấu hình MONGODB_URI (độ dài: " + mongoUri.length + "). Đang kết nối...");
} else {
    console.log("[DB Debug] Không tìm thấy cấu hình MONGODB_URI. Sử dụng JSON database dự phòng tại: " + dbPath);
}

async function getCollection() {
    if (!useMongo) return null;
    if (!dbInstance) {
        try {
            client = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 5000 });
            await client.connect();
            dbInstance = client.db();
            console.log("Đã kết nối MongoDB thành công.");
        } catch (err) {
            console.error("[DB Debug] Lỗi kết nối MongoDB CHI TIẾT:", err);
            console.error("Lỗi kết nối MongoDB, chuyển hướng sang JSON database dự phòng:", err.message);
            useMongo = false; // Tự động fallback nếu kết nối lỗi
            return null;
        }
    }
    return dbInstance.collection('users');
}

// Khởi chạy kết nối thử MongoDB nếu được cấu hình
if (useMongo) {
    getCollection().catch(err => {
        console.error("Khởi chạy MongoDB thất bại:", err.message);
    });
}

const db = {
    // Thực thi SELECT SQL giả lập
    get: (sql, params, callback) => {
        getCollection().then(async (collection) => {
            try {
                if (useMongo && collection) {
                    // 1. SELECT * FROM users WHERE username = ?
                    if (sql.includes('username = ?')) {
                        const username = params[0];
                        const user = await collection.findOne({ username });
                        return callback(null, user || null);
                    }

                    // 2. SELECT two_factor_secret FROM users WHERE id = ?
                    if (sql.includes('id = ?')) {
                        const userId = params[0];
                        const user = await collection.findOne({
                            $or: [
                                { id: userId },
                                { id: Number(userId) },
                                { id: String(userId) }
                            ]
                        });
                        return callback(null, user || null);
                    }
                    return callback(new Error("Lệnh SQL SELECT chưa được định nghĩa trong wrapper: " + sql), null);
                } else {
                    // --- FALLBACK JSON ---
                    const users = readJsonData();
                    if (sql.includes('username = ?')) {
                        const user = users.find(u => u.username === params[0]);
                        return callback(null, user || null);
                    }
                    if (sql.includes('id = ?')) {
                        const userId = parseInt(params[0], 10);
                        const user = users.find(u => u.id === userId);
                        return callback(null, user || null);
                    }
                    return callback(new Error("Lệnh SQL SELECT mock chưa được định nghĩa: " + sql), null);
                }
            } catch (err) {
                return callback(err, null);
            }
        }).catch(err => {
            return callback(err, null);
        });
    },
    
    // Thực thi INSERT / UPDATE SQL giả lập
    run: (sql, params, callback) => {
        getCollection().then(async (collection) => {
            try {
                if (useMongo && collection) {
                    // 1. INSERT INTO users (username, password) VALUES (?, ?)
                    if (sql.includes('INSERT INTO users')) {
                        const username = params[0];
                        const password = params[1];

                        const existing = await collection.findOne({ username });
                        if (existing) {
                            const err = new Error("Tên đăng nhập đã tồn tại");
                            err.code = "SQLITE_CONSTRAINT";
                            return callback(err);
                        }

                        const numericId = Date.now();
                        const newUser = {
                            id: numericId,
                            username,
                            password,
                            two_factor_secret: null,
                            two_factor_enabled: 0
                        };

                        await collection.insertOne(newUser);
                        return callback.call({ lastID: numericId }, null);
                    }

                    // 2. UPDATE users SET two_factor_secret = ?, two_factor_enabled = 1 WHERE id = ?
                    if (sql.includes('two_factor_secret = ?') && sql.includes('two_factor_enabled = 1')) {
                        const secret = params[0];
                        const userId = params[1];

                        await collection.updateOne(
                            {
                                $or: [
                                    { id: userId },
                                    { id: Number(userId) },
                                    { id: String(userId) }
                                ]
                            },
                            {
                                $set: {
                                    two_factor_secret: secret,
                                    two_factor_enabled: 1
                                }
                            }
                        );
                        return callback(null);
                    }

                    // 3. UPDATE users SET two_factor_secret = ? WHERE id = ?
                    if (sql.includes('two_factor_secret = ?')) {
                        const secret = params[0];
                        const userId = params[1];

                        await collection.updateOne(
                            {
                                $or: [
                                    { id: userId },
                                    { id: Number(userId) },
                                    { id: String(userId) }
                                ]
                            },
                            {
                                $set: {
                                    two_factor_secret: secret
                                }
                            }
                        );
                        return callback(null);
                    }

                    // 4. UPDATE users SET two_factor_enabled = 1 WHERE id = ?
                    if (sql.includes('two_factor_enabled = 1')) {
                        const userId = params[0];

                        await collection.updateOne(
                            {
                                $or: [
                                    { id: userId },
                                    { id: Number(userId) },
                                    { id: String(userId) }
                                ]
                            },
                            {
                                $set: {
                                    two_factor_enabled: 1
                                }
                            }
                        );
                        return callback(null);
                    }
                    return callback(new Error("Lệnh SQL UPDATE/INSERT chưa được định nghĩa trong wrapper: " + sql));
                } else {
                    // --- FALLBACK JSON ---
                    const users = readJsonData();
                    
                    if (sql.includes('INSERT INTO users')) {
                        const username = params[0];
                        const password = params[1];
                        
                        if (users.some(u => u.username === username)) {
                            const err = new Error("Tên đăng nhập đã tồn tại");
                            err.code = "SQLITE_CONSTRAINT";
                            return callback(err);
                        }
                        
                        const newUser = {
                            id: Date.now(),
                            username,
                            password,
                            two_factor_secret: null,
                            two_factor_enabled: 0
                        };
                        users.push(newUser);
                        writeJsonData(users);
                        return callback.call({ lastID: newUser.id }, null);
                    }
                    
                    if (sql.includes('two_factor_secret = ?') && sql.includes('two_factor_enabled = 1')) {
                        const secret = params[0];
                        const userId = parseInt(params[1], 10);
                        const user = users.find(u => u.id === userId);
                        if (user) {
                            user.two_factor_secret = secret;
                            user.two_factor_enabled = 1;
                            writeJsonData(users);
                        }
                        return callback(null);
                    }

                    if (sql.includes('two_factor_secret = ?')) {
                        const secret = params[0];
                        const userId = parseInt(params[1], 10);
                        const user = users.find(u => u.id === userId);
                        if (user) {
                            user.two_factor_secret = secret;
                            writeJsonData(users);
                        }
                        return callback(null);
                    }
                    
                    if (sql.includes('two_factor_enabled = 1')) {
                        const userId = parseInt(params[0], 10);
                        const user = users.find(u => u.id === userId);
                        if (user) {
                            user.two_factor_enabled = 1;
                            writeJsonData(users);
                        }
                        return callback(null);
                    }
                    return callback(new Error("Lệnh SQL UPDATE/INSERT mock chưa được định nghĩa: " + sql));
                }
            } catch (err) {
                return callback(err);
            }
        }).catch(err => {
            return callback(err);
        });
    }
};

module.exports = db;
