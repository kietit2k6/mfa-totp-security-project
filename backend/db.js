const fs = require('fs');
const path = require('path');

// Định cấu hình đường dẫn lưu file dữ liệu JSON
const dbPath = process.env.VERCEL 
    ? path.join('/tmp', 'users.json')
    : path.resolve(__dirname, 'users.json');

// Hàm đọc dữ liệu từ file JSON
function readData() {
    try {
        if (fs.existsSync(dbPath)) {
            const raw = fs.readFileSync(dbPath, 'utf8');
            return JSON.parse(raw);
        }
    } catch (e) {
        console.error("Lỗi đọc file cơ sở dữ liệu JSON:", e);
    }
    return [];
}

// Hàm ghi dữ liệu xuống file JSON
function writeData(data) {
    try {
        fs.writeFileSync(dbPath, JSON.stringify(data, null, 2), 'utf8');
    } catch (e) {
        console.error("Lỗi ghi file cơ sở dữ liệu JSON:", e);
    }
}

// Khởi tạo file dữ liệu trống nếu chưa tồn tại
if (!fs.existsSync(dbPath)) {
    writeData([]);
}

console.log("Connected to JSON database at: " + dbPath);

const db = {
    // Giả lập lệnh db.get (SELECT)
    get: (sql, params, callback) => {
        try {
            const users = readData();
            
            // SELECT * FROM users WHERE username = ?
            if (sql.includes('username = ?')) {
                const user = users.find(u => u.username === params[0]);
                return callback(null, user || null);
            }
            
            // SELECT two_factor_secret FROM users WHERE id = ?
            if (sql.includes('id = ?')) {
                const userId = parseInt(params[0], 10);
                const user = users.find(u => u.id === userId);
                return callback(null, user || null);
            }
            
            return callback(new Error("Lệnh SQL SELECT mock chưa được định nghĩa: " + sql), null);
        } catch (err) {
            return callback(err, null);
        }
    },
    
    // Giả lập lệnh db.run (INSERT / UPDATE)
    run: (sql, params, callback) => {
        try {
            const users = readData();
            
            // INSERT INTO users (username, password) VALUES (?, ?)
            if (sql.includes('INSERT INTO users')) {
                const username = params[0];
                const password = params[1];
                
                // Kiểm tra tên đăng nhập tồn tại (UNIQUE Constraint)
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
                writeData(users);
                
                // SQLite trả về callback với object chứa lastID
                return callback.call({ lastID: newUser.id }, null);
            }
            
            // UPDATE users SET two_factor_secret = ? WHERE id = ?
            if (sql.includes('two_factor_secret = ?')) {
                const secret = params[0];
                const userId = parseInt(params[1], 10);
                
                const user = users.find(u => u.id === userId);
                if (user) {
                    user.two_factor_secret = secret;
                    writeData(users);
                }
                return callback(null);
            }
            
            // UPDATE users SET two_factor_enabled = 1 WHERE id = ?
            if (sql.includes('two_factor_enabled = 1')) {
                const userId = parseInt(params[0], 10);
                
                const user = users.find(u => u.id === userId);
                if (user) {
                    user.two_factor_enabled = 1;
                    writeData(users);
                }
                return callback(null);
            }
            
            return callback(new Error("Lệnh SQL UPDATE/INSERT mock chưa được định nghĩa: " + sql));
        } catch (err) {
            return callback(err);
        }
    }
};

module.exports = db;
