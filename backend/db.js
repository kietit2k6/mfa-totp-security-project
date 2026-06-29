const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Trên Vercel (Serverless), thư mục chứa code là Read-Only.
// Chúng ta phải ghi file database vào thư mục '/tmp' của môi trường Serverless.
const dbPath = process.env.VERCEL 
    ? path.join('/tmp', 'database.sqlite')
    : path.resolve(__dirname, 'database.sqlite');

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error("Error opening database " + err.message);
    } else {
        console.log("Connected to the SQLite database.");
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            two_factor_secret TEXT,
            two_factor_enabled INTEGER DEFAULT 0
        )`, (err) => {
            if (err) {
                console.log("Table already exists or error creating table.");
            } else {
                console.log("Table 'users' initialized.");
            }
        });
    }
});

module.exports = db;
