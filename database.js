const sqlite3 = require('sqlite3').verbose();

// Connect to a file-based database. This will create the file if it doesn't exist.
const db = new sqlite3.Database('./app_data.db', (err) => {
    if (err) {
        console.error('Error opening database', err.message);
    } else {
        console.log('Connected to the SQLite database.');
        
        // Use serialize to ensure tables are created in order
        db.serialize(() => {
            // Create the users table
            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`, (err) => {
                if (err) console.error('Error creating users table', err.message);
            });

            // Create the orders table with a user_id to link to the users table
            db.run(`CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                reference TEXT NOT NULL UNIQUE,
                phone_number TEXT NOT NULL,
                network TEXT NOT NULL,
                data_plan TEXT NOT NULL,
                amount REAL NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )`, (err) => {
                if (err) console.error('Error creating orders table', err.message);
            });
        });
    }
});

module.exports = db;