const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');

const DB_FILE = path.join(__dirname, 'attendance.db');
const SCHEMA_FILE = path.join(__dirname, 'schema.sql');

// Ensure DB file exists (sqlite3 will create if it does not)
const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) {
    console.error('Failed to connect to SQLite database:', err.message);
  } else {
    console.log('Connected to SQLite database at', DB_FILE);
  }
});

// Run schema on startup
const schemaSql = fs.readFileSync(SCHEMA_FILE, 'utf8');

db.serialize(() => {
  db.exec(schemaSql, (err) => {
    if (err) {
      console.error('Error applying database schema:', err.message);
    } else {
      console.log('Database schema ensured.');
    }
  });

  // Lightweight migrations: ensure extra teacher detail columns exist on users table.
  // These ALTERs will fail with "duplicate column name" after the first run; we ignore that.
  const alterStatements = [
    "ALTER TABLE users ADD COLUMN email TEXT",
    "ALTER TABLE users ADD COLUMN phone TEXT",
    "ALTER TABLE users ADD COLUMN subject TEXT",
    "ALTER TABLE users ADD COLUMN experience TEXT",
  ];

  alterStatements.forEach((sql) => {
    db.run(sql, (alterErr) => {
      if (alterErr && !/duplicate column name/i.test(alterErr.message)) {
        console.error('Migration error:', alterErr.message);
      }
    });
  });
});

module.exports = db;
