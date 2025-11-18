PRAGMA foreign_keys = ON;

-- Core domain tables
CREATE TABLE IF NOT EXISTS classes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT
);

CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  roll_number TEXT,
  class_id INTEGER NOT NULL,
  FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  class_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  topic TEXT,
  FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attendance (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('present','absent')),
  marked_at TEXT DEFAULT (datetime('now')),
  UNIQUE(session_id, student_id),
  FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
);

-- Users table with roles for Admin / Teacher / Student
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','teacher','student')) DEFAULT 'teacher',
  display_name TEXT,
  class_id INTEGER,
  student_id INTEGER,
  email TEXT,
  phone TEXT,
  subject TEXT,
  experience TEXT,
  FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE SET NULL,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE SET NULL
);

-- Seed demo data (safe to run multiple times)
INSERT OR IGNORE INTO classes (id, name, description) VALUES (1, 'Class 12', 'Demo class for examples');
INSERT OR IGNORE INTO students (id, name, roll_number, class_id) VALUES (1, 'aditya', '123', 1);

-- Admin / Teacher / Student demo accounts
INSERT OR IGNORE INTO users (id, username, password, role, display_name) VALUES (1, 'admin', 'admin123', 'admin', 'System Admin');
INSERT OR IGNORE INTO users (id, username, password, role, display_name, class_id) VALUES (2, 'teacher1', 'teacher123', 'teacher', 'Demo Teacher', 1);
INSERT OR IGNORE INTO users (id, username, password, role, display_name, class_id, student_id) VALUES (3, 'aditya', 'student123', 'student', 'aditya', 1, 1);
