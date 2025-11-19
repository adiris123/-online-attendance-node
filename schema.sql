-- PostgreSQL schema for attendance management system
-- Foreign keys are enabled by default in PostgreSQL

-- Core domain tables
CREATE TABLE IF NOT EXISTS classes (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  description TEXT
);

CREATE TABLE IF NOT EXISTS students (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  roll_number VARCHAR(50),
  class_id INTEGER NOT NULL,
  FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
  id SERIAL PRIMARY KEY,
  class_id INTEGER NOT NULL,
  date DATE NOT NULL,
  topic TEXT,
  FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attendance (
  id SERIAL PRIMARY KEY,
  session_id INTEGER NOT NULL,
  student_id INTEGER NOT NULL,
  status VARCHAR(10) NOT NULL CHECK (status IN ('present','absent')),
  marked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(session_id, student_id),
  FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
);

-- Users table with roles for Admin / Teacher / Student
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL CHECK (role IN ('admin','teacher','student')) DEFAULT 'teacher',
  display_name VARCHAR(255),
  class_id INTEGER,
  student_id INTEGER,
  email VARCHAR(255),
  phone VARCHAR(50),
  subject VARCHAR(255),
  experience TEXT,
  FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE SET NULL,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE SET NULL
);

-- Seed demo data (safe to run multiple times using ON CONFLICT)
-- Note: Using explicit IDs requires setting the sequence to the correct value
INSERT INTO classes (id, name, description) VALUES (1, 'Class 12', 'Demo class for examples')
ON CONFLICT (id) DO NOTHING;
SELECT setval('classes_id_seq', COALESCE((SELECT MAX(id) FROM classes), 1), true);

INSERT INTO students (id, name, roll_number, class_id) VALUES (1, 'aditya', '123', 1)
ON CONFLICT (id) DO NOTHING;
SELECT setval('students_id_seq', COALESCE((SELECT MAX(id) FROM students), 1), true);

-- Admin / Teacher / Student demo accounts
INSERT INTO users (id, username, password, role, display_name) VALUES (1, 'admin', 'admin123', 'admin', 'System Admin')
ON CONFLICT (id) DO NOTHING;
SELECT setval('users_id_seq', COALESCE((SELECT MAX(id) FROM users), 1), true);

INSERT INTO users (id, username, password, role, display_name, class_id) VALUES (2, 'teacher1', 'teacher123', 'teacher', 'Demo Teacher', 1)
ON CONFLICT (id) DO NOTHING;
SELECT setval('users_id_seq', COALESCE((SELECT MAX(id) FROM users), 1), true);

INSERT INTO users (id, username, password, role, display_name, class_id, student_id) VALUES (3, 'aditya', 'student123', 'student', 'aditya', 1, 1)
ON CONFLICT (id) DO NOTHING;
SELECT setval('users_id_seq', COALESCE((SELECT MAX(id) FROM users), 1), true);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_attendance_session ON attendance(session_id);
CREATE INDEX IF NOT EXISTS idx_attendance_student ON attendance(student_id);
CREATE INDEX IF NOT EXISTS idx_students_class ON students(class_id);
CREATE INDEX IF NOT EXISTS idx_sessions_class ON sessions(class_id);
CREATE INDEX IF NOT EXISTS idx_sessions_class_date ON sessions(class_id, date);
CREATE INDEX IF NOT EXISTS idx_users_student ON users(student_id);
CREATE INDEX IF NOT EXISTS idx_users_class ON users(class_id);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
