const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const PDFDocument = require('pdfkit');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory session store: token -> { user, expiresAt }
const sessions = new Map();
const SESSION_TTL_HOURS = parseInt(process.env.SESSION_TTL_HOURS || '8', 10);
const SESSION_TTL_MS = SESSION_TTL_HOURS * 60 * 60 * 1000;

// Clean up expired sessions periodically
setInterval(() => {
  const now = Date.now();
  let cleaned = 0;
  for (const [token, session] of sessions.entries()) {
    if (session.expiresAt && session.expiresAt <= now) {
      sessions.delete(token);
      cleaned++;
    }
  }
  if (cleaned > 0) {
    console.log(`Cleaned up ${cleaned} expired session(s)`);
  }
}, 1000 * 60 * 60); // Run every hour

// Rate limiting (login route excluded - correct credentials should never be blocked)
// Note: loginLimiter removed to ensure users with correct credentials can always log in

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute
  message: { error: 'Too many requests, please slow down' }
});

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-auth-token']
}));
app.use(bodyParser.json());
// Apply rate limiting to all API routes except static files
app.use('/api', apiLimiter);
app.use(express.static(path.join(__dirname, 'public')));

// --- Helpers ---
function handleDbCallback(res, successStatus = 200, transform = (rows) => rows) {
  return (err, result) => {
    if (err) {
      console.error('DB Error:', err);
      return res.status(500).json({ 
        error: 'Database error',
        details: process.env.NODE_ENV === 'development' ? err.message : undefined
      });
    }
    res.status(successStatus).json(transform(result));
  };
}

function getUserFromRequest(req) {
  const token = req.headers['x-auth-token'] || req.query.token;
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;

  if (session.expiresAt && session.expiresAt <= Date.now()) {
    // Expired session: clean it up and treat as unauthenticated
    sessions.delete(token);
    return null;
  }

  return session.user || null;
}

function createSession(userRow) {
  const safeUser = {
    id: userRow.id,
    username: userRow.username,
    role: userRow.role,
    class_id: userRow.class_id || null,
    student_id: userRow.student_id || null,
  };

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = Date.now() + SESSION_TTL_MS;
  sessions.set(token, { user: safeUser, expiresAt });
  return { token, user: safeUser, expiresAt };
}

function requireAuth(req, res, next) {
  const user = getUserFromRequest(req);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.user = user;
  return next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    return next();
  };
}

function validateInteger(value, fieldName) {
  const num = parseInt(value, 10);
  if (isNaN(num) || num <= 0) {
    throw new Error(`Invalid ${fieldName}: must be a positive integer`);
  }
  return num;
}

function validateDate(dateString) {
  const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRegex.test(dateString)) {
    throw new Error('Invalid date format. Use YYYY-MM-DD');
  }
  const date = new Date(dateString);
  if (isNaN(date.getTime())) {
    throw new Error('Invalid date value');
  }
  return dateString;
}

// --- Export helpers ---
function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const str = String(value);
  if (/[",\n]/.test(str)) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

function sendCsv(res, filename, headerColumns, rows) {
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  const headerLine = headerColumns.join(',') + '\n';
  const bodyLines = rows.map((cols) => cols.map(csvEscape).join(',')).join('\n');
  res.send(headerLine + bodyLines);
}

function sendStudentReportCsv(res, rows, label = 'student-report') {
  const filename = `${label}.csv`;
  const csvRows = rows.map((r) => [r.date, r.class_name, r.topic || '', r.status]);
  sendCsv(res, filename, ['Date', 'Class', 'Topic', 'Status'], csvRows);
}

function sendClassSummaryCsv(res, rows, label = 'class-summary') {
  const filename = `${label}.csv`;
  const csvRows = rows.map((r) => {
    const total = r.total || 0;
    const presents = r.presents || 0;
    const percent = total > 0 ? ((presents / total) * 100).toFixed(1) : '0.0';
    return [r.student_name, r.roll_number || '', presents, total, percent];
  });
  sendCsv(res, filename, ['Student', 'Roll', 'Presents', 'Total', 'Percent'], csvRows);
}

function sendStudentReportPdf(res, rows, options = {}) {
  const filename = options.filename || 'student-report.pdf';
  const title = options.title || 'Student Attendance Report';

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

  const doc = new PDFDocument({ margin: 40, size: 'A4' });
  doc.pipe(res);

  doc.fontSize(18).text(title, { align: 'center' });
  doc.moveDown();

  doc.fontSize(11);
  rows.forEach((r) => {
    doc.text(`${r.date}  |  ${r.class_name}  |  ${(r.topic || '')}  |  ${String(r.status).toUpperCase()}`);
  });

  doc.end();
}

function sendClassSummaryPdf(res, rows, options = {}) {
  const filename = options.filename || 'class-summary.pdf';
  const title = options.title || 'Class Attendance Summary';

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

  const doc = new PDFDocument({ margin: 40, size: 'A4' });
  doc.pipe(res);

  doc.fontSize(18).text(title, { align: 'center' });
  doc.moveDown();

  doc.fontSize(11);
  rows.forEach((r) => {
    const total = r.total || 0;
    const presents = r.presents || 0;
    const percent = total > 0 ? ((presents / total) * 100).toFixed(1) : '0.0';
    doc.text(`${r.student_name} (${r.roll_number || ''}) - ${presents}/${total} (${percent}%)`);
  });

  doc.end();
}

// --- Auth ---
app.post('/api/login', (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Username, password, and role are required' });
  }

  const sql = 'SELECT id, username, role, class_id, student_id, password FROM users WHERE username = ?';
  db.get(sql, [username], async (err, user) => {
    if (err) {
      console.error('Login error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Check password (support both hashed and plain text for migration)
    let passwordMatch = false;
    if (user.password.startsWith('$2b$') || user.password.startsWith('$2a$')) {
      // Hashed password
      passwordMatch = await bcrypt.compare(password, user.password);
    } else {
      // Plain text password (for migration)
      passwordMatch = user.password === password;
      // Optionally hash and update in database
      if (passwordMatch) {
        const hashed = await bcrypt.hash(password, 10);
        db.run('UPDATE users SET password = ? WHERE id = ?', [hashed, user.id]);
      }
    }

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    if (String(user.role) !== String(role)) {
      return res
        .status(400)
        .json({ error: 'Incorrect role selected. Please choose the correct role.' });
    }

    const { token, user: sessionUser, expiresAt } = createSession(user);
    res.json({ message: 'Login successful', user: sessionUser, token, expiresAt });
  });
});

app.post('/api/logout', requireAuth, (req, res) => {
  const token = req.headers['x-auth-token'] || req.query.token;
  if (token && sessions.has(token)) {
    sessions.delete(token);
  }
  res.json({ message: 'Logged out' });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// --- Classes ---
app.get('/api/classes', requireAuth, (req, res) => {
  const sql = 'SELECT * FROM classes ORDER BY name';
  db.all(sql, [], handleDbCallback(res));
});

app.post('/api/classes', requireAuth, requireRole('admin'), (req, res) => {
  const { name, description } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Class name is required' });
  }
  const sql = 'INSERT INTO classes (name, description) VALUES (?, ?)';
  db.run(sql, [name, description || null], function (err) {
    if (err) {
      console.error('Create class error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.status(201).json({ id: this.lastID, name, description: description || null });
  });
});

// --- Students ---
app.get('/api/students', requireAuth, (req, res) => {
  const { class_id } = req.query;
  const user = req.user;

  // Students can only see their own record.
  if (user.role === 'student') {
    if (!user.student_id) {
      return res.json([]);
    }
    const sql = 'SELECT * FROM students WHERE id = ? ORDER BY name';
    return db.all(sql, [user.student_id], handleDbCallback(res));
  }

  // Admins and teachers can list students, optionally filtered by class.
  let sql = 'SELECT * FROM students';
  const params = [];
  const where = [];

  if (class_id) {
    where.push('class_id = ?');
    params.push(class_id);
  }

  if (where.length > 0) {
    sql += ' WHERE ' + where.join(' AND ');
  }

  sql += ' ORDER BY name';
  db.all(sql, params, handleDbCallback(res));
});

app.post('/api/students', requireAuth, requireRole('admin'), (req, res) => {
  const { name, roll_number, class_id } = req.body;
  if (!name || !class_id) {
    return res.status(400).json({ error: 'Student name and class_id are required' });
  }

  const classIdInt = parseInt(class_id, 10);
  if (isNaN(classIdInt) || classIdInt <= 0) {
    return res.status(400).json({ error: 'Invalid class_id' });
  }

  // Validate class exists
  db.get('SELECT id FROM classes WHERE id = ?', [classIdInt], (err, classRow) => {
    if (err) {
      console.error('Check class error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!classRow) {
      return res.status(400).json({ error: 'Invalid class_id: class does not exist' });
    }

    const sql = 'INSERT INTO students (name, roll_number, class_id) VALUES (?, ?, ?)';
    db.run(sql, [name, roll_number || null, classIdInt], function (err) {
      if (err) {
        console.error('Add student error:', err);
        return res.status(500).json({ error: 'Database error', details: err.message });
      }
      res.status(201).json({ id: this.lastID, name, roll_number: roll_number || null, class_id: classIdInt });
    });
  });
});

// --- Teachers ---
// Teachers are stored in the users table with role = 'teacher'.
// These endpoints let admins list and create teacher accounts.
app.get('/api/teachers', requireAuth, requireRole('admin'), (req, res) => {
  const { class_id } = req.query;

  let sql = `
    SELECT u.id,
           u.username,
           u.display_name,
           u.class_id,
           u.email,
           u.phone,
           u.subject,
           u.experience,
           c.name AS class_name
    FROM users u
    LEFT JOIN classes c ON u.class_id = c.id
    WHERE u.role = 'teacher'
  `;

  const params = [];
  if (class_id) {
    sql += ' AND u.class_id = ?';
    params.push(class_id);
  }

  sql += ' ORDER BY COALESCE(u.display_name, u.username)';
  db.all(sql, params, handleDbCallback(res));
});

app.post('/api/teachers', requireAuth, requireRole('admin'), (req, res) => {
  const { username, display_name, password, class_id, email, phone, subject, experience } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required for a teacher account' });
  }

  // Validate username format (basic)
  if (username.length < 3 || username.length > 50) {
    return res.status(400).json({ error: 'Username must be between 3 and 50 characters' });
  }

  // Check if username already exists
  db.get('SELECT id FROM users WHERE username = ?', [username], async (err, existing) => {
    if (err) {
      console.error('Check username error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (existing) {
      return res.status(400).json({ error: 'Username already exists' });
    }

    // Validate class_id if provided
    if (class_id) {
      const classIdInt = parseInt(class_id, 10);
      if (isNaN(classIdInt) || classIdInt <= 0) {
        return res.status(400).json({ error: 'Invalid class_id' });
      }

      db.get('SELECT id FROM classes WHERE id = ?', [classIdInt], (classErr, classRow) => {
        if (classErr) {
          console.error('Check class error:', classErr);
          return res.status(500).json({ error: 'Database error' });
        }
        if (!classRow) {
          return res.status(400).json({ error: 'Invalid class_id: class does not exist' });
        }

        insertTeacher();
      });
    } else {
      insertTeacher();
    }

    async function insertTeacher() {
      const hashedPassword = await bcrypt.hash(password, 10);
      const sql = 'INSERT INTO users (username, password, role, display_name, class_id, email, phone, subject, experience) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
      db.run(sql, [username, hashedPassword, 'teacher', display_name || null, class_id || null, email || null, phone || null, subject || null, experience || null], function (err) {
        if (err) {
          console.error('Add teacher error:', err);
          return res.status(500).json({ error: 'Database error', details: err.message });
        }

        res.status(201).json({
          id: this.lastID,
          username,
          display_name: display_name || null,
          class_id: class_id || null,
          email: email || null,
          phone: phone || null,
          subject: subject || null,
          experience: experience || null,
        });
      });
    }
  });
});

// --- Dashboard stats ---

app.get('/api/dashboard/admin', requireAuth, requireRole('admin'), (req, res) => {
  const sql = `
    SELECT
      (SELECT COUNT(*) FROM students) AS total_students,
      (SELECT COUNT(*) FROM users WHERE role = 'teacher') AS total_teachers,
      (SELECT COUNT(*) FROM classes) AS total_classes,
      0 AS active_policies
  `;

  db.get(sql, [], (err, row) => {
    if (err) {
      console.error('Admin dashboard error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    const safeRow = row || {
      total_students: 0,
      total_teachers: 0,
      total_classes: 0,
      active_policies: 0,
    };

    res.json(safeRow);
  });
});

app.get('/api/dashboard/teacher', requireAuth, requireRole('teacher'), (req, res) => {
  const user = req.user;
  const classId = user.class_id;

  if (!classId) {
    return res.json({
      class_id: null,
      class_name: null,
      student_count: 0,
      today_sessions: 0,
    });
  }

  const today = new Date().toISOString().slice(0, 10);

  const sql = `
    SELECT
      c.id AS class_id,
      c.name AS class_name,
      (SELECT COUNT(*) FROM students s WHERE s.class_id = c.id) AS student_count,
      (SELECT COUNT(*) FROM sessions sess WHERE sess.class_id = c.id AND sess.date = ?) AS today_sessions
    FROM classes c
    WHERE c.id = ?
  `;

  db.get(sql, [today, classId], (err, row) => {
    if (err) {
      console.error('Teacher dashboard error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!row) {
      return res.json({
        class_id: classId,
        class_name: null,
        student_count: 0,
        today_sessions: 0,
      });
    }

    res.json(row);
  });
});

// --- Sessions ---
// Admins can view all sessions (for reporting/management).
// Teachers can view sessions for any class in the system (multi-class access).
// Students remain scoped to their own class.
app.get('/api/sessions', requireAuth, (req, res) => {
  const { class_id } = req.query;
  const user = req.user;

  let sql = 'SELECT s.*, c.name as class_name FROM sessions s JOIN classes c ON s.class_id = c.id';
  const params = [];
  const where = [];

  if (user.role === 'admin' || user.role === 'teacher') {
    // Admins and teachers can optionally filter by any class_id.
    if (class_id) {
      where.push('s.class_id = ?');
      params.push(class_id);
    }
  } else if (user.role === 'student') {
    // Students are still restricted to sessions for their own class.
    if (!user.class_id) {
      return res.json([]);
    }
    where.push('s.class_id = ?');
    params.push(user.class_id);
  }

  if (where.length > 0) {
    sql += ' WHERE ' + where.join(' AND ');
  }

  sql += ' ORDER BY date DESC, s.id DESC';

  db.all(sql, params, handleDbCallback(res));
});

// NOTE: Only teachers create classroom sessions. Admin can manage/view but not create.
app.post('/api/sessions', requireAuth, requireRole('teacher'), (req, res) => {
  const user = req.user;
  const { class_id, date, topic } = req.body;
  if (!class_id || !date) {
    return res.status(400).json({ error: 'class_id and date are required' });
  }

  const classIdInt = parseInt(class_id, 10);
  if (isNaN(classIdInt) || classIdInt <= 0) {
    return res.status(400).json({ error: 'Invalid class_id' });
  }

  // Validate date format
  const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
  if (!dateRegex.test(date)) {
    return res.status(400).json({ error: 'Invalid date format. Use YYYY-MM-DD' });
  }

  const dateObj = new Date(date);
  if (isNaN(dateObj.getTime())) {
    return res.status(400).json({ error: 'Invalid date value' });
  }

  // Validate class exists
  db.get('SELECT id FROM classes WHERE id = ?', [classIdInt], (err, classRow) => {
    if (err) {
      console.error('Check class error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!classRow) {
      return res.status(400).json({ error: 'Invalid class_id: class does not exist' });
    }

    insertSession();

    function insertSession() {
      const sql = 'INSERT INTO sessions (class_id, date, topic) VALUES (?, ?, ?)';
      db.run(sql, [classIdInt, date, topic || null], function (err) {
        if (err) {
          console.error('Create session error:', err);
          return res.status(500).json({ error: 'Database error', details: err.message });
        }
        res.status(201).json({ id: this.lastID, class_id: classIdInt, date, topic: topic || null });
      });
    }
  });
});

// --- Attendance ---
// Mark attendance for one or many students
// NOTE: Only teachers can mark attendance. Admins can view reports but cannot mark.
app.post('/api/attendance', requireAuth, requireRole('teacher'), (req, res) => {
  const { session_id, records } = req.body;

  if (!session_id || !Array.isArray(records) || records.length === 0) {
    return res.status(400).json({ error: 'session_id and an array of records are required' });
  }

  // Validate session_id is integer
  const sessionIdInt = parseInt(session_id, 10);
  if (isNaN(sessionIdInt) || sessionIdInt <= 0) {
    return res.status(400).json({ error: 'Invalid session_id' });
  }

  db.get('SELECT class_id FROM sessions WHERE id = ?', [sessionIdInt], (err, sessionRow) => {
    if (err) {
      console.error('Lookup session error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!sessionRow) {
      return res.status(400).json({ error: 'Invalid session_id' });
    }

    const sessionClassId = sessionRow.class_id;

    // Validate all student_ids belong to the session's class
    const studentIds = records
      .map(r => parseInt(r.student_id, 10))
      .filter(id => !isNaN(id) && id > 0);
    
    if (studentIds.length === 0) {
      return res.status(400).json({ error: 'No valid student_ids provided' });
    }

    // Validate status values
    const validStatuses = ['present', 'absent'];
    const invalidRecords = records.filter(r => !validStatuses.includes(String(r.status).toLowerCase()));
    if (invalidRecords.length > 0) {
      return res.status(400).json({ error: 'Invalid status values. Must be "present" or "absent"' });
    }

    // Check all students belong to the session's class
    const placeholders = studentIds.map(() => '?').join(',');
    const checkSql = `SELECT id FROM students WHERE id IN (${placeholders}) AND class_id = ?`;
    db.all(checkSql, [...studentIds, sessionClassId], (checkErr, validStudents) => {
      if (checkErr) {
        console.error('Student validation error:', checkErr);
        return res.status(500).json({ error: 'Database error' });
      }

      if (validStudents.length !== studentIds.length) {
        return res.status(400).json({ error: 'Some students do not belong to this session\'s class' });
      }

      // Use INSERT ... ON CONFLICT to preserve marked_at timestamp on updates
      // This requires SQLite 3.24+. For older versions, falls back to INSERT OR REPLACE behavior
      let upsertStmt;
      try {
        // Try to use ON CONFLICT syntax (SQLite 3.24+)
        upsertStmt = db.prepare(`
          INSERT INTO attendance (session_id, student_id, status, marked_at)
          VALUES (?, ?, ?, datetime('now'))
          ON CONFLICT(session_id, student_id) 
          DO UPDATE SET status = excluded.status
        `);
      } catch (prepareErr) {
        // Fallback to INSERT OR REPLACE if ON CONFLICT not supported
        console.warn('ON CONFLICT not supported, using INSERT OR REPLACE (marked_at will be reset on updates)');
        upsertStmt = db.prepare('INSERT OR REPLACE INTO attendance (session_id, student_id, status) VALUES (?, ?, ?)');
      }
      
      let hasError = false;
      let completed = 0;
      const validRecords = records.filter(rec => {
        const studentId = parseInt(rec.student_id, 10);
        const status = String(rec.status).toLowerCase();
        return !isNaN(studentId) && studentId > 0 && validStatuses.includes(status);
      });
      const totalRecords = validRecords.length;

      if (totalRecords === 0) {
        upsertStmt.finalize();
        return res.status(400).json({ error: 'No valid records to save' });
      }

      db.serialize(() => {
        db.run('BEGIN TRANSACTION', (beginErr) => {
          if (beginErr) {
            console.error('Begin transaction error:', beginErr);
            upsertStmt.finalize();
            return res.status(500).json({ error: 'Failed to start transaction' });
          }

          for (const rec of validRecords) {
            const studentId = parseInt(rec.student_id, 10);
            const status = String(rec.status).toLowerCase();

            upsertStmt.run([sessionIdInt, studentId, status], (runErr) => {
              completed++;
              
              if (runErr && !hasError) {
                hasError = true;
                console.error('Attendance insert error:', runErr);
                db.run('ROLLBACK', () => {
                  upsertStmt.finalize();
                  return res.status(500).json({ error: 'Failed to save attendance', details: runErr.message });
                });
                return;
              }

              if (!hasError && completed === totalRecords) {
                db.run('COMMIT', (commitErr) => {
                  upsertStmt.finalize();
                  
                  if (commitErr) {
                    console.error('Commit error:', commitErr);
                    return res.status(500).json({ error: 'Failed to save attendance', details: commitErr.message });
                  }
                  
                  res.status(201).json({ message: 'Attendance saved successfully' });
                });
              }
            });
          }
        });
      });
    });
  });
});

// Get attendance by session
app.get('/api/attendance/by-session', requireAuth, requireRole('admin', 'teacher'), (req, res) => {
  const { session_id } = req.query;
  if (!session_id) {
    return res.status(400).json({ error: 'session_id is required' });
  }

  db.get('SELECT class_id FROM sessions WHERE id = ?', [session_id], (err, sessionRow) => {
    if (err) {
      console.error('Lookup session error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!sessionRow) {
      return res.status(400).json({ error: 'Invalid session_id' });
    }

    const sql = `
      SELECT a.id, a.status, a.marked_at,
             s.id AS student_id, s.name AS student_name, s.roll_number,
             sess.date, sess.topic, c.name AS class_name
      FROM attendance a
      JOIN students s ON a.student_id = s.id
      JOIN sessions sess ON a.session_id = sess.id
      JOIN classes c ON sess.class_id = c.id
      WHERE a.session_id = ?
      ORDER BY s.name
    `;

    db.all(sql, [session_id], handleDbCallback(res));
  });
});

// --- Reports ---
// Attendance for a single student across sessions
app.get('/api/reports/by-student', requireAuth, (req, res) => {
  const { student_id } = req.query;
  if (!student_id) {
    return res.status(400).json({ error: 'student_id is required' });
  }

  const studentIdInt = parseInt(student_id, 10);
  if (isNaN(studentIdInt) || studentIdInt <= 0) {
    return res.status(400).json({ error: 'Invalid student_id' });
  }

  const user = req.user;

  const runQuery = () => {
    const sql = `
      SELECT a.status, a.marked_at,
             sess.id AS session_id, sess.date, sess.topic,
             c.id AS class_id, c.name AS class_name
      FROM attendance a
      JOIN sessions sess ON a.session_id = sess.id
      JOIN classes c ON sess.class_id = c.id
      WHERE a.student_id = ?
      ORDER BY sess.date DESC, sess.id DESC
    `;

    db.all(sql, [studentIdInt], handleDbCallback(res));
  };

  if (user.role === 'admin') {
    return runQuery();
  }

  if (user.role === 'student') {
    if (!user.student_id || String(user.student_id) !== String(studentIdInt)) {
      return res.status(403).json({ error: 'Forbidden: You can only view your own attendance' });
    }
    return runQuery();
  }

  if (user.role === 'teacher') {
    return runQuery();
  }

  return res.status(403).json({ error: 'Forbidden' });
});

// Summary by class: per-student counts
app.get('/api/reports/summary-by-class', requireAuth, (req, res) => {
  const { class_id } = req.query;
  if (!class_id) {
    return res.status(400).json({ error: 'class_id is required' });
  }

  const classIdInt = parseInt(class_id, 10);
  if (isNaN(classIdInt) || classIdInt <= 0) {
    return res.status(400).json({ error: 'Invalid class_id' });
  }

  const user = req.user;

  if (user.role === 'student') {
    return res.status(403).json({ error: 'Forbidden' });
  }

  // FIXED: Only count sessions where attendance was actually marked
  const sql = `
    SELECT 
      st.id AS student_id,
      st.name AS student_name,
      st.roll_number,
      COUNT(DISTINCT a.session_id) AS total,
      SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) AS presents,
      (COUNT(DISTINCT a.session_id) - SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END)) AS absents
    FROM students st
    LEFT JOIN attendance a ON a.student_id = st.id
    LEFT JOIN sessions sess ON sess.id = a.session_id AND sess.class_id = st.class_id
    WHERE st.class_id = ?
    GROUP BY st.id, st.name, st.roll_number
    ORDER BY st.name
  `;

  db.all(sql, [classIdInt], handleDbCallback(res));
});

// Export: Student report (CSV / PDF)
app.get('/api/reports/by-student/export', requireAuth, (req, res) => {
  const { student_id, format = 'csv' } = req.query;
  if (!student_id) {
    return res.status(400).json({ error: 'student_id is required' });
  }

  const user = req.user;

  const runQuery = () => {
    const sql = `
      SELECT a.status, a.marked_at,
             sess.id AS session_id, sess.date, sess.topic,
             c.id AS class_id, c.name AS class_name
      FROM attendance a
      JOIN sessions sess ON a.session_id = sess.id
      JOIN classes c ON sess.class_id = c.id
      WHERE a.student_id = ?
      ORDER BY sess.date DESC, sess.id DESC
    `;

    db.all(sql, [student_id], (err, rows) => {
      if (err) {
        console.error('Student report export error:', err);
        return res.status(500).json({ error: 'Database error' });
      }

      if (format === 'pdf') {
        return sendStudentReportPdf(res, rows, {
          filename: `student-${student_id}-report.pdf`,
        });
      }

      return sendStudentReportCsv(res, rows, `student-${student_id}-report`);
    });
  };

  if (user.role === 'admin') {
    return runQuery();
  }

  if (user.role === 'student') {
    if (!user.student_id || String(user.student_id) !== String(student_id)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    // Students can only download PDF, not CSV, for their own reports.
    if (format && String(format).toLowerCase() !== 'pdf') {
      return res.status(400).json({ error: 'Students can only download PDF reports.' });
    }
    return runQuery();
  }

  if (user.role === 'teacher') {
    return runQuery();
  }

  return res.status(403).json({ error: 'Forbidden' });
});

// Export: Class summary (CSV / PDF)
app.get('/api/reports/summary-by-class/export', requireAuth, (req, res) => {
  const { class_id, format = 'csv' } = req.query;
  if (!class_id) {
    return res.status(400).json({ error: 'class_id is required' });
  }

  const user = req.user;

  if (user.role === 'student') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const sql = `
    SELECT st.id AS student_id,
           st.name AS student_name,
           st.roll_number,
           SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) AS presents,
           COUNT(sess.id) AS total,
           (COUNT(sess.id) - SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END)) AS absents
    FROM students st
    LEFT JOIN sessions sess ON sess.class_id = st.class_id
    LEFT JOIN attendance a
           ON a.student_id = st.id
          AND a.session_id = sess.id
    WHERE st.class_id = ?
    GROUP BY st.id, st.name, st.roll_number
    ORDER BY st.name
  `;

  db.all(sql, [class_id], (err, rows) => {
    if (err) {
      console.error('Class summary export error:', err);
      return res.status(500).json({ error: 'Database error' });
    }

    if (format === 'pdf') {
      return sendClassSummaryPdf(res, rows, {
        filename: `class-${class_id}-summary.pdf`,
      });
    }

    return sendClassSummaryCsv(res, rows, `class-${class_id}-summary`);
  });
});

// Fallback route - serve index
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
